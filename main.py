from gevent import monkey
monkey.patch_all()

import ssl
ssl._create_default_https_context = ssl._create_unverified_context

import sqlite3
import os
import logging
import requests
import gevent
from datetime import datetime, timedelta
from flask import Flask, render_template, request, jsonify, redirect, session
from steam.client import SteamClient
from steam.enums import EResult
from concurrent.futures import ThreadPoolExecutor
from functools import wraps

# --- IMPORTANT: we use Fernet for user password encryption ---
from cryptography.fernet import Fernet

# ------------------- SETTINGS -------------------
DATABASE = 'steam_accounts.db'
STEAM_API_KEY = os.getenv('STEAM_API_KEY', 'YOUR KEY API')

LOG_FORMAT = "\033[1;32m%(asctime)s\033[0m [\033[1;34m%(levelname)s\033[0m] %(message)s"
logging.basicConfig(level=logging.INFO, format=LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()

# Steam clients (for farming, etc.)
clients = {}
executor = ThreadPoolExecutor(max_workers=5)

# --- Load Fernet key ---
with open('key.key', 'rb') as f:
    key = f.read()
fernet = Fernet(key)

# ------------------- DECORATORS -------------------
def login_required(f):
    """Check that the user is logged in."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect('/login')

        # Update last_seen for the current user
        user_id = session['user_id']
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        conn = sqlite3.connect(DATABASE)
        conn.execute("UPDATE users SET last_seen=? WHERE id=?", (now_str, user_id))
        conn.commit()
        conn.close()

        return f(*args, **kwargs)
    return decorated

def subscription_required(f):
    """Check that the user has an active subscription."""
    @wraps(f)
    def wrapped(*args, **kwargs):
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        user = conn.execute("SELECT subscription_end, banned FROM users WHERE id=?", (session['user_id'],)).fetchone()
        conn.close()

        # Ban check
        if user and user['banned'] == 1:
            # If the user is banned, redirect to /logout or show a "banned" page
            return "You are banned."

        # Subscription check
        if not user or not user['subscription_end']:
            return redirect('/no_subscription')

        try:
            sub_end = datetime.strptime(user['subscription_end'], '%Y-%m-%d %H:%M:%S')
        except ValueError:
            return redirect('/no_subscription')

        if sub_end < datetime.now():
            return redirect('/no_subscription')

        return f(*args, **kwargs)
    return wrapped
    
# ------------------- DATABASE AND INITIALIZATION -------------------
def db_connection(f):
    """
    SQLite wrapper with timeout=10 to reduce 'database is locked' errors
    during parallel operations.
    """
    @wraps(f)
    def wrapped(*args, **kwargs):
        conn = sqlite3.connect(DATABASE, timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            result = f(conn, *args, **kwargs)
            conn.commit()
            return result
        except Exception as e:
            conn.rollback()
            logger.error(f"DB Error: {e}")
            raise
        finally:
            conn.close()
    return wrapped

@db_connection
def init_db(conn):
    """
    Create tables (users, accounts, games, account_games) with required fields.
    """
    cur = conn.cursor()

    # Users table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            subscription_end TEXT,
            is_admin INTEGER DEFAULT 0,
            banned INTEGER DEFAULT 0,
            last_ip TEXT,
            last_seen TEXT
        )
    ''')

    # Steam accounts table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            shared_secret TEXT,
            steamid64 TEXT,
            user_id INTEGER
        )
    ''')

    # Games table
    cur.execute('''
        CREATE TABLE IF NOT EXISTS games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            game_id INTEGER UNIQUE,
            game_name TEXT
        )
    ''')

    # Link accounts to games
    cur.execute('''
        CREATE TABLE IF NOT EXISTS account_games (
            account_id INTEGER,
            game_id INTEGER,
            PRIMARY KEY (account_id, game_id),
            FOREIGN KEY (account_id) REFERENCES accounts(id),
            FOREIGN KEY (game_id) REFERENCES games(id)
        )
    ''')

# ------------------- USER REGISTRATION / LOGIN -------------------
@db_connection
def register_user(conn, username, password):
    """
    Register a new user (if username is not taken).
    Password is encrypted with Fernet (reversible).
    """
    cur = conn.cursor()
    existing = cur.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        return False

    # Encrypt password
    encrypted_password = fernet.encrypt(password.encode()).decode()

    cur.execute("""
        INSERT INTO users (username, password)
        VALUES (?, ?)
    """, (username, encrypted_password))

    return True

def verify_user(username, password):
    """
    Check login/password by decrypting the stored password (via Fernet) and comparing.
    Also checks if the user is banned.
    """
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()

    if not user:
        return None

    # Ban check
    if user['banned'] == 1:
        return None  # user is banned

    stored_enc = user['password']
    try:
        stored_plain = fernet.decrypt(stored_enc.encode()).decode()
    except Exception as e:
        logger.error(f"Error decrypting user password: {e}")
        return None

    if stored_plain == password:
        return dict(user)
    else:
        return None

# ------------------- SUBSCRIPTION -------------------
@app.route('/no_subscription')
@login_required
def no_subscription():
    return render_template('no_subscription.html')

@app.route('/buy_subscription', methods=['GET', 'POST'])
@login_required
def buy_subscription():
    """
    Purchase a subscription via crypto payment.
    Form to select plan and payment method (only crypto in this example).
    On POST, creates a payment via API (create_crypto_charge function),
    and the user is redirected to the payment page.
    """
    if request.method == 'POST':
        plan = request.form.get('plan')
        payment_method = request.form.get('payment_method')  # in this example, expects "crypto"
        if payment_method == "crypto":
            # Determine price (example values)
            if plan == "1_week":
                amount = "10.00"
            elif plan == "3_months":
                amount = "25.00"
            elif plan == "6_months":
                amount = "40.00"
            elif plan == "12_months":
                amount = "70.00"
            elif plan == "lifetime":
                amount = "150.00"
            else:
                amount = "0.00"
            # Create payment via crypto API
            crypto_url = create_crypto_charge(plan, amount)
            if crypto_url:
                # You can save pending_plan in session for later update via webhook
                session['pending_plan'] = plan
                return redirect(crypto_url)
            else:
                return "Payment creation error. Please try again later.", 500
        else:
            return "Unknown payment method.", 400
    else:
        return render_template('buy_subscription.html')

def create_crypto_charge(plan, amount, currency="USD"):
    """
    Function to create a payment charge via Coinbase Commerce.
    This is an example; for real integration, configure parameters and keys.
    """
    headers = {
        "X-CC-Api-Key": COINBASE_API_KEY,
        "X-CC-Version": "2018-03-22",
        "Content-Type": "application/json"
    }
    data = {
        "name": f"Subscription {plan}",
        "description": f"Subscription plan: {plan}",
        "local_price": {
            "amount": amount,
            "currency": currency
        },
        "pricing_type": "fixed_price"
    }
    try:
        response = requests.post(COINBASE_CHARGE_URL, headers=headers, json=data)
        if response.status_code == 201:
            charge = response.json()["data"]
            return charge["hosted_url"]
        else:
            logger.error(f"Error creating crypto charge: {response.text}")
            return None
    except Exception as e:
        logger.error(f"Exception creating crypto charge: {e}")
        return None

# ------------------- ADMIN PANEL -------------------
@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin_panel():
    """
    Admin can:
      - Search users by username (GET q=...),
      - Change subscription, ban, is_admin
    """
    if not session.get('is_admin'):
        return redirect('/')

    conn = sqlite3.connect(DATABASE, timeout=10)
    conn.row_factory = sqlite3.Row

    # Handle POST - update user data
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        is_admin = request.form.get('is_admin', 1)
        banned = request.form.get('banned', 0)

        # Subscription period
        option = request.form.get('subscription_duration')
        if option == "0":
            subscription_end = None
        elif option == "1_week":
            subscription_end = datetime.now() + timedelta(weeks=1)
        elif option == "3_months":
            subscription_end = datetime.now() + timedelta(days=90)
        elif option == "6_months":
            subscription_end = datetime.now() + timedelta(days=180)
        elif option == "12_months":
            subscription_end = datetime.now() + timedelta(days=365)
        elif option == "lifetime":
            subscription_end = datetime(9999, 12, 31, 23, 59, 59)
        else:
            subscription_end = None

        sub_end_str = subscription_end.strftime('%Y-%m-%d %H:%M:%S') if subscription_end else None

        conn.execute("""
            UPDATE users
            SET subscription_end=?,
                is_admin=?,
                banned=?
            WHERE id=?
        """, (sub_end_str, is_admin, banned, user_id))
        conn.commit()

    # Handle GET - search users
    q = request.args.get('q', '')
    if q:
        sql = "SELECT * FROM users WHERE username LIKE ?"
        users = conn.execute(sql, (f"%{q}%",)).fetchall()
    else:
        users = conn.execute("SELECT * FROM users").fetchall()

    conn.close()
    return render_template('admin.html', users=users, query=q)

# ------------------- LOGIN / REGISTRATION / LOGOUT -------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        success = register_user(request.form['username'], request.form['password'])
        if success:
            return redirect('/login')
        else:
            return render_template('register.html', error='User already exists')
    return render_template('register.html', error=None)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = verify_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['is_admin'] = user['is_admin']

            # Save IP
            user_ip = request.remote_addr or 'unknown'
            conn = sqlite3.connect(DATABASE)
            conn.execute("UPDATE users SET last_ip=? WHERE id=?", (user_ip, user['id']))
            conn.commit()
            conn.close()

            return redirect('/')
        else:
            return render_template('login.html', error='Invalid username/password or you are banned')
    return render_template('login.html', error=None)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

# ------------------- MAIN PAGE -------------------
@app.route('/')
@login_required
@subscription_required
def index():
    return render_template('index.html', username=session.get('username'), is_admin=session.get('is_admin'))

# ------------------- STEAM ACCOUNT FUNCTIONS -------------------
@db_connection
def get_accounts_db(conn, user_id):
    """Return a list of accounts for the given user_id."""
    rows = conn.execute("SELECT * FROM accounts WHERE user_id=?", (user_id,)).fetchall()
    return [dict(r) for r in rows]

@app.route('/get_accounts', methods=['GET'])
@login_required
def api_get_accounts():
    user_id = session['user_id']
    rows = get_accounts_db(user_id)
    accounts = []
    for row in rows:
        try:
            dec_username = fernet.decrypt(row['username'].encode()).decode()
        except Exception as e:
            logger.error(f"Error decrypting account username: {e}")
            dec_username = "Decryption error"
        active_games = get_account_games(row["id"])
        accounts.append({
            "id": row["id"],
            "username": dec_username,
            "steamid64": row["steamid64"],
            "status": "online" if dec_username in clients else "offline",
            "active_games": active_games  # List of games, if any
        })
    return jsonify(accounts)


@app.route('/add_account', methods=['POST'])
@login_required
def api_add_account():
    data = request.json
    if not data:
        return jsonify({"success": False, "error": "No data"})
    user_id = session['user_id']
    # Encrypt login/password/shared_secret
    enc_username = fernet.encrypt(data['username'].encode()).decode()
    enc_password = fernet.encrypt(data['password'].encode()).decode()
    enc_shared = fernet.encrypt(data.get('shared_secret', '').encode()).decode()
    logger.info(f"Encrypted steam_username: {enc_username}")
    logger.info(f"Encrypted steam_password: {enc_password}")
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO accounts (username, password, shared_secret, steamid64, user_id)
            VALUES (?, ?, ?, ?, ?)
        """, (enc_username, enc_password, enc_shared, '', user_id))
        conn.commit()
        account_id = cur.lastrowid
        conn.close()
        return jsonify({"success": True, "account_id": account_id})
    except sqlite3.IntegrityError:
        conn.close()
        return jsonify({"success": False, "error": "Account already exists"})


@db_connection
def delete_account_db(conn, account_id):
    cur = conn.cursor()
    cur.execute("DELETE FROM account_games WHERE account_id=?", (account_id,))
    cur.execute("DELETE FROM accounts WHERE id=?", (account_id,))

@db_connection
def update_steamid64(conn, account_id, steamid64):
    cur = conn.cursor()
    cur.execute("UPDATE accounts SET steamid64=? WHERE id=?", (steamid64, account_id))

@app.route('/delete_account', methods=['POST'])
@login_required
def api_delete_account():
    data = request.json
    account_id = data.get('id')
    user_id = session['user_id']
    conn = sqlite3.connect(DATABASE)
    cur = conn.cursor()
    account = cur.execute("SELECT username FROM accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    if not account:
        conn.close()
        return jsonify({"success": False, "error": "Account not found"})
    dec_username = fernet.decrypt(account[0].encode()).decode()
    # Stop farming and logout from client if account is in clients
    if dec_username in clients:
        stop_farming_background(dec_username)
        clients[dec_username]["client"].logout()
        del clients[dec_username]
    conn.close()
    delete_account_db(account_id)
    return jsonify({"success": True})

def login_steam(account, steam_guard_code=None):
    enc_username = account["username"]
    enc_password = account["password"]
    try:
        plain_username = fernet.decrypt(enc_username.encode()).decode()
        plain_password = fernet.decrypt(enc_password.encode()).decode()
    except:
        return {"success": False, "error": "Decryption error"}

    logger.info(f"[{plain_username}] Attempting login")
    try:
        client = SteamClient()
        result = client.login(username=plain_username, password=plain_password, auth_code=steam_guard_code)
        if result == EResult.OK:
            steamid64 = str(client.steam_id.as_64)
            update_steamid64(account["id"], steamid64)  # <--- this function is now defined
            clients[plain_username] = {
                "client": client,
                "account_id": account["id"],
            }
            executor.submit(client.run_forever)
            logger.info(f"[{plain_username}] Login successful (SteamID64: {steamid64})")
            return {"success": True}
        elif result in (EResult.AccountLogonDenied, EResult.InvalidLoginAuthCode):
            logger.warning(f"[{plain_username}] SteamGuard required")
            return {"success": False, "need_steam_guard": True, "error": "SteamGuard required"}
        else:
            logger.error(f"[{plain_username}] Login failed: {result}")
            return {"success": False, "error": f"Login failed ({result})"}
    except Exception as e:
        logger.error(f"[{plain_username}] Exception: {e}")
        return {"success": False, "error": str(e)}

@app.route('/login_account', methods=['POST'])
@login_required
def api_login_account():
    data = request.json
    account_id = data.get('id')
    steam_guard_code = data.get('steam_guard_code')
    user_id = session['user_id']

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute("""
        SELECT id, username, password, shared_secret
        FROM accounts
        WHERE id=? AND user_id=?
    """, (account_id, user_id)).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    result = login_steam(dict(account), steam_guard_code)
    return jsonify(result)

@app.route('/logout_account', methods=['POST'])
@login_required
def api_logout_account():
    data = request.json
    account_id = data.get('account_id')

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute("""
        SELECT username
        FROM accounts
        WHERE id=? AND user_id=?
    """, (account_id, session['user_id'])).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    try:
        dec_username = fernet.decrypt(account['username'].encode()).decode()
    except:
        return jsonify({"success": False, "error": "Username decryption error"})

    if dec_username in clients:
        stop_farming_background(dec_username)
        clients[dec_username]["client"].logout()
        del clients[dec_username]
        logger.info(f"[{dec_username}] Logged out")
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "error": "Account not logged in"})

def farm_loop(username, client, game_ids):
    minutes_counter = {gid: 0 for gid in game_ids}
    logger.info(f"[{username}] Farming started for games: {game_ids}")
    while True:
        try:
            client.games_played(game_ids)
            logger.info(f"[{username}] Sent game status: {game_ids}")
            for gid in game_ids:
                minutes_counter[gid] += 1
                total = minutes_counter[gid]
                hours = total // 60
                mins = total % 60
                logger.info(f"[{username}] Game {gid}: +1 minute (total {hours}h {mins}m)")
        except Exception as e:
            logger.error(f"[{username}] Farming error: {e}")
            break
        gevent.sleep(60)
    try:
        client.games_played([])
    except Exception as e:
        logger.error(f"[{username}] Error stopping games: {e}")
    logger.info(f"[{username}] Farming stopped.")

def start_farming_background(username):
    if username not in clients:
        return {"success": False, "error": "Account not logged in"}
    client_data = clients[username]
    client = client_data["client"]
    account_id = client_data["account_id"]
    games = get_account_games(account_id)
    game_ids = [g["game_id"] for g in games]
    if not game_ids:
        return {"success": False, "error": "No games selected for farming"}
    if "farming_greenlet" in client_data:
        client_data["farming_greenlet"].kill()
    greenlet = gevent.spawn(farm_loop, username, client, game_ids)
    client_data["farming_greenlet"] = greenlet
    return {"success": True, "games": game_ids}

def stop_farming_background(username):
    if username not in clients:
        return {"success": False, "error": "Account not logged in"}
    client_data = clients[username]
    if "farming_greenlet" in client_data:
        client_data["farming_greenlet"].kill()
        del client_data["farming_greenlet"]
        return {"success": True}
    return {"success": False, "error": "Farming not running"}

def get_account_games(account_id):
    with sqlite3.connect(DATABASE) as conn:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("""
            SELECT g.game_id, g.game_name
            FROM games g
            JOIN account_games ag ON g.id = ag.game_id
            WHERE ag.account_id = ?
        """, (account_id,))
        return [dict(row) for row in cur.fetchall()]

@app.route('/start_farming', methods=['POST'])
@login_required
def api_start_farming():
    data = request.json
    account_id = data.get('account_id')
    user_id = session['user_id']

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute("SELECT username FROM accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    try:
        dec_username = fernet.decrypt(account['username'].encode()).decode()
    except:
        return jsonify({"success": False, "error": "Username decryption error"})

    if dec_username not in clients:
        return jsonify({"success": False, "error": "Account not logged in"})
    return jsonify(start_farming_background(dec_username))

@app.route('/stop_farming', methods=['POST'])
@login_required
def api_stop_farming():
    data = request.json
    account_id = data.get('account_id')
    user_id = session['user_id']

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute("SELECT username FROM accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    try:
        dec_username = fernet.decrypt(account['username'].encode()).decode()
    except:
        return jsonify({"success": False, "error": "Username decryption error"})

    if dec_username not in clients:
        return jsonify({"success": False, "error": "Account not logged in"})
    return jsonify(stop_farming_background(dec_username))

@app.route('/fetch_owned_games', methods=['POST'])
@login_required
def api_fetch_owned_games():
    data = request.json
    account_id = data.get('account_id')
    user_id = session['user_id']

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute("SELECT username, steamid64 FROM accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    try:
        dec_username = fernet.decrypt(account['username'].encode()).decode()
    except:
        return jsonify({"success": False, "error": "Username decryption error"})

    steamid64 = account['steamid64']
    if dec_username not in clients:
        return jsonify({"success": False, "error": "Account not logged in"})

    url = "https://api.steampowered.com/IPlayerService/GetOwnedGames/v0001/"
    params = {
        "key": STEAM_API_KEY,
        "steamid": steamid64,
        "include_appinfo": 1,
        "include_played_free_games": 1,
        "format": "json"
    }
    try:
        r = requests.get(url, params=params, verify=False)
        r.raise_for_status()
        data_json = r.json()
        if "response" not in data_json or "games" not in data_json["response"]:
            return jsonify({"success": True, "games": []})
        games = data_json["response"]["games"]
        result = [{"app_id": g["appid"], "name": g.get("name", f"App {g['appid']}")} for g in games]
        return jsonify({"success": True, "games": result})
    except Exception as e:
        logger.error(f"Error fetching games: {e}")
        return jsonify({"success": False, "error": str(e)})

@app.route('/update_account_games', methods=['POST'])
@login_required
def api_update_account_games():
    data = request.json
    account_id = data.get('account_id')
    games = data.get('games', [])
    user_id = session['user_id']

    conn = sqlite3.connect(DATABASE)
    account = conn.execute("SELECT id FROM accounts WHERE id=? AND user_id=?", (account_id, user_id)).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    add_games_for_account(account[0], games)
    return jsonify({"success": True, "count": len(games)})

@db_connection
def add_games_for_account(conn, account_id, games):
    cur = conn.cursor()
    cur.execute("DELETE FROM account_games WHERE account_id=?", (account_id,))
    for g in games:
        app_id = g['app_id']
        name = g['name']
        cur.execute("INSERT OR IGNORE INTO games (game_id, game_name) VALUES (?, ?)", (app_id, name))
        row = cur.execute("SELECT id FROM games WHERE game_id=?", (app_id,)).fetchone()
        if row:
            game_db_id = row['id']
            cur.execute("INSERT OR IGNORE INTO account_games (account_id, game_id) VALUES (?, ?)", (account_id, game_db_id))

@app.route('/ban_info', methods=['POST'])
@login_required
def api_ban_info():
    data = request.json
    account_id = data.get('account_id')
    if not account_id:
        return jsonify({"success": False, "error": "Account ID not provided"})

    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    account = conn.execute(
        "SELECT username, steamid64 FROM accounts WHERE id=? AND user_id=?",
        (account_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not account:
        return jsonify({"success": False, "error": "Account not found"})

    try:
        dec_username = fernet.decrypt(account['username'].encode()).decode()
    except:
        return jsonify({"success": False, "error": "Username decryption error"})

    if dec_username not in clients:
        return jsonify({"success": False, "error": "Account not logged in"})

    if not account["steamid64"]:
        return jsonify({"success": False, "error": "SteamID64 not found"})

    steamid64 = account["steamid64"]
    url = "https://api.steampowered.com/ISteamUser/GetPlayerBans/v1/"
    params = {
        "key": STEAM_API_KEY,
        "steamids": steamid64
    }
    try:
        r = requests.get(url, params=params, verify=False)
        r.raise_for_status()
        data_json = r.json()
        if "players" not in data_json or not data_json["players"]:
            return jsonify({"success": True, "bans": []})
        bans = data_json["players"][0]
        return jsonify({"success": True, "bans": bans})
    except Exception as e:
        logger.error(f"Error fetching ban info: {e}")
        return jsonify({"success": False, "error": str(e)})
        
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True, use_reloader=False)
