import sqlite3

username = input("Enter the username to make admin: ")

conn = sqlite3.connect("steam_accounts.db")
conn.execute("UPDATE users SET is_admin=1 WHERE username=?", (username,))
conn.commit()
conn.close()

print("Done! User is now admin.")