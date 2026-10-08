"""One-off: clear all test operations from the database (keeps the admin user)."""
import sqlite3
import os

db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db")
conn = sqlite3.connect(db_path)
cur = conn.cursor()

print("before:", cur.execute("SELECT COUNT(*) FROM operations").fetchone()[0])
cur.execute("DELETE FROM operations")
try:
    cur.execute("DELETE FROM sqlite_sequence WHERE name='operations'")
except sqlite3.OperationalError:
    pass
conn.commit()
print("after:", cur.execute("SELECT COUNT(*) FROM operations").fetchone()[0])
print("users:", cur.execute("SELECT id, username FROM users").fetchall())
conn.close()
