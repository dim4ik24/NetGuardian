import sqlite3, os
db = os.path.expanduser("~/.netguardian/forecast.db")
c = sqlite3.connect(db)
print("=== NET_IDs ===")
for r in c.execute("SELECT net_id, source, COUNT(1) FROM ping_log GROUP BY net_id, source"):
    print(" ", r)
