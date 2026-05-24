import sqlite3, os
print("\n=== PI CACHE ===")
db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
c = sqlite3.connect(db)
print("Total:", c.execute("SELECT COUNT(1) FROM remote_ping").fetchone()[0])
print("Last 10 min:", c.execute("SELECT COUNT(1) FROM remote_ping WHERE ts >= datetime('now', '-10 minutes', 'localtime')").fetchone()[0])
print("Last 5 ping:")
for r in c.execute("SELECT ts, target, ping_ms FROM remote_ping ORDER BY id DESC LIMIT 5"):
    print(" ", r)
print("Last heartbeat:")
for r in c.execute("SELECT ts FROM remote_heartbeat ORDER BY id DESC LIMIT 3"):
    print(" ", r)

print("\n=== FORECAST ===")
db = os.path.expanduser("~/.netguardian/forecast.db")
c = sqlite3.connect(db)
print("Total:", c.execute("SELECT COUNT(1) FROM ping_log").fetchone()[0])
print("By source:")
for r in c.execute("SELECT source, COUNT(1) FROM ping_log GROUP BY source"):
    print(" ", r)
print("Last 10 min:", c.execute("SELECT COUNT(1) FROM ping_log WHERE ts >= datetime('now', '-10 minutes', 'localtime')").fetchone()[0])
print("Last 5:")
for r in c.execute("SELECT ts, ping_ms, source FROM ping_log ORDER BY id DESC LIMIT 5"):
    print(" ", r)
