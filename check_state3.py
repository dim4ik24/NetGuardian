import sqlite3, os
from datetime import datetime, timedelta

print("=== PI CACHE (remote_ping) ===")
db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
c = sqlite3.connect(db)
total = c.execute("SELECT COUNT(1) FROM remote_ping").fetchone()[0]
print(f"Total у remote_ping: {total}")

# За останні 24 години
last24 = c.execute("""
    SELECT COUNT(1) FROM remote_ping
    WHERE ts >= datetime('now', '-24 hours', 'localtime')
""").fetchone()[0]
print(f"За 24 год: {last24}")

# Що в history_sync
total_h = c.execute("SELECT COUNT(1) FROM remote_history_sync").fetchone()[0]
print(f"Total у remote_history_sync: {total_h}")

print("\n=== FORECAST.DB ===")
db2 = os.path.expanduser("~/.netguardian/forecast.db")
c2 = sqlite3.connect(db2)
total2 = c2.execute("""
    SELECT COUNT(1) FROM ping_log
    WHERE ts >= datetime('now', '-12 hours', 'localtime')
""").fetchone()[0]
print(f"За 12 год: {total2}")
for r in c2.execute("""
    SELECT source, COUNT(1) FROM ping_log
    WHERE ts >= datetime('now', '-12 hours', 'localtime')
    GROUP BY source
"""):
    print(f"  {r[0]}: {r[1]}")
