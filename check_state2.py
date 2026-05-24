import sqlite3, os
from datetime import datetime, timedelta

print("=== PI CACHE ===")
db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
c = sqlite3.connect(db)

# За останні 2 год
total = c.execute("""
    SELECT COUNT(1) FROM remote_ping
    WHERE ts >= datetime('now', '-2 hours', 'localtime')
""").fetchone()[0]
print(f"За 2 год: {total} вимірів")

# Розподіл по 30-хв періодах за 2 год
print("\nПо півгодинах:")
for r in c.execute("""
    SELECT
        strftime('%H:%M', ts, '-' || (CAST(strftime('%M', ts) AS INTEGER) % 30) || ' minutes') as period,
        COUNT(1)
    FROM remote_ping
    WHERE ts >= datetime('now', '-2 hours', 'localtime')
    GROUP BY period ORDER BY period
"""):
    print(f"  {r[0]}: {r[1]}")

# Останні 5
print("\nОстанні 5 пінгів:")
for r in c.execute("SELECT ts, target, ping_ms FROM remote_ping ORDER BY id DESC LIMIT 5"):
    print(f"  {r[0]} → {r[1]} = {r[2]:.1f}мс")

# Heartbeat
print("\nОстанні 3 heartbeat:")
for r in c.execute("SELECT ts FROM remote_heartbeat ORDER BY id DESC LIMIT 3"):
    print(f"  {r[0]}")

print("\n=== FORECAST.DB ===")
db2 = os.path.expanduser("~/.netguardian/forecast.db")
c2 = sqlite3.connect(db2)
for r in c2.execute("""
    SELECT source, COUNT(1) FROM ping_log
    WHERE ts >= datetime('now', '-2 hours', 'localtime')
    GROUP BY source
"""):
    print(f"  {r[0]}: {r[1]}")
