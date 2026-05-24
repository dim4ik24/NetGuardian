import sqlite3, os
from datetime import datetime, timedelta

print("=== ДНІ ЗА 30 ДНІВ ===")
db = os.path.expanduser("~/.netguardian/forecast.db")
c = sqlite3.connect(db)

# Скільки днів реально мають дані
for r in c.execute("""
    SELECT date(ts), COUNT(1) as cnt, AVG(ping_ms) as p
    FROM ping_log
    WHERE ts >= datetime('now', '-30 days', 'localtime')
      AND ping_ms > 0
    GROUP BY date(ts) ORDER BY date(ts) DESC
"""):
    print(f"  {r[0]}: {r[1]:5d} вимірів, avg={r[2]:.1f}мс")

print()
print("=== ВСЬОГО УНІКАЛЬНИХ ДНІВ ===")
r = c.execute("""
    SELECT COUNT(DISTINCT date(ts)) FROM ping_log
    WHERE ts >= datetime('now', '-30 days', 'localtime')
""").fetchone()
print(f"  За 30 днів: {r[0]} різних днів")
