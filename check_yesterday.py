import sqlite3, os
db = os.path.expanduser("~/.netguardian/forecast.db")
c = sqlite3.connect(db)

# Вчорашня дата
from datetime import datetime, timedelta
yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
print(f"Yesterday: {yesterday}")
print()

# Скільки даних за вчора
total = c.execute("SELECT COUNT(*) FROM ping_log WHERE date(ts)=?", (yesterday,)).fetchone()[0]
print(f"Total rows за вчора: {total}")
print()

# По годинах
print("По годинах:")
for r in c.execute("""
    SELECT hour, AVG(ping_ms), COUNT(*)
    FROM ping_log
    WHERE date(ts)=?
    GROUP BY hour
    ORDER BY hour
""", (yesterday,)):
    flag = "← проблемна" if r[1] >= 80 else ""
    print(f"  {int(r[0]):02d}h: avg={r[1]:.1f}мс  cnt={r[2]}  {flag}")
