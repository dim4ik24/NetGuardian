import sqlite3, os
print("=== GAPS у Pi-кеші ===")
db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
c = sqlite3.connect(db)

# Останні 50 записів — побачимо коли була тиша
print("Останні 50 пінгів (timestamp та різниця):")
prev = None
for r in c.execute("SELECT ts FROM remote_ping ORDER BY id DESC LIMIT 50"):
    ts = r[0]
    if prev:
        from datetime import datetime
        d1 = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
        d2 = datetime.strptime(prev, "%Y-%m-%d %H:%M:%S")
        diff_min = (d2 - d1).total_seconds() / 60
        marker = " ⚠️ GAP!" if diff_min > 5 else ""
        print(f"  {ts}  (+{diff_min:.1f}хв){marker}")
    else:
        print(f"  {ts}")
    prev = ts
