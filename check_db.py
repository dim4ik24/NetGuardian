import sqlite3, os
db = os.path.expanduser('~/.netguardian/forecast.db')
c = sqlite3.connect(db)

print('=== TOTAL ===')
print('Rows:', c.execute('SELECT COUNT(1) FROM ping_log').fetchone()[0])

print()
print('=== BY NET_ID + SOURCE ===')
for r in c.execute('SELECT net_id, source, COUNT(1) FROM ping_log GROUP BY net_id, source ORDER BY 3 DESC'):
    print(' ', r)

print()
print('=== TODAY by NET_ID ===')
for r in c.execute("SELECT net_id, COUNT(1) FROM ping_log WHERE date(ts)=date('now','localtime') GROUP BY net_id"):
    print(' ', r)

print()
print('=== FIRST/LAST timestamp per NET_ID ===')
for r in c.execute('SELECT net_id, MIN(ts), MAX(ts), COUNT(1) FROM ping_log GROUP BY net_id'):
    print(' ', r)

print()
print('=== LAST 10 ROWS ===')
for r in c.execute('SELECT ts, ping_ms, source, net_id FROM ping_log ORDER BY id DESC LIMIT 10'):
    print(' ', r)