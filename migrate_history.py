import sqlite3, os

db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
c = sqlite3.connect(db)

# Кількість зараз
before = c.execute("SELECT COUNT(*) FROM remote_ping").fetchone()[0]
print(f"remote_ping ДО: {before}")

# Переносимо все з history_sync у remote_ping (з INSERT OR IGNORE)
moved = c.execute("""
    INSERT OR IGNORE INTO remote_ping (ts, target, ping_ms, jitter_ms, loss_pct)
    SELECT ts, '1.1.1.1', ping_ms, jitter_ms, loss_pct
    FROM remote_history_sync
    WHERE ping_ms > 0
""").rowcount
c.commit()

after = c.execute("SELECT COUNT(*) FROM remote_ping").fetchone()[0]
print(f"remote_ping ПІСЛЯ: {after}")
print(f"Перенесено: {moved} рядків")
