import sqlite3, os
db = os.path.expanduser("~/.netguardian/forecast.db")
c = sqlite3.connect(db)
c.execute("DELETE FROM report_history WHERE report_type='catchup'")
c.commit()
print("✅ catchup маркер очищено")

# Дивимось останній session_marker
row = c.execute("SELECT shown_at FROM report_history WHERE report_type='session'").fetchone()
print(f"Last session: {row[0] if row else 'НЕМАЄ'}")
