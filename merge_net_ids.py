"""
merge_net_ids.py
Об'єднує дві net_id у forecast.db в одну.
Безпечно: робить бекап і виводить що змінилось.
"""
import sqlite3
import os
import shutil
from datetime import datetime

DB = os.path.expanduser("~/.netguardian/forecast.db")

# ────── ВКАЖИ ТУТ ЯКА NET_ID ЦІЛЬОВА (куди мігруємо) ──────
# Та що тебе цікавить ЗАРАЗ — в яку UI зараз пише:
TARGET_NET_ID = "aec7a1bda7"   # активна (ПК пише сюди зараз)
SOURCE_NET_ID = "b3a2f53cac"   # стара (з якої беремо дані)


def main():
    if not os.path.exists(DB):
        print(f"❌ DB not found: {DB}")
        return

    # ── 1. Бекап ──
    backup = DB + f".PREMERGE-{datetime.now().strftime('%H%M%S')}"
    shutil.copy(DB, backup)
    print(f"✅ Бекап: {backup}")

    with sqlite3.connect(DB, timeout=10) as conn:
        c = conn.cursor()

        # ── 2. Поточний стан ──
        c.execute("""
            SELECT net_id, COUNT(1), MIN(ts), MAX(ts)
            FROM ping_log GROUP BY net_id
        """)
        print()
        print("=== ДО МІГРАЦІЇ ===")
        for r in c.fetchall():
            print(f"  net_id={r[0]:10s}  rows={r[1]:5d}  {r[2]} → {r[3]}")

        # ── 3. Об'єднання ──
        # У ping_log є UNIQUE-індекс на (ts, net_id, source)
        # Якщо одночасно у TARGET вже є запис із таким ts+source -
        # UPDATE дасть конфлікт. Тому використовуємо OR IGNORE
        # та потім видаляємо ті що не змогли мігрувати (вони дублікати).

        print()
        print(f"🔄 Мігрую {SOURCE_NET_ID} → {TARGET_NET_ID}...")

        # Спочатку — UPDATE OR IGNORE
        c.execute("""
            UPDATE OR IGNORE ping_log
            SET net_id = ?
            WHERE net_id = ?
        """, (TARGET_NET_ID, SOURCE_NET_ID))
        moved = c.rowcount

        # Тепер видалити записи що залишились у SOURCE (це дублікати)
        c.execute("""
            DELETE FROM ping_log WHERE net_id = ?
        """, (SOURCE_NET_ID,))
        deleted_dupes = c.rowcount

        conn.commit()

        print(f"✅ Перенесено: {moved} рядків")
        if deleted_dupes:
            print(f"🗑  Видалено дублікатів: {deleted_dupes}")

        # ── 4. Підсумок ──
        c.execute("""
            SELECT net_id, COUNT(1), MIN(ts), MAX(ts)
            FROM ping_log GROUP BY net_id
        """)
        print()
        print("=== ПІСЛЯ МІГРАЦІЇ ===")
        for r in c.fetchall():
            print(f"  net_id={r[0]:10s}  rows={r[1]:5d}  {r[2]} → {r[3]}")

        c.execute("SELECT COUNT(1) FROM ping_log")
        total = c.fetchone()[0]
        print()
        print(f"📊 ВСЬОГО рядків після міграції: {total}")
        print(f"   (до міграції було: {moved + deleted_dupes + total - moved})")

    print()
    print("🎉 ГОТОВО! Перезапусти NetGuardian — побачиш всі дані разом.")
    print(f"   Якщо щось пішло не так - відкат: copy '{backup}' '{DB}'")


if __name__ == "__main__":
    main()