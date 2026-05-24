# core/database.py
import sqlite3
import os
import time


class DatabaseManager:
    """Менеджер локальної бази даних SQLite для NetGuardian AI"""

    def __init__(self):
        # База даних — у папці data/ в корені проєкту
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        data_dir = os.path.join(base_dir, "data")
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, "netguardian_data.db")

        # Підключаємося (якщо файлу немає - він створиться)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()

        # 1. Таблиця для AI Forecast (Історія пінгу)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS ping_log (
                timestamp REAL PRIMARY KEY,
                ping_ms REAL,
                hour INTEGER,
                weekday INTEGER
            )
        """)

        # 2. Таблиця для LAN Security Audit (Довірені пристрої)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS lan_devices (
                mac_address TEXT PRIMARY KEY,
                ip_address TEXT,
                vendor TEXT,
                first_seen REAL,
                total_hours_online REAL DEFAULT 0,
                is_trusted INTEGER DEFAULT 0
            )
        """)

        self.conn.commit()

    # --- МЕТОДИ ДЛЯ ПІНГУ ---
    def add_ping_record(self, ping_ms):
        """Записує новий пінг у базу"""
        if ping_ms < 0:
            return  # Ігноруємо таймаути для середньої статистики

        now = time.time()
        t = time.localtime(now)
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                "INSERT OR IGNORE INTO ping_log (timestamp, ping_ms, hour, weekday) VALUES (?, ?, ?, ?)",
                (now, ping_ms, t.tm_hour, t.tm_wday)
            )
            self.conn.commit()
        except Exception as e:
            # Не критично — просто пропускаємо запис
            print(f"[DB] add_ping_record error: {e}")

    def get_hourly_average(self):
        """Повертає середній пінг для кожної години (для графіків)"""
        try:
            cursor = self.conn.cursor()
            cursor.execute("SELECT hour, AVG(ping_ms) FROM ping_log GROUP BY hour")
            return cursor.fetchall()
        except Exception:
            return []

    # --- МЕТОДИ ДЛЯ LAN SECURITY ---
    def update_lan_device(self, mac, ip, vendor):
        """Реєструє пристрій у мережі або оновлює час його перебування"""
        if not mac or mac == "—":
            return

        now = time.time()
        cursor = self.conn.cursor()

        # Перевіряємо, чи є вже такий пристрій
        cursor.execute("SELECT first_seen, total_hours_online FROM lan_devices WHERE mac_address=?", (mac,))
        row = cursor.fetchone()

        if row:
            first_seen, total_hours = row
            hours_since_first = (now - first_seen) / 3600.0
            is_trusted = 1 if hours_since_first >= 48 else 0

            cursor.execute("""
                UPDATE lan_devices
                SET ip_address=?, total_hours_online=?, is_trusted=?
                WHERE mac_address=?
            """, (ip, hours_since_first, is_trusted, mac))
        else:
            cursor.execute("""
                INSERT INTO lan_devices (mac_address, ip_address, vendor, first_seen, total_hours_online, is_trusted)
                VALUES (?, ?, ?, ?, 0, 0)
            """, (mac, ip, vendor, now))

        self.conn.commit()

    def check_device_trust(self, mac):
        """Повертає статус довіри пристрою (True/False)"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT is_trusted FROM lan_devices WHERE mac_address=?", (mac,))
        row = cursor.fetchone()
        return bool(row[0]) if row else False


# Створюємо глобальний екземпляр бази даних, який можна імпортувати в інші файли
db = DatabaseManager()