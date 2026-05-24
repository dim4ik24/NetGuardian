"""
features/forecast/remote_source.py
─────────────────────────────────
Адаптер що дозволяє Forecast page читати дані з Raspberry Pi-агента
(через локальний кеш ~/.netguardian/pi_agent_cache.db, який наповнюється
MQTT-підписником у app.py).

ВАЖЛИВО: цей файл НЕ підключається до MQTT. Він тільки читає з SQLite-кешу,
який пише `mqtt_subscriber.py`. Це означає — навіть якщо Pi зараз offline
(нема інтернету), але вчора він зібрав 5000 пінгів, ця статистика все ще
доступна для аналізу історії.

ЯК ЦЕ ВИРІШУЄ ПРОБЛЕМУ:
  • Ноутбук вимкнений 18 годин — Forecast все одно отримує 18 годин даних
  • Можна побудувати тижневий heatmap навіть якщо ноут запускався 3 рази
  • Аналіз за добу/тиждень — повний, не з пробілами
"""

import sqlite3
import statistics
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# Та ж сама БД що й mqtt_subscriber пише
REMOTE_DB_PATH = Path.home() / ".netguardian" / "pi_agent_cache.db"


class RemoteForecastSource:
    """Читає дані Pi-агента з локального кешу і трансформує їх у формат
    зручний для ForecastEngine.
    
    Використання:
        src = RemoteForecastSource()
        if src.is_available():
            ping, jitter, loss = src.get_current_metrics()
            ...
    """

    # Скільки секунд після останнього heartbeat ще вважаємо Pi "живим"
    HEARTBEAT_TIMEOUT_SEC = 120
    # Скільки хвилин назад дивитись для "поточного стану"
    CURRENT_WINDOW_MIN = 5

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else REMOTE_DB_PATH

    # ── Публічний API ────────────────────────────────────────────────────

    def is_available(self) -> bool:
        """Чи є дані з Pi-агента (heartbeat недавній + є записи ping_log)?
        
        Якщо False — Forecast має використовувати локальні заміри.
        """
        if not self.db_path.exists():
            return False
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                # 1. Перевіряємо чи Pi онлайн (heartbeat за останні 2 хв)
                c = conn.execute(
                    "SELECT MAX(ts) FROM remote_heartbeat "
                    "WHERE ts >= datetime('now', '-2 minutes')"
                )
                last_hb = c.fetchone()[0]
                if not last_hb:
                    # Pi може бути offline але історія є
                    # — повертаємо True якщо є хоч щось за останні 24 год
                    c = conn.execute(
                        "SELECT COUNT(*) FROM remote_ping "
                        "WHERE ts >= datetime('now', '-1 day') "
                        "AND ping_ms > 0"
                    )
                    return c.fetchone()[0] >= 10  # мінімум 10 замірів
                # 2. Pi онлайн — є хоч 1 свіжий ping?
                c = conn.execute(
                    f"SELECT COUNT(*) FROM remote_ping "
                    f"WHERE ts >= datetime('now', '-{self.CURRENT_WINDOW_MIN} minutes') "
                    f"AND ping_ms > 0"
                )
                return c.fetchone()[0] > 0
        except Exception as e:
            print(f"[RemoteSrc] is_available error: {e}")
            return False

    def is_pi_online_now(self) -> bool:
        """Чи Pi надіслав heartbeat за останні 2 хв (live статус)."""
        if not self.db_path.exists():
            return False
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                c = conn.execute(
                    "SELECT MAX(ts) FROM remote_heartbeat "
                    "WHERE ts >= datetime('now', '-2 minutes')"
                )
                return c.fetchone()[0] is not None
        except Exception:
            return False

    def get_samples_count(self, days: int = 7) -> int:
        """Скільки валідних ping-замірів накопичено за період."""
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                c = conn.execute(
                    f"SELECT COUNT(*) FROM remote_ping "
                    f"WHERE ts >= datetime('now', '-{days} days') "
                    f"AND ping_ms > 0"
                )
                return c.fetchone()[0] or 0
        except Exception:
            return 0

    def get_current_metrics(self) -> Optional[tuple]:
        """Повертає (avg_ping_ms, jitter_ms, loss_pct).

        Адаптивне вікно: пробує 5хв, потім 30хв, потім 2 години.
        Це гарантує що ми не висимо коли Pi не встиг зробити нові заміри.
        """
        for window_min in (5, 30, 120):
            try:
                with sqlite3.connect(self.db_path, timeout=2) as conn:
                    c = conn.execute(f"""
                        SELECT AVG(ping_ms), AVG(loss_pct), COUNT(*)
                        FROM remote_ping
                        WHERE ts >= datetime('now', '-{window_min} minutes')
                          AND ping_ms > 0
                    """)
                    row = c.fetchone()
                    if not row or not row[2] or row[2] < 2:
                        continue   # пробуємо ширше вікно
                    avg_ping = round(row[0], 1)
                    avg_loss = round(row[1], 1)

                    # Jitter — stdev замірів у тому ж вікні
                    c = conn.execute(f"""
                        SELECT ping_ms FROM remote_ping
                        WHERE ts >= datetime('now', '-{window_min} minutes')
                          AND ping_ms > 0
                        ORDER BY id DESC LIMIT 30
                    """)
                    pings = [r[0] for r in c.fetchall()]
                    jitter = round(statistics.stdev(pings), 1) if len(pings) > 2 else 0.0

                    if window_min > 5:
                        print(f"[RemoteSrc] get_current_metrics: вікно розширено "
                              f"до {window_min}хв (Pi мовчить)")
                    return (avg_ping, jitter, avg_loss)
            except Exception as e:
                print(f"[RemoteSrc] get_current_metrics error (window {window_min}m): {e}")
                continue
        return None

    def get_history_summary(self, days: int = 7) -> Optional[dict]:
        """Загальна історична статистика за період.
        
        Повертає dict з полями:
          { global_avg, packet_loss_pct, hourly_data, weekly_data,
            best_hour, worst_hour, sla_pct, anomalies_count,
            samples_count, cyclone_hours }
        
        або None якщо мало даних.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                # Базова статистика
                c = conn.execute(f"""
                    SELECT AVG(ping_ms), AVG(loss_pct), COUNT(*)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0
                """)
                row = c.fetchone()
                if not row or not row[2] or row[2] < 10:
                    return None
                global_avg = round(row[0], 1)
                avg_loss = round(row[1], 2)
                samples = row[2]

                # Hourly pattern (24 години усереднені)
                c = conn.execute(f"""
                    SELECT 
                        CAST(strftime('%H', ts) AS INTEGER) AS hour,
                        AVG(ping_ms),
                        COUNT(*)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0
                    GROUP BY hour
                    ORDER BY hour
                """)
                hourly_data = {}
                for r in c.fetchall():
                    hourly_data[r[0]] = {"avg_ping": round(r[1], 1), "count": r[2]}

                # Weekly heatmap (7 днів × 24 години)
                # ВАЖЛИВО: формат {wday_python: {hour: avg_ping}} (nested),
                # бо UI рендер очікує саме такий вкладений словник.
                # SQLite strftime('%w'): 0=Sun..6=Sat
                # Python weekday():       0=Mon..6=Sun
                # Конверсія: py_dow = (sql_dow + 6) % 7
                weekly_data: dict = {}
                c = conn.execute(f"""
                    SELECT 
                        CAST(strftime('%w', ts) AS INTEGER) AS dow,
                        CAST(strftime('%H', ts) AS INTEGER) AS hour,
                        AVG(ping_ms)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0
                    GROUP BY dow, hour
                """)
                for r in c.fetchall():
                    sql_dow = int(r[0])
                    py_dow  = (sql_dow + 6) % 7   # Sun(0sql)→Sun(6py), Mon(1sql)→Mon(0py)
                    hour    = int(r[1])
                    weekly_data.setdefault(py_dow, {})[hour] = round(r[2], 1)

                # Best / Worst hour
                best_hour, worst_hour = (0, 0.0), (0, 0.0)
                if hourly_data:
                    sorted_h = sorted(hourly_data.items(),
                                      key=lambda x: x[1]["avg_ping"])
                    best_hour  = (sorted_h[0][0], sorted_h[0][1]["avg_ping"])
                    worst_hour = (sorted_h[-1][0], sorted_h[-1][1]["avg_ping"])

                # SLA = % замірів де ping < 100ms і loss < 5%
                c = conn.execute(f"""
                    SELECT COUNT(*) FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0 AND ping_ms < 100 AND loss_pct < 5
                """)
                good = c.fetchone()[0] or 0
                sla = round((good / samples) * 100, 2) if samples else 0.0

                # Аномалії = заміри де ping > global_avg * 3
                threshold = global_avg * 3 if global_avg > 0 else 1000
                c = conn.execute(f"""
                    SELECT COUNT(*) FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > ?
                """, (threshold,))
                anomalies = c.fetchone()[0] or 0

                # Cyclone hours — години з пінгом > 1.5× середнього
                cyclone_threshold = global_avg * 1.5
                cyclone_hours = [
                    h for h, d in hourly_data.items()
                    if d["avg_ping"] > cyclone_threshold
                ]

                return {
                    "global_avg":      global_avg,
                    "packet_loss_pct": avg_loss,
                    "hourly_data":     hourly_data,
                    "weekly_data":     weekly_data,
                    "best_hour":       best_hour,
                    "worst_hour":      worst_hour,
                    "sla_pct":         sla,
                    "anomalies_count": anomalies,
                    "samples_count":   samples,
                    "cyclone_hours":   cyclone_hours,
                }
        except Exception as e:
            print(f"[RemoteSrc] get_history_summary error: {e}")
            return None

    def get_per_day_forecast(self, days: int = 7) -> list[dict]:
        """Повертає прогноз на 7 днів вперед, базуючись на даних минулого тижня.
        
        Кожен елемент:
          {weekday: 0-6, avg_ping, risk_pct, best_hour, worst_hour}
        """
        result = []
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                # Збираємо середній ping для кожного (weekday, hour)
                c = conn.execute(f"""
                    SELECT 
                        CAST(strftime('%w', ts) AS INTEGER) AS dow,
                        CAST(strftime('%H', ts) AS INTEGER) AS hour,
                        AVG(ping_ms),
                        AVG(loss_pct)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0
                    GROUP BY dow, hour
                """)
                # day_data[dow] = list of (hour, avg_ping, avg_loss)
                day_data = {}
                for r in c.fetchall():
                    day_data.setdefault(r[0], []).append((r[1], r[2], r[3]))

                # Глобальний середній для відсотка ризику
                c = conn.execute(f"""
                    SELECT AVG(ping_ms) FROM remote_ping
                    WHERE ts >= datetime('now', '-{days} days')
                      AND ping_ms > 0
                """)
                global_avg = c.fetchone()[0] or 50

                # Сьогодні і наступні 6 днів
                today = datetime.now().weekday()  # 0=Mon..6=Sun (Python)
                # У SQLite strftime('%w') = 0 (Sun) .. 6 (Sat)
                # Конвертуємо у Python формат: dow_python = (dow_sql + 6) % 7
                for offset in range(7):
                    py_dow  = (today + offset) % 7
                    sql_dow = (py_dow + 1) % 7   # Mon(0py)=Mon(1sql)
                    rows = day_data.get(sql_dow, [])
                    if not rows:
                        # немає даних для цього дня
                        result.append({
                            "weekday": py_dow,
                            "avg_ping": 0,
                            "risk_pct": 0,
                            "best_hour": 0,
                            "worst_hour": 0,
                            "has_data": False,
                        })
                        continue
                    pings = [r[1] for r in rows]
                    avg_p = round(sum(pings) / len(pings), 1)
                    # Ризик: % годин з пінгом > 1.5× середнього
                    high_count = sum(1 for r in rows if r[1] > global_avg * 1.5)
                    risk = round((high_count / len(rows)) * 100)
                    # Best/Worst година
                    sorted_rows = sorted(rows, key=lambda x: x[1])
                    best_h  = sorted_rows[0][0]
                    worst_h = sorted_rows[-1][0]
                    result.append({
                        "weekday": py_dow,
                        "avg_ping": avg_p,
                        "risk_pct": risk,
                        "best_hour": best_h,
                        "worst_hour": worst_h,
                        "has_data": True,
                    })
        except Exception as e:
            print(f"[RemoteSrc] get_per_day_forecast error: {e}")
            return []
        return result

    def get_24h_pattern(self) -> list[tuple]:
        """24-годинний середній паттерн пінгу.
        Returns: [(hour, avg_ping), ...] для годин 0-23 що мають дані.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                c = conn.execute("""
                    SELECT 
                        CAST(strftime('%H', ts) AS INTEGER) AS hour,
                        AVG(ping_ms)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-1 day')
                      AND ping_ms > 0
                    GROUP BY hour
                    ORDER BY hour
                """)
                return [(r[0], round(r[1], 1)) for r in c.fetchall()]
        except Exception as e:
            print(f"[RemoteSrc] get_24h_pattern error: {e}")
            return []

    def get_recommended_times(self) -> dict:
        """Рекомендовані години для ігор/завантажень/стрімінгу.
        
        Returns: {
            'gaming':    {hour: int, ping: float},
            'downloads': {hour: int, ping: float},
            'streaming': {hour: int, ping: float}
        }
        """
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                c = conn.execute("""
                    SELECT 
                        CAST(strftime('%H', ts) AS INTEGER) AS hour,
                        AVG(ping_ms),
                        AVG(loss_pct)
                    FROM remote_ping
                    WHERE ts >= datetime('now', '-7 days')
                      AND ping_ms > 0
                    GROUP BY hour
                    HAVING COUNT(*) >= 3
                """)
                rows = c.fetchall()
                if not rows:
                    return {}
                # Сортуємо за різними критеріями
                # Gaming — мінімальний ping
                gaming    = sorted(rows, key=lambda x: x[1])[0]
                # Downloads — мінімальний loss + не дуже високий ping
                downloads = sorted(rows, key=lambda x: (x[2], x[1]))[0]
                # Streaming — стабільний ping (нижче середнього)
                streaming = sorted(rows, key=lambda x: x[1])[1] if len(rows) > 1 else gaming
                return {
                    "gaming":    {"hour": gaming[0],    "ping": round(gaming[1], 1)},
                    "downloads": {"hour": downloads[0], "ping": round(downloads[1], 1)},
                    "streaming": {"hour": streaming[0], "ping": round(streaming[1], 1)},
                }
        except Exception as e:
            print(f"[RemoteSrc] get_recommended_times error: {e}")
            return {}

    def get_latest_speedtest(self) -> Optional[dict]:
        """Останній speedtest з Pi (якщо є)."""
        try:
            with sqlite3.connect(self.db_path, timeout=2) as conn:
                c = conn.execute("""
                    SELECT ts, dl_mbps, ul_mbps, ping_ms, server
                    FROM remote_speedtest
                    ORDER BY id DESC LIMIT 1
                """)
                row = c.fetchone()
                if row:
                    return {
                        "ts": row[0], "dl_mbps": row[1],
                        "ul_mbps": row[2], "ping_ms": row[3],
                        "server": row[4],
                    }
        except Exception:
            pass
        return None