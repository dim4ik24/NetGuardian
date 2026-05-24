"""
features/forecast/smart_scheduler.py

Розумний планувальник звітів NetGuardian. Працює за принципом
"перший запуск" — перевіряє чи був звіт за вчорашню добу/минулий тиждень,
і генерує його при першому запуску ПК у новій добі/тижні.

Алгоритм:
  1. При старті програми перевіряємо `report_history` у forecast.db
  2. Якщо за вчорашню дату (today_key) ще не було daily-звіту:
       a) Будуємо звіт через engine.get_daily_report(force=True)
       b) Шлемо у Telegram
       c) Зберігаємо у dashboard для popup
       d) Маркуємо як показаний
  3. Якщо неділя і ще не було weekly-звіту:
       аналогічно для тижня
  4. Telegram-аларм на «бурю» — кожні 5 хв перевіряємо storm-alert

Перевага над _WeatherScheduler у bot.py:
  • Працює "при старті" а не "о 00:00"
  • Дедуплікація через БД
  • Звіти йдуть навіть якщо ПК спав
  • Інтегрований з UI popup
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Callable


def _safe_format_catchup(report: dict) -> str:
    """Форматує catch-up звіт за період коли програма була вимкнена."""
    if not report:
        return "📡 *Catch-up*\n\n_Програма була вимкнена, але дані Pi не зібрані._"

    start = report.get("start", "—")
    end   = report.get("end",   "—")
    gap   = report.get("gap_hours", 0)

    avg_ping = report.get("avg_ping", 0)
    min_ping = report.get("min_ping", 0)
    max_ping = report.get("max_ping", 0)
    avg_loss = report.get("avg_loss", 0)
    samples  = report.get("measurements", 0)
    blackouts = report.get("blackouts", 0)

    if avg_ping < 30:
        icon = "☀️"
    elif avg_ping < 80:
        icon = "⛅"
    elif avg_ping < 150:
        icon = "🌧"
    else:
        icon = "⛈"

    lines = [
        f"📡 *Catch-up звіт NetGuardian*",
        f"",
        f"⏱ Програма була вимкнена *{gap:.1f} год*",
        f"📅 з `{start}`",
        f"📅 по `{end}`",
        f"",
        f"_Дані зібрані з Raspberry Pi (агент 24/7)_",
        f"",
        f"{icon} *Стан мережі за цей період:*",
        f"  • Середній ping: `{avg_ping:.1f} мс`",
        f"  • Мін / Макс: `{min_ping:.1f} / {max_ping:.1f} мс`",
        f"  • Втрати: `{avg_loss:.2f}%`",
        f"  • Вимірів Pi: `{samples}`",
    ]

    if blackouts > 0:
        lines.append("")
        lines.append(f"⚠️ *Обривів інтернету:* `{blackouts}`")

    worst = report.get("worst_hours", [])
    if worst and worst[0]["avg_ping"] > 80:
        lines.append("")
        lines.append(f"🌪 *Найгірші години у gap-періоді:*")
        for h in worst:
            lines.append(
                f"  • `{h['hour']:02d}:00` — "
                f"avg {h['avg_ping']:.0f} мс, max {h['max_ping']:.0f} мс"
            )

    lines.append("")
    lines.append("_Запам'ятав цей gap. Тепер моніторинг продовжується._")

    return "\n".join(lines)


def _safe_format_daily(report: dict) -> str:
    """Форматує добовий звіт для Telegram у Markdown (РОЗШИРЕНА версія)."""
    if not report:
        return "📊 *Денний звіт NetGuardian*\n\n_Недостатньо даних за вчора._"

    date = report.get("date", "—")
    net  = report.get("network", "")

    avg_ping = report.get("avg_ping", 0)
    min_ping = report.get("min_ping", 0)
    max_ping = report.get("max_ping", 0)
    avg_jit  = report.get("avg_jitter", 0)
    avg_loss = report.get("avg_loss", 0)
    samples  = report.get("measurements", 0)
    blackouts = report.get("blackouts", 0)

    # Іконка погоди по середньому ping
    if avg_ping < 30:
        icon, weather = "☀️", "Сонячно (швидко)"
    elif avg_ping < 80:
        icon, weather = "⛅", "Хмарно (стерпно)"
    elif avg_ping < 150:
        icon, weather = "🌧", "Дощ (повільно)"
    else:
        icon, weather = "⛈", "Шторм (критично)"

    lines = [
        f"📊 *Звіт за добу: {date}*",
        f"🌐 Мережа: `{net}`",
        f"",
        f"{icon} *{weather}*",
        f"",
        f"📈 *Статистика пінгу:*",
        f"  • Середній: `{avg_ping:.1f} мс`",
        f"  • Мін / Макс: `{min_ping:.1f} / {max_ping:.1f} мс`",
        f"  • Jitter: `{avg_jit:.1f} мс`",
        f"  • Втрати: `{avg_loss:.2f}%`",
        f"  • Вимірів: `{samples}`",
    ]

    if blackouts > 0:
        lines.append("")
        lines.append(f"⚠️ *Обривів інтернету:* `{blackouts}`")

    # ── Найкращі години (загальні) ──
    best_hours = report.get("best_hours", [])
    if best_hours:
        lines.append("")
        lines.append(f"🏆 *Найкращі години (загалом):*")
        for h in best_hours:
            lines.append(f"  • `{h['hour']:02d}:00` — {h['avg_ping']:.0f} мс")

    # ── Найкращий час для категорій ──
    cat_emojis = [
        ("best_for_gaming",    "🎮", "Ігри",     "(пінг ≤ 50 мс)"),
        ("best_for_streaming", "📺", "Стрімінг", "(пінг ≤ 80 мс)"),
        ("best_for_work",      "💼", "Робота",   "(пінг ≤ 150 мс)"),
    ]
    has_cat = False
    for key, emoji, name, condition in cat_emojis:
        hours = report.get(key, [])
        if hours:
            if not has_cat:
                lines.append("")
                lines.append(f"⏰ *Найкращий час за категоріями:*")
                has_cat = True
            hour_strs = [f"`{h['hour']:02d}:00`" for h in hours]
            lines.append(f"  {emoji} *{name}* {condition}:")
            lines.append(f"     {', '.join(hour_strs)}")

    # ── Глобальні сервіси ──
    services = report.get("services", {})
    if services:
        lines.append("")
        lines.append(f"🌍 *Глобальні сервіси (поточний стан):*")
        cat_names = [
            ("gaming",    "🎮", "Ігри"),
            ("streaming", "📺", "Стрімінг"),
            ("work",      "💼", "Робота"),
            ("general",   "🌐", "DNS/Інші"),
        ]
        for cat_key, emoji, name in cat_names:
            cat = services.get(cat_key, {})
            up   = cat.get("up", 0)
            down = cat.get("down", 0)
            if up + down > 0:
                status_icon = "🟢" if down == 0 else ("🟡" if up > down else "🔴")
                lines.append(f"  {emoji} *{name}*: {status_icon} {up}/{up+down}")

    # ── Циклони (найгірші години провайдера) ──
    worst_hours = report.get("worst_hours", [])
    if worst_hours and worst_hours[0]["avg_ping"] > 80:
        lines.append("")
        lines.append(f"🌪 *Циклони провайдера (найгірші години):*")
        for h in worst_hours:
            loss_str = f", {h['loss']:.1f}% loss" if h['loss'] > 1 else ""
            lines.append(
                f"  • `{h['hour']:02d}:00` — "
                f"avg {h['avg_ping']:.0f} мс, max {h['max_ping']:.0f} мс{loss_str}"
            )

    lines.append("")
    lines.append("_Сформовано автоматично при першому запуску NetGuardian._")

    return "\n".join(lines)


def _safe_format_weekly(report: dict) -> str:
    """Форматує тижневий звіт для Telegram (РОЗШИРЕНА версія)."""
    if not report:
        return "📅 *Тижневий звіт NetGuardian*\n\n_Недостатньо даних за тиждень._"

    week = report.get("week", "—")
    net  = report.get("network", "")

    avg_ping  = report.get("avg_ping", 0)
    min_ping  = report.get("min_ping", 0)
    max_ping  = report.get("max_ping", 0)
    avg_jit   = report.get("avg_jitter", 0)
    avg_loss  = report.get("avg_loss", 0)
    samples   = report.get("measurements", 0)
    blackouts = report.get("blackouts", 0)

    best_day   = report.get("best_day")
    best_dp    = report.get("best_day_ping")
    worst_day  = report.get("worst_day")
    worst_dp   = report.get("worst_day_ping")

    DAYS_FULL = ["Понеділок", "Вівторок", "Середа", "Четвер",
                 "П'ятниця", "Субота", "Неділя"]
    DAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]

    if avg_ping < 30:
        icon, weather = "☀️", "Сонячний тиждень"
    elif avg_ping < 80:
        icon, weather = "⛅", "Перемінна хмарність"
    elif avg_ping < 150:
        icon, weather = "🌧", "Дощовий тиждень"
    else:
        icon, weather = "⛈", "Штормовий тиждень"

    lines = [
        f"📅 *Тижневий звіт: {week}*",
        f"🌐 Мережа: `{net}`",
        f"",
        f"{icon} *{weather}*",
        f"",
        f"📈 *Підсумок тижня:*",
        f"  • Середній ping: `{avg_ping:.1f} мс`",
        f"  • Мін / Макс: `{min_ping:.1f} / {max_ping:.1f} мс`",
        f"  • Jitter: `{avg_jit:.1f} мс`",
        f"  • Втрати: `{avg_loss:.2f}%`",
        f"  • Замірів: `{samples}`",
    ]

    if blackouts > 0:
        lines.append("")
        lines.append(f"⚠️ *Обривів інтернету:* `{blackouts}`")

    if best_day is not None:
        lines.append("")
        lines.append(
            f"🏆 *Найкращий день:* `{DAYS_FULL[best_day]}` "
            f"({best_dp:.0f} мс)"
        )
    if worst_day is not None:
        lines.append(
            f"😔 *Найгірший день:* `{DAYS_FULL[worst_day]}` "
            f"({worst_dp:.0f} мс)"
        )

    # ── Середній по днях ──
    day_stats = report.get("day_stats", {})
    if day_stats:
        lines.append("")
        lines.append(f"📊 *Середній пінг по днях:*")
        for wd in range(7):
            if wd in day_stats:
                bar = "▓" * min(int(day_stats[wd] / 10), 10)
                lines.append(f"  `{DAYS[wd]}` `{day_stats[wd]:5.1f}` мс  {bar}")

    # ── Найкращі дні для категорій ──
    cat_emojis = [
        ("best_days_gaming",    "🎮", "Ігри",     "(пінг ≤ 50 мс)"),
        ("best_days_streaming", "📺", "Стрімінг", "(пінг ≤ 80 мс)"),
        ("best_days_work",      "💼", "Робота",   "(пінг ≤ 150 мс)"),
    ]
    has_cat = False
    for key, emoji, name, condition in cat_emojis:
        days = report.get(key, [])
        if days:
            if not has_cat:
                lines.append("")
                lines.append(f"📆 *Найкращі дні за категоріями:*")
                has_cat = True
            day_strs = [
                f"`{DAYS[d['weekday']]}` ({d['avg_ping']:.0f} мс)"
                for d in days
            ]
            lines.append(f"  {emoji} *{name}* {condition}:")
            lines.append(f"     {', '.join(day_strs)}")

    # ── Найкращі ГОДИНИ за тиждень за категоріями ──
    cat_emojis_h = [
        ("best_for_gaming",    "🎮", "Ігри"),
        ("best_for_streaming", "📺", "Стрімінг"),
        ("best_for_work",      "💼", "Робота"),
    ]
    has_h = False
    for key, emoji, name in cat_emojis_h:
        hours = report.get(key, [])
        if hours:
            if not has_h:
                lines.append("")
                lines.append(f"⏰ *Найкращі години за тиждень:*")
                has_h = True
            hour_strs = [f"`{h['hour']:02d}:00`" for h in hours]
            lines.append(f"  {emoji} *{name}*: {', '.join(hour_strs)}")

    # ── Глобальні сервіси ──
    services = report.get("services", {})
    if services:
        lines.append("")
        lines.append(f"🌍 *Глобальні сервіси (поточний стан):*")
        cat_names = [
            ("gaming",    "🎮", "Ігри"),
            ("streaming", "📺", "Стрімінг"),
            ("work",      "💼", "Робота"),
            ("general",   "🌐", "DNS/Інші"),
        ]
        for cat_key, emoji, name in cat_names:
            cat = services.get(cat_key, {})
            up   = cat.get("up", 0)
            down = cat.get("down", 0)
            if up + down > 0:
                status_icon = "🟢" if down == 0 else ("🟡" if up > down else "🔴")
                lines.append(f"  {emoji} *{name}*: {status_icon} {up}/{up+down}")

    # ── Циклони провайдера: ДНІ ──
    worst_days = report.get("worst_days", [])
    if worst_days and worst_days[0]["avg_ping"] > 80:
        lines.append("")
        lines.append(f"🌪 *Циклони провайдера (найгірші дні):*")
        for d in worst_days:
            loss_str = f", {d['loss']:.1f}% loss" if d['loss'] > 1 else ""
            lines.append(
                f"  • `{DAYS_FULL[d['weekday']]}` — "
                f"avg {d['avg_ping']:.0f} мс, max {d['max_ping']:.0f} мс{loss_str}"
            )

    # ── Циклони: ГОДИНИ ──
    worst_hours = report.get("worst_hours", [])
    if worst_hours and worst_hours[0]["avg_ping"] > 80:
        lines.append("")
        lines.append(f"🕐 *Найгірші години тижня:*")
        for h in worst_hours:
            loss_str = f", {h['loss']:.1f}% loss" if h['loss'] > 1 else ""
            lines.append(
                f"  • `{h['hour']:02d}:00` — "
                f"avg {h['avg_ping']:.0f} мс, max {h['max_ping']:.0f} мс{loss_str}"
            )

    lines.append("")
    lines.append("_Сформовано автоматично при першому запуску у понеділок._")

    return "\n".join(lines)


class SmartScheduler:
    """
    Розумний планувальник звітів. Використовується так:

        scheduler = SmartScheduler(engine)
        scheduler.set_telegram(token, chat_id)
        scheduler.set_popup_callback(my_popup_handler)
        scheduler.run_at_startup()  # викликати при старті програми
    """

    def __init__(self, engine, db_path: Optional[Path] = None):
        self.engine = engine
        self.db_path = db_path or (Path.home() / ".netguardian" / "forecast.db")
        self.token: Optional[str] = None
        self.chat_id: Optional[str] = None
        self._popup_callback: Optional[Callable] = None
        self._started = False
        # Можна підключити інстанс _TelegramAPI з bot.py — тоді не робимо
        # окреме HTTP-з'єднання
        self._bot_api = None

    def set_telegram(self, token: str, chat_id: str):
        """Налаштовує Telegram-нотифікацію (сирий HTTP — fallback)."""
        self.token   = token
        self.chat_id = str(chat_id)

    def set_bot_api(self, api, chat_id: str):
        """
        Налаштовує SmartScheduler на використання інстансу _TelegramAPI
        з bot.py. Це КРАЩЕ ніж сирий HTTP — використовує одну сесію.

        Має метод send(chat_id, text, parse_mode='Markdown')
        """
        self._bot_api = api
        self.chat_id  = str(chat_id)

    def set_popup_callback(self,
                            callback: Callable[[str, dict], None]):
        """
        Реєструє функцію яка покаже popup в UI.

        Сигнатура: callback(report_type, report_dict)
            report_type: "daily" або "weekly"
            report_dict: повний dict звіту
        """
        self._popup_callback = callback

    def _send_telegram(self, text: str) -> bool:
        """Шле повідомлення в Telegram. Повертає True/False.

        Стратегія:
          1. Якщо є _bot_api (з bot.py) — використовуємо його (бажано)
          2. Інакше — сирий HTTP через requests
        """
        # СТРАТЕГІЯ 1: через bot.py _TelegramAPI
        if self._bot_api is not None and self.chat_id:
            try:
                self._bot_api.send(self.chat_id, text)
                return True
            except Exception as e:
                print(f"[SmartScheduler] bot.send() error: {e}")
                # fall through до HTTP

        # СТРАТЕГІЯ 2: сирий HTTP
        if not self.token or not self.chat_id:
            return False
        try:
            import requests
            r = requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                json={
                    "chat_id":    self.chat_id,
                    "text":       text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            return r.status_code == 200
        except Exception as e:
            print(f"[SmartScheduler] Telegram send error: {e}")
            return False

    # ── PUBLIC API для bot.py (команди /daily, /weekly, /pi_status) ──────
    def force_send_daily(self) -> tuple[bool, str]:
        """
        Примусово надсилає daily-звіт у Telegram (для /daily команди).
        Повертає (success, message).
        """
        try:
            report = self._build_daily_for_yesterday()
            if not report:
                return False, "Недостатньо даних за вчора"

            text = _safe_format_daily(report)
            if self._send_telegram(text):
                return True, f"Daily звіт за {report.get('date')} надіслано"
            return False, "Не вдалось надіслати у Telegram"
        except Exception as e:
            return False, f"Помилка: {e}"

    def force_send_weekly(self) -> tuple[bool, str]:
        """Примусово надсилає weekly-звіт."""
        try:
            report = self._build_weekly_for_last_week()
            if not report:
                return False, "Недостатньо даних за тиждень"

            text = _safe_format_weekly(report)
            if self._send_telegram(text):
                return True, f"Weekly звіт за {report.get('week')} надіслано"
            return False, "Не вдалось надіслати у Telegram"
        except Exception as e:
            return False, f"Помилка: {e}"

    def get_pi_status_text(self) -> str:
        """Повертає текст статусу Pi для команди /pi_status."""
        try:
            from datetime import datetime
            pi_db = Path.home() / ".netguardian" / "pi_agent_cache.db"
            if not pi_db.exists():
                return "🔴 *Raspberry Pi*\n\n_БД відсутня — subscriber не запущено._"

            with sqlite3.connect(pi_db, timeout=3) as conn:
                c = conn.cursor()

                # Heartbeat
                hb_age = None
                try:
                    c.execute("""
                        SELECT MAX(ts), cpu_temp, uptime_sec
                        FROM remote_heartbeat
                    """)
                    row = c.fetchone()
                    if row and row[0]:
                        hb_ts = row[0]
                        cpu_temp = row[1]
                        uptime = row[2]
                        try:
                            hb_dt = datetime.strptime(hb_ts, "%Y-%m-%d %H:%M:%S")
                            hb_age = (datetime.now() - hb_dt).total_seconds()
                        except Exception:
                            pass
                except Exception:
                    cpu_temp, uptime = None, None

                # Ping за різні періоди
                c.execute("""
                    SELECT COUNT(*) FROM remote_ping
                    WHERE ts >= datetime('now', '-1 hour', 'localtime')
                """)
                ping_1h = c.fetchone()[0]

                c.execute("""
                    SELECT COUNT(*) FROM remote_ping
                    WHERE ts >= datetime('now', '-24 hours', 'localtime')
                """)
                ping_24h = c.fetchone()[0]

                c.execute("SELECT COUNT(*) FROM remote_ping")
                ping_total = c.fetchone()[0]

            # Визначаємо стан
            if hb_age is None:
                status = "🔴 *Raspberry Pi: OFFLINE*"
            elif hb_age < 90:
                status = "🟢 *Raspberry Pi: ONLINE*"
            elif hb_age < 600:
                status = "🟡 *Raspberry Pi: ВТРАЧЕНИЙ ЗВ'ЯЗОК*"
            else:
                status = "🔴 *Raspberry Pi: OFFLINE*"

            lines = [status, ""]

            if cpu_temp is not None:
                lines.append(f"🌡 *CPU temp:* `{cpu_temp}°C`")
            if uptime is not None:
                hours = uptime // 3600
                mins = (uptime % 3600) // 60
                lines.append(f"⏱ *Uptime:* `{hours}год {mins}хв`")
            if hb_age is not None:
                lines.append(f"💓 *Останній heartbeat:* `{int(hb_age)} сек тому`")

            lines.append("")
            lines.append(f"📊 *Pings зібрано:*")
            lines.append(f"  • За годину: `{ping_1h}`")
            lines.append(f"  • За добу: `{ping_24h}`")
            lines.append(f"  • Всього: `{ping_total}`")

            return "\n".join(lines)
        except Exception as e:
            return f"❌ Помилка отримання статусу Pi: {e}"

    def force_storm_test(self) -> tuple[bool, str]:
        """Примусово надсилає тестовий шторм-аларм."""
        msg = (
            "⚡ *STORM ALERT — NetGuardian (TEST)*\n\n"
            "🌪 Це тестовий аларм для перевірки роботи системи.\n\n"
            "_Реальні аларми приходять автоматично коли:_\n"
            "  • Середній ping за 10 хв > 200 мс\n"
            "  • Втрати пакетів > 30%\n\n"
            "_Cooldown між алармами: 30 хв._"
        )
        if self._send_telegram(msg):
            return True, "Тестовий аларм надіслано"
        return False, "Не вдалось надіслати"

    def run_at_startup(self, delay_sec: int = 8):
        """
        Запускає перевірку через delay_sec секунд після старту.
        Це дає змогу subscriber'у спочатку отримати свіжі дані з Pi.
        """
        if self._started:
            return
        self._started = True

        def worker():
            time.sleep(delay_sec)
            print(f"[SmartScheduler] 🚀 Старт перевірки (delay={delay_sec}s)")
            print(f"[SmartScheduler]   bot_api={'OK' if self._bot_api else 'NONE'}")
            print(f"[SmartScheduler]   chat_id={'SET' if self.chat_id else 'NONE'}")
            print(f"[SmartScheduler]   db_path={self.db_path}")
            try:
                self._check_and_send_reports()
            except Exception as e:
                import traceback
                print(f"[SmartScheduler] ❌ error: {e}")
                traceback.print_exc()

            # Запускаємо фоновий потік для перевірки storm alert
            self._start_storm_loop()
            # PR #6: запускаємо моніторинг Pi
            self._start_pi_monitor_loop()
            # PR #7: пінгуємо Pi щоб він знав що клієнт живий
            self._start_client_pinger()
            # PR #8: щохвилини оновлюємо session marker для коректного catch-up
            self._start_session_heartbeat()

        threading.Thread(target=worker, daemon=True, name="SmartScheduler").start()

    # ── SESSION HEARTBEAT (оновлює мітку last_session_end щохвилини) ──
    def _start_session_heartbeat(self):
        """Щохвилини оновлює мітку last_session_end, щоб при виході вона
        містила час ~хвилину тому. При наступному старті ця мітка дає
        правильний gap = (now - last_marker) ≈ час коли програма не була запущена.
        """
        def loop():
            while True:
                try:
                    time.sleep(60)
                    self._update_session_marker()
                except Exception as e:
                    print(f"[SmartScheduler] session heartbeat error: {e}")

        threading.Thread(target=loop, daemon=True,
                         name="SessionHeartbeat").start()

    # ── CLIENT PINGER LOOP (PR #7) ───────────────────────────────────────
    # Кожні 10 хв шлемо cmd/ping → Pi оновлює ~/.netguardian-agent/client_seen.txt
    # Так Pi-side monitor (cron) знає що клієнт живий.
    def _start_client_pinger(self):
        """Фоновий потік що раз на 10 хв шле cmd/ping у Pi.

        Це дає Pi-side скрипту інформацію про "живість" ПК — якщо клієнт
        не з'являвся > 30 хв, незалежний моніторинг на Pi надішле alert
        у Telegram про те, що клієнт-комп'ютер offline.
        """
        def loop():
            time.sleep(60)  # перший пінг через хвилину
            while True:
                try:
                    sub = self._get_subscriber()
                    if sub:
                        ok = sub.send_command("ping", {"ts": int(time.time())})
                        if ok:
                            print("[SmartScheduler] 📡 client-ping → Pi")
                    time.sleep(10 * 60)  # кожні 10 хв
                except Exception as e:
                    print(f"[SmartScheduler] client-pinger error: {e}")
                    time.sleep(60)

        threading.Thread(target=loop, daemon=True, name="ClientPinger").start()
        print("[SmartScheduler] ✅ ClientPinger запущений (cmd/ping кожні 10 хв)")

    @staticmethod
    def _get_subscriber():
        """Знаходить активний MQTT-subscriber щоб через нього публікувати."""
        try:
            from features.forecast.mqtt_subscriber import get_global_subscriber
            return get_global_subscriber()
        except Exception:
            try:
                from features.forecast import mqtt_subscriber
                return getattr(mqtt_subscriber, "_GLOBAL_SUBSCRIBER", None)
            except Exception:
                return None

    def _check_and_send_reports(self):
        """Основна логіка: перевіряє і шле звіти що ще не показували.

        ФІКС #3: Додано перевірку "пропуску" — якщо програма не працювала
        1+ годину, шлемо catch-up report зі статистикою за цей період.
        """
        print("[SmartScheduler] Перевіряю звіти...")

        # ── CATCH-UP: програма довго не працювала ──
        try:
            self._check_catchup_report()
        except Exception as e:
            print(f"[SmartScheduler] catch-up error: {e}")

        # ── DAILY: вчорашня дата ──
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        already_shown = self._was_shown("daily", yesterday)
        print(f"[SmartScheduler] Daily {yesterday}: "
              f"{'вже показаний' if already_shown else 'НЕ показаний'}")

        if not already_shown:
            try:
                report = self._build_daily_for_yesterday()
                if report:
                    print(f"[SmartScheduler] Daily report готовий, "
                          f"{report.get('measurements')} вимірів")
                    self._dispatch_daily(report, yesterday)
                else:
                    print("[SmartScheduler] Daily: недостатньо даних, пропускаємо")
            except Exception as e:
                import traceback
                print(f"[SmartScheduler] daily error: {e}")
                traceback.print_exc()

        # ── WEEKLY: тільки в понеділок (звіт за минулий тиждень) ──
        now = datetime.now()
        if now.weekday() == 0:  # понеділок
            last_week = (now - timedelta(days=7))
            week_key  = last_week.strftime("%Y-W%V")

            if not self._was_shown("weekly", week_key):
                print(f"[SmartScheduler] Weekly {week_key} НЕ показаний — будую")
                try:
                    report = self._build_weekly_for_last_week()
                    if report:
                        self._dispatch_weekly(report, week_key)
                except Exception as e:
                    print(f"[SmartScheduler] weekly error: {e}")

    # ── PI MONITOR LOOP (PR #6, v2) ──────────────────────────────────
    def _start_pi_monitor_loop(self):
        """Фоновий потік, що моніторить чи Pi online.

        v2: ВИПРАВЛЕНО:
          • Перевіряє кожні 2 хв
          • Поріг offline → > 3 хв тиші (раніше 5 хв)
          • Перший алерт при offline → одразу
          • Повторні алерти кожні 15 хв якщо Pi так і не повернувся
          • Recovery alert при поверненні
          • Дебаг-лог КОЖНОЇ перевірки
        """
        if not self.token and not self._bot_api:
            print("[SmartScheduler] Pi-monitor: немає Telegram — не стартую")
            return

        def loop():
            last_alert_ts = 0.0
            last_state    = "unknown"
            offline_alert_interval = 15 * 60  # 15 хв між алертами якщо offline
            check_every   = 120                # 2 хв

            print("[PiMonitor] 🚀 Loop стартує, перший check через 30 сек")
            time.sleep(30)  # дати subscriber-у час отримати перший heartbeat

            while True:
                try:
                    state, hb_age = self._get_pi_state()
                    now = time.time()

                    age_str = f"{hb_age:.0f}с" if hb_age >= 0 else "невідомо"
                    print(f"[PiMonitor] state={state} hb_age={age_str} "
                          f"last_state={last_state}")

                    # ─── OFFLINE ALERTS ───
                    if state == "offline":
                        time_since_last = now - last_alert_ts
                        # Перший алерт або повторний кожні 15 хв
                        if last_state != "offline" or time_since_last > offline_alert_interval:
                            msg = (
                                "🔴 *Raspberry Pi OFFLINE*\n\n"
                                "Втрачено зв'язок з апаратним моніторингом.\n"
                                f"⏱ Останні дані: `{int(hb_age)} сек тому`\n\n"
                                "_NetGuardian не може збирати телеметрію 24/7 "
                                "без Pi. Перевір живлення Pi або мережеве "
                                "підключення._"
                            )
                            if self._send_telegram(msg):
                                last_alert_ts = now
                                print("[PiMonitor] 📵 Pi OFFLINE alert sent")
                            else:
                                print("[PiMonitor] ⚠️ Telegram send failed")

                    # ─── RECOVERY ALERT ───
                    elif state == "online" and last_state == "offline":
                        msg = (
                            "🟢 *Raspberry Pi знову ONLINE*\n\n"
                            "Зв'язок з Pi-агентом відновлено!\n"
                            f"💓 Heartbeat: `{int(hb_age)} сек тому`\n"
                            "Моніторинг 24/7 продовжується."
                        )
                        if self._send_telegram(msg):
                            print("[PiMonitor] ✅ Pi recovery alert sent")
                            last_alert_ts = 0  # reset для майбутніх offline

                    last_state = state
                    time.sleep(check_every)
                except Exception as e:
                    import traceback
                    print(f"[PiMonitor] error: {e}")
                    traceback.print_exc()
                    time.sleep(check_every)

        threading.Thread(target=loop, daemon=True, name="PiMonitor").start()
        print("[SmartScheduler] ✅ Pi-monitor запущений (перевірка кожні 2 хв)")

    def _get_pi_state(self) -> tuple[str, float]:
        """Повертає (state, hb_age_seconds).
        state: 'online' | 'offline' | 'unknown'

        v2: знижено поріг offline з 5 хв до 3 хв.
        Pi шле heartbeat кожні 30 сек, тому 3 хв = 6 пропущених heartbeat'ів.
        """
        try:
            pi_db = Path.home() / ".netguardian" / "pi_agent_cache.db"
            if not pi_db.exists():
                return "unknown", -1.0

            with sqlite3.connect(pi_db, timeout=3) as conn:
                c = conn.cursor()
                c.execute("SELECT MAX(ts) FROM remote_heartbeat")
                row = c.fetchone()
                if not row or not row[0]:
                    return "unknown", -1.0

                hb_ts = row[0]
                try:
                    hb_dt = datetime.strptime(hb_ts, "%Y-%m-%d %H:%M:%S")
                    hb_age = (datetime.now() - hb_dt).total_seconds()
                except Exception:
                    return "unknown", -1.0

            # Pi heartbeat кожні 30с. Якщо > 3 хв — offline.
            if hb_age < 180:
                return "online", hb_age
            return "offline", hb_age
        except Exception as e:
            print(f"[PiMonitor] _get_pi_state error: {e}")
            return "unknown", -1.0

    def _check_catchup_report(self):
        """Перевіряє чи була програма довго вимкнена → шле catch-up.

        ФІКС v2: використовуємо record_history.last_seen — час коли
        SmartScheduler востаннє запускався. Це коректно навіть якщо
        ПК встиг записати кілька свіжих ping за 12 секунд до перевірки.
        """
        try:
            # ── Спочатку дивимось МІТКУ останнього запуску SmartScheduler ──
            session_key = "last_session_end"
            last_session_end = None

            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS report_history (
                        report_type TEXT,
                        key         TEXT,
                        shown_at    TEXT DEFAULT (datetime('now', 'localtime')),
                        PRIMARY KEY (report_type, key)
                    )
                """)
                row = conn.execute(
                    "SELECT shown_at FROM report_history "
                    "WHERE report_type='session' AND key=?",
                    (session_key,)
                ).fetchone()
                if row:
                    last_session_end = row[0]

            # ── Якщо є мітка — рахуємо gap від неї ──
            if last_session_end:
                try:
                    last_dt = datetime.strptime(last_session_end,
                                                 "%Y-%m-%d %H:%M:%S")
                    gap_seconds = (datetime.now() - last_dt).total_seconds()
                    gap_hours = gap_seconds / 3600
                    print(f"[SmartScheduler] Catch-up: пропуск {gap_hours:.1f} год "
                          f"(з last_session={last_session_end})")
                except Exception:
                    gap_hours = 0
            else:
                # Перший запуск — використовуємо max(ts) як fallback
                with sqlite3.connect(self.db_path, timeout=5) as conn:
                    c = conn.cursor()
                    c.execute("""
                        SELECT MAX(ts) FROM ping_log
                        WHERE source = 'local' OR source IS NULL
                    """)
                    row = c.fetchone()
                    last_local = row[0] if row else None

                if not last_local:
                    print("[SmartScheduler] Catch-up: перший запуск")
                    self._update_session_marker()
                    return

                try:
                    last_dt = datetime.strptime(last_local, "%Y-%m-%d %H:%M:%S")
                    gap_hours = (datetime.now() - last_dt).total_seconds() / 3600
                except Exception:
                    self._update_session_marker()
                    return

                print(f"[SmartScheduler] Catch-up: пропуск {gap_hours:.1f} год "
                      f"(з last_local={last_local})  [first run]")

            # Завжди оновлюємо мітку — в кінці цього методу
            # (щоб НАСТУПНИЙ запуск рахував від ТЕПЕР)

            # Якщо програма не працювала > 1 години
            if gap_hours < 1:
                self._update_session_marker()
                return

            # Якщо більше тижня — це вже не "catch-up", це довга пауза
            if gap_hours > 7 * 24:
                gap_hours = 7 * 24

            # Будуємо catch-up звіт за період gap
            end_dt = datetime.now()
            start_dt = end_dt - timedelta(hours=gap_hours)
            catchup = self._build_catchup_report(start_dt, end_dt, gap_hours)
            if not catchup:
                print("[SmartScheduler] Catch-up: недостатньо даних від Pi")
                self._update_session_marker()
                return

            # Перевіряємо чи вже не показували його
            key = f"{start_dt.strftime('%Y-%m-%d_%H')}_to_{end_dt.strftime('%Y-%m-%d_%H')}"
            if self._was_shown("catchup", key):
                self._update_session_marker()
                return

            self._dispatch_catchup(catchup, key)
            self._update_session_marker()
        except Exception as e:
            import traceback
            print(f"[SmartScheduler] _check_catchup error: {e}")
            traceback.print_exc()

    def _update_session_marker(self):
        """Оновлює мітку 'last_session_end' на поточний час.

        Викликається після перевірки catch-up. Цей timestamp буде використано
        наступного разу для розрахунку gap (різниця now() - last_session).
        """
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO report_history
                    (report_type, key, shown_at) VALUES
                    ('session', 'last_session_end', datetime('now', 'localtime'))
                """)
                conn.commit()
        except Exception as e:
            print(f"[SmartScheduler] _update_session_marker error: {e}")

    def _build_catchup_report(self, start_dt: datetime, end_dt: datetime,
                               gap_hours: float) -> Optional[dict]:
        """Будує catch-up звіт за період коли програма була вимкнена.
        Дані БЕРУТЬСЯ З Pi (бо ПК не вимірював).
        """
        report = {
            "type":      "catchup",
            "start":     start_dt.strftime("%Y-%m-%d %H:%M"),
            "end":       end_dt.strftime("%Y-%m-%d %H:%M"),
            "gap_hours": round(gap_hours, 1),
            "network":   getattr(self.engine, "display_name", "невідома"),
        }

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                net_id = getattr(self.engine, "net_id", "legacy")

                # Беремо записи за період gap (БУДЬ-ЯКИЙ source)
                # Раніше була умова source='pi' — це блокувало catch-up
                # якщо у gap були тільки local-дані
                c.execute("""
                    SELECT AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                           AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= ? AND ts <= ?
                      AND ping_ms > 0 AND net_id = ?
                """, (start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      net_id))
                row = c.fetchone()
                if not row or not row[0] or row[5] < 3:
                    print(f"[SmartScheduler] _build_catchup: мало даних "
                          f"(row={row}) за період "
                          f"{start_dt}..{end_dt}, net_id={net_id}")
                    return None  # надто мало даних

                report.update({
                    "avg_ping":     round(row[0], 1),
                    "min_ping":     round(row[1], 1),
                    "max_ping":     round(row[2], 1),
                    "avg_jitter":   round(row[3] or 0, 1),
                    "avg_loss":     round(row[4] or 0, 2),
                    "measurements": row[5],
                })

                # Блекаути за період (БУДЬ-ЯКИЙ source)
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE ts >= ? AND ts <= ?
                      AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      net_id))
                report["blackouts"] = c.fetchone()[0]

                # Найгірші години у gap (БУДЬ-ЯКИЙ source)
                c.execute("""
                    SELECT hour, AVG(ping_ms), MAX(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE ts >= ? AND ts <= ?
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) DESC
                    LIMIT 3
                """, (start_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      end_dt.strftime("%Y-%m-%d %H:%M:%S"),
                      net_id))
                report["worst_hours"] = [
                    {
                        "hour":     int(r[0]),
                        "avg_ping": round(r[1], 1),
                        "max_ping": round(r[2], 1),
                        "samples":  r[3],
                    }
                    for r in c.fetchall()
                ]
        except Exception as e:
            print(f"[SmartScheduler] _build_catchup error: {e}")
            return None

        return report

    def _dispatch_catchup(self, report: dict, key: str):
        """Шле catch-up звіт у Telegram і popup."""
        if (self.token or self._bot_api) and self.chat_id:
            text = _safe_format_catchup(report)
            if self._send_telegram(text):
                print(f"[SmartScheduler] ✅ Catch-up звіт надіслано у Telegram "
                      f"(gap {report['gap_hours']}год)")
            else:
                print("[SmartScheduler] ⚠️ Telegram send failed")

        if self._popup_callback:
            try:
                self._popup_callback("catchup", report)
            except Exception as e:
                print(f"[SmartScheduler] popup error: {e}")

        self._mark_shown("catchup", key)

    def _build_daily_for_yesterday(self) -> Optional[dict]:
        """Будує добовий звіт за ВЧОРАШНІЙ день з розширеною статистикою:
          • Базова статистика (avg/min/max/jitter/loss)
          • Найкращий час для категорій (gaming, streaming, work)
          • Глобальні сервіси — як вони почувались
          • Циклони (години провалів пінгу)
        """
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        report = {
            "type":    "daily",
            "date":    yesterday,
            "network": getattr(self.engine, "display_name", "невідома"),
        }

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                net_id = getattr(self.engine, "net_id", "legacy")

                # ── Базова статистика ──
                c.execute("""
                    SELECT AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                           AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ?
                      AND ping_ms > 0 AND net_id = ?
                """, (yesterday, net_id))
                row = c.fetchone()
                if not row or not row[0]:
                    return None

                report.update({
                    "avg_ping":     round(row[0], 1),
                    "min_ping":     round(row[1], 1),
                    "max_ping":     round(row[2], 1),
                    "avg_jitter":   round(row[3] or 0, 1),
                    "avg_loss":     round(row[4] or 0, 2),
                    "measurements": row[5],
                })

                # ── Циклони (години провалів) ──
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE date(ts) = ?
                      AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (yesterday, net_id))
                report["blackouts"] = c.fetchone()[0]

                # Топ-3 найгірші години (циклони)
                c.execute("""
                    SELECT hour, AVG(ping_ms), MAX(ping_ms),
                           AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ?
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) DESC
                    LIMIT 3
                """, (yesterday, net_id))
                report["worst_hours"] = [
                    {
                        "hour":     int(r[0]),
                        "avg_ping": round(r[1], 1),
                        "max_ping": round(r[2], 1),
                        "loss":     round(r[3] or 0, 2),
                        "samples":  r[4],
                    }
                    for r in c.fetchall()
                ]

                # Топ-3 найкращі години (загалом)
                c.execute("""
                    SELECT hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ?
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) ASC
                    LIMIT 3
                """, (yesterday, net_id))
                report["best_hours"] = [
                    {"hour": int(r[0]), "avg_ping": round(r[1], 1), "samples": r[2]}
                    for r in c.fetchall()
                ]

                # Сумісність зі старим форматом
                if report["best_hours"]:
                    report["best_hour"]      = report["best_hours"][0]["hour"]
                    report["best_hour_ping"] = report["best_hours"][0]["avg_ping"]

                # ── Найкращі години для категорій ──
                # Гра потребує найнижчого пінгу + jitter (тому фільтр < 50 мс)
                # Стрім — стабільності (loss < 1%)
                # Робота — будь-який низький
                report["best_for_gaming"] = self._find_best_hours_for_category(
                    c, yesterday, net_id, max_ping=50, max_loss=2.0
                )
                report["best_for_streaming"] = self._find_best_hours_for_category(
                    c, yesterday, net_id, max_ping=80, max_loss=1.0
                )
                report["best_for_work"] = self._find_best_hours_for_category(
                    c, yesterday, net_id, max_ping=150, max_loss=5.0
                )

                # ── Статус глобальних сервісів (поточний) ──
                # Беремо реальний check_services через engine
                try:
                    services = self.engine.check_services()
                    report["services"] = self._summarize_services(services)
                except Exception:
                    report["services"] = {}
        except Exception as e:
            print(f"[SmartScheduler] _build_daily error: {e}")
            return None

        return report

    @staticmethod
    def _find_best_hours_for_category(
        cursor, date_or_period_clause, net_id,
        max_ping: float, max_loss: float, limit: int = 3
    ) -> list:
        """Шукає найкращі години для категорії з фільтрами.
        Працює і для дня (передаємо рядок дати), і для тижня (interval)."""
        # Підтримка двох форматів: вчорашня дата ("YYYY-MM-DD") або період "-7 days"
        if date_or_period_clause.startswith("-"):
            where = f"ts >= datetime('now', '{date_or_period_clause}', 'localtime')"
            params = (net_id,)
        else:
            where = "date(ts) = ?"
            params = (date_or_period_clause, net_id)

        try:
            cursor.execute(f"""
                SELECT hour,
                       AVG(ping_ms) as avg_p,
                       AVG(loss_pct) as avg_l,
                       COUNT(*) as cnt
                FROM ping_log
                WHERE {where}
                  AND ping_ms > 0 AND net_id = ?
                GROUP BY hour
                HAVING avg_p <= ? AND (avg_l IS NULL OR avg_l <= ?)
                ORDER BY (avg_p * 0.7 + COALESCE(avg_l, 0) * 30) ASC
                LIMIT ?
            """, (*params, max_ping, max_loss, limit))
            return [
                {
                    "hour":     int(r[0]),
                    "avg_ping": round(r[1], 1),
                    "loss":     round(r[2] or 0, 2),
                    "samples":  r[3],
                }
                for r in cursor.fetchall()
            ]
        except Exception:
            return []

    @staticmethod
    def _summarize_services(services: list) -> dict:
        """Підсумовує стан глобальних сервісів по категоріях."""
        result = {
            "gaming":    {"up": 0, "down": 0, "items": []},
            "streaming": {"up": 0, "down": 0, "items": []},
            "work":      {"up": 0, "down": 0, "items": []},
            "general":   {"up": 0, "down": 0, "items": []},
        }
        try:
            for svc in services:
                cat = getattr(svc, "category", "general")
                if cat not in result:
                    continue
                is_up = getattr(svc, "is_up", False)
                ms    = getattr(svc, "ping_ms", -1)
                name  = getattr(svc, "name", "?")
                icon  = getattr(svc, "icon", "")
                if is_up:
                    result[cat]["up"] += 1
                else:
                    result[cat]["down"] += 1
                result[cat]["items"].append({
                    "name": name, "ping": ms, "up": is_up, "icon": icon
                })
        except Exception:
            pass
        return result

    def _build_weekly_for_last_week(self) -> Optional[dict]:
        """Будує тижневий звіт за минулі 7 днів з розширеною статистикою:
          • Базова статистика
          • Найкращі дні для категорій (gaming, streaming, work)
          • Глобальні сервіси
          • Циклони — дні і години провалів
        """
        now      = datetime.now()
        week_key = (now - timedelta(days=7)).strftime("%Y-W%V")

        report = {
            "type":    "weekly",
            "week":    week_key,
            "network": getattr(self.engine, "display_name", "невідома"),
        }

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                net_id = getattr(self.engine, "net_id", "legacy")

                # ── Базова статистика ──
                c.execute("""
                    SELECT AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                           AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                """, (net_id,))
                row = c.fetchone()
                if not row or not row[0]:
                    return None

                report.update({
                    "avg_ping":     round(row[0], 1),
                    "min_ping":     round(row[1], 1),
                    "max_ping":     round(row[2], 1),
                    "avg_jitter":   round(row[3] or 0, 1),
                    "avg_loss":     round(row[4] or 0, 2),
                    "measurements": row[5],
                })

                # Блекаути
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (net_id,))
                report["blackouts"] = c.fetchone()[0]

                # ── По днях (середній + макс) ──
                c.execute("""
                    SELECT weekday, AVG(ping_ms), MAX(ping_ms),
                           AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY weekday
                """, (net_id,))
                day_data = {}
                for r in c.fetchall():
                    day_data[int(r[0])] = {
                        "avg_ping": round(r[1], 1),
                        "max_ping": round(r[2], 1),
                        "loss":     round(r[3] or 0, 2),
                        "samples":  r[4],
                    }
                report["day_stats"] = {wd: d["avg_ping"] for wd, d in day_data.items()}
                report["day_data"]  = day_data  # повна версія

                if day_data:
                    best  = min(day_data.items(), key=lambda x: x[1]["avg_ping"])
                    worst = max(day_data.items(), key=lambda x: x[1]["avg_ping"])
                    report["best_day"]       = best[0]
                    report["best_day_ping"]  = best[1]["avg_ping"]
                    report["worst_day"]      = worst[0]
                    report["worst_day_ping"] = worst[1]["avg_ping"]

                # ── Циклони: дні з найгіршим пінгом ──
                worst_days = sorted(
                    day_data.items(),
                    key=lambda x: x[1]["avg_ping"],
                    reverse=True
                )[:3]
                report["worst_days"] = [
                    {
                        "weekday":  wd,
                        "avg_ping": data["avg_ping"],
                        "max_ping": data["max_ping"],
                        "loss":     data["loss"],
                    }
                    for wd, data in worst_days
                ]

                # ── Циклони: години з найгіршим пінгом за тиждень ──
                c.execute("""
                    SELECT hour, AVG(ping_ms), MAX(ping_ms),
                           AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) DESC
                    LIMIT 3
                """, (net_id,))
                report["worst_hours"] = [
                    {
                        "hour":     int(r[0]),
                        "avg_ping": round(r[1], 1),
                        "max_ping": round(r[2], 1),
                        "loss":     round(r[3] or 0, 2),
                    }
                    for r in c.fetchall()
                ]

                # ── Найкращі години за тиждень за категоріями ──
                report["best_for_gaming"] = self._find_best_hours_for_category(
                    c, "-7 days", net_id, max_ping=50, max_loss=2.0
                )
                report["best_for_streaming"] = self._find_best_hours_for_category(
                    c, "-7 days", net_id, max_ping=80, max_loss=1.0
                )
                report["best_for_work"] = self._find_best_hours_for_category(
                    c, "-7 days", net_id, max_ping=150, max_loss=5.0
                )

                # ── Найкращі ДНІ для категорій ──
                report["best_days_gaming"] = self._find_best_days_for_category(
                    day_data, max_ping=50
                )
                report["best_days_streaming"] = self._find_best_days_for_category(
                    day_data, max_ping=80
                )
                report["best_days_work"] = self._find_best_days_for_category(
                    day_data, max_ping=150
                )

                # ── Статус глобальних сервісів (поточний) ──
                try:
                    services = self.engine.check_services()
                    report["services"] = self._summarize_services(services)
                except Exception:
                    report["services"] = {}
        except Exception as e:
            print(f"[SmartScheduler] _build_weekly error: {e}")
            return None

        return report

    @staticmethod
    def _find_best_days_for_category(day_data: dict, max_ping: float) -> list:
        """Знаходить дні тижня що підходять для категорії."""
        result = []
        for wd, data in day_data.items():
            if data["avg_ping"] <= max_ping:
                result.append({
                    "weekday":  wd,
                    "avg_ping": data["avg_ping"],
                    "loss":     data["loss"],
                })
        # Сортуємо по якості (нижчий пінг = краще)
        result.sort(key=lambda x: x["avg_ping"])
        return result[:3]

    def _dispatch_daily(self, report: dict, date_key: str):
        """Шле daily-звіт у Telegram і popup."""
        # 1. Telegram (працює якщо є або token, або _bot_api)
        if (self.token or self._bot_api) and self.chat_id:
            text = _safe_format_daily(report)
            if self._send_telegram(text):
                print(f"[SmartScheduler] ✅ Daily звіт надіслано у Telegram")
            else:
                print("[SmartScheduler] ⚠️ Telegram send failed")

        # 2. Popup в UI
        if self._popup_callback:
            try:
                self._popup_callback("daily", report)
            except Exception as e:
                print(f"[SmartScheduler] popup error: {e}")

        # 3. Зберігаємо як показаний
        self._mark_shown("daily", date_key)

    def _dispatch_weekly(self, report: dict, week_key: str):
        """Шле weekly-звіт у Telegram і popup."""
        if (self.token or self._bot_api) and self.chat_id:
            text = _safe_format_weekly(report)
            if self._send_telegram(text):
                print(f"[SmartScheduler] ✅ Weekly звіт надіслано у Telegram")
            else:
                print("[SmartScheduler] ⚠️ Telegram send failed")

        if self._popup_callback:
            try:
                self._popup_callback("weekly", report)
            except Exception as e:
                print(f"[SmartScheduler] popup error: {e}")

        self._mark_shown("weekly", week_key)

    def _was_shown(self, report_type: str, key: str) -> bool:
        """Перевіряє чи був звіт вже показаний (через report_history)."""
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS report_history (
                        report_type TEXT,
                        key         TEXT,
                        shown_at    TEXT DEFAULT (datetime('now', 'localtime')),
                        PRIMARY KEY (report_type, key)
                    )
                """)
                row = conn.execute(
                    "SELECT 1 FROM report_history WHERE report_type=? AND key=?",
                    (report_type, key)
                ).fetchone()
                return row is not None
        except Exception:
            return False

    def _mark_shown(self, report_type: str, key: str):
        """Маркує звіт як показаний."""
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS report_history (
                        report_type TEXT,
                        key         TEXT,
                        shown_at    TEXT DEFAULT (datetime('now', 'localtime')),
                        PRIMARY KEY (report_type, key)
                    )
                """)
                conn.execute(
                    "INSERT OR REPLACE INTO report_history "
                    "(report_type, key) VALUES (?, ?)",
                    (report_type, key)
                )
                conn.commit()
        except Exception:
            pass

    # ── STORM ALERT LOOP ──────────────────────────────────────────
    def _start_storm_loop(self):
        """Запускає фоновий потік для перевірки storm-аларму кожні 5 хв."""
        # Без Telegram немає сенсу
        if not self.token and not self._bot_api:
            return

        def loop():
            last_alert_ts = 0.0
            cooldown = 30 * 60  # 30 хв між alerts

            while True:
                try:
                    time.sleep(5 * 60)  # 5 хв
                    if time.time() - last_alert_ts < cooldown:
                        continue

                    # Перевіряємо чи є шторм (ping > 200 або loss > 30%)
                    storm_msg = self._check_storm()
                    if storm_msg:
                        self._send_telegram(storm_msg)
                        last_alert_ts = time.time()
                        print("[SmartScheduler] ⚡ Storm alert sent")
                except Exception as e:
                    print(f"[SmartScheduler] storm loop error: {e}")

        threading.Thread(target=loop, daemon=True, name="StormLoop").start()

    def _check_storm(self) -> Optional[str]:
        """Перевіряє чи є зараз 'буря' у мережі. Повертає текст або None."""
        try:
            with sqlite3.connect(self.db_path, timeout=3) as conn:
                c = conn.cursor()
                net_id = getattr(self.engine, "net_id", "legacy")

                # Дивимось останні 10 хв
                c.execute("""
                    SELECT AVG(ping_ms), AVG(loss_pct), COUNT(*) FROM ping_log
                    WHERE ts >= datetime('now', '-10 minutes', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                """, (net_id,))
                row = c.fetchone()
                if not row or not row[2] or row[2] < 3:
                    return None  # недостатньо вимірів

                avg_ping = row[0]
                avg_loss = row[1] or 0

                # Шторм-критерії
                if avg_ping > 200:
                    return (
                        f"⚡ *STORM ALERT — NetGuardian*\n\n"
                        f"🌪 Високий пінг!\n"
                        f"  • Середній за 10 хв: `{avg_ping:.1f} мс`\n"
                        f"  • Втрати: `{avg_loss:.1f}%`\n\n"
                        f"_Рекомендую перевірити мережу_"
                    )
                if avg_loss > 30:
                    return (
                        f"⚡ *STORM ALERT — NetGuardian*\n\n"
                        f"🌪 Великі втрати пакетів!\n"
                        f"  • Середній пінг: `{avg_ping:.1f} мс`\n"
                        f"  • Втрати: `{avg_loss:.1f}%`\n\n"
                        f"_Перевірте стабільність каналу_"
                    )
        except Exception:
            pass
        return None


# ── Глобальний singleton ────────────────────────────────────────────────
_global_scheduler: Optional[SmartScheduler] = None


def get_scheduler(engine=None) -> Optional[SmartScheduler]:
    global _global_scheduler
    if _global_scheduler is None and engine is not None:
        _global_scheduler = SmartScheduler(engine)
    return _global_scheduler