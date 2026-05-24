"""
NetGuardian AI — Smart Agent  v2.0
Автономний агент що:
  • Сканує мережу кожні 5 хвилин
  • Авто-виправляє прості мережеві проблеми
  • Відправляє сповіщення в Telegram
  • Керує розеткою Tapo P110 (Voltage Guardian — захист від скачків напруги)
  • Веде журнал всіх подій

v2.0:
  • Tapo P110 змінила роль: більше НЕ перезавантажує роутер
  • Нова роль: захист обладнання від нестабільної електрики
  • Авто-запуск Voltage Monitor при ініціалізації
  • Alert callback підключений до Telegram
"""

import os
import time
import json
import threading
import sqlite3
import re
import socket
import subprocess
import platform
from pathlib import Path
from typing import Optional, Callable


DATA_DIR      = Path("data/agent")
EVENTS_DB     = DATA_DIR / "events.db"
SETTINGS_PATH = DATA_DIR / "settings.json"


# ══════════════════════════════════════════════════════════
#  ЖУРНАЛ ПОДІЙ
# ══════════════════════════════════════════════════════════

class EventLogger:
    """SQLite журнал всіх подій агента."""

    SEV_LABELS = {0: "INFO", 1: "WARNING", 2: "CRITICAL", 3: "AUTO_FIX"}

    def __init__(self, db_path: Path = EVENTS_DB):
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self.db = db_path
        self._init()

    def _init(self):
        with sqlite3.connect(self.db) as c:
            c.execute("""CREATE TABLE IF NOT EXISTS events (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ts        INTEGER,
                sev       INTEGER,
                code      TEXT,
                title     TEXT,
                detail    TEXT,
                auto_fixed INTEGER DEFAULT 0,
                notified  INTEGER DEFAULT 0
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS scans (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ts         INTEGER,
                ping_ms    INTEGER,
                loss_pct   REAL,
                dns_ms     INTEGER,
                issues_cnt INTEGER,
                ok         INTEGER
            )""")
            c.execute("""CREATE TABLE IF NOT EXISTS tapo_log (
                id      INTEGER PRIMARY KEY AUTOINCREMENT,
                ts      INTEGER,
                action  TEXT,
                result  TEXT,
                volts   REAL,
                watts   REAL
            )""")
            c.commit()

    def log_event(self, sev: int, code: str,
                  title: str, detail: str = "",
                  auto_fixed: bool = False) -> int:
        with sqlite3.connect(self.db) as c:
            cur = c.execute(
                "INSERT INTO events (ts,sev,code,title,detail,auto_fixed) "
                "VALUES (?,?,?,?,?,?)",
                (int(time.time()), sev, code, title, detail, int(auto_fixed)))
            c.commit()
            return cur.lastrowid

    def log_scan(self, ping_ms, loss_pct, dns_ms, issues_cnt, ok):
        with sqlite3.connect(self.db) as c:
            c.execute(
                "INSERT INTO scans (ts,ping_ms,loss_pct,dns_ms,issues_cnt,ok) "
                "VALUES (?,?,?,?,?,?)",
                (int(time.time()), ping_ms, loss_pct, dns_ms, issues_cnt, int(ok)))
            c.commit()

    def log_tapo(self, action: str, result: str,
                 volts: float = 0.0, watts: float = 0.0):
        with sqlite3.connect(self.db) as c:
            c.execute(
                "INSERT INTO tapo_log (ts,action,result,volts,watts) VALUES (?,?,?,?,?)",
                (int(time.time()), action, result, volts, watts))
            c.commit()

    def get_recent_events(self, hours: int = 24, min_sev: int = 1) -> list:
        cutoff = int(time.time()) - hours * 3600
        with sqlite3.connect(self.db) as c:
            rows = c.execute(
                "SELECT ts,sev,code,title,detail,auto_fixed FROM events "
                "WHERE ts>=? AND sev>=? ORDER BY ts DESC LIMIT 50",
                (cutoff, min_sev)).fetchall()
        return rows

    def get_scan_stats(self, hours: int = 24) -> dict:
        cutoff = int(time.time()) - hours * 3600
        with sqlite3.connect(self.db) as c:
            rows = c.execute(
                "SELECT ping_ms,loss_pct,issues_cnt,ok FROM scans WHERE ts>=?",
                (cutoff,)).fetchall()
        if not rows:
            return {}
        valid_pings = [r[0] for r in rows if r[0] and r[0] > 0]
        return {
            "total_scans":  len(rows),
            "ok_scans":     sum(r[3] for r in rows),
            "avg_ping":     int(sum(valid_pings) / len(valid_pings)) if valid_pings else 0,
            "avg_loss":     round(sum(r[1] for r in rows if r[1]) / len(rows), 1),
            "total_issues": sum(r[2] for r in rows),
        }

    def mark_notified(self, event_id: int):
        with sqlite3.connect(self.db) as c:
            c.execute("UPDATE events SET notified=1 WHERE id=?", (event_id,))
            c.commit()


# ══════════════════════════════════════════════════════════
#  ГОЛОВНИЙ АГЕНТ
# ══════════════════════════════════════════════════════════

class SmartAgent:
    """
    Автономний агент NetGuardian.

    Tapo P110 підключається через core/tapo.py (TapoPlug).
    Роль розетки: захист обладнання від нестабільної електрики.
    Налаштування: /tapo setup <IP> <email> <password>
    """

    SCAN_INTERVAL = 5 * 60   # 5 хвилин

    def __init__(self,
                 telegram_send_fn: Callable = None,
                 get_snapshot_fn:  Callable = None,
                 diagnose_fn:      Callable = None,
                 ai_analyzer       = None):
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        self.send_tg      = telegram_send_fn
        self.get_snapshot = get_snapshot_fn or (lambda: {})
        self.diagnose_fn  = diagnose_fn
        self.ai           = ai_analyzer

        self.logger       = EventLogger()
        self.tapo         = None   # TapoPlug instance (core/tapo.py)

        self._running         = False
        self._last_issues     = set()
        self._scan_count      = 0
        self._settings        = self._load_settings()
        self._auto_fix_lock   = threading.Lock()

        # Ініціалізуємо Tapo якщо налаштовано
        self._init_tapo_from_settings()

    # ──────────────────────────────────────────────────────
    # ІНІЦІАЛІЗАЦІЯ TAPO
    # ──────────────────────────────────────────────────────

    def _init_tapo_from_settings(self):
        """Підключає Tapo P110 з збережених налаштувань і запускає моніторинг."""
        tapo_cfg = self._settings.get("tapo", {})
        if not (tapo_cfg.get("enabled") and tapo_cfg.get("ip")):
            return
        try:
            from app.hardware.tapo import TapoPlug
            self.tapo = TapoPlug(
                ip       = tapo_cfg["ip"],
                email    = tapo_cfg.get("email", ""),
                password = tapo_cfg.get("password", ""),
            )
            # Застосовуємо збережені налаштування захисту
            self._apply_guard_settings()
            # Підключаємо Telegram сповіщення
            self.tapo.set_alert_callback(self._notify)
            # Запускаємо моніторинг напруги
            self.tapo.start_monitor()
            print(f"[Agent] Tapo P110 ініціалізовано: {tapo_cfg['ip']} | Voltage Guardian активний")
        except Exception as e:
            print(f"[Agent] Tapo ініціалізація помилка: {e}")

    def _apply_guard_settings(self):
        """Застосовує збережені налаштування захисту до TapoPlug."""
        if not self.tapo:
            return
        guard_cfg = self._settings.get("tapo_guard", {})
        g = self.tapo.guard
        if "volt_min" in guard_cfg:       g.volt_min       = float(guard_cfg["volt_min"])
        if "volt_max" in guard_cfg:       g.volt_max       = float(guard_cfg["volt_max"])
        if "volt_warn_low" in guard_cfg:  g.volt_warn_low  = float(guard_cfg["volt_warn_low"])
        if "volt_warn_high" in guard_cfg: g.volt_warn_high = float(guard_cfg["volt_warn_high"])
        if "amp_max" in guard_cfg:        g.amp_max        = float(guard_cfg["amp_max"])
        if "watt_max" in guard_cfg:       g.watt_max       = float(guard_cfg["watt_max"])
        if "auto_restore" in guard_cfg:   g.auto_restore   = bool(guard_cfg["auto_restore"])
        if "restore_delay" in guard_cfg:  g.restore_delay  = int(guard_cfg["restore_delay"])
        if "price_per_kwh" in guard_cfg:  g.price_per_kwh  = float(guard_cfg["price_per_kwh"])
        if "monitor_interval" in guard_cfg:
            g.monitor_interval = int(guard_cfg["monitor_interval"])

    # ──────────────────────────────────────────────────────
    # НАЛАШТУВАННЯ
    # ──────────────────────────────────────────────────────

    def _load_settings(self) -> dict:
        if SETTINGS_PATH.exists():
            try:
                return json.loads(SETTINGS_PATH.read_text())
            except Exception:
                pass
        return {
            "scan_interval": 300,
            "auto_fix":      True,
            "notify_all":    False,
            "tapo": {
                "enabled":  False,
                "ip":       "",
                "email":    "",
                "password": "",
            },
            "tapo_guard": {
                "volt_min":        200.0,
                "volt_max":        250.0,
                "volt_warn_low":   210.0,
                "volt_warn_high":  240.0,
                "amp_max":         10.0,
                "watt_max":        2200.0,
                "auto_restore":    True,
                "restore_delay":   30,
                "price_per_kwh":   4.32,
                "monitor_interval":60,
            }
        }

    def save_settings(self, settings: dict):
        self._settings = settings
        SETTINGS_PATH.write_text(json.dumps(settings, indent=2, ensure_ascii=False))

    def save_guard_settings(self):
        """Зберігає поточні налаштування guard з TapoPlug в settings.json."""
        if not self.tapo:
            return
        g = self.tapo.guard
        self._settings["tapo_guard"] = {
            "volt_min":        g.volt_min,
            "volt_max":        g.volt_max,
            "volt_warn_low":   g.volt_warn_low,
            "volt_warn_high":  g.volt_warn_high,
            "amp_max":         g.amp_max,
            "watt_max":        g.watt_max,
            "auto_restore":    g.auto_restore,
            "restore_delay":   g.restore_delay,
            "price_per_kwh":   g.price_per_kwh,
            "monitor_interval":g.monitor_interval,
        }
        self.save_settings(self._settings)

    def configure_tapo(self, ip: str, email: str = "",
                       password: str = "", enabled: bool = True) -> tuple:
        """
        Налаштовує Tapo P110 і тестує підключення.
        Після успішного підключення запускає Voltage Guardian.
        """
        self._settings["tapo"]["ip"]       = ip.strip()
        self._settings["tapo"]["email"]    = email.strip()
        self._settings["tapo"]["password"] = password.strip()
        self._settings["tapo"]["enabled"]  = enabled
        self.save_settings(self._settings)

        try:
            from app.hardware.tapo import TapoPlug
            # Зупиняємо попередній моніторинг
            if self.tapo and self.tapo.is_monitoring:
                self.tapo.stop_monitor()

            self.tapo = TapoPlug(ip.strip(), email.strip(), password.strip())
            ok, msg = self.tapo.test_connection()

            if ok:
                self._apply_guard_settings()
                self.tapo.set_alert_callback(self._notify)
                self.tapo.start_monitor()
                self.logger.log_event(0, "TAPO-INIT",
                                      f"Tapo P110 підключено: {ip} | Voltage Guardian активний")
                msg += "\n✅ Voltage Guardian запущено!"
            return ok, msg
        except Exception as e:
            return False, f"❌ Помилка підключення: {e}"

    # ──────────────────────────────────────────────────────
    # ЗАПУСК / ЗУПИНКА
    # ──────────────────────────────────────────────────────

    def start(self):
        self._running = True
        threading.Thread(target=self._main_loop, daemon=True).start()
        print("[Agent] Автосканування запущено (кожні 5 хв)")

    def stop(self):
        self._running = False
        if self.tapo and self.tapo.is_monitoring:
            self.tapo.stop_monitor()

    # ──────────────────────────────────────────────────────
    # ГОЛОВНИЙ ЦИКЛ
    # ──────────────────────────────────────────────────────

    def _main_loop(self):
        time.sleep(30)   # перший запуск через 30 сек
        while self._running:
            try:
                self._run_scan()
            except Exception as e:
                print(f"[Agent] Помилка сканування: {e}")
            interval = self._settings.get("scan_interval", self.SCAN_INTERVAL)
            time.sleep(interval)

    # ──────────────────────────────────────────────────────
    # СКАНУВАННЯ МЕРЕЖІ
    # ──────────────────────────────────────────────────────

    def _run_scan(self):
        self._scan_count += 1
        ts = time.strftime("%H:%M:%S")
        print(f"[Agent] Сканування #{self._scan_count} о {ts}")

        ping_ms      = self._quick_ping("8.8.8.8")
        has_internet = ping_ms > 0
        dns_ms       = self._check_dns()

        self.logger.log_scan(
            ping_ms=ping_ms if has_internet else -1,
            loss_pct=0 if has_internet else 100,
            dns_ms=dns_ms,
            issues_cnt=0,
            ok=has_internet)

        if not has_internet:
            event_id = self.logger.log_event(
                2, "NET-DOWN",
                f"⛔ Інтернет відсутній",
                f"Ping 8.8.8.8: timeout. DNS: {'OK' if dns_ms > 0 else 'timeout'}")
            self._notify(
                f"🔴 *ІНТЕРНЕТ ВІДСУТНІЙ*\n"
                f"Час: {ts}\n"
                f"DNS: {'✅' if dns_ms > 0 else '❌ timeout'}",
                event_id=event_id)
        else:
            # Відновлення після збою — перевіряємо чи було попереднє падіння
            last_events = self.logger.get_recent_events(1, min_sev=2)
            had_down    = any(e[2] == "NET-DOWN" for e in last_events)
            if had_down:
                self._notify(
                    f"🟢 *Інтернет відновлено!*\n"
                    f"Час відновлення: {ts}\n"
                    f"Пінг: {ping_ms} ms")

        # Повна діагностика кожне 5-те сканування
        if self._scan_count % 5 == 0 and self.diagnose_fn:
            self._run_full_diagnostics()

        # DNS деградація
        if dns_ms > 500 and has_internet:
            event_id = self.logger.log_event(
                1, "DNS-SLOW",
                f"🟡 DNS повільний: {dns_ms} ms",
                "Рекомендується змінити на 1.1.1.1")
            if self._settings.get("auto_fix"):
                self._auto_fix_dns(event_id)

        # Пінг попередження
        if has_internet:
            if ping_ms > 200:
                self.logger.log_event(
                    2, "PING-CRIT",
                    f"🔴 Критична затримка: {ping_ms} ms",
                    "Можливі проблеми з провайдером або роутером")
                self._notify(
                    f"🔴 *Висока затримка*\n"
                    f"Пінг: `{ping_ms} ms`\nЧас: {ts}")
            elif ping_ms > 100:
                self.logger.log_event(
                    1, "PING-WARN",
                    f"🟡 Підвищена затримка: {ping_ms} ms")

    # ──────────────────────────────────────────────────────
    # ПОВНА ДІАГНОСТИКА
    # ──────────────────────────────────────────────────────

    def _run_full_diagnostics(self):
        print("[Agent] Повна діагностика...")
        try:
            report  = self.diagnose_fn()
            issues  = report.get("issues", [])

            current_codes = {i.get("code") for i in issues}
            new_issues    = [i for i in issues
                             if i.get("code") not in self._last_issues]
            self._last_issues = current_codes

            if not new_issues:
                return

            for issue in new_issues:
                sev_map = {"CRITICAL": 2, "WARNING": 1, "INFO": 0}
                sev_int = sev_map.get(issue.get("sev", "INFO"), 0)
                self.logger.log_event(
                    sev_int,
                    issue.get("code", "?"),
                    issue.get("title", ""),
                    issue.get("desc", ""))

            if self._settings.get("auto_fix"):
                self._try_auto_fix(new_issues)

            new_critical = [i for i in new_issues if i.get("sev") == "CRITICAL"]
            if new_critical:
                lines = "\n".join(
                    f"🔴 `[{i.get('code')}]` {i.get('title')}"
                    for i in new_critical[:3])
                self._notify(
                    f"🔴 *НОВІ КРИТИЧНІ ПРОБЛЕМИ ({len(new_critical)}):*\n"
                    f"{lines}\n\n"
                    f"Напиши /diagnose для детального аналізу")
            elif new_issues and self._settings.get("notify_all"):
                lines = "\n".join(
                    f"{'🔴' if i.get('sev')=='CRITICAL' else '🟡'} {i.get('title')}"
                    for i in new_issues[:3])
                self._notify(f"⚠️ *Нові події ({len(new_issues)}):*\n{lines}")

        except Exception as e:
            print(f"[Agent] Помилка діагностики: {e}")

    # ──────────────────────────────────────────────────────
    # АВТО-ВИПРАВЛЕННЯ
    # ──────────────────────────────────────────────────────

    def _try_auto_fix(self, issues: list):
        from features.diagnostics.engine import DiagnosticEngine
        engine = DiagnosticEngine()
        safe_fixes = {"flush_dns", "set_fast_dns", "enable_autotuning", "fix_mtu"}
        for issue in issues:
            fix_method = issue.get("fix")
            if not fix_method or fix_method not in safe_fixes:
                continue
            with self._auto_fix_lock:
                fn = getattr(engine, fix_method, None)
                if fn:
                    ok, msg = fn()
                    self.logger.log_event(
                        3, f"AUTOFIX-{issue.get('code')}",
                        f"{'✅' if ok else '❌'} Авто-виправлення: {issue.get('title')}",
                        msg, auto_fixed=ok)
                    if ok:
                        self._notify(
                            f"🔧 *Авто-виправлено:*\n"
                            f"`{issue.get('title')}`\n"
                            f"✅ {msg}")

    def _auto_fix_dns(self, event_id: int):
        from features.diagnostics.engine import DiagnosticEngine
        with self._auto_fix_lock:
            ok, msg = DiagnosticEngine.set_fast_dns()
            self.logger.log_event(
                3, "AUTOFIX-DNS",
                f"Авто-виправлення DNS: {msg}", auto_fixed=ok)
            if ok:
                self._notify(f"🔧 *DNS авто-виправлено*\n✅ {msg}")

    # ──────────────────────────────────────────────────────
    # TAPO P110 — публічні методи для Bot
    # ──────────────────────────────────────────────────────

    def tapo_get_status(self) -> str:
        """Форматований статус Tapo P110 для Telegram."""
        if not self.tapo:
            return (
                "❌ *Tapo P110 не налаштована*\n\n"
                "Щоб налаштувати надішли:\n"
                "`/tapo setup <IP> <email> <password>`\n\n"
                "Приклад:\n"
                "`/tapo setup 192.168.0.104 me@gmail.com mypass`"
            )
        return self.tapo.format_status_message()

    def tapo_get_guard(self) -> str:
        """Налаштування захисту для Telegram."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована. Виконай `/tapo setup`"
        return self.tapo.format_guard_message()

    def tapo_get_stats(self) -> str:
        """Статистика споживання для Telegram."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована. Виконай `/tapo setup`"
        return self.tapo.format_stats_message()

    def tapo_get_voltage_trend(self) -> str:
        """Графік напруги для Telegram."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована."
        trend = self.tapo.get_voltage_trend()
        stats = self.tapo.get_stats()
        header = (
            f"📈 *Графік напруги (останні заміри)*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
        )
        if stats:
            header += (
                f"Мін: `{stats['volt_min']}V` | Макс: `{stats['volt_max']}V` | "
                f"Сер: `{stats['volt_avg']}V`\n\n"
            )
        return header + trend

    def tapo_get_guard_events(self) -> str:
        """Журнал подій захисту для Telegram."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована."
        return self.tapo.get_guard_events_text()

    def tapo_start_monitor(self) -> str:
        """Запустити Voltage Monitor."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована. Виконай `/tapo setup`"
        if self.tapo.is_monitoring:
            return "✅ Voltage Monitor вже активний."
        self.tapo.set_alert_callback(self._notify)
        self.tapo.start_monitor()
        interval = self.tapo.guard.monitor_interval
        return (
            f"✅ *Voltage Monitor запущено!*\n"
            f"Інтервал замірів: `{interval}с`\n"
            f"Я сповіщу якщо напруга вийде за межі."
        )

    def tapo_stop_monitor(self) -> str:
        """Зупинити Voltage Monitor."""
        if not self.tapo:
            return "❌ Tapo P110 не налаштована."
        if not self.tapo.is_monitoring:
            return "❌ Voltage Monitor не активний."
        self.tapo.stop_monitor()
        return "⏹️ Voltage Monitor зупинено."

    # ──────────────────────────────────────────────────────
    # СТАТУС АГЕНТА
    # ──────────────────────────────────────────────────────

    def get_agent_status(self) -> str:
        stats  = self.logger.get_scan_stats(24)
        events = self.logger.get_recent_events(24, min_sev=1)

        if self.tapo:
            mon_icon = "✅" if self.tapo.is_monitoring else "⚠️"
            tapo_st = self.tapo.get_stats()
            if tapo_st:
                stab = tapo_st.get("stability_pct", "?")
                guard_events = tapo_st.get("guard_events", 0)
                tapo_line = (
                    f"{mon_icon} {self.tapo.ip} | "
                    f"Стабільність: `{stab}%` | "
                    f"Спрацювань: `{guard_events}`"
                )
            else:
                tapo_line = f"{mon_icon} {self.tapo.ip} (немає даних)"
        else:
            tapo_line = "не налаштована"

        return (
            f"🤖 *Smart Agent — Статус*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"🔄 Сканувань виконано: `{self._scan_count}`\n"
            f"📊 За 24 год: `{stats.get('total_scans', 0)}` сканувань\n"
            f"✅ Успішних: `{stats.get('ok_scans', 0)}`\n"
            f"📡 Середній пінг: `{stats.get('avg_ping', '?')} ms`\n"
            f"⚠️ Подій за 24 год: `{len(events)}`\n\n"
            f"🔌 Tapo P110: {tapo_line}\n"
            f"🔧 Авто-виправлення: {'✅' if self._settings.get('auto_fix') else '❌'}\n"
            f"🔔 Сповіщення: {'всі' if self._settings.get('notify_all') else 'тільки критичні'}"
        )

    def get_events_text(self, hours: int = 24) -> str:
        events = self.logger.get_recent_events(hours, min_sev=0)
        if not events:
            return f"✅ За останні {hours} годин подій не було."
        lines = [f"📋 *Останні події ({hours} год):*\n"]
        for ts, sev, code, title, detail, fixed in events[:15]:
            dt   = time.strftime("%H:%M", time.localtime(ts))
            icon = ["ℹ️", "🟡", "🔴", "🔧"][min(sev, 3)]
            fix  = " ✅" if fixed else ""
            lines.append(f"{icon} `{dt}` {title}{fix}")
        return "\n".join(lines)

    # ──────────────────────────────────────────────────────
    # СЛУЖБОВІ
    # ──────────────────────────────────────────────────────

    def _quick_ping(self, host: str) -> int:
        try:
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            if platform.system() == "Windows":
                out = subprocess.check_output(
                    ["ping", "-n", "1", "-w", "2000", host],
                    text=True, encoding="cp866", errors="replace",
                    timeout=5, creationflags=flags)
                m = re.search(r"(?:Час|time)[=<](\d+)", out)
                return int(m.group(1)) if m else -1
            else:
                out = subprocess.check_output(
                    ["ping", "-c", "1", "-W", "2", host],
                    text=True, errors="replace", timeout=5)
                m = re.search(r"time[=<]([\d.]+)", out)
                return int(float(m.group(1))) if m else -1
        except Exception:
            return -1

    def _check_dns(self) -> int:
        try:
            t0 = time.perf_counter()
            socket.gethostbyname("google.com")
            return int((time.perf_counter() - t0) * 1000)
        except Exception:
            return -1

    def _notify(self, text: str, event_id: int = None):
        if self.send_tg:
            try:
                self.send_tg(text)
                if event_id:
                    self.logger.mark_notified(event_id)
            except Exception as e:
                print(f"[Agent] Помилка Telegram: {e}")
