"""
NetGuardian AI — Telegram Bot  v4.3
"""

import re
import time
import json
import threading
import urllib.request
import urllib.error
import socket
import datetime
import statistics
import os
from typing import Callable, Optional


# ══════════════════════════════════════════════════════════════════
#  TELEGRAM API
# ══════════════════════════════════════════════════════════════════

class _TelegramAPI:
    BASE = "https://api.telegram.org/bot{token}/{method}"

    def __init__(self, token: str):
        self.token = token

    def _call(self, method: str, params: dict = None, timeout: int = 30) -> dict:
        url  = self.BASE.format(token=self.token, method=method)
        data = json.dumps(params).encode() if params else None
        req  = urllib.request.Request(
            url, data=data,
            headers={"Content-Type": "application/json"} if data else {},
            method="POST" if data else "GET")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.loads(r.read())
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def send(self, chat_id, text: str, reply_to: int = None,
             parse_mode: str = "Markdown", reply_markup: dict = None) -> dict:
        chunks = [text[i:i+4000] for i in range(0, len(text), 4000)]
        r = {}
        for i, chunk in enumerate(chunks):
            p = {"chat_id": chat_id, "text": chunk, "parse_mode": parse_mode}
            if reply_to:
                p["reply_to_message_id"] = reply_to; reply_to = None
            # Кнопки додаємо лише до останнього chunk'а
            if reply_markup and i == len(chunks) - 1:
                p["reply_markup"] = json.dumps(reply_markup)
            r = self._call("sendMessage", p)
        return r

    def edit_message(self, chat_id, message_id: int, text: str,
                     parse_mode: str = "Markdown", reply_markup: dict = None) -> dict:
        """Редагує існуюче повідомлення (для оновлення меню без спаму)."""
        p = {"chat_id": chat_id, "message_id": message_id,
             "text": text[:4000], "parse_mode": parse_mode}
        if reply_markup:
            p["reply_markup"] = json.dumps(reply_markup)
        return self._call("editMessageText", p)

    def delete_message(self, chat_id, message_id: int) -> dict:
        """Видаляє повідомлення. Використовується щоб переносити меню вниз."""
        return self._call("deleteMessage",
                          {"chat_id": chat_id, "message_id": message_id})

    def answer_callback(self, callback_query_id: str, text: str = "") -> dict:
        """Відповідає на callback_query (toast notification)."""
        p = {"callback_query_id": callback_query_id}
        if text: p["text"] = text[:200]
        return self._call("answerCallbackQuery", p)

    def set_my_commands(self, commands: list) -> dict:
        """Встановлює список команд що видно у меню Telegram."""
        return self._call("setMyCommands", {"commands": json.dumps(commands)})

    def get_updates(self, offset: int = 0, timeout: int = 25) -> list:
        r = self._call("getUpdates",
                       {"offset": offset, "timeout": timeout, "limit": 10,
                        "allowed_updates": json.dumps(["message", "callback_query"])},
                       timeout=timeout + 5)
        return r.get("result", []) if r.get("ok") else []

    def typing(self, chat_id):
        self._call("sendChatAction", {"chat_id": chat_id, "action": "typing"})


# ══════════════════════════════════════════════════════════════════
#  PORT SCANNER
# ══════════════════════════════════════════════════════════════════

_WELL_KNOWN = {21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
               80:"HTTP",110:"POP3",135:"RPC",139:"NetBIOS",
               143:"IMAP",443:"HTTPS",445:"SMB",1433:"MSSQL",
               3306:"MySQL",3389:"RDP",4444:"Metasploit",
               5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-alt",27017:"MongoDB"}
_RISK  = {23:"🔴",4444:"🔴",135:"🟡",139:"🟡",445:"🟡",6881:"🟡"}
_TOP   = [21,22,23,25,53,80,110,135,139,143,443,445,1433,3306,3389,4444,5900,6379,8080,27017]

def _quick_scan(host: str, ports=None, timeout: float=0.8) -> list:
    ports   = ports or _TOP
    results = []
    sem     = threading.Semaphore(50)
    def chk(p):
        with sem:
            try:
                s = socket.socket()
                s.settimeout(timeout)
                open_ = s.connect_ex((host, p)) == 0
                s.close()
                if open_:
                    results.append((p, _WELL_KNOWN.get(p,"?"), _RISK.get(p,"")))
            except Exception:
                pass
    ts = [threading.Thread(target=chk, args=(p,), daemon=True) for p in ports]
    for t in ts: t.start()
    for t in ts: t.join()
    return sorted(results)


# ══════════════════════════════════════════════════════════════════
#  WEATHER / FORECAST FORMATTERS (v4.3)
# ══════════════════════════════════════════════════════════════════

def _bar(value: float, total: float = 100, width: int = 12,
          fill: str = "█", empty: str = "░") -> str:
    filled = round((value / total) * width) if total else 0
    return fill * filled + empty * (width - filled)

def _quality_emoji(index: int) -> str:
    if index <= 20: return "🟢"
    if index <= 40: return "🟡"
    if index <= 60: return "🟠"
    if index <= 80: return "🔴"
    return "💀"

def _risk_emoji(pct: int) -> str:
    return "🟢" if pct < 20 else "🟡" if pct < 50 else "🔴"

def _fmt_weather(cond, history=None) -> str:
    quality = 100 - cond.weather_index
    bar     = _bar(quality)
    lines = [
        f"*{cond.icon}  {cond.title}*",
        f"_{datetime.datetime.now().strftime('%d.%m.%Y  %H:%M:%S')}_",
        "",
        f"{_quality_emoji(cond.weather_index)}  *Якість:* `{quality}/100`  `{bar}`",
        "",
        f"🌡️  *Пінг:*           `{cond.ping_ms:.0f} мс`{'  ⚠️' if cond.ping_ms > 100 else ''}",
        f"💨  *Джиттер:*        `{cond.jitter_ms:.0f} мс`{'  ⚠️' if cond.jitter_ms > 30 else ''}",
        f"🌧️  *Втрата пакетів:*  `{cond.packet_loss:.1f}%`{'  ⚠️' if cond.packet_loss > 1 else ''}",
    ]
    if cond.perceived_mbps > 0:
        lines += [
            "",
            f"⚡  *Реальна швидкість:* `{cond.perceived_mbps:.0f} Мбіт/с`",
            f"📊  *Тарифна:*          `{cond.nominal_mbps:.0f} Мбіт/с`",
        ]
        if cond.nominal_mbps > 0 and cond.perceived_mbps < cond.nominal_mbps * 0.5:
            lines.append("🐢  _Реальна < 50% тарифу — можливий throttling!_")
    lines += ["", f"_{cond.desc}_"]
    if history and history.status == "ok":
        sla = getattr(history, "sla_pct", None)
        if sla is not None:
            sla_icon = "✅" if sla >= 99 else "🔵" if sla >= 95 else "🟡" if sla >= 90 else "🔴"
            lines += ["", f"{sla_icon}  *Надійність ISP (SLA):* `{sla:.1f}%`"]
    return "\n".join(lines)

def _fmt_forecast(history) -> str:
    if history.status == "no_data":
        return "📭  *Прогноз*\n\nНедостатньо даних."
    if history.status == "error":
        return f"❌  *Прогноз*\n\nПомилка: `{history.error_msg}`"
    today_wd = datetime.datetime.now().weekday()
    lines    = ["*📅  ПРОГНОЗ НА 7 ДНІВ  (Пн–Нд)*", ""]
    for day in sorted(history.forecast_days, key=lambda d: d.weekday):
        is_today = (day.weekday == today_wd)
        marker   = " ◀ *СЬОГОДНІ*" if is_today else ""
        ping_str = f"`{day.avg_ping:.0f} мс`" if day.avg_ping else "`немає даних`"
        best_str = f"⏰ `{day.best_hour:02d}:00`" if day.avg_ping else ""
        prefix   = "*" if is_today else ""
        lines.append(
            f"{day.icon}  {prefix}{day.day_name}{prefix}  {ping_str}  "
            f"{_risk_emoji(day.risk_pct)} ризик `{day.risk_pct}%`  {best_str}{marker}"
        )
    if history.best_hour:
        bh, bv = history.best_hour
        lines += ["", f"🏆  *Найкраща година:* `{bh:02d}:00`  (avg `{bv:.0f} мс`)"]
    if history.cyclone_hours:
        ch = "  ".join(f"`{h:02d}:00`" for h in sorted(history.cyclone_hours))
        lines += ["", f"⚡  *Пікові години (циклони):* {ch}"]
    return "\n".join(lines)

def _fmt_services_weather(services) -> str:
    try:
        from features.forecast.engine import CAT_LABELS
    except Exception:
        CAT_LABELS = {"general":"🌐 Загальне","gaming":"🎮 Ігри","streaming":"📺 Стрімінг","work":"💼 Робота"}
    categories: dict[str, list] = {}
    for s in services:
        categories.setdefault(s.category, []).append(s)
    lines = ["*☁️  GLOBAL SERVICE STATUS*", ""]
    for cat_key in ["general", "gaming", "streaming", "work"]:
        svcs = categories.get(cat_key, [])
        if not svcs: continue
        lines.append(f"*{CAT_LABELS.get(cat_key, cat_key)}*")
        for s in svcs:
            ms_str = f"`{s.ping_ms:.0f} мс`" if s.is_up else "`offline`"
            lines.append(f"  {s.icon}  {s.name}  —  {ms_str}")
        lines.append("")
    down = [s.name for s in services if not s.is_up]
    lines.append(f"⚠️  *Недоступно: {', '.join(down)}*" if down else "✅  _Всі сервіси доступні_")
    return "\n".join(lines)

def _fmt_throttle(res: dict) -> str:
    if not res.get("success"):
        return f"❌  *Throttling test*\n\n`{res.get('msg','помилка')}`"
    level_icon = {"severe":"🔴","moderate":"🟠","mild":"🟡","none":"🟢"}.get(
        res.get("throttle_level","none"), "⚪")
    lines = [
        "*📡  THROTTLING TEST*", "",
        f"🇺🇦  *UA/Local:*  `{res['ua_ms']:.0f} мс`",
        f"🌍  *EU/Global:* `{res['eu_ms']:.0f} мс`",
        f"📐  *Різниця:*   `{res['ratio']:.1f}×`",
        "", f"{level_icon}  *{res.get('throttle_desc','—')}*",
    ]
    for hop in res.get("trace", [])[:6]:
        ms   = hop.get("ms", 0)
        dot  = "🟢" if ms < 20 else "🟡" if ms < 80 else "🔴"
        hint = (" ← роутер" + (" ⚠️" if ms > 10 else "")) if hop.get("hop") == 1 \
               else " ← провайдер" if hop.get("hop") == 2 else ""
        if not lines[-1].startswith("*📍"):
            lines += ["", "*📍 Traceroute:*"]
        lines.append(f"  `{hop['hop']:>2}`. {dot} `{ms:>5.1f} мс`  `{hop['ip']}`{hint}")
    return "\n".join(lines)

def _fmt_sla(history) -> str:
    if history.status != "ok":
        return "📭  *SLA*\n\nНедостатньо даних."
    sla = getattr(history, "sla_pct", None)
    if sla is None:
        return "📭  *SLA*\n\nПоле sla_pct відсутнє."
    sla_icon = "✅" if sla >= 99 else "🔵" if sla >= 95 else "🟡" if sla >= 90 else "🔴"
    verdict  = (
        "Відмінна надійність провайдера!"       if sla >= 99 else
        "Добра надійність, незначні відхилення." if sla >= 95 else
        "Помітні проблеми — розгляньте скаргу." if sla >= 90 else
        "Критично низька надійність! Час скаржитись."
    )
    lines = [
        "*📊  НАДІЙНІСТЬ ПРОВАЙДЕРА (SLA)*", "",
        f"{sla_icon}  *SLA за тиждень:* `{sla:.2f}%`",
        f"`{_bar(sla)}`", "", f"_{verdict}_", "",
        f"🌐  *Середній пінг:*       `{history.global_avg:.0f} мс`",
        f"🌧️  *Втрата пакетів (DB):* `{history.packet_loss_pct:.2f}%`",
        f"⚡  *Аномалій за тиждень:* `{history.anomalies_count}`",
    ]
    if history.cyclone_hours:
        ch = "  ".join(f"`{h:02d}:00`" for h in sorted(history.cyclone_hours))
        lines += ["", f"🌀  *Пікові години:* {ch}"]
    return "\n".join(lines)

def _fmt_besttime(history) -> str:
    if history.status != "ok" or not history.hourly_data:
        return "📭  *Найкращий час*\n\nНедостатньо даних."
    hd       = history.hourly_data
    cyclones = set(history.cyclone_hours)
    safe     = sorted([(h, v) for h, v in hd.items() if h not in cyclones], key=lambda x: x[1])
    if not safe: safe = sorted(hd.items(), key=lambda x: x[1])
    def top3(lst):
        t = lst[:3]
        return "  ".join(f"`{h:02d}:00`" for h, _ in t), \
               f"avg `{sum(v for _, v in t)/len(t):.0f} мс`" if t else "—"
    game_t, game_s = top3(safe)
    night  = [(h, v) for h, v in safe if h < 7 or h == 23]
    dl_t, dl_s     = top3(night if night else safe)
    stream = [(h, v) for h, v in safe if 7 <= h <= 23]
    st_t, st_s     = top3(stream if stream else safe)
    return "\n".join([
        "*🏆  НАЙКРАЩИЙ ЧАС ДЛЯ АКТИВНОСТЕЙ*", "",
        f"🎮  *Ігри:*          {game_t}  ({game_s})",
        f"📥  *Завантаження:*  {dl_t}  ({dl_s})",
        f"📺  *Стрімінг:*      {st_t}  ({st_s})",
        "", "_Рекомендації на основі вашої статистики._",
    ])

def _fmt_daily_report(cond, history) -> str:
    yesterday = (datetime.datetime.now() - datetime.timedelta(days=1)).strftime("%d.%m.%Y")
    quality   = 100 - cond.weather_index
    lines = [
        f"*🌅  ЩОДЕННИЙ ЗВІТ  ·  {yesterday}*", "",
        f"{cond.icon}  *Стан зараз:* {cond.title}",
        f"📊  *Якість:* `{quality}/100`",
        f"🌡️  *Пінг:*    `{cond.ping_ms:.0f} мс`",
        f"💨  *Джиттер:* `{cond.jitter_ms:.0f} мс`",
        f"🌧️  *Лосс:*    `{cond.packet_loss:.1f}%`",
    ]
    if history.status == "ok":
        sla = getattr(history, "sla_pct", None)
        if sla is not None:
            icon = "✅" if sla >= 99 else "🔵" if sla >= 95 else "🟡" if sla >= 90 else "🔴"
            lines += ["", f"{icon}  *SLA за тиждень:* `{sla:.1f}%`"]
        if history.best_hour:
            bh, bv = history.best_hour
            lines.append(f"🏆  *Найкраща година:* `{bh:02d}:00` (avg `{bv:.0f} мс`)")
        if history.cyclone_hours:
            ch = "  ".join(f"`{h:02d}:00`" for h in sorted(history.cyclone_hours))
            lines.append(f"⚡  *Циклони:* {ch}")
    lines += ["", "_Слідкуй за мережею — NetGuardian AI_"]
    return "\n".join(lines)

def _fmt_weekly_report(history) -> str:
    week_num = datetime.datetime.now().isocalendar()[1]
    lines = [f"*📅  ТИЖНЕВИЙ ЗВІТ  ·  Тиждень {week_num}*", ""]
    if history.status != "ok":
        lines.append("📭 Недостатньо даних за тиждень.")
        return "\n".join(lines)
    sla = getattr(history, "sla_pct", None)
    sla_icon = "✅" if (sla or 0) >= 99 else "🔵" if (sla or 0) >= 95 else "🟡" if (sla or 0) >= 90 else "🔴"
    lines += [
        f"🌐  *Середній пінг:*  `{history.global_avg:.0f} мс`",
        f"🌧️  *Загальний лосс:* `{history.packet_loss_pct:.2f}%`",
        f"⚡  *Аномалій:*       `{history.anomalies_count}`",
    ]
    if sla is not None:
        lines.append(f"{sla_icon}  *Надійність ISP:* `{sla:.2f}%`")
    if history.best_hour and history.worst_hour:
        bh, bv = history.best_hour
        wh, wv = history.worst_hour
        lines += ["",
            f"🏆  *Найкраща година:* `{bh:02d}:00` (avg `{bv:.0f} мс`)",
            f"💀  *Найгірша година:* `{wh:02d}:00` (avg `{wv:.0f} мс`)",
        ]
    if history.cyclone_hours:
        ch = "  ".join(f"`{h:02d}:00`" for h in sorted(history.cyclone_hours))
        lines += ["", f"🌀  *Пікові години:* {ch}"]
    lines += ["", "*Прогноз на наступний тиждень:*"]
    for day in sorted(history.forecast_days, key=lambda d: d.weekday):
        if day.avg_ping:
            lines.append(f"  {day.icon}  {day.day_name}  `{day.avg_ping:.0f} мс`  "
                         f"{_risk_emoji(day.risk_pct)} `{day.risk_pct}%`")
        else:
            lines.append(f"  ❓  {day.day_name}  немає даних")
    lines += ["", "_NetGuardian AI  ·  Дякуємо за тиждень разом!_"]
    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════
#  ПЛАНУВАЛЬНИК АВТО-ЗВІТІВ (v4.3)
# ══════════════════════════════════════════════════════════════════

class _WeatherScheduler:
    def __init__(self):
        self._api: Optional[_TelegramAPI] = None
        self._chat_id: str = ""
        self._engine = None
        self._running = False
        self._alerts_enabled = True
        self._last_alert_ts: float = 0.0
        self._alert_cooldown = 5 * 60

    def connect(self, api: _TelegramAPI, chat_id: str, engine):
        self._api     = api
        self._chat_id = str(chat_id)
        self._engine  = engine

    def set_alerts(self, enabled: bool):
        self._alerts_enabled = enabled

    def start(self):
        if self._running: return
        self._running = True
        threading.Thread(target=self._loop, daemon=True).start()

    def stop(self):
        self._running = False

    def _send(self, text: str):
        if self._api and self._chat_id:
            self._api.send(self._chat_id, text)

    def _loop(self):
        checked_minute = -1
        while self._running:
            try:
                now = datetime.datetime.now()
                minute_key = now.hour * 60 + now.minute
                if minute_key == checked_minute:
                    time.sleep(15)
                    continue
                checked_minute = minute_key
                if now.hour == 0 and now.minute == 0:
                    threading.Thread(target=self._daily_report, daemon=True).start()
                if now.weekday() == 6 and now.hour == 23 and now.minute == 55:
                    threading.Thread(target=self._weekly_report, daemon=True).start()
                if self._alerts_enabled and now.minute % 5 == 0:
                    threading.Thread(target=self._storm_check, daemon=True).start()
            except Exception as e:
                print(f"[Scheduler] {e}")
            time.sleep(40)

    def _daily_report(self):
        try:
            cond    = self._engine.measure_current()
            history = self._engine.analyze_history()
            self._send(_fmt_daily_report(cond, history))
        except Exception as e:
            self._send(f"❌ Помилка щоденного звіту: {e}")

    def _weekly_report(self):
        try:
            history = self._engine.analyze_history()
            self._send(_fmt_weekly_report(history))
        except Exception as e:
            self._send(f"❌ Помилка тижневого звіту: {e}")

    def _storm_check(self):
        try:
            cond    = self._engine.measure_current()
            history = self._engine.analyze_history()
            alert   = self._engine.check_storm_alert(cond, history)
            if alert and (time.time() - self._last_alert_ts) > self._alert_cooldown:
                self._send(f"⚡ *STORM ALERT* — NetGuardian\n\n{alert}")
                self._last_alert_ts = time.time()
        except Exception:
            pass


_scheduler = _WeatherScheduler()


# ══════════════════════════════════════════════════════════════════
#  ГОЛОВНИЙ БОТ
# ══════════════════════════════════════════════════════════════════

class NetGuardianBot:

    def start_polling(self, token: str, chat_id: str,
                      get_snapshot_fn:  Callable = None,
                      speedtest_fn:     Callable = None,
                      diagnose_fn:      Callable = None,
                      ai_analyzer       = None,
                      smart_agent       = None,
                      wifi_scan_fn:     Callable = None,
                      wifi_gateway_fn:  Callable = None,
                      lan_engine        = None,
                      game_engine       = None,
                      vpn_engine        = None,
                      forecast_engine   = None):
        self._api             = _TelegramAPI(token)
        self._chat_id         = str(chat_id)
        self._snapshot        = get_snapshot_fn or (lambda: {})
        self._speedtest       = speedtest_fn
        self._diagnose        = diagnose_fn
        self._ai              = ai_analyzer
        self._agent           = smart_agent
        self._wifi_scan_fn    = wifi_scan_fn
        self._wifi_gateway_fn = wifi_gateway_fn
        self._offset          = 0
        self._running         = True
        self._wifi_cache: tuple | None = None
        self._lan_engine      = lan_engine
        self._lan_monitor     = None
        self._lan_last_scan:  list = []
        self._lan_monitor_interval = 300
        self._game_engine     = game_engine
        self._game_mode_active = False
        self._vpn_engine      = vpn_engine
        self._game_last_scan: list = []

        if forecast_engine is not None:
            self._wx = forecast_engine
        else:
            try:
                from features.forecast.engine import ForecastEngine
                self._wx = ForecastEngine()
            except Exception:
                self._wx = None

        if self._wx:
            # PR #5: SmartScheduler замість старого _WeatherScheduler.
            # Він уміє:
            #   • "Перший запуск" логіка (звіт за вчора при старті)
            #   • Дедуплікація через report_history
            #   • Storm Alert з cooldown
            #   • Використовує цей же self._api (одна сесія до Telegram)
            try:
                from features.forecast.smart_scheduler import SmartScheduler
                self._smart_scheduler = SmartScheduler(self._wx)
                self._smart_scheduler.set_bot_api(self._api, self._chat_id)

                # PR #11: реєструємо popup callback щоб UI міг показати звіти
                # Записуємо в файл, який ForecastUI періодично перевіряє
                def _popup_handler(report_type: str, report: dict):
                    try:
                        import json
                        from pathlib import Path
                        from datetime import datetime
                        pending_dir = Path.home() / ".netguardian" / "pending_popups"
                        pending_dir.mkdir(parents=True, exist_ok=True)
                        fname = f"{report_type}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
                        with open(pending_dir / fname, "w", encoding="utf-8") as f:
                            json.dump({"type": report_type, "report": report},
                                      f, ensure_ascii=False)
                        print(f"[BOT] 📋 Popup записано: {fname}")
                    except Exception as e:
                        print(f"[BOT] popup handler error: {e}")

                self._smart_scheduler.set_popup_callback(_popup_handler)
                self._smart_scheduler.run_at_startup(delay_sec=12)
                print("[BOT] ✅ SmartScheduler (звіти + Storm Alert + Popup) підключено")

                # PR #21: запускаємо watcher для pending_tg/ — повідомлень від UI
                self._start_pending_tg_watcher()
            except Exception as e:
                print(f"[BOT] ⚠️ SmartScheduler init error: {e}")
                self._smart_scheduler = None
                # fallback на старий _WeatherScheduler
                _scheduler.connect(self._api, self._chat_id, self._wx)
                _scheduler.start()
        else:
            self._smart_scheduler = None

        threading.Thread(target=self._send_startup, daemon=True).start()
        threading.Thread(target=self._poll, daemon=True).start()
        # Реєструємо список команд що видно у Telegram-меню (синя кнопка "Меню")
        threading.Thread(target=self._register_commands, daemon=True).start()

    def _register_commands(self):
        """Реєструє список команд у Telegram — показується при натисканні
        на синю кнопку 'Меню' зліва від поля вводу повідомлення."""
        time.sleep(3)   # чекаємо щоб бот точно стартував
        commands = [
            {"command": "start",     "description": "🚀 Старт бота / головне меню"},
            {"command": "menu",      "description": "📋 Головне меню"},
            {"command": "status",    "description": "📊 Стан мережі"},
            {"command": "speedtest", "description": "⚡ Тест швидкості"},
            {"command": "ping",      "description": "📡 Ping до хоста"},
            {"command": "lan",       "description": "🛡️ LAN аудит"},
            {"command": "wifi",      "description": "📶 Wi-Fi інфо"},
            {"command": "diagnose",  "description": "🔬 Діагностика мережі"},
            {"command": "game",      "description": "🎮 Ігровий режим"},
            {"command": "weather",   "description": "🌦️ Погода"},
            {"command": "daily",     "description": "📊 Денний звіт"},
            {"command": "weekly",    "description": "📅 Тижневий звіт"},
            {"command": "pi",        "description": "🍓 Статус Pi"},
            {"command": "pi_logs",   "description": "📜 Логи Pi-monitor"},
            {"command": "sync",      "description": "🔄 Синхронізація з Pi"},
            {"command": "tapo",      "description": "🔌 Tapo Smart Plug"},
            {"command": "vpn",       "description": "🔐 VPN керування"},
            {"command": "ask",       "description": "🤖 Запитати AI"},
            {"command": "help",      "description": "❓ Усі команди"},
        ]
        try:
            self._api.set_my_commands(commands)
            print(f"[BOT] ✅ Зареєстровано {len(commands)} команд у Telegram меню")
        except Exception as e:
            print(f"[BOT] ⚠️ Не вдалось зареєструвати команди: {e}")

    def stop(self):
        self._running = False
        _scheduler.stop()
        if self._lan_monitor:
            self._lan_monitor.stop()

    def send_notification(self, text: str):
        self._api.send(self._chat_id, text)

    def _send_startup(self):
        time.sleep(2)
        snap     = self._snapshot()
        agent_on = "✅" if self._agent else "❌"
        tapo_on  = "✅" if (self._agent and self._agent.tapo) else "❌"
        ai_on    = "✅" if (self._ai and self._ai.available) else "❌"
        wifi_on  = "✅" if self._wifi_scan_fn else "⚠️"
        diag_on  = "✅" if self._diagnose else "❌"
        lan_on   = "✅" if self._lan_engine else "⚠️"
        game_on  = "✅" if self._game_engine else "⚠️"
        wx_on    = "✅" if self._wx else "❌"
        if self._agent and self._agent.tapo:
            mon_ok  = self._agent.tapo.is_monitoring
            tapo_on = f"✅ {'+ Voltage Monitor ✅' if mon_ok else '(монітор не запущено)'}"
        msg = (
            "🛡️ *NetGuardian AI v4.3 — Online!*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"📡 ISP: `{snap.get('isp','?')}`\n"
            f"🌍 IP: `{snap.get('ext_ip','?')}`\n"
            f"📊 Пінг: `{snap.get('ping_ms','?')} ms`\n\n"
            f"🤖 AI: {ai_on}  🔬 Діагностика: {diag_on}\n"
            f"🔄 Agent: {agent_on}  🔌 Tapo: {tapo_on}\n"
            f"📡 Wi-Fi: {wifi_on}  🛡️ LAN: {lan_on}\n"
            f"🎮 Game: {game_on}  🌦️ Weather: {wx_on}\n\n"
            "Натисни кнопку щоб відкрити меню ↓"
        )
        # Прикріплюємо кнопку щоб одразу відкрити головне меню
        kb = self._kb([
            [("📋 Відкрити головне меню", "menu:main")],
        ])
        self._api.send(self._chat_id, msg, reply_markup=kb)

    def _poll(self):
        while self._running:
            try:
                updates = self._api.get_updates(offset=self._offset)
                for upd in updates:
                    self._offset = upd["update_id"] + 1
                    # Звичайне повідомлення
                    msg = upd.get("message") or upd.get("edited_message")
                    if msg:
                        threading.Thread(
                            target=self._handle, args=(msg,), daemon=True).start()
                    # Callback від inline-кнопок
                    cbq = upd.get("callback_query")
                    if cbq:
                        threading.Thread(
                            target=self._handle_callback, args=(cbq,), daemon=True).start()
            except Exception as e:
                print(f"[Bot] Poll: {e}")
                time.sleep(5)

    def _handle_callback(self, cbq: dict):
        """Обробляє натискання inline-кнопок.
        FIX: answer_callback в окремому потоці щоб Telegram одразу прибрав
        loading-spinner з кнопки, а ми спокійно робимо довгу операцію."""
        try:
            chat = cbq.get("message", {}).get("chat", {})
            if str(chat.get("id", "")) != self._chat_id:
                return
            data = cbq.get("data", "")
            cb_id = cbq.get("id", "")
            msg_id = cbq.get("message", {}).get("message_id")

            # КРИТИЧНО: answer_callback в окремому потоці — інакше Telegram
            # тримає кнопку в "loading" поки ми робимо довгу операцію
            threading.Thread(
                target=lambda: self._api.answer_callback(cb_id),
                daemon=True
            ).start()

            # data має формат "menu:dashboard" / "game:on" / "tweak:on:nagle"
            parts = data.split(":")
            action = parts[0]

            if action == "menu":
                page = parts[1] if len(parts) > 1 else "main"
                self._render_menu_page(page, msg_id)
            elif action == "game":
                sub = parts[1] if len(parts) > 1 else ""
                if sub == "on":
                    self._game_on("", None)
                elif sub == "off":
                    self._game_off("", None)
                elif sub == "verify":
                    self._game_verify("", None)
                elif sub == "ping":
                    self._game_ping("", None)
                elif sub == "boostgame":
                    self._game_boost_current_games("", None)
                elif sub == "tweaks":
                    self._render_tweaks_menu(msg_id)
            elif action == "tweak":
                # tweak:on:nagle | tweak:off:nagle
                if len(parts) >= 3:
                    self._game_tweaks(f"{parts[1]} {parts[2]}", None)
            elif action == "lan":
                sub = parts[1] if len(parts) > 1 else ""
                if sub == "scan":
                    self._cmd_lan("scan", None)
                elif sub == "devices":
                    self._cmd_lan("devices", None)
                elif sub == "banned":
                    self._cmd_banned("", None)
            elif action == "dash":
                sub = parts[1] if len(parts) > 1 else ""
                if sub == "status":  self._cmd_status("", None)
                elif sub == "speed": self._cmd_speedtest("", None)
                elif sub == "ping":  self._cmd_ping("", None)
            elif action == "wifi":
                self._cmd_wifi("", None)
            elif action == "diag":
                self._cmd_diagnose("", None)
            elif action == "vpn":
                sub = parts[1] if len(parts) > 1 else ""
                if sub == "auto":
                    self._vpn_auto_connect("", None)
                elif sub == "status":
                    self._cmd_vpn("", None)
                elif sub == "list":
                    self._cmd_vpn("list", None)
                elif sub == "disconnect":
                    self._cmd_vpn("disconnect", None)
                elif sub == "ip":
                    self._cmd_vpn("ip", None)
            elif action == "noop":
                pass    # для декоративних кнопок
        except Exception as e:
            print(f"[Bot] callback error: {e}")
            import traceback; traceback.print_exc()

    def _auth(self, msg): return str(msg.get("chat",{}).get("id","")) == self._chat_id
    def _send(self, t, mid=None): self._api.send(self._chat_id, t, reply_to=mid)
    def _typing(self): self._api.typing(self._chat_id)

    def _start_pending_tg_watcher(self):
        """PR #21: Періодично перевіряє ~/.netguardian/pending_tg/
        і шле повідомлення які записали інші модулі (vpn_ui, dashboard).
        Це безпечний канал передачі сповіщень з UI у Telegram.
        """
        import threading, time
        def _loop():
            from pathlib import Path
            import json
            pending_dir = Path.home() / ".netguardian" / "pending_tg"
            while True:
                try:
                    if pending_dir.exists():
                        for f in sorted(pending_dir.glob("*.json")):
                            try:
                                with open(f, "r", encoding="utf-8") as fh:
                                    data = json.load(fh)
                                text = data.get("text", "")
                                if text:
                                    self._api.send(self._chat_id, text)
                                    print(f"[BOT] 📨 TG sent: {f.name}")
                                # Видаляємо в будь-якому випадку
                                f.unlink(missing_ok=True)
                            except Exception as e:
                                print(f"[BOT] pending_tg error: {e}")
                                try: f.unlink(missing_ok=True)
                                except Exception: pass
                except Exception as e:
                    print(f"[BOT] pending_tg loop error: {e}")
                time.sleep(5)
        threading.Thread(target=_loop, daemon=True, name="PendingTgWatcher").start()
        print("[BOT] ✅ pending_tg watcher запущено")

    def _handle(self, msg: dict):
        if not self._auth(msg): return
        text = (msg.get("text") or "").strip()
        mid  = msg.get("message_id")
        if not text: return
        if text.startswith("/"):
            parts = text.split(None, 1)
            cmd   = parts[0].lower().split("@")[0]
            args  = parts[1].strip() if len(parts) > 1 else ""
        else:
            cmd, args = "/ask", text
        routes = {
            "/start":    self._cmd_help,
            "/help":     self._cmd_help,
            "/status":   self._cmd_status,     "/s": self._cmd_status,
            "/ping":     self._cmd_ping,        "/p": self._cmd_ping,
            "/diagnose": self._cmd_diagnose,    "/d": self._cmd_diagnose,
            "/ask":      self._cmd_ask,         "/?": self._cmd_ask,
            "/scan":     self._cmd_scan,
            "/speedtest":self._cmd_speedtest,   "/st": self._cmd_speedtest,
            "/predict":  self._cmd_predict,
            "/ask":      self._cmd_ask,         "/a": self._cmd_ask,
            "/search":   self._cmd_search,
            "/fix":      self._cmd_fix,
            "/tapo":     self._cmd_tapo,
            "/events":   self._cmd_events,
            "/agent":    self._cmd_agent,
            "/wifi":     self._cmd_wifi,        "/w": self._cmd_wifi,
            "/dns":      self._cmd_dns,
            "/lan":      self._cmd_lan,         "/l": self._cmd_lan,
            "/game":     self._cmd_game,        "/g": self._cmd_game,
            "/weather":  self._cmd_weather,
            "/forecast": self._cmd_forecast,
            "/services": self._cmd_services_wx,
            "/throttle": self._cmd_throttle,
            "/sla":      self._cmd_sla,
            "/besttime": self._cmd_besttime,
            "/alert":    self._cmd_alert,
            # PR #5: SmartScheduler команди (примусове надсилання звітів)
            "/daily":      self._cmd_daily,
            "/weekly":     self._cmd_weekly,
            "/pi_status":  self._cmd_pi_status,
            "/pi":         self._cmd_pi_status,  # коротка
            "/pi_logs":    self._cmd_pi_logs,    # PR #7: логи з Pi
            "/logs":       self._cmd_pi_logs,    # коротка
            "/sync":       self._cmd_sync,       # PR #8: примусова синхронізація
            "/storm_test": self._cmd_storm_test,
            "/test_catchup": self._cmd_test_catchup,  # PR #9: тестовий catch-up
            "/test_pi":      self._cmd_test_pi,       # PR #9: тестовий Pi offline
            # NEW: розширений функціонал LAN Security (як в UI)
            "/banned":     self._cmd_banned,
            "/block":      self._cmd_block,
            "/unblock":    self._cmd_unblock,
            "/trust":      self._cmd_trust,
            "/untrust":    self._cmd_untrust,
            "/rename":     self._cmd_rename,
            "/details":    self._cmd_details,
            "/deep":       self._cmd_deep_identify,
            "/ports":      self._cmd_ports,
            "/traceroute": self._cmd_traceroute, "/tr": self._cmd_traceroute,
            "/router":     self._cmd_router,
            "/mystats":    self._cmd_mystats,
            "/channel":    self._cmd_channel,  "/ch": self._cmd_channel,
            # Меню-система — секції утиліти
            "/menu":        self._cmd_menu,
            "/back":        self._cmd_menu,
            "/home":        self._cmd_menu,
            "/m_dashboard": self._cmd_menu_dashboard,
            "/m_lan":       self._cmd_menu_lan,
            "/m_diag":      self._cmd_menu_diag,
            "/m_wifi":      self._cmd_menu_wifi,
            "/m_tapo":      self._cmd_menu_tapo,
            "/m_game":      self._cmd_menu_game,
            "/m_weather":   self._cmd_menu_weather,
            "/m_ai":        self._cmd_menu_ai,
            "/m_vpn":       self._cmd_menu_vpn,
            # VPN команди
            "/vpn":         self._cmd_vpn,
        }
        # /start теж показує головне меню замість /help
        if cmd == "/start":
            handler = self._cmd_menu
        handler = routes.get(cmd)
        if handler:
            try: handler(args, mid)
            except Exception as e: self._send(f"❌ Помилка: `{e}`", mid)
        else:
            self._send(f"❓ Невідома команда `{cmd}`\n/help — всі команди", mid)

    # ═══════════════════════════════════════════════════════
    #  МЕНЮ-СИСТЕМА З INLINE-КНОПКАМИ
    # ═══════════════════════════════════════════════════════
    def _kb(self, rows: list) -> dict:
        """Будує inline_keyboard. rows = [[(text, callback_data), ...], ...]."""
        return {"inline_keyboard": [
            [{"text": txt, "callback_data": data} for txt, data in row]
            for row in rows
        ]}

    def _async_delete(self, msg_id: int):
        """Видаляє повідомлення асинхронно (без блокування UI)."""
        if not msg_id: return
        threading.Thread(
            target=lambda: self._api.delete_message(self._chat_id, msg_id),
            daemon=True
        ).start()

    def _send_with_nav(self, text: str, section: str = "main"):
        """Надсилає повідомлення з мініатюрним nav-бар внизу.
        FIX: видаляє попереднє меню-повідомлення щоб нове меню завжди
        з'являлось в самому низу чату. Користувачу не треба скролити вгору.

        section: 'main', 'game', 'lan', 'dash', 'wifi', 'diag' — підказує
        куди користувач "працював" — туди й буде швидка кнопка повернення.
        """
        nav_buttons = {
            "game": [
                ("⚙️ Меню Game Mode", "menu:game"),
                ("📋 Головне", "menu:main"),
            ],
            "lan": [
                ("🛡️ Меню LAN", "menu:lan"),
                ("📋 Головне", "menu:main"),
            ],
            "dash": [
                ("📊 Меню Дашборд", "menu:dashboard"),
                ("📋 Головне", "menu:main"),
            ],
            "wifi": [
                ("📡 Меню Wi-Fi", "menu:wifi"),
                ("📋 Головне", "menu:main"),
            ],
            "diag": [
                ("🔬 Меню Діагностика", "menu:diag"),
                ("📋 Головне", "menu:main"),
            ],
            "main": [
                ("📋 Головне меню", "menu:main"),
            ],
        }
        row = nav_buttons.get(section, nav_buttons["main"])
        kb = self._kb([row])

        # Видаляємо попереднє nav-повідомлення асинхронно (не чекаємо HTTP)
        old_msg_id = getattr(self, "_last_nav_msg_id", None)
        if old_msg_id:
            self._async_delete(old_msg_id)
            self._last_nav_msg_id = None

        # Надсилаємо нове меню внизу
        resp = self._api.send(self._chat_id, text, reply_markup=kb)
        # Зберігаємо ID для наступного видалення
        try:
            if resp and resp.get("result", {}).get("message_id"):
                self._last_nav_msg_id = resp["result"]["message_id"]
        except Exception: pass

    def _cmd_menu(self, args, mid):
        """Головне меню — вибір розділу."""
        self._render_menu_page("main", None)

    def _render_menu_page(self, page: str, edit_msg_id: int = None):
        """Рендерить сторінку меню.
        FIX: завжди ВИДАЛЯЄ попереднє меню і надсилає нове внизу —
        щоб активне меню не губилось вгорі чату.
        edit_msg_id — id повідомлення що натиснули (теж видаляємо)."""
        if page == "main":
            text, kb = self._build_main_menu()
        elif page == "dashboard":
            text, kb = self._build_menu_dashboard()
        elif page == "lan":
            text, kb = self._build_menu_lan()
        elif page == "diag":
            text, kb = self._build_menu_diag()
        elif page == "wifi":
            text, kb = self._build_menu_wifi()
        elif page == "tapo":
            text, kb = self._build_menu_tapo()
        elif page == "game":
            text, kb = self._build_menu_game()
        elif page == "weather":
            text, kb = self._build_menu_weather()
        elif page == "ai":
            text, kb = self._build_menu_ai()
        elif page == "vpn":
            text, kb = self._build_menu_vpn()
        else:
            text, kb = self._build_main_menu()

        # Видаляємо старе nav-повідомлення асинхронно
        old_nav_id = getattr(self, "_last_nav_msg_id", None)
        if old_nav_id and old_nav_id != edit_msg_id:
            self._async_delete(old_nav_id)

        # Видаляємо повідомлення що натиснули — теж асинхронно
        if edit_msg_id:
            self._async_delete(edit_msg_id)

        # Надсилаємо нове меню ВНИЗУ
        resp = self._api.send(self._chat_id, text, reply_markup=kb)
        try:
            if resp and resp.get("result", {}).get("message_id"):
                self._last_nav_msg_id = resp["result"]["message_id"]
        except Exception: pass

    def _build_main_menu(self) -> tuple[str, dict]:
        """Головне меню — overview + 8 кнопок-розділів."""
        snap = self._snapshot() if callable(self._snapshot) else {}
        ping = snap.get("ping_ms")
        dl   = snap.get("dl_mbps")
        isp  = snap.get("isp", "?")

        ping_s = f"{ping} ms" if ping else "—"
        dl_s   = f"{dl:.0f} Mbps" if isinstance(dl, (int, float)) else "—"

        # Перевіряємо стан Game Mode
        game_state = "🟢 АКТИВНИЙ"
        try:
            if self._game_engine and self._game_engine.is_active():
                game_state = "🟢 АКТИВНИЙ"
            else:
                game_state = "⚫ Вимкнений"
        except Exception:
            game_state = "⚪ ?"

        text = (
            f"🛡️ *NETGUARDIAN AI* — ГОЛОВНЕ МЕНЮ\n"
            f"━━━━━━━━━━━━━━━━━━━\n\n"
            f"📡 *Стан мережі:*\n"
            f"  • ISP: `{isp}`\n"
            f"  • Пінг: `{ping_s}`  ·  Швидкість: `{dl_s}`\n"
            f"  • Game Mode: {game_state}\n\n"
            f"━━━━━━━━━━━━━━━━━━━\n"
            f"📋 *Оберіть розділ:*\n\n"
            f"_💡 Меню завжди буде знизу — результати попередніх команд "
            f"залишаються у чаті як історія._"
        )
        kb = self._kb([
            [("📊 Дашборд", "menu:dashboard"), ("🛡️ LAN Аудит", "menu:lan")],
            [("🔬 Діагностика", "menu:diag"), ("📡 Wi-Fi / DNS", "menu:wifi")],
            [("🎮 Ігровий режим", "menu:game"), ("🔌 Tapo", "menu:tapo")],
            [("🌦️ Погода", "menu:weather"), ("🔐 VPN", "menu:vpn")],
            [("🤖 AI", "menu:ai")],
        ])
        return text, kb

    def _build_menu_dashboard(self) -> tuple[str, dict]:
        text = (
            "📊 *ДАШБОРД І МОНІТОРИНГ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Швидкі дії — натисни кнопку:\n\n"
            "• *Стан* — загальний огляд\n"
            "• *Тест швидкості* — DL/UL\n"
            "• *Пінг* — до 8.8.8.8\n\n"
            "Або команди:\n"
            "`/mystats` `/predict` `/ping <host>`"
        )
        kb = self._kb([
            [("📊 Стан", "dash:status"), ("⚡ Тест швидкості", "dash:speed")],
            [("📡 Пінг", "dash:ping")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_lan(self) -> tuple[str, dict]:
        text = (
            "🛡️ *LAN АУДИТ / ПРИСТРОЇ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Натисни щоб діяти:\n\n"
            "• *Сканувати* — повний скан мережі\n"
            "• *Пристрої* — список з останнього скану\n"
            "• *Заблоковані* — список banned\n\n"
            "Команди керування пристроями:\n"
            "`/block <mac>` `/unblock <mac>`\n"
            "`/trust <mac>` `/details <mac>`\n"
            "`/deep <ip>` `/router`"
        )
        kb = self._kb([
            [("🔍 Сканувати", "lan:scan"), ("📋 Пристрої", "lan:devices")],
            [("🚫 Заблоковані", "lan:banned")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_diag(self) -> tuple[str, dict]:
        text = (
            "🔬 *ДІАГНОСТИКА МЕРЕЖІ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "• *Повна діагностика* — ISP, DNS, MTU, втрата пакетів\n\n"
            "Команди:\n"
            "`/scan <host>` — порти\n"
            "`/traceroute <host>` (`/tr`) — маршрут\n"
            "`/ports <ip>` — відкриті порти\n"
            "`/search <query>` — AI-пошук рішень"
        )
        kb = self._kb([
            [("🔬 Запустити діагностику", "diag:run")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_wifi(self) -> tuple[str, dict]:
        text = (
            "📡 *Wi-Fi & DNS*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "• *Wi-Fi інфо* — SSID, сила, канал\n\n"
            "Команди:\n"
            "`/wifi channels` — канали поруч\n"
            "`/channel` (`/ch`) — рекомендація\n"
            "`/dns` `/dns benchmark`\n"
            "`/dns set <addr>`"
        )
        kb = self._kb([
            [("📡 Wi-Fi інфо", "wifi:info")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_tapo(self) -> tuple[str, dict]:
        text = (
            "🔌 *TAPO SMART PLUG*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Команди:\n"
            "`/tapo` — стан розетки\n"
            "`/tapo on` / `/tapo off` / `/tapo toggle`\n"
            "`/tapo guard` — захист від перевант."
        )
        kb = self._kb([
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_game(self) -> tuple[str, dict]:
        # Перевіряємо стан
        is_on = False
        try:
            if self._game_engine: is_on = self._game_engine.is_active()
        except Exception: pass

        state_text = "🟢 *АКТИВНИЙ*" if is_on else "⚫ *Вимкнений*"

        text = (
            f"🎮 *ІГРОВИЙ РЕЖИМ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            f"Стан: {state_text}\n\n"
            f"*Швидкі дії:*"
        )

        # Динамічні кнопки залежно від стану
        if is_on:
            primary_row = [("⏹ Вимкнути режим", "game:off"),
                          ("✓ Перевірити", "game:verify")]
        else:
            primary_row = [("🚀 Увімкнути режим", "game:on"),
                          ("✓ Перевірити", "game:verify")]

        kb = self._kb([
            primary_row,
            [("⚙️ Окремі tweaks", "game:tweaks"),
             ("🚀 Boost запущену гру", "game:boostgame")],
            [("📡 Тест пінгу", "game:ping")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_weather(self) -> tuple[str, dict]:
        text = (
            "🌦️ *ПОГОДА & ПРОГНОЗ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Команди:\n"
            "`/weather` — поточна погода\n"
            "`/forecast` — прогноз тижня\n"
            "`/services` — вплив на сервіси\n"
            "`/throttle` — прогноз throttling\n"
            "`/besttime` — найкращий час гри"
        )
        kb = self._kb([
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _build_menu_ai(self) -> tuple[str, dict]:
        text = (
            "🤖 *AI АСИСТЕНТ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Команди:\n"
            "`/ask <питання>` — запитати AI\n"
            "`/agent` — Smart Agent статус\n"
            "`/agent scan` — запустити\n"
            "`/events` — журнал подій"
        )
        kb = self._kb([
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _render_tweaks_menu(self, edit_msg_id: int = None):
        """Окреме меню з кнопками для кожного tweak'а.
        FIX: видаляє старе меню щоб нове з'явилось внизу."""
        text = (
            "⚙️ *GAME MODE — ОКРЕМІ TWEAKS*\n━━━━━━━━━━━━━━━━━━━\n\n"
            "Кожен tweak можна вмикати/вимикати окремо.\n"
            "Натисни кнопку щоб застосувати:"
        )
        rows = []
        items = list(self._GAME_TWEAKS.items())
        for slug, t in items:
            label = f"{t['icon']} {t['name'][:22]}"
            rows.append([(f"▶️ {label}", f"tweak:on:{slug}")])
        rows.append([("↩️ Назад до Game Mode", "menu:game")])
        kb = self._kb(rows)

        # Видаляємо старе nav-повідомлення асинхронно
        old_nav_id = getattr(self, "_last_nav_msg_id", None)
        if old_nav_id and old_nav_id != edit_msg_id:
            self._async_delete(old_nav_id)
        # Видаляємо повідомлення що натиснули
        if edit_msg_id:
            self._async_delete(edit_msg_id)

        resp = self._api.send(self._chat_id, text, reply_markup=kb)
        try:
            if resp and resp.get("result", {}).get("message_id"):
                self._last_nav_msg_id = resp["result"]["message_id"]
        except Exception: pass

    # Старі _cmd_menu_* лишаємо як fallback (для тих хто введе /m_dashboard руками)
    def _cmd_menu_dashboard(self, args, mid):
        text, kb = self._build_menu_dashboard()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_lan(self, args, mid):
        text, kb = self._build_menu_lan()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_diag(self, args, mid):
        text, kb = self._build_menu_diag()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_wifi(self, args, mid):
        text, kb = self._build_menu_wifi()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_tapo(self, args, mid):
        text, kb = self._build_menu_tapo()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_game(self, args, mid):
        text, kb = self._build_menu_game()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_weather(self, args, mid):
        text, kb = self._build_menu_weather()
        self._api.send(self._chat_id, text, reply_markup=kb)
    def _cmd_menu_ai(self, args, mid):
        text, kb = self._build_menu_ai()
        self._api.send(self._chat_id, text, reply_markup=kb)

    # ═══════════════════════════════════════════════════════
    #  VPN — меню та команди
    # ═══════════════════════════════════════════════════════
    def _build_menu_vpn(self) -> tuple[str, dict]:
        """VPN-меню. Дивимось стан engine: connected/disconnected, скільки профілів."""
        eng = self._vpn_engine
        if not eng:
            text = (
                "🔐 *VPN — недоступний*\n━━━━━━━━━━━━━━━━━━━\n\n"
                "VPN engine не ініціалізовано.\n"
                "Перезапусти NetGuardian і переконайся що `features/vpn/`\n"
                "присутня у проекті."
            )
            kb = self._kb([[("📋 Головне меню", "menu:main")]])
            return text, kb

        try:
            from features.vpn.engine import ConnectionState
            connected = (eng.stats.state == ConnectionState.CONNECTED)
        except Exception:
            connected = False

        profile_count = len(eng.profiles) if hasattr(eng, "profiles") else 0
        active_profile = eng.stats.active_profile or "—"
        public_ip = eng.stats.public_ip_after if connected else "—"

        state_emoji = "🟢 *ПІДКЛЮЧЕНО*" if connected else "⚫ *Відключено*"

        text = (
            f"🔐 *VPN КЕРУВАННЯ*\n━━━━━━━━━━━━━━━━━━━\n\n"
            f"Стан: {state_emoji}\n"
            f"📁 Імпортованих профілів: `{profile_count}`\n"
        )
        if connected:
            text += (
                f"📡 Активний: `{active_profile}`\n"
                f"🌍 Публічна IP: `{public_ip}`\n"
            )
        text += "\n*Швидкі дії:*"

        # Динамічні кнопки
        if connected:
            primary_row = [("⏹ Відключити", "vpn:disconnect"),
                          ("📊 Статус", "vpn:status")]
        else:
            primary_row = [("🚀 Авто-підключення", "vpn:auto"),
                          ("📁 Список профілів", "vpn:list")]

        kb = self._kb([
            primary_row,
            [("🌐 Перевірити IP", "vpn:ip")],
            [("↩️ Головне меню", "menu:main")],
        ])
        return text, kb

    def _cmd_menu_vpn(self, args, mid):
        text, kb = self._build_menu_vpn()
        self._api.send(self._chat_id, text, reply_markup=kb)

    def _cmd_vpn(self, args, mid):
        """
        Головна VPN-команда:
          /vpn              — статус
          /vpn list         — список профілів з ping/score
          /vpn auto         — auto-connect best
          /vpn connect <name> — підключитись до конкретного
          /vpn disconnect   — відключитись
          /vpn ip           — поточна публічна IP
        """
        eng = self._vpn_engine
        if not eng:
            self._send_with_nav(
                "❌ VPN engine не ініціалізовано.\n"
                "_Перезапусти NetGuardian._",
                section="main"); return

        parts = args.strip().split(None, 1) if args else []
        sub = parts[0].lower() if parts else ""

        # /vpn — статус
        if not sub or sub == "status":
            try:
                from features.vpn.engine import ConnectionState
                connected = (eng.stats.state == ConnectionState.CONNECTED)
            except Exception:
                connected = False

            profile_count = len(eng.profiles)
            active = eng.stats.active_profile or "—"
            public_ip = eng.stats.public_ip_after if connected else "—"

            uptime_s = ""
            if connected and eng.stats.connected_since:
                up = int(time.time() - eng.stats.connected_since)
                h, r = divmod(up, 3600); m, _ = divmod(r, 60)
                uptime_s = f"\n⏱ Uptime: `{h:02d}:{m:02d}`"

            state = "🟢 ПІДКЛЮЧЕНО" if connected else "⚫ Відключено"
            self._send_with_nav(
                f"🔐 *VPN СТАТУС*\n━━━━━━━━━━━━━━━━━━━\n\n"
                f"Стан: *{state}*\n"
                f"📁 Профілів: `{profile_count}`\n"
                f"📡 Активний: `{active}`\n"
                f"🌍 Public IP: `{public_ip}`"
                f"{uptime_s}",
                section="main"); return

        # /vpn list
        if sub == "list":
            if not eng.profiles:
                self._send_with_nav(
                    "📁 *Немає імпортованих VPN-профілів*\n\n"
                    "Імпортуй `.conf` (WireGuard) або `.ovpn` (OpenVPN)\n"
                    "у GUI вкладці VPN.",
                    section="main"); return

            lines = ["📁 *VPN ПРОФІЛІ*", "━━━━━━━━━━━━━━━━━━━", ""]
            for i, p in enumerate(list(eng.profiles.values())[:20], 1):
                proto_icon = "🔐" if "wireguard" in p.protocol.value.lower() else "🛡"
                lines.append(f"{i}. {proto_icon} *{p.name}*")
                lines.append(f"   📡 `{p.server_host or p.server_ip}:{p.port}`")
                if p.location and p.location != "—":
                    lines.append(f"   📍 {p.location}")
                lines.append("")

            lines.extend([
                "━━━━━━━━━━━━━━━━━━━",
                "*Команди:*",
                "`/vpn auto` — авто-вибір найкращого",
                "`/vpn connect <name>` — підключитись",
            ])
            self._send_with_nav("\n".join(lines), section="main"); return

        # /vpn auto
        if sub == "auto":
            self._vpn_auto_connect("", mid); return

        # /vpn connect <name>
        if sub == "connect":
            if len(parts) < 2:
                self._send_with_nav(
                    "⚠️ Використай: `/vpn connect <name>`\n"
                    "`/vpn list` — список доступних",
                    section="main"); return
            name = parts[1].strip()
            self._send(f"🔐 Підключаюсь до `{name}`...", mid)

            def _work():
                try:
                    ok, msg = eng.connect(name, enable_kill_switch=True)
                    icon = "✅" if ok else "❌"
                    self._send_with_nav(f"{icon} {msg}", section="main")
                except Exception as e:
                    self._send_with_nav(f"❌ Помилка: `{e}`", section="main")
            threading.Thread(target=_work, daemon=True).start()
            return

        # /vpn disconnect
        if sub == "disconnect":
            self._send("⏹ Відключаю VPN...", mid)
            def _work():
                try:
                    ok, msg = eng.disconnect(reason="bot")
                    icon = "✅" if ok else "❌"
                    self._send_with_nav(
                        f"{icon} *VPN відключено*\n\n_{msg}_",
                        section="main")
                except Exception as e:
                    self._send_with_nav(f"❌ Помилка: `{e}`", section="main")
            threading.Thread(target=_work, daemon=True).start()
            return

        # /vpn ip
        if sub == "ip":
            self._typing()
            def _work():
                try:
                    # Простий запит до ip-api.com без залежності від geo_resolver
                    import urllib.request, json
                    url = ("http://ip-api.com/json/?fields="
                           "status,query,country,countryCode,city,isp")
                    req = urllib.request.Request(url, headers={
                        "User-Agent": "NetGuardian/1.0"
                    })
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        data = json.loads(resp.read().decode("utf-8"))

                    if data.get("status") != "success":
                        self._send_with_nav(
                            f"⚠️ Не вдалось отримати IP: {data.get('message', '?')}",
                            section="main")
                        return

                    ip      = data.get("query", "?")
                    country = data.get("country", "?")
                    city    = data.get("city", "?")
                    isp     = data.get("isp", "?")

                    loc = (f"\n📍 Локація: `{country}, {city}`"
                           f"\n🏢 ISP: `{isp}`")

                    self._send_with_nav(
                        f"🌍 *ПОТОЧНА ПУБЛІЧНА IP*\n━━━━━━━━━━━━━━━━━━━\n\n"
                        f"`{ip}`{loc}",
                        section="main")
                except Exception as e:
                    self._send_with_nav(f"❌ Помилка: `{e}`", section="main")
            threading.Thread(target=_work, daemon=True).start()
            return

        self._send_with_nav(
            f"❓ Невідома підкоманда `{sub}`\n\n"
            "Доступно: `/vpn`, `/vpn list`, `/vpn auto`,\n"
            "`/vpn connect <name>`, `/vpn disconnect`, `/vpn ip`",
            section="main")

    def _vpn_auto_connect(self, args, mid):
        """Авто-вибір і підключення до найкращого VPN-сервера."""
        eng = self._vpn_engine
        if not eng:
            self._send_with_nav("❌ VPN engine недоступний.", section="main"); return
        if not eng.profiles:
            self._send_with_nav(
                "📁 *Немає імпортованих профілів*\n\n"
                "Імпортуй `.conf` або `.ovpn` у GUI вкладці VPN.",
                section="main"); return

        self._send(
            "🚀 *АВТО-ПІДКЛЮЧЕННЯ — пошук найкращого сервера*\n"
            f"_Аналізую {len(eng.profiles)} серверів... ~10-20с_", mid)

        def _work():
            log_lines = []
            try:
                # auto_connect_best викликає auto_select_best_server та connect
                ok, msg = eng.auto_connect_best(
                    enable_kill_switch=True,
                    log_cb=lambda t: log_lines.append(t) if t and t.strip() else None
                )
                summary = "\n".join(l for l in log_lines[-20:] if l)
                if ok:
                    self._send_with_nav(
                        f"✅ *VPN АВТО-ПІДКЛЮЧЕНО*\n━━━━━━━━━━━━━━━━━━━\n\n"
                        f"_{msg}_\n\n"
                        f"```\n{summary[:1500]}\n```",
                        section="main")
                else:
                    self._send_with_nav(
                        f"❌ *Не вдалось підключитись*\n\n"
                        f"`{msg}`\n\n```\n{summary[:1000]}\n```",
                        section="main")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()[-300:]
                self._send_with_nav(
                    f"❌ Помилка: `{e}`\n\n```\n{tb}\n```",
                    section="main")
        threading.Thread(target=_work, daemon=True).start()

    # ── /help ─────────────────────────────────────────────────────
    def _cmd_help(self, args, mid):
        self._send(
            "╔══════════════════════════════╗\n"
            "║  🛡️  *NETGUARDIAN AI* — БОТ   ║\n"
            "╚══════════════════════════════╝\n\n"
            "📊 *ДАШБОРД І МОНІТОРИНГ*\n"
            "• /status — загальний стан мережі\n"
            "• /mystats — розширена статистика\n"
            "• /ping `[host]` — пінг (default: 8.8.8.8)\n"
            "• /speedtest — тест швидкості\n"
            "• /predict — прогноз стабільності\n\n"
            "🛡️ *БЕЗПЕКА LAN*\n"
            "• /lan — стан LAN Security\n"
            "• /lan scan — сканувати мережу\n"
            "• /lan devices — список пристроїв\n"
            "• /lan wifi / wired — фільтр\n"
            "• /banned — заблоковані пристрої\n"
            "• /block `<mac>` — заблокувати\n"
            "• /unblock `<mac>` — розблокувати\n"
            "• /trust `<mac>` — довіряти\n"
            "• /rename `<mac>` `<name>` — ім'я\n"
            "• /details `<mac>` — тех.деталі\n"
            "• /deep `<ip>` — ідентифікація\n\n"
            "🔍 *ДІАГНОСТИКА*\n"
            "• /diagnose — повна діагностика\n"
            "• /scan `[host]` — порти\n"
            "• /ports `<ip>` — детальні порти\n"
            "• /traceroute `<host>` — маршрут\n"
            "• /router — інфо про роутер\n"
            "• /search `<query>` — пошук рішення\n"
            "• /fix `<код>` — виправити помилку\n\n"
            "📡 *Wi-Fi & DNS*\n"
            "• /wifi — інфо Wi-Fi\n"
            "• /wifi channels — канали навколо\n"
            "• /channel — *рекомендація каналу*\n"
            "• /channel scan — свіжий скан\n"
            "• /dns — перевірка DNS\n"
            "• /dns benchmark — швидкість DNS\n"
            "• /dns set `<addr>` — змінити DNS\n\n"
            "🔌 *TAPO SMART PLUG*\n"
            "• /tapo — стан розетки\n"
            "• /tapo on / off — увімкнути/вимкнути\n"
            "• /tapo guard — захист від перевант.\n\n"
            "🎮 *GAME MODE*\n"
            "• /game — стан\n"
            "• /game on / off — режим гри\n"
            "• /game help — повний список\n"
            "• /game boost / ram / dns — оптимізація\n"
            "• /game procs / kill — процеси\n"
            "• /game net `<exe> <lvl>` — QoS мережі\n"
            "• /game prio `<exe> <lvl>` — CPU пріоритет\n"
            "• /game qos — активні QoS-правила\n"
            "• /game boostgame — авто для запущ. ігор\n"
            "• /game ping — пінг серверів\n\n"
            "🌦️ *WEATHER FORECAST*\n"
            "• /weather — поточна погода + інтернет\n"
            "• /forecast — прогноз на тиждень\n"
            "• /sla /throttle /besttime\n\n"
            "🤖 *AI & АВТОМАТИЗАЦІЯ*\n"
            "• /ask `<питання>` — AI асистент\n"
            "• /agent — Smart Agent\n"
            "• /events — журнал подій\n\n"
            "⚡ *ШВИДКІ АЛІАСИ:*\n"
            "/s /p /d /st /a /w /l /g\n\n"
            "📅 *АВТО-ЗВІТИ:*\n"
            "• 00:00 — денний звіт\n"
            "• Нд 23:55 — тижневий звіт\n"
            "• Алерти — при виявленні нових/"
            "небезпечних пристроїв",
            mid)

    # ══════════════════════════════════════════════════════
    #  WEATHER FORECAST (v4.3)
    # ══════════════════════════════════════════════════════

    def _wx_check(self, mid) -> bool:
        if self._wx: return True
        self._send("❌ *ForecastEngine* недоступний.\n_Переконайся що `core/forecast.py` є._", mid)
        return False

    def _cmd_weather(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        def _work():
            try:
                cond    = self._wx.measure_current()
                history = self._wx.analyze_history()
                self._api.send(self._chat_id, _fmt_weather(cond, history))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_forecast(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        def _work():
            try:
                history = self._wx.analyze_history()
                self._api.send(self._chat_id, _fmt_forecast(history))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_services_wx(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        self._send("⏳ Перевіряю сервіси… (~10с)", mid)
        def _work():
            try:
                services = self._wx.check_services(force=True)
                self._api.send(self._chat_id, _fmt_services_weather(services))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_throttle(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        self._send("⏳ Перевіряю throttling… (~20 сек)", mid)
        def _work():
            try:
                res = self._wx.check_throttling()
                self._api.send(self._chat_id, _fmt_throttle(res))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_sla(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        def _work():
            try:
                history = self._wx.analyze_history()
                self._api.send(self._chat_id, _fmt_sla(history))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_besttime(self, args, mid):
        if not self._wx_check(mid): return
        self._typing()
        def _work():
            try:
                history = self._wx.analyze_history()
                self._api.send(self._chat_id, _fmt_besttime(history))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_alert(self, args, mid):
        sub = args.strip().lower()
        if sub == "on":
            _scheduler.set_alerts(True)
            self._send("✅ *Авто-сповіщення увімкнені.*", mid)
        elif sub == "off":
            _scheduler.set_alerts(False)
            self._send("🔕 *Авто-сповіщення вимкнені.*", mid)
        else:
            state = "🟢 увімкнені" if _scheduler._alerts_enabled else "🔴 вимкнені"
            self._send(f"*Авто-сповіщення:* {state}\n\n/alert on · /alert off\n\n"
                       "_Щоденний звіт: 00:00 · Тижневий: Нд 23:55_", mid)

    # ══════════════════════════════════════════════════════
    #  PR #5: SmartScheduler команди
    # ══════════════════════════════════════════════════════

    def _cmd_daily(self, args, mid):
        """/daily — примусово надіслати звіт за вчора."""
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return
        self._typing()
        def _work():
            ok, msg = self._smart_scheduler.force_send_daily()
            if ok:
                self._send(f"✅ {msg}", mid)
            else:
                self._send(f"⚠️ {msg}", mid)
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_weekly(self, args, mid):
        """/weekly — примусово надіслати тижневий звіт."""
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return
        self._typing()
        def _work():
            ok, msg = self._smart_scheduler.force_send_weekly()
            if ok:
                self._send(f"✅ {msg}", mid)
            else:
                self._send(f"⚠️ {msg}", mid)
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_pi_status(self, args, mid):
        """/pi_status — статус Raspberry Pi-агента."""
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return
        self._typing()
        def _work():
            try:
                text = self._smart_scheduler.get_pi_status_text()
                self._send(text, mid)
            except Exception as e:
                self._send(f"❌ Помилка: {e}", mid)
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_sync(self, args, mid):
        """/sync — примусова синхронізація з Pi через MQTT + fill_gaps_from_pi.

        Шле cmd/send_history Pi, чекає 6 сек, потім доллює дані у forecast.db.
        """
        self._typing()

        def _work():
            try:
                # Знаходимо subscriber
                sub = None
                try:
                    from features.forecast.mqtt_subscriber import get_global_subscriber
                    sub = get_global_subscriber()
                except Exception:
                    pass

                if not sub or not sub.is_connected:
                    self._send(
                        "⚠️ *MQTT subscriber не підключений*\n\n"
                        "Pi-агент не може отримати команду через MQTT. "
                        "Перевір що NetGuardian працює і має інтернет.",
                        mid)
                    return

                # Шлемо команду
                sub.send_command("send_history", {"hours": 24})
                self._send(
                    "🔄 *Команда надіслана Pi-агенту*\n\n"
                    "Чекаю 6 секунд щоб дані прийшли...",
                    mid)

                time.sleep(6)

                # Викликаємо fill_gaps_from_pi через engine
                if not self._wx:
                    self._send("❌ ForecastEngine недоступний", mid)
                    return

                added = self._wx.fill_gaps_from_pi()

                # Перевіряємо стан БД
                import sqlite3
                with sqlite3.connect(self._wx.db_path, timeout=5) as conn:
                    c = conn.cursor()
                    c.execute("SELECT COUNT(*) FROM ping_log")
                    total = c.fetchone()[0]
                    c.execute("""SELECT COUNT(*) FROM ping_log
                        WHERE ts >= datetime('now', '-1 hour', 'localtime')""")
                    last_hour = c.fetchone()[0]
                    c.execute("""SELECT COUNT(*) FROM ping_log
                        WHERE source='pi'""")
                    from_pi = c.fetchone()[0]

                msg = (
                    f"✅ *Синхронізація завершена*\n\n"
                    f"📊 Додано: `{added}` записів\n"
                    f"📈 Всього у БД: `{total}`\n"
                    f"  • За останню годину: `{last_hour}`\n"
                    f"  • Від Pi всього: `{from_pi}`\n\n"
                )

                if added == 0:
                    msg += (
                        "_Дані вже синхронізовані. Якщо очікуєш нові — "
                        "перевір `/pi` що Pi online і шле дані._"
                    )
                else:
                    msg += "_Перезайди у Forecast щоб побачити нові дані._"

                self._send(msg, mid)

            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send(f"❌ Помилка: `{type(e).__name__}: {e}`", mid)

        threading.Thread(target=_work, daemon=True).start()

    def _cmd_pi_logs(self, args, mid):
        """/pi_logs [N] — останні N рядків з monitor.log на Pi (за замовч. 20).

        Стягує через HTTP /api/logs з Pi-агента (порт 8080).
        """
        # Скільки рядків
        lines_n = 20
        try:
            parts = args.strip().split()
            if parts and parts[0].isdigit():
                lines_n = max(5, min(50, int(parts[0])))
        except Exception:
            pass

        self._typing()

        def _work():
            try:
                import urllib.request
                import urllib.parse

                # Адреса Pi (із .env або константа)
                pi_host = os.environ.get("PI_HOST", "192.168.0.161")
                pi_port = os.environ.get("PI_PORT", "8080")

                url = f"http://{pi_host}:{pi_port}/api/logs?lines={lines_n}"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))

                log_text  = data.get("monitor", "(порожньо)")
                seen_age  = data.get("client_seen_age_sec")
                state     = data.get("monitor_state", {})
                log_size  = data.get("monitor_size", 0)

                # Форматування статусу
                lines = [
                    "📜 *Pi Monitor Logs*",
                    "",
                ]

                # Зведення
                if seen_age is not None:
                    if seen_age < 60:
                        seen_str = f"{seen_age} сек тому"
                    elif seen_age < 3600:
                        seen_str = f"{seen_age // 60} хв тому"
                    else:
                        seen_str = f"{seen_age / 3600:.1f} год тому"
                    lines.append(f"⏱ *Останній client-ping:* `{seen_str}`")

                if state:
                    last_state = state.get("last_state", "—")
                    icon = "🟢" if last_state == "online" else "🔴"
                    lines.append(f"{icon} *Стан клієнта:* `{last_state}`")

                lines.append(f"📦 *Розмір логу:* `{log_size} байт`")
                lines.append("")
                lines.append(f"📃 *Останні {lines_n} рядків:*")
                lines.append("```")
                # Обмежуємо щоб не перевищити Telegram-ліміт 4096
                if len(log_text) > 3200:
                    log_text = log_text[-3200:]
                    log_text = "...\n" + log_text
                lines.append(log_text)
                lines.append("```")

                self._send("\n".join(lines), mid)

            except urllib.error.URLError as e:
                self._send(
                    f"❌ *Не можу підключитись до Pi*\n\n"
                    f"`{e}`\n\n"
                    f"_Перевір що Pi-агент запущений:_\n"
                    f"`sudo systemctl status netguardian-agent`",
                    mid
                )
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send(f"❌ Помилка: `{type(e).__name__}: {e}`", mid)

        threading.Thread(target=_work, daemon=True).start()

    def _cmd_storm_test(self, args, mid):
        """/storm_test — надіслати тестовий шторм-аларм."""
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return
        ok, msg = self._smart_scheduler.force_storm_test()
        if ok:
            self._send(f"✅ {msg}", mid)
        else:
            self._send(f"⚠️ {msg}", mid)

    def _cmd_test_catchup(self, args, mid):
        """/test_catchup — примусово згенерувати catch-up звіт.

        Симулює що ПК був вимкнений 2 години і шле відповідний звіт.
        Корисно щоб переконатись що Telegram-комунікація для catch-up працює.
        """
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return

        self._typing()

        def _work():
            try:
                # Симулюємо що остання сесія була 2 години тому
                import sqlite3
                from datetime import datetime, timedelta

                db_path = self._smart_scheduler.db_path
                with sqlite3.connect(db_path, timeout=5) as conn:
                    # Видаляємо старий catch-up маркер
                    conn.execute(
                        "DELETE FROM report_history WHERE report_type='catchup'"
                    )
                    # Створюємо фіктивний session marker - 2 години тому
                    fake_ts = (datetime.now() - timedelta(hours=2)
                                ).strftime("%Y-%m-%d %H:%M:%S")
                    conn.execute("""
                        INSERT OR REPLACE INTO report_history
                        (report_type, key, shown_at) VALUES
                        ('session', 'last_session_end', ?)
                    """, (fake_ts,))
                    conn.commit()

                self._send(
                    f"🧪 *Симульовано gap 2 год* (last_session={fake_ts})\n\n"
                    f"Викликаю catch-up...",
                    mid
                )

                # Запускаємо catch-up
                self._smart_scheduler._check_catchup_report()

                # Перевірка результату
                with sqlite3.connect(db_path, timeout=5) as conn:
                    rows = conn.execute(
                        "SELECT key, shown_at FROM report_history "
                        "WHERE report_type='catchup'"
                    ).fetchall()

                if rows:
                    self._send(
                        f"✅ Catch-up згенерований. "
                        f"Має прийти повідомленням вище.\n\n"
                        f"Записів у report_history: {len(rows)}",
                        mid
                    )
                else:
                    self._send(
                        f"⚠️ Catch-up НЕ згенерований.\n\n"
                        f"Перевір лог сервера — там має бути "
                        f"причина (наприклад 'недостатньо даних від Pi').",
                        mid
                    )
            except Exception as e:
                import traceback
                traceback.print_exc()
                self._send(f"❌ Помилка: `{type(e).__name__}: {e}`", mid)

        threading.Thread(target=_work, daemon=True).start()

    def _cmd_test_pi(self, args, mid):
        """/test_pi — примусово згенерувати Pi OFFLINE alert."""
        if not self._smart_scheduler:
            self._send("❌ SmartScheduler не доступний.", mid)
            return
        msg = (
            "🔴 *Raspberry Pi OFFLINE* (TEST)\n\n"
            "Це тестовий alert. У реальному режимі він приходить коли "
            "Pi не шле heartbeat > 3 хв.\n\n"
            "_Перевір: відключи Pi від мережі або вимкни його — "
            "alert має прийти автоматично через 2-5 хвилин._"
        )
        ok = self._smart_scheduler._send_telegram(msg)
        if ok:
            self._send("✅ Тестовий Pi OFFLINE alert надіслано", mid)
        else:
            self._send("⚠️ Не вдалось надіслати alert", mid)

    # ══════════════════════════════════════════════════════
    #  /game — GAME LATENCY OPTIMIZER (v4.2 + фікси)
    # ══════════════════════════════════════════════════════

    def _get_game_engine(self):
        if self._game_engine is None:
            try:
                from features.gamemode.engine import GameBoosterEngine
                self._game_engine = GameBoosterEngine()
            except Exception as e:
                return None, str(e)
        return self._game_engine, None

    def _cmd_game(self, args, mid):
        parts = args.strip().split(None, 2)
        sub   = parts[0].lower() if parts else "status"
        rest  = " ".join(parts[1:]).strip() if len(parts) > 1 else ""
        dispatch = {
            "status":   self._game_status,   "стан":      self._game_status,
            "on":       self._game_on,        "увімк":     self._game_on,
            "off":      self._game_off,       "вимк":      self._game_off,
            "restore":  self._game_restore,   "відновити": self._game_restore,
            "procs":    self._game_procs,     "processes": self._game_procs,
            "процеси":  self._game_procs,
            "kill":     self._game_kill,      "вбити":     self._game_kill,
            "net":      self._game_net,       # /game net <exe> <level>
            "qos":      self._game_qos_list,  # /game qos — список активних QoS правил
            "prio":     self._game_priority,  # /game prio <exe> <realtime|high|normal>
            "priority": self._game_priority,
            "boostgame":self._game_boost_current_games,  # авто — знаходить ігри і оптимізує
            "ping":     self._game_ping,
            "boost":    self._game_boost,
            "tweaks":   self._game_tweaks,
            "dns":      self._game_dns,
            "ram":      self._game_ram,
            "diagnose": self._game_diagnose,
            "verify":   self._game_verify,
            "help":     self._game_help,
        }
        handler = dispatch.get(sub, self._game_status)
        handler(rest, mid)

    def _game_help(self, args, mid):
        self._send(
            "🎮 *GAME MODE — всі команди*\n"
            "━━━━━━━━━━━━━━━━━━━━━\n\n"
            "*Основні:*\n"
            "• /game — стан + пінг до серверів\n"
            "• /game on — увімкнути режим\n"
            "• /game off — вимкнути режим\n"
            "• /game verify — перевірити твіки\n"
            "• /game restore — відкотити все\n\n"
            "*Процеси:*\n"
            "• /game procs — список активних\n"
            "• /game kill `<exe>` — завершити\n\n"
            "*Пріоритет мережі (QoS):*\n"
            "• /game net `<exe> <level>` — задати\n"
            "• /game qos — список всіх правил\n"
            "• Рівні: `maximum` `high` `normal` `low`\n\n"
            "*Пріоритет CPU:*\n"
            "• /game prio `<exe> <level>`\n"
            "• Рівні: `realtime` `high` `normal` `low`\n\n"
            "*Авто-оптимізація:*\n"
            "• /game boostgame — знайти запущені\n"
            "  ігри і поставити їм максимум QoS+CPU\n\n"
            "*Тести:*\n"
            "• /game ping — пінг серверів\n"
            "• /game diagnose — повна діагностика\n\n"
            "*Приклад сценарію:*\n"
            "`/game on` → `/game boostgame`",
            mid)

    def _game_status(self, args, mid):
        self._typing()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ Game Booster недоступний: `{err}`", mid); return

        # Перевіряємо права адміна
        try:
            from features.gamemode.engine import is_admin
            admin_ok = is_admin()
        except Exception:
            admin_ok = False

        # Читаємо стан з engine (а не локального прапорця) — щоб бути
        # в синхроні з GUI: engine has_backup() == True коли Game Mode активний
        game_active = eng.is_active() if hasattr(eng, "is_active") else eng.has_backup()
        self._game_mode_active = game_active   # підтримуємо старий прапорець для сумісності

        mode_icon  = "🟢 АКТИВНИЙ" if game_active else "⚫ ВИМКНЕНИЙ"
        has_backup = eng.has_backup()
        admin_warn = "" if admin_ok else "\n⚠️ *Немає прав Адміністратора!* Деякі функції не працюватимуть."

        try:
            from features.gamemode.engine import PING_TARGETS
            # Паралельний пінг всіх серверів — інакше послідовно це 9 × 4 = 36 сек
            from concurrent.futures import ThreadPoolExecutor
            ping_results = {}
            def _p(item):
                n, h = item
                ping_results[n] = eng.ping_ms(h)
            with ThreadPoolExecutor(max_workers=10) as pool:
                list(pool.map(_p, PING_TARGETS.items()))

            ping_lines = []
            for name, host in PING_TARGETS.items():
                ms = ping_results.get(name)
                if ms is None:    ping_lines.append(f"  ⚫ {name[:24]}: timeout")
                elif ms < 50:     ping_lines.append(f"  🟢 {name[:24]}: `{ms:.0f} ms`")
                elif ms < 100:    ping_lines.append(f"  🟡 {name[:24]}: `{ms:.0f} ms`")
                else:             ping_lines.append(f"  🔴 {name[:24]}: `{ms:.0f} ms`")
            ping_str = "\n".join(ping_lines)
        except Exception as e:
            ping_str = f"  _(пінг недоступний: {str(e)[:40]})_"

        self._send(
            f"🎮 *Game Latency Optimizer v4.2*\n━━━━━━━━━━━━━━━━━━━━━\n"
            f"⬤ Game Mode: *{mode_icon}*\n"
            f"🔐 Адмін: {'✅' if admin_ok else '❌'}\n"
            f"💾 Бекап: {'✅ є' if has_backup else '❌ немає'}{admin_warn}\n\n"
            f"📡 *Пінг до ігрових серверів:*\n{ping_str}\n\n"
            f"_/game on — активувати · /game procs — процеси_\n"
            f"_/game diagnose — діагностика пінгу_", mid)

    def _game_on(self, args, mid):
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return

        # Перевірка прав адміна перед запуском
        try:
            from features.gamemode.engine import is_admin
            if not is_admin():
                self._send(
                    "🔐 *Потрібні права Адміністратора!*\n\n"
                    "Щоб Game Mode працював:\n"
                    "1. Знайди `python.exe` або `netguardian.exe`\n"
                    "2. ПКМ → *Запустити від імені адміністратора*\n\n"
                    "_Без прав — реєстрові твіки, QoS і Timer не застосовуються._",
                    mid); return
        except Exception:
            pass

        self._send("🚀 *Активую Game Mode...*\n_~5-10 секунд_", mid)

        def _work():
            import time
            t_start = time.time()
            log_lines = []

            def log_cb(t):
                if t and t.strip():
                    log_lines.append(t.strip())

            # Шведка поетапно, щоб у Telegram був прогрес
            self._api.send(self._chat_id, "🔧 *1/6* Registry твіки...")

            # ЄДИНИЙ метод активації — гарантує що стан синхронізується з GUI
            success, ok_count, fail_count = eng.activate_game_mode(
                log_cb=log_cb, source="bot")
            elapsed = time.time() - t_start

            if success and ok_count > 0:
                self._game_mode_active = True
                summary = "\n".join(l for l in log_lines[-14:] if l)
                self._send_with_nav(
                    f"✅ *Game Mode АКТИВОВАНО!*\n"
                    f"_{ok_count} операцій успішно{f', {fail_count} попереджень' if fail_count else ''}_\n"
                    f"⏱ Час: `{elapsed:.1f}с`\n\n"
                    f"```\n{summary[:1500]}\n```",
                    section="game"
                )
            else:
                summary = "\n".join(l for l in log_lines[-8:] if l)
                self._send_with_nav(
                    f"❌ *Game Mode не вдалось активувати*\n\n"
                    f"```\n{summary[:800]}\n```\n\n"
                    f"_Перезапусти від імені Адміністратора._",
                    section="game"
                )

        threading.Thread(target=_work, daemon=True).start()

    def _game_off(self, args, mid):
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._send("⏹ *Деактивую Game Mode...*", mid)
        def _work():
            log_lines = []
            # ЄДИНИЙ метод деактивації — синхронізується з GUI
            success, ops = eng.deactivate_game_mode(
                log_cb=lambda t: log_lines.append(t) if t and t.strip() else None,
                source="bot")
            self._game_mode_active = False
            if success and ops > 0:
                self._send_with_nav(
                    f"✅ *Game Mode вимкнено. Налаштування відновлено.*\n\n"
                    f"_{ops} кроків виконано_",
                    section="game"
                )
            else:
                self._send_with_nav(
                    "⚠️ Бекап не знайдено або вже відновлено.\n"
                    "_Запусти /game on спочатку._",
                    section="game"
                )
        threading.Thread(target=_work, daemon=True).start()

    def _game_restore(self, args, mid):
        self._game_off(args, mid)

    def _game_procs(self, args, mid):
        self._typing()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._send("🔍 Сканую процеси... (~3с)", mid)
        def _work():
            try:
                procs = eng.scan_processes()
                self._game_last_scan = procs
                CAT_ICON = {"game":"🎮","launcher":"🚀","hog":"⚠️",
                            "browser":"🌐","messenger":"💬","media":"🎵",
                            "protected":"🛡","dangerous":"☠️","normal":"·"}
                groups = {"game":[],"launcher":[],"hog":[],"browser":[],"messenger":[],"media":[]}
                for p in procs:
                    cat = p.get("category","normal")
                    if cat in groups: groups[cat].append(p)

                def _fmt_bytes(b):
                    """Конвертує байти/с у '12K' / '3.4M'."""
                    if not b or b == 0: return "  —  "
                    if b >= 1024*1024:
                        return f"{b/(1024*1024):>4.1f}M"
                    if b >= 1024:
                        return f"{b/1024:>5.0f}K"
                    return f"{b:>5d}B"

                def _render_group(items, max_items=8):
                    """Рівно-вирівняний блок через <pre> — Telegram зберігає моноширинність."""
                    rows = []
                    # Заголовок таблиці
                    rows.append(f"{'ПРОЦЕС':<22} {'CPU':>4} {'RAM':>6} {'NET':>7}")
                    rows.append("─" * 42)
                    for p in items[:max_items]:
                        name = p.get("name","?")[:22]
                        cpu  = p.get("cpu",0)
                        ram  = p.get("ram_mb",0)
                        # Пробуємо кілька можливих ключів для мережі
                        net_bytes = (p.get("net_bps") or p.get("net_speed") or
                                     p.get("net_kbps",0)*1024 or 0)
                        rows.append(f"{name:<22} {cpu:>3.0f}% {ram:>5.0f}M {_fmt_bytes(net_bytes):>7}")
                    return "```\n" + "\n".join(rows) + "\n```"

                lines = [f"📋 *ПРОЦЕСИ (всього {len(procs)})*"]

                # Ігри
                if groups["game"]:
                    lines.append(f"\n🎮 *ІГРИ ({len(groups['game'])}):*")
                    lines.append(_render_group(groups["game"]))

                # Лаунчери
                if groups["launcher"]:
                    lines.append(f"\n🚀 *ЛАУНЧЕРИ ({len(groups['launcher'])}):*")
                    lines.append(_render_group(groups["launcher"]))

                # Пожирачі каналу (з підказками kill)
                if groups["hog"]:
                    lines.append(f"\n⚠️ *ПОЖИРАЧІ КАНАЛУ ({len(groups['hog'])}):*")
                    lines.append(_render_group(groups["hog"], max_items=6))
                    # Команди kill окремо (не в код-блоці — щоб copy-paste працював)
                    lines.append("_Завершити:_")
                    for p in groups["hog"][:6]:
                        lines.append(f"  `/game kill {p['name']}`")

                # Браузери/месенджери/медіа
                for cat, label in [("browser","БРАУЗЕРИ"),("messenger","МЕСЕНДЖЕРИ"),("media","МЕДІА")]:
                    items = groups[cat]
                    if not items: continue
                    lines.append(f"\n{CAT_ICON[cat]} *{label} ({len(items)}):*")
                    lines.append(_render_group(items, max_items=5))

                # Зрозумілий помічник
                lines.append(
                    "\n━━━━━━━━━━━━━━━━━━\n"
                    "💡 *Пояснення колонок:*\n"
                    "• *CPU* — скільки процесор використовує\n"
                    "• *RAM* — скільки пам'яті займає (МБ)\n"
                    "• *NET* — швидкість мережі зараз\n\n"
                    "*Наступні дії:*\n"
                    "• `/game kill <exe>` — завершити процес\n"
                    "• `/game net <exe> low` — обмежити мережу процесу\n"
                    "• `/game prio <exe> low` — обмежити CPU процесу"
                )

                self._send_with_nav("\n".join(lines), section="game")
            except Exception as e:
                self._send_with_nav(f"❌ Помилка сканування: `{e}`", section="game")
        threading.Thread(target=_work, daemon=True).start()

    def _game_kill(self, args, mid):
        exe_name = args.strip().lower()
        if not exe_name:
            self._send("❓ Приклад: `/game kill chrome.exe`\n_/game procs — список_", mid); return
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._typing()
        def _work():
            procs  = self._game_last_scan or eng.scan_processes()
            target = next((p for p in procs if p["name"].lower() == exe_name or exe_name in p["name"].lower()), None)
            if not target:
                self._api.send(self._chat_id, f"❌ Процес `{exe_name}` не знайдено.\n_/game procs — оновити_"); return
            ok, msg = eng.kill_process(target["pid"], target["name"])
            self._api.send(self._chat_id, f"{'✅' if ok else '❌'} {msg}")
        threading.Thread(target=_work, daemon=True).start()

    def _game_net(self, args, mid):
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            self._send(
                "🌐 *Мережевий пріоритет QoS*\n\n"
                "*Формат:* `/game net <exe.exe> <level>`\n\n"
                "*Рівні:*\n"
                "• `maximum` — DSCP 46 (ігровий пріоритет)\n"
                "• `high` — DSCP 34 (важливі сервіси)\n"
                "• `normal` — без QoS (стандарт)\n"
                "• `low` — DSCP 8 (фонові процеси)\n\n"
                "*Приклади:*\n"
                "`/game net cs2.exe maximum`\n"
                "`/game net chrome.exe low`\n\n"
                "💡 `/game qos` — список активних правил\n"
                "🚀 `/game boostgame` — авто для запущених ігор",
                mid); return
        exe_name = parts[0].strip()
        level    = parts[1].strip().lower()
        try:
            from features.gamemode.engine import NET_PRIORITY_DSCP
            if level not in NET_PRIORITY_DSCP:
                self._send(f"❌ Допустимі рівні: `maximum`, `high`, `normal`, `low`", mid); return
        except Exception:
            pass
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._typing()
        def _work():
            log_lines = []
            ok, msg = eng.set_process_network_priority(exe_name, level, log_cb=lambda t: log_lines.append(t))
            dscp_info = {"maximum":"DSCP 46 — EF (ігровий пріоритет)","high":"DSCP 34 — AF41",
                         "normal":"QoS знято (стандартний)","low":"DSCP 8 — CS1 (фон)"}.get(level,"")
            self._api.send(self._chat_id, f"{'✅' if ok else '❌'} *{msg.strip()}*\n\nℹ️ _{dscp_info}_")
        threading.Thread(target=_work, daemon=True).start()

    def _game_qos_list(self, args, mid):
        """Список всіх активних QoS-правил системи."""
        self._typing()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return

        def _work():
            try:
                # Спочатку перевіримо права адміна (потрібен PowerShell)
                try:
                    from features.gamemode.engine import is_admin
                    if not is_admin():
                        self._api.send(self._chat_id,
                            "🔐 *Потрібні права Адміністратора*\n"
                            "_PowerShell Get-NetQosPolicy вимагає адмін-прав._")
                        return
                except Exception: pass

                # Викликаємо PowerShell для отримання списку QoS-правил
                import subprocess as sp
                cmd = ["powershell", "-Command",
                       "Get-NetQosPolicy | Select-Object Name,AppPathNameMatchCondition,DSCPAction,NetworkProfile | ConvertTo-Json"]
                r = sp.run(cmd, capture_output=True, text=True, timeout=15,
                           creationflags=getattr(sp, "CREATE_NO_WINDOW", 0))
                raw = (r.stdout or "").strip()
                if not raw or raw == "null":
                    self._api.send(self._chat_id,
                        "📋 *Активні QoS-правила*\n━━━━━━━━━━━━━━━━━━\n"
                        "_Жодних правил не налаштовано._\n\n"
                        "💡 *Що це таке?*\n"
                        "QoS (Quality of Service) — це позначки на мережевих\n"
                        "пакетах, які кажуть роутеру:\n"
                        "🔴 maximum — пропускай цей трафік ПЕРШИМ (для ігор)\n"
                        "🟢 normal — звичайний пріоритет\n"
                        "🔵 low — пропускай ПІСЛЯ всіх (для фонових процесів)\n\n"
                        "💡 *Як додати:*\n"
                        "• `/game net cs2.exe maximum` — пріоритет грі\n"
                        "• `/game boostgame` — авто для всіх ігор")
                    return

                import json as _json
                policies = _json.loads(raw)
                if isinstance(policies, dict):
                    policies = [policies]

                # Розбиваємо на NetGuardian_* (ігри) vs усе інше
                ng_games = []     # наші правила для ігор
                ng_custom = []    # наші кастомні (NetGuardian_Net_*)
                other_rules = []
                for p in policies:
                    name = p.get("Name", "")
                    if "NetGuardian_Net_" in name:
                        ng_custom.append(p)
                    elif "NetGuardian" in name:
                        ng_games.append(p)
                    else:
                        other_rules.append(p)

                # Групуємо ng_games по рівню DSCP для компактності
                by_level = {}
                for p in ng_games:
                    dscp = p.get("DSCPAction", 0)
                    level = {46: "maximum", 34: "high", 0: "normal", 8: "low"}.get(dscp, f"DSCP {dscp}")
                    by_level.setdefault(level, []).append(p)

                lines = ["📋 *АКТИВНІ QoS-ПРАВИЛА*", "━━━━━━━━━━━━━━━━━━"]

                # Блок "Ігри" — згруповано за рівнем
                if ng_games:
                    lines.append(f"\n🎮 *ІГРИ у QoS ({len(ng_games)}):*")
                    for level, items in sorted(by_level.items(), key=lambda x: x[0]):
                        emoji = {"maximum":"🔴","high":"🟠","normal":"🟢","low":"🔵"}.get(level,"⚪")
                        lines.append(f"\n  {emoji} *{level.upper()}* — {len(items)} ігор:")
                        # Показуємо перші 5 імен, потім "...та ще N"
                        for p in items[:5]:
                            app = p.get("AppPathNameMatchCondition", "—")
                            lines.append(f"    • `{app}`")
                        if len(items) > 5:
                            lines.append(f"    _...та ще {len(items)-5} ігор_")

                # Блок "Кастомні" (юзер додав через /game net для не-гри)
                if ng_custom:
                    lines.append(f"\n⚙️ *ВЛАСНІ ПРАВИЛА ({len(ng_custom)}):*")
                    for p in ng_custom[:10]:
                        app = p.get("AppPathNameMatchCondition", "—")
                        dscp = p.get("DSCPAction", 0)
                        level = {46:"maximum",34:"high",0:"normal",8:"low"}.get(dscp, f"DSCP{dscp}")
                        emoji = {"maximum":"🔴","high":"🟠","normal":"🟢","low":"🔵"}.get(level,"⚪")
                        lines.append(f"  {emoji} `{app[:30]}` → *{level}*")

                # Системні правила — тільки кількість
                if other_rules:
                    lines.append(f"\nℹ️ *Системні правила Windows:* {len(other_rules)}")

                # Головне — зрозуміле пояснення
                lines.extend([
                    "",
                    "━━━━━━━━━━━━━━━━━━",
                    "❓ *ЩО ЦЕ ТАКЕ?*",
                    "",
                    "QoS (Quality of Service) — система пріоритизації",
                    "мережевих пакетів. Правило каже роутеру:",
                    "",
                    "🔴 *maximum* — пропускай цей трафік ПЕРШИМ",
                    "   _(для ігор, VoIP, Zoom)_",
                    "🟠 *high* — важливий трафік",
                    "🟢 *normal* — звичайний",
                    "🔵 *low* — пропускай ПІСЛЯ всіх",
                    "   _(для оновлень, торрентів, Cloud sync)_",
                    "",
                    "📌 *ПОТРЕБА:* роутер має підтримувати DSCP",
                    "(усі D-Link, ASUS, TP-Link з QoS це вміють).",
                    "",
                    "━━━━━━━━━━━━━━━━━━",
                    "🛠️ *КОМАНДИ:*",
                    "",
                    "• `/game net cs2.exe maximum` — підняти",
                    "• `/game net chrome.exe low` — обмежити",
                    "• `/game net chrome.exe normal` — прибрати",
                    "• `/game boostgame` — авто-оптимізація",
                    "  (знайде запущені ігри і дасть їм maximum)"
                ])

                self._send_with_nav("\n".join(lines), section="game")
            except Exception as e:
                self._send_with_nav(f"❌ Помилка: `{str(e)[:200]}`", section="game")

        threading.Thread(target=_work, daemon=True).start()

    def _game_priority(self, args, mid):
        """CPU пріоритет процесу: /game prio <exe> <realtime|high|normal|low>"""
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            self._send(
                "⚙️ *CPU пріоритет процесу*\n\n"
                "*Формат:* `/game prio <exe.exe> <level>`\n\n"
                "*Рівні:*\n"
                "• `realtime` — максимум (обережно!)\n"
                "• `high` — високий (для ігор)\n"
                "• `normal` — стандарт\n"
                "• `low` — низький (фон)\n\n"
                "*Приклад:* `/game prio cs2.exe high`\n\n"
                "⚠️ `realtime` може зависити систему — краще `high`",
                mid); return
        exe_name = parts[0].strip().lower()
        level    = parts[1].strip().lower()

        # Мапимо user-friendly назви у Windows priority class
        level_map = {
            "realtime": "RealTime", "real-time": "RealTime", "max": "RealTime",
            "high": "High", "above": "AboveNormal", "above_normal": "AboveNormal",
            "normal": "Normal", "standard": "Normal",
            "below": "BelowNormal", "low": "Low", "idle": "Low",
        }
        if level not in level_map:
            self._send(f"❌ Допустимі: `realtime`, `high`, `normal`, `low`", mid); return
        win_level = level_map[level]

        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._typing()
        def _work():
            procs = self._game_last_scan or eng.scan_processes()
            target = next((p for p in procs if p["name"].lower() == exe_name or
                          exe_name in p["name"].lower()), None)
            if not target:
                self._api.send(self._chat_id,
                    f"❌ Процес `{exe_name}` не знайдено.\n_/game procs — список_")
                return

            ok, msg = eng.set_priority(target["pid"], win_level)
            emoji = {"RealTime":"🔴","High":"🟠","AboveNormal":"🟡",
                     "Normal":"🟢","BelowNormal":"🔵","Low":"⚪"}.get(win_level,"⚪")
            self._api.send(self._chat_id,
                f"{'✅' if ok else '❌'} *CPU Пріоритет*\n\n"
                f"• Процес: `{target['name']}`  (PID `{target['pid']}`)\n"
                f"• Рівень: {emoji} *{win_level}*\n\n"
                f"_{msg}_")

        threading.Thread(target=_work, daemon=True).start()

    def _game_boost_current_games(self, args, mid):
        """Автоматично знаходить запущені ігри і ставить їм максимум QoS + CPU-high."""
        self._typing()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return

        self._send(
            "🚀 *Автоматична оптимізація запущених ігор...*\n"
            "_Пошук + QoS Maximum + CPU High_", mid)

        def _work():
            try:
                # Перевірка адмін-прав
                try:
                    from features.gamemode.engine import is_admin
                    if not is_admin():
                        self._api.send(self._chat_id,
                            "🔐 *Потрібні права Адміністратора* для QoS.\n"
                            "_Перезапусти утиліту від імені Адміна._")
                        return
                except Exception: pass

                # Отримуємо список процесів і знаходимо ігри
                procs = eng.scan_processes()
                games = [p for p in procs if p.get("category") == "game"]

                if not games:
                    self._api.send(self._chat_id,
                        "ℹ️ *Ігор не знайдено*\n\n"
                        "Запусти гру і повтори `/game boostgame`.\n\n"
                        "💡 Якщо гра точно запущена — додай її до бази\n"
                        "`/game net <exe> maximum` вручну.")
                    return

                self._api.send(self._chat_id,
                    f"🎯 Знайдено *{len(games)}* ігор. Оптимізую...")

                results = []
                for game in games[:8]:   # обмежуємо щоб не спамити
                    exe = game["name"]
                    pid = game["pid"]
                    game_result = {"name": exe, "pid": pid,
                                   "qos": False, "cpu": False, "messages": []}

                    # 1. QoS maximum
                    try:
                        ok, msg = eng.set_process_network_priority(
                            exe, "maximum", log_cb=lambda t: None)
                        game_result["qos"] = ok
                        game_result["messages"].append(f"QoS: {msg[:60]}")
                    except Exception as e:
                        game_result["messages"].append(f"QoS error: {e}")

                    # 2. CPU high (не realtime бо це може зависнути систему)
                    try:
                        ok, msg = eng.set_priority(pid, "High")
                        game_result["cpu"] = ok
                        game_result["messages"].append(f"CPU: {msg[:60]}")
                    except Exception as e:
                        game_result["messages"].append(f"CPU error: {e}")

                    results.append(game_result)

                # Формуємо звіт
                lines = ["🎮 *РЕЗУЛЬТАТ ОПТИМІЗАЦІЇ*", "━━━━━━━━━━━━━━━━━━", ""]
                for r in results:
                    qos_i = "✅" if r["qos"] else "❌"
                    cpu_i = "✅" if r["cpu"] else "❌"
                    lines.append(f"*{r['name']}* (PID `{r['pid']}`)")
                    lines.append(f"  {qos_i} Мережа QoS Maximum")
                    lines.append(f"  {cpu_i} CPU High")
                    lines.append("")

                total_ok = sum(1 for r in results if r["qos"] and r["cpu"])
                lines.extend([
                    "━━━━━━━━━━━━━━━━━━",
                    f"📊 Оптимізовано повністю: *{total_ok}/{len(results)}*",
                    "",
                    "💡 `/game qos` — переглянути QoS-правила",
                    "↩️ `/game off` — вимкнути всі оптимізації",
                ])

                self._send_with_nav("\n".join(lines), section="game")
            except Exception as e:
                self._send_with_nav(f"❌ Помилка: `{str(e)[:200]}`", section="game")

        threading.Thread(target=_work, daemon=True).start()

    def _game_ping(self, args, mid):
        self._typing()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._send("📡 *Замірюю пінг до ігрових серверів...*\n_~3-5 секунд_", mid)
        def _work():
            try:
                from features.gamemode.engine import PING_TARGETS
                from concurrent.futures import ThreadPoolExecutor
                # Паралельний пінг всіх 9 серверів
                results = {}
                def _p(item):
                    n, h = item
                    results[n] = eng.ping_ms(h)
                with ThreadPoolExecutor(max_workers=10) as pool:
                    list(pool.map(_p, PING_TARGETS.items()))

                lines = ["📡 *Пінг до ігрових серверів:*", "━━━━━━━━━━━━━━━━━━", ""]
                for name, host in PING_TARGETS.items():
                    ms = results.get(name)
                    if ms is None:
                        icon = "⚫"; ms_str = "timeout"
                    elif ms < 50:
                        icon = "🟢"; ms_str = f"{ms:.0f} ms"
                    elif ms < 100:
                        icon = "🟡"; ms_str = f"{ms:.0f} ms"
                    else:
                        icon = "🔴"; ms_str = f"{ms:.0f} ms"
                    lines.append(f"{icon} `{name[:28]:<28}` `{ms_str:>10}`")

                # Підказка — найкращий сервер
                valid = [(n, r) for n, r in results.items() if r is not None]
                if valid:
                    best = min(valid, key=lambda x: x[1])
                    lines.extend(["",
                        f"🏆 *Найшвидший:* {best[0]} ({best[1]:.0f} ms)"])

                self._send_with_nav("\n".join(lines), section="game")
            except Exception as e:
                self._send_with_nav(f"❌ Помилка: `{e}`", section="game")
        threading.Thread(target=_work, daemon=True).start()

    def _game_boost(self, args, mid):
        self._game_on(args, mid)

    # Словник tweaks: {slug: {name, method_on, method_off, description}}
    _GAME_TWEAKS = {
        "update": {
            "name": "Disable Windows Update",
            "icon": "🔄",
            "desc": "Зупиняє служби Windows Update щоб не качали оновлення підчас гри",
            "method_on":  "stop_windows_update",
            "method_off": None,
        },
        "dns": {
            "name": "DNS Fast-Switch → 1.1.1.1",
            "icon": "🌐",
            "desc": "Перемикає DNS на Cloudflare (1.1.1.1) для швидшого resolv",
            "method_on":  "switch_dns",   # потребує параметр
            "method_off": None,
        },
        "nagle": {
            "name": "TCP NoDelay (No-Nagle)",
            "icon": "⚡",
            "desc": "Вимикає Nagle's Algorithm — пакети не батчаться, lower latency",
            "method_on":  "disable_nagle",
            "method_off": "_restore_nagle",
        },
        "power": {
            "name": "High Performance Power",
            "icon": "🔋",
            "desc": "Перемикає Windows Power Plan на High Performance",
            "method_on":  "set_high_performance_power",
            "method_off": None,
        },
        "unpark": {
            "name": "CPU Core Unpark",
            "icon": "🧩",
            "desc": "Встановлює мінімальний стан процесора на 100% (всі ядра активні)",
            "method_on":  "unpark_cpu_cores",
            "method_off": None,
        },
        "flush_dns": {
            "name": "Flush DNS Cache",
            "icon": "💨",
            "desc": "Очищує DNS-кеш (ipconfig /flushdns)",
            "method_on":  "flush_dns",
            "method_off": None,
        },
        "mmcss": {
            "name": "High Priority for Games",
            "icon": "🎮",
            "desc": "MMCSS Games Profile — ігри отримують пріоритет системних ресурсів",
            "method_on":  "apply_mmcss_tweaks",
            "method_off": None,
        },
        "ram": {
            "name": "Clean RAM",
            "icon": "🧹",
            "desc": "Очищує робочий набір (Working Set) всіх процесів + Standby List",
            "method_on":  "clean_ram",
            "method_off": None,
        },
    }

    def _game_tweaks(self, args, mid):
        """Показує меню всіх tweaks з можливістю вмикати/вимикати окремо."""
        parts = args.strip().split(None, 2)

        if not parts:
            # Показуємо список tweaks
            lines = [
                "⚙️ *GAME MODE TWEAKS — окремо*",
                "━━━━━━━━━━━━━━━━━━",
                "",
                "*Керуй кожною оптимізацією окремо*",
                "(або `/game on` — вмикає все разом)\n",
            ]
            for slug, t in self._GAME_TWEAKS.items():
                lines.append(f"{t['icon']} *{t['name']}*")
                lines.append(f"   _{t['desc']}_")
                lines.append(f"   ▶️ `/game tweaks on {slug}`")
                if t.get("method_off"):
                    lines.append(f"   ⏹ `/game tweaks off {slug}`")
                lines.append("")

            lines.extend([
                "━━━━━━━━━━━━━━━━━━",
                "*Приклади:*",
                "`/game tweaks on nagle` — лише Nagle OFF",
                "`/game tweaks on mmcss` — лише High Priority",
                "`/game tweaks on dns` — на Cloudflare",
                "",
                "↩️ /m_game — меню ігрового режиму",
            ])
            self._send("\n".join(lines), mid); return

        # Обробка: /game tweaks on <slug> | off <slug>
        action = parts[0].lower()
        if action not in ("on", "off"):
            self._send("⚠️ Формат: `/game tweaks on <назва>` або `off`", mid); return

        if len(parts) < 2:
            self._send(f"⚠️ Вкажи назву tweak'а.\n\n`/game tweaks` — список", mid); return

        slug = parts[1].lower()
        tweak = self._GAME_TWEAKS.get(slug)
        if not tweak:
            self._send(f"❌ Tweak `{slug}` не знайдено.\n`/game tweaks` — список", mid); return

        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return

        self._typing()
        method_name = tweak["method_on"] if action == "on" else tweak["method_off"]
        if not method_name:
            self._send(
                f"⚠️ Tweak *{tweak['name']}* не має {action}-режиму.\n"
                f"Використовуй `/game off` для загального відкату.", mid); return

        def _work():
            log_lines = []
            try:
                method = getattr(eng, method_name, None)
                if not method:
                    self._api.send(self._chat_id,
                        f"❌ Метод `{method_name}` відсутній в engine")
                    return

                # DNS fast-switch потребує параметр — беремо Cloudflare
                if slug == "dns" and action == "on":
                    ok = method("Cloudflare (1.1.1.1)",
                                log_cb=lambda t: log_lines.append(t))
                else:
                    ok = method(log_cb=lambda t: log_lines.append(t))

                summary = "\n".join(l for l in log_lines if l and l.strip())[:1000]
                status = "✅ УВІМКНЕНО" if (ok and action == "on") else \
                         "⏹ ВИМКНЕНО" if action == "off" else \
                         "⚠️ Не вдалось"
                self._api.send(self._chat_id,
                    f"{tweak['icon']} *{tweak['name']}*\n"
                    f"━━━━━━━━━━━━━━━━━━\n"
                    f"Статус: *{status}*\n\n"
                    f"```\n{summary[:800]}\n```")
            except Exception as e:
                self._api.send(self._chat_id,
                    f"❌ Помилка: `{str(e)[:200]}`")
        threading.Thread(target=_work, daemon=True).start()

    def _game_dns(self, args, mid):
        profile = args.strip()
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        try:
            from features.gamemode.engine import GAMING_DNS
        except Exception:
            self._send("❌ GAMING_DNS не знайдено.", mid); return
        if not profile:
            dns_list = "\n".join(f"  • `{k}`" for k in GAMING_DNS.keys())
            self._send(f"🌐 *DNS Fast-Switch*\n\nПрофілі:\n{dns_list}\n\nПриклад: `/game dns Cloudflare`", mid)
            return
        match = next((k for k in GAMING_DNS if profile.lower() in k.lower()), None)
        if not match:
            self._send(f"❌ Профіль `{profile}` не знайдено.", mid); return
        self._typing()
        def _work():
            log_lines = []
            ok = eng.switch_dns(match, log_cb=lambda t: log_lines.append(t))
            eng.flush_dns(log_cb=lambda t: log_lines.append(t))
            self._api.send(self._chat_id,
                f"{'✅' if ok else '❌'} *DNS → {match}*\n\n" + "\n".join(log_lines[-4:]))
        threading.Thread(target=_work, daemon=True).start()

    def _game_ram(self, args, mid):
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._send("🧹 *Очищую RAM...*\n_(Working Set + Standby List)_", mid)
        def _work():
            log_lines = []
            ok = eng.clean_ram(log_cb=lambda t: log_lines.append(t))
            self._api.send(self._chat_id,
                f"{'✅' if ok else '❌'} *RAM {'очищено' if ok else 'помилка'}*\n\n" +
                "\n".join(log_lines[-6:]))
        threading.Thread(target=_work, daemon=True).start()

    def _game_diagnose(self, args, mid):
        """Запускає traceroute діагностику пінгу через бот."""
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        target = args.strip() or "8.8.8.8"
        self._send(f"🔍 *Діагностика пінгу → {target}*\n_~30 сек_", mid)
        def _work():
            try:
                result = eng.diagnose_ping(target)

                avg  = result.get("avg_ms")
                mn   = result.get("min_ms")
                mx   = result.get("max_ms")
                loss = result.get("loss_pct")
                hops = result.get("traceroute", [])
                analysis = result.get("analysis", "")

                lines = [f"🔍 *ДІАГНОСТИКА: {target}*", "━━━━━━━━━━━━━━━━━━"]

                # Пінг
                if avg is not None:
                    jitter = (mx - mn) if (mn and mx) else 0
                    avg_icon = "🟢" if avg < 50 else "🟡" if avg < 100 else "🔴"
                    lines.append(f"{avg_icon} *Пінг:* `{avg} ms`")
                    lines.append(f"   • Min: `{mn} ms`  Max: `{mx} ms`  Jitter: `{jitter:.0f} ms`")
                else:
                    lines.append("❌ *Пінг не вдалось виміряти*")

                # Втрата пакетів
                if loss is not None:
                    loss_icon = "🟢" if loss < 2 else "🟡" if loss < 10 else "🔴"
                    lines.append(f"{loss_icon} *Втрата:* `{loss}%`")

                # Traceroute (скорочений)
                if hops:
                    lines.append(f"\n📡 *Маршрут ({len(hops)} хопів):*")
                    lines.append("```")
                    for hop in hops[:12]:
                        lines.append(hop[:72])
                    if len(hops) > 12:
                        lines.append(f"... та ще {len(hops) - 12}")
                    lines.append("```")

                # Аналіз
                if analysis:
                    lines.extend(["", "🔎 *Аналіз:*", analysis])

                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                import traceback
                self._api.send(self._chat_id,
                    f"❌ Помилка діагностики: `{str(e)[:100]}`\n"
                    f"_Деталі у консолі._")
                print(f"[Bot /game diagnose] {traceback.format_exc()}")
        threading.Thread(target=_work, daemon=True).start()

    def _game_verify(self, args, mid):
        """Перевіряє чи реально застосовані твіки."""
        eng, err = self._get_game_engine()
        if not eng:
            self._send(f"❌ {err}", mid); return
        self._typing()
        self._send("🔎 *Перевіряю застосовані оптимізації...*", mid)
        def _work():
            try:
                results = eng.verify_tweaks()
                # Очікуваний формат: {ok: N, fail: N, details: [(name, applied_bool, value_str), ...]}
                if not isinstance(results, dict):
                    self._api.send(self._chat_id,
                        f"❌ Неочікуваний формат verify_tweaks: `{type(results).__name__}`")
                    return

                ok_count    = results.get("ok", 0)
                fail_count  = results.get("fail", 0)
                details     = results.get("details", [])
                total       = ok_count + fail_count

                icon = ("✅" if fail_count == 0 and ok_count > 0 else
                        "🟡" if ok_count > fail_count else "🔴")

                lines = [
                    f"{icon} *СТАТУС ОПТИМІЗАЦІЙ*",
                    "━━━━━━━━━━━━━━━━━━",
                    f"✅ Застосовано: *{ok_count}*",
                    f"❌ Не застосовано: *{fail_count}*",
                    "",
                ]

                if details:
                    lines.append("*Деталі:*")
                    for item in details:
                        # Підтримка різних форматів item (tuple або dict)
                        if isinstance(item, (list, tuple)) and len(item) >= 3:
                            name, applied, value = item[0], item[1], item[2]
                        elif isinstance(item, dict):
                            name    = item.get("name", "?")
                            applied = item.get("applied", False)
                            value   = item.get("value", "?")
                        else:
                            continue
                        tick = "✅" if applied else "❌"
                        lines.append(f"{tick} *{name}:* `{value}`")

                # Рекомендації
                if fail_count > 0:
                    lines.extend([
                        "",
                        "━━━━━━━━━━━━━━━━━━",
                        "💡 *Якщо щось не застосовано:*",
                        "• Перезапусти NetGuardian як Адміністратор",
                        "• `/game on` — увімкнути всі оптимізації",
                        "• `/game off` + `/game on` — перезастосувати"
                    ])
                elif ok_count > 0:
                    lines.extend([
                        "",
                        "━━━━━━━━━━━━━━━━━━",
                        "✅ *Все налаштовано коректно!*"
                    ])
                else:
                    lines.extend([
                        "",
                        "ℹ️ *Game Mode не активований.*",
                        "💡 `/game on` — щоб увімкнути"
                    ])

                self._send_with_nav("\n".join(lines), section="game")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()[-300:]
                self._send_with_nav(
                    f"❌ Помилка: `{e}`\n\n```\n{tb}\n```", section="game")
        threading.Thread(target=_work, daemon=True).start()

    # ══════════════════════════════════════════════════════
    #  /tapo, /lan, /dns, /wifi — без змін
    # ══════════════════════════════════════════════════════

    def _cmd_tapo(self, args, mid):
        if not self._agent:
            self._send("❌ Smart Agent недоступний.", mid); return
        parts = args.strip().split()
        sub   = parts[0].lower() if parts else "status"
        if sub in ("status","стан",""):
            self._typing(); self._send(self._agent.tapo_get_status(), mid)
        elif sub in ("on","увімкни"):
            if not self._agent.tapo: self._send("❌ Tapo не налаштована.", mid); return
            self._typing(); ok, msg = self._agent.tapo.turn_on(); self._send(msg, mid)
        elif sub in ("off","вимкни"):
            if not self._agent.tapo: self._send("❌ Tapo не налаштована.", mid); return
            self._typing(); ok, msg = self._agent.tapo.turn_off(); self._send(msg, mid)
        elif sub == "guard":    self._tapo_guard_cmd(parts[1:], mid)
        elif sub == "stats":    self._typing(); self._send(self._agent.tapo_get_stats(), mid)
        elif sub in ("voltage","volt","напруга","v"):
            self._typing(); self._send(self._agent.tapo_get_voltage_trend(), mid)
        elif sub in ("events","history","журнал"):
            self._send(self._agent.tapo_get_guard_events(), mid)
        elif sub in ("monitor","mon"):
            sub2 = parts[1].lower() if len(parts) > 1 else ""
            if sub2 in ("on","start","увімк"):   self._send(self._agent.tapo_start_monitor(), mid)
            elif sub2 in ("off","stop","вимк"):  self._send(self._agent.tapo_stop_monitor(), mid)
            else:
                if self._agent.tapo:
                    mon = "✅ активний" if self._agent.tapo.is_monitoring else "❌ зупинений"
                    self._send(f"🔄 *Voltage Monitor:* {mon}\n`/tapo monitor on`", mid)
                else: self._send("❌ Tapo не налаштована.", mid)
        elif sub == "setup": self._tapo_setup_cmd(parts[1:], mid)
        elif sub == "debug":
            if not self._agent.tapo: self._send("❌ Tapo не налаштована.", mid); return
            self._typing(); self._send("🔬 Читаю сирі дані...", mid)
            def _work():
                result = self._agent.tapo.get_raw_debug()
                for chunk in [result[i:i+3800] for i in range(0, len(result), 3800)]:
                    self._api.send(self._chat_id, chunk)
            threading.Thread(target=_work, daemon=True).start()
        else: self._tapo_help(mid)

    def _tapo_guard_cmd(self, parts: list, mid):
        if not self._agent.tapo:
            self._send("❌ Tapo P110 не налаштована.\n`/tapo setup <IP> <email> <password>`", mid); return
        g = self._agent.tapo.guard
        if not parts:
            self._typing(); self._send(self._agent.tapo_get_guard(), mid); return
        sub = parts[0].lower()
        if sub in ("volt","voltage","v") and len(parts) >= 3:
            try:
                vmin = float(parts[1]); vmax = float(parts[2])
                if not (100 <= vmin < vmax <= 300):
                    self._send("❌ Приклад: `volt 200 250`", mid); return
                g.volt_min = vmin; g.volt_max = vmax
                self._agent.save_guard_settings()
                self._send(f"✅ *Критичні межі:* `{vmin:.0f}V` — `{vmax:.0f}V`", mid)
            except (ValueError, IndexError):
                self._send("❌ `/tapo guard volt 200 250`", mid)
        elif sub in ("warn","warning") and len(parts) >= 3:
            try:
                wlow = float(parts[1]); whigh = float(parts[2])
                g.volt_warn_low = wlow; g.volt_warn_high = whigh
                self._agent.save_guard_settings()
                self._send(f"✅ `{wlow:.0f}V` — `{whigh:.0f}V`", mid)
            except Exception: self._send("❌ `/tapo guard warn 210 240`", mid)
        elif sub in ("amp","current","a") and len(parts) >= 2:
            try:
                amp = float(parts[1]); g.amp_max = amp
                self._agent.save_guard_settings()
                self._send(f"✅ *Макс. струм:* `{amp:.1f}A`", mid)
            except Exception: self._send("❌ `/tapo guard amp 10`", mid)
        elif sub in ("restore",):
            if len(parts) < 2:
                self._send(f"♻️ `{'✅' if g.auto_restore else '❌'}`\n`/tapo guard restore on/off`", mid); return
            val = parts[1].lower() in ("on","true","увімк","1")
            g.auto_restore = val; self._agent.save_guard_settings()
            self._send(f"♻️ *Авто-відновлення:* {'✅' if val else '❌'}", mid)
        elif sub in ("price","tariff") and len(parts) >= 2:
            try:
                price = float(parts[1]); g.price_per_kwh = price
                self._agent.save_guard_settings()
                self._send(f"💰 *Тариф:* `{price} грн/кВт·год`", mid)
            except Exception: self._send("❌ `/tapo guard price 4.32`", mid)
        elif sub in ("interval","int") and len(parts) >= 2:
            try:
                sec = int(parts[1]); g.monitor_interval = sec
                self._agent.save_guard_settings()
                self._send(f"⏱️ *Інтервал:* `{sec}с`", mid)
            except Exception: self._send("❌ `/tapo guard interval 60`", mid)
        else: self._send(self._agent.tapo_get_guard(), mid)

    def _tapo_setup_cmd(self, parts: list, mid):
        if not parts:
            self._send("📱 `/tapo setup <IP> <email> <password>`", mid); return
        ip = parts[0] if len(parts) > 0 else ""
        email = parts[1] if len(parts) > 1 else ""
        pwd = " ".join(parts[2:]) if len(parts) > 2 else ""
        if not ip: self._send("❌ Вкажи IP.", mid); return
        self._typing(); self._send(f"⚡ Підключаюсь до `{ip}`...", mid)
        def _work():
            ok, msg = self._agent.configure_tapo(ip, email, pwd)
            self._api.send(self._chat_id, msg)
            if ok:
                time.sleep(1); self._api.send(self._chat_id, self._agent.tapo_get_status())
        threading.Thread(target=_work, daemon=True).start()

    def _tapo_help(self, mid):
        self._send("/tapo · /tapo on/off · /tapo guard\n/tapo stats · /tapo voltage\n"
                   "/tapo monitor on/off · /tapo setup `<IP> <email> <pass>`", mid)

    def _cmd_lan(self, args, mid):
        parts = args.strip().split(None, 1)
        sub   = parts[0].lower() if parts else "status"
        rest  = parts[1].strip() if len(parts) > 1 else ""
        if sub in ("scan","скан"):                       self._lan_scan(mid)
        elif sub in ("devices","list","all","пристрої"):  self._lan_devices(mid,filter_type="all")
        elif sub in ("wifi","wireless"):                  self._lan_devices(mid,filter_type="wifi")
        elif sub in ("wired","cable"):                    self._lan_devices(mid,filter_type="wired")
        elif sub in ("trust","довіряти"):                 self._lan_trust_cmd(rest, mid)
        elif sub in ("allow","дозволити"):                self._lan_allow_cmd(rest, mid)
        elif sub in ("block","блок"):                     self._lan_block_cmd(rest, mid)
        elif sub in ("suppress",):                        self._lan_suppress_cmd(rest, mid)
        elif sub in ("monitor","моніторинг"):             self._lan_monitor_cmd(rest, mid)
        elif sub in ("status","стан",""):                 self._lan_status(mid)
        else:                                             self._lan_help(mid)

    def _lan_help(self, mid):
        self._send("/lan · /lan scan · /lan devices\n/lan trust `<mac>` · /lan block `<ip>` · /lan monitor on/off", mid)

    def _lan_status(self, mid):
        self._typing()
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ LAN: {e}", mid); return
        net = self._lan_engine.get_network_info()
        mon = "✅" if (self._lan_monitor and self._lan_monitor.is_running) else "❌"
        self._send(f"🛡️ *LAN Security*\n🌐 `{net.get('subnet','?')}`\n🖥️ `{net.get('my_ip','?')}`\n"
                   f"🔄 Моніторинг: {mon}\n\n_/lan scan — запустити_", mid)

    def _lan_scan(self, mid):
        self._typing()
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        self._send("🛡️ *Сканую мережу...* (~30-60с)", mid)
        def _work():
            try:
                from features.security.lan_monitor import get_device_display_name

                devices = self._lan_engine.scan_network()
                self._lan_last_scan = devices
                total  = len(devices)
                online = [d for d in devices if d.get("is_online")]
                danger = [d for d in devices if d.get("threat") in ("danger","critical")]
                new_d  = [d for d in devices if d.get("is_new") and not d.get("is_self") and not d.get("is_gateway")]

                # ── Компактний список ВСІХ онлайн пристроїв ──
                lines = [
                    f"🛡️ *АУДИТ МЕРЕЖІ ЗАВЕРШЕНО*",
                    f"━━━━━━━━━━━━━━━━━━",
                    f"📊 Всього: *{total}*  ·  Онлайн: *{len(online)}*",
                    "",
                ]

                # Якщо є небезпечні — показуємо спершу
                if danger:
                    lines.append(f"⚠️ *НЕБЕЗПЕЧНІ ({len(danger)}):*")
                    for d in danger[:5]:
                        name = get_device_display_name(d)
                        mac  = d.get("mac","—")
                        icon = "⛔" if d.get("threat") == "critical" else "⚠️"
                        lines.append(f"  {icon} `{d['ip']}` — {name}")
                        lines.append(f"     MAC: `{mac}`")
                    lines.append("")

                # Нові пристрої
                if new_d:
                    lines.append(f"🆕 *НОВІ ({len(new_d)}):*")
                    for d in new_d[:5]:
                        name = get_device_display_name(d)
                        mac  = d.get("mac","—")
                        lines.append(f"  🆕 `{d['ip']}` — {name}")
                        lines.append(f"     MAC: `{mac}`")
                    lines.append("")

                # Повний список всіх онлайн
                lines.append(f"📋 *ВСІ ОНЛАЙН ПРИСТРОЇ:*")
                for d in online[:20]:
                    name = get_device_display_name(d)
                    mac  = d.get("mac","—")
                    threat = d.get("threat","safe")
                    icon = {"critical":"⛔","danger":"⚠️","warn":"🟡","safe":"✅"}.get(threat,"✅")
                    if d.get("is_self"):    icon = "🖥️"
                    if d.get("is_gateway"): icon = "📡"
                    if d.get("is_banned"):  icon = "🚫"
                    if d.get("is_trusted"): icon = "✓"

                    # Обрізаємо ім'я якщо задовге
                    name_short = name[:32] if name else "?"
                    lines.append(f"{icon} `{d['ip']}` — {name_short}")
                    lines.append(f"   `{mac}`")

                if len(online) > 20:
                    lines.append(f"\n_...та ще {len(online) - 20} пристроїв_")

                # Підказки
                lines.extend([
                    "",
                    "💡 `/details <mac>` — технічні деталі",
                    "🚫 `/block <mac>` — заблокувати",
                    "🔍 `/deep <ip>` — глибока ідентифікація",
                ])

                if not danger and not new_d:
                    lines.insert(4, "✅ Підозрілих пристроїв не виявлено\n")

                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _lan_devices(self, mid, filter_type="all"):
        self._typing()
        if not self._lan_last_scan:
            self._send("📋 Немає даних. Запусти `/lan scan`", mid); return

        from features.security.lan_monitor import get_device_display_name

        devices  = self._lan_last_scan
        filtered = (
            [d for d in devices if d.get("connection_type")=="WiFi"] if filter_type=="wifi" else
            [d for d in devices if d.get("connection_type")=="LAN"]  if filter_type=="wired" else
            devices
        )
        # Сортуємо: небезпечні перші, потім новi, потім інші
        filtered.sort(key=lambda d: (
            0 if d.get("threat") in ("critical","danger") else
            1 if d.get("is_new") and not d.get("is_self") else
            2 if d.get("is_self") or d.get("is_gateway") else 3,
            d.get("ip","")
        ))

        title = {"wifi":"📡 *Wi-Fi ПРИСТРОЇ:*","wired":"🔌 *ДРОТОВІ:*"}.get(filter_type,"🛡️ *ВСІ ПРИСТРОЇ:*")
        if not filtered:
            self._send("📋 Нічого не знайдено.", mid); return

        lines = [title, "━━━━━━━━━━━━━━━━━━", ""]
        for d in filtered[:25]:
            name   = get_device_display_name(d)
            mac    = d.get("mac","—")
            ip     = d.get("ip","—")
            dev_t  = d.get("dev_type","") or d.get("vendor","")
            threat = d.get("threat","safe")

            # Вибираємо іконку за пріоритетом
            if d.get("is_banned"):    icon = "🚫"
            elif d.get("is_self"):    icon = "🖥️"
            elif d.get("is_gateway"): icon = "📡"
            elif threat == "critical": icon = "⛔"
            elif threat == "danger":  icon = "⚠️"
            elif threat == "warn":    icon = "🟡"
            elif d.get("is_trusted"): icon = "✓"
            else:                     icon = "✅"

            # Бейджі
            badges = []
            if d.get("is_new") and not d.get("is_self") and not d.get("is_gateway"):
                badges.append("🆕")
            if d.get("connection_type") == "WiFi": badges.append("📡")
            elif d.get("connection_type") == "LAN": badges.append("🔌")
            # Sticky-cache позначка — пристрій не відповів зараз, але бачили <5хв тому
            if d.get("_sticky"):
                age = d.get("_sticky_age_sec", 0)
                age_str = f"{age}с" if age < 60 else f"{age//60}хв"
                badges.append(f"💾{age_str}")
            badge_str = " ".join(badges)

            # Основна інфа
            lines.append(f"{icon} *{name[:36]}*  {badge_str}")
            lines.append(f"   IP: `{ip}`  ·  `{mac}`")

            # Show dev_type only if different from name
            if dev_t and dev_t != "?" and dev_t.lower() not in name.lower():
                lines.append(f"   _{dev_t[:40]}_")

            # Відкриті порти якщо є небезпечні
            ports = d.get("open_ports", [])
            critical_ports = [p for p in ports if p in (21, 22, 23, 135, 139, 445, 3389, 5900)]
            if critical_ports:
                lines.append(f"   ⚠️ Порти: `{', '.join(map(str, critical_ports[:5]))}`")

            lines.append("")

        if len(filtered) > 25:
            lines.append(f"_...та ще {len(filtered) - 25}_")

        # Legend
        lines.extend([
            "━━━━━━━━━━━━━━━━━━",
            "🖥️ твій ПК  ·  📡 роутер  ·  ✓ довірений",
            "⚠️ небезпечний  ·  🚫 заблокований  ·  🆕 новий",
            "",
            "💡 `/details <mac>` `/block <mac>` `/deep <ip>`",
        ])
        self._send("\n".join(lines), mid)

    def _lan_trust_cmd(self, mac: str, mid):
        mac = mac.strip().upper()
        if not mac or len(mac) < 17:
            self._send("❓ `/lan trust AA:BB:CC:DD:EE:FF`", mid); return
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        self._lan_engine.set_trusted(mac, True)
        for d in self._lan_last_scan:
            if d.get("mac","").upper() == mac: d["is_trusted"] = True
        self._send(f"✅ *Довірений:* `{mac}`", mid)

    def _lan_allow_cmd(self, mac: str, mid):
        mac = mac.strip().upper()
        if not mac or len(mac) < 17:
            self._send("❓ `/lan allow AA:BB:CC:DD:EE:FF`", mid); return
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        self._lan_engine.dismiss_alert(mac)
        self._send(f"🔕 *Алерт знято:* `{mac}`", mid)

    def _lan_block_cmd(self, ip: str, mid):
        ip = ip.strip()
        if not ip or not re.match(r'^\d+\.\d+\.\d+\.\d+$', ip):
            self._send("❓ `/lan block 192.168.1.50`", mid); return
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        gw = self._lan_engine._detect_gateway()
        self._send(f"✂️ *Блокую `{ip}` на 30с...*", mid)
        def _work():
            ok, msg = self._lan_engine.block_device(ip, gw, duration=30)
            self._api.send(self._chat_id, f"{'✅' if ok else '❌'} {msg}")
        threading.Thread(target=_work, daemon=True).start()

    def _lan_suppress_cmd(self, args: str, mid):
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        enabled = args.strip().lower() in ("on","увімк")
        gw = self._lan_engine._detect_gateway()
        self._lan_engine.set_router_suppress(gw, enabled)
        self._send(f"{'🔕' if enabled else '🔔'} {'Заглушено' if enabled else 'Відновлено'}", mid)

    def _lan_monitor_cmd(self, args: str, mid):
        parts = args.strip().lower().split()
        sub   = parts[0] if parts else "status"
        if sub in ("on","start","увімк"):   self._lan_monitor_start(mid)
        elif sub in ("off","stop","вимк"):  self._lan_monitor_stop(mid)
        elif sub.isdigit():
            self._lan_monitor_interval = max(1, min(60, int(sub))) * 60
            self._send(f"⏱️ Інтервал: *{int(sub)} хвилин*", mid)
        else:
            running = self._lan_monitor and self._lan_monitor.is_running
            self._send(f"🔄 LAN Monitor: {'✅' if running else '❌'}\n`/lan monitor on/off`", mid)

    def _lan_monitor_start(self, mid):
        if self._lan_monitor and self._lan_monitor.is_running:
            self._send("✅ Вже активний.", mid); return
        if not self._lan_engine:
            try:
                from features.security.lan_security import LanSecurityEngine
                self._lan_engine = LanSecurityEngine()
            except Exception as e:
                self._send(f"❌ {e}", mid); return
        try:
            from features.security.lan_monitor import LanMonitor
            self._lan_monitor = LanMonitor(engine=self._lan_engine, interval_sec=self._lan_monitor_interval)
            self._lan_monitor.connect_to_bot(self)
            self._lan_monitor.start()
            self._send(f"✅ *LAN Моніторинг запущено!*\nІнтервал: `{self._lan_monitor_interval//60} хв`", mid)
        except Exception as e:
            self._send(f"❌ {e}", mid)

    def _lan_monitor_stop(self, mid):
        if not self._lan_monitor or not self._lan_monitor.is_running:
            self._send("❌ Не активний.", mid); return
        self._lan_monitor.stop()
        self._send("⏹️ *LAN Моніторинг зупинено.*", mid)

    def notify_lan_new_device(self, device: dict):
        if not any(d.get("mac") == device.get("mac") for d in self._lan_last_scan):
            self._lan_last_scan.append(device)
        name    = device.get("user_label") or device.get("vendor","Невідомий")
        ct_icon = "📡" if device.get("connection_type")=="WiFi" else "🔌"
        self._api.send(self._chat_id,
            f"🆕 *Новий пристрій!*\n{ct_icon} {name}\n"
            f"🌐 `{device.get('ip','?')}` | `{device.get('mac','?')}`\n\n"
            f"_/lan trust {device.get('mac','')} — довіряти_")

    def notify_lan_suspicious(self, device: dict):
        name   = device.get("user_label") or device.get("vendor","?")
        threat = device.get("threat","danger")
        icon   = "⛔" if threat == "critical" else "⚠️"
        self._api.send(self._chat_id,
            f"{icon} *{'КРИТИЧНА ЗАГРОЗА' if threat=='critical' else 'ПІДОЗРІЛИЙ'}*\n"
            f"{name} · `{device.get('ip','?')}`\n\n"
            f"_/lan block {device.get('ip','')} — заблокувати_")

    def notify_lan_device_left(self, mac: str, last_ip: str, label: str):
        self._api.send(self._chat_id, f"👋 *Відключився*\n📛 {label}\n🌐 `{last_ip}` | `{mac}`")

    def _cmd_dns(self, args, mid):
        parts = args.strip().split(None, 1)
        sub   = parts[0].lower() if parts else ""
        rest  = parts[1].strip() if len(parts) > 1 else ""
        if sub == "list":                            self._dns_list(mid)
        elif sub in ("benchmark","bench","test"):    self._dns_benchmark(mid)
        elif sub == "set":                           self._dns_set(rest, mid)
        elif sub == "leak":                          self._dns_leak(mid)
        elif sub == "flush":                         self._dns_flush(mid)
        else:                                        self._dns_status(mid)

    def _dns_status(self, mid):
        self._typing()
        try:
            from features.dns.engine import DNSBenchmarker, DNS_SERVERS, _query_dns
            bench = DNSBenchmarker()
            ip, iface = bench.get_current_dns()
            if not ip: self._send("❌ Не вдалося визначити DNS.", mid); return
            known = next((e for e in DNS_SERVERS if e[1] == ip), None)
            ms    = _query_dns(ip, "google.com")
            speed_line = "⚫ Timeout" if ms is None else f"🟢 {ms:.0f} ms" if ms < 25 else f"🟡 {ms:.0f} ms" if ms < 60 else f"🔴 {ms:.0f} ms"
            self._send(f"🔬 *DNS* `{ip}` — *{known[0] if known else 'Невідомий'}*\n{speed_line}\n_/dns benchmark · /dns leak_", mid)
        except Exception as e:
            self._send(f"❌ {e}", mid)

    def _dns_list(self, mid):
        try:
            from features.dns.engine import DNS_SERVERS
            lines = ["🔬 *DNS сервери:*\n"]
            for e in DNS_SERVERS[:8]:
                sec_icon = "🔒" if e[6] else ("🛡" if e[5] else "⚡")
                lines.append(f"{sec_icon} *{e[0]}* `{e[1]}`")
            lines.append("\n`/dns set cloudflare`")
            self._send("\n".join(lines), mid)
        except Exception as e:
            self._send(f"❌ {e}", mid)

    def _dns_benchmark(self, mid):
        self._typing(); self._send("⏳ *DNS Benchmark...* (~5с)", mid)
        def _work():
            try:
                from features.dns.engine import DNSBenchmarker
                results = DNSBenchmarker().run_benchmark()
                lines   = ["🔬 *DNS Benchmark:*\n"]
                for i, r in enumerate(results[:8]):
                    ms   = r.get("avg_ms")
                    icon = "🟢" if (ms and ms<25) else "🟡" if (ms and ms<60) else "🔴"
                    lines.append(f"{icon} `#{i+1}` *{r['name']}* — `{f'{ms:.1f} ms' if ms else 'timeout'}`")
                best = next((r for r in results if r["avg_ms"] is not None), None)
                if best: lines.append(f"\n🏆 *{best['name']}* — `/dns set {best['name'].lower().split()[0]}`")
                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _dns_set(self, name_query: str, mid):
        if not name_query: self._send("❓ `/dns set cloudflare`", mid); return
        self._typing()
        try:
            from features.dns.engine import DNS_SERVERS, DNSBenchmarker
            query = name_query.lower().strip()
            match = next((e for e in DNS_SERVERS if query in e[0].lower() or query==e[1]), None)
            if not match: self._send(f"❌ `{name_query}` не знайдено.", mid); return
            bench = DNSBenchmarker()
            if not bench.is_admin(): self._send("🔐 Потрібні права Адміністратора.", mid); return
            self._send(f"⚡ Переключаю на *{match[0]}*...", mid)
            def _work():
                bench.apply_dns(match[1], match[2])
                self._api.send(self._chat_id, f"✅ DNS → `{match[1]}` ({match[0]})")
            threading.Thread(target=_work, daemon=True).start()
        except Exception as e:
            self._send(f"❌ {e}", mid)

    def _dns_leak(self, mid):
        self._typing(); self._send("🔍 DNS Leak Test... (~5с)", mid)
        def _work():
            try:
                from features.dns.engine import DNSBenchmarker
                res    = DNSBenchmarker().dns_leak_test()
                leaked = res["leaked"]
                lines  = [f"{'⚠️' if leaked else '✅'} *{res['summary']}*"]
                for r in res.get("resolvers",[])[:4]:
                    lines.append(f"`{r['ip']}` — {r['country']} | {r['isp']}")
                if leaked: lines.append("\n_/dns set cloudflare — виправити_")
                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _dns_flush(self, mid):
        def _work():
            try:
                from features.dns.engine import DNSBenchmarker
                ok = DNSBenchmarker().flush_dns()
                self._api.send(self._chat_id, "✅ DNS кеш очищено!" if ok else "❌ Помилка.")
            except Exception as e:
                self._api.send(self._chat_id, f"❌ {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_wifi(self, args, mid):
        sub = args.strip().lower().split()[0] if args.strip() else ""
        if sub == "router":           self._wifi_router_link(mid); return
        if sub in ("channels","ch"):  self._wifi_channels_only(mid); return
        if sub == "change":           self._wifi_change_channel(mid); return
        self._wifi_full_report(mid, force=(sub == "scan"))

    def _wifi_change_channel(self, mid):
        """
        Допомагає змінити канал Wi-Fi. Оскільки канал змінюється тільки
        через admin-панель роутера — бот показує найкращий канал і інструкцію.
        """
        self._typing()
        try:
            if not self._wifi_scan_fn:
                self._send("❌ Wi-Fi сканер недоступний", mid); return

            networks, rating = self._wifi_scan_fn()
            if not networks or not rating:
                self._send("❌ Не вдалось зібрати дані про Wi-Fi", mid); return

            # Витягуємо найкращі канали з rating
            best_24 = rating.get("best_24ghz") or rating.get("best_2_4")
            best_5  = rating.get("best_5ghz") or rating.get("best_5")
            current = rating.get("current_channel") or rating.get("my_channel")

            # Пробуємо дістати gateway для відкриття
            gw = "192.168.0.1"
            try:
                from features.security.lan_security import LanSecurityEngine
                eng = self._lan_engine or LanSecurityEngine()
                gw = eng._detect_gateway() or gw
            except Exception: pass

            lines = [
                "📡 *ЗМІНА WI-FI КАНАЛУ*",
                "━━━━━━━━━━━━━━━━━━━━",
                "",
                f"📊 Поточний канал: `{current or '?'}`",
            ]
            if best_24:
                lines.append(f"✅ Рекомендовано (2.4 GHz): *канал {best_24}*")
            if best_5:
                lines.append(f"✅ Рекомендовано (5 GHz): *канал {best_5}*")

            lines.extend([
                "",
                "⚠️ *Канал змінюється тільки через роутер*",
                "",
                "📋 *Інструкція:*",
                f"1. Відкрий браузер: `http://{gw}`",
                "2. Залогінься в адмін-панель",
                "3. Перейди: *Wi-Fi* → *Основні налаштування*",
                f"4. Зміни поле 'Канал' на рекомендований",
                "5. *Застосувати* / *Зберегти*",
                "",
                f"💡 Відкрий: http://{gw}"
            ])
            self._send("\n".join(lines), mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    def _wifi_full_report(self, mid, force: bool = False):
        self._typing()
        if not force and self._wifi_cache and time.time() - self._wifi_cache[2] < 180:
            networks, rating, _ = self._wifi_cache
            self._send("📡 _(дані < 3 хв)_", mid)
        else:
            networks, rating = self._do_wifi_scan()
            if not networks:
                self._send("❌ Не вдалось отримати дані Wi-Fi.", mid); return
        from features.wifi.engine import WifiEngine
        self._send(WifiEngine().get_wifi_report_text(networks, rating), mid)

    def _wifi_channels_only(self, mid):
        self._typing()
        networks, rating = self._do_wifi_scan()
        if not networks: self._send("❌ Немає даних.", mid); return
        from features.wifi.engine import WifiEngine
        my_ch = rating["my_channel"]; best_ch = rating["best_channel"]
        self._send(f"📊 *2.4 GHz каналів*\n\n{WifiEngine.ascii_channel_bar(rating, my_ch, best_ch)}", mid)

    def _wifi_router_link(self, mid):
        gw  = self._get_local_gateway()
        url = self._probe_router_url(gw)
        self._api.send(self._chat_id, f"🌐 <b>Панель роутера</b>\n🔗 <a href=\"{url}\">{url}</a>",
                       reply_to=mid, parse_mode="HTML")

    def _get_local_gateway(self) -> str:
        if self._wifi_gateway_fn:
            try:
                gw = self._wifi_gateway_fn()
                if gw and gw != "0.0.0.0": return gw
            except Exception: pass
        from features.wifi.engine import WifiEngine
        return WifiEngine.get_gateway_ip()

    @staticmethod
    def _probe_router_url(gw: str) -> str:
        for url in [f"http://{gw}", f"http://{gw}:8080"]:
            try:
                req = urllib.request.Request(url, method="HEAD")
                with urllib.request.urlopen(req, timeout=2) as r:
                    if r.status < 500: return url
            except urllib.error.HTTPError as e:
                if e.code in (200,301,302,401,403): return url
            except Exception: pass
        return f"http://{gw}/"

    def _do_wifi_scan(self) -> tuple:
        if self._wifi_cache and time.time() - self._wifi_cache[2] < 180:
            return self._wifi_cache[0], self._wifi_cache[1]
        try:
            if self._wifi_scan_fn:
                result = self._wifi_scan_fn()
                if isinstance(result, tuple) and len(result) == 2:
                    networks, rating = result
                else:
                    networks = result
                    from features.wifi.engine import WifiEngine
                    rating = WifiEngine().get_channel_rating(networks)
            else:
                from features.wifi.engine import WifiEngine
                engine   = WifiEngine()
                networks = engine.scan_networks()
                rating   = engine.get_channel_rating(networks)
            self._wifi_cache = (networks, rating, time.time())
            return networks, rating
        except Exception as e:
            print(f"[Bot] wifi: {e}")
            return [], {}

    def notify_wifi_interference(self, networks=None, rating=None):
        if networks is None or rating is None:
            networks, rating = self._do_wifi_scan()
        if not rating.get("worth_switching"): return
        my_ch = rating["my_channel"]; best_ch = rating["best_channel"]
        gw    = self._get_local_gateway()
        self._api.send(self._chat_id,
            f"📡 <b>Wi-Fi канал перевантажений!</b>\n"
            f"Зараз: <b>{my_ch}</b> → Рекомендовано: <b>{best_ch}</b>\n"
            f'<a href="http://{gw}/">http://{gw}/</a>', parse_mode="HTML")

    # ══════════════════════════════════════════════════════
    #  MONITOR / STATUS / DIAGNOSE / PING / etc.
    # ══════════════════════════════════════════════════════

    def _cmd_status(self, args, mid):
        self._typing()
        snap = self._snapshot()
        ping = snap.get("ping_ms")
        dl   = snap.get("dl_mbps")
        ul   = snap.get("ul_mbps")
        ping_s = (
            "⚫ невідомо" if ping is None else
            f"🟢 {ping} ms — відмінно" if ping < 30 else
            f"🟢 {ping} ms — добре"    if ping < 80 else
            f"🟡 {ping} ms — задовільно" if ping < 150 else
            f"🔴 {ping} ms — погано"
        )
        # Явна перевірка на None (бо 0.0 теж falsy) —
        # 0.0 показуємо саме як 0.0 щоб користувач знав що тест дав нуль,
        # а не що даних немає.
        dl_str = f"{dl:.1f} Mbps" if isinstance(dl, (int, float)) else "— (не тестовано)"
        ul_str = f"{ul:.1f} Mbps" if isinstance(ul, (int, float)) else "— (не тестовано)"
        up_sec = snap.get("uptime_sec", 0)
        h, r = divmod(up_sec, 3600); m, s = divmod(r, 60)
        self._send_with_nav(
            f"📡 *СТАН МЕРЕЖІ* — {time.strftime('%H:%M:%S')}\n━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"📊 Пінг: {ping_s}\n⬇️ Download: `{dl_str}`\n⬆️ Upload: `{ul_str}`\n\n"
            f"💡 `/speedtest` — запустити тест зараз\n\n"
            f"🏠 Local IP: `{snap.get('local_ip','?')}`\n"
            f"🌐 Gateway: `{snap.get('gateway','?')}`\n"
            f"🔒 External: `{snap.get('ext_ip','?')}`\n"
            f"📡 ISP: {snap.get('isp','?')}\n"
            f"⏱️ Uptime: {h:02d}:{m:02d}:{s:02d}",
            section="dash"
        )
        if self._ai and self._ai.available:
            self._typing()
            self._send(f"🤖 *AI:* {self._ai.quick_status_summary(snap)}")

    def _cmd_ping(self, args, mid):
        import subprocess, platform
        host = args.strip() or "8.8.8.8"
        self._typing()
        results = []
        for _ in range(4):
            try:
                fl  = getattr(subprocess,"CREATE_NO_WINDOW",0)
                if platform.system()=="Windows":
                    out = subprocess.check_output(["ping","-n","1","-w","1000",host],
                        text=True,encoding="cp866",errors="replace",creationflags=fl,timeout=4)
                    m = re.search(r"(?:Час|time)[=<](\d+)",out)
                    results.append(int(m.group(1)) if m else None)
                else:
                    out = subprocess.check_output(["ping","-c","1","-W","1",host],
                        text=True,errors="replace",timeout=4)
                    m = re.search(r"time[=<]([\d.]+)",out)
                    results.append(int(float(m.group(1))) if m else None)
            except Exception:
                results.append(None)
            time.sleep(0.3)
        valid = [r for r in results if r is not None]
        loss  = round(results.count(None)/4*100)
        icon  = "🟢" if valid and sum(valid)/len(valid)<80 else "🟡" if valid else "🔴"
        avg   = sum(valid)//len(valid) if valid else "—"
        bars  = "▓"*len(valid) + "░"*results.count(None)
        self._send(f"{icon} *Ping: {host}*\navg: `{avg} ms` | loss: `{loss}%`\n{bars}", mid)

    def _cmd_search(self, args, mid):
        if not args.strip(): self._send("🔍 `/search dns повільний`", mid); return
        self._typing()
        from app.core.knowledge_base import search_kb
        results = search_kb(args.strip(), limit=3)
        if not results: self._send(f"❌ За `{args}` нічого.", mid); return
        lines = [f"🔍 *{len(results)} результати:*\n"]
        for entry in results:
            sev_icon = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🔵"}.get(entry.severity,"⚪")
            lines.append(f"{sev_icon} *[{entry.code}]* {entry.title}\n🔧 {entry.solutions[0]}\n")
        self._send("\n".join(lines), mid)

    def _cmd_fix(self, args, mid):
        from app.core.knowledge_base import _INDEX
        code = args.strip().upper()
        if not code: self._send("🔧 `/fix DNS-001`", mid); return
        entry = _INDEX["by_code"].get(code)
        if not entry: self._send(f"❌ `{code}` не знайдено.", mid); return
        sev_icon = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🔵"}.get(entry.severity,"⚪")
        self._send(
            f"{sev_icon} *{entry.title}*\n\n📋 *Причини:*\n" +
            "\n".join(f"• {c}" for c in entry.causes) + "\n\n🔧 *Рішення:*\n" +
            "\n".join(f"{i+1}. {s}" for i,s in enumerate(entry.solutions)), mid)

    def _cmd_scan(self, args, mid):
        host = args.strip() or "127.0.0.1"
        if not re.match(r'^[\w\.\-]+$', host):
            self._send("❌ Невалідний хост", mid); return
        self._typing(); self._send(f"🔍 Сканую `{host}`...", mid)
        open_ports = _quick_scan(host)
        if not open_ports: self._send(f"✅ `{host}` — відкритих не знайдено.", mid); return
        dangerous = [(p,s,r) for p,s,r in open_ports if r]
        self._send(
            f"🔍 *Scan: {host}*\nВідкритих: {len(open_ports)} | Небезпечних: {len(dangerous)}\n\n" +
            "\n".join(f"{r or '🟢'} `:{p}` — {s}" for p,s,r in open_ports), mid)

    def _cmd_diagnose(self, args, mid):
        self._typing()
        if not self._diagnose: self._send("❌ Функція діагностики недоступна.", mid); return
        self._send("🔬 Діагностую... (~30с)", mid)
        def _work():
            try:
                report   = self._diagnose()
                issues   = report.get("issues",[])
                critical = [i for i in issues if i.get("sev")=="CRITICAL"]
                warnings = [i for i in issues if i.get("sev")=="WARNING"]
                overall  = ("🟢 МЕРЕЖА В НОРМІ" if not issues else
                            f"🔴 КРИТИЧНО ({len(critical)})" if critical else
                            f"🟡 Є ПРОБЛЕМИ ({len(warnings)})")
                lines = [f"{'🔴' if i.get('sev')=='CRITICAL' else '🟡'} `[{i.get('code')}]` {i.get('title')}"
                         for i in (critical + warnings)[:8]]
                self._api.send(self._chat_id,
                    f"🔬 *Діагностика:* {overall}\n\n" + ("\n".join(lines) if lines else "✅ OK"),
                    reply_to=mid)

                # ── AI-аналіз через Gemini (новий) ──
                try:
                    from app.core.gemini_client import get_gemini_client
                    gemini = get_gemini_client()
                    if gemini.is_available():
                        self._api.send(self._chat_id, "🤖 _AI аналізує..._")
                        ai = gemini.analyze_network(report)
                        if ai.get("success"):
                            msg = self._format_ai_for_telegram(ai)
                            self._api.send(self._chat_id, msg)
                        else:
                            err = ai.get("error", "невідома помилка")[:100]
                            self._api.send(self._chat_id,
                                f"⚠️ AI-аналіз не вдався: {err}")
                    elif self._ai and getattr(self._ai, "available", False):
                        # Fallback на локальний AI engine якщо Gemini недоступний
                        self._api.send(self._chat_id,
                            f"🤖 *AI (локально):*\n"
                            f"{self._ai.analyze_diagnostics(report, for_telegram=True)}")
                    else:
                        self._api.send(self._chat_id,
                            "ℹ️ AI-аналіз недоступний.\n"
                            "Налаштуй Gemini у NetGuardian → Settings → AI Settings")
                except Exception as ai_err:
                    print(f"[Bot] AI diagnose error: {ai_err}")
                    # Fallback на локальний AI engine
                    if self._ai and getattr(self._ai, "available", False):
                        try:
                            self._api.send(self._chat_id,
                                f"🤖 *AI (локально):*\n"
                                f"{self._ai.analyze_diagnostics(report, for_telegram=True)}")
                        except Exception: pass
            except Exception as e:
                self._api.send(self._chat_id, f"❌ {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _format_ai_for_telegram(self, ai_data: dict) -> str:
        """Форматує AI-результат у Telegram MarkdownV2-сумісний рядок."""
        overall = ai_data.get("overall", "good")
        emoji = {
            "excellent": "🟢", "good": "🟢",
            "warning":  "🟡", "critical": "🔴",
        }.get(overall, "⚪")

        lines = [f"🤖 *AI ВИСНОВОК* {emoji}", ""]

        summary = ai_data.get("summary", "").strip()
        if summary:
            lines.append(f"_{summary}_")
            lines.append("")

        good = ai_data.get("good", [])
        if good:
            lines.append("*✅ Працює добре:*")
            for line in good[:4]:
                lines.append(f"  {line}")
            lines.append("")

        warnings = ai_data.get("warnings", [])
        if warnings:
            lines.append("*🟡 Попередження:*")
            for line in warnings[:4]:
                lines.append(f"  {line}")
            lines.append("")

        critical = ai_data.get("critical", [])
        if critical:
            lines.append("*🔴 Критичні проблеми:*")
            for line in critical[:4]:
                lines.append(f"  {line}")
            lines.append("")

        tips = ai_data.get("tips", [])
        if tips:
            lines.append("*💡 Поради:*")
            for i, tip in enumerate(tips[:5], 1):
                lines.append(f"  {i}. {tip}")

        result = "\n".join(lines)
        # Telegram має ліміт 4096 символів
        if len(result) > 4000:
            result = result[:3950] + "\n\n_(скорочено)_"
        return result

    def _cmd_speedtest(self, args, mid):
        self._typing()
        if not self._speedtest: self._send("❌ Speedtest недоступний.", mid); return
        self._send("⚡ *Запускаю speedtest...*\n_~20с — вимірюю DL+UL_", mid)
        def _work():
            try:
                t0 = time.time()
                dl, ul = self._speedtest()
                elapsed = time.time() - t0
                snap   = self._snapshot()
                ping   = snap.get("ping_ms",0) or 0

                # Обидва нулі — повний fail
                if (not dl or dl <= 0) and (not ul or ul <= 0):
                    self._send_with_nav(
                        f"⚠️ *Speedtest не вдалось*\n\n"
                        f"DL: 0.0 Mbps · UL: 0.0 Mbps\n"
                        f"⏱ Час: {elapsed:.1f}с\n\n"
                        f"Можливі причини:\n"
                        f"• Cloudflare/Hetzner rate-limit (частий тест)\n"
                        f"• Проблеми з інтернетом\n"
                        f"• Brandmauer/Antivirus блокує HTTPS\n"
                        f"• VPN перехоплює трафік\n\n"
                        f"💡 Спробуй `/speedtest` ще раз через 1-2 хв\n"
                        f"💡 Або в GUI натисни *'ТЕСТ'* — там видно деталі",
                        section="dash")
                    return

                # Хоч один з них спрацював — показуємо обидва чесно
                dl_str = f"{dl:.1f} Mbps" if dl and dl > 0 else "— (не виміряно)"
                ul_str = f"{ul:.1f} Mbps" if ul and ul > 0 else "— (не виміряно)"

                if dl and dl > 100:   icon, verdict = "🟢", "Відмінно"
                elif dl and dl > 30:  icon, verdict = "🟢", "Добре"
                elif dl and dl > 10:  icon, verdict = "🟡", "Повільно"
                elif dl and dl > 0:   icon, verdict = "🔴", "Дуже повільно"
                else:                  icon, verdict = "⚠️", "DL не виміряно"

                self._send_with_nav(
                    f"⚡ *Speedtest результат*\n"
                    f"━━━━━━━━━━━━━━━━━\n"
                    f"⬇️ Download: `{dl_str}`\n"
                    f"⬆️ Upload:   `{ul_str}`\n"
                    f"📊 Пінг:     `{ping} ms`\n"
                    f"⏱ Час: {elapsed:.1f}с\n\n"
                    f"{icon} {verdict}",
                    section="dash")
            except Exception as e:
                import traceback
                tb = traceback.format_exc()[-300:]
                self._send_with_nav(
                    f"❌ *Помилка Speedtest*\n\n`{e}`\n\n```\n{tb}\n```",
                    section="dash")
        threading.Thread(target=_work, daemon=True).start()

    def _cmd_predict(self, args, mid):
        if not (self._ai and self._ai.available):
            self._send("❌ AI недоступний", mid); return
        self._typing()
        self._send(self._ai.predict_issues(self._snapshot()), mid)

    def _cmd_ask(self, args, mid):
        """Швидке Q&A з AI (Gemini) + контекст з Knowledge Base.

        Якщо ключ Gemini налаштований — використовує Gemini.
        Якщо ні — fallback на локальну KB (без AI, тільки пошук).
        """
        if not args.strip():
            self._send(
                "❓ *Швидке питання до AI*\n\n"
                "Приклад: `/ask чому інтернет повільний?`\n"
                "         `/ask як налаштувати DNS?`\n"
                "         `/ask пояснити jitter простими словами`",
                mid)
            return
        self._typing()

        # Шукаємо релевантні записи у локальній Knowledge Base
        try:
            from app.core.knowledge_base import search_kb
            kb_results = search_kb(args.strip(), limit=3)
        except Exception:
            kb_results = []

        # Спроба 1: Gemini AI (новий клієнт)
        try:
            from app.core.gemini_client import get_gemini_client
            gemini = get_gemini_client()
            if gemini.is_available():
                # Будуємо контекст з KB + поточної мережі
                ctx = {}
                if self._snapshot:
                    try:
                        snap = self._snapshot()
                        ctx = {
                            "ping_ms":  snap.get("ping_ms"),
                            "isp":      snap.get("isp_name"),
                            "wifi":     snap.get("wifi_ssid"),
                        }
                    except Exception: pass
                if kb_results:
                    ctx["kb_hints"] = [
                        f"[{e.code}] {e.title}: {e.solutions[0]}"
                        for e in kb_results
                    ]

                def _work_gemini():
                    try:
                        self._api.send(self._chat_id, "🤖 _Думаю..._",
                                        reply_to=mid)
                        answer = gemini.quick_answer(args.strip(), context=ctx)
                        if len(answer) > 4000:
                            answer = answer[:3950] + "\n\n_(скорочено)_"
                        self._api.send(self._chat_id,
                            f"🤖 *Gemini AI:*\n\n{answer}", reply_to=mid)
                    except Exception as e:
                        self._api.send(self._chat_id, f"❌ {e}")
                threading.Thread(target=_work_gemini, daemon=True).start()
                return
        except ImportError:
            pass   # gemini_client не існує — спробуємо старий AI
        except Exception as e:
            print(f"[Bot/ask] Gemini error, fallback: {e}")

        # Спроба 2: старий локальний AI engine (Anthropic Claude)
        if self._ai and self._ai.available:
            kb_context = ""
            if kb_results:
                kb_context = "\n".join(
                    f"KB: [{e.code}] {e.title}: {e.solutions[0]}"
                    for e in kb_results)
            snap   = self._snapshot() if self._snapshot else {}
            answer = self._ai.chat(
                args.strip() + (f"\n\nКонтекст:\n{kb_context}"
                                if kb_context else ""),
                network_context=snap, for_telegram=True)
            self._send(f"🤖 {answer}", mid)
            return

        # Спроба 3: тільки KB (без жодного AI)
        if kb_results:
            e = kb_results[0]
            sev_icon = {"CRITICAL":"🔴","WARNING":"🟡","INFO":"🔵"}.get(
                e.severity,"⚪")
            self._send(
                f"{sev_icon} *{e.title}*\n\n"
                f"🔧 {e.solutions[0]}\n\n"
                f"_💡 Налаштуй Gemini AI у Settings для розумніших відповідей_",
                mid)
        else:
            self._send(
                "❌ AI недоступне.\n\n"
                "*Налаштуй ключ Gemini:*\n"
                "1. Отримай безкоштовно на https://aistudio.google.com/apikey\n"
                "2. NetGuardian → Налаштування → 🤖 AI Діагностика\n"
                "3. Встав ключ → Зберегти",
                mid)

    def _cmd_events(self, args, mid):
        if not self._agent: self._send("❌ Smart Agent недоступний", mid); return
        hours = 24
        try:
            if args.strip(): hours = int(args.strip())
        except Exception: pass
        self._send(self._agent.get_events_text(hours), mid)

    def _cmd_agent(self, args, mid):
        if not self._agent: self._send("❌ Smart Agent недоступний", mid); return
        parts = args.strip().split()
        sub   = parts[0].lower() if parts else "status"
        if sub in ("status",""):
            self._send(self._agent.get_agent_status(), mid)
        elif sub == "autofix":
            enabled = len(parts)>1 and parts[1].lower() in ("on","true")
            self._agent._settings["auto_fix"] = enabled
            self._agent.save_settings(self._agent._settings)
            self._send(f"🔧 Авто-виправлення: {'✅' if enabled else '❌'}", mid)
        elif sub == "scan":
            self._typing(); self._send("🔄 Запускаю сканування...", mid)
            threading.Thread(target=self._agent._run_scan, daemon=True).start()
        else:
            self._send("*Команди:*\n/agent status\n/agent scan\n/agent autofix on/off", mid)

    # ══════════════════════════════════════════════════════
    #  NEW COMMANDS — розширений функціонал LAN Security
    # ══════════════════════════════════════════════════════

    def _ensure_lan_engine(self, mid) -> bool:
        """Лінивий імпорт LAN engine. Повертає True якщо готовий."""
        if self._lan_engine: return True
        try:
            from features.security.lan_security import LanSecurityEngine
            self._lan_engine = LanSecurityEngine()
            return True
        except Exception as e:
            self._send(f"❌ LAN недоступний: `{e}`", mid); return False

    @staticmethod
    def _normalize_mac(mac: str) -> str:
        """12:7A:22:BF:D4:9E — приводить до єдиного формату."""
        if not mac: return ""
        clean = mac.upper().replace("-", ":").strip()
        # Валідація: 6 груп по 2 hex
        parts = clean.split(":")
        if len(parts) == 6 and all(len(p) == 2 and all(c in "0123456789ABCDEF" for c in p) for p in parts):
            return clean
        # Пробуємо без розділювачів (12 hex символів)
        alt = mac.upper().replace(":","").replace("-","").strip()
        if len(alt) == 12 and all(c in "0123456789ABCDEF" for c in alt):
            return ":".join(alt[i:i+2] for i in range(0,12,2))
        return ""

    def _find_host(self, ident: str) -> dict:
        """Знаходить пристрій за MAC, IP, hostname або tail MAC.
        Шукає в останньому скані, а якщо нема — у TrustDB.
        """
        ident_orig = ident.strip()
        ident = ident_orig.lower()

        # Спочатку шукаємо в last_scan якщо є
        if self._lan_last_scan:
            # 1. Точний MAC
            mac_norm = self._normalize_mac(ident).lower()
            if mac_norm:
                for h in self._lan_last_scan:
                    if h.get("mac","").lower() == mac_norm:
                        return h
            # 2. IP
            for h in self._lan_last_scan:
                if h.get("ip","") == ident: return h
            # 3. MAC-tail (останні 6 символів, напр. "BFD49E")
            if len(ident) == 6 and all(c in "0123456789abcdef" for c in ident):
                for h in self._lan_last_scan:
                    mac_clean = h.get("mac","").lower().replace(":","").replace("-","")
                    if mac_clean.endswith(ident): return h
            # 4. Hostname / label
            for h in self._lan_last_scan:
                for key in ("user_label","hostname","phone_name","phone_model"):
                    val = (h.get(key) or "").lower()
                    if val and (ident in val or val in ident):
                        return h

        # FALLBACK: пошук у TrustDB (якщо останнього скану нема або пристрій
        # там відсутній — наприклад був тільки у сповіщенні)
        try:
            from features.security.lan_security import trust_db
            mac_norm = self._normalize_mac(ident_orig)
            if mac_norm:
                db_entry = trust_db.get_device(mac_norm)
                if db_entry:
                    # Конвертуємо DB-запис у формат host-dict
                    return {
                        "mac":        mac_norm,
                        "ip":         db_entry.get("ip","—"),
                        "vendor":     db_entry.get("vendor",""),
                        "model":      db_entry.get("model",""),
                        "hostname":   db_entry.get("hostname",""),
                        "user_label": db_entry.get("label",""),
                        "dev_type":   db_entry.get("vendor",""),
                        "is_trusted": db_entry.get("trusted", False),
                        "is_allowed": db_entry.get("allowed", False),
                        "alert_dismissed": db_entry.get("alert_dismissed", False),
                        "is_banned":  trust_db.is_banned(mac_norm),
                        "threat":     "safe",
                        "open_ports": [],
                        "_from_db":   True,   # мітка що з БД, не зі скану
                    }
        except Exception as e:
            print(f"[Bot _find_host] TrustDB fallback error: {e}")

        return None

    # ── /banned ────────────────────────────────────────
    def _cmd_banned(self, args, mid):
        if not self._ensure_lan_engine(mid): return
        try:
            banned = self._lan_engine.get_banned()
        except Exception as e:
            self._send(f"❌ `{e}`", mid); return

        if not banned:
            self._send("✅ *Список заблокованих порожній*\n\n_Жоден пристрій не заблоковано._", mid)
            return

        lines = [f"🚫 *ЗАБЛОКОВАНІ ПРИСТРОЇ* ({len(banned)})", "━━━━━━━━━━━━━━━━━━"]
        for b in banned[:15]:
            mac   = b.get("mac","—")
            ip    = b.get("ip","—") or "—"
            label = b.get("label","") or b.get("vendor","Невідомий") or "Невідомий"
            rem   = b.get("remaining")
            if b.get("is_permanent", True):
                time_str = "♾ Назавжди"
            elif rem is not None:
                if rem > 3600:   time_str = f"⏱ {rem//3600}г {(rem%3600)//60}хв"
                elif rem > 60:   time_str = f"⏱ {rem//60}хв"
                else:            time_str = f"⏱ {int(rem)}с"
            else: time_str = "—"
            lines.append(f"• `{mac}`\n  {label}  ·  `{ip}`  ·  {time_str}")
        if len(banned) > 15:
            lines.append(f"\n_...та ще {len(banned)-15}_")
        lines.append("\n💡 `/unblock <mac>` — розблокувати")
        self._send("\n".join(lines), mid)

    # ── /block <mac_or_ip> ─────────────────────────────
    # Словник інструкцій для різних роутерів
    _BLOCK_INSTRUCTIONS = {
        "d-link":    ("Міжмережевий екран → MAC-фільтр",
                      "Firewall → MAC Filter / Network Filter",
                      "Режим 'Заборонити' → Додати MAC → Зберегти"),
        "dlink":     ("Міжмережевий екран → MAC-фільтр",
                      "Firewall → MAC Filter / Network Filter",
                      "Режим 'Заборонити' → Додати MAC → Зберегти"),
        "tp-link":   ("Advanced → Security → Access Control",
                      "Advanced → Security → Access Control",
                      "Blacklist → Add → Save"),
        "tplink":    ("Advanced → Security → Access Control",
                      "Advanced → Security → Access Control",
                      "Blacklist → Add → Save"),
        "asus":      ("Wireless → Wireless MAC Filter",
                      "Wireless → Wireless MAC Filter",
                      "MAC Filter Mode: Reject → Add → Apply"),
        "keenetic":  ("Мережі Wi-Fi → Список пристроїв",
                      "Wi-Fi → Access List",
                      "Обмежити → Додати MAC → Зберегти"),
        "tenda":     ("Advanced → Access Control",
                      "Advanced → Access Control",
                      "Add MAC → Enable → Save"),
        "huawei":    ("More Functions → Security → MAC Filter",
                      "More Functions → Security → MAC Filter",
                      "Enable Blacklist → Add MAC → Apply"),
    }

    def _cmd_block(self, args, mid):
        """
        Two-step manual block workflow:
          step 1 (без 'confirm'): показує повну інструкцію для роутера
          step 2 (з 'confirm'):   після блокування в роутері — запис у БД
        """
        if not args.strip():
            self._send(
                "⚠️ *Використання:*\n\n"
                "`/block <mac|ip>`\n"
                "    Показує інструкцію блокування через роутер\n\n"
                "`/block <mac> confirm`\n"
                "    Відмічає пристрій заблокованим у базі\n"
                "    (після ручного блокування в роутері)\n\n"
                "*Приклад:*\n"
                "`/block 28:3F:69:E6:C5:C3`", mid)
            return
        if not self._ensure_lan_engine(mid): return

        parts = args.strip().split()
        ident = parts[0]
        is_confirm = len(parts) > 1 and parts[1].lower() in ("confirm", "done", "готово", "ok")

        host = self._find_host(ident)
        if not host:
            self._send(f"❌ Пристрій `{ident}` не знайдено в останньому скані.\n\n"
                      f"Зроби `/lan scan` спочатку.", mid)
            return

        mac = host.get("mac","—")
        ip  = host.get("ip","—")
        label = (host.get("user_label") or host.get("phone_name") or
                 host.get("hostname") or host.get("vendor","?"))

        # ── STEP 2: CONFIRM — записуємо в БД після ручного блокування ──
        if is_confirm:
            try:
                self._lan_engine.ban_device(
                    mac=mac, ip=ip,
                    vendor=host.get("vendor",""),
                    label=label,
                    reason="Заблоковано вручну через адмін-панель (підтверджено через бота)",
                    duration=0.0)
                self._api.send(self._chat_id,
                    f"✅ *ЗАБЛОКОВАНО У БД*\n\n"
                    f"• Пристрій: *{label}*\n"
                    f"• MAC: `{mac}`\n"
                    f"• IP: `{ip}`\n"
                    f"• Статус: 🚫 permanent\n\n"
                    f"Пристрій тепер у списку заблокованих.\n"
                    f"📋 `/banned` — переглянути всі\n"
                    f"🔓 `/unblock {mac}` — розблокувати")
            except Exception as e:
                self._api.send(self._chat_id, f"❌ Помилка: `{e}`")
            return

        # ── STEP 1: показуємо інструкцію блокування через роутер ──
        try:
            # Визначаємо vendor роутера для правильної інструкції
            gw = host.get("gateway","") or self._lan_engine._detect_gateway()
            router_vendor = ""
            try:
                v, _, _ = self._lan_engine.lookup_oui(gw)
                router_vendor = (v or "").lower()
            except Exception: pass

            # Шукаємо інструкцію для цього vendor
            instruction = None
            detected = ""
            for key in self._BLOCK_INSTRUCTIONS:
                if key in router_vendor:
                    instruction = self._BLOCK_INSTRUCTIONS[key]
                    detected = key.upper()
                    break

            lines = [
                "🛡️ *БЛОКУВАННЯ ПРИСТРОЮ*",
                "━━━━━━━━━━━━━━━━━━━━━━━━",
                "",
                "🎯 *Пристрій для блокування:*",
                f"   • Назва: *{label}*",
                f"   • IP:    `{ip}`",
                f"   • MAC:   `{mac}`",
                "",
                f"📡 *Твій роутер:* {router_vendor.title() or 'невідомий'} (`{gw}`)",
                "",
                "━━━━━━━━━━━━━━━━━━━━━━━━",
            ]

            if instruction:
                ua_path, en_path, mode = instruction
                lines.extend([
                    f"📋 *ІНСТРУКЦІЯ для {detected}:*",
                    "",
                    f"*1.* Відкрий адмін-панель роутера:",
                    f"    http://{gw}",
                    "",
                    f"*2.* Увійди (логін/пароль з наклейки роутера)",
                    "",
                    f"*3.* Перейди в меню:",
                    f"    🔸 {ua_path}",
                    f"    🔸 _або EN: {en_path}_",
                    "",
                    f"*4.* Виконай:",
                    f"    {mode}",
                    "",
                    f"*5.* Скопіюй і встав MAC:",
                    f"    `{mac}`",
                    "",
                    "*6.* Збережи налаштування",
                ])
            else:
                lines.extend([
                    "📋 *ЗАГАЛЬНА ІНСТРУКЦІЯ:*",
                    "",
                    f"*1.* Відкрий: http://{gw}",
                    "*2.* Увійди в адмін-панель",
                    "*3.* Знайди розділ:",
                    "    🔸 MAC Filter / Access Control",
                    "    🔸 Parental Controls / Міжмережевий екран",
                    "*4.* Вибери режим 'Deny/Blacklist'",
                    f"*5.* Додай MAC: `{mac}`",
                    "*6.* Збережи налаштування",
                ])

            lines.extend([
                "",
                "━━━━━━━━━━━━━━━━━━━━━━━━",
                "✅ *Після блокування в роутері — підтверди в боті:*",
                "",
                f"`/block {mac} confirm`",
                "",
                "_Це додасть пристрій до списку заблокованих у NetGuardian._",
                "",
                f"🌐 Відкрити роутер: http://{gw}",
            ])

            self._send("\n".join(lines), mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /unblock <mac> ─────────────────────────────────
    def _cmd_unblock(self, args, mid):
        if not args.strip():
            self._send("⚠️ Вкажи MAC\n\n`/unblock 12:7A:22:BF:D4:9E`", mid)
            return
        if not self._ensure_lan_engine(mid): return

        mac = self._normalize_mac(args.strip().split()[0])
        if not mac:
            self._send(f"❌ Невірний MAC формат", mid); return

        try:
            self._lan_engine.unban_device(mac, "")
            # Додатково — розблокуємо через роутер (якщо є credentials)
            try:
                self._lan_engine.router_mac_filter(mac, "", "", block=False)
            except Exception: pass
            self._send(f"🔓 *Розблоковано*\n`{mac}`\n\n_Пристрій може знов підключатись до мережі._", mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /trust <mac> ───────────────────────────────────
    def _cmd_trust(self, args, mid):
        if not args.strip():
            self._send("⚠️ `/trust <mac>`", mid); return
        if not self._ensure_lan_engine(mid): return
        mac = self._normalize_mac(args.strip().split()[0])
        if not mac: self._send("❌ Невірний MAC", mid); return
        try:
            self._lan_engine.set_trusted(mac, True)
            self._send(f"✅ *Довірений*\n`{mac}`\n\n_Пристрій у білому списку._", mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /untrust <mac> ─────────────────────────────────
    def _cmd_untrust(self, args, mid):
        if not args.strip():
            self._send("⚠️ `/untrust <mac>`", mid); return
        if not self._ensure_lan_engine(mid): return
        mac = self._normalize_mac(args.strip().split()[0])
        if not mac: self._send("❌ Невірний MAC", mid); return
        try:
            self._lan_engine.set_trusted(mac, False)
            self._send(f"❔ *Знято довіру*\n`{mac}`", mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /rename <mac> <name> ───────────────────────────
    def _cmd_rename(self, args, mid):
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            self._send("⚠️ `/rename <mac> <нова_назва>`\n\nПриклад:\n`/rename 12:7A:22:BF:D4:9E Sony Xperia`", mid)
            return
        if not self._ensure_lan_engine(mid): return
        mac  = self._normalize_mac(parts[0])
        name = parts[1].strip()
        if not mac: self._send("❌ Невірний MAC", mid); return
        if not name: self._send("❌ Порожня назва", mid); return
        try:
            self._lan_engine.set_device_label(mac, name, "")
            self._send(f"✏️ *Збережено*\n`{mac}` → *{name}*", mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /details <mac_or_ip> ───────────────────────────
    def _cmd_details(self, args, mid):
        if not args.strip():
            self._send("⚠️ `/details <mac або ip>`", mid); return
        if not self._ensure_lan_engine(mid): return
        host = self._find_host(args.strip().split()[0])
        if not host:
            self._send("❌ Пристрій не знайдено. `/lan scan` спочатку.", mid); return

        # Збираємо всі корисні поля
        threat_emoji = {"critical":"⛔","danger":"⚠️","warn":"🟡","safe":"✅"}.get(
            host.get("threat","safe"),"❓")

        lines = [
            f"🔍 *ТЕХНІЧНІ ДЕТАЛІ*",
            f"━━━━━━━━━━━━━━━━━━",
            f"🆔 *Ідентифікація*",
            f"• IP: `{host.get('ip','—')}`",
            f"• MAC: `{host.get('mac','—')}`",
            f"• Vendor: {host.get('vendor','—')}",
            f"• Тип: {host.get('dev_type','—')}",
            f"• Hostname: `{host.get('hostname','—')}`",
        ]
        if host.get("user_label"):
            lines.append(f"• ✏️ Назва: *{host['user_label']}*")

        lines.extend([
            "",
            f"🌐 *Мережа*",
            f"• TTL: `{host.get('ttl','—')}`",
            f"• Gateway: `{host.get('gateway','—')}`",
            f"• Тип з'єднання: {host.get('connection_type','—')}",
            f"• Online: {'✅' if host.get('is_online') else '❌'}",
        ])

        ports = host.get("open_ports", [])
        if ports:
            lines.append(f"• Відкриті порти: `{', '.join(str(p) for p in ports[:10])}`")

        if host.get("phone_brand") or host.get("phone_model"):
            lines.extend([
                "",
                f"📱 *Телефон*",
                f"• Brand: {host.get('phone_brand','—')}",
                f"• Model: {host.get('phone_model','—')}",
                f"• OS: {host.get('phone_os','—')}",
            ])

        lines.extend([
            "",
            f"🛡️ *Статус*",
            f"• Threat: {threat_emoji} {host.get('threat','—')}",
            f"• Довірений: {'✅' if host.get('is_trusted') else '❌'}",
            f"• Заблокований: {'🚫' if host.get('is_banned') else '—'}",
            f"• Новий: {'🆕' if host.get('is_new') else '—'}",
        ])
        self._send("\n".join(lines), mid)

    # ── /deep <ip> ─────────────────────────────────────
    def _cmd_deep_identify(self, args, mid):
        if not args.strip():
            self._send("⚠️ `/deep <ip>`", mid); return
        if not self._ensure_lan_engine(mid): return

        ident = args.strip().split()[0]
        host = self._find_host(ident)
        if not host:
            self._send("❌ Пристрій не знайдено в останньому скані", mid); return

        self._send(f"🔍 *Deep Identification...*\n`{host.get('ip','')}`\n_Може зайняти до 15с_", mid)

        def _work():
            try:
                from features.security.deep_identify import get_identifier
                di = get_identifier()
                result = di.identify(host.get("ip",""),
                                     host.get("mac",""),
                                     host)
                conf  = result.get("confidence", 0)
                name  = result.get("name", "")
                method = result.get("method", "—")
                if name and conf >= 0.4:
                    confidence_bar = "●" * int(conf * 5) + "○" * (5 - int(conf * 5))
                    self._api.send(self._chat_id,
                        f"🎯 *Результат*\n"
                        f"• Назва: *{name}*\n"
                        f"• Метод: `{method}`\n"
                        f"• Впевненість: {confidence_bar} ({conf*100:.0f}%)")
                else:
                    self._api.send(self._chat_id,
                        f"⚠️ *Не вдалось ідентифікувати*\n"
                        f"Пристрій не розкриває інформації.\n"
                        f"Причини: Private MAC, iOS/Android блокує mDNS, etc.")
            except Exception as e:
                self._api.send(self._chat_id, f"❌ `{e}`")

        threading.Thread(target=_work, daemon=True).start()

    # ── /ports <ip> ────────────────────────────────────
    def _cmd_ports(self, args, mid):
        if not args.strip():
            self._send("⚠️ `/ports <ip>`\n\nПриклад: `/ports 192.168.0.147`", mid); return
        if not self._ensure_lan_engine(mid): return

        target = args.strip().split()[0]
        self._send(f"🔬 *Сканую порти...*\n`{target}`", mid)

        def _work():
            try:
                ports = self._lan_engine.scan_ports(target, timeout=0.5)
                if not ports:
                    self._api.send(self._chat_id,
                        f"✅ *{target}*\nВідкритих портів не виявлено.")
                    return
                lines = [f"🔬 *Порти {target}* ({len(ports)})", "━━━━━━━━━━━━━━━━━━"]
                for p in sorted(ports)[:30]:
                    risk = "⛔" if p in (21,23,3389,5900,1433,3306) else \
                           "⚠️" if p in (135,139,445,80,443,22) else "🔵"
                    lines.append(f"{risk} `{p}`")
                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                self._api.send(self._chat_id, f"❌ `{e}`")

        threading.Thread(target=_work, daemon=True).start()

    # ── /traceroute <host> ─────────────────────────────
    def _cmd_traceroute(self, args, mid):
        target = args.strip() or "8.8.8.8"
        self._send(f"🗺️ *Traceroute до {target}...*\n_До 30с_", mid)

        def _work():
            try:
                import platform, subprocess
                if platform.system() == "Windows":
                    cmd = ["tracert", "-h", "15", "-w", "2000", target]
                else:
                    cmd = ["traceroute", "-m", "15", "-w", "2", target]
                r = subprocess.run(cmd, capture_output=True, text=True,
                                   timeout=60, errors="replace")
                output = (r.stdout or r.stderr or "").strip()
                # Обмежуємо — Telegram не любить >4000 символів
                if len(output) > 3500:
                    output = output[:3500] + "\n...[обрізано]"
                self._api.send(self._chat_id,
                    f"🗺️ *Traceroute {target}*\n```\n{output}\n```")
            except Exception as e:
                self._api.send(self._chat_id, f"❌ `{e}`")

        threading.Thread(target=_work, daemon=True).start()

    # ── /router ────────────────────────────────────────
    def _cmd_router(self, args, mid):
        if not self._ensure_lan_engine(mid): return
        try:
            from features.security.lan_security import router_manager
            net = self._lan_engine.get_network_info()
            gw  = net.get("gateway","?")
            v, _, _ = self._lan_engine.lookup_oui(gw)
            cfg = router_manager.get_router_by_ip(gw)

            lines = [
                "📡 *ІНФО ПРО РОУТЕР*",
                "━━━━━━━━━━━━━━━━━",
                f"• IP: `{gw}`",
                f"• Vendor: {v or 'Невідомий'}",
                f"• Subnet: `{net.get('subnet','?')}`",
                f"• Мій IP: `{net.get('my_ip','?')}`",
            ]
            if cfg:
                lines.extend([
                    "",
                    f"✅ *CREDENTIALS ЗБЕРЕЖЕНО*",
                    f"• Ім'я: {cfg.get('name','—')}",
                    f"• Логін: `{cfg.get('http_user','—')}`",
                    f"• Пароль: `{'*' * len(cfg.get('http_pwd',''))}`",
                    f"• SSH: {'✅' if cfg.get('ssh_user') else '❌'}",
                ])
            else:
                lines.extend([
                    "",
                    f"⚠️ *Credentials НЕ налаштовані*",
                    f"Автоматичне блокування через API неможливе.",
                    f"Зайди у NetGuardian → Security →",
                    f"⭐ Налаштувати роутер",
                ])
            self._send("\n".join(lines), mid)
        except Exception as e:
            self._send(f"❌ `{e}`", mid)

    # ── /mystats ───────────────────────────────────────
    def _cmd_mystats(self, args, mid):
        """Розширена статистика — Dashboard snapshot у красивому вигляді."""
        self._typing()
        snap = self._snapshot() if callable(self._snapshot) else {}
        if not snap:
            self._send("⚠️ Dashboard ще не ініціалізовано", mid); return

        def _fmt(val, fallback="—"):
            if val is None or val == "" or val == "—": return fallback
            return str(val)

        ping = snap.get("ping_ms")
        ping_str = f"{ping:.1f} ms" if isinstance(ping, (int,float)) else "—"
        ping_emoji = "🟢" if isinstance(ping,(int,float)) and ping < 30 else \
                     "🟡" if isinstance(ping,(int,float)) and ping < 100 else "🔴"

        dl = snap.get("dl_mbps")
        ul = snap.get("ul_mbps")
        dl_str = f"{dl:.1f} Mbps" if isinstance(dl,(int,float)) else "—"
        ul_str = f"{ul:.1f} Mbps" if isinstance(ul,(int,float)) else "—"

        wifi_pct = snap.get("wifi_pct")
        wifi_str = f"{wifi_pct}%" if wifi_pct else "—"
        wifi_bar = "●" * (int(wifi_pct/20) if wifi_pct else 0) + "○" * (5 - (int(wifi_pct/20) if wifi_pct else 0))

        uptime = snap.get("uptime_sec", 0)
        up_str = f"{uptime//3600}г {(uptime%3600)//60}хв" if uptime else "—"

        lines = [
            "📊 *РОЗШИРЕНА СТАТИСТИКА*",
            "━━━━━━━━━━━━━━━━━━━",
            "",
            f"{ping_emoji} *Пінг:* {ping_str}",
            f"   Статус: {_fmt(snap.get('ping_status'))}",
            "",
            f"⚡ *Швидкість:*",
            f"   ↓ DL: {dl_str}",
            f"   ↑ UL: {ul_str}",
            "",
            f"📡 *Wi-Fi:*",
            f"   SSID: `{_fmt(snap.get('wifi_ssid'))}`",
            f"   Сила: {wifi_bar} {wifi_str}",
            f"   dBm: {_fmt(snap.get('wifi_dbm'))}",
            "",
            f"🌐 *Мережа:*",
            f"   Мій IP: `{_fmt(snap.get('local_ip'))}`",
            f"   Шлюз: `{_fmt(snap.get('gateway'))}`",
            f"   Публічний: `{_fmt(snap.get('ext_ip'))}`",
            "",
            f"🏢 *Провайдер:* {_fmt(snap.get('isp'))}",
            f"📍 *Локація:* {_fmt(snap.get('city'))}, {_fmt(snap.get('country'))}",
            "",
            f"⏱ *Uptime:* {up_str}",
        ]
        self._send("\n".join(lines), mid)

    # ══════════════════════════════════════════════════════
    #  /channel — ЗМІНА Wi-Fi КАНАЛУ
    # ══════════════════════════════════════════════════════
    def _cmd_channel(self, args, mid):
        """
        /channel — рекомендує найкращий канал Wi-Fi і відкриває admin-панель.
        /channel scan — перед рекомендацією робить свіжий скан сусідніх мереж.
        """
        force_scan = args.strip().lower() == "scan"
        self._typing()

        # Окремий потік — сканування може займати 5-10 сек
        def _work():
            try:
                if not self._wifi_scan_fn:
                    self._api.send(self._chat_id,
                        "❌ Wi-Fi сканер недоступний.\nЦя функція потребує запущеної утиліти.")
                    return

                # Викликаємо scan — повертає (networks, rating)
                result = self._wifi_scan_fn()
                if not result or not isinstance(result, tuple):
                    self._api.send(self._chat_id, "❌ Не вдалось зібрати дані")
                    return
                networks, rating = result[0], result[1] if len(result) > 1 else None

                if not networks:
                    self._api.send(self._chat_id,
                        "❌ Не виявлено жодної Wi-Fi мережі поруч.\n"
                        "_Переконайся що Wi-Fi адаптер увімкнений._")
                    return

                # Визначаємо свою мережу (за snapshot або найсильнішим сигналом)
                my_ssid = ""
                my_channel = None
                my_dbm = None
                try:
                    snap = self._snapshot() if callable(self._snapshot) else {}
                    my_ssid = snap.get("wifi_ssid", "") or ""
                    my_channel = snap.get("wifi_channel")
                    my_dbm = snap.get("wifi_dbm")
                except Exception: pass

                # Рахуємо зайнятість каналів 2.4 GHz (1-13) і 5 GHz (36-165)
                channels_24 = [0] * 14   # 0-13
                channels_5  = {}          # dict бо канали 5GHz нерегулярні

                for net in networks:
                    ch = net.get("channel") if isinstance(net, dict) else getattr(net, "channel", None)
                    if ch is None: continue
                    try: ch = int(ch)
                    except Exception: continue

                    # Рахуємо "вагу" мережі за сигналом (сильніший = більше навантаження)
                    dbm = net.get("signal_dbm", -80) if isinstance(net, dict) else getattr(net, "signal_dbm", -80)
                    try: dbm = int(dbm)
                    except Exception: dbm = -80
                    weight = max(1, 100 + dbm)  # -50 dBm → 50, -90 dBm → 10

                    if 1 <= ch <= 13:
                        channels_24[ch] += weight
                        # 2.4 GHz: сусідні канали теж "пересікаються" (±2)
                        for near in range(max(1, ch-2), min(13, ch+2)+1):
                            if near != ch: channels_24[near] += weight // 2
                    elif ch >= 36:
                        channels_5[ch] = channels_5.get(ch, 0) + weight

                # Найкращі канали у 2.4 GHz — з рекомендованих [1, 6, 11]
                # (тільки вони не пересікаються між собою)
                best_24 = min([1, 6, 11], key=lambda c: channels_24[c])
                best_24_load = channels_24[best_24]

                # Найкращий 5 GHz — той у якого менше сусідів
                best_5 = None
                if channels_5:
                    # Всі використовувані канали з найменшим навантаженням
                    best_5 = min(channels_5.keys(), key=lambda c: channels_5[c])
                else:
                    # Нікого немає на 5 GHz → стандартний рекомендований
                    best_5 = 36

                # Gateway для посилання
                gw = "192.168.0.1"
                try:
                    from features.security.lan_security import LanSecurityEngine
                    eng = self._lan_engine or LanSecurityEngine()
                    gw = eng._detect_gateway() or gw
                except Exception: pass

                # Формуємо відповідь
                lines = [
                    "📡 *ЗМІНА WI-FI КАНАЛУ*",
                    "━━━━━━━━━━━━━━━━━━━━━━━━",
                    "",
                ]
                if my_ssid and my_ssid != "—":
                    lines.append(f"🏠 *Твоя мережа:* `{my_ssid}`")
                lines.append(f"📊 *Мереж поруч:* {len(networks)}")
                if my_channel:
                    curr_load = channels_24[my_channel] if 1 <= my_channel <= 13 else channels_5.get(my_channel, 0)
                    emoji = "🟢" if curr_load < 30 else "🟡" if curr_load < 80 else "🔴"
                    lines.append(f"{emoji} *Поточний канал:* `{my_channel}`  (завантаж. ~{curr_load})")
                lines.append("")

                # Рекомендації
                lines.append("💡 *РЕКОМЕНДАЦІЇ:*")
                load_24_emoji = "🟢" if best_24_load < 30 else "🟡" if best_24_load < 80 else "🔴"
                lines.append(f"   {load_24_emoji} *2.4 GHz:* канал `{best_24}`  (навантаж. ~{best_24_load})")
                if best_5:
                    load_5 = channels_5.get(best_5, 0)
                    load_5_emoji = "🟢" if load_5 < 30 else "🟡" if load_5 < 80 else "🔴"
                    lines.append(f"   {load_5_emoji} *5 GHz:*   канал `{best_5}`  (навантаж. ~{load_5})")

                # Якщо поточний канал вже хороший — не міняй
                if my_channel:
                    current_is_best = (my_channel == best_24 or my_channel == best_5)
                    if current_is_best:
                        lines.extend([
                            "",
                            "✅ *Твій канал вже оптимальний — міняти не потрібно*"
                        ])
                    elif 1 <= my_channel <= 13 and channels_24[my_channel] - best_24_load < 20:
                        lines.extend([
                            "",
                            "ℹ️ *Поточний канал майже такий самий — зміна не критична*"
                        ])

                lines.extend([
                    "",
                    "━━━━━━━━━━━━━━━━━━━━━━━━",
                    "⚠️ *Канал змінюється тільки через адмін-панель роутера:*",
                    "",
                    f"1. Відкрий: http://{gw}",
                    "2. Увійди (admin / пароль роутера)",
                    "3. Перейди: *Wi-Fi* → *Основні налаштування*",
                    f"4. Поміняй 'Канал' на *{best_24}* (або *{best_5}* для 5 GHz)",
                    "5. Натисни *Застосувати*",
                    "",
                    "🔄 `/channel scan` — оновити рекомендацію",
                ])

                self._api.send(self._chat_id, "\n".join(lines))
            except Exception as e:
                import traceback
                self._api.send(self._chat_id,
                    f"❌ Помилка: `{str(e)[:200]}`\n\n"
                    f"_Деталі у консолі програми._")
                print(f"[Bot /channel] {traceback.format_exc()}")

        self._send(
            "📡 *Сканую Wi-Fi мережі поруч...*\n_~5-10 секунд_", mid)
        threading.Thread(target=_work, daemon=True).start()


# ══════════════════════════════════════════════════════════════════
#  ФАБРИКА
# ══════════════════════════════════════════════════════════════════

def start_polling(token: str, chat_id: str,
                  get_snapshot_fn=None, speedtest_fn=None,
                  diagnose_fn=None, ai_analyzer=None,
                  smart_agent=None,
                  wifi_scan_fn=None, wifi_gateway_fn=None,
                  lan_engine=None, game_engine=None, vpn_engine=None,
                  forecast_engine=None) -> "NetGuardianBot":
    bot = NetGuardianBot()
    bot.start_polling(
        token=token, chat_id=chat_id,
        get_snapshot_fn=get_snapshot_fn, speedtest_fn=speedtest_fn,
        diagnose_fn=diagnose_fn, ai_analyzer=ai_analyzer,
        smart_agent=smart_agent,
        wifi_scan_fn=wifi_scan_fn, wifi_gateway_fn=wifi_gateway_fn,
        lan_engine=lan_engine, game_engine=game_engine, vpn_engine=vpn_engine,
        forecast_engine=forecast_engine,
    )
    return bot


# ══════════════════════════════════════════════════════════════════
#  ЗВОРОТНА СУМІСНІСТЬ
# ══════════════════════════════════════════════════════════════════

class TelegramAlerter:
    _bot_instance = None

    @staticmethod
    def send_message(token: str, chat_id: str, text: str,
                     parse_mode: str = "HTML") -> bool:
        try:
            text = (text.replace("<b>","*").replace("</b>","*")
                        .replace("<i>","_").replace("</i>","_")
                        .replace("<code>","`").replace("</code>","`"))
            _TelegramAPI(token).send(chat_id, text, parse_mode="Markdown")
            return True
        except Exception as e:
            print(f"[TelegramAlerter] {e}")
            return False

    @staticmethod
    def start_polling(token: str, allowed_chat_id: str,
                      handlers: dict = None, snapshot_fn=None,
                      speedtest_fn=None, diagnose_fn=None,
                      ai_analyzer=None, smart_agent=None,
                      wifi_scan_fn=None, wifi_gateway_fn=None,
                      lan_engine=None, game_engine=None, vpn_engine=None,
                      forecast_engine=None):
        TelegramAlerter._bot_instance = start_polling(
            token=token, chat_id=allowed_chat_id,
            get_snapshot_fn=snapshot_fn, speedtest_fn=speedtest_fn,
            diagnose_fn=diagnose_fn, ai_analyzer=ai_analyzer,
            smart_agent=smart_agent,
            wifi_scan_fn=wifi_scan_fn, wifi_gateway_fn=wifi_gateway_fn,
            lan_engine=lan_engine, game_engine=game_engine, vpn_engine=vpn_engine,
            forecast_engine=forecast_engine,
        )
        return TelegramAlerter._bot_instance