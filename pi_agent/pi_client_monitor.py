#!/usr/bin/env python3
"""
pi_client_monitor.py — Незалежний моніторинг ПК-клієнта на Pi.

Запускається на Pi через cron кожні 5 хв. Перевіряє чи клієнт-ПК
надсилав MQTT-команди останнім часом (мітка у ~/.netguardian-agent/client_seen.txt).
Якщо клієнт не з'являвся > 30 хв — шле alert у Telegram прямо з Pi.

Це дає ПОВНУ НЕЗАЛЕЖНІСТЬ алертів від стану ПК-клієнта.

УСТАНОВКА НА Pi:
  1. Скопіюй цей файл у /home/dim4ik/NetGuardian/
  2. Створи /home/dim4ik/NetGuardian/.env з токеном:
        TELEGRAM_BOT_TOKEN=твій_токен
        TELEGRAM_CHAT_ID=твій_chat_id
  3. Додай у crontab (crontab -e):
        */5 * * * * /home/dim4ik/NetGuardian/venv/bin/python /home/dim4ik/NetGuardian/pi_client_monitor.py >> /home/dim4ik/.netguardian-agent/monitor.log 2>&1
  4. Перевір: tail -f /home/dim4ik/.netguardian-agent/monitor.log
"""
import os
import sys
import time
import json
import urllib.request
import urllib.parse
from pathlib import Path


# ── Конфігурація ───────────────────────────────────────────
SEEN_FILE        = Path.home() / ".netguardian-agent" / "client_seen.txt"
STATE_FILE       = Path.home() / ".netguardian-agent" / "monitor_state.json"
THRESHOLD_SEC    = 30 * 60       # 30 хв тиші → клієнт offline
COOLDOWN_SEC     = 60 * 60       # 1 година між повторними алертами


def _load_env():
    """Читає .env файл який лежить поряд зі скриптом."""
    env_file = Path(__file__).parent / ".env"
    if not env_file.exists():
        return {}
    out = {}
    try:
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception:
        pass
    return out


def _send_telegram(token, chat_id, text):
    """Шле повідомлення у Telegram через urllib (без requests)."""
    try:
        data = urllib.parse.urlencode({
            "chat_id":    chat_id,
            "text":       text,
            "parse_mode": "Markdown",
        }).encode("utf-8")
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[monitor] Telegram error: {e}", file=sys.stderr)
        return False


def _load_state():
    """Останній стан моніторингу: коли востаннє надсилали alert."""
    if not STATE_FILE.exists():
        return {"last_alert": 0, "last_state": "unknown"}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"last_alert": 0, "last_state": "unknown"}


def _save_state(state):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state))
    except Exception:
        pass


def _get_client_age():
    """Повертає секунди з останнього звернення клієнта.
    Якщо файлу нема — повертає None (перший запуск).
    """
    if not SEEN_FILE.exists():
        return None
    try:
        ts = int(SEEN_FILE.read_text().strip())
        return time.time() - ts
    except Exception:
        return None


def main():
    env = _load_env()
    token   = env.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = env.get("TELEGRAM_CHAT_ID", "").strip()

    if not token or not chat_id:
        print("[monitor] ❌ TELEGRAM_BOT_TOKEN/CHAT_ID не задані в .env")
        return 1

    age = _get_client_age()
    state = _load_state()
    now   = time.time()

    if age is None:
        # Файл client_seen.txt ще не створено - агент тільки запустився
        # або ПК-клієнт ніколи не звертався. Не шлемо нічого.
        print("[monitor] ℹ️  client_seen.txt ще не існує")
        return 0

    is_offline = age > THRESHOLD_SEC

    print(f"[monitor] age={age:.0f}s threshold={THRESHOLD_SEC}s "
          f"offline={is_offline} last_state={state.get('last_state')}")

    # ── Перехід online → offline ──
    if is_offline and state.get("last_state") in ("online", "unknown"):
        if now - state.get("last_alert", 0) > COOLDOWN_SEC:
            msg = (
                "🔴 *ПК-клієнт OFFLINE*\n\n"
                f"NetGuardian-клієнт не звертався *{age/60:.0f} хв*.\n"
                "Можливі причини:\n"
                "  • Комп'ютер вимкнено / спить\n"
                "  • Утиліту закрито\n"
                "  • Втрата інтернет-зв'язку на ПК\n\n"
                "_Pi-агент продовжує збирати дані 24/7 — "
                "вони синхронізуються коли клієнт повернеться._\n\n"
                "_Цей alert надіслано безпосередньо з Raspberry Pi._"
            )
            if _send_telegram(token, chat_id, msg):
                state["last_alert"] = now
                print("[monitor] 📵 OFFLINE alert sent")
        state["last_state"] = "offline"
        _save_state(state)
        return 0

    # ── Перехід offline → online ──
    if not is_offline and state.get("last_state") == "offline":
        msg = (
            "🟢 *ПК-клієнт ONLINE*\n\n"
            "NetGuardian-клієнт знову на зв'язку.\n"
            f"Останній пінг: *{age/60:.1f} хв тому*\n\n"
            "_Зараз відбувається синхронізація даних які накопичились "
            "поки клієнт був вимкнений._\n\n"
            "_Pi-агент → клієнт._"
        )
        _send_telegram(token, chat_id, msg)
        state["last_state"] = "online"
        state["last_alert"] = 0
        _save_state(state)
        print("[monitor] ✅ ONLINE recovery alert sent")
        return 0

    # ── Стан не змінився — нічого не робимо ──
    if not is_offline:
        state["last_state"] = "online"
        _save_state(state)
    return 0


if __name__ == "__main__":
    sys.exit(main())