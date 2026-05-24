"""
pi_error_collector.py — Збір мережевих помилок на Raspberry Pi 24/7.

КОНЦЕПЦІЯ:
Pi постійно моніторить мережу і записує ПОМИЛКИ у локальну БД.
Коли інтернет на ПК падає — ПК може запитати у Pi через MQTT:
"що ти бачив за останню годину?"

Pi у відповідь надсилає:
  • Список помилок (DNS timeout, packet loss spikes, gateway lost, ...)
  • Результат rule-based аналізу (через pi_kb.py)
  • Конкретне діагностичне рішення (як локальний AI)

ЦЕ І Є "локальний AI на Pi" — використовуємо Pi не тільки як збирач,
а як ПОВНОЦІННИЙ діагностичний агент для AI-системи NetGuardian.

ТИПИ ПОМИЛОК що Pi може зафіксувати:
  ICMP_TIMEOUT       — пінг до цілі timeout
  DNS_NXDOMAIN       — DNS повертає неіснуючий
  DNS_TIMEOUT        — DNS не відповідає
  DNS_SLOW           — DNS відповідає > 500мс
  HIGH_PACKET_LOSS   — втрата пакетів > 10%
  HIGH_JITTER        — jitter > 50мс
  GATEWAY_LOST       — пінг до 192.168.x.1 fail
  HTTP_5xx           — сервер повертає 5xx
  TCP_RST_BURST      — багато RST за хвилину
  ROUTE_CHANGED      — змінився маршрут
  WIFI_DISCONNECT    — wlan0 відключився
  INTERNET_DOWN      — повна втрата інтернету
"""
from __future__ import annotations

import json
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# Імпорт KB (на Pi)
try:
    from pi_kb import KB, search_kb, get_by_symptoms, entry_to_dict
except ImportError:
    print("[ErrorCollector] WARNING: pi_kb.py not found — AI analysis disabled")
    KB = []
    def search_kb(*a, **kw): return []
    def get_by_symptoms(*a, **kw): return []
    def entry_to_dict(e): return {}


DB_PATH = Path.home() / ".netguardian-agent" / "ping_log.db"


# ═════════════════════════════════════════════════════════════════════════════
#  ERROR DB SCHEMA
# ═════════════════════════════════════════════════════════════════════════════
def ensure_error_schema():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(DB_PATH, timeout=5) as conn:
        c = conn.cursor()

        # Таблиця помилок (compact, для швидкого читання)
        c.execute("""
            CREATE TABLE IF NOT EXISTS network_errors (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ts          TEXT DEFAULT (datetime('now', 'localtime')),
                error_type  TEXT NOT NULL,
                severity    TEXT DEFAULT 'WARNING',
                target      TEXT,
                value       TEXT,
                details     TEXT,
                net_id      TEXT DEFAULT 'unknown'
            )
        """)

        # Індекс для швидкого пошуку за часом
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_errors_ts
            ON network_errors(ts)
        """)
        c.execute("""
            CREATE INDEX IF NOT EXISTS idx_errors_type
            ON network_errors(error_type, ts)
        """)

        conn.commit()


def log_error(error_type: str, severity: str = "WARNING",
              target: str = "", value: str = "", details: str = "",
              net_id: str = "unknown"):
    """Логує помилку у локальну БД."""
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            conn.execute("""
                INSERT INTO network_errors
                (error_type, severity, target, value, details, net_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (error_type, severity, target, value, details, net_id))

            # Чистимо помилки старші за 14 днів
            conn.execute(
                "DELETE FROM network_errors "
                "WHERE ts < datetime('now', '-14 days', 'localtime')"
            )
            conn.commit()
    except Exception as e:
        print(f"[ErrorCollector] log_error failed: {e}")


def get_errors_since(seconds: int = 3600,
                     limit: int = 100) -> list[dict]:
    """Повертає помилки за останні N секунд."""
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            c = conn.cursor()
            c.execute(f"""
                SELECT ts, error_type, severity, target, value, details, net_id
                FROM network_errors
                WHERE ts >= datetime('now', '-{int(seconds)} seconds', 'localtime')
                ORDER BY ts DESC
                LIMIT ?
            """, (limit,))
            cols = ["ts", "error_type", "severity", "target",
                    "value", "details", "net_id"]
            return [dict(zip(cols, r)) for r in c.fetchall()]
    except Exception:
        return []


def count_errors_by_type(seconds: int = 3600) -> dict:
    """Повертає {error_type: count} за останні N секунд."""
    try:
        with sqlite3.connect(DB_PATH, timeout=5) as conn:
            c = conn.cursor()
            c.execute(f"""
                SELECT error_type, COUNT(*) FROM network_errors
                WHERE ts >= datetime('now', '-{int(seconds)} seconds', 'localtime')
                GROUP BY error_type
            """)
            return {row[0]: row[1] for row in c.fetchall()}
    except Exception:
        return {}


# ═════════════════════════════════════════════════════════════════════════════
#  CHECKS — постійно бігають у фоні і пишуть помилки
# ═════════════════════════════════════════════════════════════════════════════
def check_dns(domains: list[str] = None) -> list[str]:
    """Перевіряє DNS на коректну роботу. Повертає список знайдених помилок."""
    if domains is None:
        domains = ["google.com", "cloudflare.com", "github.com"]

    errors = []
    for domain in domains:
        try:
            t0 = time.perf_counter()
            socket.gethostbyname(domain)
            elapsed_ms = (time.perf_counter() - t0) * 1000

            if elapsed_ms > 500:
                errors.append(f"DNS_SLOW: {domain} = {elapsed_ms:.0f}ms")
                log_error("DNS_SLOW", "WARNING", target=domain,
                          value=f"{elapsed_ms:.0f}ms")

        except socket.gaierror as e:
            err_str = str(e)
            if "Name or service not known" in err_str:
                log_error("DNS_NXDOMAIN", "CRITICAL", target=domain,
                          value=err_str)
                errors.append(f"DNS_NXDOMAIN: {domain}")
            else:
                log_error("DNS_TIMEOUT", "CRITICAL", target=domain,
                          value=err_str)
                errors.append(f"DNS_TIMEOUT: {domain}")
        except Exception as e:
            log_error("DNS_ERROR", "WARNING", target=domain, value=str(e))

    return errors


def check_gateway() -> bool:
    """Перевіряє доступність шлюзу. True = доступний."""
    try:
        r = subprocess.run(["ip", "route", "show", "default"],
                          capture_output=True, text=True, timeout=3)
        m = re.search(r"default\s+via\s+([\d.]+)", r.stdout)
        if not m:
            log_error("NO_GATEWAY", "CRITICAL", details="no default route")
            return False

        gw_ip = m.group(1)
        # Пінг до шлюзу
        r = subprocess.run(["ping", "-c", "2", "-W", "1", gw_ip],
                          capture_output=True, text=True, timeout=5)
        if "0 received" in r.stdout or r.returncode != 0:
            log_error("GATEWAY_LOST", "CRITICAL", target=gw_ip,
                      details="ping timeout")
            return False
        return True
    except Exception as e:
        log_error("GATEWAY_CHECK_FAIL", "WARNING", details=str(e))
        return False


def check_internet() -> bool:
    """Перевіряє доступність інтернету (по-кільком цілям)."""
    targets = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    success = 0
    for t in targets:
        try:
            r = subprocess.run(["ping", "-c", "1", "-W", "2", t],
                              capture_output=True, text=True, timeout=4)
            if r.returncode == 0 and "1 received" in r.stdout:
                success += 1
        except Exception:
            pass

    if success == 0:
        log_error("INTERNET_DOWN", "CRITICAL",
                  details=f"all 3 targets fail")
        return False

    if success < len(targets):
        log_error("INTERNET_PARTIAL", "WARNING",
                  details=f"{success}/{len(targets)} ok")

    return True


def check_packet_loss(target: str = "8.8.8.8",
                       threshold_pct: float = 10.0) -> Optional[float]:
    """Перевіряє loss на цільовий хост. Повертає % або None."""
    try:
        r = subprocess.run(["ping", "-c", "10", "-W", "1", target],
                          capture_output=True, text=True, timeout=15)
        m = re.search(r"(\d+(?:\.\d+)?)%\s*packet\s*loss", r.stdout)
        if m:
            loss = float(m.group(1))
            if loss >= threshold_pct:
                log_error("HIGH_PACKET_LOSS", "WARNING", target=target,
                          value=f"{loss}%")
            return loss
    except Exception:
        pass
    return None


def check_wifi_status() -> dict:
    """Перевіряє стан wlan0 і логує проблеми."""
    info = {"connected": False, "rssi": None, "ssid": ""}
    try:
        r = subprocess.run(["iwgetid", "-r"],
                          capture_output=True, text=True, timeout=3)
        ssid = r.stdout.strip()
        if not ssid:
            log_error("WIFI_DISCONNECT", "CRITICAL",
                      details="wlan0 not connected")
            return info

        info["ssid"]      = ssid
        info["connected"] = True

        # RSSI
        r = subprocess.run(["iwconfig", "wlan0"],
                          capture_output=True, text=True, timeout=3)
        m = re.search(r"Signal level=(-?\d+)", r.stdout)
        if m:
            rssi = int(m.group(1))
            info["rssi"] = rssi
            if rssi < -75:
                log_error("WIFI_WEAK_SIGNAL", "WARNING", value=f"{rssi}dBm")
    except Exception as e:
        log_error("WIFI_CHECK_FAIL", "WARNING", details=str(e))
    return info


# ═════════════════════════════════════════════════════════════════════════════
#  AI ANALYSIS — використовує KB для діагнозу
# ═════════════════════════════════════════════════════════════════════════════
def analyze_situation(seconds: int = 3600) -> dict:
    """
    ГОЛОВНА AI-ФУНКЦІЯ PI.

    Аналізує помилки за останній час і формує діагноз через KB.
    Це і є "локальний AI на Pi" — Pi на власних даних робить висновок.

    Повертає dict сумісний з відповідями hybrid_ai.py:
    {
        "source": "raspberry_pi",
        "summary": "...",
        "critical": [...],
        "warnings": [...],
        "tips": [...],
        "fixes": [...],
        "errors_found": {...},
        "kb_matches": [...]
    }
    """
    errors = get_errors_since(seconds, limit=200)
    counts = count_errors_by_type(seconds)

    result = {
        "source":       "raspberry_pi",
        "analyzed_at":  datetime.now().isoformat(),
        "period_sec":   seconds,
        "errors_count": len(errors),
        "errors_by_type": counts,
        "summary":      "",
        "critical":     [],
        "warnings":     [],
        "tips":         [],
        "fixes":        [],
        "kb_matches":   [],
    }

    if not errors:
        result["summary"] = "Pi не зафіксував мережевих помилок за вказаний період."
        result["tips"].append("Мережа працює стабільно з боку Pi.")
        return result

    # ── Будуємо список симптомів для KB-пошуку ──
    symptoms = []
    if counts.get("INTERNET_DOWN", 0) > 0:
        symptoms.append("інтернет недоступний")
    if counts.get("DNS_NXDOMAIN", 0) >= 3 or counts.get("DNS_TIMEOUT", 0) >= 3:
        symptoms.append("DNS не відповідає")
    if counts.get("DNS_SLOW", 0) >= 5:
        symptoms.append("DNS повільний")
    if counts.get("HIGH_PACKET_LOSS", 0) >= 2:
        symptoms.append("втрата пакетів")
    if counts.get("GATEWAY_LOST", 0) > 0:
        symptoms.append("gateway недоступний")
    if counts.get("WIFI_DISCONNECT", 0) > 0:
        symptoms.append("wifi відключився")
    if counts.get("WIFI_WEAK_SIGNAL", 0) >= 3:
        symptoms.append("слабкий сигнал wifi")

    # ── Пошук в KB ──
    kb_matches = get_by_symptoms(symptoms, KB)[:5]
    result["kb_matches"] = [entry_to_dict(e) for e in kb_matches]

    # ── Формуємо summary ──
    if counts.get("INTERNET_DOWN", 0) > 0 and counts.get("GATEWAY_LOST", 0) > 0:
        result["summary"] = (
            "🔴 КРИТИЧНО: Pi втратив зв'язок і з шлюзом, і з інтернетом. "
            "Найімовірніше — проблема з роутером або провайдером."
        )
        result["critical"].append(
            f"Втрати інтернету: {counts.get('INTERNET_DOWN', 0)} разів"
        )
        result["critical"].append(
            f"Втрати шлюзу: {counts.get('GATEWAY_LOST', 0)} разів"
        )
    elif counts.get("INTERNET_DOWN", 0) > 0:
        result["summary"] = (
            "🟡 Pi зафіксував перебої інтернету, але шлюз доступний. "
            "Проблема, ймовірно, на боці провайдера."
        )
        result["warnings"].append(
            f"Перебої інтернету: {counts.get('INTERNET_DOWN', 0)}"
        )
    elif counts.get("WIFI_DISCONNECT", 0) > 0:
        result["summary"] = (
            "🟡 Pi періодично втрачав Wi-Fi. Можливо проблема із сигналом."
        )
        result["warnings"].append(f"Wi-Fi розриви: {counts.get('WIFI_DISCONNECT', 0)}")
    elif counts.get("DNS_TIMEOUT", 0) >= 3:
        result["summary"] = (
            "🟡 DNS-сервери не відповідають. Спробуй змінити DNS на Cloudflare 1.1.1.1."
        )
        result["warnings"].append(f"DNS timeouts: {counts.get('DNS_TIMEOUT', 0)}")
    elif counts.get("HIGH_PACKET_LOSS", 0) > 0:
        result["summary"] = (
            "🟡 Високі втрати пакетів. Перевір стабільність каналу."
        )
        result["warnings"].append(
            f"Loss spikes: {counts.get('HIGH_PACKET_LOSS', 0)}"
        )
    else:
        result["summary"] = (
            f"🟢 Pi зафіксував {len(errors)} незначних помилок. "
            "Мережа працює загалом стабільно."
        )

    # ── Tips з KB ──
    for entry in kb_matches[:3]:
        for solution in entry.solutions[:2]:
            result["tips"].append(f"[{entry.code}] {solution}")
        if entry.auto_fix:
            result["fixes"].append({
                "id":      entry.auto_fix,
                "label":   f"Auto-fix: {entry.title}",
                "reason":  ", ".join(entry.causes[:2]),
                "risk":    "low" if entry.severity == "INFO" else "medium",
                "kb_code": entry.code,
            })

    return result


# ═════════════════════════════════════════════════════════════════════════════
#  COLLECTOR LOOP
# ═════════════════════════════════════════════════════════════════════════════
class ErrorCollector:
    """Фоновий потік що збирає помилки 24/7."""

    def __init__(self, net_id_getter=None):
        ensure_error_schema()
        self.stop_evt = threading.Event()
        self.thread:  Optional[threading.Thread] = None
        self._get_net_id = net_id_getter or (lambda: "unknown")

        # Інтервали перевірок
        self.dns_interval      = 300    # DNS кожні 5 хв
        self.gateway_interval  = 120    # gateway кожні 2 хв
        self.internet_interval = 180    # інтернет кожні 3 хв
        self.wifi_interval     = 600    # wifi кожні 10 хв
        self.loss_interval     = 900    # loss check кожні 15 хв

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_evt.clear()
        self.thread = threading.Thread(target=self._loop, daemon=True,
                                       name="PiErrorCollector")
        self.thread.start()
        print("[ErrorCollector] started")

    def stop(self):
        self.stop_evt.set()
        if self.thread:
            self.thread.join(timeout=3)

    def _loop(self):
        last_dns      = 0
        last_gw       = 0
        last_inet     = 0
        last_wifi     = 0
        last_loss     = 0

        while not self.stop_evt.is_set():
            now = time.time()
            net_id = self._get_net_id()

            try:
                if now - last_dns >= self.dns_interval:
                    check_dns()
                    last_dns = now

                if now - last_gw >= self.gateway_interval:
                    check_gateway()
                    last_gw = now

                if now - last_inet >= self.internet_interval:
                    check_internet()
                    last_inet = now

                if now - last_wifi >= self.wifi_interval:
                    check_wifi_status()
                    last_wifi = now

                if now - last_loss >= self.loss_interval:
                    check_packet_loss()
                    last_loss = now

            except Exception as e:
                print(f"[ErrorCollector] error in check loop: {e}")

            self.stop_evt.wait(15)


# ═════════════════════════════════════════════════════════════════════════════
#  TEST
# ═════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    ensure_error_schema()
    print("DB:", DB_PATH)

    # Тест: лог фіктивних помилок
    log_error("DNS_TIMEOUT", "CRITICAL", "google.com", "10s")
    log_error("HIGH_PACKET_LOSS", "WARNING", "8.8.8.8", "23%")
    log_error("WIFI_WEAK_SIGNAL", "WARNING", "wlan0", "-82dBm")

    print("\nЛог за останню годину:")
    for e in get_errors_since(3600):
        print(f"  {e['ts']} [{e['severity']}] {e['error_type']}: "
              f"{e['target']} {e['value']}")

    print("\nКількість за типом:")
    print(count_errors_by_type(3600))

    print("\n=== AI ANALYSIS ===")
    analysis = analyze_situation(3600)
    print(json.dumps(analysis, indent=2, ensure_ascii=False))