"""
MQTT-підписник для отримання даних з Raspberry Pi-агента.

Підписується на топіки `netguardian/<user>/+` і пише отримані
повідомлення у локальний SQLite-кеш `~/.netguardian/pi_agent_cache.db`.

ВИПРАВЛЕНО v3:
  Раніше subscriber очікував поля {target, ping_ms, jitter_ms, loss_pct},
  але Pi-агент насправді надсилає {host, ms, loss}. Тепер читаємо обидва
  варіанти імен — і нові, і старі.

Працює у фоновому потоці постійно протягом усього сеансу.
Інші модулі (наприклад, Forecast) читають з цієї бази через
features/forecast/remote_source.py.
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable

try:
    import paho.mqtt.client as mqtt  # type: ignore
    HAS_MQTT = True
except ImportError:
    HAS_MQTT = False


# ── Конфіг (читається з .env або з параметрів) ───────────────────────────
DEFAULT_BROKER       = "broker.hivemq.com"
DEFAULT_PORT         = 1883
DEFAULT_TOPIC_PREFIX = "netguardian/dim4ik2003"
DB_PATH              = Path.home() / ".netguardian" / "pi_agent_cache.db"


def _ensure_schema(conn: sqlite3.Connection):
    """Створює всі таблиці кешу Pi-агента."""
    c = conn.cursor()

    # Heartbeat — статус Pi
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_heartbeat (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT DEFAULT (datetime('now', 'localtime')),
            cpu_temp   REAL,
            cpu_load   REAL,
            mem_pct    REAL,
            disk_pct   REAL,
            uptime_sec INTEGER,
            throttled  TEXT,
            raw_json   TEXT
        )
    """)

    # Ping (з Pi на 8.8.8.8 / 1.1.1.1 / 9.9.9.9)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_ping (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            ts        TEXT DEFAULT (datetime('now', 'localtime')),
            target    TEXT,
            ping_ms   REAL,
            jitter_ms REAL,
            loss_pct  REAL,
            raw_json  TEXT
        )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_remote_ping_ts ON remote_ping(ts)")
    # UNIQUE щоб INSERT OR IGNORE не робив дублів при синхронізації історії
    c.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_remote_ping_unique "
              "ON remote_ping(ts, target)")

    # LAN-сканування
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_lan_scan (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT DEFAULT (datetime('now', 'localtime')),
            device_count INTEGER,
            raw_json     TEXT
        )
    """)

    # Інтерфейси (eth0/wlan0 RSSI)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_iface (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT DEFAULT (datetime('now', 'localtime')),
            iface_name TEXT,
            rssi       REAL,
            tx_bytes   INTEGER,
            rx_bytes   INTEGER,
            raw_json   TEXT
        )
    """)

    # Процеси на Pi
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_processes (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT DEFAULT (datetime('now', 'localtime')),
            raw_json TEXT
        )
    """)

    # Speedtest від Pi (Pi-агент публікує speedtest раз на годину)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_speedtest (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            ts       TEXT DEFAULT (datetime('now', 'localtime')),
            dl_mbps  REAL,
            ul_mbps  REAL,
            ping_ms  REAL,
            server   TEXT,
            raw_json TEXT
        )
    """)

    # Денні / тижневі звіти від Pi
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_daily_summary (
            date       TEXT PRIMARY KEY,
            avg_ping   REAL,
            min_ping   REAL,
            max_ping   REAL,
            avg_jitter REAL,
            avg_loss   REAL,
            samples    INTEGER,
            blackouts  INTEGER,
            best_hour  INTEGER,
            generated_at TEXT DEFAULT (datetime('now', 'localtime')),
            raw_json   TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_weekly_summary (
            week_key   TEXT PRIMARY KEY,
            avg_ping   REAL,
            min_ping   REAL,
            max_ping   REAL,
            avg_jitter REAL,
            avg_loss   REAL,
            samples    INTEGER,
            blackouts  INTEGER,
            generated_at TEXT DEFAULT (datetime('now', 'localtime')),
            raw_json   TEXT
        )
    """)

    # Локальний AI на Pi
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_ai_analysis (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            ts           TEXT DEFAULT (datetime('now', 'localtime')),
            req_id       TEXT,
            net_id       TEXT,
            errors_count INTEGER,
            summary      TEXT,
            raw_json     TEXT
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_ai_analysis_ts "
        "ON remote_ai_analysis(ts)"
    )

    # Помилки які Pi бачив у мережі
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_errors (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            received_at TEXT DEFAULT (datetime('now', 'localtime')),
            error_ts    TEXT,
            error_type  TEXT,
            severity    TEXT,
            target      TEXT,
            value       TEXT,
            details     TEXT,
            net_id      TEXT
        )
    """)
    c.execute(
        "CREATE INDEX IF NOT EXISTS idx_remote_errors_type "
        "ON remote_errors(error_type, error_ts)"
    )

    # Історія ping з Pi (для синхронізації при старті)
    c.execute("""
        CREATE TABLE IF NOT EXISTS remote_history_sync (
            ts          TEXT,
            ping_ms     REAL,
            jitter_ms   REAL,
            loss_pct    REAL,
            net_id      TEXT,
            ssid        TEXT,
            received_at TEXT DEFAULT (datetime('now', 'localtime')),
            PRIMARY KEY (ts, net_id)
        )
    """)

    conn.commit()


# ─── ХЕЛПЕРИ ДЛЯ ЧИТАННЯ ПОЛІВ З РІЗНИМИ ІМЕНАМИ ──────────────────────────
def _get_any(data: dict, *keys):
    """Повертає перше непорожнє значення з вказаних ключів."""
    for k in keys:
        v = data.get(k)
        if v is not None:
            return v
    return None


class PiMqttSubscriber:
    """MQTT-підписник до даних з Raspberry Pi-агента."""

    def __init__(self,
                 broker: str = DEFAULT_BROKER,
                 port: int = DEFAULT_PORT,
                 topic_prefix: str = DEFAULT_TOPIC_PREFIX,
                 db_path: Optional[Path] = None,
                 on_message_cb: Optional[Callable[[str, dict], None]] = None):
        self.broker       = os.environ.get("MQTT_BROKER", broker)
        self.port         = int(os.environ.get("MQTT_PORT", port))
        self.topic_prefix = os.environ.get("MQTT_PREFIX", topic_prefix).rstrip("/")
        self.db_path      = db_path or DB_PATH
        self.on_message_cb = on_message_cb

        # Створюємо папку та схему
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            _ensure_schema(conn)

        self._client: Optional["mqtt.Client"] = None
        self._stop_evt = threading.Event()
        self._connected = False
        self._lock = threading.Lock()

        self.on_connect_cb: Optional[Callable[[bool], None]] = None
        self.on_disconnect_cb: Optional[Callable[[], None]] = None

    def start(self) -> bool:
        """Запускає фоновий MQTT-клієнт."""
        if not HAS_MQTT:
            print("[MQTT-Sub] paho-mqtt не встановлено!")
            return False

        if self._client is not None:
            return True

        try:
            self._client = mqtt.Client(client_id=f"netguardian-pc-{os.getpid()}")
            self._client.on_connect    = self._on_connect
            self._client.on_disconnect = self._on_disconnect
            self._client.on_message    = self._on_message
            self._client.reconnect_delay_set(min_delay=1, max_delay=60)
            self._client.connect_async(self.broker, self.port, keepalive=60)
            self._client.loop_start()
            return True
        except Exception as e:
            print(f"[MQTT-Sub] start error: {e}")
            self._client = None
            return False

    def stop(self):
        self._stop_evt.set()
        if self._client:
            try:
                self._client.loop_stop()
                self._client.disconnect()
            except Exception:
                pass
            self._client = None
        self._connected = False

    @property
    def is_connected(self) -> bool:
        return self._connected

    def get_db_path(self) -> Path:
        return self.db_path

    # ── Callbacks ────────────────────────────────────────────────────────
    def _on_connect(self, client, userdata, flags, rc):
        self._connected = (rc == 0)
        if rc == 0:
            print(f"[MQTT-Sub] підключено до {self.broker}:{self.port}")
            client.subscribe(f"{self.topic_prefix}/+", qos=0)
        else:
            print(f"[MQTT-Sub] помилка підключення rc={rc}")
        if self.on_connect_cb:
            try: self.on_connect_cb(self._connected)
            except Exception: pass

    def _on_disconnect(self, client, userdata, rc):
        self._connected = False
        if self.on_disconnect_cb:
            try: self.on_disconnect_cb()
            except Exception: pass

    def _on_message(self, client, userdata, msg):
        topic = msg.topic
        try:
            payload = msg.payload.decode("utf-8", errors="replace")
            data    = json.loads(payload)
        except Exception:
            return

        suffix = topic.rsplit("/", 1)[-1]

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                _ensure_schema(conn)
                self._store_message(conn, suffix, data, payload)
        except Exception as e:
            print(f"[MQTT-Sub] store error: {e}")

        if self.on_message_cb:
            try: self.on_message_cb(suffix, data)
            except Exception: pass

    # ── Обробка та збереження повідомлень ────────────────────────────────
    def _store_message(self, conn: sqlite3.Connection,
                       topic_suffix: str, data: dict, raw_json: str):
        c = conn.cursor()

        if topic_suffix == "heartbeat":
            # Pi-агент надсилає: {ts, uptime_sec, cpu_temp_c, hostname}
            # Колонки БД:        {cpu_temp, cpu_load, mem_pct, disk_pct, uptime_sec, throttled}
            c.execute("""
                INSERT INTO remote_heartbeat
                (cpu_temp, cpu_load, mem_pct, disk_pct,
                 uptime_sec, throttled, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                _get_any(data, "cpu_temp_c", "cpu_temp"),    # <-- ВИПРАВЛЕНО
                _get_any(data, "cpu_load", "cpu_percent"),
                _get_any(data, "mem_pct", "memory_percent"),
                _get_any(data, "disk_pct", "disk_percent"),
                _get_any(data, "uptime_sec", "uptime"),
                _get_any(data, "throttled"),
                raw_json,
            ))

        elif topic_suffix == "ping":
            # Pi-агент надсилає: {ts, host, ms, loss}
            # Колонки БД:        {target, ping_ms, jitter_ms, loss_pct}
            c.execute("""
                INSERT INTO remote_ping
                (target, ping_ms, jitter_ms, loss_pct, raw_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                _get_any(data, "host", "target") or "8.8.8.8",   # <-- ВИПРАВЛЕНО
                _get_any(data, "ms", "ping_ms"),                  # <-- ВИПРАВЛЕНО
                _get_any(data, "jitter_ms", "jitter"),
                _get_any(data, "loss", "loss_pct"),               # <-- ВИПРАВЛЕНО
                raw_json,
            ))

        elif topic_suffix == "speedtest":
            # Pi-агент надсилає: {ts, dl_mbps, ul_mbps, ping_ms, server}
            c.execute("""
                INSERT INTO remote_speedtest
                (dl_mbps, ul_mbps, ping_ms, server, raw_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                data.get("dl_mbps"), data.get("ul_mbps"),
                data.get("ping_ms"), data.get("server"),
                raw_json,
            ))

        elif topic_suffix == "lan":
            # Pi-агент надсилає: {ts, count, devices: [...]}
            devs = data.get("devices", [])
            count = data.get("count", len(devs) if isinstance(devs, list) else 0)
            c.execute("""
                INSERT INTO remote_lan_scan (device_count, raw_json)
                VALUES (?, ?)
            """, (count, raw_json))

        elif topic_suffix == "lan_scan":
            # Старий формат (на випадок)
            devs = data.get("devices", [])
            c.execute("""
                INSERT INTO remote_lan_scan (device_count, raw_json)
                VALUES (?, ?)
            """, (len(devs) if isinstance(devs, list) else 0, raw_json))

        elif topic_suffix == "interfaces":
            for iface in data.get("interfaces", []):
                c.execute("""
                    INSERT INTO remote_iface
                    (iface_name, rssi, tx_bytes, rx_bytes, raw_json)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    iface.get("name"), iface.get("rssi"),
                    iface.get("tx_bytes"), iface.get("rx_bytes"),
                    json.dumps(iface),
                ))

        elif topic_suffix == "processes":
            c.execute(
                "INSERT INTO remote_processes (raw_json) VALUES (?)",
                (raw_json,)
            )

        elif topic_suffix == "daily_summary":
            c.execute("""
                INSERT OR REPLACE INTO remote_daily_summary
                (date, avg_ping, min_ping, max_ping,
                 avg_jitter, avg_loss, samples, blackouts,
                 best_hour, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get("date"),
                data.get("avg_ping"), data.get("min_ping"), data.get("max_ping"),
                data.get("avg_jitter"), data.get("avg_loss"),
                data.get("samples"),    data.get("blackouts"),
                data.get("best_hour"),  raw_json,
            ))

        elif topic_suffix == "weekly_summary":
            c.execute("""
                INSERT OR REPLACE INTO remote_weekly_summary
                (week_key, avg_ping, min_ping, max_ping,
                 avg_jitter, avg_loss, samples, blackouts, raw_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                data.get("week_key"),
                data.get("avg_ping"), data.get("min_ping"), data.get("max_ping"),
                data.get("avg_jitter"), data.get("avg_loss"),
                data.get("samples"),    data.get("blackouts"),
                raw_json,
            ))

        elif topic_suffix == "ai_analysis":
            c.execute("""
                INSERT INTO remote_ai_analysis
                (req_id, net_id, errors_count, summary, raw_json)
                VALUES (?, ?, ?, ?, ?)
            """, (
                data.get("req_id", ""),
                data.get("net_id", "unknown"),
                int(data.get("errors_count", 0)),
                data.get("summary", ""),
                raw_json,
            ))

        elif topic_suffix == "errors_report":
            for err in data.get("errors", []):
                c.execute("""
                    INSERT INTO remote_errors
                    (error_ts, error_type, severity, target,
                     value, details, net_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    err.get("ts"),
                    err.get("error_type"),
                    err.get("severity", "WARNING"),
                    err.get("target", ""),
                    err.get("value", ""),
                    err.get("details", ""),
                    err.get("net_id", data.get("net_id", "unknown")),
                ))

        elif topic_suffix == "history":
            # ФІКС: записуємо і в history_sync, і в remote_ping
            # бо fill_gaps_from_pi шукає в remote_ping
            for row in data.get("data", []):
                try:
                    ts_val = row.get("ts")
                    ping_val = _get_any(row, "ms", "ping_ms")
                    jitter_val = _get_any(row, "jitter_ms", "jitter") or 0
                    loss_val = _get_any(row, "loss", "loss_pct") or 0
                    target_val = _get_any(row, "host", "target") or "1.1.1.1"
                    net_id_val = row.get("net_id", "unknown")
                    ssid_val = row.get("ssid", "")

                    # 1) Записуємо в history_sync (стара логіка)
                    c.execute("""
                        INSERT OR IGNORE INTO remote_history_sync
                        (ts, ping_ms, jitter_ms, loss_pct, net_id, ssid)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (ts_val, ping_val, jitter_val, loss_val,
                          net_id_val, ssid_val))

                    # 2) Записуємо ТАКОЖ у remote_ping щоб fill_gaps бачив
                    c.execute("""
                        INSERT OR IGNORE INTO remote_ping
                        (ts, target, ping_ms, jitter_ms, loss_pct)
                        VALUES (?, ?, ?, ?, ?)
                    """, (ts_val, target_val, ping_val, jitter_val, loss_val))
                except Exception as e:
                    print(f"[MQTT-Sub] history row error: {e}")

        # Cleanup — щоб БД не росла нескінченно (тільки 30 днів)
        c.execute(
            "DELETE FROM remote_heartbeat "
            "WHERE ts < datetime('now', '-30 days', 'localtime')"
        )
        c.execute(
            "DELETE FROM remote_ping "
            "WHERE ts < datetime('now', '-30 days', 'localtime')"
        )

        conn.commit()

    # ── PUBLIC API (методи для PR #4) ────────────────────────────────────

    def send_command(self, command: str, payload: dict = None) -> bool:
        if not self._client or not self.is_connected:
            return False
        topic = f"{self.topic_prefix}/cmd/{command}"
        try:
            self._client.publish(
                topic,
                json.dumps(payload or {}),
                qos=1
            )
            return True
        except Exception:
            return False

    def request_ai_analysis(self, period_sec: int = 3600,
                            req_id: str = "") -> bool:
        import uuid
        if not req_id:
            req_id = str(uuid.uuid4())[:8]
        return self.send_command("analyze", {
            "period_sec": period_sec,
            "req_id":     req_id,
        })

    def request_errors(self, period_sec: int = 3600) -> bool:
        return self.send_command("get_errors", {"period_sec": period_sec})

    def request_history_sync(self) -> bool:
        return self.send_command("send_history")

    def request_daily_report(self) -> bool:
        return self.send_command("build_report", {"type": "daily"})

    def get_latest_ai_analysis(self,
                               max_age_seconds: int = 300) -> Optional[dict]:
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute(f"""
                    SELECT raw_json FROM remote_ai_analysis
                    WHERE ts >= datetime('now', '-{int(max_age_seconds)} seconds',
                                          'localtime')
                    ORDER BY ts DESC LIMIT 1
                """)
                row = c.fetchone()
                if row and row[0]:
                    return json.loads(row[0])
        except Exception:
            pass
        return None

    def get_recent_errors(self, period_sec: int = 3600) -> list:
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute(f"""
                    SELECT error_ts, error_type, severity, target,
                           value, details, net_id
                    FROM remote_errors
                    WHERE error_ts >= datetime('now',
                                               '-{int(period_sec)} seconds',
                                               'localtime')
                    ORDER BY error_ts DESC LIMIT 200
                """)
                cols = ["ts", "error_type", "severity", "target",
                        "value", "details", "net_id"]
                return [dict(zip(cols, r)) for r in c.fetchall()]
        except Exception:
            return []


# ── Глобальний singleton (для зручного доступу з UI) ─────────────────────
_global_subscriber: Optional[PiMqttSubscriber] = None
_lock = threading.Lock()


def get_subscriber() -> PiMqttSubscriber:
    """Повертає глобальний MQTT-підписник (singleton)."""
    global _global_subscriber
    with _lock:
        if _global_subscriber is None:
            _global_subscriber = PiMqttSubscriber()
        return _global_subscriber


def get_global_subscriber() -> Optional[PiMqttSubscriber]:
    """Повертає глобальний MQTT-підписник якщо створений, або None.
    На відміну від get_subscriber() — НЕ створює новий інстанс автоматично."""
    return _global_subscriber


def start_global() -> bool:
    """Запускає глобальний підписник. Викликається з main.py при старті."""
    return get_subscriber().start()


def stop_global():
    """Зупиняє глобальний підписник."""
    global _global_subscriber
    if _global_subscriber:
        _global_subscriber.stop()
        _global_subscriber = None