# core/forecast.py  v3
# ─────────────────────────────────────────────────────────────────────────────
#  NetGuardian AI  ·  Internet Weather Forecast  ·  Backend Engine
#
#  v3 — PER-NETWORK DATA ISOLATION:
#    • NetworkDetector   — визначає поточну мережу (SSID + MAC шлюзу)
#    • NetworkProfile    — dataclass для профілю мережі
#    • ForecastEngine    — всі записи і запити фільтруються по net_id
#    • Авто-міграція БД  — додає net_id до існуючих таблиць
#    • rename_network()  — перейменувати мережу в БД
#    • get_all_networks()— список усіх відомих мереж
# ─────────────────────────────────────────────────────────────────────────────

import hashlib
import sqlite3
import time
import socket
import platform
import subprocess
import threading
import statistics
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional


# ═════════════════════════════════════════════════════════════════════════════
#  DATACLASSES
# ═════════════════════════════════════════════════════════════════════════════

@dataclass
class NetworkProfile:
    """Профіль однієї мережі — зберігається в таблиці networks."""
    net_id:       str    # стабільний відбиток: md5(ssid|gw_mac)[:10]
    ssid:         str    # WiFi SSID або "Ethernet" для дротового
    gateway_ip:   str    # IP-адреса шлюзу
    gateway_mac:  str    # MAC-адреса шлюзу (стабільний ідентифікатор)
    display_name: str    # дружня назва, яку користувач може змінити
    first_seen:   str    # ISO datetime
    last_seen:    str    # ISO datetime
    measurement_count: int = 0


@dataclass
class WeatherCondition:
    """Повний «погодний» стан мережі на поточний момент."""
    ping_ms:       float = 0.0
    jitter_ms:     float = 0.0
    packet_loss:   float = 0.0
    weather_index: int   = 0
    code:   str = "unknown"
    icon:   str = "📊"
    title:  str = "Невідомо"
    desc:   str = ""
    color:  str = "#888888"
    perceived_mbps: float = 0.0
    nominal_mbps:   float = 0.0
    # мережа, з якою пов'язаний цей вимір
    net_id:       str = ""
    display_name: str = ""


@dataclass
class ServiceStatus:
    """Статус одного зовнішнього сервісу."""
    name:     str
    host:     str
    port:     int
    ping_ms:  float = -1.0
    is_up:    bool  = False
    icon:     str   = "⬜"
    category: str   = "general"


@dataclass
class ForecastDay:
    """Прогноз на один день тижня на основі історії."""
    weekday:    int
    day_name:   str
    icon:       str
    code:       str
    avg_ping:   float
    risk_pct:   int
    best_hour:  int
    worst_hour: int


@dataclass
class HistoricalAnalysis:
    """Результат аналізу SQLite-бази за 7 днів для конкретної мережі."""
    status:          str   = "no_data"
    global_avg:      float = 0.0
    hourly_data:     dict  = field(default_factory=dict)
    weekly_data:     dict  = field(default_factory=dict)
    forecast_days:   list  = field(default_factory=list)
    packet_loss_pct: float = 0.0
    anomalies_count: int   = 0
    cyclone_hours:   list  = field(default_factory=list)
    best_hour:       tuple = (0, 0.0)
    worst_hour:      tuple = (0, 0.0)
    risk_pct:        int   = 0
    current_avg:     float = 0.0
    error_msg:       str   = ""
    sla_pct:         float = 0.0
    # мережа, для якої побудовано аналіз
    net_id:          str   = ""
    display_name:    str   = ""


# ─── Конфігурація сервісів ────────────────────────────────────────────────────

MONITORED_SERVICES = [
    # ── Загальні (DNS, CDN, головні сервіси) ──
    ServiceStatus("Google DNS",   "dns.google",            443, category="general"),
    ServiceStatus("Cloudflare",   "one.one.one.one",       443, category="general"),
    ServiceStatus("Cloudflare 2", "1.0.0.1",               443, category="general"),
    ServiceStatus("Quad9 DNS",    "dns.quad9.net",         443, category="general"),

    # ── Ігрові ──
    ServiceStatus("Steam",        "steamcommunity.com",    443, category="gaming"),
    ServiceStatus("Steam CDN",    "cdn.cloudflare.steamstatic.com", 443, category="gaming"),
    ServiceStatus("Riot Games",   "auth.riotgames.com",    443, category="gaming"),
    ServiceStatus("Battle.net",   "eu.actual.battle.net",  443, category="gaming"),
    ServiceStatus("Epic Games",   "epicgames.com",         443, category="gaming"),
    ServiceStatus("PlayStation",  "www.playstation.com",   443, category="gaming"),
    ServiceStatus("Xbox Live",    "xbox.com",              443, category="gaming"),

    # ── Стрімінг та відео ──
    ServiceStatus("YouTube",      "www.youtube.com",       443, category="streaming"),
    ServiceStatus("Twitch",       "www.twitch.tv",         443, category="streaming"),
    ServiceStatus("Netflix",      "www.netflix.com",       443, category="streaming"),
    ServiceStatus("Spotify",      "open.spotify.com",      443, category="streaming"),

    # ── Робота / соцмережі ──
    ServiceStatus("Discord",      "discord.com",           443, category="work"),
    ServiceStatus("GitHub",       "github.com",            443, category="work"),
    ServiceStatus("Telegram",     "telegram.org",          443, category="work"),
    ServiceStatus("Zoom",         "zoom.us",               443, category="work"),
]

WEATHER_THRESHOLDS = [
    ( 20,  5, 0.0, "sunny",    "☀️",  "Ясно",
      "Відмінні умови для гри та стрімів. Пінг мінімальний, канал чистий.",
      "#22c55e"),
    ( 50, 15, 0.5, "cloudy",   "🌤️", "Легка хмарність",
      "Невелика нестабільність. Ігри та відео працюють нормально.",
      "#84cc16"),
    ( 80, 30, 1.0, "windy",    "🌬️", "Вітряно",
      "Джиттер заважає голосовим чатам та чутливим до затримок іграм.",
      "#eab308"),
    (120, 50, 2.0, "overcast", "☁️",  "Похмуро",
      "Підвищений пінг. Стріми можуть буферизуватись.",
      "#f97316"),
    (200, 80, 5.0, "rainy",    "🌧️", "Дощ",
      "Серйозні затримки та втрати пакетів.",
      "#ef4444"),
    (999, 999, 15.0, "storm",  "⛈️", "Гроза",
      "Критичний стан мережі! Пакетлосс > 15%.",
      "#dc2626"),
]

BLACKOUT_THRESHOLD_LOSS = 50.0
BLACKOUT_ICON  = "🌑"
BLACKOUT_TITLE = "Блекаут"
BLACKOUT_DESC  = "Мережа недоступна або повністю деградована."
BLACKOUT_COLOR = "#450a0a"

DAY_NAMES = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]

CAT_LABELS = {
    "general":   "🌐 Інтернет",
    "gaming":    "🎮 Ігри",
    "streaming": "📺 Стрімінг",
    "work":      "💼 Робота",
}

SLA_PING_THRESHOLD = 100
SLA_LOSS_THRESHOLD = 2.0

IS_WINDOWS = platform.system() == "Windows"

# Мережа-заглушка: якщо визначення не вдалося
_LEGACY_NET_ID = "legacy"


# ═════════════════════════════════════════════════════════════════════════════
#  NETWORK DETECTOR
# ═════════════════════════════════════════════════════════════════════════════

class NetworkDetector:
    """
    Визначає поточну мережу за:
      1. SSID (назва Wi-Fi мережі) або "Ethernet" якщо кабель
      2. MAC-адреса шлюзу (router MAC — стабільний ідентифікатор)
      3. IP шлюзу (для відображення)

    Відбиток мережі (net_id) = перші 10 символів MD5 від "ssid|gw_mac".
    Це дозволяє стабільно ідентифікувати мережу навіть при зміні IP.
    """

    @staticmethod
    def detect() -> dict:
        """
        Повертає словник:
          {net_id, ssid, gateway_ip, gateway_mac, display_name}
        Ніколи не кидає виняток — при помилці повертає legacy-профіль.
        """
        try:
            gw_ip  = NetworkDetector._get_gateway_ip()
            gw_mac = NetworkDetector._get_gateway_mac(gw_ip) if gw_ip else "unknown"
            ssid   = NetworkDetector._get_ssid()

            # Якщо не змогли визначити — legacy
            if not gw_ip and not ssid:
                return NetworkDetector._legacy()

            raw    = f"{ssid}|{gw_mac}".encode()
            net_id = hashlib.md5(raw).hexdigest()[:10]

            # Людська назва за замовчуванням
            if ssid and ssid != "Ethernet":
                display_name = f"📶  {ssid}"
            elif gw_ip:
                display_name = f"🔌  Ethernet ({gw_ip})"
            else:
                display_name = "🌐  Невідома мережа"

            return {
                "net_id":       net_id,
                "ssid":         ssid or "Ethernet",
                "gateway_ip":   gw_ip or "",
                "gateway_mac":  gw_mac or "unknown",
                "display_name": display_name,
            }
        except Exception:
            return NetworkDetector._legacy()

    @staticmethod
    def _legacy() -> dict:
        return {
            "net_id":       _LEGACY_NET_ID,
            "ssid":         "Невідома",
            "gateway_ip":   "",
            "gateway_mac":  "unknown",
            "display_name": "🌐  Невідома мережа",
        }

    # ── Gateway IP ────────────────────────────────────────────────────────────

    @staticmethod
    def _get_gateway_ip() -> str:
        """
        Знаходить gateway ФІЗИЧНОГО адаптера, ігноруючи VPN-інтерфейси.

        Раніше: брався перший gateway з ipconfig (часто це Radmin VPN з 26.x.x.x),
                що породжувало РІЗНІ net_id для однієї фізичної мережі.
        Тепер:  парсимо ipconfig посекціно, пропускаємо VPN-адаптери.
        """
        # ── Список VPN-адаптерів які треба ігнорувати ──
        VPN_KEYWORDS = [
            "radmin", "openvpn", "wireguard", "tap-",
            "tunnel", "tailscale", "zerotier", "vpn",
            "hamachi", "softether", "pia",
            "ppp", "l2tp", "pptp", "ikev2",
        ]

        # ── VPN-діапазони IP які треба ігнорувати ──
        def _is_vpn_ip(ip: str) -> bool:
            if not ip or ip == "0.0.0.0":
                return True
            # Radmin VPN: 26.x.x.x
            if ip.startswith("26."):
                return True
            # Hamachi: 25.x.x.x (Logmein range)
            if ip.startswith("25."):
                return True
            # ZeroTier: 28.x-31.x (хоча перетинається з public, рідко зустрічається)
            return False

        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["ipconfig"], text=True, encoding="cp866",
                    errors="replace", timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )

                # ── Розбиваємо вивід на секції ПО АДАПТЕРАХ ──
                # Кожна секція починається з рядка "Адаптер ..."
                # або "Adapter ..." з двокрапкою в кінці
                sections = re.split(
                    r"\n(?=\S.*[Аа]дап?тер|\S.*[Aa]dapter)",
                    "\n" + out
                )

                physical_gw = None
                any_gw      = None

                for section in sections:
                    # Перший рядок — назва адаптера
                    first_line = section.split("\n", 1)[0].lower()

                    is_vpn = any(kw in first_line for kw in VPN_KEYWORDS)

                    # Шукаємо gateway у цій секції
                    for line in section.splitlines():
                        m = re.search(
                            r"(?:Default Gateway|Основний шлюз|"
                            r"Шлюз по умолчанию|Основной шлюз)"
                            r"[^:]*:\s*([\d.]+)",
                            line, re.IGNORECASE,
                        )
                        if not m:
                            continue
                        gw = m.group(1)
                        if _is_vpn_ip(gw):
                            continue
                        if not gw or gw == "0.0.0.0":
                            continue

                        # Запам'ятовуємо будь-який gateway як резерв
                        if any_gw is None:
                            any_gw = gw

                        # Якщо адаптер НЕ VPN — це наш ціль
                        if not is_vpn:
                            physical_gw = gw
                            break

                    if physical_gw:
                        break

                if physical_gw:
                    return physical_gw
                if any_gw:
                    return any_gw
            else:
                out = subprocess.check_output(
                    ["ip", "route", "show", "default"],
                    text=True, timeout=5,
                )
                # Може бути кілька default routes — фільтруємо VPN-інтерфейси
                for line in out.splitlines():
                    m = re.match(
                        r"default via ([\d.]+) dev (\S+)", line
                    )
                    if not m:
                        continue
                    gw, iface = m.group(1), m.group(2).lower()
                    if _is_vpn_ip(gw):
                        continue
                    # Пропускаємо tun*, ppp*, tap* інтерфейси
                    if any(iface.startswith(p) for p in
                           ("tun", "tap", "ppp", "wg", "zt")):
                        continue
                    return gw

                # fallback - перший будь-який
                m = re.search(r"default via ([\d.]+)", out)
                if m and not _is_vpn_ip(m.group(1)):
                    return m.group(1)
        except Exception as e:
            print(f"[NetworkDetector] gateway error: {e}")

        # Запасний варіант — через socket
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            # Якщо local_ip це VPN — не довіряємо
            if _is_vpn_ip(local_ip):
                return ""
            parts = local_ip.rsplit(".", 1)
            return parts[0] + ".1"
        except Exception:
            return ""

    # ── Gateway MAC ───────────────────────────────────────────────────────────

    @staticmethod
    def _get_gateway_mac(gateway_ip: str) -> str:
        """Отримує MAC шлюзу з ARP-кешу."""
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["arp", "-a", gateway_ip],
                    text=True, encoding="cp866", errors="replace",
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                out = subprocess.check_output(
                    ["arp", "-n", gateway_ip],
                    text=True, timeout=5,
                )
            # MAC: формат xx-xx-xx-xx-xx-xx або xx:xx:xx:xx:xx:xx
            m = re.search(r"([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}", out)
            if m:
                return m.group(0).upper().replace("-", ":")
        except Exception:
            pass

        # Якщо ARP не спрацював — пінгуємо щоб заповнити кеш і пробуємо ще раз
        try:
            if IS_WINDOWS:
                subprocess.run(
                    ["ping", "-n", "1", "-w", "500", gateway_ip],
                    capture_output=True, timeout=3,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                subprocess.run(
                    ["ping", "-c", "1", "-W", "1", gateway_ip],
                    capture_output=True, timeout=3,
                )

            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["arp", "-a", gateway_ip],
                    text=True, encoding="cp866", errors="replace",
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            else:
                out = subprocess.check_output(
                    ["arp", "-n", gateway_ip],
                    text=True, timeout=5,
                )
            m = re.search(r"([\da-fA-F]{2}[:\-]){5}[\da-fA-F]{2}", out)
            if m:
                return m.group(0).upper().replace("-", ":")
        except Exception:
            pass

        return "unknown"

    # ── SSID ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _get_ssid() -> str:
        """Повертає назву Wi-Fi мережі або порожній рядок (Ethernet)."""
        try:
            if IS_WINDOWS:
                out = subprocess.check_output(
                    ["netsh", "wlan", "show", "interfaces"],
                    text=True, encoding="cp866", errors="replace",
                    timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
                m = re.search(r"^\s+SSID\s+:\s+(.+)$", out, re.MULTILINE)
                if m:
                    ssid = m.group(1).strip()
                    if ssid:
                        return ssid
            else:
                # Пробуємо nmcli, потім iwgetid
                for cmd in [
                    ["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"],
                    ["iwgetid", "-r"],
                ]:
                    try:
                        out = subprocess.check_output(
                            cmd, text=True, timeout=3,
                        )
                        if "yes:" in out:
                            m = re.search(r"yes:(.+)", out)
                            if m: return m.group(1).strip()
                        elif out.strip():
                            return out.strip().splitlines()[0]
                    except Exception:
                        continue
        except Exception:
            pass
        return ""   # Порожній рядок = Ethernet або Wi-Fi не визначено


# ═════════════════════════════════════════════════════════════════════════════
#  DB HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def _ensure_schema(conn: sqlite3.Connection):
    """
    Створює/мігрує схему БД.
    Безпечно — не видаляє існуючі дані.
    """
    c = conn.cursor()

    # ── Таблиця мереж ─────────────────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS networks (
            net_id       TEXT PRIMARY KEY,
            ssid         TEXT DEFAULT '',
            gateway_ip   TEXT DEFAULT '',
            gateway_mac  TEXT DEFAULT 'unknown',
            display_name TEXT DEFAULT '',
            first_seen   TEXT DEFAULT '',
            last_seen    TEXT DEFAULT '',
            measurement_count INTEGER DEFAULT 0
        )
    """)

    # ── Таблиця пінгів (ping_log) ─────────────────────────────────────────────
    c.execute("""
        CREATE TABLE IF NOT EXISTS ping_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            ts         TEXT    DEFAULT (datetime('now','localtime')),
            ping_ms    REAL,
            jitter_ms  REAL,
            loss_pct   REAL,
            hour       INTEGER,
            weekday    INTEGER,
            net_id     TEXT    DEFAULT 'legacy'
        )
    """)

    # ── Міграція: додаємо net_id якщо ще немає ───────────────────────────────
    existing_cols = {row[1] for row in c.execute("PRAGMA table_info(ping_log)")}
    if "net_id" not in existing_cols:
        c.execute("ALTER TABLE ping_log ADD COLUMN net_id TEXT DEFAULT 'legacy'")
        # Всі старі записи відносимо до legacy-мережі
        c.execute("UPDATE ping_log SET net_id = 'legacy' WHERE net_id IS NULL")

        # Реєструємо legacy-мережу
        c.execute("""
            INSERT OR IGNORE INTO networks
                (net_id, ssid, display_name, first_seen, last_seen)
            VALUES ('legacy', 'Архів (до v3)', '🗂️  Архів (до v3)',
                    datetime('now','localtime'), datetime('now','localtime'))
        """)

    if "loss_pct" not in existing_cols:
        c.execute("ALTER TABLE ping_log ADD COLUMN loss_pct REAL")
    if "jitter_ms" not in existing_cols:
        c.execute("ALTER TABLE ping_log ADD COLUMN jitter_ms REAL")

    conn.commit()


def _upsert_network(conn: sqlite3.Connection, info: dict):
    """Реєструє або оновлює запис про мережу."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c   = conn.cursor()
    c.execute("""
        INSERT INTO networks (net_id, ssid, gateway_ip, gateway_mac,
                              display_name, first_seen, last_seen)
        VALUES (:net_id, :ssid, :gateway_ip, :gateway_mac,
                :display_name, :now, :now)
        ON CONFLICT(net_id) DO UPDATE SET
            last_seen    = :now,
            gateway_ip   = :gateway_ip,
            ssid         = :ssid
    """, {**info, "now": now})
    conn.commit()


# ═════════════════════════════════════════════════════════════════════════════
#  LOW-LEVEL NETWORK UTILS
# ═════════════════════════════════════════════════════════════════════════════

def _icmp_ping(host: str, count: int = 4,
               timeout_ms: int = 2000) -> tuple[float, float, float]:
    try:
        if IS_WINDOWS:
            cmd      = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
            encoding = "cp866"
        else:
            cmd      = ["ping", "-c", str(count), "-W",
                        str(timeout_ms // 1000 or 1), host]
            encoding = "utf-8"

        r   = subprocess.run(cmd, capture_output=True, text=True,
                             encoding=encoding, errors="replace",
                             timeout=count * 3,
                             creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                             if IS_WINDOWS else 0)
        out = r.stdout + r.stderr

        rtt_values = []
        if IS_WINDOWS:
            for m in re.finditer(
                r"(?:время|time)[=<]\s*(\d+)\s*(?:мс|ms)", out, re.IGNORECASE
            ):
                rtt_values.append(float(m.group(1)))
        else:
            for m in re.finditer(r"time[=<]\s*([\d.]+)\s*ms", out):
                rtt_values.append(float(m.group(1)))

        if not rtt_values:
            return -1.0, 0.0, 100.0

        avg_ms    = statistics.mean(rtt_values)
        jitter_ms = statistics.stdev(rtt_values) if len(rtt_values) > 1 else 0.0

        loss_pct = 0.0
        loss_m   = re.search(r"(\d+)\s*%\s*(?:loss|потер|втрат)", out, re.IGNORECASE)
        if loss_m:
            loss_pct = float(loss_m.group(1))
        elif r.returncode != 0:
            loss_pct = 100.0

        return round(avg_ms, 1), round(jitter_ms, 1), round(loss_pct, 1)

    except subprocess.TimeoutExpired:
        return -1.0, 0.0, 100.0
    except Exception:
        return -1.0, 0.0, 100.0


def _tcp_ping(host: str, port: int, timeout: float = 1.5) -> float:
    """
    Виконує TCP-handshake до host:port і повертає затримку в мс.
    Якщо host — це доменне ім'я, спочатку резолвить у IP.
    Робить до 2 спроб (важливо для нестабільних сервісів).
    Повертає -1.0 якщо обидві спроби провалились.
    """
    # Resolve hostname → IP (на випадок якщо DNS повільний)
    try:
        target_ip = socket.gethostbyname(host)
    except Exception:
        return -1.0

    best_ms = -1.0
    for attempt in range(2):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.connect((target_ip, port))
            elapsed = (time.perf_counter() - t0) * 1000
            s.close()
            if best_ms < 0 or elapsed < best_ms:
                best_ms = elapsed
            return round(best_ms, 1)
        except Exception:
            try: s.close()
            except: pass
            if attempt == 0:
                time.sleep(0.2)
                continue
            return best_ms


def _measure_nominal_speed_mbps() -> float:
    PAYLOAD_SIZE = 32_768
    try:
        start = time.perf_counter()
        with socket.create_connection(("1.1.1.1", 443), timeout=3) as s:
            s.sendall(b"X" * PAYLOAD_SIZE)
        elapsed = time.perf_counter() - start
        if elapsed > 0:
            return round(min((PAYLOAD_SIZE * 8) / (elapsed * 1_000_000), 1000.0), 1)
    except Exception:
        pass
    return 0.0


# ═════════════════════════════════════════════════════════════════════════════
#  FORECAST ENGINE  (per-network)
# ═════════════════════════════════════════════════════════════════════════════

class ForecastEngine:
    """
    Рушій «Прогнозу погоди» мережі.

    ІЗОЛЯЦІЯ ДАНИХ:
    ─────────────────────────────────────────────────────
    Кожна мережа (за SSID + MAC шлюзу) отримує унікальний net_id.
    Всі вимірювання зберігаються з цим net_id.
    analyze_history() повертає статистику лише для поточної мережі.

    ЗМІНА МЕРЕЖІ:
    ─────────────────────────────────────────────────────
    При виклику switch_network(net_id) або detect_network()
    рушій перемикається на іншу мережу без перезапуску.
    """

    MEASURE_HOSTS = ["8.8.8.8", "1.1.1.1", "146.66.156.1"]

    def __init__(self, db_path: Optional[str] = None,
                 auto_detect: bool = True):
        # ── БД ───────────────────────────────────────────────────────────────
        # ВАЖЛИВО: ForecastEngine використовує СВОЮ ВЛАСНУ БД
        # (~/.netguardian/forecast.db), щоб не конфліктувати з
        # app/core/database.py який має інший формат таблиці ping_log
        # (з колонкою timestamp замість ts).
        if db_path:
            self.db_path = db_path
        else:
            p = Path.home() / ".netguardian"
            p.mkdir(parents=True, exist_ok=True)
            self.db_path = str(p / "forecast.db")

        # Ініціалізуємо схему
        with sqlite3.connect(self.db_path, timeout=5) as conn:
            _ensure_schema(conn)

        # ── Поточна мережа ────────────────────────────────────────────────────
        self._net_info: dict = NetworkDetector._legacy()
        if auto_detect:
            self.detect_network()

        # ── Кеш сервісів ─────────────────────────────────────────────────────
        self._service_cache: list[ServiceStatus] = []
        self._cache_ts:  float = 0.0
        self._cache_ttl: float = 60.0

        # ── Авто-вимір у фоні (працює навіть коли користувач НЕ на сторінці Forecast)
        # Це вирішує проблему "вночі дані не пишуться" — раніше виміри
        # робились тільки коли користувач відкривав сторінку Forecast.
        # Тепер — постійно, поки запущена програма.
        self._auto_measure_thread: Optional[threading.Thread] = None
        self._auto_measure_stop: threading.Event = threading.Event()
        self._auto_measure_interval: int = 300  # 5 хв

    def start_continuous_measurement(self, interval_seconds: int = 300):
        """
        Запускає фоновий потік, який кожні N секунд робить вимір і пише в БД.
        Дозволяє накопичувати дані ВЕСЬ ЧАС роботи програми, навіть коли
        користувач не на сторінці Forecast.
        Безпечно викликати кілька разів — старий потік буде зупинено.
        """
        # Зупиняємо попередній потік (якщо був)
        self.stop_continuous_measurement()

        self._auto_measure_interval = max(60, interval_seconds)
        self._auto_measure_stop.clear()

        def loop():
            # Перший вимір — одразу
            try:
                self.measure_current()
            except Exception:
                pass
            while not self._auto_measure_stop.is_set():
                # Чекаємо інтервал (з можливістю переривання)
                if self._auto_measure_stop.wait(self._auto_measure_interval):
                    break
                try:
                    self.measure_current()
                except Exception:
                    pass

        self._auto_measure_thread = threading.Thread(
            target=loop, daemon=True, name="ForecastAutoMeasure"
        )
        self._auto_measure_thread.start()

    def stop_continuous_measurement(self):
        """Зупиняє фоновий потік вимірювань."""
        self._auto_measure_stop.set()
        if self._auto_measure_thread and self._auto_measure_thread.is_alive():
            self._auto_measure_thread.join(timeout=2)
        self._auto_measure_thread = None

    # ── Доступ до поточної мережі ──────────────────────────────────────────────

    @property
    def net_id(self) -> str:
        return self._net_info["net_id"]

    @property
    def display_name(self) -> str:
        return self._net_info["display_name"]

    # ─────────────────────────────────────────────────────────────────────────
    #  NETWORK MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────────

    def detect_network(self) -> dict:
        """
        Визначає поточну мережу і реєструє її в БД.
        Повертає net_info dict.
        Можна викликати повторно при зміні мережі.
        """
        info = NetworkDetector.detect()
        self._net_info = info
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                _ensure_schema(conn)
                _upsert_network(conn, info)
                # Підтягуємо збережену display_name (якщо користувач перейменував)
                c = conn.cursor()
                c.execute(
                    "SELECT display_name FROM networks WHERE net_id = ?",
                    (info["net_id"],),
                )
                row = c.fetchone()
                if row and row[0] and row[0] != info["display_name"]:
                    # Є кастомна назва — використовуємо її
                    self._net_info["display_name"] = row[0]
        except Exception:
            pass
        return self._net_info

    def switch_network(self, net_id: str) -> bool:
        """
        Вручну переключитись на іншу мережу зі списку відомих.
        Використовується в UI для перегляду статистики іншої мережі.
        """
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute("SELECT * FROM networks WHERE net_id = ?", (net_id,))
                row = c.fetchone()
                if not row:
                    return False
                cols = [d[0] for d in c.description]
                data = dict(zip(cols, row))
                self._net_info = {
                    "net_id":       data["net_id"],
                    "ssid":         data["ssid"],
                    "gateway_ip":   data["gateway_ip"],
                    "gateway_mac":  data["gateway_mac"],
                    "display_name": data["display_name"],
                }
            return True
        except Exception:
            return False

    def get_all_networks(self) -> list[NetworkProfile]:
        """Повертає всі відомі мережі з кількістю вимірювань."""
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                _ensure_schema(conn)
                c = conn.cursor()
                c.execute("""
                    SELECT n.net_id, n.ssid, n.gateway_ip, n.gateway_mac,
                           n.display_name, n.first_seen, n.last_seen,
                           COUNT(p.id) AS cnt
                    FROM networks n
                    LEFT JOIN ping_log p ON p.net_id = n.net_id
                    GROUP BY n.net_id
                    ORDER BY cnt DESC
                """)
                result = []
                for row in c.fetchall():
                    result.append(NetworkProfile(
                        net_id=row[0], ssid=row[1],
                        gateway_ip=row[2], gateway_mac=row[3],
                        display_name=row[4] or row[1],
                        first_seen=row[5], last_seen=row[6],
                        measurement_count=row[7],
                    ))
                return result
        except Exception:
            return []

    def rename_network(self, net_id: str, new_name: str) -> bool:
        """Змінює дружню назву мережі. Повертає True при успіху."""
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                conn.execute(
                    "UPDATE networks SET display_name = ? WHERE net_id = ?",
                    (new_name.strip(), net_id),
                )
                conn.commit()
            # Якщо перейменовуємо поточну — оновлюємо і в пам'яті
            if net_id == self.net_id:
                self._net_info["display_name"] = new_name.strip()
            return True
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    #  MEASURE CURRENT  (зберігає з net_id)
    # ─────────────────────────────────────────────────────────────────────────

    def measure_current(self) -> WeatherCondition:
        """Вимірює поточний стан мережі і зберігає в БД з net_id."""
        pings, jitters, losses = [], [], []

        for host in self.MEASURE_HOSTS:
            avg, jit, loss = _icmp_ping(host, count=4)
            if avg > 0:
                pings.append(avg)
                jitters.append(jit)
                losses.append(loss)

        if not pings:
            cond = WeatherCondition(
                ping_ms=999, jitter_ms=0, packet_loss=100.0,
                weather_index=100, code="blackout",
                icon=BLACKOUT_ICON, title=BLACKOUT_TITLE,
                desc=BLACKOUT_DESC, color=BLACKOUT_COLOR,
                net_id=self.net_id, display_name=self.display_name,
            )
            self._save_measurement(-1, 0, 100.0)
            return cond

        avg_ping   = round(statistics.mean(pings),   1)
        avg_jitter = round(statistics.mean(jitters),  1)
        avg_loss   = round(statistics.mean(losses),   1)

        nominal   = _measure_nominal_speed_mbps()
        perceived = self._calc_perceived_speed(nominal, avg_ping, avg_jitter, avg_loss)

        code, icon, title, desc, color = self._classify_weather(
            avg_ping, avg_jitter, avg_loss
        )
        index = self._calc_weather_index(avg_ping, avg_jitter, avg_loss)

        self._save_measurement(avg_ping, avg_jitter, avg_loss)

        return WeatherCondition(
            ping_ms=avg_ping, jitter_ms=avg_jitter, packet_loss=avg_loss,
            weather_index=index,
            code=code, icon=icon, title=title, desc=desc, color=color,
            perceived_mbps=perceived, nominal_mbps=nominal,
            net_id=self.net_id, display_name=self.display_name,
        )

    def _save_measurement(self, ping: float, jitter: float, loss: float):
        """Зберігає вимір в ping_log з прив'язкою до net_id."""
        now  = datetime.now()
        hour = now.hour
        wday = now.weekday()
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                _ensure_schema(conn)
                conn.execute(
                    """
                    INSERT INTO ping_log (ts, ping_ms, jitter_ms, loss_pct,
                                         hour, weekday, net_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (now.strftime("%Y-%m-%d %H:%M:%S"),
                     ping, jitter, loss, hour, wday, self.net_id),
                )
                conn.execute(
                    """
                    UPDATE networks
                    SET last_seen = ?, measurement_count = measurement_count + 1
                    WHERE net_id = ?
                    """,
                    (now.strftime("%Y-%m-%d %H:%M:%S"), self.net_id),
                )
        except Exception:
            pass

    # ─────────────────────────────────────────────────────────────────────────
    #  CLASSIFY / INDEX
    # ─────────────────────────────────────────────────────────────────────────

    def _classify_weather(self, ping, jitter, loss):
        """Визначає погоду на основі ping/jitter/loss.

        Логіка v2: гібридна — стан обирається за НАЙГІРШИМ з трьох метрик.
        Раніше: AND-логіка змушувала погіршити стан якщо хоч одна метрика
        не вписувалась у "найкращий" рівень. Це призводило до парадоксу
        "Вітряно при якості 90%" — коли ping/loss відмінні, але jitter
        трохи вищий.
        """
        if loss >= BLACKOUT_THRESHOLD_LOSS:
            return ("blackout", BLACKOUT_ICON, BLACKOUT_TITLE,
                    BLACKOUT_DESC, BLACKOUT_COLOR)

        # Окремо рахуємо який "рівень" відповідає кожна метрика
        def _level_for(value, thresholds):
            """Повертає індекс найменшого threshold який ≥ value."""
            for i, t in enumerate(thresholds):
                if value <= t:
                    return i
            return len(thresholds)

        ping_levels   = [20, 50, 80, 120, 200, 999]
        jitter_levels = [5, 15, 30, 50, 80, 999]
        loss_levels   = [0.0, 0.5, 1.0, 2.0, 5.0, 15.0]

        ping_lvl   = _level_for(ping,   ping_levels)
        jitter_lvl = _level_for(jitter, jitter_levels)
        loss_lvl   = _level_for(loss,   loss_levels)

        # ВАЖЛИВО: jitter сам по собі не може зіпсувати погоду більше
        # ніж на 1 рівень якщо ping та loss добрі.
        # Якщо ping=0 та loss=0 — jitter впливає максимум до cloudy.
        primary_lvl = max(ping_lvl, loss_lvl)

        # jitter додає до 1 рівня тільки якщо він серйозно гіршій
        if jitter_lvl > primary_lvl + 1:
            final_lvl = primary_lvl + 1
        else:
            final_lvl = max(primary_lvl, jitter_lvl - 1) if jitter_lvl > 0 else primary_lvl
            final_lvl = max(primary_lvl, final_lvl)

        final_lvl = min(final_lvl, len(WEATHER_THRESHOLDS) - 1)

        t = WEATHER_THRESHOLDS[final_lvl]
        # t = (p_max, j_max, l_max, code, icon, title, desc, color)
        return t[3], t[4], t[5], t[6], t[7]

    def _calc_weather_index(self, ping, jitter, loss) -> int:
        ping_score   = min(100, (ping   / 200) * 100)
        jitter_score = min(100, (jitter / 100) * 100)
        loss_score   = min(100, (loss   /  20) * 100)
        return max(0, min(100, int(
            ping_score * 0.4 + jitter_score * 0.3 + loss_score * 0.3
        )))

    def _calc_perceived_speed(self, nominal, ping, jitter, loss) -> float:
        if nominal <= 0: return 0.0
        k_ping   = max(0.1, 1.0 - (ping - 20) / 500) if ping > 20 else 1.0
        k_jitter = max(0.2, 1.0 - (jitter / 200))
        k_loss   = max(0.05, 1.0 - (loss / 100) ** 0.5) if loss > 0 else 1.0
        return round(max(0.1, nominal * k_ping * k_jitter * k_loss), 1)

    # ─────────────────────────────────────────────────────────────────────────
    #  CHECK SERVICES
    # ─────────────────────────────────────────────────────────────────────────

    def check_services(self, force: bool = False) -> list[ServiceStatus]:
        now = time.time()
        if not force and self._service_cache and \
                (now - self._cache_ts) < self._cache_ttl:
            return self._service_cache

        results: list[ServiceStatus] = []
        lock = threading.Lock()

        def check_one(svc: ServiceStatus):
            # Спочатку — TCP-ping на порт 443
            ms = _tcp_ping(svc.host, svc.port, timeout=2.5)

            # FALLBACK: якщо TCP заблоковано/таймаут (часто буває з 8.8.8.8),
            # пробуємо ICMP. Це дає рівніший статус для серверів,
            # які фільтрують вхідні TCP, але відповідають на ICMP.
            if ms < 0:
                try:
                    target_ip = socket.gethostbyname(svc.host)
                    icmp_ms, _, _ = _icmp_ping(target_ip, count=2, timeout_ms=1500)
                    if icmp_ms > 0:
                        ms = icmp_ms
                except Exception:
                    pass

            svc.ping_ms = ms
            svc.is_up   = ms > 0
            svc.icon    = (
                "🟢" if ms > 0 and ms < 50  else
                "🟡" if ms > 0 and ms < 150 else
                "🟠" if ms > 0              else
                "🔴"
            )
            with lock:
                results.append(svc)

        import copy
        services_copy = [copy.copy(s) for s in MONITORED_SERVICES]
        threads = [threading.Thread(target=check_one, args=(s,), daemon=True)
                   for s in services_copy]
        for t in threads: t.start()
        for t in threads: t.join(timeout=4)

        results.sort(key=lambda s: (s.is_up, s.ping_ms if s.is_up else 0))
        self._service_cache = results
        self._cache_ts = now
        return results

    def get_gaming_alert(self, services: list[ServiceStatus]) -> Optional[str]:
        gaming = [s for s in services if s.category == "gaming" and not s.is_up]
        if not gaming:
            return None
        names = ", ".join(s.name for s in gaming)
        return (
            f"⚠️ Проблеми з ігровими серверами: {names}.\n"
            f"Можливі затримки підключення."
        )

    # ─────────────────────────────────────────────────────────────────────────
    #  ANALYZE HISTORY  (лише для поточного net_id)
    # ─────────────────────────────────────────────────────────────────────────

    def get_today_hourly_data(self) -> dict[int, float]:
        """ФІКС #3: Повертає погодинні дані ТІЛЬКИ за сьогоднішню добу
        (з 00:00 до зараз), а не агрегацію за всі дні. Це усуває ефект
        «графік дивиться у майбутнє».

        Раніше: hourly_data з analyze_history() агрегував усі сім днів,
                тому видно було значення для 22:00 о 18:00 — як «передбачення».
        Тепер:  чітко тільки нинішня доба, заповнюється поступово.
        """
        today = datetime.now().strftime("%Y-%m-%d")
        result: dict[int, float] = {}
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ?
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                """, (today, self.net_id))
                for hr, avg, cnt in c.fetchall():
                    if cnt >= 1:  # навіть 1 виміру достатньо для сьогодні
                        result[int(hr)] = round(avg, 1)
        except Exception as e:
            print(f"[ForecastEngine] get_today_hourly_data error: {e}")
        return result

    def get_yesterday_hourly_data(self) -> dict[int, float]:
        """PR #9: Повертає погодинні дані за ВЧОРАШНІЙ день.

        Використовується як «прогнозне ехо» — показує користувачу що було
        в цей час доби 24 години тому. Допомагає прогнозувати проблеми
        провайдера які повторюються (наприклад, перевантаження вечорами).
        """
        yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        result: dict[int, float] = {}
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ?
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    HAVING COUNT(*) >= 3
                """, (yesterday, self.net_id))
                for hr, avg, cnt in c.fetchall():
                    result[int(hr)] = round(avg, 1)
        except Exception as e:
            print(f"[ForecastEngine] get_yesterday_hourly_data error: {e}")
        return result

    def get_day_summary(self, date_str: str) -> Optional[dict]:
        """ФІКС #6: Повертає детальну статистику за конкретну дату.
        Використовується для клікабельної історії погоди (Розділ "Минулі дні").

        date_str: 'YYYY-MM-DD'
        Повертає dict з ping/jitter/loss/best_hour/services або None.
        """
        result = {
            "date":    date_str,
            "network": self.display_name,
        }
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()

                # Базова статистика
                c.execute("""
                    SELECT AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                           AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ? AND ping_ms > 0 AND net_id = ?
                """, (date_str, self.net_id))
                row = c.fetchone()
                if not row or not row[0]:
                    return None

                result["avg_ping"]   = round(row[0], 1)
                result["min_ping"]   = round(row[1], 1)
                result["max_ping"]   = round(row[2], 1)
                result["avg_jitter"] = round(row[3] or 0, 1)
                result["avg_loss"]   = round(row[4] or 0, 2)
                result["samples"]    = row[5]

                # Блекаути
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE date(ts) = ? AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (date_str, self.net_id))
                result["blackouts"] = c.fetchone()[0]

                # Найкраща година
                c.execute("""
                    SELECT hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = ? AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) ASC LIMIT 5
                """, (date_str, self.net_id))
                best_hours = []
                for hr, avg, cnt in c.fetchall():
                    if cnt >= 3:
                        best_hours.append((int(hr), round(avg, 1)))
                result["best_hours"] = best_hours

                # Найгірша година
                c.execute("""
                    SELECT hour, AVG(ping_ms), MAX(ping_ms)
                    FROM ping_log
                    WHERE date(ts) = ? AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) DESC LIMIT 3
                """, (date_str, self.net_id))
                worst_hours = []
                for hr, avg, mx in c.fetchall():
                    worst_hours.append((int(hr), round(avg, 1), round(mx, 1)))
                result["worst_hours"] = worst_hours

                # Категорії - найкращі години
                def best_for(max_ping, max_loss):
                    c.execute("""
                        SELECT hour, AVG(ping_ms), AVG(loss_pct)
                        FROM ping_log
                        WHERE date(ts) = ? AND ping_ms > 0 AND net_id = ?
                        GROUP BY hour
                        HAVING AVG(ping_ms) <= ?
                           AND (AVG(loss_pct) IS NULL OR AVG(loss_pct) <= ?)
                        ORDER BY AVG(ping_ms) ASC LIMIT 3
                    """, (date_str, self.net_id, max_ping, max_loss))
                    return [int(r[0]) for r in c.fetchall()]

                result["best_for_gaming"]    = best_for(50,  2.0)
                result["best_for_streaming"] = best_for(80,  1.0)
                result["best_for_work"]      = best_for(150, 5.0)

                # Погодинні дані для mini-chart
                c.execute("""
                    SELECT hour, AVG(ping_ms)
                    FROM ping_log
                    WHERE date(ts) = ? AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                """, (date_str, self.net_id))
                hourly = {int(r[0]): round(r[1], 1) for r in c.fetchall()}
                result["hourly"] = hourly
        except Exception as e:
            print(f"[ForecastEngine] get_day_summary error: {e}")
            return None

        return result

    def analyze_history(self) -> HistoricalAnalysis:
        """
        Аналізує ping_log за останні 7 днів ЛИШЕ для поточної мережі (net_id).
        Дані інших мереж повністю ізольовані.
        """
        result = HistoricalAnalysis(
            net_id=self.net_id,
            display_name=self.display_name,
        )
        net = self.net_id

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                _ensure_schema(conn)
                c = conn.cursor()

                # Глобальний середній пінг для цієї мережі
                c.execute(
                    "SELECT AVG(ping_ms), COUNT(*) FROM ping_log "
                    "WHERE ping_ms > 0 AND net_id = ?",
                    (net,),
                )
                row        = c.fetchone()
                global_avg = row[0] if row and row[0] else 0.0
                total      = row[1] if row else 0

                if global_avg == 0 or total == 0:
                    result.status = "no_data"
                    return result

                result.global_avg = round(global_avg, 1)

                # Погодинний патерн
                c.execute(
                    """
                    SELECT hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    """,
                    (net,),
                )
                hourly_data: dict[int, float] = {}
                for hr, avg, cnt in c.fetchall():
                    if cnt >= 3:
                        hourly_data[int(hr)] = round(avg, 1)
                result.hourly_data = hourly_data

                # Тижневий патерн — ТІЛЬКИ ПОТОЧНИЙ КАЛЕНДАРНИЙ ТИЖДЕНЬ (Пн → Нд)
                # Логіка: знаходимо понеділок цього тижня → беремо все з тих пір.
                # Коли настає новий понеділок — heatmap починається з нуля.
                # Це усуває "вангування" майбутніх днів тижня.
                today = datetime.now()
                monday = today - timedelta(days=today.weekday())
                monday_str = monday.strftime("%Y-%m-%d 00:00:00")

                c.execute(
                    """
                    SELECT weekday, hour, AVG(ping_ms), COUNT(*)
                    FROM ping_log
                    WHERE ping_ms > 0 AND net_id = ?
                      AND ts >= ?
                    GROUP BY weekday, hour
                    """,
                    (net, monday_str),
                )
                weekly_data: dict[int, dict[int, float]] = {}
                for wday, hr, avg, cnt in c.fetchall():
                    if cnt >= 1:
                        weekly_data.setdefault(int(wday), {})[int(hr)] = round(avg, 1)
                result.weekly_data = weekly_data

                # Втрата пакетів
                c.execute(
                    "SELECT COUNT(*) FROM ping_log "
                    "WHERE (ping_ms < 0 OR ping_ms IS NULL) AND net_id = ?",
                    (net,),
                )
                loss_count = c.fetchone()[0]
                result.packet_loss_pct = round(loss_count / total * 100, 2)

                # Аномалії
                c.execute(
                    "SELECT COUNT(*) FROM ping_log "
                    "WHERE ping_ms > ? AND net_id = ?",
                    (global_avg * 3, net),
                )
                result.anomalies_count = c.fetchone()[0]

                # SLA
                try:
                    c.execute(
                        """
                        SELECT COUNT(*) FROM ping_log
                        WHERE ping_ms > 0 AND ping_ms < ?
                          AND (loss_pct IS NULL OR loss_pct < ?)
                          AND net_id = ?
                        """,
                        (SLA_PING_THRESHOLD, SLA_LOSS_THRESHOLD, net),
                    )
                except sqlite3.OperationalError:
                    c.execute(
                        "SELECT COUNT(*) FROM ping_log "
                        "WHERE ping_ms > 0 AND ping_ms < ? AND net_id = ?",
                        (SLA_PING_THRESHOLD, net),
                    )
                good_count     = c.fetchone()[0]
                result.sla_pct = round((good_count / total) * 100, 2) if total else 0.0

            # Пост-обробка (без БД)
            result.cyclone_hours = [
                h for h, v in hourly_data.items() if v > global_avg * 1.5
            ]

            now_hour = time.localtime().tm_hour
            result.current_avg = hourly_data.get(now_hour, global_avg)

            risk = int((result.current_avg / global_avg - 1) * 100) \
                if result.current_avg and global_avg else 0
            risk = max(0, min(100, risk))
            if result.anomalies_count:
                risk = min(100, risk + result.anomalies_count)
            result.risk_pct = risk

            valid = [(h, v) for h, v in hourly_data.items() if v is not None]
            if valid:
                result.best_hour  = min(valid, key=lambda x: x[1])
                result.worst_hour = max(valid, key=lambda x: x[1])

            result.forecast_days = self._build_weekly_forecast(weekly_data, global_avg)
            result.status = "ok"
            return result

        except Exception as e:
            result.status    = "error"
            result.error_msg = str(e)
            return result

    def _build_weekly_forecast(self, weekly_data: dict,
                                global_avg: float) -> list[ForecastDay]:
        """Завжди Пн(0)–Нд(6)."""
        days = []
        for wd in range(7):
            day_hours = weekly_data.get(wd, {})
            day_name  = DAY_NAMES[wd]

            if not day_hours:
                days.append(ForecastDay(
                    weekday=wd, day_name=day_name,
                    icon="❓", code="unknown",
                    avg_ping=0.0, risk_pct=0,
                    best_hour=0, worst_hour=0,
                ))
                continue

            vals      = list(day_hours.values())
            avg       = statistics.mean(vals)
            bad_hours = sum(1 for v in vals if v > global_avg * 1.5)
            risk_pct  = int(bad_hours / len(vals) * 100) if vals else 0

            code, icon, *_ = self._classify_weather(avg, avg * 0.3, 0.0)
            best  = min(day_hours.items(), key=lambda x: x[1])
            worst = max(day_hours.items(), key=lambda x: x[1])

            days.append(ForecastDay(
                weekday=wd, day_name=day_name,
                icon=icon, code=code,
                avg_ping=round(avg, 1), risk_pct=risk_pct,
                best_hour=best[0], worst_hour=worst[0],
            ))

        return days

    # ─────────────────────────────────────────────────────────────────────────
    #  THROTTLING
    # ─────────────────────────────────────────────────────────────────────────

    def check_throttling(self) -> dict:
        ua_candidates = [
            ("8.8.4.4",         443),
            ("77.88.8.8",       443),
            ("194.67.7.7",       53),
            ("213.180.193.3",    80),
            ("1.1.1.1",         443),
        ]
        eu_candidates = [
            ("9.9.9.9",         443),
            ("149.112.112.112", 443),
            ("208.67.222.222",  443),
            ("64.6.64.6",       443),
            ("185.228.168.9",   443),
        ]

        def measure_group(candidates):
            details, results = [], []
            for host, port in candidates:
                ms = _tcp_ping(host, port, timeout=3.0)
                details.append({"host": host, "port": port, "ms": ms, "is_up": ms > 0})
                if ms > 0:
                    results.append(ms)
            avg = round(statistics.mean(results), 1) if results else -1.0
            return avg, details

        ua_avg, ua_details = measure_group(ua_candidates)
        eu_avg, eu_details = measure_group(eu_candidates)

        if ua_avg <= 0:
            fallback = [
                ("195.46.39.39",    443),
                ("176.103.130.130", 443),
                ("8.26.56.26",      443),
            ]
            ua_avg, ua_details = measure_group(fallback)

        if ua_avg <= 0 or eu_avg <= 0:
            ua_ok = [d for d in ua_details if d["is_up"]]
            eu_ok = [d for d in eu_details if d["is_up"]]
            msg = "Не вдалося виміряти пінг:\n"
            if not ua_ok: msg += "• UA/Local хости: всі недоступні\n"
            if not eu_ok: msg += "• EU/Global хости: всі недоступні\n"
            msg += "Можливо firewall або відсутній інтернет."
            return {"success": False, "msg": msg,
                    "ua_details": ua_details, "eu_details": eu_details}

        ratio        = round(eu_avg / ua_avg, 2)
        is_throttled = ratio > 3.0 and eu_avg > 120

        if ratio > 5.0:
            level, desc = "severe",   "Жорсткий throttling — EU трафік критично обмежено"
        elif ratio > 3.0:
            level, desc = "moderate", "Помірний throttling — EU трафік уповільнено"
        elif ratio > 2.0:
            level, desc = "mild",     "Слабкі ознаки throttling або природна різниця"
        else:
            level, desc = "none",     "Різниця в нормі — throttling не виявлено"

        trace = self._quick_traceroute("8.8.8.8", max_hops=8)

        return {
            "success":        True,
            "ua_ms":          ua_avg,
            "eu_ms":          eu_avg,
            "ratio":          ratio,
            "is_throttled":   is_throttled,
            "throttle_level": level,
            "throttle_desc":  desc,
            "ua_details":     ua_details,
            "eu_details":     eu_details,
            "trace":          trace,
        }

    def _quick_traceroute(self, host: str, max_hops: int = 8) -> list[dict]:
        """Швидкий traceroute (НЕ потребує адмін-прав).

        Підтримує локалізації Windows tracert (укр/рос/англ) і Linux traceroute.
        """
        try:
            if IS_WINDOWS:
                cmd      = ["tracert", "-d", "-h", str(max_hops), "-w", "1000", host]
                # Спочатку пробуємо OEM (cp866) для українського/російського
                encodings_to_try = ["cp866", "cp1251", "utf-8"]
            else:
                cmd      = ["traceroute", "-n", "-m", str(max_hops), "-w", "1", host]
                encodings_to_try = ["utf-8"]

            r = None
            for enc in encodings_to_try:
                try:
                    r = subprocess.run(
                        cmd, capture_output=True, text=True,
                        encoding=enc, errors="replace",
                        timeout=max_hops * 3,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                        if IS_WINDOWS else 0
                    )
                    if r.stdout and len(r.stdout) > 50:
                        break
                except Exception:
                    continue

            if not r:
                return []

            out = r.stdout
            hops = []

            if IS_WINDOWS:
                # Універсальний парсер для tracert (працює з ms/мс/мс<1):
                # формат: "  1     1 ms     1 ms     1 ms  192.168.0.1"
                # або     "  2     *        *        *     Превышение..."
                # шукаємо: hop_num + 3 значення (числа або *) + IP в кінці
                for line in out.split("\n"):
                    line = line.strip()
                    if not line or not line[0].isdigit():
                        continue

                    # Шукаємо число у початку (hop)
                    m_hop = re.match(r"^\s*(\d+)\b", line)
                    if not m_hop:
                        continue
                    hop_n = int(m_hop.group(1))

                    # Шукаємо IPv4 у кінці рядка
                    m_ip = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if not m_ip:
                        continue
                    ip = m_ip.group(1)

                    # Шукаємо перше число пінгу (мс)
                    m_ms = re.search(r"(\d+)\s*(?:ms|мс)", line, re.IGNORECASE)
                    if m_ms:
                        ms = float(m_ms.group(1))
                    elif "<1" in line:
                        ms = 0.5
                    else:
                        # Усі три зірочки — пропускаємо
                        continue

                    hops.append({"hop": hop_n, "ip": ip, "ms": ms})
            else:
                for m in re.finditer(
                    r"^\s*(\d+)\s+([\d.]+)\s+([\d.]+)\s+ms",
                    out, re.MULTILINE,
                ):
                    hops.append({
                        "hop": int(m.group(1)),
                        "ip":  m.group(2),
                        "ms":  float(m.group(3)),
                    })

            return hops[:max_hops]
        except Exception as e:
            print(f"[_quick_traceroute] error: {e}")
            return []

    # ─────────────────────────────────────────────────────────────────────────
    #  STORM ALERT
    # ─────────────────────────────────────────────────────────────────────────

    def check_storm_alert(self, current: WeatherCondition,
                           history: HistoricalAnalysis) -> Optional[str]:
        if history.status != "ok" or history.global_avg <= 0:
            return None

        ratio = current.ping_ms / history.global_avg if history.global_avg else 1.0

        if current.code == "blackout":
            return "🌑 БЛЕКАУТ! Мережа недоступна.\nПеревір підключення роутера та провайдера."
        if current.packet_loss > 10:
            return (
                f"⛈️ МАГНІТНА БУРЯ! Втрата пакетів {current.packet_loss:.0f}%.\n"
                f"Не рекомендується стріми або рейтингові матчі."
            )
        if ratio > 3.0 and current.ping_ms > 150:
            return (
                f"⚡ РІЗКЕ ПОГІРШЕННЯ! Пінг {current.ping_ms:.0f} мс "
                f"(норма {history.global_avg:.0f} мс, в {ratio:.1f}× вище).\n"
                f"Можливий збій у провайдера."
            )
        if current.code in ("storm", "rainy") and current.jitter_ms > 50:
            return (
                f"🌧️ НЕСТАБІЛЬНИЙ КАНАЛ. Джиттер {current.jitter_ms:.0f} мс.\n"
                f"Голосові чати та онлайн-ігри будуть нестабільними."
            )
        return None

    # ─────────────────────────────────────────────────────────────────────────
    #  DAILY / WEEKLY REPORTS (з дедуплікацією — щоб не спамити повторно)
    # ─────────────────────────────────────────────────────────────────────────

    def get_daily_report(self, force: bool = False) -> Optional[dict]:
        """
        Повертає звіт за поточну добу.
        За замовчуванням повертає None, якщо звіт вже показували сьогодні
        (щоб не спамити при повторному запуску програми).

        force=True — повернути в будь-якому разі.
        """
        today_key = datetime.now().strftime("%Y-%m-%d")

        # Перевіряємо журнал показаних звітів
        if not force and self._was_report_shown("daily", today_key):
            return None

        # Збираємо дані за добу
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT
                        AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                        AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = date('now', 'localtime')
                      AND ping_ms > 0
                      AND net_id = ?
                """, (self.net_id,))
                row = c.fetchone()
                if not row or not row[0]:
                    return None

                avg_p, min_p, max_p, avg_j, avg_l, total = row

                # Скільки часу був "блекаут"
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE date(ts) = date('now', 'localtime')
                      AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (self.net_id,))
                blackout_count = c.fetchone()[0]

                # Найкраща година сьогодні
                c.execute("""
                    SELECT hour, AVG(ping_ms) FROM ping_log
                    WHERE date(ts) = date('now', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                    ORDER BY AVG(ping_ms) ASC LIMIT 1
                """, (self.net_id,))
                best = c.fetchone()

        except Exception:
            return None

        report = {
            "type":           "daily",
            "date":           today_key,
            "network":        self.display_name,
            "avg_ping":       round(avg_p,  1) if avg_p  else 0,
            "min_ping":       round(min_p,  1) if min_p  else 0,
            "max_ping":       round(max_p,  1) if max_p  else 0,
            "avg_jitter":     round(avg_j,  1) if avg_j  else 0,
            "avg_loss":       round(avg_l,  2) if avg_l  else 0,
            "measurements":   total,
            "blackouts":      blackout_count,
            "best_hour":      best[0] if best else None,
            "best_hour_ping": round(best[1], 1) if best else None,
        }

        # Позначаємо звіт як показаний
        self._mark_report_shown("daily", today_key)
        return report

    def get_weekly_report(self, force: bool = False) -> Optional[dict]:
        """
        Повертає звіт за тиждень. Показується ТІЛЬКИ у неділю
        (або примусово через force=True).

        Дедуплікація: один раз на неділю.
        """
        now      = datetime.now()
        is_sunday = now.weekday() == 6  # 6 = неділя

        if not force and not is_sunday:
            return None

        week_key = now.strftime("%Y-W%V")  # ISO week
        if not force and self._was_report_shown("weekly", week_key):
            return None

        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT
                        AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                        AVG(jitter_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                """, (self.net_id,))
                row = c.fetchone()
                if not row or not row[0]:
                    return None

                avg_p, min_p, max_p, avg_j, avg_l, total = row

                # Найкращий і найгірший день
                c.execute("""
                    SELECT weekday, AVG(ping_ms) FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY weekday
                """, (self.net_id,))
                day_stats = {int(r[0]): round(r[1], 1) for r in c.fetchall()}

                # Блекаути за тиждень
                c.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND (ping_ms < 0 OR loss_pct >= 50)
                      AND net_id = ?
                """, (self.net_id,))
                blackouts = c.fetchone()[0]
        except Exception:
            return None

        best_day  = min(day_stats.items(), key=lambda x: x[1]) if day_stats else None
        worst_day = max(day_stats.items(), key=lambda x: x[1]) if day_stats else None

        report = {
            "type":          "weekly",
            "week":          week_key,
            "network":       self.display_name,
            "avg_ping":      round(avg_p, 1) if avg_p else 0,
            "min_ping":      round(min_p, 1) if min_p else 0,
            "max_ping":      round(max_p, 1) if max_p else 0,
            "avg_jitter":    round(avg_j, 1) if avg_j else 0,
            "avg_loss":      round(avg_l, 2) if avg_l else 0,
            "measurements":  total,
            "blackouts":     blackouts,
            "day_stats":     day_stats,
            "best_day":      best_day[0]  if best_day  else None,
            "best_day_ping": best_day[1]  if best_day  else None,
            "worst_day":     worst_day[0] if worst_day else None,
            "worst_day_ping": worst_day[1] if worst_day else None,
        }

        self._mark_report_shown("weekly", week_key)
        return report

    def _was_report_shown(self, report_type: str, key: str) -> bool:
        """Перевіряє чи показували вже звіт цього типу з цим ключем."""
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
                c = conn.cursor()
                c.execute(
                    "SELECT 1 FROM report_history WHERE report_type=? AND key=?",
                    (report_type, key)
                )
                return c.fetchone() is not None
        except Exception:
            return False

    def _mark_report_shown(self, report_type: str, key: str):
        """Записує що звіт було показано (для дедуплікації)."""
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
                    "INSERT OR REPLACE INTO report_history (report_type, key) VALUES (?, ?)",
                    (report_type, key)
                )
                conn.commit()
        except Exception:
            pass

    def get_monthly_history(self, days: int = 30) -> dict:
        """
        Повертає історію за останні N днів для відображення у Weekly Outlook
        замість прогнозу. Це вирішує проблему "Weekly outlook не можна
        дивитись історію за місяць" — тепер можна.

        Структура:
        {
            "days": [
                {"date": "2026-05-09", "weekday": 4, "avg_ping": 24.5,
                 "min_ping": 12.3, "max_ping": 65.0, "loss": 0.5,
                 "samples": 287, "weather_code": "sunny", "icon": "☀️"}
            ],
            "summary": { ... }
        }
        """
        result_days = []
        try:
            with sqlite3.connect(self.db_path, timeout=5) as conn:
                c = conn.cursor()
                c.execute(f"""
                    SELECT
                        date(ts) AS d,
                        AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                        AVG(loss_pct), COUNT(*),
                        AVG(jitter_ms)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-{int(days)} days', 'localtime')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY date(ts)
                    ORDER BY date(ts) ASC
                """, (self.net_id,))

                for row in c.fetchall():
                    d_str, avg_p, min_p, max_p, avg_l, cnt, avg_j = row
                    dt = datetime.strptime(d_str, "%Y-%m-%d")
                    code, icon, title, *_ = self._classify_weather(
                        avg_p or 0, avg_j or 0, avg_l or 0
                    )
                    result_days.append({
                        "date":         d_str,
                        "weekday":      dt.weekday(),
                        "day_name":     DAY_NAMES[dt.weekday()],
                        "avg_ping":     round(avg_p or 0, 1),
                        "min_ping":     round(min_p or 0, 1),
                        "max_ping":     round(max_p or 0, 1),
                        "loss":         round(avg_l or 0, 2),
                        "samples":      cnt,
                        "weather_code": code,
                        "icon":         icon,
                        "title":        title,
                    })
        except Exception:
            pass

        return {
            "days":    result_days,
            "summary": {
                "total_days":    len(result_days),
                "days_with_data": len([d for d in result_days if d["samples"] > 0]),
            },
        }

    def fill_gaps_from_pi(self, pi_db_path: Optional[str] = None) -> int:
        """
        Заповнює пробіли локальної БД даними з Raspberry Pi-кешу.

        ОПТИМІЗОВАНО v4: ГУЧНЕ логування для діагностики проблеми
        "дані з Pi не з'являються".
        """
        if pi_db_path is None:
            pi_db_path = str(Path.home() / ".netguardian" / "pi_agent_cache.db")
        if not Path(pi_db_path).exists():
            print(f"[ForecastEngine] ❌ Pi cache file not found: {pi_db_path}")
            return 0

        print(f"[ForecastEngine] 🔄 fill_gaps_from_pi START")
        print(f"[ForecastEngine]   pi_db: {pi_db_path}")
        print(f"[ForecastEngine]   forecast_db: {self.db_path}")
        print(f"[ForecastEngine]   net_id: {self.net_id}")

        added = 0
        try:
            with sqlite3.connect(pi_db_path, timeout=5) as pi_conn:
                pi_c = pi_conn.cursor()

                pi_c.execute("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='remote_ping'
                """)
                if not pi_c.fetchone():
                    print("[ForecastEngine] ❌ remote_ping table not found in Pi cache")
                    return 0

                pi_c.execute("PRAGMA table_info(remote_ping)")
                available_cols = {row[1] for row in pi_c.fetchall()}
                print(f"[ForecastEngine]   Pi columns: {available_cols}")

                has_jitter = "jitter_ms" in available_cols
                has_loss   = "loss_pct" in available_cols

                select_cols = ["ts", "ping_ms"]
                if has_jitter:
                    select_cols.append("jitter_ms")
                if has_loss:
                    select_cols.append("loss_pct")

                # ВАЖЛИВО: читаємо з ОБОХ таблиць щоб не втратити дані
                # remote_ping            — live MQTT  (приходять кожні 60с)
                # remote_history_sync    — історія яку Pi надсилав по запиту
                # Це усуває "сліпу зону" коли ПК запускається після паузи.
                base_cols_p = "ts, ping_ms"
                if has_jitter:
                    base_cols_p += ", jitter_ms"
                if has_loss:
                    base_cols_p += ", loss_pct"

                # Перевіряємо чи є таблиця history_sync
                pi_c.execute("""
                    SELECT name FROM sqlite_master
                    WHERE type='table' AND name='remote_history_sync'
                """)
                has_hist = pi_c.fetchone() is not None

                if has_hist:
                    # UNION з history_sync (тимч. ВЬЮ з потрібними колонками)
                    query = f"""
                        SELECT * FROM (
                            SELECT {base_cols_p}
                            FROM remote_ping
                            WHERE ts >= datetime('now', '-7 days', 'localtime')
                              AND ping_ms IS NOT NULL AND ping_ms > 0
                            UNION
                            SELECT ts, ping_ms,
                                   {'jitter_ms,' if has_jitter else ''}
                                   {'loss_pct' if has_loss else ''}
                            FROM remote_history_sync
                            WHERE ts >= datetime('now', '-7 days', 'localtime')
                              AND ping_ms IS NOT NULL AND ping_ms > 0
                        )
                        ORDER BY ts ASC
                    """
                else:
                    query = f"""
                        SELECT {base_cols_p}
                        FROM remote_ping
                        WHERE ts >= datetime('now', '-7 days', 'localtime')
                          AND ping_ms IS NOT NULL AND ping_ms > 0
                        ORDER BY ts ASC
                    """
                pi_c.execute(query)
                pi_rows = pi_c.fetchall()

                # Додаткова статистика
                pi_c.execute("SELECT COUNT(*) FROM remote_ping")
                total_pi = pi_c.fetchone()[0]
                pi_c.execute("""SELECT COUNT(*) FROM remote_ping
                    WHERE ts >= datetime('now', '-10 minutes', 'localtime')""")
                fresh_pi = pi_c.fetchone()[0]
                hist_total = 0
                if has_hist:
                    pi_c.execute("SELECT COUNT(*) FROM remote_history_sync")
                    hist_total = pi_c.fetchone()[0]
                print(f"[ForecastEngine]   Pi cache TOTAL: ping={total_pi} "
                      f"history={hist_total}, за 7 днів: {len(pi_rows)}, "
                      f"за 10хв: {fresh_pi}")

            if not pi_rows:
                print("[ForecastEngine] ⚠️ Pi cache порожній за 7 днів — нема що синхронізувати")
                return 0

            # Готуємо записи у batch
            batch = []
            for row in pi_rows:
                ts = row[0]
                ping = row[1]
                jitter = row[2] if has_jitter and len(row) > 2 else 0
                loss = row[3] if has_loss and len(row) > 3 else (
                    row[2] if not has_jitter and has_loss and len(row) > 2 else 0
                )

                try:
                    dt = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    try:
                        dt = datetime.fromisoformat(ts)
                    except Exception:
                        continue
                batch.append((
                    ts, ping, jitter or 0, loss or 0,
                    dt.hour, dt.weekday(), self.net_id
                ))

            if not batch:
                return 0

            # Записуємо в основну БД в один транзакційний batch
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                _ensure_schema(conn)
                c = conn.cursor()

                # Дізнаємось які колонки реально є у нашій ping_log
                local_cols = {row[1] for row in c.execute("PRAGMA table_info(ping_log)")}
                print(f"[ForecastEngine] local ping_log columns: {local_cols}")

                # Якщо немає базових колонок — переcтворити таблицю
                required_cols = {"ts", "ping_ms", "net_id"}
                if not required_cols.issubset(local_cols):
                    print(f"[ForecastEngine] ⚠️ ping_log відсутні колонки {required_cols - local_cols}")
                    print(f"[ForecastEngine] Пересотворюю ping_log з нуля (стара версія БД)")
                    c.execute("DROP TABLE IF EXISTS ping_log")
                    _ensure_schema(conn)
                    local_cols = {row[1] for row in c.execute("PRAGMA table_info(ping_log)")}

                # Додаємо колонку source якщо її ще немає
                if "source" not in local_cols:
                    c.execute("ALTER TABLE ping_log ADD COLUMN source TEXT DEFAULT 'local'")

                # Створюємо UNIQUE-індекс щоб уникнути дублікатів
                try:
                    c.execute("""
                        CREATE UNIQUE INDEX IF NOT EXISTS idx_ping_log_uniq
                        ON ping_log(ts, net_id, source)
                    """)
                except sqlite3.OperationalError as ie:
                    print(f"[ForecastEngine] Index error (skip): {ie}")

                # Лічимо до вставки
                c.execute("SELECT COUNT(*) FROM ping_log")
                count_before = c.fetchone()[0]

                # BATCH INSERT — швидко!
                c.executemany("""
                    INSERT OR IGNORE INTO ping_log
                    (ts, ping_ms, jitter_ms, loss_pct, hour, weekday, net_id, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'pi')
                """, batch)

                c.execute("SELECT COUNT(*) FROM ping_log")
                count_after = c.fetchone()[0]
                added = count_after - count_before

                conn.commit()

            print(f"[ForecastEngine] ✅ fill_gaps_from_pi: +{added} рядків")
        except Exception as e:
            import traceback
            print(f"[ForecastEngine] fill_gaps_from_pi error: {e}")
            traceback.print_exc()
            return 0

        return added

    # ─────────────────────────────────────────────────────────────────────────
    #  TELEGRAM SUMMARY
    # ─────────────────────────────────────────────────────────────────────────

    def get_weather_summary(self) -> str:
        cond     = self.measure_current()
        history  = self.analyze_history()
        services = self.check_services()

        lines = [
            f"*{cond.icon} NetGuardian Weather Report*",
            f"🌐 _{self.display_name}_",
            f"_{datetime.now().strftime('%d.%m.%Y %H:%M')}_",
            "",
            f"*Стан:* {cond.title}",
            f"*Пінг:* {cond.ping_ms:.0f} мс  |  *Джиттер:* {cond.jitter_ms:.0f} мс",
            f"*Втрата пакетів:* {cond.packet_loss:.1f}%",
            f"*Індекс якості:* {100 - cond.weather_index}/100",
        ]

        if cond.nominal_mbps > 0:
            lines.append(
                f"*Швидкість:* {cond.nominal_mbps:.0f} Мбіт "
                f"→ відчувається як {cond.perceived_mbps:.0f} Мбіт"
            )

        if history.status == "ok" and history.sla_pct > 0:
            lines.append(f"*Надійність ISP (SLA):* {history.sla_pct:.1f}%")

        gaming_down = [s.name for s in services
                       if s.category == "gaming" and not s.is_up]
        if gaming_down:
            lines.append(f"\n⚠️ *Недоступно:* {', '.join(gaming_down)}")

        alert = self.check_storm_alert(cond, history)
        if alert:
            lines.append(f"\n🚨 *ALERT:*\n{alert}")

        if history.status == "ok" and history.forecast_days:
            best = history.best_hour
            lines.append(
                f"\n💡 *Найкращий час:* {best[0]:02d}:00 (avg {best[1]:.0f} мс)"
            )

        lines.append(f"\n_{cond.desc}_")
        return "\n".join(lines)

    # ─────────────────────────────────────────────────────────────────────────
    #  WINDOWS TOAST
    # ─────────────────────────────────────────────────────────────────────────

    @staticmethod
    def send_windows_notification(title: str, message: str) -> None:
        if not IS_WINDOWS:
            return
        title   = title.replace("'", "''")
        message = message.replace("'", "''")
        try:
            ps = (
                "[Windows.UI.Notifications.ToastNotificationManager, "
                "Windows.UI.Notifications, ContentType=WindowsRuntime] | Out-Null; "
                "$tmpl = [Windows.UI.Notifications.ToastNotificationManager]::"
                "GetTemplateContent("
                "[Windows.UI.Notifications.ToastTemplateType]::ToastText02); "
                f"$tmpl.GetElementsByTagName('text')[0].InnerText = '{title}'; "
                f"$tmpl.GetElementsByTagName('text')[1].InnerText = '{message}'; "
                "$toast = [Windows.UI.Notifications.ToastNotification]::new($tmpl); "
                "[Windows.UI.Notifications.ToastNotificationManager]::"
                "CreateToastNotifier('NetGuardian').Show($toast);"
            )
            subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            pass