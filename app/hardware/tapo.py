"""
NetGuardian AI — Tapo P110 Integration  v10 — Voltage Guardian

РОЛЬ РОЗЕТКИ:
  Захист обладнання від нестабільної електрики.

ФУНКЦІЇ:
  1. Voltage Guardian — авто-вимкнення при небезпечній напрузі
       • Brownout  (< volt_min, default 200V) → вимикає + сповіщення
       • Overvolt  (> volt_max, default 250V) → вимикає + сповіщення
       • Авто-відновлення коли напруга нормалізується

  2. Overload Guard — авто-вимкнення при перевантаженні
       • Струм > amp_max (default 10A) → вимикає
       • Потужність > watt_max (default 2200W) → вимикає

  3. Voltage Monitor — фоновий збір статистики
       • Зберігає останні 1440 точок (~24 год при 60с)
       • Рахує мін/макс/середнє, аномалії, вартість

  4. Power Report — звіт якості електрики
       • Стабільність напруги (%)
       • Кількість подій захисту
       • Витрати в грн
"""

import os
import re
import json
import time
import asyncio
import threading
import logging
import socket
import subprocess
import collections
from dataclasses import dataclass, field
from typing import Optional, Callable

log = logging.getLogger("tapo")

# ── patch requests timeout ───────────────────────────────
def _patch_requests_timeout(min_t: float = 10.0):
    try:
        from requests import Session
        _orig = Session.request
        def _p(self, method, url, **kw):
            t = kw.get("timeout")
            if t is None or (isinstance(t, (int, float)) and t < min_t):
                kw["timeout"] = min_t
            elif isinstance(t, tuple):
                kw["timeout"] = (max(t[0], min_t), max(t[1], min_t))
            return _orig(self, method, url, **kw)
        Session.request = _p
    except ImportError:
        pass
_patch_requests_timeout(10.0)

# ── tapo lib import ──────────────────────────────────────
_HAS_TAPO = False
try:
    from tapo import ApiClient
    _HAS_TAPO = True
except ImportError:
    pass

# ── helpers ──────────────────────────────────────────────
def _is_lan_target(ip: str) -> bool:
    """Перевіряє чи IP — це локальна мережа (192.168.x / 10.x / 172.16-31.x)."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4: return False
        if parts[0] == 192 and parts[1] == 168: return True
        if parts[0] == 10: return True
        if parts[0] == 172 and 16 <= parts[1] <= 31: return True
    except (ValueError, IndexError): pass
    return False


def _tcp_ok(ip: str, timeout: float = 5.0) -> bool:
    """Перевіряє доступність розетки.

    Tapo P110 (SHIP 2.0 protocol) — HTTP на порту 80.
    Старі прошивки — порт 9999 (legacy KLAP).

    КРИТИЧНО: коли активний Radmin VPN (26.x), socket() без bind()
    маршрутизується через VPN-шлюз і НЕ дійде до 192.168.x.
    Для LAN-цілей одразу BIND на конкретний LAN-інтерфейс.
    """
    is_lan = _is_lan_target(ip)
    lan_ips = _get_local_lan_ips() if is_lan else []

    # Якщо є LAN-інтерфейс — використовуємо його ПЕРШИМ (не fallback!)
    for port in (80, 443, 9999):
        # Спочатку — пробуємо через явний bind на кожний LAN-інтерфейс
        if lan_ips:
            for local_ip in lan_ips:
                try:
                    s = socket.socket()
                    s.settimeout(timeout)
                    s.bind((local_ip, 0))
                    r = s.connect_ex((ip, port))
                    s.close()
                    if r == 0:
                        return True
                except Exception:
                    pass
        # Якщо bind не дав результату — звичайний connect (на випадок
        # коли LAN-інтерфейсу взагалі немає)
        try:
            s = socket.socket()
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                s.close()
                return True
            s.close()
        except Exception:
            pass

    return False


def _make_lan_socket(target_ip: str, timeout: float = 5.0) -> Optional[socket.socket]:
    """Створює socket з правильним bind для LAN-цілі.

    Повертає None якщо bind не вдався.
    Використовуй для всіх з'єднань з розеткою у LAN!
    """
    if not _is_lan_target(target_ip):
        return None   # для не-LAN використовуй звичайний socket

    for local_ip in _get_local_lan_ips():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.bind((local_ip, 0))
            return s
        except Exception:
            continue
    return None



def _get_local_lan_ips() -> list[str]:
    """Повертає список локальних IP адрес що належать до LAN-інтерфейсів.

    Виключає Radmin VPN (26.x.x.x), Hamachi (25.x.x.x), VirtualBox (10.0.x).
    """
    ips = []
    try:
        import psutil
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family != socket.AF_INET: continue
                ip = addr.address
                # Пропускаємо системні, VPN, virtual
                if ip.startswith(("127.", "169.254.")):
                    continue
                if ip.startswith(("26.", "25.")):  # Radmin/Hamachi
                    print(f"[Tapo] Skipping VPN interface: {iface} ({ip})")
                    continue
                # Беремо тільки приватні LAN-діапазони
                if ip.startswith(("192.168.", "10.")) or ip.startswith("172."):
                    ips.append(ip)
    except ImportError:
        # Fallback без psutil
        try:
            hostname = socket.gethostname()
            for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
                ip = info[4][0]
                if (ip.startswith(("192.168.", "10.")) or ip.startswith("172.")) \
                        and not ip.startswith(("26.", "25.")):
                    if ip not in ips:
                        ips.append(ip)
        except Exception: pass
    return ips


def _diagnose_connection(ip: str) -> str:
    """Діагностика чому _tcp_ok провалюється — для зрозумілих повідомлень.

    Returns: текст з причиною.
    """
    import platform
    import subprocess
    # 1. Перевіряємо ICMP ping
    try:
        sysname = platform.system().lower()
        if "windows" in sysname:
            cmd = ["ping", "-n", "2", "-w", "2000", ip]
        else:
            cmd = ["ping", "-c", "2", "-W", "2", ip]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=8,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        if r.returncode != 0 or "Destination host unreachable" in (r.stdout or "") \
                or "Request timed out" in (r.stdout or ""):
            return (f"❌ {ip} взагалі не пінгується. "
                    f"• Перевір що розетка увімкнена в Wi-Fi. "
                    f"• Перевір IP у додатку Tapo (можливо змінився). "
                    f"• Якщо у тебе Radmin VPN — спробуй вимкнути.")
    except Exception:
        pass

    # 2. Ping проходить, але порти закриті
    return (f"⚠️ {ip} пінгується, але порти 80/443/9999 закриті. "
            f"• Файрвол Windows блокує? "
            f"• Антивірус блокує LAN? "
            f"• Прошивка розетки застаріла? "
            f"• Radmin VPN перенаправляє трафік?")


def _run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ════════════════════════════════════════════════════════
#  НАЛАШТУВАННЯ ЗАХИСТУ
# ════════════════════════════════════════════════════════
@dataclass
class GuardSettings:
    # Напруга
    volt_min: float = 200.0      # V — нижня межа (Brownout)
    volt_max: float = 250.0      # V — верхня межа (Overvolt)
    volt_warn_low: float = 210.0 # V — попередження (жовте)
    volt_warn_high: float = 240.0# V — попередження (жовте)
    volt_enabled: bool = True

    # Струм / потужність
    amp_max: float  = 10.0       # A — максимальний струм
    watt_max: float = 2200.0     # W — максимальна потужність
    overload_enabled: bool = True

    # Авто-відновлення
    auto_restore: bool = True    # увімкнути коли напруга нормалізується
    restore_delay: int = 30      # секунд чекати перед авто-відновленням

    # Моніторинг
    monitor_interval: int = 60   # секунд між замірами
    history_points:   int = 1440 # точок (~24 год при 60с)

    # Вартість електроенергії
    price_per_kwh: float = 4.32  # грн/кВт·год (тариф Україна 2025)


# ════════════════════════════════════════════════════════
#  ТОЧКА ДАНИХ МОНІТОРИНГУ
# ════════════════════════════════════════════════════════
@dataclass
class PowerPoint:
    ts:    float
    volts: float
    amps:  float
    watts: float
    is_on: bool


# ════════════════════════════════════════════════════════
#  ПОДІЯ ЗАХИСТУ
# ════════════════════════════════════════════════════════
@dataclass
class GuardEvent:
    ts:     float
    reason: str   # brownout / overvolt / overload
    volts:  float
    amps:   float
    watts:  float
    restored_ts: Optional[float] = None  # коли відновили


# ════════════════════════════════════════════════════════
#  TAPO PLUG
# ════════════════════════════════════════════════════════
class TapoPlug:
    """
    Управління розеткою Tapo P110.
    Основна роль: захист обладнання від поганої електрики.
    """

    def __init__(self, ip: str, email: str = "", password: str = "",
                 mac: str = ""):
        self.ip       = ip.strip()
        self.email    = email.strip()
        self.password = password.strip()
        self.mac      = mac.strip().lower().replace(":", "-")  # нормалізуємо

        self._lock      = threading.Lock()
        self._cache     = {}
        self._cache_ts  = 0
        self._method    = "p110"

        # КРИТИЧНО: коли активний Radmin VPN (26.x), socket'и tapo-бібліотеки
        # маршрутизуються через VPN-шлюз. Встановлюємо СТАТИЧНИЙ route
        # до IP розетки через LAN-інтерфейс ОДИН РАЗ при ініціалізації.
        # Це гарантує що ВСІ майбутні з'єднання підуть правильно.
        self._setup_static_route()

        # Якщо вказана MAC — спробуємо знайти IP через ARP
        # перед першим запитом (на випадок якщо IP змінився)
        if self.mac and not self._tcp_check_quick():
            new_ip = self._find_ip_by_mac(self.mac)
            if new_ip and new_ip != self.ip:
                print(f"[Tapo] IP змінився: {self.ip} → {new_ip} (за MAC {self.mac})")
                self.ip = new_ip
                # Перенастроюємо route на новий IP
                self._setup_static_route()

        # Налаштування захисту
        self.guard = GuardSettings()

        # Стан захисту
        self._guard_off       = False   # True = вимкнено захистом
        self._guard_reason    = ""      # причина вимкнення
        self._restore_ts      = 0.0     # коли пробувати відновити
        self._guard_events: list[GuardEvent] = []  # журнал подій захисту

        # Моніторинг
        self._history: collections.deque = collections.deque(
            maxlen=self.guard.history_points
        )
        self._monitor_thread: Optional[threading.Thread] = None
        self._monitor_running = False

        # Callback для сповіщень (Telegram)
        self._alert_cb: Optional[Callable[[str], None]] = None

    def _tcp_check_quick(self) -> bool:
        """Швидка перевірка чи IP доступний (timeout 2с)."""
        return _tcp_ok(self.ip, timeout=2.0)

    def _setup_static_route(self):
        """Встановлює статичний маршрут до Tapo через LAN-інтерфейс.

        КРИТИЧНО для роботи з Radmin VPN/Hamachi:
        - Без route: пакети йдуть через VPN gateway → connection refused
        - З route: пакети йдуть через Wi-Fi → success

        Виконує `route add <tapo_ip> mask 255.255.255.255 <lan_gw>`
        тільки якщо такого маршруту ще немає.
        """
        if not _is_lan_target(self.ip):
            return

        try:
            # 1. Знаходимо LAN-gateway (наш Wi-Fi/Ethernet шлюз — 192.168.0.1)
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                 "Where-Object { $_.NextHop -match '^(192\\.168|10\\.|172\\.)' } | "
                 "Sort-Object RouteMetric | "
                 "Select-Object -First 1 NextHop | "
                 "ForEach-Object { $_.NextHop }"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            lan_gw = (r.stdout or "").strip()
            if not lan_gw or not _is_lan_target(lan_gw):
                # Fallback: гадаємо що шлюз .1
                lan_gw = ".".join(self.ip.split(".")[:3]) + ".1"
                print(f"[Tapo] LAN gateway не знайдено через PS — використовую fallback {lan_gw}")

            # 2. Перевіряємо чи маршрут уже існує
            r = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            existing = r.stdout or ""
            if f"  {self.ip} " in existing or f" {self.ip}\n" in existing:
                # Маршрут уже є
                print(f"[Tapo] Статичний route до {self.ip} вже існує")
                return

            # 3. Додаємо маршрут (потрібні права адміна на Windows!)
            print(f"[Tapo] Встановлюю route: {self.ip} → {lan_gw}")
            r = subprocess.run(
                ["route", "add", self.ip, "mask", "255.255.255.255", lan_gw, "metric", "1"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0 and "OK" in (r.stdout or ""):
                print(f"[Tapo] ✅ Route встановлено: {self.ip} через {lan_gw}")
            elif "The requested operation requires elevation" in (r.stderr or "") \
                    or "потрібн" in (r.stderr or "").lower():
                print(f"[Tapo] ⚠️ Не вистачає прав адміна для route add. "
                      f"Запустіть NetGuardian від адміністратора, або вимкніть Radmin VPN.")
            else:
                # Інша помилка — пробуємо без metric
                print(f"[Tapo] route add output: {r.stdout or r.stderr}")

        except Exception as e:
            print(f"[Tapo] _setup_static_route error: {e}")

    def _find_ip_by_mac(self, mac: str) -> str:
        """Шукає IP пристрою у локальній мережі за MAC-адресою.

        Використовує ARP-таблицю (`arp -a`).
        Працює якщо пристрій нещодавно пінгувався або обмінювався пакетами.
        """
        try:
            import subprocess
            r = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            target = mac.lower().replace(":", "-")
            for line in (r.stdout or "").splitlines():
                line_low = line.lower()
                if target in line_low:
                    # Формат: "  192.168.0.105     aa-bb-cc-dd-ee-ff   dynamic"
                    parts = line.split()
                    for part in parts:
                        if part.count(".") == 3:
                            try:
                                # Перевіряємо що це IP
                                octets = part.split(".")
                                if all(0 <= int(o) <= 255 for o in octets):
                                    return part
                            except ValueError:
                                continue
        except Exception as e:
            print(f"[Tapo] _find_ip_by_mac error: {e}")
        return ""

    def _trigger_arp_refresh(self):
        """Запускає ARP-discovery шляхом ping-flood усієї підмережі.

        Це форсує Windows додати IP→MAC mapping у ARP-таблицю
        для всіх активних пристроїв. Після цього `arp -a` дасть
        повний список.
        """
        try:
            import subprocess
            import socket
            # Знаходимо нашу підмережу
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            # Спрощено: припускаємо /24
            base = ".".join(local_ip.split(".")[:3])
            # ping все підряд (асинхронно через arping )
            # Найшвидший варіант — arp -d і потім ping subnet broadcast
            broadcast = f"{base}.255"
            subprocess.run(
                ["ping", "-n", "1", "-w", "100", broadcast],
                capture_output=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        except Exception as e:
            print(f"[Tapo] arp refresh error: {e}")

    # ────────────────────────────────────────────────────
    # CALLBACKS
    # ────────────────────────────────────────────────────

    def set_alert_callback(self, fn: Callable[[str], None]):
        """Встановити функцію сповіщень (викликається при захисті)."""
        self._alert_cb = fn

    def _notify(self, text: str):
        if self._alert_cb:
            try:
                self._alert_cb(text)
            except Exception as e:
                log.debug(f"[Guard] alert_cb error: {e}")

    # ────────────────────────────────────────────────────
    # З'ЄДНАННЯ
    # ────────────────────────────────────────────────────

    async def _connect_async(self):
        if not _HAS_TAPO:
            raise RuntimeError("pip install tapo")
        client = ApiClient(self.email, self.password)
        last_err = None
        for method in ("p110", "p110m"):
            try:
                device = await asyncio.wait_for(
                    getattr(client, method)(self.ip), timeout=12
                )
                self._method = method
                return device
            except asyncio.TimeoutError:
                last_err = f"{method}: timeout"
            except Exception as e:
                err = str(e).lower()
                if any(x in err for x in ("forbidden", "1003", "authentication")):
                    raise RuntimeError(
                        "❌ Невірний email/пароль.\n"
                        "Tapo App → ⚙️ → Third-Party Services → увімкнути"
                    )
                last_err = f"{method}: {e}"
        raise RuntimeError(f"❌ Не вдалось підключитись: {last_err}")

    def test_connection(self) -> tuple:
        return self.connect()

    def connect(self) -> tuple:
        with self._lock:
            return self._connect_sync()

    def _connect_sync(self) -> tuple:
        if not _tcp_ok(self.ip):
            return False, (
                f"❌ {self.ip} недоступний.\n"
                "• Перевір IP в Tapo App → ⚙️ → Device Info\n"
                "• Розетка підключена до Wi-Fi?"
            )
        try:
            async def _t():
                dev  = await self._connect_async()
                info = await asyncio.wait_for(dev.get_device_info(), timeout=12)
                return getattr(info, "nickname", None) or "Tapo P110"
            nick = _run(_t())
            return True, f"✅ Підключено до {nick} ({self.ip}) [{self._method}]"
        except Exception as e:
            return False, str(e)

    # ────────────────────────────────────────────────────
    # УВІМК / ВИМКН
    # ────────────────────────────────────────────────────

    def turn_on(self) -> tuple:
        """Увімкнути розетку (вручну)."""
        self._guard_off = False   # скидаємо guard-прапор при ручному вмиканні
        with self._lock:
            return self._power(True)

    def turn_off(self) -> tuple:
        """Вимкнути розетку (вручну)."""
        self._guard_off = False
        with self._lock:
            return self._power(False)

    def _power(self, state: bool) -> tuple:
        if not _tcp_ok(self.ip):
            return False, _diagnose_connection(self.ip)
        try:
            async def _do():
                dev = await self._connect_async()
                await asyncio.wait_for(dev.on() if state else dev.off(), timeout=12)
            _run(_do())
            self._cache_ts = 0
            return True, f"✅ {'Увімкнено' if state else 'Вимкнено'} Tapo P110"
        except Exception as e:
            return False, f"❌ {e}"

    # ════════════════════════════════════════════════════
    #  VOLTAGE GUARDIAN — ЗАХИСТ
    # ════════════════════════════════════════════════════

    def check_and_protect(self, status: dict) -> Optional[str]:
        """
        Перевіряє поточні показники і вимикає якщо небезпечно.
        Повертає рядок з причиною або None якщо все ок.
        """
        if not status.get("online") or not status.get("is_on"):
            return None

        v = status.get("volts", 0.0)
        a = status.get("amps",  0.0)
        w = status.get("watts", 0.0)

        reason_code = None
        reason_text = None

        # ── Перевірка напруги ─────────────────────────────
        if self.guard.volt_enabled and v > 0:  # v=0 означає "немає даних"
            if v < self.guard.volt_min:
                reason_code = "brownout"
                reason_text = (
                    f"⚡ BROWNOUT: Напруга впала до {v:.0f}V "
                    f"(мінімум {self.guard.volt_min:.0f}V)"
                )
            elif v > self.guard.volt_max:
                reason_code = "overvolt"
                reason_text = (
                    f"⚡ OVERVOLT: Небезпечна напруга {v:.0f}V "
                    f"(максимум {self.guard.volt_max:.0f}V)"
                )

        # ── Перевірка перевантаження ──────────────────────
        if not reason_code and self.guard.overload_enabled and w > 0:
            if a > self.guard.amp_max:
                reason_code = "overload"
                reason_text = (
                    f"⚡ OVERLOAD: Струм {a:.2f}A перевищує ліміт {self.guard.amp_max:.0f}A"
                )
            elif w > self.guard.watt_max:
                reason_code = "overload"
                reason_text = (
                    f"⚡ OVERLOAD: Потужність {w:.0f}W перевищує ліміт {self.guard.watt_max:.0f}W"
                )

        if reason_text:
            self._guard_off    = True
            self._guard_reason = reason_text
            self._restore_ts   = time.time() + self.guard.restore_delay

            # Зберігаємо подію
            self._guard_events.append(GuardEvent(
                ts=time.time(), reason=reason_code or "unknown",
                volts=v, amps=a, watts=w
            ))
            # Зберігаємо тільки 100 останніх подій
            if len(self._guard_events) > 100:
                self._guard_events = self._guard_events[-100:]

            ok, msg = self._power(False)
            log.warning(f"[Guard] ЗАХИСТ: {reason_text} → {msg}")

            restore_msg = (
                f"♻️ Авто-відновлення через {self.guard.restore_delay}с\n"
                if self.guard.auto_restore else
                "❗ Авто-відновлення вимкнено. Увімкни вручну: /tapo on\n"
            )
            self._notify(
                f"🛡️ *ЗАХИСТ СПРАЦЮВАВ!*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"{reason_text}\n\n"
                f"📊 Поточні показники:\n"
                f"⚡ Напруга: `{v:.0f} V` | Струм: `{a:.3f} A` | Потужність: `{w:.1f} W`\n\n"
                f"🔌 Розетку вимкнено автоматично.\n"
                f"{restore_msg}"
            )

        return reason_text

    def check_restore(self, status: dict):
        """
        Якщо розетку вимкнув захист і напруга нормалізувалась — вмикає назад.
        """
        if not self._guard_off or not self.guard.auto_restore:
            return
        if time.time() < self._restore_ts or not status.get("online"):
            return

        v = status.get("volts", 0.0)

        # Напруга в нормі?
        if v <= 0 or not (self.guard.volt_min <= v <= self.guard.volt_max):
            self._restore_ts = time.time() + self.guard.restore_delay
            return

        ok, msg = self._power(True)
        if ok:
            # Записуємо час відновлення в останню подію
            if self._guard_events:
                self._guard_events[-1].restored_ts = time.time()

            self._guard_off = False
            log.info(f"[Guard] Авто-відновлення: {v:.0f}V в нормі → {msg}")
            self._notify(
                f"✅ *Авто-відновлення*\n"
                f"Напруга нормалізувалась: `{v:.0f}V`\n"
                f"🔌 Розетку увімкнено автоматично."
            )

    def check_voltage_warning(self, status: dict):
        """Сповіщення про напругу поза зоною попередження (але ще не критично)."""
        v = status.get("volts", 0.0)
        if v <= 0 or not status.get("is_on"):
            return

        if v < self.guard.volt_warn_low and v >= self.guard.volt_min:
            self._notify(
                f"🟡 *Увага: низька напруга*\n"
                f"Напруга: `{v:.0f}V` (норма {self.guard.volt_warn_low:.0f}–{self.guard.volt_warn_high:.0f}V)\n"
                f"_Якщо впаде нижче {self.guard.volt_min:.0f}V — розетка вимкнеться автоматично._"
            )
        elif v > self.guard.volt_warn_high and v <= self.guard.volt_max:
            self._notify(
                f"🟡 *Увага: підвищена напруга*\n"
                f"Напруга: `{v:.0f}V` (норма {self.guard.volt_warn_low:.0f}–{self.guard.volt_warn_high:.0f}V)\n"
                f"_Якщо перевищить {self.guard.volt_max:.0f}V — розетка вимкнеться автоматично._"
            )

    # ════════════════════════════════════════════════════
    #  МОНІТОРИНГ (фоновий потік)
    # ════════════════════════════════════════════════════

    def start_monitor(self):
        """Запустити фоновий моніторинг напруги."""
        if self._monitor_running:
            return
        self._monitor_running = True
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._monitor_thread.start()
        log.info(f"[Guard] Моніторинг запущено (інтервал {self.guard.monitor_interval}с)")

    def stop_monitor(self):
        """Зупинити моніторинг."""
        self._monitor_running = False
        log.info("[Guard] Моніторинг зупинено")

    @property
    def is_monitoring(self) -> bool:
        return self._monitor_running

    def _monitor_loop(self):
        _warn_cooldown = 0  # щоб не спамити попередженнями
        while self._monitor_running:
            try:
                status = self._fetch_status()
                if status.get("online"):
                    pt = PowerPoint(
                        ts    = time.time(),
                        volts = status.get("volts", 0.0),
                        amps  = status.get("amps",  0.0),
                        watts = status.get("watts", 0.0),
                        is_on = status.get("is_on", False),
                    )
                    self._history.append(pt)

                    # Перевірки захисту
                    self.check_and_protect(status)
                    self.check_restore(status)

                    # Попередження про напругу (не частіше 1 разу на 15 хв)
                    if time.time() - _warn_cooldown > 900:
                        self.check_voltage_warning(status)
                        _warn_cooldown = time.time()

            except Exception as e:
                log.debug(f"[Guard] monitor loop error: {e}")
            time.sleep(self.guard.monitor_interval)

    # ════════════════════════════════════════════════════
    #  СТАТИСТИКА
    # ════════════════════════════════════════════════════

    def get_stats(self) -> dict:
        """Статистика за весь час в пам'яті."""
        if not self._history:
            return {}

        points = list(self._history)
        volts  = [p.volts for p in points if p.volts > 0]
        watts  = [p.watts for p in points if p.is_on and p.watts > 0]

        # Вартість: watts * hours * price
        total_wh = sum(
            p.watts * (self.guard.monitor_interval / 3600)
            for p in points if p.is_on
        )
        cost = total_wh / 1000 * self.guard.price_per_kwh

        # Аномалії напруги
        brownouts = sum(1 for v in volts if 0 < v < self.guard.volt_min)
        overvolts = sum(1 for v in volts if v > self.guard.volt_max)
        warnings  = sum(1 for v in volts if
                        (self.guard.volt_min <= v < self.guard.volt_warn_low) or
                        (self.guard.volt_warn_high < v <= self.guard.volt_max))

        # Стабільність: % точок у нормальному діапазоні
        normal = sum(1 for v in volts if self.guard.volt_warn_low <= v <= self.guard.volt_warn_high)
        stability = round(normal / len(volts) * 100, 1) if volts else 0

        return {
            "points":       len(points),
            "period_min":   round(len(points) * self.guard.monitor_interval / 60, 1),
            "volt_min":     round(min(volts), 1) if volts else 0,
            "volt_max":     round(max(volts), 1) if volts else 0,
            "volt_avg":     round(sum(volts) / len(volts), 1) if volts else 0,
            "watt_avg":     round(sum(watts) / len(watts), 1) if watts else 0,
            "watt_max":     round(max(watts), 1) if watts else 0,
            "total_wh":     round(total_wh, 2),
            "cost_uah":     round(cost, 2),
            "brownouts":    brownouts,
            "overvolts":    overvolts,
            "warnings":     warnings,
            "stability_pct":stability,
            "guard_events": len(self._guard_events),
        }

    def get_voltage_trend(self) -> str:
        """ASCII-графік напруги за останніми точками."""
        points = list(self._history)[-48:]
        if len(points) < 3:
            return "_Недостатньо даних (потрібно мінімум 3 заміри)_"

        volts = [p.volts for p in points if p.volts > 0]
        if not volts:
            return "_Немає даних напруги_"

        v_min = min(volts)
        v_max = max(volts)
        v_range = v_max - v_min or 1

        rows  = 5
        width = min(len(volts), 40)
        step  = max(1, len(volts) // width)
        sampled = volts[::step][:width]

        normalized = [int((v - v_min) / v_range * (rows - 1)) for v in sampled]

        lines = []
        for row in range(rows - 1, -1, -1):
            if row == rows - 1:
                label = f"{v_max:.0f}V "
            elif row == 0:
                label = f"{v_min:.0f}V "
            elif row == rows // 2:
                label = f"{(v_min+v_max)/2:.0f}V "
            else:
                label = "     "
            bar = "".join("█" if n >= row else " " for n in normalized)
            lines.append(f"`{label}{bar}`")

        # Межі захисту
        lines.append(
            f"🔴 Критично: <`{self.guard.volt_min:.0f}V` або >`{self.guard.volt_max:.0f}V`"
        )
        return "\n".join(lines)

    def get_guard_events_text(self, limit: int = 10) -> str:
        """Текстовий журнал подій захисту."""
        if not self._guard_events:
            return "✅ Подій захисту не було."
        events = list(reversed(self._guard_events[-limit:]))
        lines  = [f"🛡️ *Журнал захисту ({len(self._guard_events)} подій):*\n"]
        icons  = {"brownout": "⬇️", "overvolt": "⬆️", "overload": "🔌", "unknown": "⚡"}
        for ev in events:
            dt  = time.strftime("%d.%m %H:%M", time.localtime(ev.ts))
            ico = icons.get(ev.reason, "⚡")
            restored = ""
            if ev.restored_ts:
                dur = int(ev.restored_ts - ev.ts)
                restored = f" ♻️ відновлено через {dur}с"
            lines.append(
                f"{ico} `{dt}` {ev.reason.upper()} "
                f"`{ev.volts:.0f}V` `{ev.amps:.2f}A` `{ev.watts:.0f}W`{restored}"
            )
        return "\n".join(lines)

    # ════════════════════════════════════════════════════
    #  STATUS
    # ════════════════════════════════════════════════════

    def get_status(self) -> dict:
        if time.time() - self._cache_ts < 5 and self._cache:
            return self._cache
        with self._lock:
            r = self._fetch_status()
            if r.get("online"):
                self._cache    = r
                self._cache_ts = time.time()
            return r

    def _fetch_status(self) -> dict:
        base = {
            "online": False, "is_on": False,
            "nickname": "Tapo P110",
            "watts": 0.0, "volts": 0.0, "amps": 0.0, "total_wh": 0, "error": ""
        }
        if not _tcp_ok(self.ip):
            base["error"] = _diagnose_connection(self.ip)
            return base
        try:
            async def _do():
                dev  = await self._connect_async()
                info = await asyncio.wait_for(dev.get_device_info(), timeout=12)

                energy      = None
                current_pwr = None

                # Спроба 1: get_energy_usage (стандартний метод)
                try:
                    energy = await asyncio.wait_for(dev.get_energy_usage(), timeout=12)
                except Exception:
                    pass

                # Спроба 2: get_current_power (деякі версії прошивки)
                try:
                    current_pwr = await asyncio.wait_for(dev.get_current_power(), timeout=12)
                except Exception:
                    pass

                return info, energy, current_pwr

            info, energy, current_pwr = _run(_do())
            base["online"]   = True
            base["nickname"] = getattr(info, "nickname", None) or "Tapo P110"
            base["is_on"]    = getattr(info, "device_on", False)

            # ── Збираємо дані з усіх доступних джерел ──────────
            p = v = c = t = 0

            if energy:
                # Логуємо всі атрибути для діагностики (тільки один раз)
                if not getattr(self, "_energy_attrs_logged", False):
                    attrs = {k: getattr(energy, k) for k in dir(energy)
                             if not k.startswith("_") and not callable(getattr(energy, k))}
                    log.debug(f"[Tapo] energy attrs: {attrs}")
                    self._energy_attrs_logged = True

                p = getattr(energy, "current_power",    0) or 0
                t = getattr(energy, "today_energy",     0) or 0

                # Напруга і струм — різні назви атрибутів в різних версіях
                v = (getattr(energy, "voltage",          None) or
                     getattr(energy, "voltage_mv",       None) or
                     getattr(energy, "emeter_voltage",   None) or 0)
                c = (getattr(energy, "current",          None) or
                     getattr(energy, "current_ma",       None) or
                     getattr(energy, "emeter_current",   None) or 0)

            # get_current_power може мати напругу/струм там де get_energy_usage не має
            if current_pwr:
                if not getattr(self, "_cpwr_attrs_logged", False):
                    attrs = {k: getattr(current_pwr, k) for k in dir(current_pwr)
                             if not k.startswith("_") and not callable(getattr(current_pwr, k))}
                    log.debug(f"[Tapo] current_power attrs: {attrs}")
                    self._cpwr_attrs_logged = True

                if not p:
                    p = getattr(current_pwr, "current_power", 0) or 0
                if not v:
                    v = (getattr(current_pwr, "voltage",    None) or
                         getattr(current_pwr, "voltage_mv", None) or 0)
                if not c:
                    c = (getattr(current_pwr, "current",    None) or
                         getattr(current_pwr, "current_ma", None) or 0)

            # ── Конвертація одиниць ──────────────────────────────
            # Потужність: якщо > 230 → швидше за все mW
            watts = float(p)
            if watts > 230:
                watts = round(watts / 1000, 2)

            # Напруга: якщо > 300 → mV; якщо 0 → невідома
            volts = float(v)
            if volts > 300:
                volts = round(volts / 1000, 1)

            # Струм: якщо > 16 → mA; інакше A
            amps = float(c)
            if amps > 16:
                amps = round(amps / 1000, 3)

            # Якщо напруга 0 але є потужність і струм — вираховуємо
            if volts == 0 and watts > 0 and amps > 0:
                volts = round(watts / amps, 1)
            # Якщо струм 0 але є потужність і напруга — вираховуємо
            elif amps == 0 and watts > 0 and volts > 0:
                amps = round(watts / volts, 3)
            # Якщо є тільки потужність — напруга невідома, ставимо типову
            # (НЕ вигадуємо значення, залишаємо 0 щоб не вводити в оману)

            base["watts"]    = watts
            base["volts"]    = volts
            base["amps"]     = amps
            base["total_wh"] = t

        except Exception as e:
            base["error"] = str(e) or "Помилка з'єднання — виконай /tapo setup"
        return base

    def get_raw_debug(self) -> str:
        """Повертає всі сирі атрибути з API для діагностики."""
        if not _tcp_ok(self.ip):
            return f"❌ {self.ip} недоступний по TCP (порти 80/443/9999)"
        try:
            async def _do():
                lines = [f"🔬 *Tapo P110 Raw Debug* `{self.ip}`\n━━━━━━━━━━━━━━━━━━━━━\n"]

                # ── connect ──────────────────────────────
                try:
                    dev = await asyncio.wait_for(self._connect_async(), timeout=15)
                    lines.append(f"✅ З'єднання: `{self._method}`\n")
                except Exception as e:
                    lines.append(f"❌ З'єднання: `{e}`")
                    return "\n".join(lines)

                # ── device_info ───────────────────────────
                try:
                    info = await asyncio.wait_for(dev.get_device_info(), timeout=10)
                    lines.append("*device\\_info:*")
                    for k in sorted(dir(info)):
                        if k.startswith("_") or callable(getattr(info, k)):
                            continue
                        lines.append(f"  `{k}` = `{getattr(info, k)}`")
                except Exception as e:
                    lines.append(f"❌ device_info: `{e}`")

                lines.append("")

                # ── get_energy_usage ──────────────────────
                try:
                    energy = await asyncio.wait_for(dev.get_energy_usage(), timeout=10)
                    lines.append("*get\\_energy\\_usage:*")
                    for k in sorted(dir(energy)):
                        if k.startswith("_") or callable(getattr(energy, k)):
                            continue
                        lines.append(f"  `{k}` = `{getattr(energy, k)}`")
                except Exception as e:
                    lines.append(f"❌ get_energy_usage: `{e}`")

                lines.append("")

                # ── get_current_power ─────────────────────
                try:
                    cpwr = await asyncio.wait_for(dev.get_current_power(), timeout=10)
                    lines.append("*get\\_current\\_power:*")
                    for k in sorted(dir(cpwr)):
                        if k.startswith("_") or callable(getattr(cpwr, k)):
                            continue
                        lines.append(f"  `{k}` = `{getattr(cpwr, k)}`")
                except Exception as e:
                    lines.append(f"❌ get_current_power: `{e}`")

                return "\n".join(lines)

            # Загальний таймаут 40 секунд
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(
                    asyncio.wait_for(_do(), timeout=40)
                )
            finally:
                loop.close()

        except asyncio.TimeoutError:
            return "❌ *Таймаут 40с* — розетка не відповідає на запити API.\nПеревір логін/пароль в Tapo App."
        except Exception as e:
            return f"❌ Помилка: `{e}`"

    # ════════════════════════════════════════════════════
    #  FORMAT — ПОВІДОМЛЕННЯ ДЛЯ TELEGRAM
    # ════════════════════════════════════════════════════

    def format_status_message(self) -> str:
        s = self.get_status()

        if not s["online"]:
            err = s.get("error") or "Перевір IP та облікові дані"
            return (
                f"🔌 *Tapo P110 ({self.ip})*\n"
                f"━━━━━━━━━━━━━━━━━━━━━\n"
                f"❌ Недоступна\n_{err}_\n\n"
                f"_/tapo setup <IP> <email> <pass>_"
            )

        state = "✅ УВІМКНЕНА" if s["is_on"] else "⭕ ВИМКНЕНА"
        w = s["watts"]; v = s["volts"]; a = s["amps"]

        # Іконки стану напруги
        if v <= 0:
            volt_icon = "⚫"; volt_note = ""; volt_str = "— (немає даних)"
        elif v < self.guard.volt_min:
            volt_icon = "🔴"; volt_note = " ⚠️ BROWNOUT!"; volt_str = f"{v:.0f} V"
        elif v > self.guard.volt_max:
            volt_icon = "🔴"; volt_note = " ⚠️ OVERVOLT!"; volt_str = f"{v:.0f} V"
        elif v < self.guard.volt_warn_low:
            volt_icon = "🟡"; volt_note = " (низька)"; volt_str = f"{v:.0f} V"
        elif v > self.guard.volt_warn_high:
            volt_icon = "🟡"; volt_note = " (підвищена)"; volt_str = f"{v:.0f} V"
        else:
            volt_icon = "🟢"; volt_note = ""; volt_str = f"{v:.0f} V"

        amps_str = f"{a:.3f} A" if a > 0 else "— (немає даних)"

        pwr_icon = (
            "🔴" if w > self.guard.watt_max * 0.9 else
            "🟡" if w > self.guard.watt_max * 0.7 else
            "🟢" if w > 0.5 else "⚫"
        )

        guard_line = ""
        if self._guard_off:
            guard_line = f"\n🛡️ _Вимкнено захистом: {self._guard_reason}_"

        mon_status = "✅ активний" if self._monitor_running else "⚠️ зупинений"
        events_cnt = len(self._guard_events)

        wh   = s.get("total_wh", 0)
        cost = round(wh / 1000 * self.guard.price_per_kwh, 2)

        return (
            f"🔌 *{s['nickname']}* ({self.ip}) `[{self._method}]`\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"Стан: {state}{guard_line}\n\n"
            f"{pwr_icon} Потужність: `{w:.1f} W`\n"
            f"{volt_icon} Напруга:    `{volt_str}`{volt_note}\n"
            f"⚡ Струм:     `{amps_str}`\n"
            f"📊 Сьогодні: `{wh} Wh` ≈ `{cost} грн`\n\n"
            f"🛡️ Захист: ✅ | Монітор: {mon_status} | Подій: `{events_cnt}`\n\n"
            f"_/tapo on · /tapo off · /tapo stats · /tapo guard_"
        )

    def format_guard_message(self) -> str:
        g = self.guard
        restore   = "✅ увімкнено" if g.auto_restore else "❌ вимкнено"
        monitor   = "✅ активний" if self._monitor_running else "❌ зупинений"
        volt_prot = "✅" if g.volt_enabled else "❌"
        ovld_prot = "✅" if g.overload_enabled else "❌"
        return (
            f"🛡️ *Налаштування захисту Tapo P110*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n\n"
            f"⚡ *Напруга (захист {volt_prot}):*\n"
            f"  🔴 Критично: < `{g.volt_min:.0f}V` або > `{g.volt_max:.0f}V`\n"
            f"  🟡 Попередження: < `{g.volt_warn_low:.0f}V` або > `{g.volt_warn_high:.0f}V`\n\n"
            f"🔋 *Навантаження (захист {ovld_prot}):*\n"
            f"  Макс. струм: `{g.amp_max:.0f}A` | Макс. потужність: `{g.watt_max:.0f}W`\n\n"
            f"♻️ Авто-відновлення: {restore} (затримка `{g.restore_delay}с`)\n"
            f"🔄 Моніторинг: {monitor} (кожні `{g.monitor_interval}с`)\n"
            f"💰 Тариф: `{g.price_per_kwh} грн/кВт·год`\n\n"
            f"📋 *Зміна налаштувань:*\n"
            f"`/tapo guard volt 200 250` — критичні межі\n"
            f"`/tapo guard warn 210 240` — межі попереджень\n"
            f"`/tapo guard amp 10` — макс. струм\n"
            f"`/tapo guard restore on/off` — авто-відновлення\n"
            f"`/tapo guard price 4.32` — тариф грн/кВт·год"
        )

    def format_stats_message(self) -> str:
        st = self.get_stats()
        if not st:
            return (
                "📊 *Статистика недоступна*\n"
                "Немає даних — спочатку запусти моніторинг:\n"
                "`/tapo monitor on`"
            )
        period_h = round(st["period_min"] / 60, 1)
        stability_icon = (
            "🟢" if st["stability_pct"] >= 90 else
            "🟡" if st["stability_pct"] >= 70 else "🔴"
        )
        return (
            f"📊 *Статистика Tapo P110*\n"
            f"━━━━━━━━━━━━━━━━━━━━━\n"
            f"⏱️ Період: `{period_h:.1f} год` ({st['points']} замірів)\n\n"
            f"⚡ *Напруга:*\n"
            f"  Мін: `{st['volt_min']}V` | Макс: `{st['volt_max']}V` | Сер: `{st['volt_avg']}V`\n"
            f"  {stability_icon} Стабільність: `{st['stability_pct']}%`\n\n"
            f"💡 *Споживання:*\n"
            f"  Сер: `{st['watt_avg']}W` | Макс: `{st['watt_max']}W`\n"
            f"  Всього: `{st['total_wh']} Wh`\n"
            f"  Вартість: `{st['cost_uah']} грн` @ {self.guard.price_per_kwh} грн/кВт·год\n\n"
            f"🛡️ *Спрацювань захисту:* `{st['guard_events']}`\n"
            f"  ⬇️ Brownout: `{st['brownouts']}` | ⬆️ Overvolt: `{st['overvolts']}`\n"
            f"  🟡 Попереджень: `{st['warnings']}`\n\n"
            f"_/tapo voltage — графік напруги_\n"
            f"_/tapo guard events — журнал подій_"
        )


# ════════════════════════════════════════════════════════
#  TapoConfig — збереження налаштувань
# ════════════════════════════════════════════════════════
class TapoConfig:
    # __file__ = <ROOT>/app/hardware/tapo.py → піднімаємось на 3 рівні до ROOT
    _PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    DEFAULT_PATH = os.path.join(_PROJECT_ROOT, "data", "tapo_config.json")

    def __init__(self, path: str = DEFAULT_PATH):
        self.path = path
        # Переконуємось, що папка data/ існує
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._data = {}
        self.load()

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            self._data = {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            log.error(f"TapoConfig save: {e}")

    def get(self, key, default=None):
        return self._data.get(key, default)

    def set(self, key, value):
        self._data[key] = value
        self.save()

    def get_plug_params(self) -> dict:
        return {
            "ip":       self._data.get("ip",       ""),
            "email":    self._data.get("email",     ""),
            "password": self._data.get("password",  ""),
        }

    def is_configured(self) -> bool:
        return bool(self._data.get("ip") and self._data.get("email"))