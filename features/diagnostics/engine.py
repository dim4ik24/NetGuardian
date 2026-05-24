# core/diagnostics.py
"""
NetGuardian AI — Expert Diagnostic Engine
Rule-Based System з 100+ перевірок мережевих аномалій.
Патерн MVC: чистий бекенд без знання про UI.

v3.2 fix: фільтрація до активного адаптера — усунено хибні
          спрацьовування для WiFi-правил на Ethernet-підключеннях.

v3.3 PR #25: VPN-aware skip — при активному VPN правила що перевіряють
          фізичний канал/шлюз/APIPA пропускаються, бо VPN змінює маршрут
          і це не є реальною проблемою з фізичною мережею.
"""
import subprocess
import platform
import socket
import time
import re
import concurrent.futures
from dataclasses import dataclass, field
from typing import Callable, Optional


# ══════════════════════════════════════════════════════════
#   СТРУКТУРИ ДАНИХ
# ══════════════════════════════════════════════════════════

@dataclass
class Issue:
    code:    str
    sev:     str          # "CRITICAL" | "WARNING" | "INFO"
    group:   str
    title:   str
    desc:    str
    fix:     Optional[str] = None
    fix_lbl: Optional[str] = None


@dataclass
class RawData:
    """Сирі дані, зібрані паралельно перед аналізом."""
    ipconfig:    str  = ""
    route:       str  = ""
    netstat:     str  = ""
    wlan:        str  = ""
    firewall:    str  = ""
    winhttp:     str  = ""
    tcp_global:  str  = ""
    hosts_lines: list = field(default_factory=list)
    ping_lo:     tuple = (-1, 100)
    ping_gw:     tuple = (-1, 100)
    ping_cf:     tuple = (-1, 100)
    ping_google: tuple = (-1, 100)
    dns_ms:      int  = -1
    dns_ok:      bool = False
    local_ip:    str  = ""
    gateway_ip:  str  = ""
    mtu:         int  = 0
    # ── Нові поля v3.2 ────────────────────────────────────
    wifi_is_primary: bool = False  # True = WiFi є АКТИВНИМ підключенням
    is_vpn_active:   bool = False  # True = знайдено активну VPN-секцію
    active_section:  str  = ""     # секція ipconfig тільки для активного адаптера


# ══════════════════════════════════════════════════════════
#   ГОЛОВНИЙ КЛАС
# ══════════════════════════════════════════════════════════

class DiagnosticEngine:

    IS_WIN = platform.system() == "Windows"

    # ──────────────────────────────────────────────────────
    # УТИЛІТИ
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _run(cmd: list, timeout: int = 6) -> str:
        encodings = ("utf-8", "cp1251", "cp866", "latin-1")
        for enc in encodings:
            try:
                r = subprocess.run(
                    cmd, capture_output=True, text=True,
                    encoding=enc, errors="ignore", timeout=timeout)
                out = r.stdout + r.stderr
                if out.strip():
                    return out
            except subprocess.TimeoutExpired:
                return ""
            except Exception:
                continue
        try:
            r = subprocess.run(cmd, capture_output=True, timeout=timeout)
            raw = r.stdout + r.stderr
            for enc in encodings:
                try:
                    return raw.decode(enc, errors="ignore")
                except Exception:
                    continue
        except Exception:
            pass
        return ""

    @staticmethod
    def _ping(host: str, count: int = 4, timeout_ms: int = 1500) -> tuple:
        try:
            if platform.system() == "Windows":
                out = subprocess.run(
                    ["ping", "-n", str(count), "-w", str(timeout_ms), host],
                    capture_output=True,
                    timeout=count * (timeout_ms / 1000) + 5)
                raw = out.stdout + out.stderr
                text = ""
                for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
                    try:
                        text = raw.decode(enc, errors="ignore")
                        if text.strip():
                            break
                    except Exception:
                        continue
                m = re.search(
                    r"(?:Average|Среднее|Середнє)[^\d]*(\d+)\s*(?:ms|мс)", text, re.I)
                avg = int(m.group(1)) if m else -1
                lm = re.search(r"(\d+)%", text)
                loss = int(lm.group(1)) if lm else (100 if avg < 0 else 0)
            else:
                out = subprocess.run(
                    ["ping", "-c", str(count), "-W", "1", host],
                    capture_output=True, text=True, timeout=count + 5).stdout
                m = re.search(
                    r"min/avg/max[^\d]*([\d.]+)/([\d.]+)/([\d.]+)", out)
                avg = int(float(m.group(2))) if m else -1
                lm = re.search(r"(\d+)%\s*packet loss", out)
                loss = int(lm.group(1)) if lm else (100 if avg < 0 else 0)
            return avg, loss
        except Exception:
            return -1, 100

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except Exception:
            return ""

    @staticmethod
    def _get_gateway() -> str:
        try:
            if platform.system() == "Windows":
                raw = subprocess.run(
                    ["ipconfig"], capture_output=True, timeout=5)
                out = ""
                for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
                    try:
                        out = raw.stdout.decode(enc, errors="ignore")
                        if out.strip():
                            break
                    except Exception:
                        continue
                for line in out.splitlines():
                    if re.search(
                            r"Default Gateway|Основний шлюз|Основной шлюз", line, re.I):
                        ip = line.split(":")[-1].strip()
                        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                            return ip
            else:
                out = subprocess.run(
                    ["ip", "route"], capture_output=True, text=True, timeout=5).stdout
                for line in out.splitlines():
                    if line.startswith("default"):
                        return line.split()[2]
        except Exception:
            pass
        return "192.168.1.1"

    @staticmethod
    def _get_mtu() -> int:
        try:
            if platform.system() == "Windows":
                out = DiagnosticEngine._run(
                    ["netsh", "interface", "ipv4", "show", "subinterfaces"])
                nums = re.findall(r"\b(1[0-9]{3})\b", out)
                if nums:
                    return int(nums[0])
            else:
                out = subprocess.run(
                    ["ip", "link"], capture_output=True, text=True, timeout=5).stdout
                m = re.search(r"mtu (\d+)", out)
                if m:
                    return int(m.group(1))
        except Exception:
            pass
        return 0

    # ──────────────────────────────────────────────────────
    # ВИЗНАЧЕННЯ АКТИВНОГО АДАПТЕРА  (v3.2)
    # ──────────────────────────────────────────────────────

    @staticmethod
    def _parse_active_adapter(rd: "RawData") -> None:
        """
        Заповнює rd.wifi_is_primary, rd.active_section та rd.is_vpn_active.

        Логіка:
        1. Витягуємо з ipconfig секції, що містять local_ip.
        2. Пропускаємо VPN-секції (Radmin/OpenVPN/WireGuard...).
        3. Визначаємо тип активного фізичного адаптера.
        4. Якщо знайдено VPN-секцію — позначаємо is_vpn_active=True.
        """
        # ── VPN-ключові слова у назвах адаптерів ──
        VPN_KEYWORDS = re.compile(
            r"radmin|openvpn|wireguard|tap-|tunnel|tailscale|"
            r"zerotier|vpn|hamachi|softether|"
            r"ppp|l2tp|pptp|ikev2",
            re.IGNORECASE
        )

        # ── Витягуємо ВСІ секції адаптерів ──────────────
        active_section = ""
        vpn_section    = ""
        if rd.ipconfig:
            blocks = re.split(r"\r?\n(?=\S)", rd.ipconfig)
            for block in blocks:
                # Перший рядок — назва адаптера
                first_line = block.split("\n", 1)[0].lower()
                is_vpn = bool(VPN_KEYWORDS.search(first_line))

                # Якщо у секції є локальний IP — це активна
                if rd.local_ip and rd.local_ip in block:
                    if is_vpn:
                        vpn_section = block
                    else:
                        active_section = block
                # Якщо local_ip не вказаний, беремо першу не-VPN секцію
                # з gateway
                elif not active_section and not is_vpn:
                    if re.search(r"Default Gateway|Шлюз", block, re.I):
                        if not re.search(r":\s*$", block.strip().split("\n")[-1]):
                            active_section = block

        # Якщо знайшли тільки VPN-секцію, але не фізичну — спробуємо
        # знайти будь-яку фізичну секцію з заповненим Default Gateway
        if not active_section and rd.ipconfig:
            blocks = re.split(r"\r?\n(?=\S)", rd.ipconfig)
            for block in blocks:
                first_line = block.split("\n", 1)[0].lower()
                if VPN_KEYWORDS.search(first_line):
                    continue
                if re.search(r"(?:Default Gateway|Основн[иі]й шлюз)"
                             r"[^:]*:\s*\d+\.\d+\.\d+\.\d+",
                             block, re.I):
                    active_section = block
                    break

        rd.active_section = active_section if active_section else rd.ipconfig
        rd.is_vpn_active  = bool(vpn_section)

        # PR #25: Додаткова перевірка через UI state (vpn_ui._ext_vpn_state)
        # Якщо vpn_ui визначив що VPN активний по IP-зміні — довіряємо йому.
        if not rd.is_vpn_active:
            try:
                import sys
                for mod_name in ("main", "app.main"):
                    mod = sys.modules.get(mod_name)
                    if mod and hasattr(mod, "vpn_page"):
                        vpn_page = getattr(mod, "vpn_page", None)
                        if (vpn_page and hasattr(vpn_page, "_ext_vpn_state")
                                and vpn_page._ext_vpn_state.get("active")):
                            rd.is_vpn_active = True
                            break
            except Exception:
                pass

        # ── Визначаємо тип активного адаптера ────────────────
        wifi_keywords = re.compile(
            r"Wireless|Wi-Fi|WLAN|беспровод|бездроти", re.I)

        if active_section and wifi_keywords.search(active_section):
            if rd.wlan:
                rd.wifi_is_primary = bool(
                    re.search(r"State\s*[:\s]+connected", rd.wlan, re.I))
            else:
                rd.wifi_is_primary = True
        else:
            rd.wifi_is_primary = False

    # ──────────────────────────────────────────────────────
    # ЗБІР ДАНИХ (паралельно)
    # ──────────────────────────────────────────────────────

    def collect_data(self, gateway_ip: str) -> RawData:
        rd = RawData()
        rd.gateway_ip = gateway_ip or self._get_gateway()
        rd.local_ip   = self._get_local_ip()

        def _ipconfig():
            rd.ipconfig = self._run(["ipconfig", "/all"])

        def _route():
            rd.route = self._run(
                ["route", "print"] if self.IS_WIN else ["ip", "route"])

        def _netstat():
            rd.netstat = self._run(["netstat", "-an"])

        def _wlan():
            if self.IS_WIN:
                rd.wlan = self._run(["netsh", "wlan", "show", "interfaces"])

        def _firewall():
            if self.IS_WIN:
                rd.firewall = self._run(
                    ["netsh", "advfirewall", "show", "allprofiles", "state"])

        def _winhttp():
            if self.IS_WIN:
                rd.winhttp = self._run(["netsh", "winhttp", "show", "proxy"])

        def _tcp_global():
            if self.IS_WIN:
                rd.tcp_global = self._run(
                    ["netsh", "int", "tcp", "show", "global"])

        def _hosts():
            p = (r"C:\Windows\System32\drivers\etc\hosts"
                 if self.IS_WIN else "/etc/hosts")
            try:
                with open(p, "r", errors="ignore") as f:
                    rd.hosts_lines = [
                        ln.strip() for ln in f
                        if ln.strip() and not ln.strip().startswith("#")]
            except Exception:
                rd.hosts_lines = []

        def _ping_lo():
            rd.ping_lo = self._ping("127.0.0.1", count=3, timeout_ms=500)

        def _ping_gw():
            rd.ping_gw = self._ping(rd.gateway_ip, count=4)

        def _ping_cf():
            rd.ping_cf = self._ping("1.1.1.1", count=4)

        def _ping_google():
            rd.ping_google = self._ping("8.8.8.8", count=4)

        def _dns():
            try:
                t0 = time.perf_counter()
                socket.gethostbyname("google.com")
                rd.dns_ms = int((time.perf_counter() - t0) * 1000)
                rd.dns_ok = True
            except Exception:
                rd.dns_ms = -1
                rd.dns_ok = False

        def _mtu():
            rd.mtu = self._get_mtu()

        tasks = [
            _ipconfig, _route, _netstat, _wlan,
            _firewall, _winhttp, _tcp_global, _hosts,
            _ping_lo, _ping_gw, _ping_cf, _ping_google,
            _dns, _mtu,
        ]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(tasks)) as ex:
            concurrent.futures.wait([ex.submit(t) for t in tasks])

        # Визначаємо активний адаптер ПІСЛЯ збору даних
        self._parse_active_adapter(rd)

        return rd

    # ──────────────────────────────────────────────────────
    # МАСИВ ПРАВИЛ (100+ перевірок)
    # ──────────────────────────────────────────────────────

    def _build_rules(self) -> list:
        rules = []

        def rule(label):
            def decorator(fn):
                rules.append((label, fn))
                return fn
            return decorator

        # ════════════════════════════════════════════════
        # ГРУПА 1: Фізичний рівень та ОС (L1)
        # ════════════════════════════════════════════════

        @rule("L1 · TCP/IP Loopback (127.0.0.1)")
        def _(rd: RawData):
            if rd.ping_lo[0] < 0:
                return Issue("L1-01", "CRITICAL", "L1 Фізичний",
                    "TCP/IP Stack пошкоджено",
                    "Ping 127.0.0.1 не відповідає. Мережева карта вимкнена або стек ОС пошкоджений.",
                    "reset_tcp_ip", "🔧 Скинути Winsock")

        @rule("L1 · APIPA адреса (169.254.x.x)")
        def _(rd: RawData):
            # PR #25: При активному VPN local_ip може бути VPN-адресою —
            # APIPA-перевірка не релевантна (фізичний DHCP працює інакше).
            if rd.is_vpn_active:
                return None
            # rd.local_ip — IP активного адаптера (визначений через socket)
            if rd.local_ip.startswith("169.254."):
                return Issue("L1-02", "CRITICAL", "L1 Фізичний",
                    "APIPA адреса — DHCP не відповів",
                    f"IP: {rd.local_ip}. DHCP сервер не видав адресу. Перевір кабель або роутер.",
                    "dhcp_renew", "🔧 Оновити IP")

        @rule("L1 · Media disconnected (активний адаптер)")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: перевіряємо тільки якщо немає зв'язку взагалі.
            # Якщо роутер або інтернет відповідає — якийсь адаптер працює,
            # "Media disconnected" на іншому адаптері не є проблемою.
            if rd.ping_gw[0] >= 0 or rd.ping_cf[0] >= 0 or rd.ping_lo[0] >= 0:
                return None  # є робоче з'єднання — ігноруємо
            # PR #25: При активному VPN не показуємо "media disconnected"
            # бо фізичний адаптер може бути disconnected, а VPN-туннель працює
            if rd.is_vpn_active:
                return None
            if re.search(
                    r"Media disconnected|Среда передачи данных отключена|Носій відключено",
                    rd.active_section, re.I):
                return Issue("L1-03", "CRITICAL", "L1 Фізичний",
                    "Мережевий адаптер: Media disconnected",
                    "Фізичне з'єднання відсутнє. Перевір кабель або Wi-Fi.")

        @rule("L1 · Wi-Fi сигнал < 30% (критично)")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ підключенням
            if not rd.wifi_is_primary:
                return None
            m = re.search(r"Signal\s*[:=]\s*(\d+)%", rd.wlan, re.I)
            if m and int(m.group(1)) < 30:
                return Issue("L1-04", "CRITICAL", "L1 Wi-Fi",
                    f"Критично слабкий Wi-Fi сигнал: {m.group(1)}%",
                    "Сигнал менше 30%. Очікуй постійних дисконектів і дуже повільного з'єднання.")

        @rule("L1 · Wi-Fi сигнал 30–50% (попередження)")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ підключенням
            if not rd.wifi_is_primary:
                return None
            m = re.search(r"Signal\s*[:=]\s*(\d+)%", rd.wlan, re.I)
            if m and 30 <= int(m.group(1)) <= 50:
                return Issue("L1-05", "WARNING", "L1 Wi-Fi",
                    f"Слабкий Wi-Fi сигнал: {m.group(1)}%",
                    "Сигнал 30–50%. Можливі лаги. Наблизься до роутера або зменш перешкоди.")

        @rule("L1 · Відкрита Wi-Fi мережа (без пароля)")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ підключенням
            if not rd.wifi_is_primary:
                return None
            if re.search(r"Authentication\s*[:=]\s*Open", rd.wlan, re.I):
                return Issue("L1-06", "WARNING", "L1 Безпека",
                    "Підключено до відкритої Wi-Fi мережі",
                    "Ризик MITM. Увесь трафік може перехоплюватись зловмисниками.")

        @rule("L1 · IP-конфлікт у підмережі")
        def _(rd: RawData):
            # Перевіряємо тільки активну секцію
            if re.search(r"conflict|конфлікт|конфликт|duplicate",
                         rd.active_section, re.I):
                return Issue("L1-07", "CRITICAL", "L1 Фізичний",
                    "Дублювання IP-адрес (IP Conflict)",
                    "Дві машини мають однаковий IP. Інтернет буде нестабільним.",
                    "dhcp_renew", "🔧 Оновити IP")

        @rule("L1 · Кілька активних шлюзів")
        def _(rd: RawData):
            # PR #25: При активному VPN — другий шлюз це VPN-сервер, це нормально
            if rd.is_vpn_active:
                return None
            # Перевіряємо тільки активну секцію
            gws = re.findall(
                r"(?:Default Gateway|Основний шлюз|Основной шлюз)\s*[:.]\s*(\d+\.\d+\.\d+\.\d+)",
                rd.active_section, re.I)
            real = [g for g in gws if g != "0.0.0.0"]
            if len(set(real)) > 1:
                return Issue("L1-08", "WARNING", "L1 Маршрутизація",
                    f"Кілька активних шлюзів: {', '.join(set(real))}",
                    "Конфлікт маршрутів. Може спричиняти нестабільне з'єднання.")

        @rule("L1 · Адаптер вимкнено адміністратором")
        def _(rd: RawData):
            # Тільки якщо немає зв'язку
            if rd.ping_gw[0] >= 0 or rd.ping_cf[0] >= 0:
                return None
            if re.search(r"administratively down|admin down", rd.ipconfig, re.I):
                return Issue("L1-09", "CRITICAL", "L1 Фізичний",
                    "Мережевий адаптер вимкнено адміністратором",
                    "Адаптер відключений вручну або груповою політикою.")

        @rule("L1 · IPv4 адреса відсутня (є loopback)")
        def _(rd: RawData):
            # PR #25: При активному VPN local_ip може містити VPN-IP
            if rd.is_vpn_active:
                return None
            if not rd.local_ip and rd.ping_lo[0] >= 0:
                return Issue("L1-10", "CRITICAL", "L1 Фізичний",
                    "IPv4 адреса відсутня",
                    "TCP/IP стек живий, але DHCP не видав адресу.",
                    "dhcp_renew", "🔧 Оновити IP")

        @rule("L1 · Loopback затримка > 5 мс")
        def _(rd: RawData):
            if rd.ping_lo[0] > 5:
                return Issue("L1-11", "INFO", "L1 TCP/IP",
                    f"Підвищена затримка loopback: {rd.ping_lo[0]} мс",
                    "Loopback має відповідати < 1 мс. Можливе навантаження CPU або вірус.")

        @rule("L1 · Відсутній DNS suffix")
        def _(rd: RawData):
            # Перевіряємо тільки активну секцію
            has_field = bool(re.search(
                r"Connection-specific DNS Suffix", rd.active_section, re.I))
            has_value = bool(re.search(
                r"Connection-specific DNS Suffix\s*\.\s*:\s*\S", rd.active_section, re.I))
            if has_field and not has_value:
                return Issue("L1-12", "INFO", "L1 Конфігурація",
                    "DNS суфікс не налаштований",
                    "Пусте поле DNS Suffix може ускладнювати резолвінг у корпоративних мережах.")

        @rule("L1 · Wi-Fi у режимі Ad-Hoc")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ
            if not rd.wifi_is_primary:
                return None
            if re.search(r"Network type\s*:\s*(Ad|IBSS)", rd.wlan, re.I):
                return Issue("L1-13", "WARNING", "L1 Wi-Fi",
                    "Wi-Fi у режимі Ad-Hoc (P2P)",
                    "Ad-Hoc мережа без роутера. Немає захисту та повільне з'єднання.")

        @rule("L1 · Wi-Fi стандарт 802.11b/g (застарілий)")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ
            if not rd.wifi_is_primary:
                return None
            if re.search(r"Radio type\s*[:=]\s*802\.11[bg]\b", rd.wlan, re.I):
                return Issue("L1-14", "INFO", "L1 Wi-Fi",
                    "Застарілий Wi-Fi стандарт (802.11b/g)",
                    "Максимум 54 Мбіт/с. Переключись на 802.11n/ac/ax для кращої швидкості.")

        @rule("L1 · Wi-Fi канал нестандартний")
        def _(rd: RawData):
            # ВИПРАВЛЕННЯ v3.2: тільки якщо WiFi є АКТИВНИМ
            if not rd.wifi_is_primary:
                return None
            m = re.search(r"Channel\s*[:=]\s*(\d+)", rd.wlan, re.I)
            if m and int(m.group(1)) not in (1, 6, 11, 36, 40, 44, 48):
                return Issue("L1-15", "INFO", "L1 Wi-Fi",
                    f"Нестандартний Wi-Fi канал: {m.group(1)}",
                    "Рекомендовані канали 2.4 ГГц: 1, 6, 11. Інші перекриваються.")

        # ════════════════════════════════════════════════
        # ГРУПА 2: Маршрутизація та Провайдер (L3)
        # ════════════════════════════════════════════════

        @rule("L3 · WAN down (шлюз є, провайдер немає)")
        def _(rd: RawData):
            if rd.ping_gw[0] >= 0 and rd.ping_cf[0] < 0:
                return Issue("L3-01", "CRITICAL", "L3 WAN/Провайдер",
                    "Роутер OK — провайдер недоступний",
                    "Ping 1.1.1.1 провалився. 100% проблема на стороні ISP або обрив WAN.")

        @rule("L3 · Відсутній Default Route (0.0.0.0)")
        def _(rd: RawData):
            if rd.ping_lo[0] >= 0 and not re.search(r"0\.0\.0\.0\s+0\.0\.0\.0", rd.route):
                return Issue("L3-02", "CRITICAL", "L3 Маршрутизація",
                    "Відсутній маршрут за замовчуванням",
                    "Таблиця маршрутизації без запису 0.0.0.0. Пакети не знають куди йти.",
                    "reset_tcp_ip", "🔧 Скинути TCP/IP")

        @rule("L3 · Packet Loss до шлюзу 5–30%")
        def _(rd: RawData):
            # PR #25: При VPN шлюз може бути VPN-server, ICMP до нього часто блокується
            if rd.is_vpn_active:
                return None
            loss = rd.ping_gw[1]
            if rd.ping_gw[0] >= 0 and 5 < loss <= 30:
                return Issue("L3-03", "WARNING", "L3 LAN",
                    f"Втрата пакетів до роутера: {loss}%",
                    "Поганий кабель, Wi-Fi перешкоди або перевантажений роутер.")

        @rule("L3 · Packet Loss до шлюзу > 30% (критично)")
        def _(rd: RawData):
            # PR #25: При VPN шлюз може бути VPN-server, ICMP до нього часто блокується
            if rd.is_vpn_active:
                return None
            loss = rd.ping_gw[1]
            if rd.ping_gw[0] >= 0 and loss > 30:
                return Issue("L3-04", "CRITICAL", "L3 LAN",
                    f"Критична втрата пакетів до роутера: {loss}%",
                    "З'єднання з роутером нестабільне. Замінь кабель або перезапусти адаптер.")

        @rule("L3 · Packet Loss до 8.8.8.8 > 10%")
        def _(rd: RawData):
            loss = rd.ping_google[1]
            if rd.ping_google[0] >= 0 and loss > 10:
                return Issue("L3-05", "WARNING", "L3 WAN",
                    f"Втрата пакетів до Google DNS: {loss}%",
                    "Проблема на магістральній лінії провайдера або пірингу.")

        @rule("L3 · Пінг до шлюзу 50–200 мс")
        def _(rd: RawData):
            # PR #25: При VPN шлюз = VPN-сервер, висока затримка це нормально
            if rd.is_vpn_active:
                return None
            ms = rd.ping_gw[0]
            if 50 < ms <= 200:
                return Issue("L3-06", "WARNING", "L3 LAN",
                    f"Висока затримка до роутера: {ms} мс",
                    "Перевантажений роутер, Wi-Fi перешкоди або поганий кабель.")

        @rule("L3 · Пінг до шлюзу > 200 мс (критично)")
        def _(rd: RawData):
            # PR #25: При VPN шлюз = VPN-сервер, висока затримка це нормально
            if rd.is_vpn_active:
                return None
            ms = rd.ping_gw[0]
            if ms > 200:
                return Issue("L3-07", "CRITICAL", "L3 LAN",
                    f"Критична затримка до роутера: {ms} мс",
                    "Роутер перевантажений або Wi-Fi сигнал критично слабкий.")

        @rule("L3 · Пінг до провайдера > 150 мс")
        def _(rd: RawData):
            ms = rd.ping_cf[0]
            if ms > 150:
                return Issue("L3-08", "WARNING", "L3 WAN",
                    f"Глобальна затримка до Cloudflare: {ms} мс",
                    "Перевантажені вузли провайдера або проблема на магістралі.")

        @rule("L3 · MTU < 1400 (фрагментація пакетів)")
        def _(rd: RawData):
            if 576 <= rd.mtu < 1400:
                return Issue("L3-09", "WARNING", "L3 MTU",
                    f"Нестандартний MTU: {rd.mtu} байт",
                    "MTU < 1400 викликає фрагментацію пакетів і уповільнює з'єднання.",
                    "fix_mtu", "🔧 Встановити MTU 1500")

        @rule("L3 · MTU < 576 (критично малий)")
        def _(rd: RawData):
            if 0 < rd.mtu < 576:
                return Issue("L3-10", "CRITICAL", "L3 MTU",
                    f"Критично малий MTU: {rd.mtu} байт",
                    "MTU нижче RFC 791 мінімуму (576). З'єднання майже непрацездатне.",
                    "fix_mtu", "🔧 Встановити MTU 1500")

        @rule("L3 · Double NAT")
        def _(rd: RawData):
            gw = rd.gateway_ip
            private = re.compile(
                r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")
            next_hop_m = re.search(r"0\.0\.0\.0\s+0\.0\.0\.0\s+(\S+)", rd.route)
            if private.match(gw) and next_hop_m:
                nh = next_hop_m.group(1)
                if private.match(nh) and nh != gw:
                    return Issue("L3-11", "WARNING", "L3 Маршрутизація",
                        f"Double NAT виявлено: {gw} → {nh}",
                        "Два шари NAT збільшують затримку та ламають P2P, VoIP, VPN.")

        @rule("L3 · Роутер недоступний (шлюз не пінгується)")
        def _(rd: RawData):
            if rd.ping_gw[0] < 0:
                # PR #25: при активному VPN — це норма, ICMP блокується
                if rd.is_vpn_active:
                    return None  # повна тиша при VPN, не спамимо
                # ФІКС VPN: якщо інтернет ОК — шлюз "недоступний" може бути
                # тому що ми пінгуємо VPN-шлюз (26.0.0.1) який обмежує ICMP,
                # а фізичний шлюз вже працює. Не показуємо це як CRITICAL.
                if rd.ping_cf[0] >= 0 or rd.ping_google[0] >= 0:
                    # Інтернет є, але шлюз не пінгується — не критично
                    return Issue("L3-12c", "INFO", "L3 LAN",
                        f"Шлюз {rd.gateway_ip} блокує ICMP "
                        "(але інтернет працює)",
                        "Деякі роутери блокують ping. "
                        "Це не впливає на функціональність.")
                # Інтернет теж недоступний — РЕАЛЬНА проблема
                return Issue("L3-12", "CRITICAL", "L3 LAN",
                    f"Роутер {rd.gateway_ip} недоступний",
                    "Кабель відійшов, роутер завис або Wi-Fi вимкнено.",
                    "dhcp_renew", "🔧 Оновити IP")

        @rule("L3 · 8.8.8.8 недоступний (але 1.1.1.1 OK)")
        def _(rd: RawData):
            if rd.ping_cf[0] >= 0 and rd.ping_google[0] < 0:
                return Issue("L3-13", "WARNING", "L3 WAN",
                    "8.8.8.8 (Google DNS) недоступний, 1.1.1.1 OK",
                    "Провайдер блокує Google або проблема в пірингу з Google.")

        @rule("L3 · Підозріло малий пінг до 1.1.1.1 (< 5 мс)")
        def _(rd: RawData):
            if 0 < rd.ping_cf[0] < 5:
                return Issue("L3-14", "INFO", "L3 WAN",
                    f"Пінг до 1.1.1.1 підозріло малий: {rd.ping_cf[0]} мс",
                    "Можлива підміна DNS або MITM — хтось локально відповідає замість Cloudflare.")

        @rule("L3 · Повна відсутність зв'язку (total blackout)")
        def _(rd: RawData):
            # PR #25: При VPN навіть якщо фізичний gw не відповідає —
            # VPN-тунель може працювати, тому не показуємо "total blackout"
            if rd.is_vpn_active:
                return None
            if rd.ping_lo[0] >= 0 and rd.ping_gw[0] < 0 and rd.ping_cf[0] < 0:
                return Issue("L3-15", "CRITICAL", "L3 LAN",
                    "Повна відсутність мережевого зв'язку",
                    "Loopback живий, але ні роутер ні інтернет недоступні. Перевір кабель/Wi-Fi.",
                    "dhcp_renew", "🔧 Оновити IP")

        @rule("L3 · MTU 1492 (можливо PPPoE)")
        def _(rd: RawData):
            if rd.mtu == 1492:
                return Issue("L3-16", "INFO", "L3 MTU",
                    "MTU 1492 — типово для PPPoE з'єднань",
                    "Якщо у тебе не PPPoE — рекомендується встановити MTU 1500.",
                    "fix_mtu", "🔧 Встановити MTU 1500")

        @rule("L3 · Велика різниця пінгу GW↔CF (довгий маршрут)")
        def _(rd: RawData):
            # PR #25: При VPN gw_ms часто = 0 (блокується ICMP), різниця неінформативна
            if rd.is_vpn_active:
                return None
            cf_ms = rd.ping_cf[0]
            gw_ms = rd.ping_gw[0]
            if cf_ms > 0 and gw_ms > 0 and (cf_ms - gw_ms) > 300:
                return Issue("L3-17", "WARNING", "L3 WAN",
                    f"Велика різниця пінгу GW↔CF: {cf_ms - gw_ms} мс",
                    "Маршрут до провайдера дуже довгий або є вузькі місця на магістралі.")

        # ════════════════════════════════════════════════
        # ГРУПА 3: DNS Аномалії (L4)
        # ════════════════════════════════════════════════

        @rule("L4 · DNS не резолвує (IP-зв'язок є)")
        def _(rd: RawData):
            if rd.ping_cf[0] >= 0 and not rd.dns_ok:
                return Issue("L4-01", "CRITICAL", "L4 DNS",
                    "DNS не резолвує google.com (IP-зв'язок є)",
                    "Інтернет є, але DNS сервер не відповідає. Сайти не відкриватимуться.",
                    "set_fast_dns", "🔧 Cloudflare 1.1.1.1")

        @rule("L4 · DNS критично повільний (> 500 мс)")
        def _(rd: RawData):
            if rd.dns_ok and rd.dns_ms > 500:
                return Issue("L4-02", "CRITICAL", "L4 DNS",
                    f"DNS критично повільний: {rd.dns_ms} мс",
                    "DNS сервер провайдера перевантажений. Серфінг буде дуже повільним.",
                    "set_fast_dns", "🔧 Cloudflare 1.1.1.1")

        @rule("L4 · DNS повільний (200–500 мс)")
        def _(rd: RawData):
            if rd.dns_ok and 200 < rd.dns_ms <= 500:
                return Issue("L4-03", "WARNING", "L4 DNS",
                    f"Повільний DNS: {rd.dns_ms} мс",
                    "DNS провайдера відповідає повільно. Рекомендується Cloudflare 1.1.1.1.",
                    "set_fast_dns", "🔧 Cloudflare 1.1.1.1")

        @rule("L4 · DNS помірно повільний (100–200 мс)")
        def _(rd: RawData):
            if rd.dns_ok and 100 < rd.dns_ms <= 200:
                return Issue("L4-04", "INFO", "L4 DNS",
                    f"DNS відповідає {rd.dns_ms} мс",
                    "Прийнятно, але Cloudflare 1.1.1.1 зазвичай відповідає < 30 мс.",
                    "set_fast_dns", "🔧 Cloudflare 1.1.1.1")

        @rule("L4 · Підозрілий файл hosts (Malware)")
        def _(rd: RawData):
            bad = [
                ln for ln in rd.hosts_lines
                if any(d in ln.lower() for d in
                       ["google", "microsoft", "windows", "avast",
                        "kaspersky", "norton", "bitdefender"])
                and not ln.startswith(("0.0.0.0", "127.", "::1"))
            ]
            if bad:
                return Issue("L4-05", "CRITICAL", "L4 DNS / Безпека",
                    f"Підозрілий hosts! {len(bad)} записів-перенаправлень",
                    f"Ознака Malware. Приклад: {bad[0][:60]}")

        @rule("L4 · DNS кеш > 500 записів")
        def _(rd: RawData):
            if not DiagnosticEngine.IS_WIN:
                return None
            try:
                out = DiagnosticEngine._run(["ipconfig", "/displaydns"], timeout=12)
                count = out.count("Record Name")
                if count > 500:
                    return Issue("L4-06", "WARNING", "L4 DNS",
                        f"Великий кеш DNS: {count} записів",
                        "Роздутий кеш може гальмувати резолвінг. Рекомендується очистити.",
                        "flush_dns", "🔧 Очистити DNS кеш")
            except Exception:
                pass

        @rule("L4 · DNS провайдера замість надійних серверів")
        def _(rd: RawData):
            safe = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4",
                    "9.9.9.9", "149.112.112.112", "208.67.222.222"}
            servers = re.findall(
                r"(?:DNS Servers|DNS-сервери|DNS-серверы)\s*[:.]+\s*([\d.]+)",
                rd.active_section, re.I)
            if servers and not any(s in safe for s in servers):
                return Issue("L4-07", "INFO", "L4 DNS",
                    f"DNS провайдера: {', '.join(servers)}",
                    "Провайдерські DNS логують запити та можуть цензурувати сайти.",
                    "set_fast_dns", "🔧 Cloudflare 1.1.1.1")

        @rule("L4 · Hosts-файл з адблоком (> 50 записів)")
        def _(rd: RawData):
            adblock_patterns = [
                "ads.", "tracker.", "telemetry.", "analytics.",
                "doubleclick", "googletagmanager", "adservice"]
            count = sum(1 for ln in rd.hosts_lines
                        if any(p in ln.lower() for p in adblock_patterns))
            if count > 50:
                return Issue("L4-08", "INFO", "L4 Конфігурація",
                    f"hosts-файл містить {count} блокувань реклами/трекерів",
                    "Hosts-based адблок активний. Нормально, якщо ти це налаштував.")

        @rule("L4 · DNS over HTTPS не налаштований (Windows)")
        def _(rd: RawData):
            if not DiagnosticEngine.IS_WIN:
                return None
            try:
                out = subprocess.run(
                    ["reg", "query",
                     r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
                     "/v", "EnableAutoDoh"],
                    capture_output=True, text=True, timeout=3).stdout
                if "0x0" in out or not out.strip():
                    return Issue("L4-09", "INFO", "L4 Приватність",
                        "DNS over HTTPS (DoH) не налаштований",
                        "DNS запити передаються відкритим текстом. "
                        "Провайдер бачить усі сайти які ти відвідуєш.")
            except Exception:
                pass

        @rule("L4 · Дублюючий DNS сервер у налаштуваннях")
        def _(rd: RawData):
            servers = re.findall(
                r"(?:DNS Servers|DNS-сервери|DNS-серверы)\s*[:.]+\s*([\d.]+)",
                rd.active_section, re.I)
            if len(servers) != len(set(servers)):
                return Issue("L4-10", "INFO", "L4 DNS",
                    "Дублюючі DNS сервери в налаштуваннях",
                    "Один і той самий DNS прописаний двічі. Це зайве, але не критично.")

        # ════════════════════════════════════════════════
        # ГРУПА 4: Безпека та Налаштування (L7)
        # ════════════════════════════════════════════════

        @rule("L7 · Windows Firewall вимкнено")
        def _(rd: RawData):
            out = rd.firewall.upper()
            if DiagnosticEngine.IS_WIN and re.search(r"\bOFF\b|\bВИМК|\bОТКЛ", out):
                return Issue("L7-01", "WARNING", "L7 Безпека",
                    "Windows Firewall вимкнено",
                    "Комп'ютер вразливий до атак з локальної мережі та інтернету.",
                    "enable_firewall", "🔧 Увімкнути Firewall")

        @rule("L7 · Активний WinHTTP Proxy")
        def _(rd: RawData):
            if (DiagnosticEngine.IS_WIN and
                    re.search(r"Proxy Server", rd.winhttp, re.I) and
                    not re.search(r"Direct access|no proxy", rd.winhttp, re.I)):
                return Issue("L7-02", "WARNING", "L7 Безпека",
                    "Активний WinHTTP Proxy",
                    "Трафік проходить через проксі. Можливе перехоплення Malware.",
                    "disable_proxy", "🔧 Скинути Proxy")

        @rule("L7 · Порт 23 Telnet (LISTENING)")
        def _(rd: RawData):
            if re.search(r"\b0\.0\.0\.0:23\b|:::23\b", rd.netstat):
                return Issue("L7-03", "CRITICAL", "L7 Безпека",
                    "Відкритий порт Telnet (23)",
                    "Telnet передає дані відкритим текстом. Негайно закрий.")

        @rule("L7 · Порт 23 Telnet (ESTABLISHED)")
        def _(rd: RawData):
            if re.search(r":23\s+ESTABLISHED", rd.netstat):
                return Issue("L7-04", "CRITICAL", "L7 Безпека",
                    "Активне Telnet з'єднання",
                    "Хтось підключений через небезпечний Telnet протокол.")

        @rule("L7 · Порт 21 FTP (LISTENING)")
        def _(rd: RawData):
            if re.search(r"\b0\.0\.0\.0:21\b|:::21\b", rd.netstat):
                return Issue("L7-05", "WARNING", "L7 Безпека",
                    "Відкритий порт FTP (21)",
                    "FTP передає паролі відкритим текстом. Замінити на SFTP.")

        @rule("L7 · Порт 4444 (Metasploit backdoor, LISTENING)")
        def _(rd: RawData):
            if re.search(r"\b:4444\b.*LISTEN", rd.netstat):
                return Issue("L7-06", "CRITICAL", "L7 Безпека",
                    "Відкритий порт 4444 (backdoor Metasploit)",
                    "Стандартний backdoor порт. Можливе зараження системи.")

        @rule("L7 · Порт 4444 (ESTABLISHED)")
        def _(rd: RawData):
            if re.search(r":4444\s+ESTABLISHED", rd.netstat):
                return Issue("L7-07", "CRITICAL", "L7 Безпека",
                    "Активне з'єднання на backdoor-порті 4444",
                    "Зовнішнє з'єднання на порті 4444. Вірогідне зараження трояном.")

        @rule("L7 · Порт 31337 (BackOrifice троян)")
        def _(rd: RawData):
            if re.search(r"\b:31337\b", rd.netstat):
                return Issue("L7-08", "CRITICAL", "L7 Безпека",
                    "Порт 31337 (BackOrifice троян)",
                    "Класичний порт трояна. Негайно запусти антивірусне сканування.")

        @rule("L7 · Порт 1080 SOCKS proxy (LISTENING)")
        def _(rd: RawData):
            if re.search(r"\b:1080\b.*LISTEN", rd.netstat):
                return Issue("L7-09", "WARNING", "L7 Безпека",
                    "Відкритий SOCKS proxy порт 1080",
                    "Локальний SOCKS проксі. Перевір, чи ти його встановлював.")

        @rule("L7 · Порт 3389 RDP відкритий для всіх")
        def _(rd: RawData):
            if re.search(r"0\.0\.0\.0:3389.*LISTEN", rd.netstat, re.I):
                return Issue("L7-10", "WARNING", "L7 Безпека",
                    "RDP (3389) відкритий для всіх інтерфейсів",
                    "Remote Desktop доступний з мережі. Ризик брутфорсу.")

        @rule("L7 · TCP Auto-Tuning вимкнено")
        def _(rd: RawData):
            if DiagnosticEngine.IS_WIN and re.search(
                    r"Receive Window Auto-Tuning Level\s*:\s*disabled",
                    rd.tcp_global, re.I):
                return Issue("L7-11", "WARNING", "L7 Продуктивність",
                    "TCP Auto-Tuning вимкнено",
                    "Вимкнений авто-тюнінг суттєво знижує швидкість завантаження.",
                    "enable_autotuning", "🔧 Увімкнути Auto-Tuning")

        @rule("L7 · IPv6 увімкнено без маршруту")
        def _(rd: RawData):
            if (re.search(r"IPv6 Address", rd.active_section, re.I) and
                    not re.search(r"::/0", rd.route)):
                return Issue("L7-12", "INFO", "L7 Продуктивність",
                    "IPv6 увімкнено, але маршрут відсутній",
                    "Браузер пробує IPv6 перед fallback на IPv4. +20–100 мс до кожного з'єднання.")

        @rule("L7 · Велика кількість ESTABLISHED з'єднань (> 200)")
        def _(rd: RawData):
            count = len(re.findall(r"ESTABLISHED", rd.netstat))
            if count > 200:
                return Issue("L7-13", "WARNING", "L7 Мережева активність",
                    f"Велика кількість активних з'єднань: {count}",
                    "Можливо активне P2P, масове завантаження або небажане ПЗ.")

        @rule("L7 · Порт BitTorrent 6881–6889 (LISTENING)")
        def _(rd: RawData):
            for port in range(6881, 6890):
                if re.search(rf"\b:{port}\b.*LISTEN", rd.netstat):
                    return Issue("L7-14", "INFO", "L7 Мережева активність",
                        f"Відкритий порт BitTorrent ({port})",
                        "BitTorrent активний і може займати велику частину каналу.")

        @rule("L7 · Порт 445 SMB відкритий (EternalBlue ризик)")
        def _(rd: RawData):
            if re.search(r"0\.0\.0\.0:445.*LISTEN|:::445.*LISTEN", rd.netstat, re.I):
                return Issue("L7-15", "WARNING", "L7 Безпека",
                    "SMB порт 445 відкритий для всіх",
                    "Вразливість EternalBlue (WannaCry). Закрий SMB або обмеж firewall.")

        @rule("L7 · Велика кількість TIME_WAIT з'єднань (> 100)")
        def _(rd: RawData):
            count = len(re.findall(r"TIME_WAIT", rd.netstat))
            if count > 100:
                return Issue("L7-16", "INFO", "L7 Продуктивність",
                    f"Багато з'єднань TIME_WAIT: {count}",
                    "Велика кількість закритих з'єднань. Можливий TCP leak.")

        @rule("L7 · Порт 8080 відкритий (локальний HTTP proxy)")
        def _(rd: RawData):
            if re.search(r"0\.0\.0\.0:8080.*LISTEN|:::8080.*LISTEN", rd.netstat, re.I):
                return Issue("L7-17", "INFO", "L7 Конфігурація",
                    "Порт 8080 відкритий (HTTP proxy)",
                    "Локальний проксі-сервер активний на порті 8080.")

        @rule("L7 · Порт 5900 VNC (LISTENING)")
        def _(rd: RawData):
            if re.search(r"\b:5900\b.*LISTEN", rd.netstat):
                return Issue("L7-18", "WARNING", "L7 Безпека",
                    "VNC порт 5900 відкритий",
                    "Remote desktop через VNC доступний. Перевір чи це навмисно.")

        @rule("L7 · Порт 22 SSH (LISTENING, Windows)")
        def _(rd: RawData):
            if DiagnosticEngine.IS_WIN and re.search(r"\b:22\b.*LISTEN", rd.netstat):
                return Issue("L7-19", "INFO", "L7 Конфігурація",
                    "SSH порт 22 відкритий (Windows)",
                    "OpenSSH сервер активний на Windows. Перевір чи це навмисно.")

        @rule("L7 · Порт 135 RPC відкритий (атаки DCom)")
        def _(rd: RawData):
            if re.search(r"0\.0\.0\.0:135.*LISTEN", rd.netstat, re.I):
                return Issue("L7-20", "INFO", "L7 Безпека",
                    "RPC Endpoint Mapper порт 135 відкритий",
                    "Стандартний для Windows, але може використовуватись для DCom-атак.")

        @rule("L7 · Багато з'єднань у CLOSE_WAIT (> 20)")
        def _(rd: RawData):
            count = len(re.findall(r"CLOSE_WAIT", rd.netstat))
            if count > 20:
                return Issue("L7-21", "INFO", "L7 Продуктивність",
                    f"Багато з'єднань у CLOSE_WAIT: {count}",
                    "Сервер закрив з'єднання, але клієнт ще тримає. Можливий баг у ПЗ.")

        @rule("L7 · TCP Chimney Offload вимкнено")
        def _(rd: RawData):
            if DiagnosticEngine.IS_WIN and re.search(
                    r"Chimney Offload State\s*:\s*disabled", rd.tcp_global, re.I):
                return Issue("L7-22", "INFO", "L7 Продуктивність",
                    "TCP Chimney Offload вимкнено",
                    "Апаратне прискорення TCP вимкнено. Може навантажувати CPU при великому трафіку.")

        @rule("L7 · RSS (Receive-Side Scaling) вимкнено")
        def _(rd: RawData):
            if DiagnosticEngine.IS_WIN and re.search(
                    r"Receive-Side Scaling State\s*:\s*disabled", rd.tcp_global, re.I):
                return Issue("L7-23", "INFO", "L7 Продуктивність",
                    "RSS (Receive-Side Scaling) вимкнено",
                    "RSS розподіляє мережеве навантаження по ядрах CPU. "
                    "Вмикання підвищує продуктивність.")

        @rule("L7 · ECN (Explicit Congestion Notification) вимкнено")
        def _(rd: RawData):
            if DiagnosticEngine.IS_WIN and re.search(
                    r"ECN Capability\s*:\s*disabled", rd.tcp_global, re.I):
                return Issue("L7-24", "INFO", "L7 Продуктивність",
                    "ECN (Explicit Congestion Notification) вимкнено",
                    "ECN зменшує перевантаження мережі та покращує throughput.")

        @rule("L7 · Порт 161 SNMP відкритий")
        def _(rd: RawData):
            if re.search(r"\b:161\b", rd.netstat):
                return Issue("L7-25", "WARNING", "L7 Безпека",
                    "SNMP порт 161 відкритий",
                    "SNMP v1/v2 передає дані відкритим текстом. "
                    "Може розкрити конфігурацію мережі зловмисникам.")

        return rules

    # ──────────────────────────────────────────────────────
    # ГОЛОВНИЙ МЕТОД ДІАГНОСТИКИ
    # ──────────────────────────────────────────────────────

    def run_full_diagnostics(self, gateway_ip: str,
                             log_cb: Callable = None,
                             prog_cb: Callable = None) -> dict:
        def log(t):
            if log_cb:
                log_cb(t)
        def prog(t):
            if prog_cb:
                prog_cb(t)

        log(f"\n{'═' * 58}")
        log("  NetGuardian AI · Expert Rule-Based Diagnostic Engine")
        log("  Збір даних з усіх джерел паралельно...")
        log(f"{'═' * 58}")

        prog("Збір системних даних...")
        rd = self.collect_data(gateway_ip)

        iface_type = "Wi-Fi" if rd.wifi_is_primary else "Ethernet/інший"
        # PR #25: показуємо інформацію про VPN
        vpn_info = ""
        if rd.is_vpn_active:
            vpn_info = "  🛡️ VPN активний — деякі правила (фізичний канал) скіпаються"
            log(vpn_info)

        log(f"  ✅ IP: {rd.local_ip}  |  GW: {rd.gateway_ip}  |  Адаптер: {iface_type}")
        log(f"  ✅ Ping  LO:{rd.ping_lo[0]}мс  GW:{rd.ping_gw[0]}мс  "
            f"CF:{rd.ping_cf[0]}мс  G:{rd.ping_google[0]}мс  DNS:{rd.dns_ms}мс")
        log(f"\n{'─' * 58}")
        log("  Запуск Rule Engine...")
        log(f"{'─' * 58}\n")

        rules  = self._build_rules()
        issues = []
        total  = len(rules)

        for idx, (label, checker) in enumerate(rules, 1):
            prog(f"Перевірка {idx}/{total}  ·  {label}")
            try:
                result = checker(rd)
            except Exception:
                result = None
            if result:
                icon = ("🔴" if result.sev == "CRITICAL" else
                        "🟡" if result.sev == "WARNING" else "🔵")
                log(f"  {icon} [{result.code}] {result.title}")
                issues.append(result.__dict__)
            else:
                log(f"  ✅ {label}")

        log(f"\n{'═' * 58}")
        crit = sum(1 for i in issues if i["sev"] == "CRITICAL")
        warn = sum(1 for i in issues if i["sev"] == "WARNING")
        info = sum(1 for i in issues if i["sev"] == "INFO")

        if issues:
            root = (f"Знайдено {len(issues)} аномалій: "
                    f"{crit} критичних · {warn} попереджень · {info} інфо.")
        else:
            root = f"Перевірено {total} сценаріїв. Мережа в ідеальному стані ✅"

        log(f"  ВИСНОВОК: {root}")
        log(f"{'═' * 58}\n")
        prog(f"Готово ✅  ({total} перевірок)")

        return {
            "issues":     issues,
            "root_cause": root,
            "total_checks": total,
            "raw": {
                "local_ip":      rd.local_ip,
                "gateway_ip":    rd.gateway_ip,
                "ping_gw":       rd.ping_gw,
                "ping_cf":       rd.ping_cf,
                "dns_ms":        rd.dns_ms,
                "wifi_primary":  rd.wifi_is_primary,
                "vpn_active":    rd.is_vpn_active,
            },
        }

    # ──────────────────────────────────────────────────────
    # AI-АНАЛІЗ через Gemini API
    # ──────────────────────────────────────────────────────

    def analyze_with_ai(self, gateway_ip: str,
                        log_cb: Callable = None,
                        prog_cb: Callable = None) -> dict:
        """Гібридна діагностика: rule-based + LLM-інтерпретація.

        1. Виконує звичайний run_full_diagnostics() (як раніше)
        2. Передає результат у Gemini API для розумної інтерпретації
        3. Повертає об'єднаний результат з полями:
            - rule_based: результат rule engine (як раніше)
            - ai:         розумний аналіз від Gemini
                         {summary, good, warnings, critical, tips, overall}
            - has_ai:     bool — чи був AI-аналіз успішним

        Якщо API-ключ не налаштований або інтернет offline —
        повертає тільки rule_based, has_ai=False.
        """
        def log(t):
            if log_cb: log_cb(t)
        def prog(t):
            if prog_cb: prog_cb(t)

        # 1. Збираємо метрики rule-based способом
        rule_result = self.run_full_diagnostics(gateway_ip, log_cb, prog_cb)

        # 1.5. Запускаємо РОЗШИРЕНУ діагностику (security/gaming/streaming etc)
        log(f"\n{'─' * 58}")
        log("  🔬 РОЗШИРЕНА ДІАГНОСТИКА (40+ перевірок)")
        log(f"{'─' * 58}")
        prog("Розширена діагностика...")
        try:
            from features.diagnostics.advanced import run_advanced_diagnostics
            adv_result = run_advanced_diagnostics(log_cb=log_cb, prog_cb=prog_cb)
            adv_issues = adv_result.get("issues", [])
            # Додаємо до загального списку
            if adv_issues:
                rule_result.setdefault("issues", []).extend(adv_issues)
            # Додаємо advanced категорії в дані для AI
            rule_result["advanced"] = {
                "categories": {k: len(v) for k, v in adv_result.get("categories", {}).items()},
                "total_advanced_issues": len(adv_issues),
                "metrics": adv_result.get("metrics", {}),
            }
            log(f"\n✅ Розширена діагностика: +{len(adv_issues)} issues")
            # Зберігаємо у last_report для AI
            self._last_report = rule_result
        except Exception as e:
            log(f"\n⚠️ Розширена діагностика помилка: {e}")
            print(f"[Diagnostics] advanced error: {e}")
            import traceback; traceback.print_exc()
            self._last_report = rule_result

        # 2. AI-аналіз через HybridAIClient (Gemini → KB fallback)
        try:
            from hybrid_ai import get_hybrid_client, is_internet_available
            hybrid = get_hybrid_client()

            online = is_internet_available()
            log(f"\n{'─' * 58}")
            if online:
                log("  🤖 AI-аналіз через Google Gemini (онлайн)...")
            else:
                log("  📦 AI-аналіз через локальну базу знань (offline)...")
            log(f"{'─' * 58}")
            prog("AI-інтерпретація даних...")

            ai_result = hybrid.analyze_diagnostics(rule_result)
            source = ai_result.get("source", "unknown")

            if ai_result.get("success"):
                log(f"  ✅ Аналіз готовий (джерело: {source})")
                if source == "knowledge_base":
                    log("  ℹ️ Інтернет недоступний — використано локальну базу.")
                log(f"  📊 {ai_result.get('summary', '')[:120]}")
                overall = ai_result.get("overall", "good")
                emoji_map = {
                    "excellent": "🟢", "good": "🟢",
                    "warning":  "🟡", "critical": "🔴",
                }
                log(f"  📊 Стан: {emoji_map.get(overall, '⚪')} {overall}")
                prog("AI-аналіз завершено ✅")
                return {
                    "rule_based": rule_result,
                    "ai":         ai_result,
                    "has_ai":     True,
                    "ai_source":  source,
                    "ai_online":  online,
                    "ai_error":   "",
                }
            else:
                err = ai_result.get("error", "невідома помилка")
                log(f"  ❌ Аналіз провалився: {err[:150]}")
                return {
                    "rule_based": rule_result,
                    "ai":         None,
                    "has_ai":     False,
                    "ai_source":  source,
                    "ai_online":  online,
                    "ai_error":   err,
                }

        except ImportError:
            # Fallback на старий шлях якщо hybrid_ai.py не встановлено
            log("\n⚠️ hybrid_ai.py не знайдено — використовую тільки Gemini")
            try:
                from app.core.gemini_client import get_gemini_client
                client = get_gemini_client()
                if not client.is_available():
                    return {
                        "rule_based": rule_result, "ai": None,
                        "has_ai": False, "ai_source": "none",
                        "ai_online": False,
                        "ai_error": "Gemini API key не налаштовано",
                    }
                ai_result = client.analyze_network(rule_result)
                return {
                    "rule_based": rule_result,
                    "ai":         ai_result if ai_result.get("success") else None,
                    "has_ai":     bool(ai_result.get("success")),
                    "ai_source":  "gemini",
                    "ai_online":  True,
                    "ai_error":   ai_result.get("error", ""),
                }
            except Exception as e:
                return {
                    "rule_based": rule_result, "ai": None,
                    "has_ai": False, "ai_source": "none",
                    "ai_online": False, "ai_error": str(e),
                }
        except Exception as e:
            log(f"  ❌ AI exception: {e}")
            return {
                "rule_based": rule_result,
                "ai":         None,
                "has_ai":     False,
                "ai_error":   str(e),
            }

    # ──────────────────────────────────────────────────────
    # AUTO-FIX МЕТОДИ
    # ──────────────────────────────────────────────────────

    @staticmethod
    def flush_dns() -> tuple:
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=8)
            return True, "DNS кеш очищено."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def reset_tcp_ip() -> tuple:
        try:
            subprocess.run(["netsh", "winsock", "reset"], capture_output=True, timeout=8)
            subprocess.run(["netsh", "int", "ip", "reset"], capture_output=True, timeout=8)
            return True, "Winsock і TCP/IP скинуто. Потрібне перезавантаження."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def dhcp_renew() -> tuple:
        try:
            subprocess.run(["ipconfig", "/release"], capture_output=True, timeout=8)
            subprocess.run(["ipconfig", "/renew"],   capture_output=True, timeout=20)
            return True, "IP-адресу оновлено через DHCP."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def set_fast_dns() -> tuple:
        if platform.system() != "Windows":
            return False, "Тільки для Windows."
        try:
            out = DiagnosticEngine._run(
                ["netsh", "interface", "show", "interface"])
            iface = "Wi-Fi"
            for line in out.splitlines():
                if re.search(r"Connected|Підключено|Подключен", line, re.I):
                    parts = line.split()
                    if len(parts) >= 4:
                        iface = " ".join(parts[3:])
                        break
            subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dns",
                 iface, "static", "1.1.1.1"],
                capture_output=True, timeout=8)
            subprocess.run(
                ["netsh", "interface", "ipv4", "add", "dns",
                 iface, "8.8.8.8", "index=2"],
                capture_output=True, timeout=8)
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=5)
            return True, f"DNS «{iface}» → 1.1.1.1 / 8.8.8.8"
        except Exception as e:
            return False, f"Потрібні права адміністратора. ({e})"

    @staticmethod
    def fix_mtu() -> tuple:
        if platform.system() != "Windows":
            return False, "Тільки для Windows."
        try:
            out = DiagnosticEngine._run(
                ["netsh", "interface", "ipv4", "show", "subinterfaces"])
            iface = None
            for line in out.splitlines()[2:]:
                parts = line.split()
                if len(parts) >= 4:
                    iface = " ".join(parts[3:])
                    break
            if iface:
                subprocess.run(
                    ["netsh", "interface", "ipv4", "set", "subinterface",
                     iface, "mtu=1500", "store=persistent"],
                    capture_output=True, timeout=8)
                return True, f"MTU для «{iface}» встановлено на 1500."
            return False, "Інтерфейс не знайдено."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def enable_firewall() -> tuple:
        if platform.system() != "Windows":
            return False, "Тільки для Windows."
        try:
            subprocess.run(
                ["netsh", "advfirewall", "set", "allprofiles", "state", "on"],
                capture_output=True, timeout=8)
            return True, "Windows Firewall увімкнено."
        except Exception as e:
            return False, f"Потрібні права адміністратора. ({e})"

    @staticmethod
    def disable_proxy() -> tuple:
        if platform.system() != "Windows":
            return False, "Тільки для Windows."
        try:
            subprocess.run(
                ["netsh", "winhttp", "reset", "proxy"],
                capture_output=True, timeout=8)
            subprocess.run(
                ["reg", "add",
                 r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                 "/v", "ProxyEnable", "/t", "REG_DWORD", "/d", "0", "/f"],
                capture_output=True, timeout=5)
            return True, "WinHTTP та IE/Edge Proxy скинуто."
        except Exception as e:
            return False, str(e)

    @staticmethod
    def enable_autotuning() -> tuple:
        if platform.system() != "Windows":
            return False, "Тільки для Windows."
        try:
            subprocess.run(
                ["netsh", "int", "tcp", "set", "global", "autotuninglevel=normal"],
                capture_output=True, timeout=8)
            return True, "TCP Auto-Tuning увімкнено (normal)."
        except Exception as e:
            return False, str(e)

    # ── Зворотна сумісність ────────────────────────────────
    fix_flush_dns          = flush_dns
    fix_winsock_reset      = reset_tcp_ip
    fix_renew_ip           = dhcp_renew
    fix_set_cloudflare_dns = set_fast_dns
    fix_enable_firewall    = enable_firewall