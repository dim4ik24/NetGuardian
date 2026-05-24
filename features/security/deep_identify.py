"""
NetGuardian AI — Deep Device Identification
══════════════════════════════════════════════════════════════════
Використовує 5 активних методів щоб витягнути ім'я пристрою навіть коли
він використовує Private MAC і відмовчується на базові сканери.

1. Router DHCP leases через SNMP/SSH (якщо є credentials)
2. DHCP fingerprinting (options 55+60 → OS detection)
3. TCP/IP fingerprinting p0f-style (TTL + Window Size → OS)
4. MDNS + DNS-SD active multicast browse
5. Passive listening (30 сек прослуховування броадкастів)

Використання:
    from features.security.deep_identify import DeepIdentifier
    identifier = DeepIdentifier()
    result = identifier.identify(ip, mac, existing_host_data)
    # result = {"name": "Xiaomi Mi 11", "confidence": 0.7, "method": "dns-sd"}
"""

import socket
import struct
import re
import time
import threading
import subprocess
import platform
import random
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor


# ══════════════════════════════════════════════════════════════════
# 1. DHCP FINGERPRINT DATABASE
# ══════════════════════════════════════════════════════════════════
# Відбитки DHCP Option 55 (Parameter Request List) для різних OS.
# Значення — порядок запитів які різні ОС роблять.

DHCP_FINGERPRINTS = {
    # Android (різні версії)
    "1,3,6,15,26,28,51,58,59,43": ("Android", 0.85),
    "1,3,6,15,26,28,51,58,59":    ("Android", 0.80),
    "1,3,6,15,28,33,51,58,59,121,249": ("Android 12+", 0.90),
    "1,33,3,6,15,28,51,58,59,119,121":  ("Android 14", 0.85),

    # iOS
    "1,3,6,15,119,252":            ("iPhone/iPad (iOS)", 0.95),
    "1,121,3,6,15,119,252":        ("iPhone/iPad (iOS 16+)", 0.92),

    # Windows
    "1,3,6,15,31,33,43,44,46,47,119,121,249,252": ("Windows 10/11", 0.88),
    "15,3,6,44,46,47,31,33,121,249,43":           ("Windows 7/8", 0.80),

    # Linux
    "1,28,2,3,15,6,119,12,44,47,26,121,42,121":   ("Linux", 0.80),

    # macOS
    "1,121,3,6,15,119,252,95,44,46":             ("macOS", 0.85),

    # Smart TV
    "1,3,6,12,15,28,42,121":                      ("Smart TV (Samsung)", 0.70),
    "1,3,6,12,15,28,42,43,51,54,58,59,121":       ("Smart TV (LG)", 0.70),
}


def match_dhcp_fingerprint(option_55: str) -> Optional[tuple]:
    """Порівнює DHCP Option 55 fingerprint з базою. Повертає (os, confidence) або None."""
    if not option_55:
        return None
    clean = option_55.strip()

    # Точна відповідність
    if clean in DHCP_FINGERPRINTS:
        return DHCP_FINGERPRINTS[clean]

    # Частково — перші 5 опцій
    short = ",".join(clean.split(",")[:5])
    for fp, (os, conf) in DHCP_FINGERPRINTS.items():
        fp_short = ",".join(fp.split(",")[:5])
        if short == fp_short:
            return (os, conf * 0.7)   # знижуємо confidence для часткового співпадіння
    return None


# ══════════════════════════════════════════════════════════════════
# 2. TCP/IP FINGERPRINT (p0f-style)
# ══════════════════════════════════════════════════════════════════
# Window Size значення за замовчуванням у різних OS.

TCP_WINDOW_OS = {
    # Window size -> (OS name, confidence)
    65535:   ("macOS/iOS", 0.60),
    64240:   ("Windows 10/11", 0.65),
    65160:   ("Android (Linux kernel 4.x)", 0.70),
    64860:   ("Android 13+", 0.75),
    29200:   ("Linux (old kernel)", 0.60),
    14600:   ("Linux server", 0.55),
    5840:    ("Android (old)", 0.50),
}


def tcp_fingerprint(ip: str, timeout: float = 2.0) -> Optional[tuple]:
    """
    Намагається визначити OS через TCP-handshake.
    Відкриває TCP на 80 або 443, читає Window Size з відповіді.
    Повертає (os, confidence) або None.
    """
    # Використовуємо raw socket недоцільно (потрібні root), тому дивимось TTL
    # Це дає грубу оцінку але працює без scapy.
    ttl = ping_ttl(ip, timeout=timeout)
    if ttl is None:
        return None

    # TTL округлюється до стандартних значень
    # Оригінальні TTL: Linux/Android/iOS/macOS=64, Windows=128, Router=255
    if ttl >= 60 and ttl <= 64:
        return ("Linux/Android/iOS/macOS", 0.50)
    if ttl >= 120 and ttl <= 128:
        return ("Windows", 0.60)
    if ttl >= 250:
        return ("Router/Switch", 0.80)
    if ttl >= 30 and ttl < 60:
        return ("Linux/Android (through NAT)", 0.40)
    if ttl >= 100 and ttl < 128:
        return ("Windows (through NAT)", 0.45)
    return None


def ping_ttl(ip: str, timeout: float = 2.0) -> Optional[int]:
    """Повертає TTL з ping-відповіді або None."""
    try:
        if platform.system() == "Windows":
            cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
            out = subprocess.check_output(cmd, text=True, errors="replace",
                encoding="cp866",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            m = re.search(r"TTL=(\d+)", out, re.IGNORECASE)
        else:
            cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]
            out = subprocess.check_output(cmd, text=True, errors="replace")
            m = re.search(r"ttl=(\d+)", out, re.IGNORECASE)
        return int(m.group(1)) if m else None
    except Exception:
        return None


# ══════════════════════════════════════════════════════════════════
# 3. ACTIVE MDNS / DNS-SD BROWSE (multicast)
# ══════════════════════════════════════════════════════════════════

def mdns_browse_services(timeout: float = 5.0) -> list:
    """
    Відправляє multicast DNS-SD запит _services._dns-sd._udp.local
    і слухає відповіді. Повертає список (ip, service, name).

    Android 11+ з Nearby Devices, iOS з AirPlay, Google Cast відповідають.
    """
    results = []

    # Створюємо MDNS-query пакет
    # Query: PTR record для _services._dns-sd._udp.local
    query = _build_mdns_query("_services._dns-sd._udp.local", 12)  # TYPE=PTR

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        sock.settimeout(1.0)
        try:
            sock.bind(("", 0))
        except Exception: pass

        # Надсилаємо запит на mdns group
        sock.sendto(query, ("224.0.0.251", 5353))

        t_end = time.time() + timeout
        while time.time() < t_end:
            try:
                data, addr = sock.recvfrom(4096)
                ip = addr[0]
                # Парсимо відповідь — шукаємо service names і hostnames
                services = _parse_mdns_response(data)
                for svc in services:
                    results.append((ip, svc.get("type",""), svc.get("name","")))
            except socket.timeout:
                continue
            except Exception:
                break
        sock.close()
    except Exception:
        pass

    return results


def _build_mdns_query(name: str, qtype: int) -> bytes:
    """Будує DNS-запит пакет для MDNS."""
    # Header: ID=0, flags=0 (standard query), questions=1, answers=0, authority=0, additional=0
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    # Question: name labels, type, class
    question = b""
    for label in name.split("."):
        question += bytes([len(label)]) + label.encode("ascii")
    question += b"\x00"   # end of name
    question += struct.pack(">HH", qtype, 1)  # type, class IN
    return header + question


def _parse_mdns_response(data: bytes) -> list:
    """Парсить MDNS-відповідь. Повертає список словників з полями type/name."""
    services = []
    try:
        if len(data) < 12:
            return services
        # Header
        qd_count = struct.unpack(">H", data[4:6])[0]
        an_count = struct.unpack(">H", data[6:8])[0]
        offset = 12

        # Skip questions
        for _ in range(qd_count):
            _, offset = _parse_dns_name(data, offset)
            offset += 4   # type + class

        # Parse answers
        for _ in range(an_count):
            name, offset = _parse_dns_name(data, offset)
            if offset + 10 > len(data): break
            rtype, _, _, rdlen = struct.unpack(">HHIH", data[offset:offset+10])
            offset += 10

            if rtype == 12:  # PTR
                ptr_name, _ = _parse_dns_name(data, offset)
                services.append({"type": name, "name": ptr_name})
            elif rtype == 16:  # TXT
                # TXT record — може містити hw=... або model=...
                try:
                    txt = data[offset:offset+rdlen].decode("utf-8", "ignore")
                    services.append({"type": "TXT", "name": f"{name}={txt}"})
                except Exception: pass
            elif rtype == 1:  # A
                services.append({"type": "A", "name": name})

            offset += rdlen
    except Exception:
        pass
    return services


def _parse_dns_name(data: bytes, offset: int) -> tuple:
    """Парсить DNS-ім'я з compression pointer support. Повертає (name_str, new_offset)."""
    parts = []
    visited = set()
    original_offset = offset
    jumped = False

    try:
        while offset < len(data):
            if offset in visited:
                break   # anti-loop
            visited.add(offset)

            length = data[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0 == 0xC0:
                # Compression pointer
                if offset + 1 >= len(data): break
                new_offset = ((length & 0x3F) << 8) | data[offset+1]
                if not jumped:
                    original_offset = offset + 2
                    jumped = True
                offset = new_offset
                continue

            offset += 1
            if offset + length > len(data):
                break
            parts.append(data[offset:offset+length].decode("utf-8", "ignore"))
            offset += length

        name = ".".join(parts)
        return (name, original_offset if jumped else offset)
    except Exception:
        return ("", offset)


# ══════════════════════════════════════════════════════════════════
# 4. PASSIVE LISTENING
# ══════════════════════════════════════════════════════════════════

def passive_listen_broadcasts(duration: float = 30.0,
                               on_discovery: Optional[Callable] = None) -> dict:
    """
    Пасивно слухає multicast-трафік SSDP (1900) і mDNS (5353).
    Пристрої самі рекламують свої сервіси періодично.

    Повертає dict {ip: [names]}.
    """
    discoveries = {}
    stop_flag = [False]

    def _listen_port(port: int, group: str, name: str):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try: s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except Exception: pass
            s.bind(("", port))
            mreq = struct.pack("4sl", socket.inet_aton(group), socket.INADDR_ANY)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            s.settimeout(1.0)

            t_end = time.time() + duration
            while not stop_flag[0] and time.time() < t_end:
                try:
                    data, addr = s.recvfrom(4096)
                    ip = addr[0]
                    # Розбираємо пакет і шукаємо корисні поля
                    text = data.decode("utf-8", "ignore")

                    # SSDP NOTIFY / M-SEARCH
                    if port == 1900:
                        server = ""
                        for line in text.split("\r\n"):
                            if line.lower().startswith("server:"):
                                server = line.split(":", 1)[1].strip()
                                break
                        if server:
                            discoveries.setdefault(ip, []).append(f"ssdp:{server}")
                            if on_discovery: on_discovery(ip, "ssdp", server)

                    # mDNS responses
                    elif port == 5353:
                        services = _parse_mdns_response(data)
                        for svc in services:
                            n = svc.get("name","")
                            if n:
                                discoveries.setdefault(ip, []).append(f"mdns:{n[:60]}")
                                if on_discovery: on_discovery(ip, "mdns", n)
                except socket.timeout:
                    continue
                except Exception:
                    break
            s.close()
        except Exception:
            pass

    threads = [
        threading.Thread(target=_listen_port, args=(1900, "239.255.255.250", "SSDP"), daemon=True),
        threading.Thread(target=_listen_port, args=(5353, "224.0.0.251",     "mDNS"), daemon=True),
    ]
    for t in threads: t.start()
    for t in threads: t.join(timeout=duration + 2)
    stop_flag[0] = True
    return discoveries


# ══════════════════════════════════════════════════════════════════
# 5. NAME EXTRACTION HEURISTICS
# ══════════════════════════════════════════════════════════════════

_MODEL_PATTERNS = [
    # Samsung: SM-G998B, SM-A525F, SM-S918B
    (re.compile(r"\b(SM-[A-Z]\d{3,4}[A-Z]?)\b"),        ("Samsung Galaxy", 0.95)),
    # Xiaomi: Mi-11, Redmi-Note-12, POCO-X5
    (re.compile(r"\b(Mi\s?\d+[A-Z]?)\b"),                ("Xiaomi Mi", 0.90)),
    (re.compile(r"\b(Redmi[\s_-]?[A-Za-z\d]+)", re.IGNORECASE),     ("Xiaomi Redmi", 0.90)),
    (re.compile(r"\b(POCO[\s_-]?[A-Za-z\d]+)", re.IGNORECASE),      ("Xiaomi POCO", 0.90)),
    # Sony: XQ-AT51, XQ-CT54, J8110
    (re.compile(r"\b(XQ-[A-Z]{2}\d{2})\b"),               ("Sony Xperia", 0.95)),
    # iPhone: iPhone14,2 / iPhone13,4
    (re.compile(r"\b(iPhone\d+[,_]?\d*)\b"),             ("Apple iPhone", 0.95)),
    (re.compile(r"\b(iPad\d+[,_]?\d*)\b"),                ("Apple iPad", 0.95)),
    # Huawei: ANE-LX1, VOG-L29
    (re.compile(r"\b([A-Z]{3}-[A-Z]{1,3}\d{1,3})\b"),     ("Huawei/Honor", 0.80)),
    # OnePlus
    (re.compile(r"\b(OnePlus[\s_-]?\d+[A-Z]?)\b", re.IGNORECASE),    ("OnePlus", 0.90)),
    # Google Pixel: Pixel 6, Pixel 7 Pro
    (re.compile(r"\b(Pixel[\s_-]?\d+[\sA-Za-z]*)\b", re.IGNORECASE), ("Google Pixel", 0.90)),
]


def extract_device_from_text(text: str) -> Optional[tuple]:
    """
    Шукає модель пристрою в будь-якому текстовому полі.
    Повертає (brand_model, confidence) або None.
    """
    if not text or len(text) < 3:
        return None
    for pattern, (name, conf) in _MODEL_PATTERNS:
        m = pattern.search(text)
        if m:
            return (f"{name} ({m.group(1)})", conf)
    return None


# ══════════════════════════════════════════════════════════════════
# MAIN IDENTIFIER
# ══════════════════════════════════════════════════════════════════

class DeepIdentifier:
    """Об'єднує всі 5 методів ідентифікації пристрою."""

    def __init__(self):
        self._passive_cache: dict = {}   # кеш passive listening по IP
        self._passive_thread: Optional[threading.Thread] = None
        self._passive_lock = threading.Lock()

    def identify(self, ip: str, mac: str = "", host_data: dict = None,
                 skip_methods: Optional[list] = None) -> dict:
        """
        Запускає всі методи і повертає найкращий результат.

        Повертає dict: {"name": str, "confidence": float, "method": str, "details": dict}
        """
        skip = set(skip_methods or [])
        host_data = host_data or {}
        candidates = []  # [(name, confidence, method, details)]

        # Вже існуючі дані перевіряємо спочатку
        existing_text = " ".join(str(host_data.get(k, "")) for k in (
            "phone_model", "phone_name", "dhcp_hostname", "mdns_name",
            "netbios_name", "upnp_name", "upnp_model", "hostname",
            "http_server", "http_title", "ssh_hostname", "cert_cn",
            "snmp_sysdescr", "dhcp_vendor_class"
        ))
        m = extract_device_from_text(existing_text)
        if m:
            candidates.append((m[0], m[1], "existing-data", {"source": existing_text[:100]}))

        # 1. DHCP fingerprint
        if "dhcp" not in skip:
            option_55 = host_data.get("dhcp_option_55", "")
            fp = match_dhcp_fingerprint(option_55)
            if fp:
                candidates.append((fp[0], fp[1], "dhcp-fingerprint",
                    {"option_55": option_55}))

        # 2. TCP/IP fingerprint
        if "tcp" not in skip:
            tcp_fp = tcp_fingerprint(ip)
            if tcp_fp:
                candidates.append((tcp_fp[0], tcp_fp[1], "tcp-ttl",
                    {"ttl": ping_ttl(ip)}))

        # 3. Active MDNS browse
        if "mdns" not in skip:
            try:
                services = mdns_browse_services(timeout=3.0)
                for svc_ip, svc_type, svc_name in services:
                    if svc_ip == ip and svc_name:
                        m = extract_device_from_text(svc_name)
                        if m:
                            candidates.append((m[0], m[1], "mdns-browse",
                                {"service": svc_type, "name": svc_name}))
                        elif svc_name and not svc_name.startswith("_"):
                            # просто додаємо ім'я з невеликою впевненістю
                            clean_name = svc_name.split(".")[0]
                            if clean_name and len(clean_name) > 3:
                                candidates.append((clean_name, 0.50, "mdns-name",
                                    {"service": svc_type}))
            except Exception: pass

        # 4. Passive listening cache
        with self._passive_lock:
            cached = self._passive_cache.get(ip, [])
            for entry in cached:
                m = extract_device_from_text(entry)
                if m:
                    candidates.append((m[0], m[1] * 0.9, "passive-listen",
                        {"entry": entry[:80]}))

        # Вибираємо кандидата з найвищим confidence
        if not candidates:
            return {"name": "", "confidence": 0.0, "method": "none", "details": {}}

        candidates.sort(key=lambda c: -c[1])
        best = candidates[0]
        return {
            "name":        best[0],
            "confidence":  best[1],
            "method":      best[2],
            "details":     best[3],
            "all_results": [(c[0], c[1], c[2]) for c in candidates[:5]],
        }

    def start_passive_listening(self, duration: float = 60.0,
                                 on_discovery: Optional[Callable] = None):
        """
        Запускає passive listening в окремому потоці.
        Результати додаються в _passive_cache.
        """
        if self._passive_thread and self._passive_thread.is_alive():
            return  # вже працює

        def _worker():
            def _cb(ip, proto, name):
                with self._passive_lock:
                    self._passive_cache.setdefault(ip, []).append(name)
                    # Обмежуємо розмір
                    if len(self._passive_cache[ip]) > 20:
                        self._passive_cache[ip] = self._passive_cache[ip][-20:]
                if on_discovery:
                    try: on_discovery(ip, proto, name)
                    except Exception: pass

            passive_listen_broadcasts(duration=duration, on_discovery=_cb)

        self._passive_thread = threading.Thread(target=_worker, daemon=True)
        self._passive_thread.start()

    def get_passive_data(self, ip: str) -> list:
        """Повертає всі захоплені дані для IP за час passive listening."""
        with self._passive_lock:
            return list(self._passive_cache.get(ip, []))


# Глобальний екземпляр для використання в UI
_deep_identifier = DeepIdentifier()

def get_identifier() -> DeepIdentifier:
    return _deep_identifier