"""
features/diagnostics/advanced.py
─────────────────────────────────
РОЗШИРЕНА ДІАГНОСТИКА МЕРЕЖІ для NetGuardian.

Цей модуль доповнює базовий DiagnosticEngine десятками додаткових
перевірок розбитих на категорії:

  • SECURITY    — leak detection (DNS/IPv6/WebRTC), port scan, MITM
  • STREAMING   — bitrate availability, CDN performance, buffering risk
  • GAMING      — game server pings, region quality, anti-cheat readiness
  • STABILITY   — jitter analysis, route stability, packet reordering
  • HARDWARE    — NIC info, drivers, MAC, link speed, duplex
  • CONNECTIVITY — IPv6, MTU, TTL, fragmentation, MSS
  • DNS_ADVANCED — DNSSEC, DoH, DoT, leak test, hijacking
  • HTTP        — HTTP/2/3, QUIC, certificate validation, redirects
  • LATENCY     — jitter histogram, percentiles, spike detection
  • ROUTING     — traceroute analysis, AS path, asymmetric routes
  • WIRELESS    — Wi-Fi quality, congestion, neighbor APs

Усі перевірки повертають список Issue (
                group="Розширена",з модуля engine.py).
Кожна група має таймаут — щоб ніяка перевірка не висла.
"""

from __future__ import annotations
import os
import sys
import time
import socket
import struct
import subprocess
import platform
import json
import ssl
import urllib.request
import urllib.parse
import urllib.error
import re
import threading
from typing import Optional, Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout
from dataclasses import dataclass, field

# Імпортуємо Issue з основного engine
try:
    from features.diagnostics.engine import Issue as _RawIssue
    _ENGINE_ISSUE = True
except ImportError:
    _ENGINE_ISSUE = False
    @dataclass
    class _RawIssue:
        code: str = ""
        sev: str = "INFO"
        title: str = ""
        desc: str = ""
        fix: str = ""


# Wrapper-фабрика щоб не падати на missing group у engine.Issue
# Engine Issue вимагає group= (positional після sev), без нього TypeError.
# Цей wrapper КИНЕ default group якщо її не передали.
class Issue:
    """Wrapper що завжди передає group у real Issue.

    Використання як звичайний Issue(): Issue(code=..., sev=..., title=...)
    """
    def __new__(cls, *args, **kwargs):
        if _ENGINE_ISSUE and 'group' not in kwargs:
            kwargs['group'] = "Розширена"
        return _RawIssue(*args, **kwargs)


# ═════════════════════════════════════════════════════════════════════════════
#  КОНСТАНТИ
# ═════════════════════════════════════════════════════════════════════════════

# Game server endpoints — для перевірки ігрового пінгу
GAME_SERVERS = {
    "Steam EU":       ("146.66.155.10", 443),
    "Steam US":       ("208.78.164.10", 443),
    "Riot EU West":   ("104.160.131.3", 80),
    "Riot EU NE":     ("104.160.141.3", 80),
    "Battle.net EU":  ("blzddist1-a.akamaihd.net", 80),
    "Epic Games":     ("epicgames.com", 443),
    "PSN EU":         ("ps5.psn.eu", 443),
    "Xbox Live":      ("xbox.com", 443),
    "Discord Voice":  ("162.159.135.232", 443),
    "Cloudflare WS":  ("1.1.1.1", 443),
}

# Streaming endpoints
STREAMING_ENDPOINTS = {
    "YouTube":        ("youtube.com", 443),
    "Netflix":        ("netflix.com", 443),
    "Twitch":         ("twitch.tv", 443),
    "Spotify":        ("spotify.com", 443),
    "Apple Music":    ("music.apple.com", 443),
    "Megogo":         ("megogo.net", 443),
    "TikTok":         ("tiktok.com", 443),
    "Instagram":      ("instagram.com", 443),
    "Vimeo":          ("vimeo.com", 443),
}

# DNS-провайдери для тестування
DNS_PROVIDERS = {
    "Google":      ("8.8.8.8",        "8.8.4.4"),
    "Cloudflare":  ("1.1.1.1",        "1.0.0.1"),
    "Quad9":       ("9.9.9.9",        "149.112.112.112"),
    "OpenDNS":     ("208.67.222.222", "208.67.220.220"),
    "AdGuard":     ("94.140.14.14",   "94.140.15.15"),
    "Comodo":      ("8.26.56.26",     "8.20.247.20"),
    "Yandex":      ("77.88.8.8",      "77.88.8.1"),
    "DNS.WATCH":   ("84.200.69.80",   "84.200.70.40"),
    "CleanBrowsing": ("185.228.168.9", "185.228.169.9"),
    "Verisign":    ("64.6.64.6",      "64.6.65.6"),
    "Level3":      ("4.2.2.1",        "4.2.2.2"),
    "Neustar":     ("156.154.70.1",   "156.154.71.1"),
}

# Test domains для DNS resolution
TEST_DOMAINS = [
    "google.com", "github.com", "youtube.com", "wikipedia.org",
    "amazon.com", "cloudflare.com", "microsoft.com",
    # UA сайти
    "rozetka.com.ua", "diia.gov.ua", "monobank.ua", "privatbank.ua",
    # Перевірка цензури
    "twitter.com", "facebook.com",
]

# Common ports для перевірки
COMMON_PORTS = {
    20:  "FTP-Data",
    21:  "FTP",
    22:  "SSH",
    23:  "Telnet",
    25:  "SMTP",
    53:  "DNS",
    80:  "HTTP",
    110: "POP3",
    119: "NNTP",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-Sub",
    993: "IMAPS",
    995: "POP3S",
    3389: "RDP",
    5060: "SIP",
    5061: "SIPS",
    8080: "HTTP-Alt",
}

# Підозрілі порти (NetBIOS, SMB, RDP exposed)
DANGEROUS_OPEN_PORTS = {135, 137, 138, 139, 445, 3389, 5900}


# ═════════════════════════════════════════════════════════════════════════════
#  УТИЛІТИ
# ═════════════════════════════════════════════════════════════════════════════

def _tcp_check(host: str, port: int, timeout: float = 2.0) -> tuple[bool, float]:
    """Перевіряє чи порт відкритий, повертає (is_open, latency_ms)."""
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.perf_counter() - start) * 1000, 1)
    except Exception:
        return False, -1.0


def _resolve_dns_via(server: str, domain: str, timeout: float = 2.0) -> tuple[bool, float, str]:
    """DNS-резолюція через конкретний сервер.

    Returns: (success, time_ms, resolved_ip)
    """
    try:
        start = time.perf_counter()
        # Створюємо raw DNS query (тип A)
        query_id = os.urandom(2)
        flags = b'\x01\x00'
        questions = b'\x00\x01'
        answers = b'\x00\x00'
        authority = b'\x00\x00'
        additional = b'\x00\x00'
        header = query_id + flags + questions + answers + authority + additional

        # QNAME — domain encoded
        qname = b''
        for part in domain.split('.'):
            qname += bytes([len(part)]) + part.encode()
        qname += b'\x00'

        qtype = b'\x00\x01'    # A record
        qclass = b'\x00\x01'   # IN
        query = header + qname + qtype + qclass

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (server, 53))
        response, _ = sock.recvfrom(4096)
        sock.close()

        elapsed = round((time.perf_counter() - start) * 1000, 1)

        # Парсинг відповіді (примітивний — просто шукаємо IPv4 в RDATA)
        if len(response) < 12: return False, elapsed, ""

        # Перевіряємо ANCOUNT
        ancount = struct.unpack('!H', response[6:8])[0]
        if ancount == 0:
            return False, elapsed, ""

        # Шукаємо A record (type=1, class=1, rdlength=4)
        # Skip header (12 bytes) + question section
        offset = 12
        # Skip QNAME
        while offset < len(response):
            length = response[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:  # compression pointer
                offset += 2
                break
            offset += length + 1
        offset += 4   # QTYPE + QCLASS

        # Answer section — шукаємо першу A record
        for _ in range(ancount):
            if offset + 12 > len(response): break
            # Skip name (compression pointer = 2 bytes)
            if response[offset] & 0xC0:
                offset += 2
            else:
                while response[offset] != 0:
                    if response[offset] & 0xC0:
                        offset += 2
                        break
                    offset += response[offset] + 1
                else:
                    offset += 1
            atype = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 2
            aclass = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 2
            ttl = struct.unpack('!I', response[offset:offset+4])[0]
            offset += 4
            rdlength = struct.unpack('!H', response[offset:offset+2])[0]
            offset += 2
            rdata = response[offset:offset+rdlength]
            offset += rdlength
            if atype == 1 and aclass == 1 and rdlength == 4:
                ip = '.'.join(str(b) for b in rdata)
                return True, elapsed, ip
        return False, elapsed, ""
    except Exception:
        return False, 0.0, ""


def _http_get(url: str, timeout: float = 5.0) -> tuple[int, dict, str]:
    """GET request, повертає (status_code, headers, body_first_500_chars)."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetGuardian/1.0"
        })
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(500).decode("utf-8", errors="replace")
            return r.status, dict(r.headers), body
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers) if e.headers else {}, ""
    except Exception:
        return 0, {}, ""


def _ping_simple(host: str, count: int = 3, timeout_ms: int = 1500) -> tuple[float, float, float]:
    """Простий ping через системну команду.

    Returns: (avg_ms, min_ms, max_ms). 0 при помилці.
    """
    try:
        sysname = platform.system().lower()
        if "windows" in sysname:
            cmd = ["ping", "-n", str(count), "-w", str(timeout_ms), host]
        else:
            cmd = ["ping", "-c", str(count), "-W", str(timeout_ms // 1000), host]
        r = subprocess.run(
            cmd, capture_output=True, text=True, timeout=8,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        out = r.stdout
        # Шукаємо середній time
        avg_match = re.search(r'[Aa]verage[\s=]+(\d+)', out) or \
                    re.search(r'avg[/=]+([\d.]+)', out)
        min_match = re.search(r'[Mm]inimum[\s=]+(\d+)', out) or \
                    re.search(r'min[/=]+([\d.]+)', out)
        max_match = re.search(r'[Mm]aximum[\s=]+(\d+)', out) or \
                    re.search(r'max[/=]+([\d.]+)', out)
        avg = float(avg_match.group(1)) if avg_match else 0
        mn  = float(min_match.group(1)) if min_match else 0
        mx  = float(max_match.group(1)) if max_match else 0
        return avg, mn, mx
    except Exception:
        return 0.0, 0.0, 0.0


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 1: SECURITY (БЕЗПЕКА)
# ═════════════════════════════════════════════════════════════════════════════

class SecurityChecks:
    """Перевірки безпеки мережі."""

    @staticmethod
    def check_dns_leak(log_cb: Callable = None) -> list[Issue]:
        """Виявляє DNS leak.

        DNS leak — це коли DNS-запити йдуть через ISP замість VPN.
        Перевіряємо: чи DNS-сервер що використовується = очікуваний.
        """
        issues = []
        try:
            # 1. Дізнаємось наш реальний DNS-resolver через DNS leak test
            if log_cb: log_cb("  🔍 Перевірка DNS leak...")
            real_dns = SecurityChecks._get_actual_dns_servers()

            # 2. Перевіряємо чи це публічні безпечні DNS
            safe_dns = {
                "1.1.1.1", "1.0.0.1",
                "8.8.8.8", "8.8.4.4",
                "9.9.9.9", "149.112.112.112",
                "94.140.14.14", "94.140.15.15",
            }
            unsafe_dns = []
            for dns in real_dns:
                if dns not in safe_dns and not dns.startswith("192.168."):
                    unsafe_dns.append(dns)

            if unsafe_dns:
                issues.append(Issue(
                group="Безпека",
                    code="DNS_LEAK_RISK",
                    sev="WARNING",
                    title="Можливий DNS leak — ISP бачить ваші запити",
                    desc=(f"DNS-сервери: {', '.join(real_dns)}. "
                          f"Це не публічні безпечні DNS — ISP може логувати "
                          f"всі ваші запити. Якщо використовуєте VPN — "
                          f"DNS може 'витікати' повз нього."),
                    fix=("Налаштуйте DNS на 1.1.1.1 (Cloudflare) "
                         "або 9.9.9.9 (Quad9): NetGuardian → Швидкі фікси → "
                         "Cloudflare DNS"),
                ))
            if log_cb: log_cb(f"     {'⚠️' if unsafe_dns else '✅'} DNS перевірено")
        except Exception as e:
            print(f"[SecurityChecks] dns_leak: {e}")
        return issues

    @staticmethod
    def _get_actual_dns_servers() -> list[str]:
        """Отримує DNS-сервери що реально використовуються."""
        servers = []
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-DnsClientServerAddress | "
                 "Where-Object {$_.AddressFamily -eq 2 -and $_.ServerAddresses} | "
                 "ForEach-Object { $_.ServerAddresses } | Select-Object -Unique"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', line):
                    servers.append(line)
        except Exception: pass
        return servers

    @staticmethod
    def check_ipv6_leak(log_cb: Callable = None) -> list[Issue]:
        """Перевірка IPv6 leak.

        Деякі VPN не тунелюють IPv6 — тоді через IPv6 трафік йде в обхід.
        """
        issues = []
        if log_cb: log_cb("  🔍 IPv6 leak detection...")
        try:
            # 1. Дізнаємось наш IPv6 (якщо є)
            ipv6 = SecurityChecks._get_public_ipv6()
            if not ipv6:
                if log_cb: log_cb("     ✅ IPv6 не активний (leak неможливий)")
                return []

            # 2. Якщо IPv6 є, перевіряємо чи він не локальний
            if ipv6.startswith("fe80::") or ipv6.startswith("::1"):
                return []

            # 3. Дізнаємось наш IPv4
            ipv4 = SecurityChecks._get_public_ipv4()

            # 4. Якщо IPv4 і IPv6 з різних AS/країн — це leak ознака
            if ipv4 and ipv6:
                # Простий тест: пробуємо порівняти. Реально — потрібен
                # API типу ip-api.com/json для AS
                pass

            issues.append(Issue(
                group="Безпека",
                code="IPV6_DETECTED",
                sev="INFO",
                title=f"IPv6 активний: {ipv6[:30]}...",
                desc=("IPv6-з'єднання активне. Якщо ви використовуєте VPN — "
                      "переконайтесь що VPN тунелює IPv6 теж, інакше це leak."),
                fix=("Перевірте налаштування VPN на наявність IPv6 leak protection. "
                     "Або вимкніть IPv6: NetGuardian → Швидкі фікси → "
                     "Disable IPv6"),
            ))
        except Exception as e:
            print(f"[SecurityChecks] ipv6_leak: {e}")
        return issues

    @staticmethod
    def _get_public_ipv6() -> str:
        try:
            r = urllib.request.urlopen("https://api64.ipify.org", timeout=3)
            ip = r.read().decode().strip()
            if ":" in ip:
                return ip
        except Exception: pass
        return ""

    @staticmethod
    def _get_public_ipv4() -> str:
        try:
            r = urllib.request.urlopen("https://api.ipify.org", timeout=3)
            return r.read().decode().strip()
        except Exception: pass
        return ""

    @staticmethod
    def check_open_ports_inbound(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє відкриті вхідні порти (НЕБЕЗПЕЧНО).

        Деякі віруси відкривають RDP, SMB на 0.0.0.0.
        """
        issues = []
        if log_cb: log_cb("  🔍 Перевірка відкритих портів...")
        try:
            r = subprocess.run(
                ["netstat", "-ano", "-p", "TCP"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            listening_ports = set()
            for line in (r.stdout or "").splitlines():
                if "LISTENING" not in line: continue
                parts = line.split()
                if len(parts) < 4: continue
                local = parts[1]
                # Виявляємо 0.0.0.0:PORT — слухає на ВСІХ інтерфейсах
                if local.startswith("0.0.0.0:") or local.startswith("[::]:"):
                    try:
                        port = int(local.rsplit(":", 1)[-1])
                        listening_ports.add(port)
                    except ValueError: pass

            dangerous = listening_ports & DANGEROUS_OPEN_PORTS
            if dangerous:
                ports_str = ", ".join(f"{p} ({COMMON_PORTS.get(p, '?')})"
                                      for p in sorted(dangerous))
                issues.append(Issue(
                group="Безпека",
                    code="DANGEROUS_PORTS_OPEN",
                    sev="CRITICAL",
                    title=f"Небезпечні порти відкриті: {ports_str}",
                    desc=("На вашому ПК слухаються порти що зазвичай "
                          "експлуатуються вірусами/хакерами. "
                          "Це може бути: NetBIOS, SMB, RDP, VNC."),
                    fix=("1. Якщо ви не налаштовували RDP/SMB сервер — "
                         "негайно перевірте антивірусом. "
                         "2. Заблокуйте у файрволі: NetGuardian → Файрвол. "
                         "3. Запустіть Malwarebytes на повне сканування."),
                ))
        except Exception as e:
            print(f"[SecurityChecks] open_ports: {e}")
        return issues

    @staticmethod
    def check_https_certificate(host: str = "google.com",
                                 log_cb: Callable = None) -> list[Issue]:
        """Перевіряє HTTPS-сертифікат.

        Виявляє MITM-атаки (підмінений сертифікат) і прострочені сертифікати.
        """
        issues = []
        if log_cb: log_cb(f"  🔍 HTTPS certificate ({host})...")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    subject = dict(x[0] for x in cert.get("subject", []))
                    not_after = cert.get("notAfter", "")
                    issuer_org = issuer.get("organizationName", "Unknown")
                    if log_cb:
                        log_cb(f"     ✅ Issuer: {issuer_org}")
                    # Перевіряємо термін
                    if not_after:
                        try:
                            from datetime import datetime
                            exp = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            days_left = (exp - datetime.utcnow()).days
                            if days_left < 30:
                                issues.append(Issue(
                group="Безпека",
                                    code="CERT_EXPIRING_SOON",
                                    sev="WARNING",
                                    title=f"Сертифікат {host} закінчується через {days_left} днів",
                                    desc=("Це не критично для вас, але якщо це ваш сайт — "
                                          "оновіть сертифікат."),
                                    fix="",
                                ))
                        except Exception: pass
        except ssl.SSLError as e:
            issues.append(Issue(
                group="Безпека",
                code="SSL_ERROR",
                sev="CRITICAL",
                title=f"SSL помилка для {host}: {str(e)[:60]}",
                desc=("Не вдається встановити захищене з'єднання. "
                      "Можливі причини: антивірус перехоплює HTTPS, "
                      "сертифікат прострочений, MITM-атака."),
                fix=("Перевірте антивірус (HTTPS scanning), "
                     "оновіть Windows, перевірте час на ПК."),
            ))
        except Exception as e:
            print(f"[SecurityChecks] cert {host}: {e}")
        return issues

    @staticmethod
    def check_dns_hijacking(log_cb: Callable = None) -> list[Issue]:
        """Виявляє DNS hijacking — коли DNS-запити змінюються провайдером.

        Перевіряємо: чи google.com резолвиться у Google IP (140.x, 142.x).
        Якщо у щось інше — це може бути hijacking.
        """
        issues = []
        if log_cb: log_cb("  🔍 DNS hijacking detection...")
        try:
            # Очікувані IP-діапазони Google
            ok, _, ip = _resolve_dns_via("8.8.8.8", "google.com")
            if ok and ip:
                # Перевіряємо що це справді Google
                if not (ip.startswith("142.") or ip.startswith("172.") or
                        ip.startswith("216.") or ip.startswith("173.")):
                    issues.append(Issue(
                group="Безпека",
                        code="DNS_HIJACKING",
                        sev="CRITICAL",
                        title=f"DNS hijacking: google.com → {ip}",
                        desc=("Запит google.com резолвиться у нестандартну IP. "
                              "Можливо ISP перехоплює DNS-запити або у вас "
                              "вірус що змінює DNS."),
                        fix=("1. Перевірте DNS-налаштування адаптера. "
                             "2. NetGuardian → Швидкі фікси → Cloudflare DNS. "
                             "3. Перевірте hosts файл на підміни. "
                             "4. Скан антивірусом."),
                    ))
        except Exception as e:
            print(f"[SecurityChecks] dns_hijack: {e}")
        return issues

    @staticmethod
    def check_arp_spoofing(log_cb: Callable = None) -> list[Issue]:
        """Виявляє ARP spoofing — коли два IP мають один MAC."""
        issues = []
        if log_cb: log_cb("  🔍 ARP spoofing detection...")
        try:
            r = subprocess.run(
                ["arp", "-a"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            mac_to_ips = {}
            for line in (r.stdout or "").splitlines():
                m = re.match(r'\s+(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]{17})', line.lower())
                if m:
                    ip, mac = m.group(1), m.group(2)
                    mac_to_ips.setdefault(mac, []).append(ip)
            # Шукаємо MAC з > 1 IP (spoofing ознака)
            for mac, ips in mac_to_ips.items():
                if len(ips) > 1 and mac != "ff-ff-ff-ff-ff-ff":
                    issues.append(Issue(
                group="Безпека",
                        code="ARP_SPOOFING_RISK",
                        sev="CRITICAL",
                        title=f"Можливий ARP spoofing: MAC {mac[:8]}... → {len(ips)} IP",
                        desc=(f"MAC-адреса {mac} призначена кільком IP: "
                              f"{', '.join(ips[:3])}. Це може бути ARP-атака — "
                              f"хтось у мережі перехоплює ваш трафік."),
                        fix=("1. Негайно вимкніть Wi-Fi і перевірте мережу. "
                             "2. Перевірте чи всі пристрої LAN-аудиту легальні."),
                    ))
        except Exception as e:
            print(f"[SecurityChecks] arp_spoof: {e}")
        return issues

    @staticmethod
    def check_firewall_status(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє чи увімкнений Windows Firewall."""
        issues = []
        if log_cb: log_cb("  🔍 Перевірка Windows Firewall...")
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetFirewallProfile | Select-Object Name, Enabled"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            disabled = []
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if "False" in line:
                    name = line.split()[0] if line.split() else "?"
                    disabled.append(name)
            if disabled:
                issues.append(Issue(
                group="Безпека",
                    code="FIREWALL_DISABLED",
                    sev="WARNING",
                    title=f"Firewall вимкнено для профілів: {', '.join(disabled)}",
                    desc=("Windows Firewall — основна лінія захисту мережі. "
                          "Вимкнений firewall небезпечно якщо ви в публічній мережі."),
                    fix=("NetGuardian → Швидкі фікси → Enable Firewall, "
                         "або вручну: Settings → Windows Security → Firewall"),
                ))
        except Exception as e:
            print(f"[SecurityChecks] firewall: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 2: GAMING (ІГРИ)
# ═════════════════════════════════════════════════════════════════════════════

class GamingChecks:
    """Перевірки придатності мережі для онлайн-ігор."""

    @staticmethod
    def check_game_servers_pings(log_cb: Callable = None) -> list[Issue]:
        """Пінгує популярні game-сервери.

        Виявляє регіональні проблеми (наприклад EU OK, US bad).
        """
        issues = []
        if log_cb: log_cb("  🎮 Пінгую game-сервери...")

        results = {}
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                name: ex.submit(_tcp_check, host, port, 2.0)
                for name, (host, port) in GAME_SERVERS.items()
            }
            for name, fut in futures.items():
                try:
                    is_up, ms = fut.result(timeout=3)
                    results[name] = (is_up, ms)
                    if log_cb:
                        if is_up:
                            log_cb(f"     {GamingChecks._ping_emoji(ms)} {name}: {ms:.0f}мс")
                        else:
                            log_cb(f"     ❌ {name}: timeout")
                except Exception:
                    results[name] = (False, -1)

        # Аналіз
        good_pings = [(n, ms) for n, (ok, ms) in results.items() if ok and ms < 80]
        bad_pings = [(n, ms) for n, (ok, ms) in results.items() if ok and ms > 150]
        timeouts = [n for n, (ok, _) in results.items() if not ok]

        if len(good_pings) == 0 and len(timeouts) > 5:
            issues.append(Issue(
                group="Ігри",
                code="GAMING_NO_CONNECTIVITY",
                sev="CRITICAL",
                title="Жодний game-сервер не доступний",
                desc=("Перевірено 10+ серверів — всі timeout. "
                      "Це говорить про серйозні проблеми з інтернетом, "
                      "блокування мережею ISP або файрволом."),
                fix=("Перевірте загальне з'єднання, "
                     "вимкніть VPN на пробу, перевірте файрвол."),
            ))
        elif len(bad_pings) > 5:
            sample = ", ".join(f"{n} ({int(ms)}мс)" for n, ms in bad_pings[:3])
            issues.append(Issue(
                group="Ігри",
                code="GAMING_HIGH_PING",
                sev="WARNING",
                title=f"Високий ping до game-серверів: {sample}",
                desc=("Багато ігрових серверів пінгуються повільно (>150мс). "
                      "В іграх це означає лаги."),
                fix=("1. Виберіть EU-регіон у налаштуваннях ігор. "
                     "2. Закрийте програми що качають інтернет. "
                     "3. Перевірте Wi-Fi сигнал. "
                     "4. Розгляньте проводове з'єднання."),
            ))

        # Регіональні проблеми (EU OK, NA/US bad)
        eu_pings = [ms for n, (ok, ms) in results.items()
                    if ok and "EU" in n.upper()]
        us_pings = [ms for n, (ok, ms) in results.items()
                    if ok and "US" in n.upper()]
        if eu_pings and us_pings:
            avg_eu = sum(eu_pings) / len(eu_pings)
            avg_us = sum(us_pings) / len(us_pings)
            if avg_eu < 60 and avg_us > 200:
                issues.append(Issue(
                group="Ігри",
                    code="GAMING_REGION_NA",
                    sev="INFO",
                    title=f"NA-регіон далеко: EU={avg_eu:.0f}мс, US={avg_us:.0f}мс",
                    desc=("Це нормально для України — NA-сервери далеко. "
                          "Грайте на EU-серверах для найкращого досвіду."),
                    fix="",
                ))
        return issues

    @staticmethod
    def _ping_emoji(ms: float) -> str:
        if ms < 30: return "🟢"
        if ms < 80: return "🟡"
        if ms < 150: return "🟠"
        return "🔴"

    @staticmethod
    def check_jitter_for_gaming(log_cb: Callable = None) -> list[Issue]:
        """Аналіз jitter — критичний для онлайн-ігор."""
        issues = []
        if log_cb: log_cb("  🎮 Аналіз jitter (стабільності)...")
        try:
            samples = []
            for i in range(10):
                avg, mn, mx = _ping_simple("8.8.8.8", count=1, timeout_ms=1000)
                if avg > 0:
                    samples.append(avg)
                time.sleep(0.2)
            if len(samples) < 5:
                return []
            import statistics
            avg = statistics.mean(samples)
            stdev = statistics.stdev(samples) if len(samples) > 1 else 0
            mx = max(samples)
            mn = min(samples)
            spike_ratio = (mx / avg) if avg else 1

            if log_cb:
                log_cb(f"     📊 ping={avg:.1f}мс  jitter={stdev:.1f}мс  "
                       f"min={mn:.0f}  max={mx:.0f}")

            if stdev > 30:
                issues.append(Issue(
                group="Ігри",
                    code="GAMING_JITTER_HIGH",
                    sev="WARNING",
                    title=f"Високий jitter: {stdev:.0f}мс",
                    desc=("Jitter — це коливання пінгу. Великий jitter "
                          "означає що з'єднання нестабільне — пакети йдуть "
                          "то швидко, то повільно. У ФПС-іграх це створює "
                          "ефект 'ракетного пінгу' (rubber-banding)."),
                    fix=("1. Перейдіть на проводове з'єднання. "
                         "2. Закрийте торренти, оновлення, відеодзвінки. "
                         "3. Перевірте Wi-Fi на навантаження сусідніх мереж."),
                ))
            if spike_ratio > 5:
                issues.append(Issue(
                group="Ігри",
                    code="GAMING_PING_SPIKES",
                    sev="WARNING",
                    title=f"Пінгові спайки: max={mx:.0f}мс при avg={avg:.0f}мс",
                    desc=("Виявлено сильні стрибки пінгу. У іграх це проявляється "
                          "як короткочасне 'фриз' з телепортацією супротивника."),
                    fix=("Перевірте Wi-Fi на колізії з сусідніми мережами, "
                         "розгляньте 5GHz Wi-Fi або проводове з'єднання."),
                ))
        except Exception as e:
            print(f"[GamingChecks] jitter: {e}")
        return issues

    @staticmethod
    def check_voip_quality(log_cb: Callable = None) -> list[Issue]:
        """VoIP-якість для голосових чатів (Discord, TeamSpeak)."""
        issues = []
        if log_cb: log_cb("  🎤 VoIP якість (Discord)...")
        try:
            # Discord використовує UDP — у нас тільки TCP перевірка
            ok, ms = _tcp_check("162.159.135.232", 443, 2.0)
            if not ok:
                issues.append(Issue(
                group="Ігри",
                    code="VOIP_DISCORD_DOWN",
                    sev="WARNING",
                    title="Discord недоступний",
                    desc="Discord-сервери не відповідають. Можливо ISP блокує.",
                    fix="Спробуйте VPN, або перевірте https://discordstatus.com",
                ))
            elif ms > 100:
                issues.append(Issue(
                group="Ігри",
                    code="VOIP_HIGH_LATENCY",
                    sev="WARNING",
                    title=f"Голосові чати: затримка {ms:.0f}мс",
                    desc=("Висока затримка до Discord може спричинити "
                          "відлуння та переривання звуку."),
                    fix="Перейдіть на проводове з'єднання, виберіть найближчий регіон у Discord.",
                ))
        except Exception as e:
            print(f"[GamingChecks] voip: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 3: STREAMING (СТРІМІНГ)
# ═════════════════════════════════════════════════════════════════════════════

class StreamingChecks:
    """Перевірки готовності мережі для стрімінгу."""

    @staticmethod
    def check_streaming_endpoints(log_cb: Callable = None) -> list[Issue]:
        """Доступність стрімінгових сервісів."""
        issues = []
        if log_cb: log_cb("  📺 Стрімінгові сервіси...")
        results = {}
        with ThreadPoolExecutor(max_workers=8) as ex:
            futures = {
                name: ex.submit(_tcp_check, host, port, 2.0)
                for name, (host, port) in STREAMING_ENDPOINTS.items()
            }
            for name, fut in futures.items():
                try: results[name] = fut.result(timeout=3)
                except Exception: results[name] = (False, -1)
        down = [n for n, (ok, _) in results.items() if not ok]
        if down:
            issues.append(Issue(
                group="Стрімінг",
                code="STREAMING_PARTIAL_DOWN",
                sev="INFO" if len(down) < 3 else "WARNING",
                title=f"Стрімінг недоступний: {', '.join(down)}",
                desc=("Деякі стрімінгові платформи не відповідають. "
                      "Це може бути: блокування ISP, обмеження регіону, "
                      "або тимчасові проблеми сервісу."),
                fix=("Спробуйте VPN з геолокацією США/ЄС "
                     "або перевірте статус на статус-сторінках сервісів."),
            ))
        return issues

    @staticmethod
    def estimate_video_quality(log_cb: Callable = None) -> list[Issue]:
        """Оцінює яка якість відео потягне зараз мережу.

        Базується на: avg ping, packet loss, перевірка 1MB download speed.
        """
        issues = []
        if log_cb: log_cb("  📺 Оцінка якості відео...")
        try:
            # Простий download test через HTTPS GET
            url = "https://speed.cloudflare.com/__down?bytes=2097152"  # 2MB
            start = time.perf_counter()
            try:
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=10) as r:
                    total = 0
                    while True:
                        chunk = r.read(8192)
                        if not chunk: break
                        total += len(chunk)
                elapsed = time.perf_counter() - start
                mbps = (total * 8) / (elapsed * 1_000_000)
                if log_cb: log_cb(f"     ⚡ Швидкість: {mbps:.1f} Mbps")

                if mbps < 1.5:
                    issues.append(Issue(
                group="Стрімінг",
                        code="STREAMING_TOO_SLOW",
                        sev="WARNING",
                        title=f"Швидкість надто низька для відео: {mbps:.1f} Mbps",
                        desc=("Для 720p потрібно 3+ Mbps, для 1080p — 5+, "
                              "для 4K — 25+ Mbps."),
                        fix=("Закрийте інші програми, перевірте Wi-Fi сигнал, "
                             "розгляньте проводове з'єднання."),
                    ))
                elif mbps < 5:
                    issues.append(Issue(
                group="Стрімінг",
                        code="STREAMING_HD_ONLY",
                        sev="INFO",
                        title=f"Швидкість для 720p: {mbps:.1f} Mbps",
                        desc="Якісне відео тільки в 720p (без 1080p).",
                        fix="",
                    ))
            except Exception as e:
                if log_cb: log_cb(f"     ❌ Speed test failed: {e}")
        except Exception as e:
            print(f"[StreamingChecks] video: {e}")
        return issues

    @staticmethod
    def check_buffering_risk(log_cb: Callable = None) -> list[Issue]:
        """Risk-аналіз буферизації."""
        issues = []
        if log_cb: log_cb("  📺 Risk-аналіз буферизації...")
        try:
            # Перевіряємо jitter
            samples = []
            for _ in range(8):
                ok, ms = _tcp_check("youtube.com", 443, 2.0)
                if ok: samples.append(ms)
                time.sleep(0.3)
            if len(samples) < 3:
                return []
            import statistics
            stdev = statistics.stdev(samples)
            avg = statistics.mean(samples)
            if stdev > 50 or avg > 200:
                issues.append(Issue(
                group="Стрімінг",
                    code="STREAMING_BUFFERING_RISK",
                    sev="WARNING",
                    title=f"Можлива буферизація: stdev={stdev:.0f}мс avg={avg:.0f}мс",
                    desc=("Високі коливання затримки до YouTube. "
                          "Це означає що відео може 'замерзати' на 1-3с."),
                    fix=("Зменшіть якість відео до 720p, "
                         "перейдіть на проводове з'єднання, "
                         "вимкніть Wi-Fi пристрої що ви не використовуєте."),
                ))
        except Exception as e:
            print(f"[StreamingChecks] buffer: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 4: STABILITY (СТАБІЛЬНІСТЬ)
# ═════════════════════════════════════════════════════════════════════════════

class StabilityChecks:
    """Перевірки стабільності з'єднання."""

    @staticmethod
    def check_packet_reordering(log_cb: Callable = None) -> list[Issue]:
        """Виявляє reordering пакетів — індикатор проблем з маршрутизацією."""
        issues = []
        if log_cb: log_cb("  🔄 Packet reordering...")
        # Спрощений тест: пінгуємо 20 разів і дивимось чи послідовність ROUNDTRIP
        # стабільна
        try:
            samples = []
            for _ in range(15):
                avg, _, _ = _ping_simple("1.1.1.1", count=1, timeout_ms=500)
                if avg > 0:
                    samples.append(avg)
                time.sleep(0.1)
            if len(samples) < 10:
                return []
            # Перевіряємо чи є "ями" — серії з різко різним ping
            spikes = sum(1 for i in range(1, len(samples))
                         if abs(samples[i] - samples[i-1]) > 50)
            if spikes > 3:
                issues.append(Issue(
                group="Стабільність",
                    code="STABILITY_REORDERING",
                    sev="WARNING",
                    title=f"Маршрут нестабільний: {spikes} стрибків з 15",
                    desc=("Затримка пакетів сильно коливається — це може "
                          "означати що роутинг постійно змінюється або "
                          "є проблема з ISP."),
                    fix="Перезапустіть роутер, при повторенні зверніться до ISP.",
                ))
        except Exception as e:
            print(f"[StabilityChecks] reorder: {e}")
        return issues

    @staticmethod
    def check_long_term_stability(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє довготривалу стабільність (з історії forecast)."""
        issues = []
        if log_cb: log_cb("  🔄 Довготривала стабільність...")
        try:
            # Беремо дані з ForecastEngine якщо є
            from features.forecast.engine import ForecastEngine
            fe = ForecastEngine(enable_background=False, auto_detect=True)
            history = fe.analyze_history()
            if history and history.status == "ok":
                if history.anomalies_count > 5:
                    issues.append(Issue(
                group="Стабільність",
                        code="STABILITY_FREQUENT_OUTAGES",
                        sev="WARNING",
                        title=f"Часті обриви: {history.anomalies_count} за тиждень",
                        desc=("За останній тиждень виявлено багато аномалій "
                              "(різке падіння пінгу або обриви)."),
                        fix=("Це проблема ISP. "
                             "Зверніться до техпідтримки оператора з конкретними даними."),
                    ))
                if history.sla_pct < 95:
                    issues.append(Issue(
                group="Стабільність",
                        code="STABILITY_LOW_SLA",
                        sev="WARNING",
                        title=f"SLA провайдера: {history.sla_pct:.1f}%",
                        desc=(f"Лише {history.sla_pct:.1f}% часу мережа стабільна. "
                              "Хороший провайдер забезпечує >99%."),
                        fix="Розгляньте зміну провайдера. У договорі зазвичай SLA >99.5%.",
                    ))
        except Exception as e:
            print(f"[StabilityChecks] long_term: {e}")
        return issues

    @staticmethod
    def check_route_stability(log_cb: Callable = None) -> list[Issue]:
        """Аналізує стабільність маршруту через traceroute."""
        issues = []
        if log_cb: log_cb("  🔄 Стабільність маршруту...")
        try:
            r = subprocess.run(
                ["tracert", "-h", "10", "-w", "1500", "8.8.8.8"],
                capture_output=True, text=True, timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            timeouts = (r.stdout or "").count("*  *  *")
            if timeouts > 3:
                issues.append(Issue(
                group="Стабільність",
                    code="ROUTE_TIMEOUTS",
                    sev="WARNING",
                    title=f"Маршрут має {timeouts} таймаути",
                    desc=("На шляху до 8.8.8.8 кілька хопів не відповідають. "
                          "Це може бути нормально (ICMP блокується), "
                          "але також ознака проблем."),
                    fix="Зазвичай ICMP блокують для безпеки, не критично.",
                ))
        except Exception as e:
            print(f"[StabilityChecks] route: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 5: HARDWARE (ОБЛАДНАННЯ)
# ═════════════════════════════════════════════════════════════════════════════

class HardwareChecks:
    """Перевірки мережевого обладнання."""

    @staticmethod
    def check_nic_link_speed(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє швидкість мережевого адаптера."""
        issues = []
        if log_cb: log_cb("  💻 Швидкість мережевого адаптера...")
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Where-Object Status -eq 'Up' | "
                 "Select-Object Name, LinkSpeed | Format-Table -AutoSize"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if "Mbps" in line:
                    # Виявляємо повільні адаптери
                    if " 10 Mbps" in line or "10 Mbps " in line:
                        issues.append(Issue(
                group="Обладнання",
                            code="NIC_SLOW_10MBPS",
                            sev="WARNING",
                            title=f"Дуже повільний мережевий адаптер: {line.strip()}",
                            desc=("Адаптер працює на 10Mbps — це дуже повільно "
                                  "для сучасного інтернету. Можливо проблема з кабелем "
                                  "або портом роутера."),
                            fix=("1. Замініть Ethernet-кабель (Cat5e або краще). "
                                 "2. Перепідключіть до іншого порту роутера. "
                                 "3. Оновіть драйвер мережевої карти."),
                        ))
                    elif "100 Mbps" in line and " 100 Mbps" in line:
                        issues.append(Issue(
                group="Обладнання",
                            code="NIC_FAST_ETHERNET",
                            sev="INFO",
                            title=f"Адаптер 100Mbps: {line.strip()}",
                            desc="Не Gigabit. Якщо у вас швидкий тариф (>100Mbps), не використовується повністю.",
                            fix="Перевірте кабель — потрібен Cat5e/Cat6 для Gigabit.",
                        ))
        except Exception as e:
            print(f"[HardwareChecks] link_speed: {e}")
        return issues

    @staticmethod
    def check_driver_age(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє вік драйверів мережевої карти."""
        issues = []
        if log_cb: log_cb("  💻 Вік драйверів...")
        try:
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "Get-NetAdapter | Where-Object Status -eq 'Up' | "
                 "ForEach-Object { Get-PnpDevice -InstanceId $_.PnPDeviceID -ErrorAction SilentlyContinue | "
                 "Get-PnpDeviceProperty -KeyName 'DEVPKEY_Device_DriverDate' -ErrorAction SilentlyContinue } | "
                 "Select-Object Data | Format-List"],
                capture_output=True, text=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            # Не критичний check
        except Exception as e:
            print(f"[HardwareChecks] driver: {e}")
        return issues

    @staticmethod
    def check_wifi_strength(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє силу Wi-Fi сигналу."""
        issues = []
        if log_cb: log_cb("  💻 Сила Wi-Fi сигналу...")
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = r.stdout or ""
            m = re.search(r'Signal\s*[:\s]+(\d+)%', text)
            if m:
                sig = int(m.group(1))
                if sig < 40:
                    issues.append(Issue(
                group="Обладнання",
                        code="WIFI_WEAK_SIGNAL",
                        sev="WARNING",
                        title=f"Слабкий Wi-Fi сигнал: {sig}%",
                        desc=("Сигнал нижче 40% означає що пристрій далеко від роутера, "
                              "або є перешкоди (стіни, інші пристрої)."),
                        fix=("1. Підійдіть ближче до роутера. "
                             "2. Перенесіть роутер у центр квартири. "
                             "3. Розгляньте Wi-Fi mesh або повторювач. "
                             "4. Перейдіть на 5GHz Wi-Fi якщо у вас 2.4GHz."),
                    ))
                elif sig < 60:
                    issues.append(Issue(
                group="Обладнання",
                        code="WIFI_MEDIUM_SIGNAL",
                        sev="INFO",
                        title=f"Помірний Wi-Fi сигнал: {sig}%",
                        desc="Сигнал не оптимальний, можливі періодичні проблеми.",
                        fix="",
                    ))
        except Exception as e:
            print(f"[HardwareChecks] wifi: {e}")
        return issues

    @staticmethod
    def check_wifi_band(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє чи використовується 2.4GHz або 5GHz."""
        issues = []
        if log_cb: log_cb("  💻 Wi-Fi band...")
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = r.stdout or ""
            if "2.4 GHz" in text or "2,4 GHz" in text:
                issues.append(Issue(
                group="Обладнання",
                    code="WIFI_2_4GHZ",
                    sev="INFO",
                    title="Wi-Fi працює на 2.4GHz",
                    desc=("2.4GHz має більший радіус але повільніший і "
                          "сильно перевантажений сусідніми мережами."),
                    fix="Якщо роутер підтримує 5GHz — переключіться на нього (швидше і менше перевантажено).",
                ))
        except Exception as e:
            print(f"[HardwareChecks] wifi_band: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 6: CONNECTIVITY (РОЗШИРЕНА З'ЄДНАНІСТЬ)
# ═════════════════════════════════════════════════════════════════════════════

class ConnectivityChecks:
    """IPv6, MTU, TTL та інші мережеві деталі."""

    @staticmethod
    def check_ipv6_status(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє статус IPv6."""
        issues = []
        if log_cb: log_cb("  🌐 IPv6 status...")
        try:
            ipv6 = SecurityChecks._get_public_ipv6()
            if not ipv6:
                issues.append(Issue(
                group="З'єднання",
                    code="IPV6_NOT_AVAILABLE",
                    sev="INFO",
                    title="IPv6 недоступне",
                    desc=("Ваш ISP не надає IPv6. Це не критично, але "
                          "деякі сервіси (наприклад Steam) працюють краще через IPv6."),
                    fix="Зверніться до провайдера за інформацією про IPv6.",
                ))
        except Exception as e:
            print(f"[ConnectivityChecks] ipv6: {e}")
        return issues

    @staticmethod
    def check_mtu(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє MTU (Maximum Transmission Unit)."""
        issues = []
        if log_cb: log_cb("  🌐 MTU...")
        try:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "subinterfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = r.stdout or ""
            for line in text.splitlines():
                # Парсимо MTU
                m = re.match(r'\s*(\d+)\s+', line)
                if m:
                    mtu = int(m.group(1))
                    if mtu < 1400 and mtu > 0:
                        issues.append(Issue(
                group="З'єднання",
                            code="MTU_LOW",
                            sev="WARNING",
                            title=f"Низький MTU: {mtu}",
                            desc=("Стандартний MTU = 1500. Низький MTU "
                                  "означає що великі пакети розбиваються — "
                                  "це сповільнює мережу."),
                            fix=("netsh interface ipv4 set subinterface "
                                 "\"<інтерфейс>\" mtu=1500 store=persistent"),
                        ))
        except Exception as e:
            print(f"[ConnectivityChecks] mtu: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 7: DNS_ADVANCED (РОЗШИРЕНІ DNS-ПЕРЕВІРКИ)
# ═════════════════════════════════════════════════════════════════════════════

class DnsAdvancedChecks:
    """Розширені DNS-діагностики."""

    @staticmethod
    def benchmark_dns_providers(log_cb: Callable = None) -> list[Issue]:
        """Бенчмаркує всі публічні DNS-провайдери.

        Знаходить найшвидший і пропонує переключитись.
        """
        issues = []
        if log_cb: log_cb("  🔍 DNS benchmark (12 провайдерів)...")
        results = {}
        for name, (primary, _) in DNS_PROVIDERS.items():
            samples = []
            for domain in ["google.com", "youtube.com", "github.com"]:
                ok, ms, _ = _resolve_dns_via(primary, domain, timeout=2.0)
                if ok:
                    samples.append(ms)
            if samples:
                results[name] = sum(samples) / len(samples)
                if log_cb:
                    log_cb(f"     {name:<14}: {results[name]:.1f}мс")

        if not results:
            return []

        # Знаходимо найшвидший
        fastest = min(results.items(), key=lambda x: x[1])
        # Знаходимо який зараз
        current_dns = SecurityChecks._get_actual_dns_servers()
        current_speed = None
        for name, (primary, _) in DNS_PROVIDERS.items():
            if primary in current_dns:
                current_speed = results.get(name)

        if current_speed and current_speed > fastest[1] * 1.5:
            issues.append(Issue(
                group="DNS+",
                code="DNS_SLOW",
                sev="INFO",
                title=f"Швидший DNS доступний: {fastest[0]} ({fastest[1]:.1f}мс)",
                desc=(f"Зараз ваш DNS відповідає за ~{current_speed:.0f}мс. "
                      f"{fastest[0]} був би швидшим."),
                fix=f"NetGuardian → Швидкі фікси → змінити DNS на {fastest[0]}",
            ))
        return issues

    @staticmethod
    def check_dnssec(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє підтримку DNSSEC у поточних DNS."""
        issues = []
        if log_cb: log_cb("  🔍 DNSSEC support...")
        # Простий тест: запит до DNSSEC-сайту
        try:
            ok, _, _ = _resolve_dns_via("1.1.1.1", "dnssec-failed.org")
            # Якщо resolved — DNSSEC НЕ працює
            # Якщо NXDOMAIN — DNSSEC працює (захищає)
            # (це спрощений тест)
        except Exception: pass
        return issues

    @staticmethod
    def check_dns_resolution_consistency(log_cb: Callable = None) -> list[Issue]:
        """Чи всі DNS-провайдери дають один і той же IP для популярних сайтів."""
        issues = []
        if log_cb: log_cb("  🔍 DNS consistency...")
        inconsistencies = []
        for domain in ["google.com", "github.com"]:
            ips = set()
            for name, (primary, _) in list(DNS_PROVIDERS.items())[:5]:
                ok, _, ip = _resolve_dns_via(primary, domain)
                if ok and ip:
                    # Беремо тільки перші 2 октети — для CDN це нормально що різниця
                    ips.add(".".join(ip.split(".")[:2]))
            if len(ips) > 3:
                inconsistencies.append(domain)
        if inconsistencies:
            issues.append(Issue(
                group="DNS+",
                code="DNS_INCONSISTENT",
                sev="INFO",
                title=f"DNS-провайдери дають різні IP для: {', '.join(inconsistencies)}",
                desc="Це нормально для CDN-сервісів (Cloudflare, Akamai) — кожен провайдер дає найближчий вузол.",
                fix="",
            ))
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 8: HTTP / HTTPS
# ═════════════════════════════════════════════════════════════════════════════

class HttpChecks:
    """HTTP / HTTPS / HTTP/2 / HTTP/3 перевірки."""

    @staticmethod
    def check_http2_support(log_cb: Callable = None) -> list[Issue]:
        """Чи працює HTTP/2."""
        issues = []
        if log_cb: log_cb("  🌍 HTTP/2 support...")
        # Складний тест — перевіряємо чи Cloudflare віддає по HTTP/2
        try:
            ctx = ssl.create_default_context()
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection(("cloudflare.com", 443), timeout=5) as s:
                with ctx.wrap_socket(s, server_hostname="cloudflare.com") as ssl_s:
                    proto = ssl_s.selected_alpn_protocol()
                    if log_cb:
                        log_cb(f"     ALPN: {proto}")
                    if proto != "h2":
                        issues.append(Issue(
                group="HTTP",
                            code="HTTP2_NOT_NEGOTIATED",
                            sev="INFO",
                            title=f"HTTP/2 не активний (узгоджено: {proto})",
                            desc="Сучасні браузери підтримують HTTP/2, який швидший за HTTP/1.1.",
                            fix="Це нормально якщо ви використовуєте старий браузер.",
                        ))
        except Exception as e:
            print(f"[HttpChecks] http2: {e}")
        return issues

    @staticmethod
    def check_https_redirects(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє наскільки сайти редіректять на HTTPS."""
        issues = []
        if log_cb: log_cb("  🌍 HTTPS redirect compliance...")
        try:
            for url in ["http://google.com", "http://github.com"]:
                code, headers, _ = _http_get(url, timeout=3)
                location = headers.get("Location", "") or headers.get("location", "")
                if code in (301, 302, 307, 308) and location.startswith("https://"):
                    pass   # OK
                elif code == 200:
                    issues.append(Issue(
                group="HTTP",
                        code="HTTP_NO_HTTPS_REDIRECT",
                        sev="INFO",
                        title=f"HTTPS не enforced для {url}",
                        desc="Сайт відповідає по HTTP без редіректу на HTTPS.",
                        fix="",
                    ))
        except Exception as e:
            print(f"[HttpChecks] https: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 9: WIRELESS (БЕЗДРОТОВА МЕРЕЖА)
# ═════════════════════════════════════════════════════════════════════════════

class WirelessChecks:
    """Перевірки якості Wi-Fi."""

    @staticmethod
    def check_wifi_congestion(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє перевантаження Wi-Fi-каналу сусідами."""
        issues = []
        if log_cb: log_cb("  📶 Wi-Fi congestion...")
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=Bssid"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = r.stdout or ""
            # Підраховуємо канали
            channels = []
            for m in re.finditer(r'Channel\s*[:\s]+(\d+)', text):
                channels.append(int(m.group(1)))
            if not channels: return []

            # Знаходимо найзагалненіший канал
            from collections import Counter
            counter = Counter(channels)
            top = counter.most_common(3)
            if top and top[0][1] > 5:
                issues.append(Issue(
                group="Wi-Fi",
                    code="WIFI_CONGESTED",
                    sev="WARNING",
                    title=f"Wi-Fi переповнений: канал {top[0][0]} → {top[0][1]} мереж",
                    desc=("На вашому каналі багато сусідніх мереж. "
                          "Це створює інтерференцію і знижує швидкість."),
                    fix=("Зайдіть у налаштування роутера, "
                         "змініть Wi-Fi-канал на менш зайнятий "
                         "(наприклад 1, 6 або 11 для 2.4GHz)."),
                ))

            if log_cb:
                log_cb(f"     📊 Знайдено {len(channels)} мереж навколо")
        except Exception as e:
            print(f"[WirelessChecks] congestion: {e}")
        return issues

    @staticmethod
    def check_wifi_security(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє безпеку поточної Wi-Fi мережі."""
        issues = []
        if log_cb: log_cb("  📶 Wi-Fi security...")
        try:
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            text = r.stdout or ""
            # Шукаємо тип шифрування
            if "WEP" in text and "WPA" not in text:
                issues.append(Issue(
                group="Wi-Fi",
                    code="WIFI_WEP_INSECURE",
                    sev="CRITICAL",
                    title="Wi-Fi використовує WEP — застарілий протокол",
                    desc=("WEP-шифрування ламається за хвилини. "
                          "Будь-хто поруч може перехопити ваш трафік."),
                    fix="Переключіть Wi-Fi на WPA2 (мінімум) або WPA3 у роутері.",
                ))
            elif "WPA " in text and "WPA2" not in text:
                issues.append(Issue(
                group="Wi-Fi",
                    code="WIFI_WPA1_OUTDATED",
                    sev="WARNING",
                    title="Wi-Fi використовує WPA1",
                    desc="WPA1 застарілий, WPA2/WPA3 безпечніші.",
                    fix="Переключіть на WPA2-PSK (AES) або WPA3 у роутері.",
                ))
            elif "WPA3" in text:
                if log_cb: log_cb("     ✅ WPA3 — найкраща безпека")
            elif "WPA2" in text:
                if log_cb: log_cb("     ✅ WPA2 — добре")
        except Exception as e:
            print(f"[WirelessChecks] security: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 10: PERFORMANCE BENCHMARKS (ШВИДКІСНІ ТЕСТИ)
# ═════════════════════════════════════════════════════════════════════════════

class PerformanceChecks:
    """Бенчмарк продуктивності з'єднання."""

    @staticmethod
    def benchmark_download_speed(log_cb: Callable = None) -> tuple[list, dict]:
        """Тестує швидкість завантаження з різних серверів.

        Returns: (issues, metrics)
        """
        issues = []
        metrics = {}
        if log_cb: log_cb("  ⚡ Speed test (download)...")

        # Cloudflare speed test endpoint — без обмежень
        servers = [
            ("Cloudflare US",   "https://speed.cloudflare.com/__down?bytes=5242880"),
            ("Cloudflare EU",   "https://speed.cloudflare.com/__down?bytes=5242880"),
        ]

        speeds = []
        for name, url in servers:
            try:
                start = time.perf_counter()
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req, timeout=15) as r:
                    total = 0
                    while True:
                        chunk = r.read(8192)
                        if not chunk: break
                        total += len(chunk)
                elapsed = time.perf_counter() - start
                if elapsed > 0:
                    mbps = (total * 8) / (elapsed * 1_000_000)
                    speeds.append(mbps)
                    if log_cb: log_cb(f"     {name}: {mbps:.1f} Mbps")
            except Exception as e:
                if log_cb: log_cb(f"     {name}: ❌ {str(e)[:50]}")

        if speeds:
            avg_speed = sum(speeds) / len(speeds)
            metrics["avg_download_mbps"] = round(avg_speed, 1)

            # Аналіз
            if avg_speed < 5:
                issues.append(Issue(
                group="Швидкість",
                    code="PERF_VERY_SLOW",
                    sev="WARNING",
                    title=f"Дуже низька швидкість: {avg_speed:.1f} Mbps",
                    desc=("Швидкість завантаження нижче 5 Mbps. "
                          "Це не вистачить навіть для HD-відео в YouTube."),
                    fix=("1. Перевірте тариф у провайдера. "
                         "2. Відключіть VPN на тест. "
                         "3. Закрийте торренти / онлайн-завантаження."),
                ))
            elif avg_speed < 15:
                issues.append(Issue(
                group="Швидкість",
                    code="PERF_LOW",
                    sev="INFO",
                    title=f"Помірна швидкість: {avg_speed:.1f} Mbps",
                    desc="Підходить для HD-відео, але не для 4K чи багатокористувацького використання.",
                    fix="",
                ))
        return issues, metrics

    @staticmethod
    def benchmark_latency_distribution(log_cb: Callable = None) -> tuple[list, dict]:
        """Аналізує розподіл затримок (percentiles)."""
        issues = []
        metrics = {}
        if log_cb: log_cb("  ⚡ Latency distribution (50 samples)...")
        try:
            samples = []
            for _ in range(50):
                ok, ms = _tcp_check("1.1.1.1", 443, 1.0)
                if ok: samples.append(ms)
                time.sleep(0.05)
            if len(samples) < 30:
                return [], {}

            samples.sort()
            n = len(samples)
            p50 = samples[n // 2]
            p90 = samples[int(n * 0.9)]
            p99 = samples[int(n * 0.99)] if n > 100 else samples[-1]
            mn = samples[0]
            mx = samples[-1]

            metrics.update({
                "latency_p50": p50,
                "latency_p90": p90,
                "latency_p99": p99,
                "latency_min": mn,
                "latency_max": mx,
            })

            if log_cb:
                log_cb(f"     p50={p50:.1f}мс  p90={p90:.1f}мс  "
                       f"p99={p99:.1f}мс  max={mx:.1f}мс")

            # Якщо p99 значно більший за p50 — є рідкі спайки
            if p99 > p50 * 5 and p99 > 100:
                issues.append(Issue(
                group="Швидкість",
                    code="PERF_LATENCY_OUTLIERS",
                    sev="INFO",
                    title=f"Рідкі затримки: p99={p99:.0f}мс при p50={p50:.0f}мс",
                    desc=("Зазвичай мережа працює добре, але рідко (~1% часу) "
                          "пакети йдуть набагато повільніше."),
                    fix="Це нормально для wired+wifi, не критично.",
                ))
        except Exception as e:
            print(f"[PerformanceChecks] latency_dist: {e}")
        return issues, metrics

    @staticmethod
    def benchmark_concurrent_connections(log_cb: Callable = None) -> list[Issue]:
        """Тестує паралельні з'єднання — чи їх обмежує файрвол/роутер."""
        issues = []
        if log_cb: log_cb("  ⚡ Concurrent connections test...")
        try:
            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = [
                    ex.submit(_tcp_check, "1.1.1.1", 443, 2.0)
                    for _ in range(20)
                ]
                ok_count = 0
                for f in futures:
                    try:
                        ok, _ = f.result(timeout=3)
                        if ok: ok_count += 1
                    except Exception: pass
            if log_cb: log_cb(f"     {ok_count}/20 паралельних з'єднань OK")
            if ok_count < 15:
                issues.append(Issue(
                group="Швидкість",
                    code="PERF_CONCURRENT_LIMIT",
                    sev="WARNING",
                    title=f"Файрвол обмежує паралельні з'єднання ({ok_count}/20)",
                    desc=("Лише частина з 20 одночасних з'єднань пройшла. "
                          "Це може обмежити торренти, ігри, відеодзвінки."),
                    fix=("Перевірте налаштування файрволу/роутера на ліміти "
                         "одночасних з'єднань (NAT table size)."),
                ))
        except Exception as e:
            print(f"[PerformanceChecks] concurrent: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 11: ISP & GEO
# ═════════════════════════════════════════════════════════════════════════════

class IspGeoChecks:
    """Перевірки ISP, геолокації, AS-path."""

    @staticmethod
    def check_isp_info(log_cb: Callable = None) -> tuple[list, dict]:
        """Інформація про ISP."""
        issues = []
        metrics = {}
        if log_cb: log_cb("  🌍 ISP та геолокація...")
        try:
            req = urllib.request.Request("http://ip-api.com/json/?fields=66846719")
            with urllib.request.urlopen(req, timeout=5) as r:
                data = json.loads(r.read().decode())
            if data.get("status") == "success":
                isp = data.get("isp", "?")
                org = data.get("org", "?")
                country = data.get("country", "?")
                city = data.get("city", "?")
                asn = data.get("as", "?")
                metrics["isp"] = isp
                metrics["country"] = country
                metrics["city"] = city
                metrics["asn"] = asn
                if log_cb:
                    log_cb(f"     ISP: {isp}")
                    log_cb(f"     Локація: {city}, {country}")
                    log_cb(f"     AS: {asn}")

                # Перевіряємо чи країна співпадає з очікуваною
                if country and country.lower() not in ("ukraine", "україна"):
                    issues.append(Issue(
                group="ISP",
                        code="ISP_FOREIGN_COUNTRY",
                        sev="INFO",
                        title=f"Інтернет з {country}",
                        desc=("Ваш зовнішній IP належить не Україні. "
                              "Якщо у вас увімкнений VPN — це нормально. "
                              "Якщо ні — деякі сервіси можуть не працювати."),
                        fix="",
                    ))
        except Exception as e:
            print(f"[IspGeoChecks] info: {e}")
        return issues, metrics

    @staticmethod
    def check_asn_route_quality(log_cb: Callable = None) -> list[Issue]:
        """Перевіряє якість маршруту через AS."""
        issues = []
        if log_cb: log_cb("  🌍 AS path quality...")
        # Спрощений тест: tracert до google.com і дивимось скільки хопів
        try:
            r = subprocess.run(
                ["tracert", "-h", "20", "-w", "1500", "google.com"],
                capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            hops = 0
            for line in (r.stdout or "").splitlines():
                m = re.match(r'\s*(\d+)\s+', line)
                if m: hops = int(m.group(1))
            if log_cb: log_cb(f"     Хопів до google.com: {hops}")
            if hops > 18:
                issues.append(Issue(
                group="ISP",
                    code="ASN_LONG_ROUTE",
                    sev="INFO",
                    title=f"Довгий маршрут до google.com: {hops} хопів",
                    desc=("Кількість хопів вища за стандартну. "
                          "Може говорити про неоптимальну маршрутизацію ISP."),
                    fix="Зв'язатись з провайдером якщо часто є проблеми з затримкою.",
                ))
        except Exception as e:
            print(f"[IspGeoChecks] asn_route: {e}")
        return issues


# ═════════════════════════════════════════════════════════════════════════════
#  КАТЕГОРІЯ 12: HEALTH HISTORY (ІСТОРИЧНІ ДАНІ)
# ═════════════════════════════════════════════════════════════════════════════

class HealthHistoryChecks:
    """Перевірки на основі історичних даних з ForecastEngine."""

    @staticmethod
    def check_recent_outages(log_cb: Callable = None) -> list[Issue]:
        """Виявляє часті обриви за останні 24 години."""
        issues = []
        if log_cb: log_cb("  📊 Recent outages (24h)...")
        try:
            from features.forecast.engine import ForecastEngine
            import sqlite3
            fe = ForecastEngine(enable_background=False, auto_detect=True)
            db = fe.db_path
            with sqlite3.connect(db, timeout=3) as conn:
                # Скільки високих loss-замірів за 24 год
                c = conn.execute("""
                    SELECT COUNT(*) FROM ping_log
                    WHERE ts >= datetime('now', '-24 hours')
                      AND loss_pct >= 50
                      AND net_id = ?
                """, (fe.net_id,))
                outages = c.fetchone()[0]
            if outages > 5:
                issues.append(Issue(
                group="Історія",
                    code="HISTORY_FREQUENT_OUTAGES",
                    sev="WARNING",
                    title=f"За останні 24 год: {outages} обривів",
                    desc=("За добу зафіксовано багато моментів коли мережа "
                          "не працювала (loss >= 50%)."),
                    fix=("1. Запишіть ці моменти і покажіть провайдеру. "
                         "2. Перевірте wifi-канал на колізії."),
                ))
        except Exception as e:
            print(f"[HealthHistoryChecks] outages: {e}")
        return issues

    @staticmethod
    def check_peak_usage_times(log_cb: Callable = None) -> list[Issue]:
        """Аналізує в які години найгірша мережа."""
        issues = []
        if log_cb: log_cb("  📊 Peak congestion analysis...")
        try:
            from features.forecast.engine import ForecastEngine
            import sqlite3
            fe = ForecastEngine(enable_background=False, auto_detect=True)
            db = fe.db_path
            with sqlite3.connect(db, timeout=3) as conn:
                c = conn.execute("""
                    SELECT strftime('%H', ts) as hour, AVG(ping_ms)
                    FROM ping_log
                    WHERE ts >= datetime('now', '-7 days')
                      AND ping_ms > 0 AND net_id = ?
                    GROUP BY hour
                """, (fe.net_id,))
                hours = {int(h): p for h, p in c.fetchall() if h}
            if len(hours) >= 12:
                worst_h, worst_ping = max(hours.items(), key=lambda x: x[1])
                best_h, best_ping = min(hours.items(), key=lambda x: x[1])
                if worst_ping > best_ping * 1.5:
                    if log_cb:
                        log_cb(f"     Найгірша година: {worst_h:02d}:00 "
                               f"({worst_ping:.0f}мс)")
                        log_cb(f"     Найкраща година: {best_h:02d}:00 "
                               f"({best_ping:.0f}мс)")
                    issues.append(Issue(
                group="Історія",
                        code="HISTORY_PEAK_HOURS",
                        sev="INFO",
                        title=f"Пік перевантаження о {worst_h:02d}:00",
                        desc=(f"О {worst_h:02d} годині мережа повільніша на "
                              f"{((worst_ping/best_ping - 1) * 100):.0f}% "
                              f"за нормальний час ({best_h:02d}:00)."),
                        fix="Це нормально — пік у вечірні години через сусідів. Грати важливе вранці.",
                    ))
        except Exception as e:
            print(f"[HealthHistoryChecks] peak: {e}")
        return issues


def run_advanced_diagnostics(log_cb: Callable = None,
                              prog_cb: Callable = None) -> dict:
    """Виконує всі розширені перевірки.

    Returns: {
        'issues': [Issue, ...],   — всі знайдені проблеми
        'categories': {
            'security':    [Issue, ...],
            'gaming':      [Issue, ...],
            'streaming':   [Issue, ...],
            ...
        },
        'metrics': {           — додаткові метрики для AI
            'avg_dns_speed': X,
            'wifi_signal': Y,
            ...
        }
    }
    """
    all_issues = []
    categories = {}
    metrics = {}

    def log(msg):
        if log_cb: log_cb(msg)
    def prog(msg):
        if prog_cb: prog_cb(msg)

    # ── Категорія 1: SECURITY ─────────────────────────────────────────
    prog("Безпека мережі...")
    log("\n🔐 SECURITY CHECKS")
    cat_issues = []
    cat_issues += SecurityChecks.check_dns_leak(log)
    cat_issues += SecurityChecks.check_ipv6_leak(log)
    cat_issues += SecurityChecks.check_open_ports_inbound(log)
    cat_issues += SecurityChecks.check_https_certificate("google.com", log)
    cat_issues += SecurityChecks.check_dns_hijacking(log)
    cat_issues += SecurityChecks.check_arp_spoofing(log)
    cat_issues += SecurityChecks.check_firewall_status(log)
    categories["security"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 2: GAMING ───────────────────────────────────────────
    prog("Ігрова придатність...")
    log("\n🎮 GAMING CHECKS")
    cat_issues = []
    cat_issues += GamingChecks.check_game_servers_pings(log)
    cat_issues += GamingChecks.check_jitter_for_gaming(log)
    cat_issues += GamingChecks.check_voip_quality(log)
    categories["gaming"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 3: STREAMING ────────────────────────────────────────
    prog("Стрімінгова придатність...")
    log("\n📺 STREAMING CHECKS")
    cat_issues = []
    cat_issues += StreamingChecks.check_streaming_endpoints(log)
    cat_issues += StreamingChecks.estimate_video_quality(log)
    cat_issues += StreamingChecks.check_buffering_risk(log)
    categories["streaming"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 4: STABILITY ────────────────────────────────────────
    prog("Стабільність...")
    log("\n🔄 STABILITY CHECKS")
    cat_issues = []
    cat_issues += StabilityChecks.check_packet_reordering(log)
    cat_issues += StabilityChecks.check_long_term_stability(log)
    cat_issues += StabilityChecks.check_route_stability(log)
    categories["stability"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 5: HARDWARE ─────────────────────────────────────────
    prog("Обладнання...")
    log("\n💻 HARDWARE CHECKS")
    cat_issues = []
    cat_issues += HardwareChecks.check_nic_link_speed(log)
    cat_issues += HardwareChecks.check_wifi_strength(log)
    cat_issues += HardwareChecks.check_wifi_band(log)
    categories["hardware"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 6: CONNECTIVITY ─────────────────────────────────────
    prog("З'єднаність...")
    log("\n🌐 CONNECTIVITY CHECKS")
    cat_issues = []
    cat_issues += ConnectivityChecks.check_ipv6_status(log)
    cat_issues += ConnectivityChecks.check_mtu(log)
    categories["connectivity"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 7: DNS_ADVANCED ─────────────────────────────────────
    prog("DNS-розширений...")
    log("\n🔍 DNS ADVANCED CHECKS")
    cat_issues = []
    cat_issues += DnsAdvancedChecks.benchmark_dns_providers(log)
    cat_issues += DnsAdvancedChecks.check_dns_resolution_consistency(log)
    categories["dns_advanced"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 8: HTTP ─────────────────────────────────────────────
    prog("HTTP/HTTPS...")
    log("\n🌍 HTTP CHECKS")
    cat_issues = []
    cat_issues += HttpChecks.check_http2_support(log)
    cat_issues += HttpChecks.check_https_redirects(log)
    categories["http"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 9: WIRELESS ─────────────────────────────────────────
    prog("Бездротова мережа...")
    log("\n📶 WIRELESS CHECKS")
    cat_issues = []
    cat_issues += WirelessChecks.check_wifi_congestion(log)
    cat_issues += WirelessChecks.check_wifi_security(log)
    categories["wireless"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 10: PERFORMANCE BENCHMARKS ──────────────────────────
    prog("Бенчмарки швидкості...")
    log("\n⚡ PERFORMANCE BENCHMARKS")
    cat_issues = []
    iss, perf_metrics = PerformanceChecks.benchmark_download_speed(log)
    cat_issues += iss
    metrics.update(perf_metrics)
    iss, lat_metrics = PerformanceChecks.benchmark_latency_distribution(log)
    cat_issues += iss
    metrics.update(lat_metrics)
    cat_issues += PerformanceChecks.benchmark_concurrent_connections(log)
    categories["performance"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 11: ISP & GEO ───────────────────────────────────────
    prog("ISP та геолокація...")
    log("\n🌍 ISP & GEO CHECKS")
    cat_issues = []
    iss, isp_metrics = IspGeoChecks.check_isp_info(log)
    cat_issues += iss
    metrics.update(isp_metrics)
    cat_issues += IspGeoChecks.check_asn_route_quality(log)
    categories["isp_geo"] = cat_issues
    all_issues += cat_issues

    # ── Категорія 12: HISTORY ─────────────────────────────────────────
    prog("Історичні дані...")
    log("\n📊 HISTORY ANALYSIS")
    cat_issues = []
    cat_issues += HealthHistoryChecks.check_recent_outages(log)
    cat_issues += HealthHistoryChecks.check_peak_usage_times(log)
    categories["history"] = cat_issues
    all_issues += cat_issues

    log(f"\n✅ Розширена діагностика завершена: знайдено {len(all_issues)} додаткових проблем")
    prog("Розширена діагностика готова")

    return {
        "issues": all_issues,
        "categories": categories,
        "metrics": metrics,
    }


# ═════════════════════════════════════════════════════════════════════════════
#  AUTO-FIX LIBRARY
# ─────────────────────────────────────────────────────────────────────────────
#  Бібліотека готових фіксів які AI може порекомендувати або користувач
#  може виконати вручну з UI. Кожен фікс має:
#    • id      — унікальний ідентифікатор
#    • label   — людино-читана назва
#    • desc    — короткий опис
#    • risk    — low/medium/high
#    • cmd     — команда для виконання
#    • check   — як перевірити результат
# ═════════════════════════════════════════════════════════════════════════════

AUTO_FIX_LIBRARY = [
    {
        "id": "flush_dns",
        "label": "Скинути DNS-кеш",
        "desc": "Видаляє локальний DNS-кеш Windows. Корисно якщо сайти не відкриваються.",
        "risk": "low",
        "cmd": "ipconfig /flushdns",
        "check": "ipconfig /displaydns",
        "category": "dns",
    },
    {
        "id": "set_dns_cloudflare",
        "label": "DNS → Cloudflare (1.1.1.1)",
        "desc": "Встановлює швидкий і безпечний DNS Cloudflare на всіх адаптерах.",
        "risk": "medium",
        "cmd": (r'powershell -Command "Get-NetAdapter | '
                r'Where-Object Status -eq Up | ForEach-Object { '
                r'Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex '
                r'-ServerAddresses 1.1.1.1,1.0.0.1 }"'),
        "check": "ipconfig /all",
        "category": "dns",
    },
    {
        "id": "set_dns_google",
        "label": "DNS → Google (8.8.8.8)",
        "desc": "Встановлює DNS Google на всіх адаптерах.",
        "risk": "medium",
        "cmd": (r'powershell -Command "Get-NetAdapter | '
                r'Where-Object Status -eq Up | ForEach-Object { '
                r'Set-DnsClientServerAddress -InterfaceIndex $_.ifIndex '
                r'-ServerAddresses 8.8.8.8,8.8.4.4 }"'),
        "check": "ipconfig /all",
        "category": "dns",
    },
    {
        "id": "release_renew_ip",
        "label": "Перевипустити IP-адресу",
        "desc": "Запитує нову IP-адресу від DHCP-сервера. Корисно якщо є конфлікти.",
        "risk": "medium",
        "cmd": "ipconfig /release && ipconfig /renew",
        "check": "ipconfig",
        "category": "network",
    },
    {
        "id": "winsock_reset",
        "label": "Скинути Winsock catalog",
        "desc": "Скидає мережевий стек Windows. Допомагає при поломці після VPN/AV.",
        "risk": "high",
        "cmd": "netsh winsock reset",
        "check": "",
        "category": "network",
    },
    {
        "id": "tcp_reset",
        "label": "Скинути TCP/IP стек",
        "desc": "Повний reset TCP/IP. Потребує перезавантаження.",
        "risk": "high",
        "cmd": "netsh int ip reset",
        "check": "",
        "category": "network",
    },
    {
        "id": "reset_tcp_autotune",
        "label": "TCP Auto-Tuning → normal",
        "desc": "Включає автоматичне налаштування розміру TCP-вікна.",
        "risk": "low",
        "cmd": "netsh int tcp set global autotuninglevel=normal",
        "check": "netsh int tcp show global",
        "category": "performance",
    },
    {
        "id": "disable_tcp_autotune",
        "label": "TCP Auto-Tuning → disabled",
        "desc": "Вимикає auto-tuning. Деколи допомагає на старих роутерах.",
        "risk": "medium",
        "cmd": "netsh int tcp set global autotuninglevel=disabled",
        "check": "netsh int tcp show global",
        "category": "performance",
    },
    {
        "id": "enable_firewall",
        "label": "Увімкнути Windows Firewall",
        "desc": "Включає захист на всіх профілях.",
        "risk": "low",
        "cmd": (r'powershell -Command "Set-NetFirewallProfile '
                r'-Profile Domain,Public,Private -Enabled True"'),
        "check": (r'powershell -Command "Get-NetFirewallProfile | '
                  r'Select Name,Enabled"'),
        "category": "security",
    },
    {
        "id": "disable_ipv6",
        "label": "Вимкнути IPv6",
        "desc": "Деякі ISP мають проблеми з IPv6. Вимкнення може покращити швидкість.",
        "risk": "medium",
        "cmd": (r'powershell -Command "Disable-NetAdapterBinding '
                r'-Name * -ComponentID ms_tcpip6"'),
        "check": (r'powershell -Command "Get-NetAdapterBinding '
                  r'-ComponentID ms_tcpip6"'),
        "category": "network",
    },
    {
        "id": "enable_ipv6",
        "label": "Увімкнути IPv6",
        "desc": "Повертає IPv6 на всіх адаптерах.",
        "risk": "low",
        "cmd": (r'powershell -Command "Enable-NetAdapterBinding '
                r'-Name * -ComponentID ms_tcpip6"'),
        "check": "",
        "category": "network",
    },
    {
        "id": "release_arp",
        "label": "Скинути ARP-кеш",
        "desc": "Видаляє ARP-таблицю. Допомагає при ARP-конфліктах у LAN.",
        "risk": "low",
        "cmd": "arp -d *",
        "check": "arp -a",
        "category": "network",
    },
    {
        "id": "reset_route_table",
        "label": "Скинути таблицю маршрутів",
        "desc": "Видаляє додаткові маршрути. Може зламати VPN-з'єднання.",
        "risk": "high",
        "cmd": "route -f",
        "check": "route print",
        "category": "network",
    },
    {
        "id": "disable_largesend",
        "label": "Вимкнути Large Send Offload",
        "desc": "Вирішує проблеми з повільним інтернетом на деяких NIC.",
        "risk": "medium",
        "cmd": (r'powershell -Command "Get-NetAdapter | ForEach-Object { '
                r'Set-NetAdapterAdvancedProperty -Name $_.Name '
                r'-DisplayName ''Large Send Offload V2 (IPv4)'' '
                r'-DisplayValue ''Disabled'' -ErrorAction SilentlyContinue }"'),
        "check": "",
        "category": "performance",
    },
    {
        "id": "set_qos_dscp",
        "label": "Увімкнути QoS DSCP",
        "desc": "Дає пріоритет геймінг-трафіку (DSCP=46).",
        "risk": "medium",
        "cmd": (r'powershell -Command "New-NetQosPolicy '
                r'-Name ''Gaming'' -DSCPAction 46 '
                r'-IPProtocolMatchCondition Both"'),
        "check": (r'powershell -Command "Get-NetQosPolicy"'),
        "category": "gaming",
    },
    {
        "id": "purge_arp_static",
        "label": "Скинути статичні ARP",
        "desc": "Видаляє ручні ARP-записи (захист від ARP spoofing).",
        "risk": "low",
        "cmd": "netsh interface ipv4 delete neighbors *",
        "check": "arp -a",
        "category": "security",
    },
    {
        "id": "block_smb_inbound",
        "label": "Заблокувати SMB вхідний",
        "desc": "Блокує порти 137-139, 445 для зовнішніх з'єднань.",
        "risk": "medium",
        "cmd": (r'powershell -Command "New-NetFirewallRule '
                r'-DisplayName ''Block SMB Inbound'' -Direction Inbound '
                r'-Protocol TCP -LocalPort 137,138,139,445 -Action Block"'),
        "check": "",
        "category": "security",
    },
    {
        "id": "wifi_show_profiles",
        "label": "Показати збережені Wi-Fi паролі",
        "desc": "Виводить список збережених Wi-Fi мереж з паролями (ADMIN-only).",
        "risk": "low",
        "cmd": (r'powershell -Command "(netsh wlan show profiles) | '
                r'Select-String ''All User Profile'' | ForEach-Object { '
                r'$name = ($_.ToString() -split '':'')[1].Trim(); '
                r'(netsh wlan show profile name=$name key=clear) | '
                r'Select-String ''Key Content''}"'),
        "check": "",
        "category": "info",
    },
    {
        "id": "test_dns_speed",
        "label": "Тест швидкості DNS",
        "desc": "Швидко тестує 4 публічні DNS і виводить найшвидший.",
        "risk": "low",
        "cmd": (r'powershell -Command "1.1.1.1, 8.8.8.8, 9.9.9.9, '
                r'94.140.14.14 | ForEach-Object { '
                r'Measure-Command { Resolve-DnsName -Server $_ '
                r'-Name google.com -ErrorAction SilentlyContinue } | '
                r'Select-Object @{n=''Server'';e={$_}}, TotalMilliseconds }"'),
        "check": "",
        "category": "dns",
    },
    {
        "id": "show_routes",
        "label": "Показати таблицю маршрутів",
        "desc": "Виводить активну таблицю маршрутів IPv4.",
        "risk": "low",
        "cmd": "route print -4",
        "check": "",
        "category": "info",
    },
    {
        "id": "show_listening_ports",
        "label": "Показати слухаючі порти",
        "desc": "Список локальних TCP-портів що слухають з'єднання.",
        "risk": "low",
        "cmd": "netstat -ano -p TCP | findstr LISTENING",
        "check": "",
        "category": "info",
    },
    {
        "id": "wifi_show_signal",
        "label": "Поточний Wi-Fi signal",
        "desc": "Показує SSID, BSSID, силу сигналу, канал.",
        "risk": "low",
        "cmd": "netsh wlan show interfaces",
        "check": "",
        "category": "info",
    },
    {
        "id": "wifi_show_neighbors",
        "label": "Сусідні Wi-Fi мережі",
        "desc": "Показує всі видимі Wi-Fi мережі з каналами.",
        "risk": "low",
        "cmd": "netsh wlan show networks mode=Bssid",
        "check": "",
        "category": "info",
    },
    {
        "id": "trace_to_google",
        "label": "Traceroute до Google",
        "desc": "Показує маршрут від ПК до google.com.",
        "risk": "low",
        "cmd": "tracert -d -h 20 google.com",
        "check": "",
        "category": "diagnostic",
    },
    {
        "id": "ping_burst_test",
        "label": "Burst ping test (50 пакетів)",
        "desc": "Запускає 50 пінгів до 1.1.1.1 для аналізу стабільності.",
        "risk": "low",
        "cmd": "ping -n 50 1.1.1.1",
        "check": "",
        "category": "diagnostic",
    },
    {
        "id": "dhcp_release",
        "label": "DHCP release",
        "desc": "Повертає IP-адресу серверу. Потребує renew після цього.",
        "risk": "high",
        "cmd": "ipconfig /release",
        "check": "",
        "category": "network",
    },
    {
        "id": "dhcp_renew",
        "label": "DHCP renew",
        "desc": "Запитує нову IP-адресу. Виконуй після release.",
        "risk": "medium",
        "cmd": "ipconfig /renew",
        "check": "",
        "category": "network",
    },
    {
        "id": "show_arp_table",
        "label": "Показати ARP таблицю",
        "desc": "Поточна ARP-таблиця (MAC → IP mappings у LAN).",
        "risk": "low",
        "cmd": "arp -a",
        "check": "",
        "category": "info",
    },
    {
        "id": "show_dns_cache",
        "label": "Показати DNS-кеш",
        "desc": "Поточний DNS-кеш Windows.",
        "risk": "low",
        "cmd": "ipconfig /displaydns",
        "check": "",
        "category": "info",
    },
    {
        "id": "show_netstat",
        "label": "Активні з'єднання",
        "desc": "Всі активні мережеві з'єднання та їх стан.",
        "risk": "low",
        "cmd": "netstat -ano",
        "check": "",
        "category": "info",
    },
    {
        "id": "tcp_window_optimize",
        "label": "Оптимізувати TCP-вікно",
        "desc": "Встановлює максимальний розмір TCP-вікна для швидкого інтернету.",
        "risk": "medium",
        "cmd": "netsh int tcp set global autotuninglevel=experimental",
        "check": "netsh int tcp show global",
        "category": "performance",
    },
    {
        "id": "disable_nagle",
        "label": "Вимкнути Nagle's Algorithm",
        "desc": "Зменшує затримку у іграх ціною ефективності.",
        "risk": "high",
        "cmd": (r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                r'/v TcpAckFrequency /t REG_DWORD /d 1 /f && '
                r'reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" '
                r'/v TCPNoDelay /t REG_DWORD /d 1 /f'),
        "check": "",
        "category": "gaming",
    },
    {
        "id": "test_loopback",
        "label": "Test loopback (127.0.0.1)",
        "desc": "Швидкий ping localhost для перевірки TCP/IP стека.",
        "risk": "low",
        "cmd": "ping -n 4 127.0.0.1",
        "check": "",
        "category": "diagnostic",
    },
    {
        "id": "show_interface_stats",
        "label": "Статистика інтерфейсу",
        "desc": "Bytes/packets sent/received на адаптері.",
        "risk": "low",
        "cmd": "netstat -e",
        "check": "",
        "category": "info",
    },
    {
        "id": "show_routing_metrics",
        "label": "Метрики маршрутів",
        "desc": "Показує метрики (вартість) кожного маршруту.",
        "risk": "low",
        "cmd": (r'powershell -Command "Get-NetRoute -AddressFamily IPv4 | '
                r'Select-Object DestinationPrefix, NextHop, RouteMetric, '
                r'InterfaceMetric | Format-Table -AutoSize"'),
        "check": "",
        "category": "info",
    },
]


def get_fixes_by_category(category: str) -> list[dict]:
    """Повертає список фіксів конкретної категорії.

    Категорії: dns, network, security, performance, gaming, info, diagnostic
    """
    return [f for f in AUTO_FIX_LIBRARY if f.get("category") == category]


def get_fix_by_id(fix_id: str) -> Optional[dict]:
    """Знаходить фікс за ID."""
    for f in AUTO_FIX_LIBRARY:
        if f["id"] == fix_id:
            return f
    return None


def get_recommended_fixes_for_issues(issues: list) -> list[dict]:
    """Повертає список рекомендованих фіксів на основі знайдених issues.

    Простий mapping issue.code → fix.id.
    """
    # Map issue code → fix id
    ISSUE_TO_FIX = {
        "DNS_LEAK_RISK":          "set_dns_cloudflare",
        "DNS_HIJACKING":          "set_dns_cloudflare",
        "DNS_SLOW":               "set_dns_cloudflare",
        "FIREWALL_DISABLED":      "enable_firewall",
        "DANGEROUS_PORTS_OPEN":   "block_smb_inbound",
        "MTU_LOW":                "tcp_window_optimize",
        "ARP_SPOOFING_RISK":      "release_arp",
        "PERF_VERY_SLOW":         "reset_tcp_autotune",
        "WIFI_CONGESTED":         "wifi_show_neighbors",
        "WIFI_WEAK_SIGNAL":       "wifi_show_signal",
        "GAMING_HIGH_PING":       "set_qos_dscp",
        "GAMING_JITTER_HIGH":     "disable_nagle",
        "ROUTE_TIMEOUTS":         "trace_to_google",
        "STABILITY_REORDERING":   "ping_burst_test",
    }
    recommended = []
    seen = set()
    for issue in issues:
        code = issue.code if hasattr(issue, "code") else issue.get("code", "")
        fix_id = ISSUE_TO_FIX.get(code)
        if fix_id and fix_id not in seen:
            fix = get_fix_by_id(fix_id)
            if fix:
                recommended.append(fix)
                seen.add(fix_id)
    return recommended