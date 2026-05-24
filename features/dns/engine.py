# core/dns_bench.py
"""
NetGuardian AI — DNS Benchmark & Optimizer Engine
Multi-threaded DNS latency tester + Windows DNS applier
"""

import socket
import struct
import time
import random
import platform
import subprocess
import threading
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Callable


# ──────────────────────────────────────────────
# DNS SERVER DATABASE
# ──────────────────────────────────────────────
# Structure: (name, primary_ip, secondary_ip, category, features, dnssec, security_badge, pros, cons)
DNS_SERVERS = [
    (
        "Cloudflare", "1.1.1.1", "1.0.0.1",
        "⚡ Швидкі / Ігрові", "Найшвидший публічний DNS, без логів", True, False,
        ["Найнижча затримка у світі (~11ms)", "Суворе збереження приватності (no-log)", "DNSSEC + DoH + DoT підтримка", "Не прив'язаний до жодної країни"],
        ["Не блокує рекламу за замовчуванням", "Не фільтрує шкідливі сайти (базова версія)"],
    ),
    (
        "Google Public DNS", "8.8.8.8", "8.8.4.4",
        "⚡ Швидкі / Ігрові", "Google DNS, широке покриття", True, False,
        ["Глобальна інфраструктура, стабільний", "DNSSEC підтримка", "Широко підтримується всіма пристроями", "Відмінна швидкість (~14ms)"],
        ["Google збирає анонімні дані запитів", "Не блокує рекламу або шкідливі сайти", "Корпоративний DNS — ціль для атак"],
    ),
    (
        "Quad9", "9.9.9.9", "149.112.112.112",
        "🛡️ Безпечні", "Блокує malware/phishing, DNSSEC", True, True,
        ["Блокує 1M+ шкідливих доменів щодня", "Некомерційна організація (приватність)", "DNSSEC обов'язковий", "Розміщений у Швейцарії (нейтральна юрисдикція)"],
        ["Трохи повільніший за Cloudflare (~20ms)", "Не блокує рекламу", "Може блокувати деякі легітимні сайти"],
    ),
    (
        "OpenDNS Home", "208.67.222.222", "208.67.220.220",
        "🛡️ Безпечні", "Cisco OpenDNS, фільтрація фішингу", False, True,
        ["Cisco-рівень захисту від фішингу", "Налаштовувані категорії блокування", "Працює з 2006 — перевірений роками", "Швидкий (~20ms)"],
        ["Власником є Cisco — корпоративні дані", "Без DNSSEC на базовому рівні", "Потребує реєстрації для повного функціоналу"],
    ),
    (
        "AdGuard DNS", "94.140.14.14", "94.140.15.15",
        "🔒 Блокування реклами", "Блокує рекламу та трекери", True, True,
        ["Блокує рекламу на рівні DNS (без розширень)", "Блокує трекери та fingerprinting", "DNSSEC + DoH + DoT + DNSCrypt", "Без логів, Кіпр + Росія (сервери поза РФ)"],
        ["Може ламати деякі сайти з рекламою", "Повільніший за Cloudflare (~30ms)", "Може блокувати CDN і легітимний контент"],
    ),
    (
        "CleanBrowsing", "185.228.168.168", "185.228.169.168",
        "🔒 Блокування реклами", "Фільтрація шкідливого контенту", True, True,
        ["Блокує malware, phishing, рекламу", "DNSSEC підтримка", "Кілька профілів: Security / Adult / Family", "Хороший вибір для компаній"],
        ["Менш відомий — менша спільнота", "Може мати затримки у деяких регіонах", "Менш гнучкий ніж AdGuard за налаштуваннями"],
    ),
    (
        "OpenDNS Family", "208.67.222.123", "208.67.220.123",
        "👨\u200d👩\u200d👧 Сімейні (Family)", "Блокує дорослий контент + реклама", False, True,
        ["Блокує весь дорослий контент", "Захист дітей на рівні мережі", "Cisco інфраструктура — надійно", "Простий у налаштуванні"],
        ["Занадто агресивна фільтрація", "Без DNSSEC", "Не підходить для дорослих користувачів", "Обмежена гнучкість налаштувань"],
    ),
    (
        "CleanBrowsing Fam", "185.228.168.10", "185.228.169.11",
        "👨\u200d👩\u200d👧 Сімейні (Family)", "Суворий сімейний фільтр", True, True,
        ["Найсуворіший сімейний фільтр", "DNSSEC підтримка", "Блокує VPN і proxy для обходу", "Безкоштовний базовий план"],
        ["Може блокувати Wikipedia та освітні ресурси", "Не підходить для загального використання", "Деякі помилкові спрацьовування"],
    ),
    (
        "ControlD", "76.76.2.0", "76.76.10.0",
        "⚡ Швидкі / Ігрові", "ControlD — без логів, низька затримка", True, False,
        ["Дуже низька затримка (~12ms)", "Підтримує DoH, DoT, DoQ (QUIC)", "Гнучке налаштування правил блокування", "Zero-log політика"],
        ["Преміум функції потребують підписки", "Менша мережа серверів ніж Cloudflare/Google", "Відносно новий — менше перевірений"],
    ),
    (
        "NextDNS", "45.90.28.0", "45.90.30.0",
        "🔒 Блокування реклами", "Налаштовуваний DNS, блокує трекери", True, True,
        ["Повністю налаштовуваний через веб-панель", "300+ списків блокування на вибір", "Детальна аналітика запитів", "DNSSEC + DoH + DoT"],
        ["Безкоштовний план обмежений 300k запитів/місяць", "Потребує реєстрації облікового запису", "Затримка вища ніж у Cloudflare (~25ms)"],
    ),
    (
        "Comodo Secure DNS", "8.26.56.26", "8.20.247.20",
        "🛡️ Безпечні", "Comodo, блокує шкідливі сайти", False, True,
        ["Корпоративний рівень захисту від malware", "Comodo — відомий у сфері кібербезпеки", "Безкоштовний для домашнього використання"],
        ["Без DNSSEC", "Повільніший за конкурентів (~40ms)", "Менш активно оновлюється", "Меньший пріоритет для домашніх користувачів"],
    ),
    (
        "DNS.Watch", "84.200.69.80", "84.200.70.40",
        "⚡ Швидкі / Ігрові", "Без логів, нейтральний", True, False,
        ["Абсолютно без логів і цензури", "DNSSEC підтримка", "Розміщений у Німеччині (GDPR)", "Відкритий і нейтральний"],
        ["Менша інфраструктура — нижча надійність", "Без захисту від malware", "Може бути повільним за межами Європи"],
    ),
    (
        "Verisign", "64.6.64.6", "64.6.65.6",
        "🛡️ Безпечні", "Verisign, стабільний", True, False,
        ["Verisign управляє .com/.net зонами — надійний", "DNSSEC підтримка", "Висока стабільність і uptime", "Нейтральна політика приватності"],
        ["Без фільтрації реклами чи malware", "Трохи повільніший (~25ms)", "Менш відомий як публічний DNS"],
    ),
]

TEST_HOSTS = ["google.com", "youtube.com", "github.com", "cloudflare.com", "amazon.com"]
QUERIES_PER_SERVER = 5
TIMEOUT_SEC = 1.5


# ──────────────────────────────────────────────
# DNS QUERY BUILDER (RFC 1035)
# ──────────────────────────────────────────────
def _build_dns_query(hostname: str) -> bytes:
    tid = random.randint(0, 65535)
    flags = 0x0100          # Recursion desired
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    question = b""
    for label in hostname.split("."):
        encoded = label.encode("ascii")
        question += bytes([len(encoded)]) + encoded
    question += b"\x00"     # root label
    question += struct.pack(">HH", 1, 1)   # QTYPE=A, QCLASS=IN
    return header + question


def _query_dns(server_ip: str, hostname: str) -> Optional[float]:
    """Single DNS query, returns latency in ms or None on failure."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(TIMEOUT_SEC)
        query = _build_dns_query(hostname)
        t0 = time.perf_counter()
        sock.sendto(query, (server_ip, 53))
        data, _ = sock.recvfrom(512)
        t1 = time.perf_counter()
        sock.close()
        ancount = struct.unpack(">H", data[6:8])[0]
        if len(data) > 12 and ancount > 0:
            return (t1 - t0) * 1000.0
        return None
    except Exception:
        return None


# ──────────────────────────────────────────────
# BENCHMARK ENGINE
# ──────────────────────────────────────────────
class DNSBenchmarker:

    def benchmark_server(self, name: str, ip: str, category: str,
                         features: str, dnssec: bool, security: bool,
                         live_cb: Optional[Callable] = None) -> dict:
        latencies = []
        success_count = 0
        total_queries = 0

        for host in TEST_HOSTS:
            for _ in range(max(1, QUERIES_PER_SERVER // len(TEST_HOSTS))):
                ms = _query_dns(ip, host)
                total_queries += 1
                if ms is not None:
                    latencies.append(ms)
                    success_count += 1

        if latencies:
            avg_ms  = sum(latencies) / len(latencies)
            min_ms  = min(latencies)
            max_ms  = max(latencies)
            jitter  = max_ms - min_ms
            sorted_l = sorted(latencies)
            p95_ms  = sorted_l[int(len(sorted_l) * 0.95)] if len(sorted_l) >= 2 else avg_ms
        else:
            avg_ms = min_ms = max_ms = jitter = p95_ms = None

        reliability = round(success_count / total_queries * 100) if total_queries else 0

        if live_cb and avg_ms is not None:
            live_cb(name, ip, avg_ms)

        return {
            "name": name, "ip": ip, "category": category,
            "features": features, "dnssec": dnssec, "security_badge": security,
            "avg_ms": avg_ms, "min_ms": min_ms, "max_ms": max_ms,
            "jitter_ms": jitter, "p95_ms": p95_ms,
            "reliability": reliability,
        }

    def run_benchmark(self,
                      progress_cb: Optional[Callable[[str], None]] = None,
                      live_result_cb: Optional[Callable[[dict], None]] = None) -> list[dict]:
        results = []
        lock = threading.Lock()

        def _task(entry):
            name, ip, _, cat, feat, dnssec, sec, pros, cons = entry
            if progress_cb:
                progress_cb(f"⏳  Тестую {name} ({ip})…")

            def _live(n, i, ms):
                if progress_cb:
                    progress_cb(f"✅  {n} ({i}) — {ms:.1f} ms")

            res = self.benchmark_server(name, ip, cat, feat, dnssec, sec, live_cb=_live)
            res["pros"] = pros
            res["cons"] = cons

            with lock:
                results.append(res)
                if live_result_cb:
                    live_result_cb(res)
            return res

        with ThreadPoolExecutor(max_workers=len(DNS_SERVERS)) as pool:
            futures = [pool.submit(_task, entry) for entry in DNS_SERVERS]
            for f in as_completed(futures):
                _ = f.result()

        results.sort(key=lambda x: (x["avg_ms"] is None, x["avg_ms"] or 9999))
        return results

    # ──────────────────────────────────────────
    # CURRENT DNS DETECTION
    # ──────────────────────────────────────────
    def get_current_dns(self) -> tuple[Optional[str], Optional[str]]:
        """
        Читає поточний DNS через PowerShell Get-DnsClientServerAddress.
        Повертає (primary_dns_ip, iface_name) адаптера з дефолтним маршрутом.
        """
        # Метод 1: PowerShell — найнадійніший
        try:
            ps = (
                "Get-DnsClientServerAddress -AddressFamily IPv4 "
                "| Where-Object { $_.ServerAddresses.Count -gt 0 } "
                "| Select-Object InterfaceAlias, ServerAddresses "
                "| ConvertTo-Json -Compress"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            raw = r.stdout.decode("utf-8", errors="replace").strip()
            if raw:
                import json as _json
                data = _json.loads(raw)
                # Може бути об'єктом або масивом
                if isinstance(data, dict):
                    data = [data]
                # Шукаємо адаптер з дефолтним маршрутом
                default_iface = self._get_default_route_iface_ps()
                print(f"[DNS] PS dns entries: {[(d.get('InterfaceAlias'), d.get('ServerAddresses')) for d in data]}")
                print(f"[DNS] default iface: {default_iface}")

                # Спочатку шукаємо дефолтний адаптер
                if default_iface:
                    for entry in data:
                        alias = entry.get("InterfaceAlias", "")
                        addrs = entry.get("ServerAddresses", [])
                        if alias == default_iface and addrs:
                            ip = addrs[0] if isinstance(addrs, list) else addrs
                            return str(ip), alias

                # Fallback: перший не-loopback
                for entry in data:
                    alias = entry.get("InterfaceAlias", "")
                    addrs = entry.get("ServerAddresses", [])
                    if addrs and alias not in ("Loopback Pseudo-Interface 1",):
                        ip = addrs[0] if isinstance(addrs, list) else addrs
                        return str(ip), alias
        except Exception as e:
            print(f"[DNS] PowerShell get_current_dns error: {e}")

        # Метод 2: netsh з прямим парсингом байт
        try:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dnsservers"],
                capture_output=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            import re as _re
            for enc in ("utf-8", "cp1251", "cp866"):
                try:
                    text = r.stdout.decode(enc, errors="replace")
                    # Знаходимо всі IPv4 адреси
                    ips = _re.findall(
                        r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text
                    )
                    # Відфільтровуємо gateway/broadcast
                    for ip in ips:
                        parts = ip.split(".")
                        if all(0 <= int(p) <= 255 for p in parts) and ip not in ("0.0.0.0", "255.255.255.255"):
                            print(f"[DNS] netsh fallback found: {ip}")
                            return ip, None
                    break
                except Exception:
                    continue
        except Exception as e:
            print(f"[DNS] netsh fallback error: {e}")

        return None, None

    def _get_default_route_iface_ps(self) -> Optional[str]:
        """
        Знаходить ім'я адаптера через PowerShell (Find-NetRoute або Get-NetIPInterface).
        """
        try:
            ps = (
                "Get-NetIPInterface "
                "| Where-Object { $_.ConnectionState -eq 'Connected' -and $_.AddressFamily -eq 'IPv4' } "
                "| Sort-Object InterfaceMetric "
                "| Select-Object -First 1 -ExpandProperty InterfaceAlias"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True, timeout=8,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            name = r.stdout.decode("utf-8", errors="replace").strip()
            if name and len(name) > 1:
                return name
        except Exception as e:
            print(f"[DNS] _get_default_route_iface_ps error: {e}")
        return None

    def _get_default_route_iface(self) -> Optional[str]:
        return self._get_default_route_iface_ps()

    def compare_with_current(self, results: list[dict]) -> Optional[dict]:
        current_ip, iface = self.get_current_dns()
        if not current_ip:
            return None

        current_result = next((r for r in results if r["ip"] == current_ip), None)

        if not current_result:
            latencies = []
            for host in TEST_HOSTS:
                ms = _query_dns(current_ip, host)
                if ms is not None:
                    latencies.append(ms)
            avg = sum(latencies) / len(latencies) if latencies else None
            current_result = {
                "name": f"Ваш DNS ({current_ip})", "ip": current_ip,
                "avg_ms": avg, "reliability": round(len(latencies)/len(TEST_HOSTS)*100)
            }

        best = next((r for r in results if r["avg_ms"] is not None), None)
        if not best or not current_result.get("avg_ms"):
            return None

        diff_pct = ((current_result["avg_ms"] - best["avg_ms"]) / best["avg_ms"]) * 100

        return {
            "current_ip":   current_ip,
            "current_name": current_result["name"],
            "current_ms":   current_result["avg_ms"],
            "best_name":    best["name"],
            "best_ip":      best["ip"],
            "best_ms":      best["avg_ms"],
            "diff_pct":     diff_pct,
            "iface":        iface or "unknown",
        }

    # ──────────────────────────────────────────
    # DNS LEAK TEST
    # ──────────────────────────────────────────
    def dns_leak_test(self) -> dict:
        resolver_ips = set()
        test_domains = [f"leak{random.randint(10000,99999)}.dnsleaktest.com" for _ in range(3)]

        for domain in test_domains:
            try:
                addrs = socket.getaddrinfo(domain, None)
                for addr in addrs:
                    resolver_ips.add(addr[4][0])
            except Exception:
                pass

        api_resolvers = []
        try:
            import urllib.request, json
            with urllib.request.urlopen("https://bash.ws/dnsleak/test/random?json", timeout=4) as resp:
                data = json.loads(resp.read())
                for entry in data:
                    if entry.get("type") == "resolver":
                        api_resolvers.append({
                            "ip":      entry.get("ip", "?"),
                            "country": entry.get("country_name", "?"),
                            "isp":     entry.get("asn_org", "?"),
                        })
        except Exception:
            pass

        leaked = len(api_resolvers) > 1
        return {
            "resolvers":    api_resolvers,
            "leaked":       leaked,
            "count":        len(api_resolvers),
            "summary":      "⚠️ DNS Leak виявлено!" if leaked else "✅ DNS Leak не знайдено",
        }

    # ──────────────────────────────────────────
    # ADMIN CHECK
    # ──────────────────────────────────────────
    @staticmethod
    def is_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    # ──────────────────────────────────────────
    # APPLY DNS
    # ──────────────────────────────────────────
    def apply_dns(self, dns_ip: str, secondary_ip: str = "8.8.8.8") -> tuple[bool, str, dict]:
        """
        Встановлює DNS через netsh (правильний синтаксис) та PowerShell.
        Перевірка результату теж через PowerShell — не через netsh.
        Returns (success, message, meta).
        """
        meta = {"old_dns": None, "new_dns": dns_ip, "iface": "?"}
        log  = []

        if platform.system() != "Windows":
            return False, "Авто-зміна підтримується лише на Windows.", meta

        if not self.is_admin():
            return False, (
                "Потрібні права Адміністратора.\n"
                "Закрийте програму → ПКМ на ярлику → «Запустити від імені адміністратора»."
            ), meta

        old_ip, _ = self.get_current_dns()
        meta["old_dns"] = old_ip
        log.append(f"[DNS] Поточний DNS: {old_ip}")

        iface, all_ifaces = self._detect_active_iface_verbose()
        meta["iface"] = iface
        alt = secondary_ip if secondary_ip != dns_ip else "8.8.8.8"
        log.append(f"[DNS] Цільовий адаптер: '{iface}'")
        log.append(f"[DNS] Всі адаптери: {all_ifaces}")

        def _verify_ps(target_iface: str) -> bool:
            """Читає DNS через PowerShell і порівнює з target."""
            try:
                ps = (
                    f'(Get-DnsClientServerAddress -InterfaceAlias "{target_iface}" '
                    f'-AddressFamily IPv4).ServerAddresses[0]'
                )
                r = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-Command", ps],
                    capture_output=True, timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
                )
                got = r.stdout.decode("utf-8", errors="replace").strip()
                log.append(f"  verify PS got='{got}'  want='{dns_ip}'")
                return got == dns_ip
            except Exception as e:
                log.append(f"  verify PS error: {e}")
                return False

        NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        # ── Метод 1: netsh правильний синтаксис ────────────────────────
        # Правильно: netsh interface ipv4 set dnsservers "iface" static IP primary validate=no
        log.append("[DNS] Спроба 1: netsh set dnsservers (правильний синтаксис)")
        try:
            r1 = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dnsservers",
                 iface, "static", dns_ip, "primary", "validate=no"],
                capture_output=True, timeout=10, creationflags=NO_WIN
            )
            out1 = (r1.stdout + r1.stderr).decode("cp866", errors="replace").strip()
            log.append(f"  rc={r1.returncode}  out='{out1[:80]}'")

            subprocess.run(
                ["netsh", "interface", "ipv4", "add", "dnsservers",
                 iface, alt, "index=2", "validate=no"],
                capture_output=True, timeout=8, creationflags=NO_WIN
            )
            if _verify_ps(iface):
                self.flush_dns()
                print("\n".join(log))
                return True, f"DNS змінено на {dns_ip} (адаптер: {iface}). Кеш очищено.", meta
        except Exception as e:
            log.append(f"  EXCEPTION: {e}")

        # ── Метод 2: netsh без validate=no ────────────────────────────
        log.append("[DNS] Спроба 2: netsh без validate=no")
        try:
            r2 = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "dnsservers",
                 iface, "static", dns_ip, "primary"],
                capture_output=True, timeout=10, creationflags=NO_WIN
            )
            out2 = (r2.stdout + r2.stderr).decode("cp866", errors="replace").strip()
            log.append(f"  rc={r2.returncode}  out='{out2[:80]}'")

            subprocess.run(
                ["netsh", "interface", "ipv4", "add", "dnsservers",
                 iface, alt, "index=2"],
                capture_output=True, timeout=8, creationflags=NO_WIN
            )
            if _verify_ps(iface):
                self.flush_dns()
                print("\n".join(log))
                return True, f"DNS змінено на {dns_ip} (адаптер: {iface}). Кеш очищено.", meta
        except Exception as e:
            log.append(f"  EXCEPTION: {e}")

        # ── Метод 3: PowerShell для кожного адаптера ──────────────────
        log.append("[DNS] Спроба 3: PowerShell Set-DnsClientServerAddress")
        for iface_try in ([iface] + [i for i in all_ifaces if i != iface]):
            try:
                ps_cmd = (
                    f'Set-DnsClientServerAddress -InterfaceAlias "{iface_try}" '
                    f'-ServerAddresses ("{dns_ip}","{alt}")'
                )
                r3 = subprocess.run(
                    ["powershell", "-NoProfile", "-NonInteractive",
                     "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                    capture_output=True, timeout=15, creationflags=NO_WIN
                )
                out3 = (r3.stdout + r3.stderr).decode("utf-8", errors="replace").strip()
                log.append(f"  iface='{iface_try}' rc={r3.returncode} out='{out3[:80]}'")

                if _verify_ps(iface_try):
                    self.flush_dns()
                    meta["iface"] = iface_try
                    print("\n".join(log))
                    return True, f"DNS змінено через PowerShell на {dns_ip} (адаптер: {iface_try}).", meta
            except Exception as e:
                log.append(f"  EXCEPTION iface='{iface_try}': {e}")

        # ── Всі методи провалились ────────────────────────────────────
        print("\n".join(log))
        return False, (
            f"Не вдалося змінити DNS на адаптері '{iface}'.\n"
            f"Перегляньте консоль для деталей."
        ), meta

    def flush_dns(self) -> bool:
        try:
            subprocess.run(
                ["ipconfig", "/flushdns"],
                capture_output=True, timeout=5,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            return True
        except Exception:
            return False

    def _detect_active_iface(self) -> str:
        iface, _ = self._detect_active_iface_verbose()
        return iface

    def _detect_active_iface_verbose(self) -> tuple[str, list[str]]:
        """
        Повертає (найкращий_адаптер, список_всіх_активних) через PowerShell.
        """
        NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        # 1. Адаптер з найменшим InterfaceMetric (дефолтний маршрут)
        default_iface = self._get_default_route_iface_ps()

        # 2. Всі підключені IPv4 адаптери
        all_ifaces: list[str] = []
        try:
            ps = (
                "Get-NetIPInterface "
                "| Where-Object { $_.ConnectionState -eq 'Connected' "
                "-and $_.AddressFamily -eq 'IPv4' } "
                "| Sort-Object InterfaceMetric "
                "| Select-Object -ExpandProperty InterfaceAlias"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive",
                 "-ExecutionPolicy", "Bypass", "-Command", ps],
                capture_output=True, timeout=10, creationflags=NO_WIN
            )
            for line in r.stdout.decode("utf-8", errors="replace").splitlines():
                name = line.strip()
                if name and name not in all_ifaces:
                    all_ifaces.append(name)
            print(f"[DNS] all connected ifaces (PS): {all_ifaces}")
        except Exception as e:
            print(f"[DNS] Get-NetIPInterface error: {e}")

        # Fallback через netsh якщо PS не дав результату
        if not all_ifaces:
            for enc in ("utf-8", "cp1251", "cp866"):
                try:
                    r = subprocess.run(
                        ["netsh", "interface", "show", "interface"],
                        capture_output=True, timeout=5, creationflags=NO_WIN
                    )
                    text = r.stdout.decode(enc, errors="replace")
                    for line in text.splitlines():
                        parts = line.split()
                        if len(parts) >= 4 and parts[0].lower() in (
                            "connected", "підключено", "подключен"
                        ):
                            name = " ".join(parts[3:]).strip()
                            if name and name not in all_ifaces:
                                all_ifaces.append(name)
                    if all_ifaces:
                        break
                except Exception:
                    continue

        if not all_ifaces:
            all_ifaces = ["Wi-Fi", "Ethernet"]

        best = default_iface or all_ifaces[0]
        # Переконуємося що best є в списку
        if best not in all_ifaces:
            all_ifaces.insert(0, best)

        print(f"[DNS] best='{best}'  all={all_ifaces}")
        return best, all_ifaces

    # ──────────────────────────────────────────
    # ONE-CLICK OPTIMIZE
    # ──────────────────────────────────────────
    def auto_optimize(self, progress_cb=None, done_cb=None):
        def _worker():
            results = self.run_benchmark(progress_cb=progress_cb)
            best = next((r for r in results if r["avg_ms"] is not None), None)
            if not best:
                if done_cb:
                    done_cb(False, "Не знайдено доступних серверів.", results, None)
                return
            secondary = "8.8.8.8"
            for entry in DNS_SERVERS:
                if entry[1] == best["ip"]:
                    secondary = entry[2]
                    break
            ok, msg, meta = self.apply_dns(best["ip"], secondary)
            if done_cb:
                done_cb(ok, msg, results, best, meta)
        threading.Thread(target=_worker, daemon=True).start()

    # ──────────────────────────────────────────
    # GEOLOCATION
    # ──────────────────────────────────────────
    def get_geo(self, ip: str) -> str:
        try:
            import urllib.request, json
            url = f"http://ip-api.com/json/{ip}?fields=country,city,org"
            with urllib.request.urlopen(url, timeout=3) as resp:
                data = json.loads(resp.read())
                city    = data.get("city", "")
                country = data.get("country", "")
                return f"{city}, {country}".strip(", ") or "?"
        except Exception:
            return "?"
