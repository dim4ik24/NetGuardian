"""
core/vpn_manager.py
NetGuardian AI — VPN Manager & Secure Tunneling Engine v2.0
New: ProtonVPN auto-detect, shortcut launcher, connection history,
     bandwidth quota tracker, auto-reconnect with backoff.
"""

import subprocess
import platform
import os
import re
import time
import threading
import json
import socket
import ctypes
import urllib.request
import winreg
from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum
from pathlib import Path


# ─────────────────────────────────────────────────────────────────────────────
#  ENUMS & DATA MODELS
# ─────────────────────────────────────────────────────────────────────────────

class VpnProtocol(Enum):
    WIREGUARD = "WireGuard"
    OPENVPN   = "OpenVPN"
    UNKNOWN   = "Unknown"

class ConnectionState(Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING   = "CONNECTING"
    CONNECTED    = "CONNECTED"
    ERROR        = "ERROR"
    KILL_SWITCH  = "KILL_SWITCH"
    RECONNECTING = "RECONNECTING"


@dataclass
class VpnProfile:
    name: str
    protocol: VpnProtocol
    file_path: str
    server_ip: str   = "—"
    server_host: str = "—"
    location: str    = "—"
    port: int        = 0
    interface: str   = ""
    dns_servers: list = field(default_factory=list)
    raw_config: str  = ""


@dataclass
class TunnelStats:
    state: ConnectionState     = ConnectionState.DISCONNECTED
    public_ip_before: str      = "—"
    public_ip_after: str       = "—"
    ip_changed: bool           = False
    rx_bytes: int              = 0
    tx_bytes: int              = 0
    rx_speed_kbps: float       = 0.0
    tx_speed_kbps: float       = 0.0
    connected_since: float     = 0.0
    dns_leak_safe: bool        = True
    active_profile: Optional[str] = None
    reconnect_count: int       = 0


@dataclass
class ConnectionRecord:
    profile_name: str
    connected_at: float
    disconnected_at: float = 0.0
    duration_sec: float    = 0.0
    ip_before: str         = "—"
    ip_after: str          = "—"
    disconnect_reason: str = "manual"
    rx_bytes: int          = 0
    tx_bytes: int          = 0


# ─────────────────────────────────────────────────────────────────────────────
#  PRIVILEGE HELPER
# ─────────────────────────────────────────────────────────────────────────────

def is_admin() -> bool:
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        try:
            return os.geteuid() == 0
        except AttributeError:
            return False


# ─────────────────────────────────────────────────────────────────────────────
#  VPN AUTO-DETECTOR  (ProtonVPN + всі популярні клієнти)
# ─────────────────────────────────────────────────────────────────────────────

class VpnAutoDetector:
    """
    Знаходить VPN-клієнти через: прямі шляхи, реєстр Windows,
    активні процеси, PATH, ярлики Start Menu та Desktop.
    Якщо не знайдено — повертає посилання для завантаження.
    """

    DOWNLOAD_URLS = {
        "ProtonVPN":  "https://protonvpn.com/download/ProtonVPN_win_v3.5.0.exe",
        "WireGuard":  "https://download.wireguard.com/windows-client/wireguard-installer.exe",
        "OpenVPN":    "https://openvpn.net/downloads/openvpn-install.exe",
        "NordVPN":    "https://nordvpn.com/download/",
        "Mullvad":    "https://mullvad.net/en/download/app/exe/latest",
        "ExpressVPN": "https://www.expressvpn.com/download",
        "Tailscale":  "https://tailscale.com/download/windows",
    }

    SIGNATURES = [
        {
            "name": "ProtonVPN", "icon": "🟣",
            "protocol": VpnProtocol.UNKNOWN,
            "check_paths": [
                r"C:\Program Files\Proton\VPN\ProtonVPN.exe",
                r"C:\Program Files\Proton AG\Proton VPN\ProtonVPN.exe",
                r"C:\Program Files (x86)\Proton Technologies\ProtonVPN\ProtonVPN.exe",
                r"C:\Users\{user}\AppData\Local\Programs\proton\ProtonVPN.exe",
                r"C:\Users\{user}\AppData\Local\Proton AG\Proton VPN\ProtonVPN.exe",
                r"C:\Users\{user}\AppData\Local\Proton\VPN\ProtonVPN.exe",
            ],
            "check_exe": ["ProtonVPN.exe", "protonvpn.exe"],
            "reg_keys": [
                r"SOFTWARE\Proton AG\ProtonVPN",
                r"SOFTWARE\Proton Technologies\ProtonVPN",
                r"SOFTWARE\WOW6432Node\Proton AG\ProtonVPN",
                r"SOFTWARE\WOW6432Node\Proton Technologies\ProtonVPN",
            ],
        },
        {
            "name": "WireGuard", "icon": "🔵",
            "protocol": VpnProtocol.WIREGUARD,
            "check_paths": [
                r"C:\Program Files\WireGuard\wireguard.exe",
                r"C:\Program Files\WireGuard\wg.exe",
            ],
            "check_exe": ["wireguard.exe", "wg-quick.exe"],
            "reg_keys": [r"SOFTWARE\WireGuard"],
        },
        {
            "name": "OpenVPN", "icon": "🟠",
            "protocol": VpnProtocol.OPENVPN,
            "check_paths": [
                r"C:\Program Files\OpenVPN\bin\openvpn.exe",
                r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe",
                r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe",
            ],
            "check_exe": ["openvpn.exe", "openvpn-gui.exe"],
            "reg_keys": [r"SOFTWARE\OpenVPN"],
        },
        {
            "name": "NordVPN", "icon": "🔷",
            "protocol": VpnProtocol.UNKNOWN,
            "check_paths": [
                r"C:\Program Files\NordVPN\NordVPN.exe",
                r"C:\Users\{user}\AppData\Local\NordVPN\NordVPN.exe",
            ],
            "check_exe": ["NordVPN.exe"],
            "reg_keys": [r"SOFTWARE\NordVPN"],
        },
        {
            "name": "Mullvad", "icon": "🟤",
            "protocol": VpnProtocol.WIREGUARD,
            "check_paths": [
                r"C:\Program Files\Mullvad VPN\mullvad-vpn.exe",
                r"C:\Program Files\Mullvad VPN\Mullvad VPN.exe",
            ],
            "check_exe": ["mullvad-vpn.exe", "Mullvad VPN.exe"],
            "reg_keys": [r"SOFTWARE\Mullvad VPN"],
        },
        {
            "name": "Tailscale", "icon": "⚪",
            "protocol": VpnProtocol.WIREGUARD,
            "check_paths": [
                r"C:\Program Files\Tailscale\tailscale.exe",
                r"C:\Users\{user}\AppData\Local\Tailscale\tailscale.exe",
            ],
            "check_exe": ["tailscale.exe"],
            "reg_keys": [r"SOFTWARE\Tailscale IPN"],
        },
    ]

    def detect_all(self, log_cb: Optional[Callable] = None) -> list:
        found, missing = [], []
        user = os.environ.get("USERNAME", "User")
        for sig in self.SIGNATURES:
            r = self._detect_one(sig, user, log_cb)
            (found if r["detected"] else missing).append(r)
        return found + missing

    def _detect_one(self, sig: dict, user: str, log_cb) -> dict:
        name = sig["name"]
        def _log(m):
            if log_cb: log_cb(f"  [{name}] {m}")

        # 1 — Direct paths
        for raw in sig.get("check_paths", []):
            path = raw.replace("{user}", user)
            if os.path.exists(path):
                _log(f"знайдено: {path}")
                return self._ok(sig, path)

        # 2 — Windows Registry
        for rk in sig.get("reg_keys", []):
            path = self._reg_find_exe(rk)
            if path:
                _log(f"реєстр: {path}")
                return self._ok(sig, path)

        # 3 — Running processes (wmic)
        if platform.system() == "Windows":
            path = self._process_scan(sig.get("check_exe", []))
            if path:
                _log(f"активний процес: {path}")
                return self._ok(sig, path)

        # 4 — PATH
        for exe in sig.get("check_exe", []):
            resolved = self._which(exe)
            if resolved:
                _log(f"PATH: {resolved}")
                return self._ok(sig, resolved)

        # 5 — Start Menu / Desktop shortcuts
        path = self._shortcut_scan(name, user)
        if path:
            _log(f"ярлик: {path}")
            return self._ok(sig, path)

        _log("не знайдено")
        return {"name": name, "icon": sig["icon"], "detected": False,
                "path": None, "protocol": sig.get("protocol", VpnProtocol.UNKNOWN),
                "download_url": self.DOWNLOAD_URLS.get(name, "")}

    @staticmethod
    def _ok(sig, path) -> dict:
        return {"name": sig["name"], "icon": sig["icon"], "detected": True,
                "path": path, "protocol": sig.get("protocol", VpnProtocol.UNKNOWN),
                "download_url": ""}

    @staticmethod
    def _reg_find_exe(reg_key: str) -> Optional[str]:
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            try:
                with winreg.OpenKey(hive, reg_key) as key:
                    for val_name in ("InstallLocation", "ExePath", "", "Path"):
                        try:
                            val, _ = winreg.QueryValueEx(key, val_name)
                            if os.path.isfile(val):
                                return val
                            if os.path.isdir(val):
                                for f in os.listdir(val):
                                    if f.lower().endswith(".exe"):
                                        full = os.path.join(val, f)
                                        if os.path.isfile(full):
                                            return full
                        except FileNotFoundError:
                            continue
            except (FileNotFoundError, OSError):
                continue
        return None

    @staticmethod
    def _process_scan(exe_names: list) -> Optional[str]:
        try:
            r = subprocess.run(
                ["wmic", "process", "get", "name,executablepath", "/format:csv"],
                capture_output=True, text=True, encoding="utf-8",
                errors="ignore", timeout=5
            )
            for line in r.stdout.splitlines():
                for exe in exe_names:
                    if exe.lower() in line.lower():
                        parts = line.split(",")
                        if len(parts) >= 3 and os.path.isfile(parts[2].strip()):
                            return parts[2].strip()
                        return f"Процес активний: {exe}"
        except Exception:
            pass
        return None

    @staticmethod
    def _which(exe: str) -> Optional[str]:
        try:
            r = subprocess.run(["where", exe], capture_output=True,
                               text=True, timeout=3)
            if r.returncode == 0:
                p = r.stdout.strip().splitlines()[0]
                return p if os.path.isfile(p) else None
        except Exception:
            pass
        return None

    @staticmethod
    def _shortcut_scan(app_name: str, user: str) -> Optional[str]:
        dirs = [
            r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs",
            rf"C:\Users\{user}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs",
            rf"C:\Users\{user}\Desktop",
            r"C:\Users\Public\Desktop",
        ]
        keyword = app_name.lower().replace(" ", "")
        for d in dirs:
            if not os.path.isdir(d):
                continue
            for root, _, files in os.walk(d):
                for f in files:
                    if not f.lower().endswith(".lnk"):
                        continue
                    fn = f.lower().replace(" ", "").replace(".lnk", "")
                    if keyword in fn or fn in keyword:
                        lnk = os.path.join(root, f)
                        target = VpnAutoDetector._resolve_lnk(lnk)
                        return target if (target and os.path.isfile(target)) else lnk
        return None

    @staticmethod
    def _resolve_lnk(lnk_path: str) -> Optional[str]:
        try:
            script = (
                f"$sh=$([Runtime.InteropServices.Marshal]::GetActiveObject('WScript.Shell') "
                f"2>$null); if(!$sh){{$sh=New-Object -ComObject WScript.Shell}}; "
                f"$sc=$sh.CreateShortcut('{lnk_path}'); Write-Output $sc.TargetPath"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
                capture_output=True, text=True, timeout=5
            )
            t = r.stdout.strip()
            return t if t else None
        except Exception:
            return None


# ─────────────────────────────────────────────────────────────────────────────
#  SHORTCUT LAUNCHER
# ─────────────────────────────────────────────────────────────────────────────

class ShortcutLauncher:
    """Запускає VPN через .exe, .lnk або завантажує інсталятор."""

    def launch(self, path: str, log_cb=None) -> tuple:
        def L(m):
            if log_cb: log_cb(m)
        if not path:
            return False, "❌ Шлях не вказано."
        if path.startswith("Процес активний:"):
            L(f"✅ {path}")
            return True, path
        if path.lower().endswith(".lnk"):
            try:
                os.startfile(path)
                L(f"🚀 Ярлик: {os.path.basename(path)}")
                return True, f"Запущено ярлик: {os.path.basename(path)}"
            except Exception as e:
                return False, f"Помилка ярлика: {e}"
        if os.path.isfile(path):
            try:
                subprocess.Popen([path], shell=False)
                L(f"🚀 {os.path.basename(path)}")
                return True, f"Запущено: {os.path.basename(path)}"
            except Exception as e:
                return False, f"Помилка: {e}"
        return False, f"❌ Файл не знайдено: {path}"

    def download_and_install(self, url: str, name: str, log_cb=None) -> tuple:
        def L(m):
            if log_cb: log_cb(m)
        tmp  = os.environ.get("TEMP", os.path.expanduser("~"))
        dest = os.path.join(tmp, f"NG_install_{name.replace(' ','_')}.exe")
        L(f"⬇️  Завантаження {name}...")
        try:
            def hook(c, bs, tot):
                if tot > 0 and c % 100 == 0:
                    L(f"   {min(100, c*bs*100//tot)}%...")
            urllib.request.urlretrieve(url, dest, hook)
            L(f"✅ Збережено: {dest}")
        except Exception as e:
            return False, f"❌ Помилка завантаження: {e}"
        try:
            subprocess.Popen([dest], shell=False)
            L(f"🚀 Інсталятор {name} запущено.")
            return True, f"Інсталятор {name} запущено."
        except Exception as e:
            return False, f"❌ {e}"


# ─────────────────────────────────────────────────────────────────────────────
#  KILL SWITCH
# ─────────────────────────────────────────────────────────────────────────────

class KillSwitchEngine:
    RULE_OUT = "NetGuardian_KS_OUT"
    RULE_IN  = "NetGuardian_KS_IN"

    def activate(self) -> tuple:
        if not is_admin():
            return False, "Потрібні права адміністратора."
        try:
            for nm, dr in [(self.RULE_OUT, "out"), (self.RULE_IN, "in")]:
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    f"name={nm}", f"dir={dr}", "action=block",
                    "protocol=any", "remoteip=0.0.0.0/0", "enable=yes"
                ], capture_output=True, timeout=10)
            return True, "🛑 Kill Switch АКТИВОВАНО."
        except Exception as e:
            return False, f"Kill Switch помилка: {e}"

    def deactivate(self) -> tuple:
        if not is_admin():
            return False, "Потрібні права адміністратора."
        try:
            for nm in (self.RULE_OUT, self.RULE_IN):
                subprocess.run([
                    "netsh", "advfirewall", "firewall", "delete",
                    "rule", f"name={nm}"
                ], capture_output=True, timeout=10)
            return True, "✅ Kill Switch ЗНЯТО."
        except Exception as e:
            return False, f"Помилка: {e}"

    def is_active(self) -> bool:
        try:
            r = subprocess.run([
                "netsh", "advfirewall", "firewall", "show",
                "rule", f"name={self.RULE_OUT}"
            ], capture_output=True, text=True,
               encoding="cp866", errors="ignore", timeout=5)
            return self.RULE_OUT in r.stdout
        except Exception:
            return False


# ─────────────────────────────────────────────────────────────────────────────
#  SPLIT TUNNEL
# ─────────────────────────────────────────────────────────────────────────────

class SplitTunnelEngine:
    def add_bypass_route(self, cidr: str, gateway: str) -> tuple:
        if not is_admin():
            return False, "Потрібні права адміністратора."
        try:
            net, bits = cidr.split("/")
            mask = self._bits_mask(int(bits))
            subprocess.run(
                ["route", "add", net, "mask", mask, gateway, "metric", "1"],
                capture_output=True, timeout=10
            )
            return True, f"Split route: {cidr} → {gateway}"
        except Exception as e:
            return False, f"Помилка: {e}"

    def remove_bypass_route(self, cidr: str) -> tuple:
        try:
            net, bits = cidr.split("/")
            mask = self._bits_mask(int(bits))
            subprocess.run(["route", "delete", net, "mask", mask],
                           capture_output=True, timeout=10)
            return True, f"Видалено: {cidr}"
        except Exception as e:
            return False, f"Помилка: {e}"

    @staticmethod
    def _bits_mask(b: int) -> str:
        m = (0xFFFFFFFF >> (32 - b)) << (32 - b)
        return ".".join(str((m >> (8 * i)) & 0xFF) for i in [3, 2, 1, 0])


# ─────────────────────────────────────────────────────────────────────────────
#  SHADOW MODE
# ─────────────────────────────────────────────────────────────────────────────

class ShadowModeEngine:
    PROBE_PORTS = [443, 1194, 51820, 80, 8080, 4500, 1701, 500]

    def probe_ports(self, host: str, timeout: float = 1.5,
                    log_cb=None) -> dict:
        results = {}
        for port in self.PROBE_PORTS:
            try:
                with socket.create_connection((host, port), timeout=timeout):
                    results[port] = True
                    if log_cb: log_cb(f"  ✅ {port}/TCP — відкритий")
            except Exception:
                results[port] = False
                if log_cb: log_cb(f"  🔒 {port}/TCP — закритий")
        opens = [p for p, ok in results.items() if ok]
        return {"results": results, "open_ports": opens,
                "recommended": opens[0] if opens else None}


# ─────────────────────────────────────────────────────────────────────────────
#  TRAFFIC MONITOR
# ─────────────────────────────────────────────────────────────────────────────

class TunnelTrafficMonitor:
    def get_wireguard_stats(self, interface: str) -> dict:
        s = {"rx_bytes": 0, "tx_bytes": 0}
        try:
            r = subprocess.run(["wg", "show", interface, "transfer"],
                               capture_output=True, text=True, timeout=5)
            for line in r.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3:
                    s["rx_bytes"] += int(parts[1])
                    s["tx_bytes"] += int(parts[2])
        except Exception:
            pass
        return s

    def get_interface_stats(self, keyword: str) -> dict:
        s = {"rx_bytes": 0, "tx_bytes": 0}
        try:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "subinterfaces"],
                capture_output=True, text=True,
                encoding="cp866", errors="ignore", timeout=5
            )
            for line in r.stdout.splitlines():
                if keyword.lower() in line.lower():
                    p = line.split()
                    if len(p) >= 4:
                        try:
                            s["rx_bytes"] = int(p[2])
                            s["tx_bytes"] = int(p[3])
                        except ValueError:
                            pass
                    break
        except Exception:
            pass
        return s


# ─────────────────────────────────────────────────────────────────────────────
#  GEO RESOLVER
# ─────────────────────────────────────────────────────────────────────────────

class IpGeoResolver:
    IP_SERVICES = [
        "https://api.ipify.org",
        "https://icanhazip.com",
        "https://ifconfig.me/ip",
    ]

    def get_public_ip(self, timeout: float = 4.0) -> str:
        for url in self.IP_SERVICES:
            try:
                with urllib.request.urlopen(url, timeout=timeout) as r:
                    return r.read().decode().strip()
            except Exception:
                continue
        return "—"

    def get_geo(self, ip: str, timeout: float = 5.0) -> dict:
        d = {"country": "—", "city": "—", "org": "—",
             "flag": "🌐", "country_code": "", "lat": 0.0, "lon": 0.0}
        if ip in ("—", ""):
            return d
        try:
            url = f"http://ip-api.com/json/{ip}?fields=country,city,org,countryCode,lat,lon"
            with urllib.request.urlopen(url, timeout=timeout) as r:
                data = json.loads(r.read().decode())
                cc = data.get("countryCode", "")
                return {
                    "country":      data.get("country", "—"),
                    "city":         data.get("city", "—"),
                    "org":          data.get("org", "—"),
                    "flag":         self._flag(cc),
                    "country_code": cc,
                    "lat":          float(data.get("lat", 0)),
                    "lon":          float(data.get("lon", 0)),
                }
        except Exception:
            return d

    @staticmethod
    def _flag(code: str) -> str:
        if len(code) != 2:
            return "🌐"
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())


# ─────────────────────────────────────────────────────────────────────────────
#  DNS LEAK CHECKER
# ─────────────────────────────────────────────────────────────────────────────

class DnsLeakChecker:
    def check(self, expected_vpn_ip: str = "", timeout: float = 6.0) -> dict:
        result = {"leak_detected": False, "resolvers": [], "details": ""}
        try:
            r = subprocess.run(["nslookup", "whoami.akamai.net"],
                               capture_output=True, text=True, timeout=timeout)
            ips = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", r.stdout)
            result["resolvers"] = ips
            if expected_vpn_ip and ips:
                pfx = ".".join(expected_vpn_ip.split(".")[:2])
                result["leak_detected"] = any(not i.startswith(pfx) for i in ips)
            result["details"] = f"DNS резолвери: {', '.join(ips) or '—'}"
        except Exception as e:
            result["details"] = f"DNS недоступний: {e}"
        return result


# ─────────────────────────────────────────────────────────────────────────────
#  PROFILE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ProfileEngine:
    @staticmethod
    def parse(file_path: str) -> Optional[VpnProfile]:
        if not os.path.exists(file_path):
            return None
        ext  = os.path.splitext(file_path)[1].lower()
        name = os.path.splitext(os.path.basename(file_path))[0]
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            raw = f.read()
        if ext == ".conf":  return ProfileEngine._wg(name, file_path, raw)
        if ext == ".ovpn":  return ProfileEngine._ovpn(name, file_path, raw)
        return None

    @staticmethod
    def _wg(name, path, raw) -> Optional[VpnProfile]:
        """Парсимо WireGuard .conf. ЛИШЕ якщо файл має ВСІ ключові маркери:
        [Interface], PrivateKey, [Peer], Endpoint. Інакше це не WireGuard."""
        # Валідація — щоб не парсити випадкові .conf файли як VPN-профілі
        if "[Interface]" not in raw:
            print(f"[WireGuard] Відхилено '{name}': немає секції [Interface]")
            return None
        if "[Peer]" not in raw:
            print(f"[WireGuard] Відхилено '{name}': немає секції [Peer]")
            return None
        if not re.search(r"PrivateKey\s*=\s*[A-Za-z0-9+/=]{40,}", raw):
            print(f"[WireGuard] Відхилено '{name}': немає валідного PrivateKey")
            return None
        if not re.search(r"PublicKey\s*=\s*[A-Za-z0-9+/=]{40,}", raw):
            print(f"[WireGuard] Відхилено '{name}': немає валідного PublicKey")
            return None
        m_endpoint = re.search(r"Endpoint\s*=\s*([^\s:]+)(?::(\d+))?", raw, re.I)
        if not m_endpoint:
            print(f"[WireGuard] Відхилено '{name}': немає Endpoint")
            return None

        p = VpnProfile(name=name, protocol=VpnProtocol.WIREGUARD,
                       file_path=path, raw_config=raw)
        p.server_host = m_endpoint.group(1)
        p.server_ip   = m_endpoint.group(1)
        p.port        = int(m_endpoint.group(2)) if m_endpoint.group(2) else 51820
        dm = re.search(r"DNS\s*=\s*(.+)", raw, re.I)
        if dm:
            p.dns_servers = [d.strip() for d in dm.group(1).split(",")]
        p.interface = re.sub(r"[^a-zA-Z0-9_]", "_", name)[:15]
        return p

    @staticmethod
    def _ovpn(name, path, raw) -> Optional[VpnProfile]:
        """OpenVPN .ovpn — потрібен 'remote' + 'client' або '<ca>' секція."""
        # Валідація — справжній .ovpn має client/dev директиви + remote
        if not re.search(r"^\s*remote\s+\S+", raw, re.I | re.M):
            print(f"[OpenVPN] Відхилено '{name}': немає директиви 'remote'")
            return None
        # Має бути хоча б один з: client, dev, proto, ca
        has_marker = any(re.search(rf"^\s*{kw}\b", raw, re.I | re.M)
                         for kw in ("client", "dev", "proto", "<ca>", "auth-user-pass"))
        if not has_marker:
            print(f"[OpenVPN] Відхилено '{name}': немає client/dev/proto/ca маркерів")
            return None

        p = VpnProfile(name=name, protocol=VpnProtocol.OPENVPN,
                       file_path=path, raw_config=raw)
        m = re.search(r"^remote\s+([^\s]+)(?:\s+(\d+))?", raw, re.I | re.M)
        if m:
            p.server_host = m.group(1)
            p.server_ip   = m.group(1)
            p.port        = int(m.group(2)) if m.group(2) else 1194
        p.dns_servers = re.findall(r"dhcp-option\s+DNS\s+([^\s]+)", raw, re.I)
        return p


# ─────────────────────────────────────────────────────────────────────────────
#  BANDWIDTH QUOTA TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class BandwidthQuotaTracker:
    def __init__(self):
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        self._dir  = os.path.join(appdata, "NetGuardian")
        self._file = os.path.join(self._dir, "bandwidth.json")
        os.makedirs(self._dir, exist_ok=True)
        self._data = self._load()

    def _load(self) -> dict:
        try:
            if os.path.exists(self._file):
                with open(self._file) as f:
                    return json.load(f)
        except Exception:
            pass
        return {"month": time.strftime("%Y-%m"), "rx": 0, "tx": 0,
                "quota_gb": 0, "sessions": 0}

    def _save(self):
        try:
            with open(self._file, "w") as f:
                json.dump(self._data, f, indent=2)
        except Exception:
            pass

    def add_session(self, rx: int, tx: int):
        if self._data.get("month") != time.strftime("%Y-%m"):
            self._data = {"month": time.strftime("%Y-%m"), "rx": 0, "tx": 0,
                          "quota_gb": self._data.get("quota_gb", 0), "sessions": 0}
        self._data["rx"] += rx
        self._data["tx"] += tx
        self._data["sessions"] = self._data.get("sessions", 0) + 1
        self._save()

    def set_quota_gb(self, gb: float):
        self._data["quota_gb"] = gb
        self._save()

    def get_summary(self) -> dict:
        rx_gb  = self._data["rx"] / 1024**3
        tx_gb  = self._data["tx"] / 1024**3
        total  = rx_gb + tx_gb
        quota  = self._data.get("quota_gb", 0)
        pct    = (total / quota * 100) if quota > 0 else 0
        return {
            "month": self._data["month"], "rx_gb": round(rx_gb, 3),
            "tx_gb": round(tx_gb, 3), "total_gb": round(total, 3),
            "quota_gb": quota, "used_pct": round(pct, 1),
            "warning": quota > 0 and pct > 80,
            "sessions": self._data.get("sessions", 0),
        }


# ─────────────────────────────────────────────────────────────────────────────
#  CONNECTION HISTORY
# ─────────────────────────────────────────────────────────────────────────────

class ConnectionHistory:
    MAX = 100

    def __init__(self):
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        self._file = os.path.join(appdata, "NetGuardian", "history.json")
        self._records: list = self._load()

    def _load(self) -> list:
        try:
            if os.path.exists(self._file):
                with open(self._file) as f:
                    return [ConnectionRecord(**r) for r in json.load(f)]
        except Exception:
            pass
        return []

    def _save(self):
        try:
            os.makedirs(os.path.dirname(self._file), exist_ok=True)
            with open(self._file, "w") as f:
                json.dump([r.__dict__ for r in self._records[-self.MAX:]], f, indent=2)
        except Exception:
            pass

    def add(self, rec: ConnectionRecord):
        self._records.append(rec)
        self._save()

    def get_all(self) -> list:
        return list(reversed(self._records))

    def clear(self):
        self._records.clear()
        self._save()


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class VpnManagerEngine:
    VPN_EXE_CANDIDATES = {
        VpnProtocol.WIREGUARD: [r"C:\Program Files\WireGuard\wireguard.exe"],
        VpnProtocol.OPENVPN:   [
            r"C:\Program Files\OpenVPN\bin\openvpn.exe",
            r"C:\Program Files\OpenVPN Connect\OpenVPNConnect.exe",
        ],
    }

    def __init__(self, log_callback=None):
        self.log       = log_callback or (lambda m: None)
        self.profiles: dict = {}
        self.stats     = TunnelStats()

        self.kill_switch       = KillSwitchEngine()
        self.split_tunnel      = SplitTunnelEngine()
        self.shadow_mode       = ShadowModeEngine()
        self.traffic_monitor   = TunnelTrafficMonitor()
        self.geo_resolver      = IpGeoResolver()
        self.dns_checker       = DnsLeakChecker()
        self.profile_engine    = ProfileEngine()
        self.auto_detector     = VpnAutoDetector()
        self.shortcut_launcher = ShortcutLauncher()
        self.quota_tracker     = BandwidthQuotaTracker()
        self.history           = ConnectionHistory()

        self._vpn_proc         = None
        self._monitor_thread   = None
        self._auto_vpn_thread  = None
        self._kill_switch_on   = False
        self._stop_monitor     = threading.Event()
        self._stop_auto_vpn    = threading.Event()
        self._auto_reconnect   = True
        self._max_reconnect    = 3
        self._prev_time        = 0.0
        self._prev_rx          = 0
        self._prev_tx          = 0
        self._current_record: Optional[ConnectionRecord] = None

    # ── SCAN ─────────────────────────────────────────────────────────────────

    def full_system_scan(self) -> list:
        self.log("🔍 Скан системи на наявність VPN-клієнтів...")
        results = self.auto_detector.detect_all(log_cb=self.log)
        found   = [r for r in results if r["detected"]]
        missing = [r for r in results if not r["detected"]]
        self.log(f"✅ Знайдено: {len(found)}  |  ❌ Не встановлено: {len(missing)}")
        for r in found:
            self.log(f"  {r['icon']} {r['name']} → {r['path']}")
        for r in missing:
            extra = "  (є посилання для завантаження)" if r.get("download_url") else ""
            self.log(f"  {r['icon']} {r['name']} — не знайдено{extra}")
        return results

    def launch_detected_vpn(self, scan_result: dict) -> tuple:
        if scan_result.get("detected") and scan_result.get("path"):
            return self.shortcut_launcher.launch(scan_result["path"], self.log)
        url = scan_result.get("download_url", "")
        name = scan_result.get("name", "VPN")
        if url:
            return False, f"DOWNLOAD_REQUIRED:{url}:{name}"
        return False, "❌ VPN не знайдено, посилання відсутнє."

    # ── PROFILES ─────────────────────────────────────────────────────────────

    def import_profile(self, file_path: str) -> tuple:
        profile = self.profile_engine.parse(file_path)
        if not profile:
            return False, f"Не вдалося розпарсити: {file_path}", None
        if profile.server_host and not re.match(r"^\d+\.\d+\.\d+\.\d+$", profile.server_host):
            try:
                profile.server_ip = socket.gethostbyname(profile.server_host)
            except Exception:
                profile.server_ip = profile.server_host
        self.profiles[profile.name] = profile
        self.log(f"📁 [{profile.protocol.value}] {profile.name} → {profile.server_ip}:{profile.port}")
        return True, f"Профіль '{profile.name}' завантажено.", profile

    def get_profiles(self) -> list:
        return list(self.profiles.values())

    def delete_profile(self, name: str) -> bool:
        return self.profiles.pop(name, None) is not None

    # ── АВТОМАТИЧНИЙ ВИБІР НАЙКРАЩОГО СЕРВЕРА ───────────────────────────────

    def auto_select_best_server(self, log_cb=None) -> Optional["VpnProfile"]:
        """
        Знаходить найкращий VPN-сервер серед імпортованих профілів.
        Критерії:
          1. Швидкість пінгу (нижчий — краще, вага 60%)
          2. Географічна близькість (преференція EU для UA-юзерів, вага 30%)
          3. Доступність порту (10%)

        Повертає VpnProfile або None.
        """
        log = log_cb or self.log

        if not self.profiles:
            log("❌ Немає імпортованих профілів для авто-вибору")
            return None

        log(f"🔍 Аналізую {len(self.profiles)} серверів...")

        # Європейські країни — преференція для UA-юзера
        EU_COUNTRIES = {"DE", "PL", "CZ", "AT", "NL", "FR", "GB", "IE",
                        "SE", "NO", "FI", "DK", "CH", "BE", "LU", "ES", "IT",
                        "RO", "BG", "HU", "SK", "GR", "PT"}

        scored = []
        for profile in self.profiles.values():
            # Пробуємо отримати IP сервера
            server_ip = profile.server_ip if profile.server_ip != "—" else profile.server_host
            if not server_ip or server_ip == "—":
                continue

            # 1. Ping
            ping_ms = self._measure_ping(server_ip)
            ping_score = 0.0
            if ping_ms is not None:
                # Інверсія: 0ms = 100, 200ms = 0
                ping_score = max(0, 100 - ping_ms / 2.0)

            # 2. Geo-bonus
            geo_score = 50.0   # default
            country_code = self._extract_country_code(profile)
            if country_code in EU_COUNTRIES:
                geo_score = 90.0
            if country_code in ("PL", "DE", "CZ", "SK", "RO", "HU"):
                # Сусіди UA — найкраща пріоритетність
                geo_score = 100.0

            # 3. Port reachability (тільки якщо ping пройшов)
            port_score = 100.0 if ping_ms is not None else 0.0

            # Вагова формула
            total = ping_score * 0.6 + geo_score * 0.3 + port_score * 0.1

            scored.append({
                "profile": profile,
                "ping_ms": ping_ms if ping_ms is not None else 999,
                "country": country_code,
                "score": total,
            })

            ping_str = f"{ping_ms:.0f}ms" if ping_ms is not None else "timeout"
            log(f"  {country_code} · {profile.name[:30]:<30} → {ping_str:>8}  score={total:.0f}")

        if not scored:
            log("❌ Жоден сервер не доступний")
            return None

        # Сортуємо за score (більше = краще)
        scored.sort(key=lambda x: -x["score"])
        best = scored[0]
        log(f"\n🏆 НАЙКРАЩИЙ: {best['profile'].name}")
        log(f"   📍 Країна: {best['country']}")
        log(f"   📡 Ping: {best['ping_ms']:.0f}ms")
        log(f"   ⭐ Score: {best['score']:.1f}/100")
        return best["profile"]

    def _measure_ping(self, host: str, timeout: float = 1.5) -> Optional[float]:
        """Швидкий ICMP ping. Повертає медіану з 3 пакетів або None."""
        import platform as _p
        try:
            if _p.system() == "Windows":
                r = subprocess.run(
                    ["ping", "-n", "3", "-w", str(int(timeout * 1000)), host],
                    capture_output=True, text=True,
                    encoding="cp866", errors="replace", timeout=8,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                times = re.findall(
                    r"(?:time|время|час)[=<]\s*(\d+)\s*(?:ms|мс)",
                    r.stdout or "", re.IGNORECASE)
            else:
                r = subprocess.run(
                    ["ping", "-c", "3", "-W", str(int(timeout)), host],
                    capture_output=True, text=True, timeout=8)
                times = re.findall(r"time=([\d.]+)\s*ms", r.stdout or "")
            samples = [float(t) for t in times if float(t) > 0]
            if not samples: return None
            samples.sort()
            return samples[len(samples) // 2]
        except Exception:
            return None

    def _extract_country_code(self, profile: "VpnProfile") -> str:
        """Витягує country-code з імені або endpoint'а профілю."""
        # 1. З назви профілю (типу "us-nyc-001" → "US")
        name_lower = profile.name.lower()
        # Перевіряємо очевидні префікси
        for cc, countries in {
            "us": ["us", "america", "usa", "united states"],
            "gb": ["uk", "britain", "britania", "england", "london"],
            "de": ["de", "germany", "deutschland", "frankfurt", "berlin"],
            "nl": ["nl", "netherlands", "amsterdam", "holland"],
            "fr": ["fr", "france", "paris"],
            "pl": ["pl", "poland", "warsaw", "warszaw"],
            "cz": ["cz", "czech", "prague", "praha"],
            "se": ["se", "sweden", "stockholm"],
            "no": ["no", "norway", "oslo"],
            "fi": ["fi", "finland", "helsinki"],
            "ch": ["ch", "switzerland", "zurich", "swiss"],
            "at": ["at", "austria", "vienna"],
            "ro": ["ro", "romania", "bucharest"],
            "ua": ["ua", "ukraine", "kyiv", "kiev"],
            "ru": ["ru", "russia", "moscow"],
            "ca": ["ca", "canada", "toronto"],
            "jp": ["jp", "japan", "tokyo"],
            "sg": ["sg", "singapore"],
            "au": ["au", "australia", "sydney"],
            "br": ["br", "brazil", "sao"],
            "in": ["in", "india", "mumbai", "delhi"],
            "hk": ["hk", "hongkong", "hong kong"],
            "kr": ["kr", "korea", "seoul"],
            "es": ["es", "spain", "madrid"],
            "it": ["it", "italy", "rome", "milan"],
        }.items():
            for c in countries:
                if c in name_lower:
                    return cc.upper()

        # 2. З raw_config (Endpoint) — IP-geo lookup
        try:
            if profile.server_ip and profile.server_ip != "—":
                # Спрощено: dns reverse (без зовнішніх API щоб не уповільнювати)
                hostname = socket.gethostbyaddr(profile.server_ip)[0].lower()
                for cc, countries in {
                    "us": [".us."], "gb": [".uk.", ".gb."],
                    "de": [".de."], "nl": [".nl."], "fr": [".fr."],
                    "pl": [".pl."], "se": [".se."],
                }.items():
                    for c in countries:
                        if c in hostname:
                            return cc.upper()
        except Exception:
            pass

        return "??"

    def auto_connect_best(self, enable_kill_switch: bool = True,
                          log_cb=None) -> tuple:
        """Знаходить найкращий сервер і одразу під'єднується до нього.
        Зручно для одного виклику з GUI/бота."""
        best = self.auto_select_best_server(log_cb=log_cb)
        if not best:
            return False, "Жоден сервер не доступний"
        if log_cb:
            log_cb(f"\n⚡ Підключаюсь до {best.name}...")
        return self.connect(best.name, enable_kill_switch=enable_kill_switch)

    # ── АВТО-ПОШУК VPN-ПРОФІЛІВ У СИСТЕМІ ───────────────────────────────────

    def auto_discover_profiles(self, log_cb=None) -> int:
        """
        Сканує систему на наявність .conf (WireGuard) та .ovpn (OpenVPN)
        файлів у стандартних місцях. Імпортує знайдені профілі.

        Повертає кількість нових профілів.
        """
        log = log_cb or self.log
        log("🔍 Сканую систему на VPN-профілі...")

        # Список папок для пошуку (Windows-specific + cross-platform)
        search_paths = []
        try:
            home = Path.home()
            search_paths.extend([
                home / "Documents",
                home / "Downloads",
                home / "Desktop",
                home / ".config",
                home / "AppData" / "Local",
                home / "AppData" / "Roaming",
            ])

            # Стандартні папки VPN-клієнтів
            if platform.system() == "Windows":
                appdata = os.environ.get("LOCALAPPDATA", "")
                if appdata:
                    search_paths.extend([
                        Path(appdata) / "WireGuard" / "Configurations",
                        Path(appdata) / "OpenVPN",
                        Path(appdata) / "OpenVPN Connect" / "profiles",
                    ])
                programfiles = os.environ.get("ProgramFiles", "")
                if programfiles:
                    search_paths.extend([
                        Path(programfiles) / "WireGuard" / "Data" / "Configurations",
                        Path(programfiles) / "OpenVPN" / "config",
                    ])
            else:
                # Linux/Mac
                search_paths.extend([
                    Path("/etc/wireguard"),
                    Path("/etc/openvpn"),
                    home / ".wireguard",
                ])
        except Exception as e:
            log(f"⚠️ Помилка визначення шляхів: {e}")

        # Видаляємо дублікати і перевіряємо існування
        unique_paths = []
        seen = set()
        for p in search_paths:
            try:
                resolved = p.resolve()
                if resolved in seen: continue
                seen.add(resolved)
                if resolved.exists() and resolved.is_dir():
                    unique_paths.append(resolved)
            except Exception: pass

        log(f"  📁 Перевіряю {len(unique_paths)} папок...")

        # Сканування — тільки 1 рівень глибини щоб не зависати
        found_files = []
        for path in unique_paths:
            try:
                for ext in (".conf", ".ovpn"):
                    # rglob ОБМЕЖЕНИЙ — не йдемо у `node_modules`, `.git`, etc.
                    for f in path.rglob(f"*{ext}"):
                        # Скіпаємо системні папки
                        if any(skip in str(f) for skip in
                               (".git", "node_modules", "__pycache__", ".cache")):
                            continue
                        found_files.append(f)
                        if len(found_files) >= 50:
                            break
                    if len(found_files) >= 50: break
                if len(found_files) >= 50: break
            except (PermissionError, OSError):
                continue

        log(f"  📄 Знайдено файлів: {len(found_files)}")
        if not found_files:
            log("❌ VPN-профілі не знайдено у стандартних папках.")
            log("   _Підказка: помістіть .conf/.ovpn у Documents/_")
            return 0

        # Імпортуємо
        imported_count = 0
        existing_names = set(self.profiles.keys())
        for fpath in found_files:
            try:
                ok, msg, profile = self.import_profile(str(fpath))
                if ok and profile and profile.name not in existing_names:
                    imported_count += 1
                    existing_names.add(profile.name)
                    log(f"  ✅ {profile.name} ({profile.protocol.value}) → "
                        f"{profile.server_host or profile.server_ip}")
            except Exception as e:
                log(f"  ⚠️ {fpath.name}: {e}")

        log(f"\n✅ Імпортовано нових профілів: {imported_count}")
        return imported_count

    def magic_connect(self, log_cb=None) -> tuple:
        """
        ПОВНА АВТО-МАГІЯ:
          1. Сканує систему на наявність VPN-профілів
          2. Імпортує знайдені
          3. Знаходить найкращий за пінгом + локацією
          4. Підключається з kill-switch

        Найзручніший виклик коли просто треба "ввімкни мені будь-який VPN".
        """
        log = log_cb or self.log
        log("🪄 *AUTO-MAGIC: повний цикл*\n")

        # 1. Auto-discover
        if not self.profiles:
            log("📁 Жодного профілю не імпортовано — запускаю авто-пошук...")
            count = self.auto_discover_profiles(log_cb=log)
            if count == 0:
                return (False,
                    "❌ VPN-профілі не знайдено у системі.\n"
                    "Додай .conf/.ovpn у `Documents/` та повтори.")

        # 2. Auto-select + connect
        log("\n⚡ Шукаю найкращий сервер та підключаюсь...")
        return self.auto_connect_best(
            enable_kill_switch=True, log_cb=log)

    # ── CONNECTION ────────────────────────────────────────────────────────────

    def connect(self, profile_name: str, enable_kill_switch: bool = True) -> tuple:
        if not is_admin():
            return False, "❌ Потрібні права адміністратора."
        profile = self.profiles.get(profile_name)
        if not profile:
            return False, f"Профіль '{profile_name}' не знайдено."

        self.stats.state          = ConnectionState.CONNECTING
        self.stats.active_profile = profile_name
        self._kill_switch_on      = enable_kill_switch

        self.log("🌐 IP до підключення...")
        self.stats.public_ip_before = self.geo_resolver.get_public_ip()
        self.log(f"   До: {self.stats.public_ip_before}")

        ok, msg = self._launch_tunnel(profile)
        if not ok:
            self.stats.state = ConnectionState.ERROR
            return False, msg

        time.sleep(4)
        self.stats.public_ip_after = self.geo_resolver.get_public_ip()
        self.stats.ip_changed = (
            self.stats.public_ip_after not in ("—", self.stats.public_ip_before)
        )
        geo = self.geo_resolver.get_geo(self.stats.public_ip_after)
        if self.stats.ip_changed:
            self.log(f"✅ Double Hop: {self.stats.public_ip_before} → {self.stats.public_ip_after}")
            self.log(f"   {geo['flag']} {geo['city']}, {geo['country']}")
        else:
            self.log("⚠️  IP не змінився — можлива помилка конфігурації.")

        dns = self.dns_checker.check(self.stats.public_ip_after)
        self.stats.dns_leak_safe = not dns["leak_detected"]
        self.log(("⚠️  DNS LEAK! " if dns["leak_detected"] else "🔐 DNS: безпечно. ") + dns["details"])

        self.stats.state           = ConnectionState.CONNECTED
        self.stats.connected_since = time.time()
        self.stats.reconnect_count = 0
        self._current_record = ConnectionRecord(
            profile_name=profile_name,
            connected_at=time.time(),
            ip_before=self.stats.public_ip_before,
            ip_after=self.stats.public_ip_after,
        )

        self._stop_monitor.clear()
        self._monitor_thread = threading.Thread(
            target=self._connection_monitor, daemon=True)
        self._monitor_thread.start()

        return True, f"✅ Підключено: {profile_name}"

    def disconnect(self, reason: str = "manual") -> tuple:
        self._stop_monitor.set()
        profile = self.profiles.get(self.stats.active_profile or "")

        if self._vpn_proc and self._vpn_proc.poll() is None:
            self._vpn_proc.terminate()
            try:
                self._vpn_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._vpn_proc.kill()

        if profile and profile.protocol == VpnProtocol.WIREGUARD:
            self._wg_down(profile)

        if self._kill_switch_on and self.kill_switch.is_active():
            ok, msg = self.kill_switch.deactivate()
            self.log(msg)

        self.quota_tracker.add_session(self.stats.rx_bytes, self.stats.tx_bytes)
        if self._current_record:
            self._current_record.disconnected_at = time.time()
            self._current_record.duration_sec = (
                self._current_record.disconnected_at - self._current_record.connected_at)
            self._current_record.rx_bytes = self.stats.rx_bytes
            self._current_record.tx_bytes = self.stats.tx_bytes
            self._current_record.disconnect_reason = reason
            self.history.add(self._current_record)

        self.stats.state          = ConnectionState.DISCONNECTED
        self.stats.active_profile = None
        self.log("⏹ VPN відключено.")
        return True, "Відключено."

    def _launch_tunnel(self, p: VpnProfile) -> tuple:
        if p.protocol == VpnProtocol.WIREGUARD:  return self._connect_wg(p)
        if p.protocol == VpnProtocol.OPENVPN:    return self._connect_ovpn(p)
        return False, "Невідомий протокол."

    def _connect_wg(self, p: VpnProfile) -> tuple:
        exe = self._find_exe(VpnProtocol.WIREGUARD)
        if not exe: return False, "WireGuard не знайдено."
        try:
            self._vpn_proc = subprocess.Popen(
                [exe, "/installtunnelservice", p.file_path],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            self.log(f"🔵 WireGuard тунель: {p.interface}")
            return True, "WireGuard запущено."
        except Exception as e:
            return False, f"WireGuard: {e}"

    def _wg_down(self, p: VpnProfile):
        exe = self._find_exe(VpnProtocol.WIREGUARD)
        if exe:
            try:
                subprocess.run([exe, "/uninstalltunnelservice", p.interface],
                               capture_output=True, timeout=10)
            except Exception:
                pass

    def _connect_ovpn(self, p: VpnProfile) -> tuple:
        exe = self._find_exe(VpnProtocol.OPENVPN)
        if not exe: return False, "OpenVPN не знайдено."
        try:
            self._vpn_proc = subprocess.Popen(
                [exe, "--config", p.file_path, "--verb", "3"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            self.log(f"🟠 OpenVPN PID: {self._vpn_proc.pid}")
            return True, "OpenVPN запущено."
        except Exception as e:
            return False, f"OpenVPN: {e}"

    def _find_exe(self, proto: VpnProtocol) -> Optional[str]:
        for p in self.VPN_EXE_CANDIDATES.get(proto, []):
            if os.path.exists(p): return p
        name = "wireguard" if proto == VpnProtocol.WIREGUARD else "openvpn"
        try:
            r = subprocess.run(["where", name], capture_output=True,
                               text=True, timeout=3)
            if r.returncode == 0:
                return r.stdout.strip().splitlines()[0]
        except Exception:
            pass
        return None

    def _connection_monitor(self):
        self.log("👁 Монітор активний.")
        self._prev_time = time.time()
        while not self._stop_monitor.is_set():
            if self._vpn_proc and self._vpn_proc.poll() is not None:
                self.log("⚠️  VPN процес завершився!")
                if self._auto_reconnect and self.stats.reconnect_count < self._max_reconnect:
                    self.stats.state = ConnectionState.RECONNECTING
                    self.stats.reconnect_count += 1
                    self.log(f"🔄 Авто-перепідключення #{self.stats.reconnect_count}...")
                    time.sleep(3 * self.stats.reconnect_count)
                    profile = self.profiles.get(self.stats.active_profile or "")
                    if profile:
                        ok, _ = self._launch_tunnel(profile)
                        if ok:
                            self.stats.state = ConnectionState.CONNECTED
                            self.log("✅ Перепідключено.")
                            continue
                if self._kill_switch_on:
                    ok, msg = self.kill_switch.activate()
                    self.log(msg)
                    self.stats.state = ConnectionState.KILL_SWITCH
                else:
                    self.stats.state = ConnectionState.ERROR
                break
            # Traffic
            profile = self.profiles.get(self.stats.active_profile or "")
            if profile and profile.protocol == VpnProtocol.WIREGUARD:
                s = self.traffic_monitor.get_wireguard_stats(profile.interface)
            else:
                s = self.traffic_monitor.get_interface_stats("tun")
            now = time.time()
            dt  = max(now - self._prev_time, 0.001)
            self.stats.rx_speed_kbps = max(0, (s["rx_bytes"] - self._prev_rx) / dt / 1024)
            self.stats.tx_speed_kbps = max(0, (s["tx_bytes"] - self._prev_tx) / dt / 1024)
            self.stats.rx_bytes = s["rx_bytes"]
            self.stats.tx_bytes = s["tx_bytes"]
            self._prev_rx, self._prev_tx, self._prev_time = s["rx_bytes"], s["tx_bytes"], now
            self._stop_monitor.wait(5)
        self.log("👁 Монітор зупинений.")

    # ── AUTO-VPN ──────────────────────────────────────────────────────────────

    def start_auto_vpn_monitor(self, profile_name: str, interval: int = 20,
                                mode: str = "open_only") -> bool:
        """Запускає авто-VPN моніторинг.

        mode:
          - "open_only"   → підключається тільки на ВІДКРИТИХ Wi-Fi мережах
                            (стандартна поведінка для безпеки в публічних мережах)
          - "always"      → завжди тримає VPN активним; перепідключається якщо впав
          - "on_startup"  → одноразово при запуску (не моніторить далі)
        """
        if profile_name not in self.profiles: return False
        self._stop_auto_vpn.clear()
        self._auto_vpn_thread = threading.Thread(
            target=self._auto_vpn_loop,
            args=(profile_name, interval, mode), daemon=True)
        self._auto_vpn_thread.start()

        mode_desc = {
            "open_only":  "тільки відкриті Wi-Fi",
            "always":     "ЗАВЖДИ підключений",
            "on_startup": "одноразово при старті",
        }.get(mode, mode)
        self.log(f"🤖 Auto-VPN ON → {profile_name} ({mode_desc}, кожні {interval}с)")
        return True

    def stop_auto_vpn_monitor(self):
        self._stop_auto_vpn.set()
        self.log("⏹ Auto-VPN вимкнено.")

    def _auto_vpn_loop(self, profile_name: str, interval: int,
                       mode: str = "open_only"):
        """Моніторинг циклу — поведінка залежить від режиму mode.

        FIX: підтримка 3 режимів:
        - open_only: тільки на відкритих мережах
        - always: завжди тримає VPN активним
        - on_startup: одноразове підключення при старті
        """
        last_picked = profile_name
        scan_counter = 0

        # Режим "on_startup" — одноразово, потім вихід
        if mode == "on_startup":
            try:
                self.log(f"🚀 Auto-VPN (одноразово): {profile_name}")
                threading.Thread(target=self.connect,
                                 args=(profile_name, True), daemon=True).start()
            except Exception as e:
                self.log(f"⚠️ Auto-VPN startup error: {e}")
            return

        # Режими "open_only" та "always" — постійний моніторинг
        while not self._stop_auto_vpn.is_set():
            try:
                # Якщо ми вже підключені — нічого не робимо
                if self.stats.state == ConnectionState.CONNECTED:
                    self._stop_auto_vpn.wait(interval)
                    continue

                should_connect = False
                reason = ""

                if mode == "always":
                    # Підключаємось завжди коли disconnected
                    should_connect = True
                    reason = "режим ALWAYS"
                else:
                    # mode == "open_only" — тільки відкриті мережі
                    net = self.check_network_security()
                    if net["is_open"]:
                        should_connect = True
                        reason = f"відкрита мережа '{net['ssid']}'"

                if should_connect:
                    self.log(f"🚨 Auto-VPN trigger: {reason}")
                    # Кожні 5 сканів переоцінюємо найкращий сервер
                    if scan_counter % 5 == 0:
                        self.log("🔍 Auto-VPN: переоцінюю найкращий сервер...")
                        try:
                            best = self.auto_select_best_server(log_cb=self.log)
                            if best:
                                last_picked = best.name
                        except Exception as e:
                            self.log(f"⚠️ auto_select помилка: {e}")
                    threading.Thread(target=self.connect,
                                     args=(last_picked, True), daemon=True).start()
                scan_counter += 1
            except Exception as e:
                self.log(f"⚠️ auto_vpn_loop error: {e}")
            self._stop_auto_vpn.wait(interval)

    # ── NETWORK ───────────────────────────────────────────────────────────────

    def check_network_security(self) -> dict:
        result = {"type": "Unknown", "ssid": "—", "auth": "—", "is_open": False}
        if platform.system() != "Windows":
            result["type"] = "Ethernet / Linux"
            return result
        try:
            r = subprocess.run(["netsh", "wlan", "show", "interfaces"],
                               capture_output=True, text=True,
                               encoding="cp866", errors="ignore", timeout=5)
            for line in r.stdout.splitlines():
                line = line.strip()
                if "SSID" in line and "BSSID" not in line:
                    result["ssid"] = line.split(":", 1)[-1].strip()
                elif "Authentication" in line or "Аутентиф" in line:
                    result["auth"] = line.split(":", 1)[-1].strip()
                    if "Open" in result["auth"] or "Открытая" in result["auth"]:
                        result["is_open"] = True
            if not result["ssid"] or result["ssid"] == "—":
                result["type"] = "Ethernet"
            elif result["is_open"]:
                result["type"] = "WiFi · ВІДКРИТА ⚠️"
            else:
                result["type"] = f"WiFi · Захищена ({result['auth']})"
        except Exception as e:
            result["type"] = f"Помилка: {e}"
        return result

    def run_shadow_probe(self, profile_name: str) -> dict:
        p = self.profiles.get(profile_name)
        if not p:
            self.log(f"Профіль '{profile_name}' не знайдено.")
            return {}
        self.log(f"👥 Shadow Mode: {p.server_host}...")
        return self.shadow_mode.probe_ports(p.server_host, log_cb=self.log)

    def quick_connect(self) -> tuple:
        if not self.profiles: return False, "Немає профілів."
        self.log("⚡ Quick Connect: пінг серверів...")
        best, best_ms = None, float("inf")
        for name, p in self.profiles.items():
            host = p.server_host or p.server_ip
            port = p.port or 443
            try:
                t0 = time.perf_counter()
                with socket.create_connection((host, port), timeout=3):
                    ms = (time.perf_counter() - t0) * 1000
                self.log(f"   {name}: {ms:.1f} мс")
                if ms < best_ms:
                    best_ms, best = ms, name
            except Exception:
                self.log(f"   {name}: недоступний")
        if not best:
            best = next(iter(self.profiles))
        self.log(f"⚡ Обрано: {best} ({best_ms:.1f} мс)")
        return self.connect(best)

    def get_stats_snapshot(self) -> TunnelStats:
        return self.stats

    def get_uptime_str(self) -> str:
        if self.stats.state not in (ConnectionState.CONNECTED, ConnectionState.RECONNECTING):
            return "—"
        e = int(time.time() - (self.stats.connected_since or time.time()))
        h, r = divmod(e, 3600)
        m, s = divmod(r, 60)
        return f"{h:02d}:{m:02d}:{s:02d}"

    def set_auto_reconnect(self, enabled: bool, max_attempts: int = 3):
        self._auto_reconnect = enabled
        self._max_reconnect  = max_attempts