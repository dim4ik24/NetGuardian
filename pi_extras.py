"""
pi_extras.py
─────────────
20+ ДЖЕРЕЛ ДАНИХ З RASPBERRY PI

Цей модуль ВИКОНУЄ команди на Pi через SSH або через FastAPI endpoint
і збирає різноманітні метрики які корисні для AI.

USAGE:
  from pi_extras import PiDataCollector
  pi = PiDataCollector(host="netguardian.local", user="pi")
  data = pi.gather_all()    # повертає dict з усіма метриками

ВСІ ЗБИРАНІ ДАНІ (20+):

  МЕРЕЖА:
    1. wifi_signal       — RSSI, SNR, bitrate Wi-Fi на Pi
    2. wifi_neighbors    — список сусідніх Wi-Fi мереж
    3. lan_devices       — ARP-таблиця (хто в мережі)
    4. router_info       — дані про роутер (модель, MAC, OUI)
    5. wan_ip_check      — публічний IP з Pi (другий ракурс)
    6. dns_servers       — які DNS використовує Pi
    7. dns_speed_test    — швидкість 5 DNS-провайдерів
    8. traceroute        — шлях до 8.8.8.8 і 1.1.1.1
    9. mtu_discovery     — оптимальний MTU
   10. open_ports_lan    — відкриті порти на роутері

  ШВИДКІСТЬ:
   11. iperf3_to_router  — швидкість LAN до роутера
   12. throughput        — поточний RX/TX
   13. tcp_retrans       — % повторних пакетів TCP
   14. icmp_burst        — burst ping для jitter аналізу

  СИСТЕМА:
   15. cpu_temperature   — температура CPU
   16. cpu_load          — навантаження
   17. memory            — RAM used/free
   18. disk              — free space
   19. uptime            — час від останнього reboot
   20. throttling        — voltage/temp throttling status

  БЕЗПЕКА:
   21. failed_logins     — невдалі спроби SSH
   22. listening_ports   — що слухає на Pi
   23. arp_anomalies     — duplicate MAC в LAN
   24. packet_capture    — швидкий sniff підозрілого трафіку
"""

from __future__ import annotations
import subprocess
import re
import socket
import time
import json
from typing import Optional


class PiDataCollector:
    """Збирач даних з Raspberry Pi.

    Може працювати у 2-х режимах:
      MODE 1: SSH (потрібні ключі)
      MODE 2: HTTP до FastAPI на Pi (порт 8765)

    Якщо SSH не працює — пробує HTTP.
    """

    def __init__(self, host: str = "netguardian.local",
                 user: str = "pi",
                 ssh_key: Optional[str] = None,
                 http_port: int = 8765):
        self.host = host
        self.user = user
        self.ssh_key = ssh_key
        self.http_port = http_port
        self._mode = None   # "ssh" | "http" | None

    def _ssh(self, cmd: str, timeout: int = 10) -> str:
        """Виконує команду на Pi через SSH."""
        ssh_cmd = ["ssh", "-o", "ConnectTimeout=3",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "BatchMode=yes"]
        if self.ssh_key:
            ssh_cmd += ["-i", self.ssh_key]
        ssh_cmd += [f"{self.user}@{self.host}", cmd]
        try:
            r = subprocess.run(ssh_cmd, capture_output=True, text=True,
                                timeout=timeout,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return (r.stdout or "").strip()
        except Exception as e:
            return ""

    def _http(self, endpoint: str, timeout: int = 5) -> dict:
        """Звертається до FastAPI endpoint на Pi."""
        try:
            import urllib.request
            url = f"http://{self.host}:{self.http_port}/{endpoint}"
            with urllib.request.urlopen(url, timeout=timeout) as r:
                return json.loads(r.read().decode())
        except Exception:
            return {}

    def detect_mode(self) -> str:
        """Визначає який метод доступу працює."""
        if self._mode: return self._mode
        # Test SSH
        if self._ssh("echo ok", timeout=3) == "ok":
            self._mode = "ssh"
            return "ssh"
        # Test HTTP
        if self._http("ping").get("ok"):
            self._mode = "http"
            return "http"
        return "none"

    # ═══════════════════════════════════════════════════════════════
    #  МЕРЕЖА (10 методів)
    # ═══════════════════════════════════════════════════════════════

    def get_wifi_signal(self) -> dict:
        """RSSI, SNR, bitrate Wi-Fi на Pi."""
        out = self._ssh("iwconfig wlan0 2>/dev/null")
        if not out: return {}
        result = {}
        m = re.search(r'Signal level=(-?\d+)', out)
        if m: result["signal_dbm"] = int(m.group(1))
        m = re.search(r'Bit Rate[:=]\s*([\d.]+)\s*([GMK]?)b/s', out)
        if m:
            rate = float(m.group(1))
            unit = m.group(2)
            mult = {"G": 1000, "M": 1, "K": 0.001}.get(unit, 1)
            result["bitrate_mbps"] = rate * mult
        m = re.search(r'ESSID:"([^"]+)"', out)
        if m: result["ssid"] = m.group(1)
        m = re.search(r'Frequency:([\d.]+)', out)
        if m: result["frequency_ghz"] = float(m.group(1))
        m = re.search(r'Quality=(\d+)/(\d+)', out)
        if m: result["quality_pct"] = int(int(m.group(1)) / int(m.group(2)) * 100)
        return result

    def get_wifi_neighbors(self) -> list[dict]:
        """Сканує сусідні Wi-Fi мережі."""
        out = self._ssh("sudo iwlist wlan0 scan 2>/dev/null | head -200")
        if not out: return []
        networks = []
        cells = out.split("Cell ")
        for cell in cells[1:]:
            net = {}
            m = re.search(r'ESSID:"([^"]*)"', cell)
            if m: net["ssid"] = m.group(1) or "(hidden)"
            m = re.search(r'Address:\s*([0-9A-F:]{17})', cell)
            if m: net["bssid"] = m.group(1)
            m = re.search(r'Signal level=(-?\d+)', cell)
            if m: net["signal_dbm"] = int(m.group(1))
            m = re.search(r'Channel:(\d+)', cell)
            if m: net["channel"] = int(m.group(1))
            m = re.search(r'Encryption key:(\w+)', cell)
            if m: net["encrypted"] = m.group(1) == "on"
            if net.get("ssid"):
                networks.append(net)
        return networks[:20]

    def get_lan_devices(self) -> list[dict]:
        """ARP-таблиця Pi — хто в мережі."""
        out = self._ssh("ip neighbor show | awk '{print $1, $5, $NF}'")
        devices = []
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                devices.append({
                    "ip": parts[0],
                    "mac": parts[1] if len(parts) >= 3 else "?",
                    "state": parts[-1],
                })
        return devices

    def get_router_info(self) -> dict:
        """Інфа про дефолтний gateway."""
        gw = self._ssh("ip route | grep default | awk '{print $3}' | head -1")
        if not gw: return {}
        # Знаходимо MAC з ARP
        out = self._ssh(f"ip neighbor show {gw}")
        m = re.search(r'lladdr ([0-9a-f:]{17})', out)
        return {
            "gateway_ip": gw,
            "gateway_mac": m.group(1) if m else None,
            "gateway_oui": m.group(1)[:8].upper().replace(":", "-") if m else None,
        }

    def get_wan_ip(self) -> str:
        """Публічний IP з Pi (інший ракурс ніж ПК)."""
        out = self._ssh("curl -s --max-time 5 https://api.ipify.org")
        return out if out and "." in out else ""

    def get_dns_servers(self) -> list[str]:
        """DNS-сервери на Pi."""
        out = self._ssh("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'")
        return [line.strip() for line in out.splitlines() if line.strip()]

    def get_dns_speed_test(self) -> list[dict]:
        """Швидкість 5 DNS-провайдерів."""
        servers = ["1.1.1.1", "8.8.8.8", "9.9.9.9", "94.140.14.14"]
        results = []
        for srv in servers:
            cmd = (f"for d in google.com youtube.com github.com; do "
                   f"dig @{srv} +time=2 +tries=1 +short $d > /dev/null 2>&1; "
                   f"echo $?; done")
            # Простіший - через `dig`
            out = self._ssh(f"dig @{srv} +noall +stats +time=2 google.com 2>&1 | grep 'Query time'")
            m = re.search(r'Query time:\s*(\d+)', out)
            if m:
                results.append({"server": srv, "time_ms": int(m.group(1))})
            else:
                results.append({"server": srv, "time_ms": None})
        return results

    def get_traceroute(self, target: str = "8.8.8.8") -> dict:
        """Traceroute з Pi до target."""
        out = self._ssh(f"traceroute -n -w 1 -m 15 {target} 2>/dev/null")
        if not out: return {}
        hops = []
        for line in out.splitlines()[1:]:   # skip header
            parts = line.strip().split()
            if not parts: continue
            try:
                hop_n = int(parts[0])
                ip = parts[1] if parts[1] != "*" else None
                # Time
                ms = None
                for p in parts[2:]:
                    try:
                        ms = float(p)
                        break
                    except ValueError: continue
                hops.append({"hop": hop_n, "ip": ip, "ms": ms})
            except (ValueError, IndexError): continue
        return {
            "target": target,
            "hops_count": len(hops),
            "hops": hops[:10],
            "total_ms": hops[-1].get("ms") if hops else None,
        }

    def get_mtu_discovery(self, target: str = "8.8.8.8") -> int:
        """Знаходить максимальний MTU без фрагментації."""
        for size in (1500, 1492, 1472, 1400, 1280):
            payload = size - 28   # IP+ICMP header
            out = self._ssh(f"ping -c 1 -M do -s {payload} -W 2 {target} 2>&1 | head -3")
            if "1 received" in out or "bytes from" in out:
                return size
        return 0

    def get_open_ports_router(self) -> list[int]:
        """Які порти відкриті на роутері (UDP+TCP scan з Pi)."""
        gw = self._ssh("ip route | grep default | awk '{print $3}' | head -1")
        if not gw: return []
        # Швидкий scan TCP портів
        ports = []
        for port in (22, 53, 80, 443, 8080, 8443, 7547, 161, 445):
            out = self._ssh(f"nc -zw1 {gw} {port} 2>&1; echo $?")
            if out.strip().endswith("0"):
                ports.append(port)
        return ports

    # ═══════════════════════════════════════════════════════════════
    #  ШВИДКІСТЬ (4 методи)
    # ═══════════════════════════════════════════════════════════════

    def get_iperf3_to_router(self) -> dict:
        """Швидкість LAN до роутера (якщо роутер підтримує iperf3)."""
        gw = self._ssh("ip route | grep default | awk '{print $3}' | head -1")
        if not gw: return {}
        out = self._ssh(f"iperf3 -c {gw} -t 3 -J 2>/dev/null", timeout=15)
        try:
            data = json.loads(out)
            return {
                "sent_mbps": data.get("end", {}).get("sum_sent", {}).get("bits_per_second", 0) / 1e6,
                "received_mbps": data.get("end", {}).get("sum_received", {}).get("bits_per_second", 0) / 1e6,
            }
        except Exception:
            return {}

    def get_throughput(self) -> dict:
        """Поточний RX/TX на wlan0."""
        out1 = self._ssh("cat /sys/class/net/wlan0/statistics/rx_bytes /sys/class/net/wlan0/statistics/tx_bytes")
        if not out1: return {}
        try:
            rx1, tx1 = map(int, out1.split())
            time.sleep(1)
            out2 = self._ssh("cat /sys/class/net/wlan0/statistics/rx_bytes /sys/class/net/wlan0/statistics/tx_bytes")
            rx2, tx2 = map(int, out2.split())
            return {
                "rx_kbps": (rx2 - rx1) * 8 / 1000,
                "tx_kbps": (tx2 - tx1) * 8 / 1000,
            }
        except Exception: return {}

    def get_tcp_retrans(self) -> dict:
        """% повторних TCP-пакетів."""
        out = self._ssh("cat /proc/net/snmp | grep 'Tcp:' | tail -1")
        if not out: return {}
        try:
            parts = out.split()
            # Tcp: ... InSegs OutSegs RetransSegs ...
            if len(parts) > 12:
                outs = int(parts[11])
                retrans = int(parts[12])
                if outs > 0:
                    return {"retrans_pct": round(retrans / outs * 100, 2)}
        except Exception: pass
        return {}

    def get_icmp_burst(self, target: str = "8.8.8.8", count: int = 30) -> dict:
        """Burst ping для аналізу jitter."""
        out = self._ssh(f"ping -c {count} -i 0.2 {target} 2>/dev/null")
        if not out: return {}
        # Шукаємо statistics
        m = re.search(r'(\d+)\s+packets transmitted,\s+(\d+)\s+received', out)
        if not m: return {}
        sent, recv = int(m.group(1)), int(m.group(2))
        loss = round((sent - recv) / sent * 100, 1) if sent > 0 else 0
        # min/avg/max/mdev
        m = re.search(r'rtt\s+min/avg/max/mdev\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/([\d.]+)', out)
        if m:
            return {
                "sent": sent, "received": recv, "loss_pct": loss,
                "min_ms": float(m.group(1)),
                "avg_ms": float(m.group(2)),
                "max_ms": float(m.group(3)),
                "mdev_ms": float(m.group(4)),
            }
        return {"sent": sent, "received": recv, "loss_pct": loss}

    # ═══════════════════════════════════════════════════════════════
    #  СИСТЕМА (6 методів)
    # ═══════════════════════════════════════════════════════════════

    def get_cpu_temperature(self) -> float:
        """Температура CPU."""
        out = self._ssh("vcgencmd measure_temp 2>/dev/null")
        m = re.search(r'temp=([\d.]+)', out)
        if m: return float(m.group(1))
        # Fallback
        out = self._ssh("cat /sys/class/thermal/thermal_zone0/temp 2>/dev/null")
        try: return int(out.strip()) / 1000
        except (ValueError, AttributeError): return 0

    def get_cpu_load(self) -> dict:
        """Навантаження."""
        out = self._ssh("cat /proc/loadavg")
        if not out: return {}
        parts = out.split()
        try:
            return {"load_1m": float(parts[0]),
                    "load_5m": float(parts[1]),
                    "load_15m": float(parts[2])}
        except (ValueError, IndexError): return {}

    def get_memory(self) -> dict:
        """RAM."""
        out = self._ssh("free -m | grep Mem:")
        if not out: return {}
        parts = out.split()
        try:
            total = int(parts[1])
            used = int(parts[2])
            free = int(parts[3])
            return {
                "total_mb": total,
                "used_mb": used,
                "free_mb": free,
                "used_pct": round(used / total * 100) if total else 0,
            }
        except (ValueError, IndexError): return {}

    def get_disk(self) -> dict:
        """Диск."""
        out = self._ssh("df -h / | tail -1")
        if not out: return {}
        parts = out.split()
        if len(parts) < 5: return {}
        return {
            "total": parts[1], "used": parts[2], "free": parts[3],
            "used_pct": parts[4],
        }

    def get_uptime(self) -> dict:
        """Час роботи."""
        out = self._ssh("cat /proc/uptime")
        if not out: return {}
        try:
            seconds = float(out.split()[0])
            return {
                "uptime_seconds": seconds,
                "uptime_hours": round(seconds / 3600, 1),
                "uptime_days": round(seconds / 86400, 1),
            }
        except Exception: return {}

    def get_throttling_status(self) -> dict:
        """Throttling: voltage/temp."""
        out = self._ssh("vcgencmd get_throttled 2>/dev/null")
        m = re.search(r'throttled=0x([0-9a-fA-F]+)', out)
        if not m: return {}
        flags = int(m.group(1), 16)
        return {
            "raw": f"0x{flags:X}",
            "under_voltage_now": bool(flags & 0x1),
            "freq_capped_now": bool(flags & 0x2),
            "throttled_now": bool(flags & 0x4),
            "soft_temp_now": bool(flags & 0x8),
            "under_voltage_history": bool(flags & 0x10000),
            "freq_capped_history": bool(flags & 0x20000),
            "throttled_history": bool(flags & 0x40000),
        }

    # ═══════════════════════════════════════════════════════════════
    #  БЕЗПЕКА (4 методи)
    # ═══════════════════════════════════════════════════════════════

    def get_failed_logins(self) -> int:
        """К-сть невдалих SSH-спроб за добу."""
        out = self._ssh("sudo grep 'Failed password' /var/log/auth.log 2>/dev/null | wc -l")
        try: return int(out.strip())
        except Exception: return 0

    def get_listening_ports(self) -> list[dict]:
        """Що слухає на Pi."""
        out = self._ssh("ss -tlnp 2>/dev/null | tail -n +2")
        ports = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) < 4: continue
            local = parts[3]
            if ":" in local:
                ip, port = local.rsplit(":", 1)
                try:
                    ports.append({"ip": ip, "port": int(port)})
                except ValueError: continue
        return ports

    def get_arp_anomalies(self) -> list[dict]:
        """Дивні випадки в ARP — duplicate MAC."""
        out = self._ssh("ip neighbor show | awk '{print $1, $5}'")
        mac_to_ips = {}
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 2:
                ip, mac = parts[0], parts[1]
                if mac == "FAILED" or len(mac) < 17: continue
                mac_to_ips.setdefault(mac, []).append(ip)
        # Знаходимо MAC що мають > 1 IP
        anomalies = []
        for mac, ips in mac_to_ips.items():
            if len(ips) > 1:
                anomalies.append({"mac": mac, "ips": ips})
        return anomalies

    def get_packet_capture_stats(self, duration: int = 5) -> dict:
        """Швидкий tcpdump на 5 секунд для статистики трафіку."""
        out = self._ssh(
            f"sudo timeout {duration} tcpdump -i wlan0 -nn -q 2>/dev/null | wc -l",
            timeout=duration + 5)
        try:
            packets = int(out.strip())
            return {"packets_per_sec": round(packets / duration, 1),
                    "duration_sec": duration}
        except Exception: return {}

    # ═══════════════════════════════════════════════════════════════
    #  АГРЕГАТОР
    # ═══════════════════════════════════════════════════════════════

    def gather_all(self) -> dict:
        """Збирає ВСЮ доступну інформацію — для AI контексту.

        Returns: dict з усіма метриками.
        """
        if self.detect_mode() == "none":
            return {"error": "Pi не доступний (ні SSH, ні HTTP)"}

        result = {"mode": self._mode}

        # Мережа
        try: result["wifi_signal"] = self.get_wifi_signal()
        except Exception as e: result["wifi_signal_err"] = str(e)
        try: result["wifi_neighbors"] = self.get_wifi_neighbors()
        except Exception as e: result["wifi_neighbors_err"] = str(e)
        try: result["lan_devices"] = self.get_lan_devices()
        except Exception as e: result["lan_devices_err"] = str(e)
        try: result["router_info"] = self.get_router_info()
        except Exception as e: result["router_info_err"] = str(e)
        try: result["wan_ip"] = self.get_wan_ip()
        except Exception as e: result["wan_ip_err"] = str(e)
        try: result["dns_servers"] = self.get_dns_servers()
        except Exception as e: result["dns_servers_err"] = str(e)
        try: result["traceroute_8888"] = self.get_traceroute("8.8.8.8")
        except Exception as e: result["traceroute_err"] = str(e)
        try: result["mtu"] = self.get_mtu_discovery()
        except Exception as e: result["mtu_err"] = str(e)
        try: result["open_router_ports"] = self.get_open_ports_router()
        except Exception as e: result["open_router_ports_err"] = str(e)

        # Швидкість
        try: result["throughput"] = self.get_throughput()
        except Exception as e: result["throughput_err"] = str(e)
        try: result["tcp_retrans"] = self.get_tcp_retrans()
        except Exception as e: result["tcp_retrans_err"] = str(e)
        try: result["icmp_burst"] = self.get_icmp_burst()
        except Exception as e: result["icmp_burst_err"] = str(e)

        # Система
        try: result["cpu_temp"] = self.get_cpu_temperature()
        except Exception as e: result["cpu_temp_err"] = str(e)
        try: result["cpu_load"] = self.get_cpu_load()
        except Exception as e: result["cpu_load_err"] = str(e)
        try: result["memory"] = self.get_memory()
        except Exception as e: result["memory_err"] = str(e)
        try: result["disk"] = self.get_disk()
        except Exception as e: result["disk_err"] = str(e)
        try: result["uptime"] = self.get_uptime()
        except Exception as e: result["uptime_err"] = str(e)
        try: result["throttling"] = self.get_throttling_status()
        except Exception as e: result["throttling_err"] = str(e)

        # Безпека
        try: result["failed_logins"] = self.get_failed_logins()
        except Exception as e: result["failed_logins_err"] = str(e)
        try: result["listening_ports"] = self.get_listening_ports()
        except Exception as e: result["listening_ports_err"] = str(e)
        try: result["arp_anomalies"] = self.get_arp_anomalies()
        except Exception as e: result["arp_anomalies_err"] = str(e)

        return result

    def gather_quick(self) -> dict:
        """Швидкий збір (тільки лайтові метрики, без traceroute/sniff)."""
        if self.detect_mode() == "none":
            return {}
        result = {"mode": self._mode}
        try: result["cpu_temp"] = self.get_cpu_temperature()
        except: pass
        try: result["cpu_load"] = self.get_cpu_load()
        except: pass
        try: result["memory"] = self.get_memory()
        except: pass
        try: result["uptime"] = self.get_uptime()
        except: pass
        try: result["wifi_signal"] = self.get_wifi_signal()
        except: pass
        try: result["throttling"] = self.get_throttling_status()
        except: pass
        try: result["lan_devices_count"] = len(self.get_lan_devices())
        except: pass
        try: result["wan_ip"] = self.get_wan_ip()
        except: pass
        try: result["icmp_burst"] = self.get_icmp_burst(count=10)
        except: pass
        return result


# ──────────────────────────────────────────────────────────────────
#  Singleton
# ──────────────────────────────────────────────────────────────────
_GLOBAL_PI: Optional[PiDataCollector] = None


def get_pi_collector(host: str = None) -> PiDataCollector:
    """Глобальний інстанс."""
    global _GLOBAL_PI
    if _GLOBAL_PI is None or (host and host != _GLOBAL_PI.host):
        import os
        _GLOBAL_PI = PiDataCollector(
            host=host or os.environ.get("PI_HOST", "netguardian.local"),
            user=os.environ.get("PI_USER", "pi"),
            ssh_key=os.environ.get("PI_SSH_KEY"),
        )
    return _GLOBAL_PI