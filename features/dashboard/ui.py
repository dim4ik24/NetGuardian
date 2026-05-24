# gui/pages/dashboard.py
"""
NetGuardian AI — Dashboard Page  v3.6
Cyberpunk Dark Theme | customtkinter | MVC

Зміни v3.6:
  • Інтегрована система підказок HelpButton / HelpPopup
  • Кнопка ❓ біля кожного заголовку секції
  • При відкритті порту — кнопка ❓ з поясненням і інструкцією
"""

import time
import math
import threading
import subprocess
import platform
import socket
import urllib.request
import http.client
import ssl
import json
import re
from collections import deque
import tkinter as tk

import psutil
import customtkinter as ctk

from app.ui.components.help_system import HelpButton, HelpPopup


# ══════════════════════════════════════════════════════════
#  ГЛОБАЛЬНИЙ КОНТРОЛЬ АНІМАЦІЙ
#  (використовуєтся щоб паузити canvas-анімації під час прокрутки)
# ══════════════════════════════════════════════════════════
_ANIMATIONS_PAUSED = [False]   # Список-обгортка щоб можна було мутувати з inner scope

def _animations_paused() -> bool:
    return _ANIMATIONS_PAUSED[0]

def _pause_animations(paused: bool):
    _ANIMATIONS_PAUSED[0] = paused


# ══════════════════════════════════════════════════════════
#  ПАЛІТРА
# ══════════════════════════════════════════════════════════
COLORS = {
    "bg_primary":    "#0d0d14",
    "bg_secondary":  "#13131e",
    "bg_card":       "#16161f",
    "border":        "#1e2030",
    "border_accent": "#0a1929",
    "accent_cyan":   "#00e5ff",
    "accent_blue":   "#2979ff",
    "accent_purple": "#d500f9",
    "accent_green":  "#00e676",
    "accent_yellow": "#ffea00",
    "accent_red":    "#ff1744",
    "accent_orange": "#ff6d00",
    "text_primary":  "#e8eaf6",
    "text_secondary":"#546e7a",
    "text_dim":      "#2e3548",
}

ICON_PALETTE = [
    "#00e5ff","#2979ff","#d500f9","#00e676",
    "#ffea00","#ff6d00","#ff1744","#00bcd4",
    "#7c4dff","#ff4081",
]

try:
    from app.ui.components.widgets import GlowCard, StatusDot  # type: ignore
except ImportError:
    pass


# ══════════════════════════════════════════════════════════
#  FALLBACK WIDGETS
# ══════════════════════════════════════════════════════════
class GlowCard(ctk.CTkFrame):
    def __init__(self, parent, accent=None, **kw):
        accent = accent or COLORS["accent_cyan"]
        super().__init__(parent,
                         fg_color=COLORS["bg_card"],
                         border_width=1,
                         border_color=accent,
                         corner_radius=14, **kw)
        self._accent   = accent
        self._glow_job = None

    def configure(self, **kw):
        if "border_color" in kw:
            self._accent = kw["border_color"]
        super().configure(**kw)

    def start_glow_cycle(self, ca, cb, steps=30, delay=60):
        self._gc = (ca, cb)
        self._gs = steps
        self._gi = 0
        self._gd = delay
        if self._glow_job:
            try: self.after_cancel(self._glow_job)
            except Exception: pass
        self._glow_step()

    def stop_glow_cycle(self):
        if self._glow_job:
            try: self.after_cancel(self._glow_job)
            except Exception: pass
        self._glow_job = None

    def _glow_step(self):
        # Під час прокрутки не робимо configure — це знімає основні лаги
        if _animations_paused():
            try:
                self._glow_job = self.after(self._gd, self._glow_step)
            except Exception:
                pass
            return
        t  = abs(math.sin(self._gi * math.pi / self._gs))
        c1 = self._gc[0].lstrip("#")
        c2 = self._gc[1].lstrip("#")
        r  = int(int(c1[0:2],16) + (int(c2[0:2],16)-int(c1[0:2],16))*t)
        g  = int(int(c1[2:4],16) + (int(c2[2:4],16)-int(c1[2:4],16))*t)
        b  = int(int(c1[4:6],16) + (int(c2[4:6],16)-int(c1[4:6],16))*t)
        try:
            super().configure(border_color=f"#{r:02x}{g:02x}{b:02x}")
            self._gi = (self._gi+1) % (self._gs*2)
            self._glow_job = self.after(self._gd, self._glow_step)
        except Exception:
            pass


class StatusDot(ctk.CTkLabel):
    def __init__(self, parent, text_color=None, **kw):
        text_color = text_color or COLORS["accent_green"]
        super().__init__(parent, text="●",
                         font=ctk.CTkFont(size=18),
                         text_color=text_color, **kw)
        self._color  = text_color
        self._bright = True
        self._job    = None

    def start_pulse(self, color=None):
        if color:
            self._color = color
        if self._job:
            try: self.after_cancel(self._job)
            except Exception: pass
        self._do_pulse()

    def _do_pulse(self):
        self._bright = not self._bright
        try:
            self.configure(text_color=self._color if self._bright else COLORS["text_dim"])
            self._job = self.after(600, self._do_pulse)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════
#  БІЗНЕС-ЛОГІКА — мережа
# ══════════════════════════════════════════════════════════
def _get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "н/д"


def _get_gateway_ip() -> str:
    try:
        if platform.system() == "Windows":
            out = subprocess.check_output("ipconfig", text=True,
                                          encoding="cp866", errors="replace")
            for line in out.splitlines():
                if "Gateway" in line or "Шлюз" in line:
                    ip = line.split(":")[-1].strip()
                    if ip: return ip
        else:
            out = subprocess.check_output(["ip","route"], text=True)
            for line in out.splitlines():
                if line.startswith("default"):
                    return line.split()[2]
    except Exception:
        pass
    return "н/д"


def _fetch_isp_info() -> dict:
    """Fetches ISP/geo info. Tries multiple endpoints with HTTPS fallback."""
    endpoints = [
        # HTTPS endpoints перші — щоб VPN/firewall їх пропустив
        "https://ipapi.co/json/",
        "https://ipwhois.app/json/",
        "https://api.ipify.org?format=json",  # тільки IP, без geo
        "http://ip-api.com/json/?fields=status,country,countryCode,city,isp,query",
    ]
    for url in endpoints:
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "NetGuardianAI/3.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                d = json.loads(r.read().decode())
                # Нормалізуємо різні формати → під ip-api схему
                if "ip" in d and "country" not in d:
                    # ipify — тільки IP
                    return {"status": "success",
                            "query": d.get("ip", "—"),
                            "country": "?", "countryCode": "?",
                            "city": "?", "isp": "?"}
                if "country_name" in d:
                    # ipapi.co
                    return {"status": "success",
                            "query": d.get("ip", "—"),
                            "country": d.get("country_name", "?"),
                            "countryCode": d.get("country_code", "?"),
                            "city": d.get("city", "?"),
                            "isp": d.get("org", "?")}
                if "country" in d and "ip" in d:
                    # ipwhois.app
                    return {"status": "success",
                            "query": d.get("ip", "—"),
                            "country": d.get("country", "?"),
                            "countryCode": d.get("country_code", "?"),
                            "city": d.get("city", "?"),
                            "isp": d.get("isp", d.get("org", "?"))}
                # ip-api.com стандарт
                if d.get("status") == "success":
                    return d
        except Exception as e:
            print(f"[ISP] {url[:30]}: {type(e).__name__}: {e}")
            continue
    return {}


# ══════════════════════════════════════════════════════════
#  WIFI SIGNAL
# ══════════════════════════════════════════════════════════
def _get_wifi_signal() -> dict:
    result = {"ssid":"н/д","dbm":0,"pct":0,"bars":0,"connected":False}
    try:
        sys = platform.system()
        if sys == "Windows":
            flags = 0
            if hasattr(subprocess, "CREATE_NO_WINDOW"):
                flags = subprocess.CREATE_NO_WINDOW
            out = subprocess.check_output(
                ["netsh","wlan","show","interfaces"],
                text=True, encoding="cp866", errors="replace",
                creationflags=flags)
            ssid_m = re.search(r"SSID\s*:\s(.+)",   out)
            sig_m  = re.search(r"Signal\s*:\s(\d+)%", out)
            if ssid_m and sig_m:
                result["ssid"]      = ssid_m.group(1).strip()
                pct                 = int(sig_m.group(1))
                result["pct"]       = pct
                result["dbm"]       = int(pct/2 - 100)
                result["bars"]      = max(0, min(4, int(pct/25)))
                result["connected"] = True
        elif sys == "Darwin":
            out = subprocess.check_output(
                ["/System/Library/PrivateFrameworks/Apple80211.framework"
                 "/Versions/Current/Resources/airport","-I"],
                text=True, errors="replace")
            ssid_m = re.search(r"SSID:\s+(.+)",       out)
            rssi_m = re.search(r"agrCtlRSSI:\s+(-\d+)", out)
            if ssid_m and rssi_m:
                result["ssid"]      = ssid_m.group(1).strip()
                dbm                 = int(rssi_m.group(1))
                result["dbm"]       = dbm
                pct                 = max(0, min(100, 2*(dbm+100)))
                result["pct"]       = pct
                result["bars"]      = max(0, min(4, int(pct/25)))
                result["connected"] = True
        else:
            out = subprocess.check_output(
                ["iwconfig"], text=True,
                stderr=subprocess.DEVNULL, errors="replace")
            ssid_m = re.search(r'ESSID:"([^"]+)"', out)
            lvl_m  = re.search(r"Signal level=(-\d+)", out)
            if ssid_m and lvl_m:
                result["ssid"]      = ssid_m.group(1)
                dbm                 = int(lvl_m.group(1))
                result["dbm"]       = dbm
                pct                 = max(0, min(100, 2*(dbm+100)))
                result["pct"]       = pct
                result["bars"]      = max(0, min(4, int(pct/25)))
                result["connected"] = True
    except Exception:
        pass
    return result




# ══════════════════════════════════════════════════════════
#  SPEED TEST — raw http.client для максимальної швидкості
# ══════════════════════════════════════════════════════════
PARALLEL    = 4
WARMUP_SEC  = 2
CHUNK       = 262144        # 256 KB — оптимально для гігабітних каналів
SAMPLE_INT  = 0.5
PROBE_SEC   = 1.5           # скільки сек міряти кожен сервер у pre-flight

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
       "AppleWebKit/537.36 (KHTML, like Gecko) "
       "Chrome/120.0.0.0 Safari/537.36")

_SPD_HOST = "speed.cloudflare.com"   # для UL (єдиний надійний endpoint)

# Download-сервери для pre-flight. Формат: (назва, host, path, use_https)
_DL_SERVERS = [
    ("Cloudflare", "speed.cloudflare.com", "/__down?bytes=209715200", True),   # 200MB
    ("Hetzner",    "speed.hetzner.de",     "/100MB.bin",              True),
    ("OVH",        "proof.ovh.net",        "/files/100Mb.dat",        True),
    ("Tele2",      "speedtest.tele2.net",  "/100MB.zip",              False),
]


def _open_dl_conn(host: str, path: str, https: bool, timeout_sec: int = 15):
    """Відкриває HTTP(S) з'єднання і повертає (conn, resp) якщо 200/206, інакше None."""
    try:
        if https:
            ctx = ssl.create_default_context()
            conn = http.client.HTTPSConnection(host, timeout=timeout_sec, context=ctx)
        else:
            conn = http.client.HTTPConnection(host, timeout=timeout_sec)
        conn.request("GET", path, headers={
            "User-Agent":      _UA,
            "Accept":          "*/*",
            "Accept-Encoding": "identity",
            "Connection":      "keep-alive",
            "Referer":         f"https://{host}/",
        })
        resp = conn.getresponse()
        if resp.status not in (200, 206):
            conn.close()
            return None
        return conn, resp
    except Exception:
        return None


def _probe_server_speed(host: str, path: str, https: bool, measure_sec: float):
    """Вимірює скільки MB/s видає сервер за measure_sec. Повертає Mbps (float) або 0.0."""
    result = _open_dl_conn(host, path, https, timeout_sec=4)
    if result is None:
        return 0.0
    conn, resp = result
    try:
        t0 = time.perf_counter()
        total = 0
        while time.perf_counter() - t0 < measure_sec:
            data = resp.read(CHUNK)
            if not data:
                break
            total += len(data)
        elapsed = time.perf_counter() - t0
        mbps = (total * 8) / (elapsed * 1_000_000) if elapsed > 0 else 0.0
        return mbps
    except Exception:
        return 0.0
    finally:
        try: conn.close()
        except Exception: pass


def _choose_fastest_server():
    """
    Паралельно тестує всі сервери за PROBE_SEC. Повертає (name, host, path, https)
    сервера з найвищою швидкістю. Або None якщо жоден не відповів.
    """
    results: dict = {}
    results_lock = threading.Lock()

    def _probe(idx):
        name, host, path, https = _DL_SERVERS[idx]
        mbps = _probe_server_speed(host, path, https, PROBE_SEC)
        if mbps > 0:
            with results_lock:
                results[idx] = (mbps, name, host, path, https)

    threads = [threading.Thread(target=_probe, args=(i,), daemon=True)
               for i in range(len(_DL_SERVERS))]
    for t in threads: t.start()
    for t in threads: t.join(timeout=PROBE_SEC + 2.0)

    if not results:
        return None
    # Вибираємо найшвидший
    best = max(results.values(), key=lambda r: r[0])
    return best   # (mbps, name, host, path, https)


def _speedtest_worker(on_progress, on_done, duration=10):
    CHUNK_UL = 262144

    # ── ФАЗА 0: Pre-flight — сортуємо сервери за швидкістю ──────────
    on_progress("dl_info", 0, "⏳ Пошук найшвидшого сервера...")

    # Збираємо ВСІ робочі сервери з їх швидкостями (не тільки найкращий)
    probe_results: dict = {}
    probe_lock = threading.Lock()

    def _probe(idx):
        name, host, path, https = _DL_SERVERS[idx]
        mbps = _probe_server_speed(host, path, https, PROBE_SEC)
        if mbps > 0:
            with probe_lock:
                probe_results[idx] = (mbps, name, host, path, https)

    probe_threads = [threading.Thread(target=_probe, args=(i,), daemon=True)
                     for i in range(len(_DL_SERVERS))]
    for t in probe_threads: t.start()
    for t in probe_threads: t.join(timeout=PROBE_SEC + 2.0)

    # Сортуємо за швидкістю (найшвидші перші) — на випадок провалу основного
    working_servers = sorted(probe_results.values(), key=lambda r: -r[0])

    if not working_servers:
        on_progress("dl_error", 0, "❌ Жоден сервер не відповідає (перевір інтернет)")
        dl_avg = 0.0
    else:
        dl_avg = 0.0
        # Пробуємо сервери по черзі — якщо топовий не дає даних,
        # переходимо до наступного. Всього 10 сек, розподіляємо.
        remaining_time = duration

        for attempt_idx, (best_mbps, server_name, best_host, best_path, best_https) in enumerate(working_servers[:3]):
            if remaining_time < 4:   # замало часу для нормального тесту
                break

            # Скільки секунд виділяємо цьому серверу
            attempt_duration = remaining_time if attempt_idx == len(working_servers) - 1 else min(remaining_time, duration)

            if attempt_idx == 0:
                on_progress("dl_info", 0, f"✅ Сервер: {server_name} (~{best_mbps:.0f} Mbps)")
            else:
                on_progress("dl_info", 0, f"🔄 Fallback → {server_name} (~{best_mbps:.0f} Mbps)")

            # ── DOWNLOAD на цьому сервері ──
            _dl_stop      = [False]
            _dl_lock      = threading.Lock()
            _dl_bytes_acc = [0]
            _dl_errors    = []

            def _dl_thread(host=best_host, path=best_path, https=best_https):
                while not _dl_stop[0]:
                    result = _open_dl_conn(host, path, https,
                                            timeout_sec=attempt_duration + 10)
                    if result is None:
                        _dl_errors.append("connect failed")
                        time.sleep(0.3)
                        continue
                    conn, resp = result
                    try:
                        while not _dl_stop[0]:
                            data = resp.read(CHUNK)
                            if not data: break
                            with _dl_lock: _dl_bytes_acc[0] += len(data)
                    except Exception as e:
                        _dl_errors.append(f"{type(e).__name__}")
                    finally:
                        try: conn.close()
                        except Exception: pass

            for _ in range(PARALLEL):
                threading.Thread(target=_dl_thread, daemon=True).start()

            dl_samples = []
            t0 = t_sample = time.perf_counter()
            while True:
                time.sleep(0.05)
                now = time.perf_counter(); elapsed = now - t0
                if elapsed >= attempt_duration: _dl_stop[0] = True; break
                dt = now - t_sample
                if dt >= SAMPLE_INT:
                    with _dl_lock:
                        rb = _dl_bytes_acc[0]; _dl_bytes_acc[0] = 0
                    instant = (rb * 8) / (dt * 1_000_000); t_sample = now
                    if elapsed > WARMUP_SEC and instant > 0:
                        dl_samples.append(instant)
                        on_progress("dl", instant, list(dl_samples))

            _dl_stop[0] = True; time.sleep(0.3)
            attempt_avg = sum(dl_samples) / len(dl_samples) if dl_samples else 0.0
            remaining_time -= (time.perf_counter() - t0)

            # Якщо сервер дав нормальний результат — закінчуємо
            if attempt_avg >= 1.0:   # хоча б 1 Mbps щоб вважати успіхом
                dl_avg = attempt_avg
                break
            # Інакше — пробуємо наступний сервер
            print(f"[SpeedTest] {server_name} повернув {attempt_avg:.2f} Mbps, пробую наступний")

        if dl_avg < 1.0:
            on_progress("dl_error", 0, f"❌ DL: всі сервери повільно (<1 Mbps)")
            dl_avg = 0.0

    # ── ФАЗА 2: UPLOAD (Cloudflare /__up, з retry якщо 0) ───────────
    def _do_upload_session(dur: int) -> tuple[float, list]:
        """Один повний upload-сеанс на duration секунд. Повертає (ul_avg_mbps, samples)."""
        _ul_stop      = [False]
        _ul_lock      = threading.Lock()
        _ul_bytes_acc = [0]

        def _ul_thread():
            try:
                ctx  = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    _SPD_HOST, timeout=dur + 20, context=ctx)
                conn.connect()
                conn.putrequest("POST", "/__up")
                conn.putheader("Transfer-Encoding", "chunked")
                conn.putheader("Content-Type", "application/octet-stream")
                conn.putheader("User-Agent", _UA)
                conn.putheader("Referer",   f"https://{_SPD_HOST}/")
                conn.putheader("Origin",    f"https://{_SPD_HOST}")
                conn.endheaders()
                payload = b"\x00" * CHUNK_UL; sent = 0
                while not _ul_stop[0] and sent < 800 * 1024 * 1024:
                    frame = f"{len(payload):x}\r\n".encode() + payload + b"\r\n"
                    conn.send(frame); sent += len(payload)
                    with _ul_lock: _ul_bytes_acc[0] += len(payload)
                try: conn.send(b"0\r\n\r\n")
                except Exception: pass
                try: conn.getresponse()
                except Exception: pass
                conn.close()
            except Exception as e:
                print(f"[SpeedTest UL thread]: {e}")

        for _ in range(PARALLEL):
            threading.Thread(target=_ul_thread, daemon=True).start()

        samples = []
        t0 = t_sample = time.perf_counter()
        while True:
            time.sleep(0.05)
            now = time.perf_counter(); elapsed = now - t0
            if elapsed >= dur: _ul_stop[0] = True; break
            dt = now - t_sample
            if dt >= SAMPLE_INT:
                with _ul_lock:
                    sb = _ul_bytes_acc[0]; _ul_bytes_acc[0] = 0
                instant = (sb * 8) / (dt * 1_000_000); t_sample = now
                if elapsed > WARMUP_SEC and instant > 0:
                    samples.append(instant)
                    on_progress("ul", instant, list(samples))

        _ul_stop[0] = True; time.sleep(0.3)
        return (sum(samples) / len(samples) if samples else 0.0, samples)

    # Перша спроба UL
    ul_avg, ul_samples = _do_upload_session(duration)

    # Retry якщо UL=0 (Cloudflare міг обмежити rate після DL)
    if ul_avg == 0.0:
        on_progress("ul_info", 0, "⏳ UL retry через 2с...")
        time.sleep(2.0)
        ul_avg, ul_samples = _do_upload_session(duration)

    on_done(dl_avg, ul_avg)

# ══════════════════════════════════════════════════════════
#  SHARED DASHBOARD STATE
# ══════════════════════════════════════════════════════════
_DASHBOARD_STATE: dict = {
    "ping_ms":      None,
    "ping_status":  "—",
    "dl_mbps":      None,
    "ul_mbps":      None,
    "local_ip":     "—",
    "gateway":      "—",
    "ext_ip":       "—",
    "isp":          "—",
    "city":         "—",
    "country":      "—",
    "wifi_ssid":    "—",
    "wifi_dbm":     None,
    "wifi_pct":     None,
    "uptime_sec":   0,
}

def get_dashboard_snapshot() -> dict:
    return dict(_DASHBOARD_STATE)


# ══════════════════════════════════════════════════════════
class TrafficChart(ctk.CTkFrame):
    N = 60
    def __init__(self, parent, w=700, h=130):
        super().__init__(parent, height=h,
                         fg_color=COLORS["bg_secondary"], corner_radius=8)
        self._H=h; self._W=w; self._cv=None; self._scan=0; self._job=None
        self._resize_job = None
        self._dl = deque([0.0]*self.N, maxlen=self.N)
        self._ul = deque([0.0]*self.N, maxlen=self.N)
        self.bind("<Configure>", self._on_resize)
        self.after(100, self._late_init)

    def _on_resize(self, event):
        """Debounced resize — не перемальовуємо одразу на кожен pixel під час scroll."""
        new_w = event.width
        if new_w <= 10 or new_w == self._W:
            return
        self._W = new_w
        if self._cv:
            self._cv.config(width=new_w)
        # Відкласти перемальовування на 150мс після останнього resize-event
        if self._resize_job is not None:
            try: self.after_cancel(self._resize_job)
            except Exception: pass
        self._resize_job = self.after(150, self._paint)

    def push(self, dl, ul):
        self._dl.append(dl); self._ul.append(ul); self._paint()

    def _late_init(self):
        try:
            self.winfo_id()
            w = self.winfo_width()
            if w > 10: self._W = w
            self._cv = tk.Canvas(self, width=self._W, height=self._H,
                                 bg=COLORS["bg_secondary"], highlightthickness=0)
            self._cv.place(x=0, y=0, relwidth=1.0)
            self._paint(); self._tick()
        except Exception:
            self.after(150, self._late_init)

    def _tick(self):
        # Пропускаємо перемальовування коли:
        #   • анімації зупинено (йде прокрутка)
        #   • віджет не видимий (інша вкладка)
        try:
            if not _animations_paused() and self.winfo_ismapped():
                self._scan = (self._scan+1) % self.N
                self._paint()
        except Exception:
            pass
        # 400мс — плавно, але вчетверо менше роботи ніж 120мс
        try: self._job = self.after(400, self._tick)
        except Exception: pass

    def _paint(self):
        if _animations_paused(): return
        c = self._cv
        if c is None: return
        try: c.delete("all")
        except Exception: return
        # Беремо РЕАЛЬНУ ширину canvas щоб рамка покривала весь фрейм
        try:
            real_w = c.winfo_width()
            if real_w > 50:
                self._W = real_w
        except Exception: pass
        W, H, p = self._W, self._H, 10
        for i in range(1,4):
            y = p+(H-2*p)*i//4
            c.create_line(p,y,W-p,y,fill=COLORS["text_dim"],dash=(3,6))
        for i in range(1,7):
            x = p+(W-2*p)*i//6
            c.create_line(x,p,x,H-p,fill=COLORS["text_dim"],dash=(3,6))
        vals = list(self._dl)+list(self._ul)
        mx   = max(vals) if max(vals)>0 else 1.0
        self._series(c,list(self._dl),mx,COLORS["accent_blue"],  "#001a55",p)
        self._series(c,list(self._ul),mx,COLORS["accent_purple"],"#330055",p)
        c.create_oval(W-130,H-18,W-118,H-6,fill=COLORS["accent_blue"],  outline="")
        c.create_text(W-112,H-12,text="DL",anchor="w",
                      fill=COLORS["accent_blue"], font=("Consolas",8))
        c.create_oval(W-80,H-18,W-68,H-6,fill=COLORS["accent_purple"],outline="")
        c.create_text(W-62,H-12,text="UL",anchor="w",
                      fill=COLORS["accent_purple"],font=("Consolas",8))
        c.create_text(p+4,14,anchor="w",
                      text=f"↓ {list(self._dl)[-1]:.2f} Mbps",
                      fill=COLORS["accent_blue"],font=("Consolas",9,"bold"))
        c.create_text(p+4,28,anchor="w",
                      text=f"↑ {list(self._ul)[-1]:.2f} Mbps",
                      fill=COLORS["accent_purple"],font=("Consolas",9,"bold"))
        sx = p+(W-2*p)*self._scan/self.N
        c.create_line(sx,p,sx,H-p,fill=COLORS["accent_cyan"],width=1)

        # ── ПОВНА РАМКА графіка ──
        c.create_line(p, p, W-p, p,       fill=COLORS["text_dim"], width=1)  # верх
        c.create_line(p, H-p, W-p, H-p,   fill=COLORS["text_dim"], width=1)  # низ
        c.create_line(p, p, p, H-p,       fill=COLORS["text_dim"], width=1)  # ліва
        c.create_line(W-p, p, W-p, H-p,   fill=COLORS["text_dim"], width=1)  # права

    def _series(self,c,pts,mx,color,fill,p):
        W,H=self._W,self._H; n=len(pts)
        if n<2: return
        coords=[(p+(W-2*p)*i/(n-1),(H-p)-(H-2*p)*(v/mx))
                for i,v in enumerate(pts)]
        poly=[(p,H-p)]+coords+[(W-p,H-p)]
        c.create_polygon([v for xy in poly for v in xy],
                         fill=fill,outline="",smooth=True)
        c.create_line(*[v for xy in coords for v in xy],
                      fill=color,width=2,smooth=True)
        ex,ey=coords[-1]
        c.create_oval(ex-3,ey-3,ex+3,ey+3,fill=color,outline=COLORS["bg_card"])

    def destroy(self):
        if self._job:
            try: self.after_cancel(self._job)
            except Exception: pass
        super().destroy()


# ══════════════════════════════════════════════════════════
#  PING HISTORY CHART
# ══════════════════════════════════════════════════════════
class PingHistoryChart(ctk.CTkFrame):
    N = 120

    def __init__(self, parent, w=700, h=140):
        super().__init__(parent, height=h,
                         fg_color=COLORS["bg_secondary"], corner_radius=8)
        self._W=w; self._H=h; self._cv=None; self._job=None
        self._resize_job = None
        self._pings      = deque([None]*self.N, maxlen=self.N)
        self._loss_count = 0
        self._total      = 0
        self.bind("<Configure>", self._on_resize)
        self.after(100, self._late_init)

    def _on_resize(self, event):
        """Debounced resize щоб не лагало під час прокрутки."""
        new_w = event.width
        if new_w <= 10 or new_w == self._W:
            return
        self._W = new_w
        if self._cv:
            self._cv.config(width=new_w)
        if self._resize_job is not None:
            try: self.after_cancel(self._resize_job)
            except Exception: pass
        self._resize_job = self.after(150, self._paint)

    def push(self, ms):
        self._total += 1
        if ms is None:
            self._loss_count += 1
        self._pings.append(ms)
        self._paint()

    def loss_pct(self) -> float:
        return (self._loss_count/self._total*100) if self._total else 0.0

    def _late_init(self):
        try:
            self.winfo_id()
            w = self.winfo_width()
            if w > 10: self._W = w
            self._cv = tk.Canvas(self, width=self._W, height=self._H,
                                 bg=COLORS["bg_secondary"], highlightthickness=0)
            self._cv.place(x=0, y=0, relwidth=1.0)
            self._paint()
        except Exception:
            self.after(150, self._late_init)

    def _paint(self):
        if _animations_paused(): return
        c = self._cv
        if c is None: return
        try: c.delete("all")
        except Exception: return
        # ВАЖЛИВО: беремо РЕАЛЬНУ ширину canvas (не self._W) щоб рамка
        # малювалась по краях, навіть якщо вікно ширше за початкове.
        try:
            real_w = c.winfo_width()
            if real_w > 50:
                self._W = real_w
        except Exception: pass
        W, H, p = self._W, self._H, 10
        pts   = list(self._pings)

        # ФІКСОВАНА шкала 0..200ms — не масштабуємо динамічно
        mx = 200

        # Сітка з підписами 50/100/150/200ms (через 4 ділення = 50ms)
        for i in range(1, 5):
            y   = p + (H - 2*p) * i // 5
            lbl_ms = int(mx * (1 - i/5))
            c.create_line(p+34, y, W-p, y, fill=COLORS["text_dim"], dash=(3,6))
            c.create_text(p+32, y, anchor="e", text=f"{lbl_ms} ms",
                          fill=COLORS["text_dim"], font=("Consolas", 7))

        # Зона "добре" (під 50ms) — затемнена
        threshold_y = (H-p) - (H - 2*p) * (50/mx)
        if threshold_y > p:
            c.create_rectangle(p+34, threshold_y, W-p, H-p,
                               fill="#001a10", outline="")

        n      = len(pts)
        coords = []
        for i, v in enumerate(pts):
            x = p+34+(W-p-34)*i/(n-1) if n>1 else p+34
            if v is not None:
                # Кліпуємо до шкали 0..200 (значення >200 малюємо як 200)
                v_clipped = min(v, mx)
                y = (H-p) - (H - 2*p) * (v_clipped / mx)
                coords.append((x, y))
            else:
                if len(coords) >= 2:
                    c.create_line(*[cv for xy in coords for cv in xy],
                                  fill=COLORS["accent_cyan"], width=2, smooth=True)
                coords = []
                c.create_line(x-4, H//2-4, x+4, H//2+4,
                              fill=COLORS["accent_red"], width=2)
                c.create_line(x-4, H//2+4, x+4, H//2-4,
                              fill=COLORS["accent_red"], width=2)

        if len(coords) >= 2:
            c.create_line(*[cv for xy in coords for cv in xy],
                          fill=COLORS["accent_cyan"], width=2, smooth=True)

        if coords:
            ex, ey = coords[-1]
            c.create_oval(ex-4, ey-4, ex+4, ey+4,
                          fill=COLORS["accent_cyan"],
                          outline=COLORS["bg_card"],width=2)

        # Текстові позначки last/loss/peak
        valid = [v for v in pts if v is not None]
        last = valid[-1] if valid else 0
        loss = self.loss_pct()
        loss_col = (COLORS["accent_red"]    if loss>5
                    else COLORS["accent_yellow"] if loss>1
                    else COLORS["accent_green"])
        c.create_text(p+36, 12, anchor="w",
                      text=f"last: {last} ms",
                      fill=COLORS["accent_cyan"], font=("Consolas",9,"bold"))
        c.create_text(p+36, 26, anchor="w",
                      text=f"loss: {loss:.1f}%",
                      fill=loss_col, font=("Consolas",9,"bold"))
        # Підпис "peak" — реальний пік з даних, обмежений до 200ms
        peak_val = max(valid) if valid else 0
        c.create_text(W-p, 12, anchor="e",
                      text=f"peak: {peak_val} ms",
                      fill=COLORS["text_dim"], font=("Consolas",8))

        # ── ПОВНА РАМКА графіка ──
        # Y-вісь (ліва)
        c.create_line(p+34, p, p+34, H-p,
                      fill=COLORS["text_dim"], width=1)
        # X-вісь (нижня)
        c.create_line(p+34, H-p, W-p, H-p,
                      fill=COLORS["text_dim"], width=1)
        # Права рамка
        c.create_line(W-p, p, W-p, H-p,
                      fill=COLORS["text_dim"], width=1)
        # Верхня рамка
        c.create_line(p+34, p, W-p, p,
                      fill=COLORS["text_dim"], width=1)

    def destroy(self):
        if self._job:
            try: self.after_cancel(self._job)
            except Exception: pass
        super().destroy()


# ══════════════════════════════════════════════════════════
#  SHIMMER PROGRESS BAR
# ══════════════════════════════════════════════════════════
class ShimmerBar(ctk.CTkFrame):
    _COLORS = ["#00e5ff","#00ccee","#0099bb","#00ccee","#00e5ff","#2979ff","#00e5ff"]

    def __init__(self, parent, height=8):
        super().__init__(parent, height=height, fg_color="transparent")
        self._bar = ctk.CTkProgressBar(self, height=height,
                                        progress_color=COLORS["accent_cyan"],
                                        fg_color=COLORS["border"],
                                        corner_radius=4)
        self._bar.pack(fill="x", expand=True)
        self._bar.set(0)
        self._active=False; self._idx=0; self._job=None

    def start(self):
        self._active=True; self._idx=0; self._bar.set(0); self._tick()

    def stop(self):
        self._active=False
        if self._job:
            try: self.after_cancel(self._job)
            except Exception: pass
        try:
            self._bar.set(0)
            self._bar.configure(progress_color=COLORS["accent_cyan"])
        except Exception: pass

    def set_value(self, v):
        try: self._bar.set(max(0.0,min(1.0,v)))
        except Exception: pass

    def _tick(self):
        if not self._active: return
        try:
            self._bar.configure(
                progress_color=self._COLORS[self._idx%len(self._COLORS)])
            self._idx += 1
            self._job = self.after(90, self._tick)
        except Exception: pass


# ══════════════════════════════════════════════════════════
#  CONTEXT MENU
# ══════════════════════════════════════════════════════════
class _ProcMenu(tk.Menu):
    def __init__(self, parent, pid, name):
        super().__init__(parent, tearoff=0,
                         bg=COLORS["bg_card"], fg=COLORS["text_primary"],
                         activebackground=COLORS["border_accent"],
                         activeforeground=COLORS["accent_cyan"],
                         font=("Consolas",10))
        self._pid = pid
        self.add_command(label=f"  {name[:24]}  (PID {pid})",
                         state="disabled", foreground=COLORS["text_secondary"])
        self.add_separator()
        self.add_command(label="🗂️  Диспетчер завдань", command=self._task_manager)
        self.add_command(label="❌  Завершити процес",  command=self._kill,
                         foreground=COLORS["accent_red"])

    def popup(self, x, y):
        try: self.tk_popup(x,y)
        finally: self.grab_release()

    def _task_manager(self):
        s = platform.system()
        try:
            if s=="Windows": subprocess.Popen(["taskmgr"])
            elif s=="Darwin": subprocess.Popen(["open","-a","Activity Monitor"])
            else:
                for t in ["gnome-system-monitor","ksysguard","htop"]:
                    try: subprocess.Popen([t]); break
                    except FileNotFoundError: pass
        except Exception: pass

    def _kill(self):
        try: psutil.Process(self._pid).terminate()
        except Exception: pass


# ══════════════════════════════════════════════════════════
#  ГОЛОВНИЙ КЛАС
# ══════════════════════════════════════════════════════════
class DashboardPage(ctk.CTkScrollableFrame):

    SPEEDTEST_DURATION = 10
    PING_INTERVAL      = 5

    def __init__(self, parent,
                 start_speedtest_callback=None,
                 toggle_widget_callback=None):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.start_speedtest_callback = start_speedtest_callback
        self.toggle_widget_callback   = toggle_widget_callback

        self._speedtest_running = False
        self._speedtest_t0      = 0.0
        self._traffic_prev: dict = {}
        self._session_start     = time.time()
        self._uptime_running    = True
        self._row_pids:  list = [0]*5
        self._row_names: list = [""]*5

        # ── Детекція прокрутки (паузить canvas-анімації глобально) ──
        self._scroll_timer = None
        self._bind_scroll_events()

        self.grid_columnconfigure((0,1), weight=1)
        self._build_ui()
        self.after(100, self._start_bg)

    # ──────────────────────────────────────────────────────
    # SCROLL DETECTION — паузить анімації канвасів поки юзер крутить колесо
    # ──────────────────────────────────────────────────────
    def _bind_scroll_events(self):
        """Зв'язуємо події прокрутки на багатьох рівнях для надійності."""
        try:
            # CTkScrollableFrame використовує внутрішній Canvas + Scrollbar
            inner_canvas = getattr(self, "_parent_canvas", None)
            scrollbar    = getattr(self, "_scrollbar",     None)

            if inner_canvas is None:
                # віджет ще не готовий — спробуємо знов через 200мс
                self.after(200, self._bind_scroll_events)
                return

            # Колесо миші на внутрішньому Canvas
            inner_canvas.bind("<MouseWheel>", self._on_scroll_event, add="+")   # Windows
            inner_canvas.bind("<Button-4>",   self._on_scroll_event, add="+")   # Linux scroll up
            inner_canvas.bind("<Button-5>",   self._on_scroll_event, add="+")   # Linux scroll down

            # Scrollbar drag
            if scrollbar is not None:
                scrollbar.bind("<B1-Motion>",      self._on_scroll_event, add="+")
                scrollbar.bind("<ButtonRelease-1>", self._on_scroll_event, add="+")
                scrollbar.bind("<Button-1>",        self._on_scroll_event, add="+")

            # На сам DashboardPage і всі його children — global widget tree
            self.bind_all("<MouseWheel>", self._on_scroll_event, add="+")
            self.bind_all("<Button-4>",   self._on_scroll_event, add="+")
            self.bind_all("<Button-5>",   self._on_scroll_event, add="+")
        except Exception:
            pass

    def _on_scroll_event(self, event=None):
        """Вмикаємо паузу анімацій. Через 250мс тиші — знімаємо."""
        _pause_animations(True)
        if self._scroll_timer is not None:
            try: self.after_cancel(self._scroll_timer)
            except Exception: pass
        self._scroll_timer = self.after(250, self._clear_scroll_flag)

    def _clear_scroll_flag(self):
        _pause_animations(False)
        self._scroll_timer = None

    # ──────────────────────────────────────────────────────
    def _build_ui(self):
        R = 0

        # ── 0. AUTO-DIAGNOSIS BANNER ─────────────────────
        # Прихований за замовчуванням. З'являється коли інтернет
        # недоступний — пропонує auto-fix кнопки.
        self._build_offline_banner(R)
        R += 1

        # ── 1. PING CARD ──────────────────────────────────
        self.ping_card = GlowCard(self, accent=COLORS["accent_cyan"])
        self.ping_card.grid(row=R, column=0, columnspan=2,
                            padx=24, pady=(24,12), sticky="ew")
        self.ping_card.grid_columnconfigure(1, weight=1)
        self.ping_card.start_glow_cycle(
            COLORS["accent_cyan"], COLORS["accent_blue"], 40, 80)

        lp = ctk.CTkFrame(self.ping_card, fg_color="transparent")
        lp.grid(row=0, column=0, padx=30, pady=25, sticky="w")

        # Заголовок з кнопкою ❓
        pm_hdr = ctk.CTkFrame(lp, fg_color="transparent")
        pm_hdr.pack(anchor="w")
        ctk.CTkLabel(pm_hdr, text="PING  MONITOR",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(side="left")
        HelpButton(pm_hdr, help_key="ping_monitor").pack(side="left", padx=(4,0))

        self.lbl_ping = ctk.CTkLabel(lp, text="-- ms",
            font=ctk.CTkFont(family="Consolas",size=52,weight="bold"),
            text_color=COLORS["accent_cyan"])
        self.lbl_ping.pack(anchor="w")
        ctk.CTkLabel(lp, text="google dns  ·  8.8.8.8",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_dim"]).pack(anchor="w")

        rp = ctk.CTkFrame(self.ping_card, fg_color="transparent")
        rp.grid(row=0, column=1, padx=30, pady=25, sticky="e")
        self.status_dot = StatusDot(rp, text_color=COLORS["accent_green"])
        self.status_dot.pack(side="left", padx=(0,10))
        self.status_dot.start_pulse()
        self.lbl_status = ctk.CTkLabel(rp, text="ОЧІКУВАННЯ",
            font=ctk.CTkFont(family="Consolas",size=16,weight="bold"),
            text_color=COLORS["accent_green"])
        self.lbl_status.pack(side="left")
        R += 1

        # ── 2. PING HISTORY GRAPH ─────────────────────────
        ph_card = GlowCard(self, accent=COLORS["accent_cyan"])
        ph_card.grid(row=R, column=0, columnspan=2,
                     padx=24, pady=12, sticky="ew")
        ph_card.grid_columnconfigure(0, weight=1)

        ph_hdr = ctk.CTkFrame(ph_card, fg_color="transparent")
        ph_hdr.grid(row=0, column=0, padx=20, pady=(15,5), sticky="ew")
        ph_hdr.grid_columnconfigure(0, weight=1)

        # Заголовок з кнопкою ❓
        ph_title_f = ctk.CTkFrame(ph_hdr, fg_color="transparent")
        ph_title_f.grid(row=0, column=0, sticky="w")
        ctk.CTkLabel(ph_title_f,
                     text="📉  PING HISTORY  ·  LAST 10 MIN  ·  5s INTERVAL  ·  ✕ = TIMEOUT",
                     font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                     text_color=COLORS["accent_cyan"]).pack(side="left")
        HelpButton(ph_title_f, help_key="ping_history").pack(side="left", padx=(6,0))

        stats_f = ctk.CTkFrame(ph_hdr, fg_color="transparent")
        stats_f.grid(row=0, column=1, sticky="e")
        self._lbl_ph_min = ctk.CTkLabel(stats_f, text="min: --",
            font=ctk.CTkFont(family="Consolas",size=10),
            text_color=COLORS["accent_green"])
        self._lbl_ph_min.pack(side="left", padx=10)
        self._lbl_ph_avg = ctk.CTkLabel(stats_f, text="avg: --",
            font=ctk.CTkFont(family="Consolas",size=10),
            text_color=COLORS["accent_yellow"])
        self._lbl_ph_avg.pack(side="left", padx=10)
        self._lbl_ph_max = ctk.CTkLabel(stats_f, text="max: --",
            font=ctk.CTkFont(family="Consolas",size=10),
            text_color=COLORS["accent_red"])
        self._lbl_ph_max.pack(side="left", padx=10)

        self.ping_chart = PingHistoryChart(ph_card, w=700, h=140)
        self.ping_chart.grid(row=1, column=0, padx=20, pady=(0, 18), sticky="ew")
        R += 1

        # ── 3. ISP & LOCATION ─────────────────────────────
        isp_card = GlowCard(self, accent=COLORS["accent_green"])
        isp_card.grid(row=R, column=0, columnspan=2,
                      padx=24, pady=12, sticky="ew")
        isp_card.grid_columnconfigure((0,1,2,3), weight=1)

        # Заголовок з кнопкою ❓
        isp_hdr_f = ctk.CTkFrame(isp_card, fg_color="transparent")
        isp_hdr_f.grid(row=0, column=0, columnspan=4, padx=30, pady=(15,6), sticky="w")
        ctk.CTkLabel(isp_hdr_f,
                     text="🌐  ISP & LOCATION  ·  EXTERNAL NETWORK INFO",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(side="left")
        HelpButton(isp_hdr_f, help_key="isp_location").pack(side="left", padx=(6,0))

        self._lbl_flag  = self._isp_cell(isp_card, 0, "🌍","COUNTRY")
        self._lbl_isp   = self._isp_cell(isp_card, 1, "📡","ISP")
        self._lbl_city  = self._isp_cell(isp_card, 2, "🏙️","МІСТО")
        self._lbl_extip = self._isp_cell(isp_card, 3, "🔒","EXTERNAL IP")
        self._lbl_vpn   = ctk.CTkLabel(isp_card, text="⏳ Перевірка...",
            font=ctk.CTkFont(family="Consolas",size=9),
            text_color=COLORS["text_dim"])
        self._lbl_vpn.grid(row=2, column=0, columnspan=4,
                           padx=30, pady=(4,12), sticky="w")
        R += 1

        # ── 4. WIFI SIGNAL ────────────────────────────────
        wifi_card = GlowCard(self, accent=COLORS["accent_blue"])
        wifi_card.grid(row=R, column=0, columnspan=2,
                       padx=24, pady=12, sticky="ew")
        wifi_card.grid_columnconfigure((0,1,2,3), weight=1)

        # Заголовок з кнопкою ❓
        wifi_hdr_f = ctk.CTkFrame(wifi_card, fg_color="transparent")
        wifi_hdr_f.grid(row=0, column=0, columnspan=4, padx=20, pady=(15,8), sticky="w")
        ctk.CTkLabel(wifi_hdr_f,
                     text="📶  WiFi SIGNAL MONITOR  ·  LIVE  ·  ОНОВЛЕННЯ КОЖНІ 10с",
                     font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left")
        HelpButton(wifi_hdr_f, help_key="wifi_signal").pack(side="left", padx=(6,0))

        self._lbl_wifi_ssid = self._wifi_cell(wifi_card, 0, "📡","SSID",     COLORS["accent_blue"])
        self._lbl_wifi_dbm  = self._wifi_cell(wifi_card, 1, "📊","СИГНАЛ",   COLORS["accent_cyan"])
        self._lbl_wifi_pct  = self._wifi_cell(wifi_card, 2, "💯","ЯКІСТЬ %", COLORS["accent_green"])
        self._lbl_wifi_bars = self._wifi_cell(wifi_card, 3, "📶","ПОЛОСИ",   COLORS["accent_yellow"])

        self._lbl_wifi_status = ctk.CTkLabel(wifi_card,
            text="⏳ Зчитування даних WiFi...",
            font=ctk.CTkFont(family="Consolas",size=9),
            text_color=COLORS["text_dim"])
        self._lbl_wifi_status.grid(row=2, column=0, columnspan=4,
                                   padx=20, pady=(0,12), sticky="w")
        R += 1

        # ── 5. SPEEDTEST ──────────────────────────────────
        spd_card = GlowCard(self, accent=COLORS["border"])
        spd_card.grid(row=R, column=0, columnspan=2,
                      padx=24, pady=12, sticky="ew")
        spd_card.grid_columnconfigure((0,1,2), weight=1)
        self._spd_card = spd_card

        # Заголовок з кнопкою ❓
        spd_hdr_f = ctk.CTkFrame(spd_card, fg_color="transparent")
        spd_hdr_f.grid(row=0, column=0, columnspan=3, padx=30, pady=(20,10), sticky="w")
        ctk.CTkLabel(spd_hdr_f,
                     text=f"ПРОПУСКНА ЗДАТНІСТЬ  ·  {self.SPEEDTEST_DURATION}с ТЕСТ  ·  {PARALLEL} ПОТОКІВ  ·  DIRECT BYTE METER",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(side="left")
        HelpButton(spd_hdr_f, help_key="speedtest").pack(side="left", padx=(6,0))

        dlf = ctk.CTkFrame(spd_card, fg_color=COLORS["bg_secondary"], corner_radius=12)
        dlf.grid(row=1, column=0, padx=20, pady=(0,8), sticky="ew")
        ctk.CTkLabel(dlf, text="📥  DOWNLOAD  ·  AVG",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(pady=(15,0))
        self.lbl_dl = ctk.CTkLabel(dlf, text="--",
            font=ctk.CTkFont(family="Consolas",size=40,weight="bold"),
            text_color=COLORS["accent_blue"])
        self.lbl_dl.pack()
        ctk.CTkLabel(dlf, text="Mbps",
                     font=ctk.CTkFont(family="Consolas",size=11),
                     text_color=COLORS["text_dim"]).pack()
        self.lbl_dl_live = ctk.CTkLabel(dlf, text="live: --",
            font=ctk.CTkFont(family="Consolas",size=9),
            text_color=COLORS["text_dim"])
        self.lbl_dl_live.pack(pady=(0,15))

        ulf = ctk.CTkFrame(spd_card, fg_color=COLORS["bg_secondary"], corner_radius=12)
        ulf.grid(row=1, column=1, padx=20, pady=(0,8), sticky="ew")
        ctk.CTkLabel(ulf, text="📤  UPLOAD  ·  AVG",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(pady=(15,0))
        self.lbl_ul = ctk.CTkLabel(ulf, text="--",
            font=ctk.CTkFont(family="Consolas",size=40,weight="bold"),
            text_color=COLORS["accent_purple"])
        self.lbl_ul.pack()
        ctk.CTkLabel(ulf, text="Mbps",
                     font=ctk.CTkFont(family="Consolas",size=11),
                     text_color=COLORS["text_dim"]).pack()
        self.lbl_ul_live = ctk.CTkLabel(ulf, text="live: --",
            font=ctk.CTkFont(family="Consolas",size=9),
            text_color=COLORS["text_dim"])
        self.lbl_ul_live.pack(pady=(0,15))

        bf = ctk.CTkFrame(spd_card, fg_color="transparent")
        bf.grid(row=1, column=2, padx=20, pady=(0,8))
        self.btn_spd = ctk.CTkButton(bf,
            text="▶  ЗАПУСТИТИ ТЕСТ",
            command=self._on_speedtest,
            fg_color=COLORS["border_accent"], hover_color="#0d3d8a",
            text_color=COLORS["accent_cyan"],
            font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
            height=48, corner_radius=12,
            border_width=1, border_color=COLORS["accent_blue"])
        self.btn_spd.pack(pady=(0,8))
        self.lbl_spd_timer = ctk.CTkLabel(bf, text="",
            font=ctk.CTkFont(family="Consolas",size=11),
            text_color=COLORS["accent_yellow"])
        self.lbl_spd_timer.pack()

        self._pbar = ShimmerBar(spd_card, height=8)
        self._pbar.grid(row=2, column=0, columnspan=3,
                        padx=20, pady=(0,4), sticky="ew")
        R += 1

        # ── 6. QUICK STATS ────────────────────────────────
        sr = ctk.CTkFrame(self, fg_color="transparent")
        sr.grid(row=R, column=0, columnspan=2, padx=24, pady=12, sticky="ew")
        sr.grid_columnconfigure((0,1,2), weight=1)
        self.lbl_gw     = self._stat_card(sr,0,"🌐","ШЛЮЗ / РОУТЕР", COLORS["accent_green"])
        self.lbl_lip    = self._stat_card(sr,1,"🏠","LOCAL IP",       COLORS["accent_cyan"])
        self.lbl_uptime = self._stat_card(sr,2,"⏱️","UPTIME SESSION", COLORS["accent_yellow"])
        R += 1

        # ── 7. TRAFFIC CHART ──────────────────────────────
        chart_card = GlowCard(self, accent=COLORS["accent_cyan"])
        chart_card.grid(row=R, column=0, columnspan=2,
                        padx=24, pady=12, sticky="ew")
        chart_card.grid_columnconfigure(0, weight=1)

        # Заголовок з кнопкою ❓
        tc_hdr_f = ctk.CTkFrame(chart_card, fg_color="transparent")
        tc_hdr_f.grid(row=0, column=0, padx=20, pady=(15,5), sticky="w")
        ctk.CTkLabel(tc_hdr_f,
                     text="📈  REAL-TIME BANDWIDTH  ·  LAST 2 MIN  ·  2s INTERVAL",
                     font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                     text_color=COLORS["accent_cyan"]).pack(side="left")
        HelpButton(tc_hdr_f, help_key="traffic_chart").pack(side="left", padx=(6,0))

        self.chart = TrafficChart(chart_card, w=700, h=130)
        self.chart.grid(row=1, column=0, padx=20, pady=(0, 18), sticky="ew")
        R += 1

        # ── 8. PER-APP TRAFFIC ────────────────────────────
        trf_card = GlowCard(self, accent=COLORS["accent_blue"])
        trf_card.grid(row=R, column=0, columnspan=2,
                      padx=24, pady=12, sticky="ew")
        trf_card.grid_columnconfigure(0, weight=1)

        # Заголовок з кнопкою ❓
        pa_hdr_f = ctk.CTkFrame(trf_card, fg_color="transparent")
        pa_hdr_f.grid(row=0, column=0, padx=20, pady=(15,5), sticky="w")
        ctk.CTkLabel(pa_hdr_f,
                     text="📊  PER-APP TRAFFIC  ·  TOP-5  ·  ПКМ = ДІЇ",
                     font=ctk.CTkFont(family="Consolas",size=11,weight="bold"),
                     text_color=COLORS["accent_blue"]).pack(side="left")
        HelpButton(pa_hdr_f, help_key="per_app_traffic").pack(side="left", padx=(6,0))

        hdr = ctk.CTkFrame(trf_card, fg_color=COLORS["bg_secondary"], corner_radius=8)
        hdr.grid(row=1, column=0, padx=20, pady=(0,4), sticky="ew")
        for ci,(txt,w) in enumerate([
            ("●",30),("ПРОЦЕС",180),("PID",70),
            ("↓ Mbps",110),("↑ Mbps",110),("ВСЬОГО MB",100)
        ]):
            ctk.CTkLabel(hdr, text=txt, width=w,
                         font=ctk.CTkFont(family="Consolas",size=10,weight="bold"),
                         text_color=COLORS["text_secondary"],
                         anchor="w").grid(row=0,column=ci,padx=(6,2),pady=6,sticky="w")

        self._trf_rows   = []
        self._trf_frames = []
        for ri in range(5):
            bg = COLORS["bg_card"] if ri%2==0 else COLORS["bg_secondary"]
            rf = ctk.CTkFrame(trf_card, fg_color=bg, corner_radius=6)
            rf.grid(row=ri+2, column=0, padx=20, pady=2, sticky="ew")
            self._trf_frames.append(rf)
            icon = ctk.CTkLabel(rf, text="●", width=30,
                                font=ctk.CTkFont(size=20),
                                text_color=COLORS["text_dim"])
            icon.grid(row=0,column=0,padx=(6,2),pady=5)
            cells = [icon]
            for ci,(cw,_) in enumerate([(180,"w"),(70,"w"),(110,"w"),(110,"w"),(100,"w")]):
                lbl = ctk.CTkLabel(rf, text="—", width=cw,
                                   font=ctk.CTkFont(family="Consolas",size=11),
                                   text_color=COLORS["text_secondary"], anchor="w")
                lbl.grid(row=0,column=ci+1,padx=(4,2),pady=5,sticky="w")
                cells.append(lbl)
            self._trf_rows.append(cells)
            for w in [rf]+cells:
                w.bind("<Button-3>", lambda e,i=ri: self._proc_menu(e,i))

        ctk.CTkLabel(trf_card, text="оновлення кожні 2 с",
                     font=ctk.CTkFont(family="Consolas",size=9),
                     text_color=COLORS["text_dim"]).grid(
            row=8, column=0, padx=20, pady=(0,10), sticky="e")
        R += 1

        # ── 10.5 TAPO SMART PLUG ────────────────────────────────
        # Карточка для керування Tapo P110 — дозволяє вмикати/вимикати
        # і бачити споживання енергії в реальному часі.
        self._build_tapo_card(R)
        R += 1


        # ── 11. FLOATING WIDGET ───────────────────────────
        wc = GlowCard(self, accent=COLORS["accent_purple"])
        wc.grid(row=R, column=0, columnspan=2,
                padx=24, pady=(12,24), sticky="ew")
        wc.grid_columnconfigure(1, weight=1)

        # Заголовок з кнопкою ❓
        fw_hdr_f = ctk.CTkFrame(wc, fg_color="transparent")
        fw_hdr_f.grid(row=0, column=0, padx=20, pady=15, sticky="w")
        ctk.CTkLabel(fw_hdr_f, text="🪟  FLOATING WIDGET (OVERLAY)",
                     font=ctk.CTkFont(family="Consolas",size=12,weight="bold"),
                     text_color=COLORS["accent_purple"]).pack(side="left")
        HelpButton(fw_hdr_f, help_key="floating_widget").pack(side="left", padx=(6,0))

        self.btn_widget = ctk.CTkButton(wc, text="Увімкнути",
            command=self._on_widget_toggle,
            fg_color="transparent", border_width=1,
            border_color=COLORS["accent_purple"],
            text_color=COLORS["accent_purple"],
            font=ctk.CTkFont(family="Consolas",size=12))
        self.btn_widget.grid(row=0, column=1, padx=20, pady=15, sticky="e")

    # ── helpers ───────────────────────────────────────────

    def _build_offline_banner(self, row: int):
        """Великий помітний банер який з'являється коли інтернет недоступний.

        Показує AI-діагноз причини + кнопки швидких фіксів.
        Auto-detect через polling кожні 10 секунд.
        """
        self._offline_banner = ctk.CTkFrame(
            self,
            fg_color="#3a0d0d",      # темно-червоний
            corner_radius=12,
            border_width=2,
            border_color="#ef4444",
        )
        # СПОЧАТКУ ПРИХОВАНИЙ — grid_remove() не виділяє місце
        self._offline_banner.grid(row=row, column=0, columnspan=2,
                                   padx=24, pady=(24, 0), sticky="ew")
        self._offline_banner.grid_columnconfigure(0, weight=1)
        self._offline_banner.grid_remove()  # ← приховуємо

        # Заголовок
        hdr = ctk.CTkFrame(self._offline_banner, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=20, pady=(14, 6))
        hdr.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            hdr, text="⚠️  ІНТЕРНЕТ НЕДОСТУПНИЙ",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color="#fca5a5",
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            hdr,
            text="(автоматичне виявлення активне)",
            font=ctk.CTkFont(family="Consolas", size=10, slant="italic"),
            text_color="#94a3b8",
        ).grid(row=0, column=1, sticky="w", padx=(12, 0))

        # Діагноз — заповнюється динамічно
        self._lbl_offline_diagnosis = ctk.CTkLabel(
            self._offline_banner,
            text="🔍 Аналізую причину...",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color="#fef3c7",
            wraplength=900, justify="left", anchor="w",
        )
        self._lbl_offline_diagnosis.grid(row=1, column=0, sticky="ew",
                                          padx=20, pady=(4, 8))

        # Auto-fix кнопки
        fix_row = ctk.CTkFrame(self._offline_banner, fg_color="transparent")
        fix_row.grid(row=2, column=0, sticky="ew", padx=20, pady=(4, 16))

        # Швидкі фікси що допоможуть якщо інтернет лежить
        QUICK_FIXES = [
            ("🔄  Скинути DNS",  "ipconfig /flushdns"),
            ("🌐  Перевипустити IP", "ipconfig /release && ipconfig /renew"),
            ("📡  Скинути Wi-Fi", "netsh interface set interface name=\"Wi-Fi\" admin=DISABLED && timeout /t 2 && netsh interface set interface name=\"Wi-Fi\" admin=ENABLED"),
            ("🔧  Скинути TCP/IP", "netsh int ip reset"),
        ]
        for i, (label, cmd) in enumerate(QUICK_FIXES):
            btn = ctk.CTkButton(
                fix_row, text=label,
                command=lambda c=cmd, l=label: self._execute_quick_fix(l, c),
                fg_color="#1a3a0d", hover_color="#22552d",
                text_color="#86efac",
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=36, corner_radius=8,
                border_width=1, border_color="#22c55e",
            )
            btn.grid(row=0, column=i, padx=4, sticky="ew")
            fix_row.grid_columnconfigure(i, weight=1)

        # Старт моніторингу — кожні 15с перевіряємо інтернет
        self.after(5000, self._check_offline_status)

    def _check_offline_status(self):
        """Перевіряє чи доступний інтернет, показує/приховує банер."""
        try:
            from hybrid_ai import is_internet_available, reset_internet_cache
            reset_internet_cache()    # свіжа перевірка
            online = is_internet_available()

            if online:
                # Все ОК — приховуємо банер
                if hasattr(self, "_offline_banner"):
                    try: self._offline_banner.grid_remove()
                    except Exception: pass
            else:
                # Інтернет лежить — показуємо банер + діагноз
                if hasattr(self, "_offline_banner"):
                    try:
                        self._offline_banner.grid()
                        # Запускаємо діагностику в окремому потоці
                        threading.Thread(
                            target=self._diagnose_offline,
                            daemon=True).start()
                    except Exception: pass
        except Exception as e:
            print(f"[Dashboard] _check_offline_status: {e}")

        # Перепланувати наступну перевірку
        try: self.after(15_000, self._check_offline_status)
        except Exception: pass

    def _diagnose_offline(self):
        """Аналізує чому немає інтернету — у фоновому потоці."""
        try:
            import subprocess
            import platform

            # Перевіряємо ping до різних точок
            results = {}
            targets = {
                "gateway":    self._get_gateway() or "192.168.1.1",
                "cloudflare": "1.1.1.1",
                "google_dns": "8.8.8.8",
            }
            sysname = platform.system().lower()
            for name, host in targets.items():
                if "windows" in sysname:
                    cmd = ["ping", "-n", "2", "-w", "1500", host]
                else:
                    cmd = ["ping", "-c", "2", "-W", "2", host]
                try:
                    r = subprocess.run(cmd, capture_output=True, text=True,
                                        timeout=8,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    results[name] = (r.returncode == 0)
                except Exception:
                    results[name] = False

            # Логіка діагностики
            gw_ok = results.get("gateway", False)
            ext_ok = results.get("cloudflare", False) or results.get("google_dns", False)

            if not gw_ok:
                diagnosis = (
                    "🔴 Шлюз не пінгується.\n"
                    "💡 Можливі причини:\n"
                    "   • Wi-Fi/Ethernet відключено від роутера\n"
                    "   • Роутер вимкнено або завис\n"
                    "   • Кабель не вставлений\n"
                    "💊 Рекомендую: перезапустити Wi-Fi або перевірити кабель"
                )
            elif gw_ok and not ext_ok:
                diagnosis = (
                    "🟡 Шлюз працює, але інтернет недоступний.\n"
                    "💡 Можливі причини:\n"
                    "   • Проблема у провайдера (ISP)\n"
                    "   • Роутер не отримує WAN-сигнал\n"
                    "   • Налаштування DNS/маршрутизації\n"
                    "💊 Рекомендую: 'Скинути DNS' → 'Перевипустити IP'"
                )
            else:
                diagnosis = (
                    "🟢 Локально все ОК, але немає підключення до основних "
                    "серверів (1.1.1.1, 8.8.8.8).\n"
                    "💡 Можливо часткова деградація — перевірте через 1 хв."
                )

            # Оновлюємо UI у main thread через after()
            try:
                self.after(0, lambda d=diagnosis:
                    self._lbl_offline_diagnosis.configure(text=d))
            except Exception: pass
        except Exception as e:
            print(f"[Dashboard] diagnose offline error: {e}")

    def _get_gateway(self) -> str:
        """Отримує IP шлюзу через ipconfig."""
        try:
            import subprocess
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command",
                 "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
                 "Sort-Object RouteMetric | Select-Object -First 1).NextHop"],
                capture_output=True, text=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            gw = (r.stdout or "").strip()
            if gw and "." in gw:
                return gw
        except Exception: pass
        return ""

    def _execute_quick_fix(self, label: str, cmd: str):
        """Виконує quick-fix з offline-банера."""
        try:
            from tkinter import messagebox
            ok = messagebox.askyesno(
                "Підтвердження",
                f"Виконати дію?\n\n"
                f"📛 {label}\n"
                f"💻 Команда: {cmd}\n\n"
                f"⚠️ Ці команди потребують прав адміністратора.\n"
                f"Якщо NetGuardian запущений без них — нічого не станеться.")
            if not ok: return

            import subprocess
            print(f"[Dashboard] Виконую quick-fix: {label}")
            print(f"             $ {cmd}")
            r = subprocess.run(cmd, shell=True,
                                capture_output=True, text=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                messagebox.showinfo(
                    "Готово",
                    f"✅ {label} виконано успішно.\n\n"
                    f"Зараз перевірю чи запрацював інтернет...")
                # Скидаємо кеш і одразу перевіряємо
                try:
                    from hybrid_ai import reset_internet_cache
                    reset_internet_cache()
                except Exception: pass
                self.after(2000, self._check_offline_status)
            else:
                err = (r.stderr or r.stdout or "")[:300]
                messagebox.showerror(
                    "Помилка",
                    f"❌ {label} не виконано (код {r.returncode}).\n\n"
                    f"{err}\n\n"
                    f"Можливо потрібні права адміна. "
                    f"Запусти NetGuardian від імені адміністратора.")
        except Exception as e:
            from tkinter import messagebox
            messagebox.showerror("Помилка", f"❌ {e}")

    def _build_tapo_card(self, row: int):
        """Картка Tapo P110 — кнопка увімк/вимк + споживання."""
        tc = GlowCard(self, accent="#10b981")
        tc.grid(row=row, column=0, columnspan=2,
                padx=24, pady=(12, 12), sticky="ew")
        tc.grid_columnconfigure(1, weight=1)

        # Header
        hdr_f = ctk.CTkFrame(tc, fg_color="transparent")
        hdr_f.grid(row=0, column=0, padx=20, pady=(15, 5), sticky="w")
        ctk.CTkLabel(hdr_f, text="🔌  TAPO SMART PLUG (P110)",
                     font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color="#10b981").pack(side="left")

        # Кнопки керування
        btn_f = ctk.CTkFrame(tc, fg_color="transparent")
        btn_f.grid(row=0, column=1, padx=20, pady=(15, 5), sticky="e")

        self._btn_tapo_on = ctk.CTkButton(
            btn_f, text="✓ Увімкнути",
            command=lambda: self._tapo_action("on"),
            fg_color="#0d3a1a", hover_color="#155d2c",
            text_color="#10b981",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, width=110, corner_radius=8,
            border_width=1, border_color="#10b981")
        self._btn_tapo_on.pack(side="left", padx=4)

        self._btn_tapo_off = ctk.CTkButton(
            btn_f, text="✕ Вимкнути",
            command=lambda: self._tapo_action("off"),
            fg_color="#3a0d0d", hover_color="#5d1515",
            text_color="#ef4444",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, width=110, corner_radius=8,
            border_width=1, border_color="#ef4444")
        self._btn_tapo_off.pack(side="left", padx=4)

        self._btn_tapo_refresh = ctk.CTkButton(
            btn_f, text="🔄",
            command=lambda: self._tapo_refresh_status(),
            fg_color="transparent", hover_color="#1a2a3a",
            text_color=COLORS["text_dim"],
            font=ctk.CTkFont(family="Consolas", size=14),
            height=34, width=38, corner_radius=8,
            border_width=1, border_color=COLORS["border"])
        self._btn_tapo_refresh.pack(side="left", padx=4)

        # Метрики (4 колонки: статус, потужність, сьогодні, місяць)
        stats = ctk.CTkFrame(tc, fg_color="transparent")
        stats.grid(row=1, column=0, columnspan=2, padx=20, pady=(8, 18), sticky="ew")
        for i in range(4):
            stats.grid_columnconfigure(i, weight=1)

        def _stat_cell(col: int, label: str, value: str, color: str):
            cell = ctk.CTkFrame(
                stats, fg_color=COLORS["bg_secondary"],
                corner_radius=8, border_width=1, border_color=COLORS["border"])
            cell.grid(row=0, column=col, padx=4, sticky="ew")
            ctk.CTkLabel(cell, text=label,
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS["text_dim"]).pack(pady=(8, 2))
            lbl = ctk.CTkLabel(cell, text=value,
                font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
                text_color=color)
            lbl.pack(pady=(0, 8))
            return lbl

        self._lbl_tapo_status = _stat_cell(
            0, "СТАТУС", "—", COLORS["text_dim"])
        self._lbl_tapo_power = _stat_cell(
            1, "ПОТУЖНІСТЬ", "— Вт", "#10b981")
        self._lbl_tapo_today = _stat_cell(
            2, "СЬОГОДНІ", "— Вт·год", "#3b82f6")
        self._lbl_tapo_month = _stat_cell(
            3, "ЦЬОГО МІСЯЦЯ", "— кВт·год", "#a78bfa")

        # Hint якщо немає налаштувань
        self._lbl_tapo_hint = ctk.CTkLabel(
            tc, text="",
            font=ctk.CTkFont(family="Consolas", size=10, slant="italic"),
            text_color=COLORS["text_dim"],
            wraplength=900, justify="left", anchor="w")
        self._lbl_tapo_hint.grid(row=2, column=0, columnspan=2,
                                  padx=20, pady=(0, 12), sticky="w")

        # Запускаємо первинне оновлення статусу через 2с (щоб UI встиг прорендеритись)
        try: self.after(2000, self._tapo_init_and_refresh)
        except Exception: pass

    def _tapo_init_and_refresh(self):
        """Перше підключення — намагаємось дістати кеш або проявити hint."""
        try:
            from app.hardware.tapo import TapoPlug
            import os
            ip = os.environ.get("TAPO_IP", "").strip()
            email = os.environ.get("TAPO_EMAIL", "").strip()
            pwd = os.environ.get("TAPO_PASSWORD", "").strip()

            if not (ip and email and pwd):
                self._lbl_tapo_hint.configure(
                    text="ℹ️ Додай TAPO_IP, TAPO_EMAIL, TAPO_PASSWORD у .env щоб активувати")
                return

            # Зберігаємо instance для повторного використання
            if not hasattr(self, "_tapo_plug") or self._tapo_plug is None:
                self._tapo_plug = TapoPlug(ip=ip, email=email, password=pwd)

            self._tapo_refresh_status()
        except ImportError:
            self._lbl_tapo_hint.configure(
                text="⚠️ Не вдалось імпортувати модуль Tapo. "
                     "Виконай: pip install tapo")
        except Exception as e:
            self._lbl_tapo_hint.configure(
                text=f"⚠️ Tapo init error: {str(e)[:80]}")

    def _tapo_refresh_status(self):
        """Запит статусу у фоні."""
        if not hasattr(self, "_tapo_plug") or self._tapo_plug is None:
            self._tapo_init_and_refresh()
            return

        # Блокуємо кнопку refresh
        try: self._btn_tapo_refresh.configure(text="⏳", state="disabled")
        except Exception: pass

        # State-pattern: worker -> queue -> poller
        self._tapo_status_state = {"data": None, "error": None, "done": False}

        def _work():
            try:
                self._tapo_status_state["data"] = self._tapo_plug.get_status()
            except Exception as e:
                self._tapo_status_state["error"] = str(e)
            finally:
                self._tapo_status_state["done"] = True

        threading.Thread(target=_work, daemon=True).start()
        self._tapo_status_poll()

    def _tapo_status_poll(self):
        """Polling — кожні 200мс перевіряє чи готовий статус."""
        try:
            st = getattr(self, "_tapo_status_state", None)
            if not st or not st.get("done"):
                try: self.after(200, self._tapo_status_poll)
                except Exception: pass
                return

            # Розблоковуємо кнопку
            try: self._btn_tapo_refresh.configure(text="🔄", state="normal")
            except Exception: pass

            if st.get("error"):
                err = st["error"]
                # Показуємо повну помилку (wraplength)
                self._lbl_tapo_hint.configure(
                    text=f"❌ {err}",
                    text_color=COLORS["accent_red"])
                self._lbl_tapo_status.configure(
                    text="ERROR", text_color=COLORS["accent_red"])
                return

            data = st.get("data") or {}
            # tapo.py повертає 'online' (не 'connected')
            if not data.get("online"):
                self._lbl_tapo_status.configure(
                    text="OFFLINE", text_color=COLORS["accent_red"])
                err_msg = data.get("error", "Не вдалось підключитись")
                self._lbl_tapo_hint.configure(
                    text=f"⚠️ {err_msg}",
                    text_color=COLORS["text_dim"])
                return

            # Статус (is_on, не on)
            is_on = data.get("is_on", False)
            self._lbl_tapo_status.configure(
                text="✓ УВІМК." if is_on else "✕ ВИМК.",
                text_color="#10b981" if is_on else "#ef4444")

            # Потужність зараз (Вт) — поле 'watts'
            current_w = data.get("watts", 0) or 0
            self._lbl_tapo_power.configure(
                text=f"{current_w:.1f} Вт",
                text_color="#10b981" if current_w > 0 else COLORS["text_dim"])

            # Сьогодні (Вт·год) — поле 'total_wh' це ВСЬОГО, не сьогодні.
            # Беремо today_energy з info якщо є, або total_wh
            today_wh = data.get("today_energy", 0) or data.get("total_wh", 0) or 0
            if today_wh < 1000:
                today_str = f"{today_wh} Вт·г"
            else:
                today_str = f"{today_wh / 1000:.2f} кВт·г"
            self._lbl_tapo_today.configure(text=today_str)

            # Цього місяця (Вт·год → кВт·год)
            month_wh = data.get("month_energy", 0) or 0
            self._lbl_tapo_month.configure(text=f"{month_wh / 1000:.2f} кВт·г")

            # Hint з відомостями про пристрій
            dev_name = data.get("nickname") or data.get("model") or "Tapo P110"
            self._lbl_tapo_hint.configure(
                text=f"📡 {dev_name}  ·  оновлено щойно",
                text_color=COLORS["text_dim"])

            # Schedule наступне авто-оновлення через 30с
            try: self.after(30_000, self._tapo_refresh_status)
            except Exception: pass

        except Exception as e:
            print(f"[Dashboard] tapo_status_poll error: {e}")

    def _tapo_action(self, action: str):
        """Вмикає або вимикає Tapo. action='on' або 'off'."""
        if not hasattr(self, "_tapo_plug") or self._tapo_plug is None:
            self._tapo_init_and_refresh()
            return

        # Блокуємо кнопки
        try:
            self._btn_tapo_on.configure(state="disabled")
            self._btn_tapo_off.configure(state="disabled")
        except Exception: pass

        self._tapo_action_state = {"ok": None, "msg": "", "done": False}

        def _work():
            try:
                if action == "on":
                    ok, msg = self._tapo_plug.turn_on()
                else:
                    ok, msg = self._tapo_plug.turn_off()
                self._tapo_action_state["ok"] = ok
                self._tapo_action_state["msg"] = msg
            except Exception as e:
                self._tapo_action_state["ok"] = False
                self._tapo_action_state["msg"] = str(e)
            finally:
                self._tapo_action_state["done"] = True

        threading.Thread(target=_work, daemon=True).start()
        self._tapo_action_poll()

    def _tapo_action_poll(self):
        """Polling — після виконання дії розблоковує кнопки і робить refresh."""
        try:
            st = getattr(self, "_tapo_action_state", None)
            if not st or not st.get("done"):
                try: self.after(200, self._tapo_action_poll)
                except Exception: pass
                return

            try:
                self._btn_tapo_on.configure(state="normal")
                self._btn_tapo_off.configure(state="normal")
            except Exception: pass

            if not st.get("ok"):
                err = st.get("msg", "")[:80]
                self._lbl_tapo_hint.configure(
                    text=f"❌ Дія не вдалась: {err}",
                    text_color=COLORS["accent_red"])
                return

            # Refresh статус через 1с (Tapo потребує час щоб застосувати)
            try: self.after(1000, self._tapo_refresh_status)
            except Exception: pass
        except Exception as e:
            print(f"[Dashboard] tapo_action_poll error: {e}")

    def _isp_cell(self, parent, col, icon, title):
        f = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=10)
        f.grid(row=1, column=col, padx=10, pady=(0,12), sticky="ew")
        ctk.CTkLabel(f, text=f"{icon}  {title}",
                     font=ctk.CTkFont(family="Consolas",size=9),
                     text_color=COLORS["text_secondary"]).pack(pady=(10,0))
        lbl = ctk.CTkLabel(f, text="...",
                           font=ctk.CTkFont(family="Consolas",size=18,weight="bold"),
                           text_color=COLORS["accent_green"])
        lbl.pack(pady=(2,10))
        return lbl

    def _wifi_cell(self, parent, col, icon, title, color):
        f = ctk.CTkFrame(parent, fg_color=COLORS["bg_secondary"], corner_radius=10)
        f.grid(row=1, column=col, padx=10, pady=(0,8), sticky="ew")
        ctk.CTkLabel(f, text=f"{icon}  {title}",
                     font=ctk.CTkFont(family="Consolas",size=9),
                     text_color=COLORS["text_secondary"]).pack(pady=(10,0))
        lbl = ctk.CTkLabel(f, text="--",
                           font=ctk.CTkFont(family="Consolas",size=22,weight="bold"),
                           text_color=color)
        lbl.pack(pady=(2,10))
        return lbl

    def _stat_card(self, parent, col, icon, title, color):
        c = GlowCard(parent, accent=color)
        c.grid(row=0, column=col, padx=6, sticky="ew")
        inner = ctk.CTkFrame(c, fg_color="transparent")
        inner.pack(padx=20, pady=15, fill="x")
        ctk.CTkLabel(inner, text=f"{icon}  {title}",
                     font=ctk.CTkFont(family="Consolas",size=10),
                     text_color=COLORS["text_secondary"]).pack(anchor="w")
        lbl = ctk.CTkLabel(inner, text="—",
                           font=ctk.CTkFont(family="Consolas",size=22,weight="bold"),
                           text_color=color)
        lbl.pack(anchor="w", pady=(5,0))
        return lbl


    # ──────────────────────────────────────────────────────
    # SPEEDTEST
    # ──────────────────────────────────────────────────────
    def _on_speedtest(self):
        """Хендлер кнопки '▶ ЗАПУСТИТИ ТЕСТ' — викликає _run_speedtest()."""
        if getattr(self, "_speedtest_running", False):
            return
        self._run_speedtest()

    def _run_speedtest(self, extra_callback=None):
        """
        Запускає speedtest у фоновому потоці.
        extra_callback(dl, ul) — опціональний для бота, викликається з результатом.
        FIX: якщо тест уже йде — не робимо новий, але реєструємо callback
        щоб бот отримав результат поточного тесту замість отримання 0.0.
        """
        if getattr(self, "_speedtest_running", False):
            # Вже йде — зберігаємо callback щоб викликати коли завершиться
            if extra_callback:
                self._pending_speedtest_callbacks = getattr(
                    self, "_pending_speedtest_callbacks", [])
                self._pending_speedtest_callbacks.append(extra_callback)
                print(f"[Dashboard] speedtest_for_bot: тест вже йде, "
                      f"callback зареєстровано (всього: "
                      f"{len(self._pending_speedtest_callbacks)})")
            return
        self.update_speedtest_ui(is_running=True, down_text="...",
                                 up_text="...", btn_text="⏳  ТЕСТУЄМО...")
        # Запускаємо анімацію рамки карточки speedtest (якщо є)
        try:
            self._spd_card.start_glow_cycle(
                COLORS["accent_cyan"], COLORS["accent_purple"])
        except Exception: pass

        self._pbar.start() if hasattr(self, "_pbar") else None

        def on_progress(direction, mbps, samples):
            # Інформаційна подія pre-flight (пошук сервера)
            if direction == "dl_info":
                info_text = samples if isinstance(samples, str) else ""
                def _u_info():
                    self.lbl_dl_live.configure(
                        text=info_text[:45],
                        text_color=COLORS.get("accent_cyan", "#00e5ff"))
                try: self.after(0, _u_info)
                except RuntimeError: pass
                return

            # Інформаційна подія UL (напр. retry)
            if direction == "ul_info":
                info_text = samples if isinstance(samples, str) else ""
                def _u_ul_info():
                    self.lbl_ul_live.configure(
                        text=info_text[:45],
                        text_color=COLORS.get("accent_cyan", "#00e5ff"))
                try: self.after(0, _u_ul_info)
                except RuntimeError: pass
                return

            # Помилка DL (жоден сервер не відповідає)
            if direction == "dl_error":
                err_text = samples if isinstance(samples, str) else "DL недоступний"
                def _u_err():
                    self.lbl_dl_live.configure(text=err_text[:45], text_color="#ff6b6b")
                try: self.after(0, _u_err)
                except RuntimeError: pass
                return

            avg = sum(samples)/len(samples) if samples else 0.0
            def _u():
                if direction == "dl":
                    self.lbl_dl.configure(text=f"{mbps:.1f}")
                    self.lbl_dl_live.configure(
                        text=f"live: {mbps:.1f}  avg: {avg:.1f}",
                        text_color=COLORS.get("text_dim", "gray"))
                else:
                    self.lbl_ul.configure(text=f"{mbps:.1f}")
                    self.lbl_ul_live.configure(
                        text=f"live: {mbps:.1f}  avg: {avg:.1f}")
            try: self.after(0, _u)
            except RuntimeError: pass

        def on_done(dl, ul):
            def _u():
                try: self._pbar.stop()
                except Exception: pass
                try:
                    self._spd_card.stop_glow_cycle()
                    self._spd_card.configure(border_color=COLORS["accent_green"])
                except Exception: pass
                self.update_speedtest_ui(is_running=False,
                                         down_text=f"{dl:.1f}",
                                         up_text=f"{ul:.1f}",
                                         btn_text="▶  ЗАПУСТИТИ ТЕСТ")
                try:
                    self.lbl_dl_live.configure(
                        text=f"avg: {dl:.1f} Mbps",
                        text_color=COLORS.get("accent_blue", "#2979ff"))
                    self.lbl_ul_live.configure(
                        text=f"avg: {ul:.1f} Mbps",
                        text_color=COLORS.get("accent_purple", "#d500f9"))
                except Exception: pass
                # Оновлюємо глобальний snapshot — /status та /mystats підхоплять
                _DASHBOARD_STATE["dl_mbps"] = dl
                _DASHBOARD_STATE["ul_mbps"] = ul
                # Timestamp щоб бот знав чи результат свіжий
                _DASHBOARD_STATE["speedtest_ts"] = time.time()
            try: self.after(0, _u)
            except RuntimeError: pass
            if extra_callback:
                try: extra_callback(dl, ul)
                except Exception: pass

            # Викликаємо всі pending callbacks (якщо бот зареєстрував їх під час роботи)
            pending = getattr(self, "_pending_speedtest_callbacks", [])
            for cb in pending:
                try: cb(dl, ul)
                except Exception as e:
                    print(f"[Dashboard] pending speedtest callback error: {e}")
            self._pending_speedtest_callbacks = []

        threading.Thread(
            target=_speedtest_worker,
            args=(on_progress, on_done, self.SPEEDTEST_DURATION),
            daemon=True).start()


    # ──────────────────────────────────────────────────────
    # TRAFFIC MONITOR
    # ──────────────────────────────────────────────────────
    def _start_traffic(self):
        threading.Thread(target=self._trf_loop, daemon=True).start()

    def _trf_loop(self):
        INT = 2.0
        while True:
            snap = {}; deltas = []
            nb = psutil.net_io_counters()
            time.sleep(INT)
            na = psutil.net_io_counters()
            dl = max(0, na.bytes_recv-nb.bytes_recv)
            ul = max(0, na.bytes_sent-nb.bytes_sent)
            try:
                self.after(0, lambda d=dl/INT*8/1e6, u=ul/INT*8/1e6:
                           self.chart.push(d, u))
            except RuntimeError: pass
            for proc in psutil.process_iter(["pid","name"]):
                try:
                    io = proc.io_counters(); pid = proc.pid
                    r,s = io.read_bytes, io.write_bytes
                    snap[pid] = (r,s)
                    if pid in self._traffic_prev:
                        pr,ps = self._traffic_prev[pid]
                        dr = max(0,r-pr); ds = max(0,s-ps)
                        rm = dr*8/(INT*1e6); sm = ds*8/(INT*1e6)
                        mb = (r+s)//(1024*1024)
                        if rm>0 or sm>0:
                            deltas.append((rm,sm,proc.info["name"] or "?",pid,mb))
                except (psutil.NoSuchProcess, psutil.AccessDenied): pass
            self._traffic_prev = snap
            top = sorted(deltas, key=lambda x:x[0]+x[1], reverse=True)[:5]
            try: self.after(0, lambda t=top: self._update_trf(t))
            except RuntimeError: pass

    def _update_trf(self, top):
        for ri, cells in enumerate(self._trf_rows):
            if ri < len(top):
                rm,sm,name,pid,mb = top[ri]
                self._row_pids[ri]  = pid
                self._row_names[ri] = name
                total = rm+sm
                col   = COLORS["accent_red"] if total>5 else COLORS["text_primary"]
                icol  = ICON_PALETTE[hash(name)%len(ICON_PALETTE)]
                try: cells[0].configure(text="●", text_color=icol)
                except Exception: pass
                cells[1].configure(text=name[:22],   text_color=col)
                cells[2].configure(text=str(pid),    text_color=col)
                cells[3].configure(text=f"{rm:.2f}", text_color=COLORS["accent_blue"])
                cells[4].configure(text=f"{sm:.2f}", text_color=COLORS["accent_purple"])
                cells[5].configure(text=f"{mb}",     text_color=COLORS["text_secondary"])
            else:
                self._row_pids[ri]  = 0
                self._row_names[ri] = ""
                try: cells[0].configure(text="●", text_color=COLORS["text_dim"])
                except Exception: pass
                for c in cells[1:]:
                    c.configure(text="—", text_color=COLORS["text_dim"])

    def _proc_menu(self, event, idx):
        pid  = self._row_pids[idx]
        name = self._row_names[idx]
        if not pid: return
        _ProcMenu(self, pid, name).popup(event.x_root, event.y_root)

    # ──────────────────────────────────────────────────────
    # ISP
    # ──────────────────────────────────────────────────────
    def _fetch_isp(self):
        def _w():
            print("[Dashboard] _fetch_isp: запуск...")
            d = _fetch_isp_info()
            print(f"[Dashboard] _fetch_isp: отримано {len(d)} полів: "
                  f"{list(d.keys())[:5] if d else 'EMPTY'}")

            # ВАЖЛИВО: пишемо у global state ВЖЕ ТУТ — у потоці.
            # Поллер _sync_ui_from_state() підхопить це з main thread.
            # Не залежить від self.after() який падає у Python 3.14.
            if d:
                cc = d.get("countryCode", "??")
                _DASHBOARD_STATE["ext_ip"]  = d.get("query", "—")
                _DASHBOARD_STATE["isp"]     = d.get("isp", "—")
                _DASHBOARD_STATE["city"]    = d.get("city", "—")
                _DASHBOARD_STATE["country"] = d.get("country", cc)
                print(f"[Dashboard] ✅ State оновлено: "
                      f"country={d.get('country','?')}, "
                      f"isp={d.get('isp','?')[:20]}, "
                      f"ip={d.get('query','?')}")
            else:
                print("[Dashboard] ❌ ISP fetch failed — буде ретрай через 30с")
                # Авторетрай через 30 сек у новому потоці
                import time
                def _retry():
                    time.sleep(30)
                    self._fetch_isp()
                threading.Thread(target=_retry, daemon=True).start()

            # Спроба оновити UI напряму (запасна, як раніше)
            def _u():
                if d:
                    cc = d.get("countryCode", "??")
                    self._lbl_flag.configure(text=d.get("country", cc))
                    self._lbl_isp.configure(text=str(d.get("isp", "н/д"))[:22])
                    self._lbl_city.configure(text=d.get("city", "н/д"))
                    self._lbl_extip.configure(text=d.get("query", "н/д"))
                    if cc == "UA":
                        self._lbl_vpn.configure(
                            text="✅ IP відповідає Україні — VPN не активний",
                            text_color=COLORS["accent_green"])
                    else:
                        self._lbl_vpn.configure(
                            text=f"🔒 Трафік через {cc} — можливо VPN активний",
                            text_color=COLORS["accent_yellow"])
                else:
                    for l in [self._lbl_flag, self._lbl_isp,
                              self._lbl_city, self._lbl_extip]:
                        l.configure(text="помилка", text_color=COLORS["accent_red"])
                    self._lbl_vpn.configure(
                        text="⚠️ Не вдалось отримати дані ISP — ретрай через 30с",
                        text_color=COLORS["accent_red"])
            try: self.after(0, _u)
            except (RuntimeError, tk.TclError) as e:
                print(f"[Dashboard] _fetch_isp after() skip: {e}")
        threading.Thread(target=_w, daemon=True).start()

    # ──────────────────────────────────────────────────────
    # UPTIME
    # ──────────────────────────────────────────────────────
    def _tick_uptime(self):
        if not self._uptime_running: return
        el = int(time.time()-self._session_start)
        _DASHBOARD_STATE["uptime_sec"] = el
        h,r = divmod(el,3600); m,s = divmod(r,60)
        try:
            self.lbl_uptime.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
            self.after(1000, self._tick_uptime)
        except Exception: pass

    # ──────────────────────────────────────────────────────
    # WIDGET TOGGLE
    # ──────────────────────────────────────────────────────
    def _on_widget_toggle(self):
        if self.toggle_widget_callback:
            self.toggle_widget_callback()

    # ──────────────────────────────────────────────────────
    # BACKGROUND INIT
    # ──────────────────────────────────────────────────────
    def _start_bg(self):
        self._start_traffic()
        self._tick_uptime()
        self._fetch_isp()
        threading.Thread(target=self._auto_stats,        daemon=True).start()
        threading.Thread(target=self._ping_history_loop, daemon=True).start()
        threading.Thread(target=self._wifi_loop,         daemon=True).start()
        # Поллер який читає _DASHBOARD_STATE в MAIN THREAD кожну 1с
        # і оновлює UI. Це обхід проблеми з self.after() з потоків у Python 3.14.
        self._sync_ui_from_state()

    def _sync_ui_from_state(self):
        """Викликається з MAIN THREAD кожну 1с. Читає _DASHBOARD_STATE
        і синхронізує UI labels. Це гарантує що UI оновлюється навіть
        якщо self.after() з потоків падає (Python 3.14)."""
        try:
            # 0. PING HISTORY — обробляємо pending список
            pending = _DASHBOARD_STATE.get("ping_pending", [])
            if pending and hasattr(self, "ping_chart"):
                # Перекладаємо всі pending значення у графік
                while pending:
                    val = pending.pop(0)
                    try:
                        self.ping_chart.push(val)
                    except Exception as e:
                        print(f"[Dashboard] ping_chart.push error: {e}")
                        break

            # 0.05. MIN / AVG / MAX лейбли — обчислюємо з графічної історії
            if hasattr(self, "ping_chart") and hasattr(self.ping_chart, "_pings"):
                valid = [v for v in self.ping_chart._pings if v is not None]
                if valid:
                    mn = min(valid); mx = max(valid)
                    av = int(sum(valid) / len(valid))
                    try:
                        if hasattr(self, "_lbl_ph_min"):
                            self._lbl_ph_min.configure(text=f"min: {mn}")
                        if hasattr(self, "_lbl_ph_avg"):
                            self._lbl_ph_avg.configure(text=f"avg: {av}")
                        if hasattr(self, "_lbl_ph_max"):
                            self._lbl_ph_max.configure(text=f"max: {mx}")
                    except Exception: pass

            # 0.1. PING LABEL — головний "18 ms" індикатор
            ping_ms = _DASHBOARD_STATE.get("ping_ms")
            ping_status = _DASHBOARD_STATE.get("ping_status", "")
            ping_color = _DASHBOARD_STATE.get("ping_color")
            if ping_ms is not None and ping_color:
                try:
                    self.lbl_ping.configure(
                        text=f"{ping_ms} ms" if ping_ms >= 0 else "OFFLINE",
                        text_color=ping_color)
                    self.lbl_status.configure(text=ping_status, text_color=ping_color)
                    if hasattr(self, "status_dot"):
                        self.status_dot.start_pulse(ping_color)
                except Exception: pass
            elif ping_status == "timeout" and ping_color:
                try:
                    self.lbl_ping.configure(text="OFFLINE", text_color=ping_color)
                    self.lbl_status.configure(text="timeout", text_color=ping_color)
                except Exception: pass

            # 1. Шлюз / Local IP
            gw = _DASHBOARD_STATE.get("gateway", "—")
            ip = _DASHBOARD_STATE.get("local_ip", "—")
            if gw and gw != "—" and gw != "н/д":
                self.lbl_gw.configure(text=gw)
            if ip and ip != "—" and ip != "н/д":
                self.lbl_lip.configure(text=ip)

            # 2. ISP / Country / City / External IP
            country = _DASHBOARD_STATE.get("country", "—")
            isp     = _DASHBOARD_STATE.get("isp", "—")
            city    = _DASHBOARD_STATE.get("city", "—")
            ext_ip  = _DASHBOARD_STATE.get("ext_ip", "—")

            if country and country != "—" and country != "?":
                self._lbl_flag.configure(text=country)
            if isp and isp != "—" and isp != "?":
                self._lbl_isp.configure(text=str(isp)[:22])
            if city and city != "—" and city != "?":
                self._lbl_city.configure(text=city)
            if ext_ip and ext_ip != "—" and ext_ip != "?":
                self._lbl_extip.configure(text=ext_ip)

            # 3. Wi-Fi — обережно з None
            ssid = _DASHBOARD_STATE.get("wifi_ssid")
            dbm  = _DASHBOARD_STATE.get("wifi_dbm")
            pct  = _DASHBOARD_STATE.get("wifi_pct")
            bars = _DASHBOARD_STATE.get("wifi_bars")

            # SSID — оновлюємо тільки якщо є непорожнє значення
            if ssid and ssid not in ("—", "N/A (non-Windows)", ""):
                try: self._lbl_wifi_ssid.configure(text=ssid)
                except Exception: pass
                # dbm — тільки якщо число (не None і не 0 для сигналу)
                if dbm is not None and isinstance(dbm, (int, float)):
                    try: self._lbl_wifi_dbm.configure(text=f"{int(dbm)} dBm")
                    except Exception: pass
                if pct is not None and isinstance(pct, (int, float)):
                    try: self._lbl_wifi_pct.configure(text=f"{int(pct)} %")
                    except Exception: pass
                if bars is not None and isinstance(bars, int) and 0 <= bars <= 5:
                    try: self._lbl_wifi_bars.configure(
                        text="▮" * bars + "▯" * (5 - bars))
                    except Exception: pass
        except Exception as e:
            print(f"[Dashboard] _sync_ui_from_state error: {e}")
        # Перепланування — у main thread, безпечно
        try:
            self.after(1000, self._sync_ui_from_state)
        except Exception: pass

    def _auto_stats(self):
        """Періодично оновлює gateway/local IP. Якщо after() падає —
        не зупиняємось, а повторюємо через 30 секунд."""
        import time
        max_tries = 0
        while True:
            try:
                gw = _get_gateway_ip()
                ip = _get_local_ip()
                print(f"[Dashboard] _auto_stats: gw={gw}, local_ip={ip}")

                # ВАЖЛИВО: пишемо у global state — _sync_ui_from_state
                # потім підхопить це з main thread. НЕ ЗАЛЕЖИТЬ від after()
                if gw and gw != "н/д":
                    _DASHBOARD_STATE["gateway"] = gw
                if ip and ip != "н/д":
                    _DASHBOARD_STATE["local_ip"] = ip

                # Спроба викликати set_stats (запасна, як було раніше)
                try:
                    self.after(0, lambda g=gw, i=ip: self.set_stats(g, i, "00:00:00"))
                except (RuntimeError, tk.TclError) as e:
                    print(f"[Dashboard] _auto_stats after() skip: {e}")

                # Якщо отримали валідні значення — оновлюємо рідше
                if gw != "н/д" and ip != "н/д":
                    time.sleep(60)
                else:
                    time.sleep(10)
                max_tries += 1
                if max_tries > 60:
                    break
            except Exception as e:
                print(f"[Dashboard] _auto_stats error: {e}")
                time.sleep(30)

    # ──────────────────────────────────────────────────────
    # WI-FI MONITOR
    # ──────────────────────────────────────────────────────
    def _wifi_loop(self):
        """Кожні 10с зчитує Wi-Fi інфо через netsh (Windows) і оновлює UI."""
        while True:
            try:
                data = self._read_wifi_info()
                if data:
                    # ВАЖЛИВО: пишемо у state ОДРАЗУ — поллер підхопить
                    ssid = data.get("ssid")
                    if ssid and ssid not in ("—", "N/A (non-Windows)", ""):
                        pct = data.get("pct") or 0
                        # bars: 0..5 за відсотками сигналу
                        bars = min(5, max(0, int((pct + 19) / 20)))
                        _DASHBOARD_STATE["wifi_ssid"]  = ssid
                        _DASHBOARD_STATE["wifi_dbm"]   = data.get("dbm") or 0
                        _DASHBOARD_STATE["wifi_pct"]   = pct
                        _DASHBOARD_STATE["wifi_bars"]  = bars
                        print(f"[Dashboard] _wifi_loop: ssid={ssid}, "
                              f"dbm={data.get('dbm')}, pct={pct}, bars={bars}")
                    # Спроба оновити UI напряму
                    try: self.after(0, lambda d=data: self._update_wifi_ui(d))
                    except (RuntimeError, tk.TclError) as e:
                        print(f"[Dashboard] _wifi_loop after() skip: {e}")
            except Exception as e:
                print(f"[WiFi] loop error: {e}")
            time.sleep(10)

    def _read_wifi_info(self) -> dict:
        """Зчитує Wi-Fi-інформацію (SSID, сигнал, канал).
        Windows: `netsh wlan show interfaces`.
        Linux/macOS: graceful fallback на None."""
        import platform
        import subprocess
        if platform.system() != "Windows":
            return {"ssid":"N/A (non-Windows)","dbm":None,"pct":None,"band":None}

        # Пробуємо UA → EN encoding варіанти
        output = ""
        for enc in ("cp866", "cp1251", "utf-8"):
            try:
                r = subprocess.run(
                    ["netsh","wlan","show","interfaces"],
                    capture_output=True, timeout=5,
                    creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
                output = r.stdout.decode(enc, errors="replace")
                if output and ("SSID" in output or "ССІД" in output or "ИД сети" in output):
                    break
            except Exception: continue
        if not output:
            return {}

        ssid = "—"; sig_pct = None; channel = None; band = None
        for raw in output.splitlines():
            line = raw.strip()
            low  = line.lower()

            # SSID (не BSSID!)
            if (low.startswith("ssid") and not low.startswith("bssid")) \
               or low.startswith("ссід") or low.startswith("ид sсіті") \
               or low.startswith("имя") or ("sсід" in low and ":" in low):
                val = line.split(":", 1)[1].strip() if ":" in line else ""
                if val and val not in ("", "N/A"):
                    ssid = val
            # Signal / сигнал (у % на Windows)
            elif ("signal" in low or "сигнал" in low) and "%" in line:
                m = re.search(r"(\d+)\s*%", line)
                if m: sig_pct = int(m.group(1))
            # Channel / канал
            elif "channel" in low or "канал" in low:
                m = re.search(r":\s*(\d+)", line)
                if m:
                    channel = int(m.group(1))
                    band = "5 GHz" if channel >= 36 else "2.4 GHz"

        # Переводимо відсотки в dBm (приблизно: 100% = -50, 0% = -100)
        dbm = None
        if sig_pct is not None:
            dbm = -100 + int(sig_pct / 2)

        return {
            "ssid":    ssid,
            "pct":     sig_pct,
            "dbm":     dbm,
            "channel": channel,
            "band":    band,
        }

    def _update_wifi_ui(self, data: dict):
        """Приймає {ssid, dbm, pct, band, channel} і оновлює UI-рядок."""
        try:
            ssid = data.get("ssid", "—")
            if ssid and ssid != "—" and ssid != "N/A":
                self._lbl_wifi_ssid.configure(
                    text=ssid[:18],
                    text_color=COLORS.get("accent_blue", "#2979ff"))
            else:
                self._lbl_wifi_ssid.configure(text="—", text_color=COLORS["text_dim"])

            # Сигнал (dBm)
            dbm = data.get("dbm")
            if isinstance(dbm, (int, float)):
                if dbm >= -60:   sig_col = COLORS.get("accent_green","#00ff88")
                elif dbm >= -75: sig_col = COLORS.get("accent_yellow","#ffd700")
                else:            sig_col = COLORS.get("accent_red","#ff4444")
                self._lbl_wifi_dbm.configure(text=f"{dbm} dBm", text_color=sig_col)
            else:
                self._lbl_wifi_dbm.configure(text="—", text_color=COLORS["text_dim"])

            # Якість %
            pct = data.get("pct")
            if isinstance(pct, (int, float)):
                if pct >= 70:   pct_col = COLORS.get("accent_green","#00ff88")
                elif pct >= 40: pct_col = COLORS.get("accent_yellow","#ffd700")
                else:           pct_col = COLORS.get("accent_red","#ff4444")
                self._lbl_wifi_pct.configure(text=f"{pct}%", text_color=pct_col)
            else:
                self._lbl_wifi_pct.configure(text="—", text_color=COLORS["text_dim"])

            # Діапазон (2.4/5 GHz) — у UI це "_lbl_wifi_bars"
            band = data.get("band")
            if band:
                band_col = (COLORS.get("accent_purple","#d500f9") if band == "5 GHz"
                            else COLORS.get("accent_yellow","#ffd700"))
                self._lbl_wifi_bars.configure(text=band, text_color=band_col)
            else:
                self._lbl_wifi_bars.configure(text="—", text_color=COLORS["text_dim"])

            # Прибираємо індикатор завантаження
            if hasattr(self, "_lbl_wifi_status"):
                try: self._lbl_wifi_status.configure(text="")
                except Exception: pass

            # Оновлюємо глобальний snapshot
            _DASHBOARD_STATE["wifi_ssid"] = ssid
            _DASHBOARD_STATE["wifi_dbm"]  = dbm
            _DASHBOARD_STATE["wifi_pct"]  = pct
            _DASHBOARD_STATE["wifi_band"] = band
        except Exception as e:
            print(f"[WiFi] UI error: {e}")

    # ──────────────────────────────────────────────────────
    # PING HISTORY
    # ──────────────────────────────────────────────────────
    def _ping_history_loop(self):
        """Кожні 5с пінгує 8.8.8.8 і додає сигнал у PingHistoryChart
        (відповідно до '5s INTERVAL' на графіку).
        FIX: Python 3.14 — не виходимо з циклу при RuntimeError, лише
        пишемо у _DASHBOARD_STATE['ping_pending'] і поллер це підхопить."""
        import platform
        import subprocess
        target = "8.8.8.8"
        # Ініціалізуємо buffer для pending ping значень
        if "ping_pending" not in _DASHBOARD_STATE:
            _DASHBOARD_STATE["ping_pending"] = []

        while True:
            ms = None   # None = timeout (червоний X у графіку)
            try:
                if platform.system() == "Windows":
                    r = subprocess.run(
                        ["ping","-n","1","-w","1500", target],
                        capture_output=True, text=True, timeout=4, errors="replace",
                        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
                    m = re.search(r"(?:time|час|время)[=<]\s*(\d+)\s*(?:ms|мс)",
                                  r.stdout, re.IGNORECASE)
                    if not m:
                        m = re.search(r"=\s*(\d+)\s*ms", r.stdout, re.IGNORECASE)
                    if m: ms = int(m.group(1))
                else:
                    r = subprocess.run(
                        ["ping","-c","1","-W","2", target],
                        capture_output=True, text=True, timeout=4)
                    m = re.search(r"time[=<](\d+\.?\d*)", r.stdout)
                    if m: ms = int(float(m.group(1)))
            except Exception as e:
                print(f"[Dashboard] ping error: {e}")
                pass

            print(f"[Dashboard] _ping_history_loop: ms={ms}")

            # ВАЖЛИВО: пишемо у pending список — поллер це підхопить
            try:
                _DASHBOARD_STATE["ping_pending"].append(ms)
                # Тримаємо макс 200 (на випадок якщо поллер далеко відстав)
                if len(_DASHBOARD_STATE["ping_pending"]) > 200:
                    _DASHBOARD_STATE["ping_pending"] = \
                        _DASHBOARD_STATE["ping_pending"][-200:]
            except Exception as e:
                print(f"[Dashboard] ping_pending append error: {e}")

            # Оновлюємо лейбл пінгу — пишемо у state
            if ms is not None and ms >= 0:
                status = "відмінно" if ms < 30 else "добре" if ms < 80 else "повільно"
                col    = (COLORS.get("accent_green","#00ff88") if ms < 30 else
                          COLORS.get("accent_yellow","#ffd700") if ms < 80 else
                          COLORS.get("accent_red","#ff4444"))
                _DASHBOARD_STATE["ping_ms"]     = ms
                _DASHBOARD_STATE["ping_status"] = status
                _DASHBOARD_STATE["ping_color"]  = col
                # Спроба прямого оновлення — як запас
                try: self.after(0, lambda m=ms, s=status, c=col:
                                self.update_ping(m, s, c))
                except (RuntimeError, tk.TclError) as e:
                    print(f"[Dashboard] ping update_ping skip: {e}")
            else:
                _DASHBOARD_STATE["ping_ms"]     = None
                _DASHBOARD_STATE["ping_status"] = "timeout"
                _DASHBOARD_STATE["ping_color"]  = COLORS.get("accent_red","#ff4444")
                try: self.after(0, lambda: self.update_ping(
                    -1, "timeout", COLORS.get("accent_red","#ff4444")))
                except (RuntimeError, tk.TclError) as e:
                    print(f"[Dashboard] ping update_ping skip: {e}")

            time.sleep(5.0)   # 5-секундний інтервал

    def update_ping(self, ms: int, status_text: str, color: str):
        _DASHBOARD_STATE["ping_ms"]     = ms if ms >= 0 else None
        _DASHBOARD_STATE["ping_status"] = status_text
        try:
            self.lbl_ping.configure(
                text=f"{ms} ms" if ms>=0 else "OFFLINE",
                text_color=color)
            self.lbl_status.configure(text=status_text, text_color=color)
            self.status_dot.start_pulse(color)
        except Exception: pass

    def set_stats(self, gateway: str, local_ip: str, uptime: str):
        _DASHBOARD_STATE["gateway"]  = gateway
        _DASHBOARD_STATE["local_ip"] = local_ip
        try:
            self.lbl_gw.configure(text=gateway)
            self.lbl_lip.configure(text=local_ip)
            if uptime != "00:00:00":
                self.lbl_uptime.configure(text=uptime)
        except Exception: pass

    def update_speedtest_ui(self, is_running: bool,
                            down_text="--", up_text="--",
                            btn_text="▶  ЗАПУСТИТИ ТЕСТ"):
        try:
            self.lbl_dl.configure(text=down_text)
            self.lbl_ul.configure(text=up_text)
            self.btn_spd.configure(
                text=btn_text,
                state="disabled" if is_running else "normal")
            self._speedtest_running = is_running
        except Exception: pass

    def set_widget_button_state(self, is_active: bool):
        try:
            if is_active:
                self.btn_widget.configure(
                    text="Вимкнути",
                    fg_color=COLORS["accent_red"],
                    text_color="white",
                    border_color=COLORS["accent_red"])
            else:
                self.btn_widget.configure(
                    text="Увімкнути",
                    fg_color="transparent",
                    text_color=COLORS["accent_purple"],
                    border_color=COLORS["accent_purple"])
        except Exception: pass

    def destroy(self):
        self._uptime_running = False
        try: self.chart.destroy()
        except Exception: pass
        try: self.ping_chart.destroy()
        except Exception: pass
        try: self._pbar.stop()
        except Exception: pass
        try: super().destroy()
        except Exception: pass