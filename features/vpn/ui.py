"""
gui/pages/vpn_ui.py
NetGuardian AI — VPN Manager & Secure Tunneling UI
Cyberpunk Dark Theme · customtkinter MVC
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
from typing import Optional
import threading
import time
import os

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.vpn.engine import (
    VpnManagerEngine, VpnProfile, VpnProtocol,
    ConnectionState, is_admin
)


class _NullBtn:
    """PR #23: Fallback для btn_auto_vpn якого може не бути."""
    def configure(self, **kwargs): pass


# ─────────────────────────────────────────────────────────────────────────────
#  MINI WORLD-MAP CANVAS
# ─────────────────────────────────────────────────────────────────────────────

class WorldMapCanvas(ctk.CTkCanvas):
    """
    World map з реальними координатами (lat/lng) — стиль як у DottedMap.
    Показує:
      - Точкову карту світу (як World Map з React-промта)
      - Точку юзера (Україна)
      - Точку VPN-сервера
      - Анімовану дугу між ними
    """

    # Координати країн (lat, lng) — реальні центри
    COUNTRY_COORDS = {
        "US": (39.0, -98.0),  "CA": (56.1, -106.3), "MX": (23.6, -102.5),
        "GB": (54.3, -2.4),   "DE": (51.2, 10.4),   "NL": (52.3, 5.3),
        "FR": (46.6, 1.8),    "CH": (46.8, 8.2),    "SE": (60.1, 18.6),
        "NO": (60.5, 8.5),    "FI": (61.9, 25.7),   "DK": (56.3, 9.5),
        "IS": (64.9, -19.0),  "RU": (61.5, 105.3),  "UA": (48.4, 31.2),
        "PL": (51.9, 19.1),   "CZ": (49.8, 15.5),   "SK": (48.7, 19.7),
        "AT": (47.5, 14.5),   "HU": (47.2, 19.5),   "RO": (45.9, 24.9),
        "BG": (42.7, 25.5),   "GR": (39.1, 21.8),   "IT": (41.9, 12.6),
        "ES": (40.5, -3.7),   "PT": (39.4, -8.2),   "IE": (53.1, -7.7),
        "BE": (50.5, 4.5),    "LU": (49.8, 6.1),    "BY": (53.7, 27.9),
        "JP": (36.2, 138.3),  "KR": (35.9, 127.8),  "CN": (35.9, 104.2),
        "SG": (1.4, 103.8),   "IN": (20.6, 78.9),   "HK": (22.3, 114.2),
        "TH": (15.9, 100.9),  "VN": (14.1, 108.3),  "ID": (-0.8, 113.9),
        "AU": (-25.3, 133.8), "NZ": (-40.9, 174.9),
        "BR": (-14.2, -51.9), "AR": (-38.4, -63.6), "CL": (-35.7, -71.5),
        "ZA": (-30.6, 22.9),  "NG": (9.1, 8.7),     "EG": (26.8, 30.8),
        "TR": (38.9, 35.2),   "IL": (31.0, 34.9),   "SA": (23.9, 45.1),
    }

    USER_COUNTRY = "UA"   # Юзер у Києві

    def __init__(self, parent, **kwargs):
        super().__init__(
            parent,
            bg="#0a0a14",
            highlightthickness=0,
            **kwargs
        )
        self._server_country: str = ""
        self._anim_phase: float = 0.0
        self._anim_running = False
        self.bind("<Configure>", lambda e: self._draw())
        self.after(50, self._draw)

    @staticmethod
    def _project(lat: float, lng: float, w: int, h: int) -> tuple:
        """Mercator-lite projection lat/lng → x/y."""
        import math
        x = (lng + 180) * (w / 360)
        if lat >= 50:
            t = (72 - lat) / 22.0
            y = t * (h * 0.22)
        elif lat >= -50:
            t = (50 - lat) / 100.0
            y = h * 0.22 + t * (h * 0.60)
        else:
            t = (-50 - lat) / 6.0
            y = h * 0.82 + t * (h * 0.18)
        return int(x), int(y)

    @classmethod
    def _load_world_dots(cls) -> list:
        """Lazy-loads точки континентів."""
        if hasattr(cls, "_WORLD_DOTS_CACHE"):
            return cls._WORLD_DOTS_CACHE
        try:
            from features.vpn.world_dots import WORLD_DOTS
            cls._WORLD_DOTS_CACHE = WORLD_DOTS
            print(f"[WorldMap] Завантажено {len(WORLD_DOTS)} точок континентів")
        except Exception as e:
            print(f"[WorldMap] world_dots.py не знайдено: {e}")
            cls._WORLD_DOTS_CACHE = []
        return cls._WORLD_DOTS_CACHE

    def _draw_dotted_world(self, w: int, h: int):
        dots = self._load_world_dots()
        if not dots:
            return
        dot_radius = max(1, int(min(w, h) / 180))
        dot_color = "#1f3a5e"
        for lat, lng in dots:
            px, py = self._project(lat, lng, w, h)
            if 0 <= px < w and 0 <= py < h:
                self.create_oval(
                    px - dot_radius, py - dot_radius,
                    px + dot_radius, py + dot_radius,
                    fill=dot_color, outline=""
                )

    def _draw_arc(self, x1: int, y1: int, x2: int, y2: int, color: str,
                  progress: float):
        mid_x = (x1 + x2) / 2
        mid_y = min(y1, y2) - abs(x2 - x1) * 0.18 - 25
        N = 50
        points = []
        for i in range(N + 1):
            t = i / N
            if t > progress: break
            bx = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * mid_x + t ** 2 * x2
            by = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * mid_y + t ** 2 * y2
            points.append((bx, by))
        if len(points) < 2:
            return
        for i in range(len(points) - 1):
            x_a, y_a = points[i]
            x_b, y_b = points[i + 1]
            self.create_line(
                x_a, y_a, x_b, y_b,
                fill=color, width=4, capstyle="round", stipple="gray50"
            )
        for i in range(len(points) - 1):
            x_a, y_a = points[i]
            x_b, y_b = points[i + 1]
            self.create_line(
                x_a, y_a, x_b, y_b,
                fill=color, width=2, capstyle="round"
            )
        if 0.05 < progress < 0.95:
            t = progress
            bx = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * mid_x + t ** 2 * x2
            by = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * mid_y + t ** 2 * y2
            self.create_oval(
                bx - 6, by - 6, bx + 6, by + 6,
                fill=color, outline="", stipple="gray25"
            )
            self.create_oval(
                bx - 4, by - 4, bx + 4, by + 4,
                fill=color, outline="white", width=1
            )

    def _draw_pulsing_point(self, x: int, y: int, color: str, label: str = ""):
        ring = 4 + int((self._anim_phase * 6) % 10)
        self.create_oval(x - ring, y - ring, x + ring, y + ring,
                         outline=color, width=1)
        ring2 = 4 + int(((self._anim_phase + 1.0) * 6) % 10)
        self.create_oval(x - ring2, y - ring2, x + ring2, y + ring2,
                         outline=color, width=1)
        for r, alpha_hex in [(8, "30"), (6, "60"), (4, "")]:
            fill_col = color if not alpha_hex else color
            try:
                self.create_oval(
                    x - r, y - r, x + r, y + r,
                    fill=fill_col, outline="", stipple="gray50" if alpha_hex else ""
                )
            except Exception:
                pass
        self.create_oval(x - 3, y - 3, x + 3, y + 3,
                         fill=color, outline="white", width=1)
        if label:
            label_y = y - 18
            tw = max(28, len(label) * 7 + 12)
            self.create_rectangle(
                x - tw // 2, label_y - 9, x + tw // 2, label_y + 9,
                fill="#ffffff", outline=color, width=1
            )
            self.create_text(x, label_y, text=label,
                             fill="#000000", font=("Segoe UI", 9, "bold"))

    def _draw(self):
        self.delete("all")
        w = max(self.winfo_width(), 1)
        h = max(self.winfo_height(), 1)
        self.create_rectangle(0, 0, w, h, fill="#0a0a14", outline="")
        self._draw_dotted_world(w, h)
        ua_lat, ua_lng = self.COUNTRY_COORDS["UA"]
        ua_x, ua_y = self._project(ua_lat, ua_lng, w, h)
        if self._server_country and self._server_country in self.COUNTRY_COORDS:
            slat, slng = self.COUNTRY_COORDS[self._server_country]
            sx, sy = self._project(slat, slng, w, h)
            cycle = (self._anim_phase % 2.0)
            if cycle <= 1.0:
                progress = cycle
            else:
                progress = 2.0 - cycle
            self._draw_arc(ua_x, ua_y, sx, sy, "#22d3ee", progress)
            self._draw_pulsing_point(sx, sy, "#22d3ee", self._server_country)
        self._draw_pulsing_point(ua_x, ua_y, "#a855f7", "UA")
        if self._anim_running and self._server_country:
            self._anim_phase += 0.05
            if self._anim_phase < 3.0:
                self.after(120, self._draw)
            else:
                self._anim_running = False

    def set_location(self, country_code: str):
        new_country = country_code.upper()
        if self._server_country == new_country:
            return
        self._server_country = new_country
        self._anim_phase = 0.0
        self._anim_running = True
        self._draw()

    def clear_location(self):
        self._server_country = ""
        self._anim_running = False
        self._draw()


# ─────────────────────────────────────────────────────────────────────────────
#  PROFILE ROW WIDGET
# ─────────────────────────────────────────────────────────────────────────────

class ProfileRow(ctk.CTkFrame):
    def __init__(self, parent, profile: VpnProfile,
                 on_connect, on_delete, on_shadow_probe, **kwargs):
        super().__init__(
            parent,
            fg_color=COLORS.get("bg_card", "#0f1e2e"),
            corner_radius=8,
            **kwargs
        )
        self.grid_columnconfigure(1, weight=1)

        proto_color = (
            COLORS.get("accent_cyan", "#00d4ff")
            if profile.protocol == VpnProtocol.WIREGUARD
            else COLORS.get("accent_yellow", "#f0c040")
        )
        icon = "🔵" if profile.protocol == VpnProtocol.WIREGUARD else "🟠"

        ctk.CTkLabel(
            self, text=f" {icon}",
            font=ctk.CTkFont(family="Consolas", size=20),
            text_color=proto_color
        ).grid(row=0, column=0, padx=(14, 4), pady=12, sticky="w")

        info = ctk.CTkFrame(self, fg_color="transparent")
        info.grid(row=0, column=1, sticky="ew", padx=4)

        ctk.CTkLabel(
            info, text=profile.name,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=COLORS.get("text_primary", "#e0f0ff")
        ).pack(anchor="w")
        ctk.CTkLabel(
            info,
            text=(
                f"{profile.protocol.value}  ·  "
                f"{profile.server_host or profile.server_ip}"
                f":{profile.port or '—'}"
            ),
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_secondary", "#607080")
        ).pack(anchor="w")

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.grid(row=0, column=2, padx=10, pady=10)

        _btn_cfg = dict(
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            height=30, corner_radius=6
        )

        ctk.CTkButton(
            btns, text="⚡ Connect",
            command=lambda p=profile.name: on_connect(p),
            fg_color="#00252a", hover_color="#003540",
            text_color=COLORS.get("accent_cyan", "#00d4ff"),
            border_width=1, border_color=COLORS.get("accent_cyan", "#00d4ff"),
            width=90, **_btn_cfg
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            btns, text="👥 Shadow",
            command=lambda p=profile.name: on_shadow_probe(p),
            fg_color=COLORS.get("bg_secondary", "#111c2a"),
            hover_color=COLORS.get("bg_card", "#0f1e2e"),
            text_color=COLORS.get("text_secondary", "#607080"),
            border_width=1, border_color=COLORS.get("border", "#1e3040"),
            width=82, **_btn_cfg
        ).pack(side="left", padx=2)

        ctk.CTkButton(
            btns, text="🗑",
            command=lambda p=profile.name: on_delete(p),
            fg_color="transparent", hover_color="#3a0000",
            text_color=COLORS.get("accent_red", "#ff4060"),
            width=30, height=30, corner_radius=6
        ).pack(side="left", padx=2)


# ─────────────────────────────────────────────────────────────────────────────
#  STATUS BADGE
# ─────────────────────────────────────────────────────────────────────────────

STATE_STYLE = {
    ConnectionState.DISCONNECTED: ("⬤  ВІДКЛЮЧЕНО",     "#607080"),
    ConnectionState.CONNECTING:   ("⬤  ПІДКЛЮЧЕННЯ...", "#f0c040"),
    ConnectionState.CONNECTED:    ("⬤  ПІДКЛЮЧЕНО",     "#00ff88"),
    ConnectionState.ERROR:        ("⬤  ПОМИЛКА",        "#ff4060"),
    ConnectionState.KILL_SWITCH:  ("⬤  KILL SWITCH",    "#ff4060"),
}


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN PAGE
# ─────────────────────────────────────────────────────────────────────────────

class AutoVpnPage(ctk.CTkScrollableFrame):
    """
    NetGuardian AI — VPN Manager & Secure Tunneling page.
    Features:
      • Profile import (.conf / .ovpn)
      • Connect / Disconnect with Kill Switch
      • Double-Hop IP verification
      • DNS Leak check
      • Traffic monitor (↓ ↑ speed, uptime)
      • Auto-VPN on open Wi-Fi
      • Quick Connect (lowest latency)
      • Shadow Mode (DPI port probe)
      • Split Tunnel helper
      • World-map server location
      • Security log console
    """

    POLL_INTERVAL_MS = 2000

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.engine = VpnManagerEngine(log_callback=self._write_log_safe)
        self._auto_vpn_active = False
        self._profile_rows: dict[str, ProfileRow] = {}
        self._stats_poll_running = False
        self._detected_vpn_process: Optional[tuple] = None
        self._last_network_id: Optional[str] = None
        self._ext_vpn_state: dict = {"active": False}
        self.auto_vpn_mode_var = tk.StringVar(value="open_only")

        # ── ВИПРАВЛЕННЯ БАГ #2 ──────────────────────────────────────────────
        # Ініціалізуємо btn_auto_vpn заздалегідь як NullBtn, щоб будь-який
        # потік що звертається до нього до _build_ui не отримав AttributeError.
        self.btn_auto_vpn = _NullBtn()

        # Захист від подвійного запуску VPN
        self._vpn_launch_lock = threading.Lock()
        self._vpn_launching = False

        self.grid_columnconfigure(0, weight=1)
        self._check_admin_warning()
        self._build_ui()
        self._start_stats_poll()
        self._sync_vpn_ui_from_state()
        self._start_network_change_watcher()

    def _sync_vpn_ui_from_state(self):
        """Викликається з MAIN THREAD кожну 1с.

        v4 (PR #20): ОДНЕ джерело правди — _direct_ip_check.
        """
        try:
            state = getattr(self, "_ext_vpn_state", {"active": False})

            now = time.time()
            last_check = getattr(self, "_last_ip_direct_check", 0)
            if now - last_check > 10:
                self._last_ip_direct_check = now
                threading.Thread(
                    target=self._direct_ip_check, daemon=True,
                    name="DirectIpCheck"
                ).start()

            current_signature = (
                bool(state.get("active")),
                state.get("ip", ""),
                state.get("cc", ""),
            )
            last_signature = getattr(self, "_last_vpn_signature", "INIT")

            if current_signature != last_signature:
                log_msg = state.get("log_message")
                if log_msg:
                    try:
                        self._write_log(log_msg)
                    except Exception:
                        pass

            if current_signature == last_signature:
                try:
                    self.after(1000, self._sync_vpn_ui_from_state)
                except Exception:
                    pass
                return

            self._last_vpn_signature = current_signature

            if state.get("active"):
                ip = state.get("ip", "—")
                country = state.get("country", "—")
                city    = state.get("city", "")
                cc      = state.get("cc", "")

                if ip and ip not in ("—", "Визначаю...", ""):
                    try: self._ip_lbl.configure(text=str(ip))
                    except Exception: pass

                loc_text = country if country else "—"
                if city and city not in ("?", "—", ""):
                    loc_text = f"{country}, {city}"
                if country and country not in ("—", ""):
                    try: self._loc_lbl.configure(text=loc_text[:30])
                    except Exception: pass

                try: self._enc_lbl.configure(text="AES-256")
                except Exception: pass
                try: self._dns_lbl.configure(text="OK")
                except Exception: pass

                if cc and len(cc) == 2:
                    try: self.world_map.set_location(cc)
                    except Exception: pass

                try:
                    self._set_state_ui(ConnectionState.CONNECTED)
                    print(f"[VpnUI] ✅ UI → CONNECTED (ip={ip} cc={cc})")
                except Exception as e:
                    print(f"[VpnUI] state UI error: {e}")

            else:
                try: self._ip_lbl.configure(text="—")
                except Exception: pass
                try: self._loc_lbl.configure(text="—")
                except Exception: pass
                try: self._enc_lbl.configure(text="—")
                except Exception: pass
                try: self._dns_lbl.configure(text="—")
                except Exception: pass
                try: self.world_map.clear_location()
                except Exception: pass
                try:
                    self._set_state_ui(ConnectionState.DISCONNECTED)
                    print(f"[VpnUI] ⚫ UI → DISCONNECTED")
                except Exception: pass

                self._auto_vpn_app_name = None
                self._detected_vpn_process = None
                self._vpn_launching = False
                try:
                    keys_to_remove = [k for k in list(self._profile_rows.keys())
                                      if k.startswith("__EXTERNAL__")]
                    for key in keys_to_remove:
                        try:
                            self._profile_rows[key].destroy()
                        except Exception: pass
                        del self._profile_rows[key]
                except Exception: pass

        except Exception as e:
            print(f"[VpnUI] _sync_vpn_ui_from_state error: {e}")

        try:
            self.after(1000, self._sync_vpn_ui_from_state)
        except Exception: pass

    def _direct_ip_check(self):
        """PR #20: Незалежна перевірка IP кожні 10с."""
        try:
            import urllib.request, json
            url = ("http://ip-api.com/json/?fields="
                   "status,query,country,countryCode,city,isp")
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") != "success":
                return

            current_ip = data.get("query", "")
            country    = data.get("country", "")
            cc         = (data.get("countryCode") or "").upper()[:2]
            city       = data.get("city", "")
            isp        = data.get("isp", "")

            if not hasattr(self, "_baseline_ip") or self._baseline_ip is None:
                self._baseline_ip = current_ip
                self._baseline_isp = isp
                print(f"[DirectIP] baseline set: {current_ip} ({isp})")
                return

            ip_changed = current_ip != self._baseline_ip
            current_state = getattr(self, "_ext_vpn_state", {})
            currently_active = current_state.get("active", False)

            if not hasattr(self, "_ip_check_history"):
                self._ip_check_history = []
            self._ip_check_history.append(ip_changed)
            if len(self._ip_check_history) > 3:
                self._ip_check_history = self._ip_check_history[-3:]

            if ip_changed and not currently_active:
                if sum(self._ip_check_history) >= 2:
                    # Перевіряємо чи це фоновий VPN після ручного відключення
                    manual_disconnect_at = getattr(self, "_manual_disconnect_at", 0)
                    is_background_vpn = (
                        manual_disconnect_at > 0 and
                        (time.time() - manual_disconnect_at) < 300  # 5 хвилин
                    )

                    if is_background_vpn:
                        log_msg = (
                            f"⚠️  VPN-додаток закрито, але тунель ПРОДОВЖУЄ працювати!\n"
                            f"   Фоновий сервіс VPN все ще активний.\n"
                            f"   IP: {current_ip}\n"
                            f"   Локація: {country}, {city}\n"
                            f"   ISP: {isp}\n"
                            f"   💡 Щоб повністю відключитись — зупини VPN\n"
                            f"      через його власний інтерфейс або трей."
                        )
                    else:
                        log_msg = (
                            f"🟢 ВПН активний!\n"
                            f"   IP: {current_ip}\n"
                            f"   Локація: {country}, {city}\n"
                            f"   ISP: {isp}"
                        )

                    self._ext_vpn_state = {
                        "active":  True,
                        "ip":      current_ip,
                        "country": country or cc,
                        "city":    city,
                        "isp":     isp,
                        "cc":      cc,
                        "log_message": log_msg,
                    }
                    print(f"[DirectIP] 🟢 VPN ON: {current_ip} ({cc})"
                          f"{' [BACKGROUND]' if is_background_vpn else ''}")
                else:
                    print(f"[DirectIP] IP змінився, чекаю підтвердження "
                          f"({sum(self._ip_check_history)}/2)")

            elif not ip_changed and currently_active:
                # FIX: знижено поріг з 3/3 до 2/3 для швидшого відгуку
                if self._ip_check_history.count(False) >= 2:
                    self._ext_vpn_state = {
                        "active": False,
                        "log_message": f"⚫ ВПН вимкнено. IP: {current_ip}",
                    }
                    self._detected_vpn_process = None
                    self._auto_vpn_app_name = None
                    self._vpn_launching = False
                    print(f"[DirectIP] ⚫ VPN OFF: back to {current_ip}")
                else:
                    print(f"[DirectIP] IP стабільний, чекаю підтвердження OFF "
                          f"({self._ip_check_history.count(False)}/2)")

            elif ip_changed and currently_active:
                if current_state.get("ip") != current_ip:
                    print(f"[DirectIP] VPN-сервер змінився: "
                          f"{current_state.get('ip')} → {current_ip}")

        except Exception as e:
            print(f"[DirectIP] error: {type(e).__name__}: {e}")

    # ── ADMIN WARNING ────────────────────────────────────────────────────────

    def _check_admin_warning(self):
        if not is_admin():
            self.after(800, lambda: self._write_log_safe(
                "⚠️  УВАГА: Програма запущена БЕЗ прав адміністратора.\n"
                "   Kill Switch, Split Tunnel та підключення VPN потребують прав адміна.\n"
                "   Запусти NetGuardian від імені адміністратора."
            ))

    # ── UI CONSTRUCTION ──────────────────────────────────────────────────────

    def _build_ui(self):
        self._build_header()
        self._build_map_section()
        self._build_profile_section()
        self._build_stats_section()
        self._build_tools_section()
        self._build_log_section()

    # ── 1. HEADER / STATUS ───────────────────────────────────────────────────

    def _build_header(self):
        card = GlowCard(self, accent=COLORS.get("accent_cyan", "#00d4ff"))
        card.grid(row=0, column=0, padx=24, pady=(24, 10), sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=0, column=0, padx=28, pady=22, sticky="w")

        ctk.CTkLabel(
            left,
            text="🔒  VPN MANAGER  ·  SECURE TUNNELING",
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#00d4ff")
        ).pack(anchor="w")
        ctk.CTkLabel(
            left,
            text="WireGuard & OpenVPN  ·  Kill Switch  ·  DNS Leak Protection  ·  Shadow DPI Bypass",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS.get("text_secondary", "#607080")
        ).pack(anchor="w", pady=(6, 0))

        right = ctk.CTkFrame(card, fg_color="transparent")
        right.grid(row=0, column=1, padx=28, pady=22, sticky="e")

        self.state_label = ctk.CTkLabel(
            right,
            text="⬤  ВІДКЛЮЧЕНО",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=COLORS.get("text_secondary", "#607080")
        )
        self.state_label.pack(anchor="e", pady=(0, 10))
        self._attach_tooltip(self.state_label,
            "Поточний стан VPN-з'єднання:\n"
            "• ВІДКЛЮЧЕНО — VPN не активний\n"
            "• ПІДКЛЮЧЕННЯ — встановлюється тунель\n"
            "• ПІДКЛЮЧЕНО — захищене з'єднання активне\n"
            "• KILL SWITCH — VPN розірвав з'єднання щоб не\n"
            "  допустити витоку даних")

        btn_row = ctk.CTkFrame(right, fg_color="transparent")
        btn_row.pack()

        self.btn_quick = ctk.CTkButton(
            btn_row, text="🚀 ШВИДКИЙ СТАРТ",
            command=self._launch_vpn_app,
            fg_color="#00252a", hover_color="#003540",
            text_color=COLORS.get("accent_cyan", "#00d4ff"),
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            height=52, width=200, corner_radius=10,
            border_width=2, border_color=COLORS.get("accent_cyan", "#00d4ff")
        )
        self.btn_quick.pack(side="left", padx=6)
        self._attach_tooltip(self.btn_quick,
            "Автоматичний пошук та запуск встановлених VPN-додатків\n"
            "(Radmin, Proton, Outline тощо).\n"
            "Якщо знайдено кілька — покаже діалог вибору.\n"
            "Якщо немає — запропонує імпортувати .conf/.ovpn профіль.")

        self.btn_disconnect = ctk.CTkButton(
            btn_row, text="⏹ ВІДКЛЮЧИТИ",
            command=self._disconnect,
            fg_color="#3a0000", hover_color="#5a0000",
            text_color=COLORS.get("accent_red", "#ff4060"),
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            height=52, width=180, corner_radius=10,
            border_width=2, border_color=COLORS.get("accent_red", "#ff4060"),
        )
        self.btn_disconnect.pack(side="left", padx=6)
        self._attach_tooltip(self.btn_disconnect,
            "Розриває поточне VPN-з'єднання.\n"
            "Ваша зовнішня IP-адреса повертається до реальної,\n"
            "наданої вашим інтернет-провайдером.")

    # ── 2. WORLD MAP ────────────────────────────────────────────────────────

    def _build_map_section(self):
        card = GlowCard(self, accent=COLORS.get("border", "#1e3040"))
        card.grid(row=1, column=0, padx=24, pady=10, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        map_title = ctk.CTkLabel(
            card,
            text="  🌍  ЛОКАЦІЯ СЕРВЕРА",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        map_title.grid(row=0, column=0, padx=20, pady=(18, 8), sticky="w")
        self._attach_tooltip(map_title,
            "Світова карта з позначкою VPN-сервера до якого ви підключені.\n"
            "Зелена пульсуюча точка показує країну сервера,\n"
            "анімована дуга візуалізує тунель з України до цього серверу.\n"
            "Без VPN — точка не відображається.")

        self.world_map = WorldMapCanvas(card, width=1200, height=440)
        self.world_map.grid(row=1, column=0, padx=16, pady=(0, 10), sticky="nsew")

        ip_row = ctk.CTkFrame(card, fg_color="transparent")
        ip_row.grid(row=2, column=0, padx=20, pady=(0, 14), sticky="ew")
        ip_row.grid_columnconfigure((0, 1, 2, 3), weight=1)

        self._ip_lbl = self._info_chip(
            ip_row, "Публічна IP", "—", 0,
            tooltip=("Ваша зовнішня IP-адреса — те що бачать сайти у інтернеті.\n"
                     "Коли VPN активний, вона показує IP-адресу VPN-сервера,\n"
                     "а не вашого справжнього інтернет-провайдера."))
        self._loc_lbl = self._info_chip(
            ip_row, "Локація", "—", 1,
            tooltip=("Географічна локація вашої поточної публічної IP.\n"
                     "Без VPN — показує ваше реальне місто.\n"
                     "З VPN — показує країну/місто де знаходиться VPN-сервер."))
        self._enc_lbl = self._info_chip(
            ip_row, "Шифрування", "—", 2,
            tooltip=("Алгоритм шифрування VPN-тунелю.\n"
                     "• AES-256 — стандарт для OpenVPN (армійського класу)\n"
                     "• ChaCha20 — швидший, для WireGuard\n"
                     "Обидва вважаються незламними сучасними методами."))
        self._dns_lbl = self._info_chip(
            ip_row, "DNS Leak", "—", 3,
            tooltip=("Перевірка чи DNS-запити йдуть через VPN, а не через\n"
                     "провайдера в обхід тунелю.\n"
                     "• Safe ✅ — DNS-запити захищені\n"
                     "• LEAK ⚠️ — DNS витікає поза VPN"))

    def _info_chip(self, parent, label: str, value: str, col: int,
                   tooltip: str = "") -> ctk.CTkLabel:
        frame = ctk.CTkFrame(
            parent,
            fg_color=COLORS.get("bg_card", "#0f1e2e"),
            corner_radius=12,
            border_width=1,
            border_color=COLORS.get("border", "#1e3040"),
        )
        frame.grid(row=0, column=col, padx=6, sticky="ew")

        title_lbl = ctk.CTkLabel(
            frame, text=label,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        title_lbl.pack(pady=(14, 4), padx=12)

        lbl = ctk.CTkLabel(
            frame, text=value,
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=COLORS.get("text_primary", "#ffffff"),
            wraplength=300,
        )
        lbl.pack(pady=(0, 14), padx=12)

        if tooltip:
            self._attach_tooltip(frame, tooltip)
            self._attach_tooltip(title_lbl, tooltip)
            self._attach_tooltip(lbl, tooltip)

        return lbl

    def _attach_tooltip(self, widget, text: str, delay: int = 400):
        """Прив'язує hover-tooltip до віджета."""
        tooltip_state = {"win": None, "after_id": None}

        def show(event=None):
            if tooltip_state["win"]: return
            try:
                x = widget.winfo_rootx() + widget.winfo_width() // 2
                y = widget.winfo_rooty() + widget.winfo_height() + 6
            except Exception: return
            tip = tk.Toplevel(widget)
            tip.wm_overrideredirect(True)
            tip.wm_geometry(f"+{x - 150}+{y}")
            tip.configure(bg=COLORS.get("bg_card", "#0f1e2e"))
            lbl = tk.Label(
                tip, text=text, justify="left",
                bg=COLORS.get("bg_card", "#0f1e2e"),
                fg=COLORS.get("text_primary", "#e0f0ff"),
                font=("Consolas", 9),
                padx=10, pady=6,
                wraplength=300,
                bd=1, relief="solid",
            )
            lbl.pack()
            tooltip_state["win"] = tip

        def schedule(event=None):
            cancel()
            tooltip_state["after_id"] = widget.after(delay, show)

        def cancel(event=None):
            if tooltip_state["after_id"]:
                try: widget.after_cancel(tooltip_state["after_id"])
                except Exception: pass
                tooltip_state["after_id"] = None

        def hide(event=None):
            cancel()
            if tooltip_state["win"]:
                try: tooltip_state["win"].destroy()
                except Exception: pass
                tooltip_state["win"] = None

        widget.bind("<Enter>", schedule)
        widget.bind("<Leave>", hide)
        widget.bind("<ButtonPress>", hide)

    # ── 3. PROFILE MANAGER ──────────────────────────────────────────────────

    def _build_profile_section(self):
        card = GlowCard(self, accent=COLORS.get("border", "#1e3040"))
        card.grid(row=2, column=0, padx=24, pady=10, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(14, 6), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        profile_title = ctk.CTkLabel(
            header,
            text="  📁  VPN ПРОФІЛІ",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        profile_title.grid(row=0, column=0, sticky="w")
        self._attach_tooltip(profile_title,
            "Список встановлених VPN-додатків та імпортованих профілів.\n"
            "Тут можна:\n"
            "• Запустити будь-який встановлений VPN-додаток одним кліком\n"
            "• Імпортувати власні .conf/.ovpn файли\n"
            "• Перевірити доступність кожного сервера (Shadow Probe)")

        import_row = ctk.CTkFrame(header, fg_color="transparent")
        import_row.grid(row=0, column=1, sticky="e")

        for text, cmd, tip in [
            ("🚀 Запустити VPN-додаток", self._launch_vpn_app,
             "Запускає встановлений VPN-додаток. Якщо встановлено кілька\n"
             "(Radmin, Proton, OpenVPN GUI тощо) — покаже діалог вибору."),
            ("🔍 Сканувати систему", self._rescan_vpns,
             "Шукає у системі (Program Files, AppData, Reestr) усі\n"
             "встановлені VPN-додатки та оновлює список профілів."),
        ]:
            btn = ctk.CTkButton(
                import_row, text=text, command=cmd,
                fg_color=COLORS.get("bg_secondary", "#111c2a"),
                hover_color=COLORS.get("bg_card", "#0f1e2e"),
                text_color=COLORS.get("text_primary", "#e0f0ff"),
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                height=42, corner_radius=8,
                border_width=1, border_color=COLORS.get("border", "#1e3040")
            )
            btn.pack(side="left", padx=4)
            self._attach_tooltip(btn, tip)

        info_row = ctk.CTkFrame(card, fg_color="transparent")
        info_row.grid(row=1, column=0, padx=20, pady=(0, 12), sticky="ew")

        self.auto_vpn_label = ctk.CTkLabel(
            info_row,
            text="🤖  Авто-VPN: активний — підключається автоматично при зміні мережі",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("accent_green", "#00ff88"),
            anchor="w",
        )
        self.auto_vpn_label.pack(fill="x")

        self.profile_list = ctk.CTkFrame(
            card,
            fg_color=COLORS.get("bg_primary", "#0a0f1a"),
            corner_radius=8
        )
        self.profile_list.grid(row=3, column=0, padx=16, pady=(0, 14), sticky="ew")
        self.profile_list.grid_columnconfigure(0, weight=1)

        self.empty_label = ctk.CTkLabel(
            self.profile_list,
            text="Немає VPN-додатків. Натисни '🔍 Сканувати систему' або '🚀 Запустити VPN-додаток'.",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_dim", "#2a4a5a")
        )
        self.empty_label.grid(row=0, column=0, pady=16)

    # ── 4. TRAFFIC / STATS ──────────────────────────────────────────────────

    def _build_stats_section(self):
        card = GlowCard(self, accent=COLORS.get("border", "#1e3040"))
        card.grid(row=3, column=0, padx=24, pady=10, sticky="ew")
        card.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        title = ctk.CTkLabel(
            card,
            text="  📊  СТАТИСТИКА ТУНЕЛЮ",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        title.grid(row=0, column=0, columnspan=5, padx=20, pady=(18, 10), sticky="w")
        self._attach_tooltip(title,
            "Метрики поточного VPN-з'єднання у реальному часі:\n"
            "• Швидкості завантаження та віддачі через тунель\n"
            "• Сумарний обсяг переданих даних (Rx/Tx)\n"
            "• Час безперервної роботи VPN")

        self.stat_down = self._stat_box(
            card, "↓ DOWNLOAD", "—", 0,
            tooltip=("Поточна швидкість завантаження через VPN-тунель.\n"
                     "Відображає реальний пропуск трафіку від VPN-сервера\n"
                     "до вашого ПК (Мбіт/с)."))
        self.stat_up = self._stat_box(
            card, "↑ UPLOAD", "—", 1,
            tooltip=("Поточна швидкість віддачі через VPN-тунель.\n"
                     "Швидкість передачі даних з вашого ПК до VPN-сервера."))
        self.stat_rx = self._stat_box(
            card, "Rx ВСЬОГО", "—", 2,
            tooltip=("Загальний обсяг даних отриманих через VPN з моменту\n"
                     "підключення. Обчислюється у MB/GB."))
        self.stat_tx = self._stat_box(
            card, "Tx ВСЬОГО", "—", 3,
            tooltip=("Загальний обсяг даних відправлених через VPN з моменту\n"
                     "підключення. Включає всі ваші запити, форми, файли."))
        self.stat_up_tm = self._stat_box(
            card, "⏱ ЧАС РОБОТИ", "—", 4,
            tooltip=("Тривалість поточної VPN-сесії з моменту успішного\n"
                     "підключення. Скидається при відключенні."))

    def _stat_box(self, parent, label: str, value: str, col: int,
                  tooltip: str = "") -> ctk.CTkLabel:
        frame = ctk.CTkFrame(
            parent,
            fg_color=COLORS.get("bg_card", "#0f1e2e"),
            corner_radius=12,
            border_width=1,
            border_color=COLORS.get("border", "#1e3040"),
        )
        frame.grid(row=1, column=col, padx=6, pady=(0, 16), sticky="ew")

        title_lbl = ctk.CTkLabel(
            frame, text=label,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        title_lbl.pack(pady=(14, 4), padx=12)

        lbl = ctk.CTkLabel(
            frame, text=value,
            font=ctk.CTkFont(family="Consolas", size=22, weight="bold"),
            text_color=COLORS.get("text_primary", "#ffffff")
        )
        lbl.pack(pady=(0, 14), padx=12)

        if tooltip:
            self._attach_tooltip(frame, tooltip)
            self._attach_tooltip(title_lbl, tooltip)
            self._attach_tooltip(lbl, tooltip)

        return lbl

    # ── 5. TOOLS ROW ────────────────────────────────────────────────────────

    def _build_tools_section(self):
        card = GlowCard(self, accent=COLORS.get("border", "#1e3040"))
        card.grid(row=4, column=0, padx=24, pady=10, sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        tools_title = ctk.CTkLabel(
            card,
            text="  🛠  ДОДАТКОВІ ІНСТРУМЕНТИ",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        tools_title.grid(row=0, column=0, padx=20, pady=(18, 10), sticky="w")
        self._attach_tooltip(tools_title,
            "Розширені утиліти для роботи з VPN та мережевою безпекою:\n"
            "• Тест DNS Leak — перевірка чи DNS-запити йдуть через VPN\n"
            "• Тест Shadow DPI — обхід DPI-блокувань провайдера\n"
            "• Kill Switch — автоматичний розрив трафіку при падінні VPN\n"
            "• Перевірка швидкості через тунель")

        tools_row = ctk.CTkFrame(card, fg_color="transparent")
        tools_row.grid(row=1, column=0, padx=16, pady=(0, 14), sticky="ew")

        tools = [
            ("🔍 Шукати профілі", self._discover_profiles,
             COLORS.get("accent_cyan", "#00d4ff"),
             "Сканує систему на встановлені VPN-додатки\n"
             "(NordVPN, ProtonVPN, Surfshark тощо)."),

            ("📶 Перевірити мережу", self._check_network,
             COLORS.get("text_primary", "#e0f0ff"),
             "Перевіряє безпеку поточної Wi-Fi мережі:\n"
             "тип шифрування (WPA2/WPA3/OPEN), SSID, ризик DPI/MITM."),

            ("🔍 DNS Leak Test", self._run_dns_test,
             COLORS.get("accent_yellow", "#f0c040"),
             "Перевіряє чи DNS-запити витікають повз VPN-тунель."),

            ("🌐 Перевірити IP", self._check_ip,
             COLORS.get("accent_cyan", "#00d4ff"),
             "Показує поточну публічну IP-адресу та геолокацію\n"
             "(країна, місто, ISP)."),

            ("🔀 Split Tunnel Info", self._show_split_info,
             COLORS.get("text_secondary", "#607080"),
             "Показує налаштування Split Tunneling — який трафік\n"
             "йде через VPN, а який напряму через ISP."),

            ("🛡 Kill Switch Status", self._toggle_kill_switch,
             COLORS.get("accent_red", "#ff4060"),
             "Kill Switch блокує весь трафік якщо VPN-з'єднання\n"
             "несподівано впало — щоб справжня IP не виявилась."),
        ]
        for text, cmd, color, tooltip in tools:
            btn = ctk.CTkButton(
                tools_row, text=text, command=cmd,
                fg_color=COLORS.get("bg_secondary", "#111c2a"),
                hover_color=COLORS.get("bg_card", "#0f1e2e"),
                text_color=color,
                font=ctk.CTkFont(family="Consolas", size=10),
                height=34, corner_radius=7,
                border_width=1, border_color=COLORS.get("border", "#1e3040")
            )
            btn.pack(side="left", padx=4)
            self._attach_tooltip(btn, tooltip)

    # ── 6. LOG CONSOLE ──────────────────────────────────────────────────────

    def _build_log_section(self):
        card = GlowCard(self, accent=COLORS.get("border", "#1e3040"))
        card.grid(row=5, column=0, padx=24, pady=(10, 24), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.grid(row=0, column=0, padx=20, pady=(14, 4), sticky="ew")
        header.grid_columnconfigure(0, weight=1)

        log_title = ctk.CTkLabel(
            header,
            text="  🔐  ЖУРНАЛ БЕЗПЕКИ VPN",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee")
        )
        log_title.grid(row=0, column=0, sticky="w")
        self._attach_tooltip(log_title,
            "Журнал подій VPN-модуля з мітками часу:\n"
            "• Спроби підключення/відключення\n"
            "• Зміни публічної IP-адреси (автоматично виявлені)\n"
            "• Спрацювання Kill Switch\n"
            "• Помилки автентифікації, тестування")

        ctk.CTkButton(
            header, text="🗑 Очистити",
            command=self._clear_log,
            fg_color="transparent",
            hover_color=COLORS.get("bg_card", "#0f1e2e"),
            text_color=COLORS.get("text_dim", "#607080"),
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            height=36, width=110, corner_radius=8
        ).grid(row=0, column=1, sticky="e", padx=(0, 4))

        self.log_box = ctk.CTkTextbox(
            card,
            height=240,
            font=ctk.CTkFont(family="Consolas", size=14),
            text_color=COLORS.get("accent_cyan", "#00d4ff"),
            fg_color=COLORS.get("bg_primary", "#0a0f1a"),
            corner_radius=8
        )
        self.log_box.grid(row=1, column=0, padx=16, pady=(0, 16), sticky="ew")
        self._write_log("NetGuardian VPN Engine готовий.")
        self._write_log("Імпортуй WireGuard .conf або OpenVPN .ovpn для початку роботи.")
        self._write_log("🤖 Авто-VPN активний: підключається автоматично при зміні мережі.")
        if not is_admin():
            self._write_log("⚠️  Запусти програму від імені адміністратора для повного функціоналу.")

    # ─────────────────────────────────────────────────────────────────────────
    #  PROFILE MANAGEMENT
    # ─────────────────────────────────────────────────────────────────────────

    def _rescan_vpns(self):
        self._launch_vpn_app()

    def _launch_vpn_app(self):
        import platform
        if platform.system() != "Windows":
            messagebox.showwarning(
                "VPN App",
                "Запуск .exe доступний лише на Windows.\n"
                "На Linux/Mac використовуй .conf або .ovpn."
            )
            return
        self._write_log("🔍 Сканую систему на наявність VPN-додатків...")
        threading.Thread(target=self._scan_and_show_vpns, daemon=True).start()

    def _scan_and_show_vpns(self):
        found = self._find_installed_vpns()
        if not found:
            self.after(0, self._handle_no_vpn_found)
            return
        self._write_log_safe(f"✅ Знайдено {len(found)} VPN-додатків")
        self.after(0, lambda: self._show_vpn_picker(found))

    _VPN_CATALOG = {
        "NordVPN": [
            r"C:\Program Files\NordVPN\NordVPN.exe",
            r"C:\Program Files (x86)\NordVPN\NordVPN.exe",
            r"%LocalAppData%\Programs\NordVPN\NordVPN.exe",
        ],
        "ExpressVPN": [
            r"C:\Program Files (x86)\ExpressVPN\expressvpn-ui.exe",
            r"C:\Program Files\ExpressVPN\expressvpn-ui.exe",
            r"C:\Program Files (x86)\ExpressVPN\xv_setup.exe",
        ],
        "ProtonVPN": [
            r"C:\Program Files\Proton\VPN\ProtonVPN.exe",
            r"C:\Program Files (x86)\Proton\VPN\ProtonVPN.exe",
            r"C:\Program Files\Proton Technologies\ProtonVPN\ProtonVPN.exe",
            r"%LocalAppData%\Programs\Proton\VPN\ProtonVPN.exe",
        ],
        "Surfshark": [
            r"C:\Program Files\Surfshark\Surfshark.exe",
            r"C:\Program Files (x86)\Surfshark\Surfshark.exe",
            r"%LocalAppData%\Programs\Surfshark\Surfshark.exe",
        ],
        "CyberGhost": [
            r"C:\Program Files\CyberGhost 8\CyberGhost.exe",
            r"C:\Program Files\CyberGhost 7\CyberGhost.exe",
            r"C:\Program Files (x86)\CyberGhost 8\CyberGhost.exe",
            r"C:\Program Files (x86)\CyberGhost 7\CyberGhost.exe",
        ],
        "Mullvad VPN": [
            r"C:\Program Files\Mullvad VPN\Mullvad VPN.exe",
            r"C:\Program Files (x86)\Mullvad VPN\Mullvad VPN.exe",
        ],
        "WireGuard": [
            r"C:\Program Files\WireGuard\wireguard.exe",
            r"C:\Program Files (x86)\WireGuard\wireguard.exe",
        ],
        "OpenVPN GUI": [
            r"C:\Program Files\OpenVPN\bin\openvpn-gui.exe",
            r"C:\Program Files (x86)\OpenVPN\bin\openvpn-gui.exe",
        ],
        "OpenVPN Connect": [
            r"C:\Program Files\OpenVPN Connect\OpenVPN Connect.exe",
            r"C:\Program Files (x86)\OpenVPN Connect\OpenVPN Connect.exe",
        ],
        "Hide.me VPN": [
            r"C:\Program Files\hide.me VPN\hide.me VPN.exe",
            r"C:\Program Files (x86)\hide.me VPN\hide.me VPN.exe",
        ],
        "PIA (Private Internet Access)": [
            r"C:\Program Files\Private Internet Access\pia-client.exe",
            r"C:\Program Files (x86)\Private Internet Access\pia-client.exe",
        ],
        "TunnelBear": [
            r"C:\Program Files\TunnelBear\TunnelBear.exe",
            r"C:\Program Files (x86)\TunnelBear\TunnelBear.exe",
        ],
        "Windscribe": [
            r"C:\Program Files\Windscribe\Windscribe.exe",
            r"C:\Program Files (x86)\Windscribe\Windscribe.exe",
            r"%LocalAppData%\Programs\Windscribe\Windscribe.exe",
        ],
        "IPVanish": [
            r"C:\Program Files\IPVanishVPN\IPVanish.exe",
            r"C:\Program Files (x86)\IPVanishVPN\IPVanish.exe",
            r"C:\Program Files\IPVanish\IPVanish.exe",
        ],
        "VyprVPN": [
            r"C:\Program Files\VyprVPN\VyprVPN.exe",
            r"C:\Program Files (x86)\VyprVPN\VyprVPN.exe",
            r"C:\Program Files\Golden Frog\VyprVPN\VyprVPN.exe",
        ],
        "PureVPN": [
            r"C:\Program Files\PureVPN\PureVPN.exe",
            r"C:\Program Files (x86)\PureVPN\PureVPN.exe",
        ],
        "Hotspot Shield": [
            r"C:\Program Files\Hotspot Shield\bin\HSS.exe",
            r"C:\Program Files (x86)\Hotspot Shield\bin\HSS.exe",
            r"C:\Program Files\Hotspot Shield\bin\HotspotShield.exe",
        ],
        "Avast SecureLine VPN": [
            r"C:\Program Files\AVAST Software\SecureLine VPN\SecureLine.exe",
            r"C:\Program Files (x86)\AVAST Software\SecureLine VPN\SecureLine.exe",
        ],
        "AVG Secure VPN": [
            r"C:\Program Files\AVG\Secure VPN\AVGSecureVPNTrayIcon.exe",
            r"C:\Program Files (x86)\AVG\Secure VPN\AVGSecureVPNTrayIcon.exe",
        ],
        "Bitdefender VPN": [
            r"C:\Program Files\Bitdefender Agent\bdvpn.exe",
            r"C:\Program Files\Bitdefender VPN\bdvpn.exe",
        ],
        "Kaspersky VPN": [
            r"C:\Program Files\Kaspersky Lab\Kaspersky Secure Connection\ksde.exe",
            r"C:\Program Files (x86)\Kaspersky Lab\Kaspersky Secure Connection\ksde.exe",
        ],
        "Norton Secure VPN": [
            r"C:\Program Files\NortonLifeLock\Norton Secure VPN\Engine\Engine.exe",
            r"C:\Program Files (x86)\Norton Secure VPN\Engine\Engine.exe",
        ],
        "Atlas VPN": [
            r"C:\Program Files\AtlasVPN\AtlasVPN.exe",
            r"C:\Program Files (x86)\AtlasVPN\AtlasVPN.exe",
            r"%LocalAppData%\Programs\AtlasVPN\AtlasVPN.exe",
        ],
        "X-VPN": [
            r"C:\Program Files\X-VPN\X-VPN.exe",
            r"C:\Program Files (x86)\X-VPN\X-VPN.exe",
        ],
        "Psiphon": [
            r"%UserProfile%\Downloads\psiphon3.exe",
            r"%LocalAppData%\Psiphon3\psiphon3.exe",
        ],
        "Lantern": [
            r"%LocalAppData%\Programs\Lantern\Lantern.exe",
            r"C:\Program Files\Lantern\Lantern.exe",
        ],
        "Outline Client": [
            r"%LocalAppData%\Programs\Outline\Outline.exe",
            r"C:\Program Files\Outline\Outline.exe",
        ],
        "Tailscale": [
            r"C:\Program Files\Tailscale\tailscale-ipn.exe",
            r"C:\Program Files\Tailscale IPN\tailscale-ipn.exe",
        ],
        "Urban VPN": [
            r"C:\Program Files\Urban VPN\Urban VPN.exe",
            r"C:\Program Files (x86)\Urban VPN\Urban VPN.exe",
            r"%LocalAppData%\Programs\Urban VPN\Urban VPN.exe",
            r"%ProgramFiles%\Urban VPN Desktop\Urban VPN.exe",
        ],
        "ZeroTier One": [
            r"C:\ProgramData\ZeroTier\One\zerotier_desktop_ui.exe",
            r"C:\Program Files\ZeroTier\One\zerotier_desktop_ui.exe",
        ],
    }

    _UWP_VPN_CATALOG = {
        "Urban VPN":      ["UrbanVPN.UrbanVPN_*", "Urban VPN"],
        "Hotspot Shield": ["AnchorFreeInc.HotspotShieldFreeVPN_*", "Hotspot Shield"],
        "TunnelBear":     ["McAfeeLLC.TunnelBearVPN_*", "TunnelBear"],
        "ProtonVPN":      ["ProtonAG.ProtonVPN_*", "Proton VPN"],
        "Windscribe":     ["Windscribe.WindscribeVPN_*", "Windscribe"],
    }

    def _find_installed_vpns(self) -> list:
        import os
        found = []
        seen_paths = set()

        for path in self._load_user_vpns():
            if path.lower() in seen_paths: continue
            display = os.path.splitext(os.path.basename(path))[0]
            found.append((f"⭐ {display}", path))
            seen_paths.add(path.lower())

        for name, paths in self._VPN_CATALOG.items():
            for p in paths:
                expanded = os.path.expandvars(p)
                if os.path.exists(expanded) and expanded.lower() not in seen_paths:
                    found.append((name, expanded))
                    seen_paths.add(expanded.lower())
                    break

        try:
            user_dirs = [
                os.path.expandvars(r"%UserProfile%\Desktop"),
                os.path.expandvars(r"%UserProfile%\Downloads"),
                os.path.expandvars(r"%Public%\Desktop"),
            ]
            for ud in user_dirs:
                if not os.path.isdir(ud): continue
                for fname in os.listdir(ud):
                    fl = fname.lower()
                    if not (fl.endswith(".exe") or fl.endswith(".lnk")): continue
                    if "vpn" not in fl and "wire" not in fl and "tunnel" not in fl: continue
                    full = os.path.join(ud, fname)
                    if full.lower() in seen_paths: continue
                    target = full
                    if fl.endswith(".lnk"):
                        target = self._resolve_lnk(full) or full
                    if target.lower() in seen_paths: continue
                    display = os.path.splitext(fname)[0]
                    found.append((f"📁 {display}", target))
                    seen_paths.add(target.lower())
        except Exception as e:
            print(f"[VPN] Desktop/Downloads scan error: {e}")

        try:
            registry_apps = self._scan_registry_for_vpns()
            for name, path in registry_apps:
                if path.lower() in seen_paths: continue
                found.append((f"🔧 {name}", path))
                seen_paths.add(path.lower())
        except Exception as e:
            print(f"[VPN] Registry scan error: {e}")

        try:
            uwp_apps = self._scan_uwp_vpns()
            for name, aumid in uwp_apps:
                fake_path = f"uwp:{aumid}"
                if fake_path.lower() in seen_paths: continue
                found.append((f"🪟 {name} (Microsoft Store)", fake_path))
                seen_paths.add(fake_path.lower())
                print(f"[VPN] Знайдено UWP VPN: {name} → {aumid}")
        except Exception as e:
            print(f"[VPN] UWP scan error: {e}")

        try:
            import threading as _th
            deep_results_holder = {"data": []}

            def _do_deep_scan():
                try:
                    deep_results_holder["data"] = self._deep_disk_scan(seen_paths)
                except Exception as e:
                    print(f"[VPN] Deep scan thread error: {e}")

            t = _th.Thread(target=_do_deep_scan, daemon=True)
            t.start()
            t.join(timeout=10)

            if t.is_alive():
                print(f"[VPN] Deep scan: timeout 10s — додаємо те що встигли")

            for name, path in deep_results_holder["data"]:
                if path.lower() in seen_paths: continue
                found.append((f"🔍 {name}", path))
                seen_paths.add(path.lower())
                print(f"[VPN] Deep scan знайшов: {name} → {path}")
        except Exception as e:
            print(f"[VPN] Deep scan error: {e}")

        return found

    def _deep_disk_scan(self, seen_paths: set) -> list:
        import os
        results = []
        VPN_KEYWORDS = [
            "vpn", "urban", "wireguard", "openvpn", "tunnel", "tunnelbear",
            "windscribe", "proton", "mullvad", "nord", "surfshark",
            "express", "cyber", "hotspot", "psiphon", "lantern",
            "shadowsocks", "v2ray", "trojan", "outline", "hide",
            "betternet", "zenmate", "purevpn", "ipvanish", "atlas",
            "x-vpn", "xvpn", "speedify", "torguard",
            "ukrtelecom-vpn", "openconnect", "anyconnect", "fortinet", "fortigate",
            "radmin",
        ]
        base_dirs = []
        for env_var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramData",
                        "LocalAppData", "AppData"]:
            p = os.environ.get(env_var)
            if p and os.path.isdir(p):
                base_dirs.append(p)
        local = os.environ.get("LocalAppData", "")
        if local:
            programs = os.path.join(local, "Programs")
            if os.path.isdir(programs):
                base_dirs.append(programs)
        for letter in "DEFGH":
            for sub in ["", "Programs", "Program Files", "Apps",
                        "Portable", "Tools", "Soft"]:
                p = f"{letter}:\\{sub}".rstrip("\\")
                if os.path.isdir(p):
                    base_dirs.append(p)
                    break
        base_dirs = list(set(base_dirs))
        print(f"[VPN] Deep scan: {len(base_dirs)} базових папок")
        for base in base_dirs:
            try:
                self._scan_dir_recursive(base, results, seen_paths,
                                         VPN_KEYWORDS, max_depth=4)
            except Exception as e:
                print(f"[VPN] Скан {base}: {e}")
        return results

    def _scan_dir_recursive(self, dir_path: str, results: list,
                             seen_paths: set, keywords: list,
                             max_depth: int = 4, current_depth: int = 0):
        import os
        if current_depth >= max_depth:
            return
        SKIP_DIRS = {
            "windows", "$recycle.bin", "$winreagent", "system volume information",
            "perflogs", "msocache", "boot", "recovery", "config.msi",
            "node_modules", ".git", "__pycache__", ".cache", "temp", "tmp",
            "winsxs", "drivers", "syswow64", "system32", "fonts",
            "google", "mozilla", "microsoft", "opera",
            "python", "nodejs", "java", "jdk", "jre",
        }
        try:
            entries = os.scandir(dir_path)
        except (PermissionError, OSError, NotADirectoryError):
            return
        try:
            for entry in entries:
                try:
                    name_lower = entry.name.lower()
                    if entry.is_dir(follow_symlinks=False):
                        if name_lower in SKIP_DIRS or name_lower.startswith("."):
                            continue
                        self._scan_dir_recursive(
                            entry.path, results, seen_paths,
                            keywords, max_depth, current_depth + 1)
                    elif entry.is_file(follow_symlinks=False):
                        if not name_lower.endswith(".exe"): continue
                        parent_name = os.path.basename(
                            os.path.dirname(entry.path)).lower()
                        if not any(kw in name_lower or kw in parent_name
                                   for kw in keywords):
                            continue
                        skip_words = ["uninst", "update", "helper", "service",
                                      "crash", "report", "installer", "setup",
                                      "elevator", "redist"]
                        if any(sw in name_lower for sw in skip_words):
                            continue
                        if entry.path.lower() in seen_paths: continue
                        clean_parent = os.path.basename(os.path.dirname(entry.path))
                        display = clean_parent if any(
                            kw in clean_parent.lower() for kw in keywords
                        ) else os.path.splitext(entry.name)[0]
                        results.append((display, entry.path))
                        seen_paths.add(entry.path.lower())
                except (PermissionError, OSError):
                    continue
        finally:
            try: entries.close()
            except Exception: pass

    def _scan_uwp_vpns(self) -> list:
        result = []
        try:
            import subprocess
            ps = (
                "Get-StartApps | "
                "Where-Object { "
                "    $_.Name -match 'VPN|Urban|Hotspot|Tunnel|Windscribe|Proton|"
                "Mullvad|NordVPN|Surfshark|CyberGhost|Express' "
                "} | "
                "ForEach-Object { \"$($_.Name)|$($_.AppID)\" }"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
                capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if not line or "|" not in line: continue
                name, aumid = line.split("|", 1)
                name, aumid = name.strip(), aumid.strip()
                if "!" in aumid and name and aumid:
                    result.append((name, aumid))
        except subprocess.TimeoutExpired:
            print("[VPN] UWP scan timeout — пропускаю")
        except Exception as e:
            print(f"[VPN] UWP scan error: {e}")
        return result

    def _resolve_lnk(self, lnk_path: str) -> Optional[str]:
        try:
            import subprocess
            ps = (
                f"$WshShell = New-Object -ComObject WScript.Shell; "
                f"$lnk = $WshShell.CreateShortcut('{lnk_path}'); "
                f"$lnk.TargetPath"
            )
            r = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps],
                capture_output=True, text=True, timeout=4,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            target = (r.stdout or "").strip()
            if target and target.lower().endswith(".exe"):
                import os
                if os.path.exists(target):
                    return target
        except Exception: pass
        return None

    def _scan_registry_for_vpns(self) -> list:
        try:
            import winreg
        except ImportError:
            return []
        import os
        found = []
        seen = set()
        registry_paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
            (winreg.HKEY_CURRENT_USER,
             r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        ]
        for root_key, sub_path in registry_paths:
            try:
                with winreg.OpenKey(root_key, sub_path) as key:
                    i = 0
                    while True:
                        try:
                            sub_name = winreg.EnumKey(key, i)
                            i += 1
                        except OSError:
                            break
                        try:
                            with winreg.OpenKey(key, sub_name) as sub:
                                try:
                                    display_name, _ = winreg.QueryValueEx(sub, "DisplayName")
                                except OSError:
                                    continue
                                dn_lower = display_name.lower()
                                if not any(kw in dn_lower for kw in
                                           ["vpn", "wireguard", "openvpn", "tunnel",
                                            "tailscale", "zerotier", "shadowsock",
                                            "psiphon", "lantern"]):
                                    continue
                                exe = None
                                for val_name in ("InstallLocation",
                                                 "DisplayIcon",
                                                 "UninstallString"):
                                    try:
                                        v, _ = winreg.QueryValueEx(sub, val_name)
                                        if val_name == "InstallLocation" and v:
                                            if os.path.isdir(v):
                                                for f in os.listdir(v):
                                                    if (f.lower().endswith(".exe")
                                                            and "uninstall" not in f.lower()
                                                            and "setup" not in f.lower()):
                                                        exe = os.path.join(v, f)
                                                        break
                                        elif v and v.lower().endswith(".exe"):
                                            v = v.split(",")[0].strip('"')
                                            if os.path.exists(v):
                                                exe = v
                                        if exe:
                                            break
                                    except OSError: continue
                                if exe and exe.lower() not in seen:
                                    found.append((display_name, exe))
                                    seen.add(exe.lower())
                        except OSError: continue
            except OSError: continue
        return found

    def _handle_no_vpn_found(self):
        answer = messagebox.askyesno(
            "VPN-додаток не знайдено",
            "Не знайдено жодного VPN-додатку.\n\n"
            "Перевірено:\n"
            "  • Program Files / Program Files (x86)\n"
            "  • LocalAppData / AppData\n"
            "  • Desktop / Downloads (на vpn-пов'язані файли)\n"
            "  • Windows Registry (Uninstall keys)\n\n"
            "Чи хочеш вибрати .exe файл вручну?"
        )
        if not answer: return
        self._launch_custom_exe()

    def _show_vpn_picker(self, found_vpns: list):
        import os
        import subprocess

        dlg = ctk.CTkToplevel(self)
        dlg.title("Запустити VPN-додаток")
        dlg.geometry("450x380")
        dlg.transient(self.winfo_toplevel())
        dlg.grab_set()
        dlg.configure(fg_color=COLORS.get("bg_primary", "#0a0f1a"))

        ctk.CTkLabel(
            dlg, text="🚀  Знайдено VPN-додатки:",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#00d4ff"),
        ).pack(pady=(20, 8))

        ctk.CTkLabel(
            dlg, text="Натисни щоб запустити обраний VPN-клієнт:",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_secondary", "#607080"),
        ).pack(pady=(0, 16))

        list_frame = ctk.CTkScrollableFrame(
            dlg, fg_color=COLORS.get("bg_secondary", "#111c2a"),
            corner_radius=8, height=200
        )
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 16))

        def _launch(path):
            import subprocess, os
            base_name = os.path.basename(path) if not path.startswith("uwp:") else path[4:]

            # ── UWP / Microsoft Store ─────────────────────────────────
            if path.startswith("uwp:"):
                aumid = path[4:]
                self._write_log(f"🪟 UWP запуск: {aumid}")
                success = False

                try:
                    ps_cmd = f'Start-Process "shell:AppsFolder\\{aumid}"'
                    self._write_log(f"  → Метод 1: PowerShell Start-Process")
                    r = subprocess.run(
                        ["powershell", "-NoProfile", "-NonInteractive",
                         "-Command", ps_cmd],
                        capture_output=True, text=True, timeout=10,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    if r.returncode == 0:
                        self._write_log(f"  ✅ Метод 1 успішно")
                        success = True
                    else:
                        self._write_log(f"  ❌ Метод 1 failed: rc={r.returncode}")
                except subprocess.TimeoutExpired:
                    self._write_log(f"  ⚠️ Метод 1: timeout")
                except Exception as e:
                    self._write_log(f"  ❌ Метод 1 exception: {e}")

                if not success:
                    try:
                        self._write_log(f"  → Метод 2: explorer shell:AppsFolder")
                        subprocess.Popen(
                            ["explorer.exe", f"shell:AppsFolder\\{aumid}"],
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        time.sleep(2)
                        self._write_log(f"  ✅ Метод 2 виконано")
                        success = True
                    except Exception as e:
                        self._write_log(f"  ❌ Метод 2 exception: {e}")

                if not success:
                    try:
                        self._write_log(f"  → Метод 3: PowerShell Get-AppxPackage")
                        pfn = aumid.split("!")[0]
                        ps2 = (
                            f"$pkg = Get-AppxPackage -Name '{pfn.split('_')[0]}*' | Select -First 1; "
                            f"if ($pkg) {{ "
                            f"  $manifest = (Get-AppxPackageManifest $pkg).Package.Applications.Application; "
                            f"  $appId = $manifest[0].Id; "
                            f"  Start-Process \"shell:AppsFolder\\$($pkg.PackageFamilyName)!$appId\" "
                            f"}}"
                        )
                        r = subprocess.run(
                            ["powershell", "-NoProfile", "-Command", ps2],
                            capture_output=True, text=True, timeout=15,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                        if r.returncode == 0:
                            self._write_log(f"  ✅ Метод 3 успішно")
                            success = True
                        else:
                            self._write_log(f"  ❌ Метод 3 failed")
                    except Exception as e:
                        self._write_log(f"  ❌ Метод 3 exception: {e}")

                if success:
                    self._auto_vpn_app_path = path
                    self._auto_vpn_app_name = aumid.split("!")[0]
                    self._show_active_external_vpn(self._auto_vpn_app_name, path)
                    dlg.destroy()
                else:
                    self._write_log(f"❌ Всі 3 методи провалились для AUMID={aumid}")
                    messagebox.showerror(
                        "UWP запуск не вдався",
                        f"Не вдалось запустити Microsoft Store додаток.\n\n"
                        f"AUMID: {aumid}\n\n"
                        f"💡 Запусти Urban VPN з меню Пуск вручну.\n"
                        f"NetGuardian виявить його автоматично."
                    )
                return

            # ── Win32 .exe ────────────────────────────────────────────
            try:
                self._write_log(f"🚀 Запускаю: {base_name}")
                exe_dir = os.path.dirname(path)
                proc = subprocess.Popen(
                    [path],
                    cwd=exe_dir,
                    shell=False,
                    creationflags=subprocess.DETACHED_PROCESS if hasattr(
                        subprocess, "DETACHED_PROCESS") else 0
                )
                # Перевірка краш-стану у фоні щоб не блокувати UI
                def _check_proc():
                    import time as _time
                    _time.sleep(1)
                    if proc.poll() is not None:
                        self._write_log_safe(
                            f"⚠️ {base_name} впав з кодом {proc.returncode}")
                    else:
                        self._write_log_safe(f"✅ Запущено успішно (PID {proc.pid})")
                threading.Thread(target=_check_proc, daemon=True).start()

                self._auto_vpn_app_path = path
                self._auto_vpn_app_name = base_name
                self._show_active_external_vpn(base_name, path)
                dlg.destroy()
            except PermissionError:
                self._write_log(f"❌ Permission denied — потрібні права адміністратора")
                messagebox.showerror(
                    "Помилка прав доступу",
                    f"Не вдалось запустити {base_name}.\n\n"
                    f"Запусти NetGuardian від імені адміністратора."
                )
            except Exception as e:
                self._write_log(f"❌ Popen помилка: {e}")
                try:
                    os.startfile(path)
                    self._write_log(f"✅ Запущено через os.startfile")
                    self._auto_vpn_app_path = path
                    self._auto_vpn_app_name = base_name
                    self._show_active_external_vpn(base_name, path)
                    dlg.destroy()
                    return
                except Exception as e2:
                    self._write_log(f"⚠️ os.startfile fallback failed: {e2}")
                try:
                    subprocess.Popen(
                        f'start "" "{path}"',
                        shell=True,
                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                    self._write_log(f"✅ Запущено через cmd start")
                    self._auto_vpn_app_path = path
                    self._auto_vpn_app_name = base_name
                    self._show_active_external_vpn(base_name, path)
                    dlg.destroy()
                    return
                except Exception as e3:
                    self._write_log(f"❌ Усі способи не спрацювали: {e3}")
                    messagebox.showerror(
                        "Помилка запуску",
                        f"Не вдалось запустити {base_name}.\n\n"
                        f"Спробовано: Popen, os.startfile, cmd start\n\n"
                        f"Можливі причини:\n"
                        f"  • Це Microsoft Store додаток (запусти з меню Пуск)\n"
                        f"  • Потрібні права адміністратора\n"
                        f"  • Антивірус блокує запуск"
                    )

        for name, path in found_vpns:
            btn = ctk.CTkButton(
                list_frame, text=f"▶ {name}",
                anchor="w", height=36,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                fg_color=COLORS.get("bg_card", "#0f1e2e"),
                hover_color=COLORS.get("border", "#1e3040"),
                text_color=COLORS.get("text_primary", "#e0f0ff"),
                command=lambda p=path: _launch(p),
            )
            btn.pack(fill="x", padx=4, pady=3)
            ctk.CTkLabel(
                list_frame, text=f"  {path}",
                font=ctk.CTkFont(family="Consolas", size=8),
                text_color=COLORS.get("text_secondary", "#607080"),
                anchor="w",
            ).pack(fill="x", padx=12, pady=(0, 6))

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(pady=(0, 16))

        ctk.CTkButton(
            btn_row, text="📁 Інший .exe...",
            command=lambda: (dlg.destroy(), self._launch_custom_exe()),
            fg_color="transparent",
            hover_color=COLORS.get("bg_secondary", "#111c2a"),
            text_color=COLORS.get("text_primary", "#e0f0ff"),
            border_width=1, border_color=COLORS.get("border", "#1e3040"),
            font=ctk.CTkFont(family="Consolas", size=10),
            width=140, height=30, corner_radius=6,
        ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_row, text="✕ Закрити",
            command=dlg.destroy,
            fg_color=COLORS.get("accent_red", "#ff4060"),
            hover_color="#cc3050",
            text_color="white",
            font=ctk.CTkFont(family="Consolas", size=10),
            width=100, height=30, corner_radius=6,
        ).pack(side="left", padx=4)

    def _launch_custom_exe(self):
        import os, subprocess
        path = filedialog.askopenfilename(
            title="Обери .exe файл",
            filetypes=[("Executable", "*.exe"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            subprocess.Popen([path], shell=False)
            self._write_log(f"🚀 Запущено: {os.path.basename(path)}")
        except Exception as e:
            self._write_log(f"❌ Помилка запуску: {e}")
            messagebox.showerror("Помилка", f"Не вдалось запустити:\n{e}")

    def _do_import(self, path: str):
        import os
        ext = os.path.splitext(path)[1].lower()
        if ext != ".exe":
            messagebox.showwarning(
                "Тільки .exe",
                f"NetGuardian тепер працює тільки з VPN-додатками (.exe).\n\n"
                f"Замість конфіг-файлів запускає установлений VPN-клієнт.\n\n"
                f"  • Або встанови VPN (NordVPN/ProtonVPN/тощо)\n"
                f"  • Або вибери .exe вручну"
            )
            return
        answer = messagebox.askyesnocancel(
            "VPN-додаток",
            f"📦 {os.path.basename(path)}\n\n"
            f"Що зробити з цим .exe файлом?\n\n"
            f"  • [Так]  → Запустити зараз\n"
            f"  • [Ні]   → Додати у список\n"
            f"  • [Cancel] → Нічого не робити"
        )
        if answer is None:
            return
        if answer:
            try:
                import subprocess
                subprocess.Popen([path], shell=False)
                self._write_log(f"🚀 Запущено: {os.path.basename(path)}")
            except Exception as e:
                self._write_log(f"❌ Помилка запуску: {e}")
                messagebox.showerror("Помилка", f"Не вдалось запустити:\n{e}")
        else:
            self._save_user_vpn(path)
            self._write_log(f"💾 Збережено: {os.path.basename(path)}")
            messagebox.showinfo("Збережено", "Додано у список VPN-додатків.")

    def _save_user_vpn(self, exe_path: str):
        import json
        from pathlib import Path
        config_dir = Path.home() / ".netguardian"
        config_dir.mkdir(parents=True, exist_ok=True)
        config_file = config_dir / "user_vpn_apps.json"
        try:
            data = []
            if config_file.exists():
                data = json.loads(config_file.read_text())
            if exe_path not in data:
                data.append(exe_path)
            config_file.write_text(json.dumps(data, indent=2))
        except Exception as e:
            print(f"[VPN] _save_user_vpn error: {e}")

    def _load_user_vpns(self) -> list:
        import os, json
        from pathlib import Path
        config_file = Path.home() / ".netguardian" / "user_vpn_apps.json"
        if not config_file.exists():
            return []
        try:
            data = json.loads(config_file.read_text())
            return [p for p in data if os.path.exists(p)]
        except Exception:
            return []

    def _show_active_external_vpn(self, vpn_name: str, vpn_path: str = ""):
        try:
            if not hasattr(self, "profile_list"):
                return
            if not hasattr(self, "_profile_rows"):
                self._profile_rows = {}

            display_name = vpn_name.replace(".exe", "").replace("_", " ").title()
            external_key = f"__EXTERNAL__{display_name}"

            if external_key in self._profile_rows:
                existing = self._profile_rows[external_key]
                try:
                    if existing.winfo_exists():
                        return
                except Exception:
                    self._profile_rows.pop(external_key, None)

            try:
                if hasattr(self, "empty_label") and self.empty_label.winfo_exists():
                    self.empty_label.destroy()
            except Exception:
                pass

            row_idx = len(self._profile_rows)
            card = ctk.CTkFrame(
                self.profile_list,
                fg_color="#0a2a1a",
                corner_radius=12,
                border_width=2,
                border_color=COLORS.get("accent_green", "#22c55e"),
                height=88,
            )
            card.grid(row=row_idx, column=0, padx=8, pady=4, sticky="ew")
            card.grid_propagate(False)
            card.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                card,
                text=f"🟢  АКТИВНИЙ VPN  ·  {display_name}",
                font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                text_color="#ffffff",
                anchor="w",
            ).grid(row=0, column=0, sticky="ew", padx=16, pady=(14, 4))

            sub_lbl = ctk.CTkLabel(
                card,
                text=f"Запущено через NetGuardian",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS.get("accent_green", "#22c55e"),
                anchor="w",
            )
            sub_lbl.grid(row=1, column=0, sticky="ew", padx=16, pady=(0, 14))

            card._status_lbl = sub_lbl
            card._vpn_name = display_name
            self._profile_rows[external_key] = card

            try:
                self._write_log(f"📌 Профіль: {display_name} (зовнішній VPN-додаток)")
            except Exception:
                pass

        except Exception as e:
            import traceback
            print(f"[VpnUI] _show_active_external_vpn ERROR: {e}")
            traceback.print_exc()

    def _add_profile_row(self, profile: VpnProfile):
        if hasattr(self, "empty_label") and self.empty_label.winfo_exists():
            self.empty_label.destroy()
        row_idx = len(self._profile_rows)
        row = ProfileRow(
            self.profile_list, profile,
            on_connect=self._connect_profile,
            on_delete=self._delete_profile,
            on_shadow_probe=self._shadow_probe,
        )
        row.grid(row=row_idx, column=0, padx=8, pady=4, sticky="ew")
        self._profile_rows[profile.name] = row

    def _delete_profile(self, name: str):
        if self.engine.delete_profile(name):
            row = self._profile_rows.pop(name, None)
            if row:
                row.destroy()
            self._write_log(f"🗑 Профіль видалено: {name}")
        if not self._profile_rows:
            self.empty_label = ctk.CTkLabel(
                self.profile_list,
                text="Немає профілів. Натисни Import вище.",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS.get("text_dim", "#2a4a5a")
            )
            self.empty_label.grid(row=0, column=0, pady=16)

    # ─────────────────────────────────────────────────────────────────────────
    #  CONNECTION
    # ─────────────────────────────────────────────────────────────────────────

    def _connect_profile(self, name: str):
        self._set_state_ui(ConnectionState.CONNECTING)
        self._write_log(f"⚡ Підключення до профілю: {name}")

        def task():
            ok, msg = self.engine.connect(name, enable_kill_switch=True)
            self._write_log_safe(msg)
            stats = self.engine.get_stats_snapshot()
            self.after(0, lambda: self._set_state_ui(stats.state))
            if stats.ip_changed:
                geo = self._safe_get_geo(stats.public_ip_after)
                self.after(0, lambda: self._update_ip_panel(stats, geo))
        threading.Thread(target=task, daemon=True).start()

    def _safe_get_geo(self, ip: str) -> dict:
        try:
            gr = getattr(self.engine, "geo_resolver", None)
            if gr is not None:
                if hasattr(gr, "get_geo"):
                    try:
                        result = gr.get_geo(ip)
                        if result: return result
                    except Exception as e:
                        print(f"[VpnUI] geo_resolver.get_geo error: {e}")
                if hasattr(gr, "resolve"):
                    try:
                        result = gr.resolve(ip)
                        if result: return result
                    except Exception as e:
                        print(f"[VpnUI] geo_resolver.resolve error: {e}")
        except Exception:
            pass
        try:
            import urllib.request, json
            url = (f"http://ip-api.com/json/{ip}?fields="
                   f"status,query,country,countryCode,city,isp")
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return {
                    "country":      data.get("country", ""),
                    "country_code": data.get("countryCode", ""),
                    "city":         data.get("city", ""),
                    "isp":          data.get("isp", ""),
                    "flag":         "🌍",
                }
        except Exception as e:
            print(f"[VpnUI] direct geo fetch error: {e}")
        return {"country": "?", "country_code": "", "city": "", "isp": "", "flag": "🌍"}

    def _safe_get_public_ip(self) -> str:
        try:
            gr = getattr(self.engine, "geo_resolver", None)
            if gr is not None and hasattr(gr, "get_public_ip"):
                try:
                    ip = gr.get_public_ip()
                    if ip and ip not in ("?", "—"):
                        return ip
                except Exception:
                    pass
        except Exception:
            pass
        try:
            import urllib.request, json
            url = "http://ip-api.com/json/?fields=status,query"
            req = urllib.request.Request(url, headers={"User-Agent": "NetGuardian/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            if data.get("status") == "success":
                return data.get("query", "")
        except Exception as e:
            print(f"[VpnUI] direct ip fetch error: {e}")
        return ""

    def _disconnect(self):
        import os, subprocess
        any_disconnected = False

        if hasattr(self, "_auto_vpn_app_path") and self._auto_vpn_app_path:
            try:
                exe_basename = os.path.basename(self._auto_vpn_app_path)
                self._write_log(f"⏹ Закриваю {exe_basename}...")
                r = subprocess.run(
                    ["taskkill", "/F", "/IM", exe_basename],
                    capture_output=True, text=True, timeout=10,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))

                # ── ВИПРАВЛЕННЯ БАГ #1 ──────────────────────────────────────
                # Одразу скидаємо стан — не чекаємо _direct_ip_check (30-90с).
                # _ip_check_history скидається щоб ip_check не "відновив" стан.
                self._ext_vpn_state = {"active": False}
                self._ip_check_history = [False, False, False]
                self._last_vpn_signature = "INIT"
                self._vpn_launching = False
                self._auto_vpn_app_path = None
                self._auto_vpn_app_name = None
                # Запам'ятовуємо час ручного відключення — щоб виявити
                # фоновий VPN-сервіс що продовжує працювати після закриття UI
                self._manual_disconnect_at = time.time()
                # ────────────────────────────────────────────────────────────

                if r.returncode == 0:
                    self._write_log(f"✅ {exe_basename} зупинено")
                else:
                    self._write_log(
                        f"⚠️ taskkill rc={r.returncode} — можливо вже не запущено")
                any_disconnected = True

                # Негайно оновлюємо UI в main thread
                self.after(0, lambda: self._set_state_ui(ConnectionState.DISCONNECTED))
                self.after(0, self._reset_ip_panel)
                self.after(0, lambda: self.world_map.clear_location())
                self._write_log("⚫ VPN відключено.")

            except Exception as e:
                self._write_log(f"❌ Помилка закриття: {e}")
                # Все одно скидаємо стан щоб UI не завис
                self._ext_vpn_state = {"active": False}
                self._ip_check_history = [False, False, False]
                self._last_vpn_signature = "INIT"
                self.after(0, lambda: self._set_state_ui(ConnectionState.DISCONNECTED))
                self.after(0, self._reset_ip_panel)
                self.after(0, lambda: self.world_map.clear_location())

        try:
            current_state = self.engine.stats.state
            if current_state != ConnectionState.DISCONNECTED:
                self._write_log("⏹ Відключаю VPN-тунель...")
                try: self.log_box.see("end")
                except Exception: pass

                def task():
                    try:
                        ok, msg = self.engine.disconnect()
                        self._write_log_safe(msg)
                        self._ext_vpn_state = {"active": False}
                        self._ip_check_history = [False, False, False]
                        self._last_vpn_signature = "INIT"
                        self.after(0, lambda: self._set_state_ui(ConnectionState.DISCONNECTED))
                        self.after(0, lambda: self._reset_ip_panel())
                        self.after(0, lambda: self.world_map.clear_location())
                    except Exception as e:
                        self._write_log_safe(f"❌ Disconnect помилка: {e}")
                threading.Thread(target=task, daemon=True).start()
                any_disconnected = True
        except Exception: pass

        if not any_disconnected:
            messagebox.showinfo(
                "Disconnect",
                "VPN вже відключений.\n\n"
                "Немає активного з'єднання або запущеного VPN-додатку."
            )
            self._write_log("ℹ️ Disconnect: нічого не активно.")

    # ─────────────────────────────────────────────────────────────────────────
    #  TOOLS ACTIONS
    # ─────────────────────────────────────────────────────────────────────────

    def _auto_connect_best(self):
        if self.engine.profiles:
            self._write_log("🚀 АВТО-ПІДКЛЮЧЕННЯ — пошук найкращого сервера...")

            def task():
                try:
                    ok, msg = self.engine.auto_connect_best(
                        enable_kill_switch=True,
                        log_cb=self._write_log_safe
                    )
                    if ok:
                        self._write_log_safe(f"\n✅ {msg}")
                    else:
                        self._write_log_safe(f"\n❌ {msg}")
                except Exception as e:
                    self._write_log_safe(f"❌ Помилка: {e}")
            threading.Thread(target=task, daemon=True).start()
            return

        # Немає .conf профілів — шукаємо встановлені VPN-додатки
        self._write_log("🔍 Профілі відсутні — шукаю встановлені VPN-додатки...")

        def _scan_task():
            try:
                installed = self._find_installed_vpns()
                if installed:
                    self._write_log_safe(f"✅ Знайдено {len(installed)} VPN-додатків")
                    self.after(0, lambda: self._show_auto_vpn_app_picker(installed))
                else:
                    self._write_log_safe(
                        "❌ VPN-додатки не знайдено.\n"
                        "   Встанови VPN або натисни '🚀 Запустити VPN-додаток'."
                    )
            except Exception as e:
                self._write_log_safe(f"❌ Помилка сканування: {e}")
        threading.Thread(target=_scan_task, daemon=True).start()

    def _discover_profiles(self):
        self._write_log("🔍 Шукаю VPN-профілі у системі...")

        def task():
            try:
                count = self.engine.auto_discover_profiles(log_cb=self._write_log_safe)
                if count > 0:
                    self.after(0, self._rebuild_profile_list)
                    self._write_log_safe(
                        f"\n✅ Додано {count} нових профілів. "
                        f"Тепер можна використати '🚀 Авто-підключення'.")
                else:
                    self._write_log_safe(
                        "ℹ️ .conf/.ovpn не знайдено — шукаю встановлені VPN-додатки...")
                    installed = self._find_installed_vpns()
                    if installed:
                        self._write_log_safe(f"✅ Знайдено {len(installed)} VPN-додатків")
                        self.after(0, lambda: self._show_vpn_picker(installed))
                    else:
                        self._write_log_safe(
                            "❌ VPN не знайдено. Встанови або вибери .exe вручну.")
            except Exception as e:
                self._write_log_safe(f"❌ Помилка: {e}")
        threading.Thread(target=task, daemon=True).start()

    def _magic_connect(self):
        self._write_log("🪄 MAGIC CONNECT — авто-пошук + підключення...")

        def task():
            try:
                if self.engine.profiles:
                    self._write_log_safe(
                        f"✅ Є {len(self.engine.profiles)} імпортованих профілів")
                    ok, msg = self.engine.auto_connect_best(
                        enable_kill_switch=True,
                        log_cb=self._write_log_safe)
                    self.after(0, self._rebuild_profile_list)
                    if ok:
                        self._write_log_safe(f"\n✨ {msg}")
                    else:
                        self._write_log_safe(f"\n⚠️ {msg}")
                    return

                self._write_log_safe(
                    "🔍 Профілі відсутні — шукаю встановлені VPN-додатки...")
                installed = []
                try:
                    installed = self._find_installed_vpns()
                except Exception as e:
                    print(f"[VpnUI] _find_installed_vpns error: {e}")

                if installed:
                    self._write_log_safe(
                        f"✅ Знайдено {len(installed)} VPN-додатків на ПК")
                    self.after(0, lambda: self._show_auto_vpn_app_picker(installed))
                    return

                self._write_log_safe(
                    "ℹ️ VPN-додатки не знайдено. "
                    "Шукаю .conf файли у файловій системі...")
                ok, msg = self.engine.magic_connect(log_cb=self._write_log_safe)
                self.after(0, self._rebuild_profile_list)
                if ok:
                    self._write_log_safe(f"\n✨ {msg}")
                else:
                    self._write_log_safe(
                        f"\n⚠️ Не знайдено ані VPN-додатків, ані .conf файлів.\n"
                        f"   Встанови VPN або імпортуй .conf вручну.")
            except Exception as e:
                import traceback
                self._write_log_safe(f"❌ Помилка: {e}")
                traceback.print_exc()
        threading.Thread(target=task, daemon=True).start()

    def _rebuild_profile_list(self):
        try:
            if hasattr(self, "_profile_rows"):
                for row in list(self._profile_rows.values()):
                    try: row.destroy()
                    except Exception: pass
                self._profile_rows = {}
            for profile in self.engine.get_profiles():
                if hasattr(self, "_add_profile_row"):
                    try: self._add_profile_row(profile)
                    except Exception: pass
        except Exception as e:
            print(f"[VPN UI] _rebuild_profile_list: {e}")

    def _check_network(self):
        def task():
            net = self.engine.check_network_security()
            if net["is_open"]:
                self._write_log_safe(
                    f"🔓 НЕБЕЗПЕЧНО: Відкрита мережа '{net['ssid']}' "
                    "— рекомендується підключити VPN!")
            elif "Захищена" in net.get("type", ""):
                self._write_log_safe(
                    f"🔒 БЕЗПЕЧНО: {net['ssid']} ({net['auth']})")
            else:
                self._write_log_safe(f"ℹ️  Мережа: {net['type']}")
        threading.Thread(target=task, daemon=True).start()

    def _run_dns_test(self):
        def task():
            self._write_log_safe("🔍 DNS Leak Test запущено...")
            stats = self.engine.get_stats_snapshot()
            result = self.engine.dns_checker.check(
                expected_vpn_ip=stats.public_ip_after or "")
            if result["leak_detected"]:
                self._write_log_safe(f"⚠️  DNS LEAK! {result['details']}")
                self.after(0, lambda: self._dns_lbl.configure(
                    text="LEAK ⚠️",
                    text_color=COLORS.get("accent_red", "#ff4060")))
            else:
                self._write_log_safe(f"✅ DNS Leak: безпечно. {result['details']}")
                self.after(0, lambda: self._dns_lbl.configure(
                    text="Безпечно ✅",
                    text_color=COLORS.get("accent_green", "#00ff88")))
        threading.Thread(target=task, daemon=True).start()

    def _check_ip(self):
        def task():
            self._write_log_safe("🌐 Визначаємо публічну IP-адресу...")
            try:
                ip = self._safe_get_public_ip()
                geo = self._safe_get_geo(ip) if ip else {}
                country = geo.get("country", "?")
                city = geo.get("city", "?")
                isp = geo.get("isp", geo.get("org", "?"))
                self._write_log_safe(
                    f"Поточна публічна IP: {ip}  "
                    f"🌍 {city}, {country} ({isp})")
            except Exception as e:
                self._write_log_safe(f"❌ Помилка отримання IP: {e}")
        threading.Thread(target=task, daemon=True).start()

    def _show_split_info(self):
        self._write_log(
            "🔀 Split Tunneling:\n"
            "   Використовує Windows Routing Table (route add/delete).\n"
            "   Гейм-трафік → пряме з'єднання (низький пінг).\n"
            "   Браузер      → через VPN тунель (приватність).\n"
            "   API: engine.split_tunnel.add_bypass_route('8.8.8.0/24', '<gateway>')"
        )

    def _toggle_kill_switch(self):
        def task():
            if self.engine.kill_switch.is_active():
                ok, msg = self.engine.kill_switch.deactivate()
            else:
                ok, msg = self.engine.kill_switch.activate()
            self._write_log_safe(msg)
        threading.Thread(target=task, daemon=True).start()

    def _shadow_probe(self, profile_name: str):
        def task():
            self._write_log_safe(f"👥 Shadow Mode probe: {profile_name}...")
            self.engine.run_shadow_probe(profile_name)
        threading.Thread(target=task, daemon=True).start()

    # ─────────────────────────────────────────────────────────────────────────
    #  AUTO-VPN TOGGLE
    # ─────────────────────────────────────────────────────────────────────────

    def _on_auto_vpn_mode_change(self, choice: str):
        mode_map = {
            "Тільки відкриті Wi-Fi (безпека)": "open_only",
            "Завжди підключений (приватність)": "always",
            "Одноразово при старті утиліти":    "on_startup",
        }
        new_mode = mode_map.get(choice, "open_only")
        self.auto_vpn_mode_var.set(new_mode)
        self._write_log(f"📌 Режим Auto-VPN змінено: {choice}")
        if self._auto_vpn_active:
            self._write_log("🔄 Перезапуск моніторингу з новим режимом...")
            self.engine.stop_auto_vpn_monitor()
            self._auto_vpn_active = False
            self._toggle_auto_vpn()

    def _toggle_auto_vpn(self):
        if self._auto_vpn_active:
            self.engine.stop_auto_vpn_monitor()
            self._auto_vpn_active = False
            self._stop_app_watchdog()
            self.auto_vpn_label.configure(
                text="🤖  Авто-VPN: активний — підключається автоматично при зміні мережі",
                text_color=COLORS.get("accent_green", "#00ff88"))
            (getattr(self, "btn_auto_vpn", None) or _NullBtn()).configure(
                text="🤖 Увімкнути Auto-VPN",
                border_color=COLORS.get("accent_cyan", "#00d4ff"),
                text_color=COLORS.get("accent_cyan", "#00d4ff"))
            self._write_log("⏹ Auto-VPN деактивовано.")
            return

        self._write_log("🔍 Auto-VPN: шукаю VPN-додатки на комп'ютері...")

        def _activate_in_thread():
            try:
                installed_apps = self._find_installed_vpns()
                if installed_apps:
                    self._write_log_safe(
                        f"✅ Знайдено {len(installed_apps)} VPN-додатків на ПК")
                    self.after(0, lambda: self._show_auto_vpn_app_picker(installed_apps))
                    return
                if self.engine.profiles:
                    self._write_log_safe(
                        "ℹ️ VPN-додатки не знайдено, використовую імпортовані профілі.")
                    self._activate_profile_based_auto_vpn()
                    return
                self.after(0, self._show_no_vpn_dialog)
            except Exception as e:
                self._write_log_safe(f"❌ Auto-VPN error: {e}")

        threading.Thread(target=_activate_in_thread, daemon=True).start()

    def _show_auto_vpn_app_picker(self, installed_apps: list):
        dlg = ctk.CTkToplevel(self)
        dlg.title("Auto-VPN — вибір додатку")
        dlg.geometry("520x440")
        dlg.transient(self.winfo_toplevel())
        dlg.grab_set()
        dlg.configure(fg_color=COLORS.get("bg_primary", "#0a0f1a"))

        ctk.CTkLabel(
            dlg, text="🤖  Auto-VPN — обери VPN-додаток",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#00d4ff"),
        ).pack(pady=(20, 6))

        ctk.CTkLabel(
            dlg, text="Утиліта виявила встановлені VPN-додатки.\n"
                      "Обери який з них автоматично запускати:",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_secondary", "#607080"),
        ).pack(pady=(0, 14))

        list_frame = ctk.CTkScrollableFrame(
            dlg, fg_color=COLORS.get("bg_secondary", "#111c2a"),
            corner_radius=8, height=240)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 12))

        def _select(name, path):
            dlg.destroy()
            self._activate_app_based_auto_vpn(name, path)

        for name, path in installed_apps:
            row = ctk.CTkFrame(list_frame, fg_color="transparent")
            row.pack(fill="x", padx=4, pady=3)
            btn = ctk.CTkButton(
                row, text=f"▶ {name}",
                anchor="w", height=32,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                fg_color=COLORS.get("bg_card", "#0f1e2e"),
                hover_color=COLORS.get("accent_cyan", "#00d4ff"),
                text_color=COLORS.get("text_primary", "#e0f0ff"),
                command=lambda n=name, p=path: _select(n, p),
            )
            btn.pack(fill="x")
            ctk.CTkLabel(
                row, text=f"  📁 {path}",
                font=ctk.CTkFont(family="Consolas", size=8),
                text_color=COLORS.get("text_secondary", "#607080"),
                anchor="w",
            ).pack(fill="x", pady=(0, 2))

        btn_row = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_row.pack(pady=(0, 16))

        if self.engine.profiles:
            ctk.CTkButton(
                btn_row, text=f"📁 Або: профілі ({len(self.engine.profiles)})",
                command=lambda: (dlg.destroy(), self._activate_profile_based_auto_vpn()),
                fg_color="transparent",
                hover_color=COLORS.get("bg_secondary", "#111c2a"),
                text_color=COLORS.get("text_primary", "#e0f0ff"),
                border_width=1, border_color=COLORS.get("border", "#1e3040"),
                font=ctk.CTkFont(family="Consolas", size=10),
                width=180, height=30, corner_radius=6,
            ).pack(side="left", padx=4)

        ctk.CTkButton(
            btn_row, text="✕ Скасувати",
            command=dlg.destroy,
            fg_color=COLORS.get("accent_red", "#ff4060"),
            hover_color="#cc3050",
            text_color="white",
            font=ctk.CTkFont(family="Consolas", size=10),
            width=110, height=30, corner_radius=6,
        ).pack(side="left", padx=4)

    def _activate_app_based_auto_vpn(self, app_name: str, exe_path: str):
        """Запускає VPN-додаток із захистом від подвійного запуску."""
        import os, subprocess

        if not self._vpn_launch_lock.acquire(blocking=False):
            self._write_log(f"⏳ VPN вже запускається, ігнорую повторний виклик")
            return
        self._vpn_launching = True

        try:
            self._write_log(f"🚀 Запускаю: {app_name}")
            subprocess.Popen([exe_path], shell=False)
            self._auto_vpn_app_path = exe_path
            self._auto_vpn_app_name = app_name
            self._write_log(
                f"✅ Запущено {app_name}\n"
                f"   📍 Шлях: {exe_path}\n"
                f"   ℹ️ Підключайся через інтерфейс самого VPN-додатку")
            try:
                self._show_active_external_vpn(app_name, exe_path)
            except Exception: pass
        except Exception as e:
            self._vpn_launching = False
            self._write_log(f"❌ Не вдалось запустити {app_name}: {e}")
            try:
                messagebox.showerror("VPN", f"Не вдалось запустити:\n{e}")
            except Exception: pass
        finally:
            try:
                self._vpn_launch_lock.release()
            except Exception: pass

    def _start_app_watchdog(self, exe_path: str, app_name: str, mode: str):
        """PR #24: ВИМКНЕНО — watchdog мимоволі рестартував VPN у фоні."""
        return  # noop

    def _stop_app_watchdog(self):
        if hasattr(self, "_app_watchdog_stop"):
            self._app_watchdog_stop.set()

    def _activate_profile_based_auto_vpn(self):
        if not self.engine.profiles:
            self._write_log("❌ Немає профілів для Auto-VPN")
            return
        mode = self.auto_vpn_mode_var.get()
        mode_label = {
            "open_only":  "відкриті Wi-Fi",
            "always":     "завжди",
            "on_startup": "одноразово",
        }.get(mode, mode)
        self._write_log(f"🔍 Auto-VPN ({mode_label}): шукаю найкращий профіль...")

        def _start_in_thread():
            try:
                best = self.engine.auto_select_best_server(log_cb=self._write_log_safe)
                if not best:
                    best_name = next(iter(self.engine.profiles))
                    self._write_log_safe(f"⚠️ Не вдалось знайти найкращий — беру перший: {best_name}")
                else:
                    best_name = best.name
                self.engine.start_auto_vpn_monitor(best_name, interval=20, mode=mode)
                self._auto_vpn_active = True
                self.after(0, lambda: self.auto_vpn_label.configure(
                    text=f"⬤  Auto-VPN ({mode_label}): {best_name[:25]}",
                    text_color=COLORS.get("accent_green", "#00ff88")))
                self.after(0, lambda: (getattr(self, "btn_auto_vpn", None) or _NullBtn()).configure(
                    text="⏹ Вимкнути Auto-VPN",
                    border_color=COLORS.get("accent_red", "#ff4060"),
                    text_color=COLORS.get("accent_red", "#ff4060")))
                self._write_log_safe(f"✅ Auto-VPN активний (профіль: {best_name})")
            except Exception as e:
                self._write_log_safe(f"❌ Auto-VPN помилка: {e}")
                self._auto_vpn_active = False

        threading.Thread(target=_start_in_thread, daemon=True).start()

    def _show_no_vpn_dialog(self):
        result = messagebox.askyesno(
            "Auto-VPN — VPN не знайдено",
            "Не знайдено жодного встановленого VPN-додатку\n"
            "(NordVPN, ProtonVPN, ExpressVPN тощо).\n\n"
            "Спробуй:\n"
            "  1. Встановити VPN-додаток з офіційного сайту\n"
            "  2. Або вибрати .exe файл вручну\n\n"
            "Хочеш вибрати .exe файл VPN зараз?"
        )
        if result:
            self._launch_custom_exe()

    # ─────────────────────────────────────────────────────────────────────────
    #  VPN PROCESS DETECTOR
    # ─────────────────────────────────────────────────────────────────────────

    _VPN_PROCESS_KEYWORDS = [
        ("urban",         "Urban VPN"),
        ("urbanvpn",      "Urban VPN"),
        ("vectera",       "Vectera VPN"),
        ("radmin",        "Radmin VPN"),
        ("m247",          "M247"),
        ("nordvpn",       "NordVPN"),
        ("expressvpn",    "ExpressVPN"),
        ("protonvpn",     "ProtonVPN"),
        ("proton vpn",    "ProtonVPN"),
        ("surfshark",     "Surfshark"),
        ("cyberghost",    "CyberGhost"),
        ("mullvad",       "Mullvad"),
        ("wireguard",     "WireGuard"),
        ("openvpn",       "OpenVPN"),
        ("hide.me",       "Hide.me VPN"),
        ("pia-client",    "PIA"),
        ("tunnelbear",    "TunnelBear"),
        ("windscribe",    "Windscribe"),
        ("ipvanish",      "IPVanish"),
        ("vyprvpn",       "VyprVPN"),
        ("purevpn",       "PureVPN"),
        ("hotspotshield", "Hotspot Shield"),
        ("hssengine",     "Hotspot Shield"),
        ("securelinevpn", "Avast SecureLine"),
        ("avgsecurevpn",  "AVG Secure VPN"),
        ("bdvpn",         "Bitdefender VPN"),
        ("ksde",          "Kaspersky VPN"),
        ("atlasvpn",      "Atlas VPN"),
        ("x-vpn",         "X-VPN"),
        ("psiphon",       "Psiphon"),
        ("lantern",       "Lantern"),
        ("outline",       "Outline"),
        ("tailscale",     "Tailscale"),
        ("zerotier",      "ZeroTier"),
        ("rvrvpngui",     "Radmin VPN"),
        ("rvrvpn",        "Radmin VPN"),
    ]

    def _start_vpn_process_detector(self):
        """Кожні 5с перевіряє чи юзер вручну запустив VPN-додаток."""
        def _loop():
            import time
            while True:
                try:
                    detected = self._scan_running_vpn_processes()
                    prev = self._detected_vpn_process

                    if detected and not prev:
                        name, pid = detected
                        self._detected_vpn_process = detected
                        self._write_log_safe(
                            f"🟢 Виявлено запущений VPN: {name} (PID {pid})")
                        self.after(0, lambda n=name: self._on_external_vpn_detected(n))
                    elif not detected and prev:
                        old_name, _ = prev
                        self._detected_vpn_process = None
                        self._write_log_safe(f"⚫ VPN {old_name} зупинено")
                        self.after(0, self._on_external_vpn_disconnected)
                    elif detected and prev and detected[0] != prev[0]:
                        self._detected_vpn_process = detected
                        self.after(0, lambda n=detected[0]:
                                   self._on_external_vpn_detected(n))
                except Exception as e:
                    print(f"[VpnDetector] {e}")
                time.sleep(5)

        threading.Thread(target=_loop, daemon=True, name="VpnProcessDetector").start()

    def _scan_running_vpn_processes(self) -> Optional[tuple]:
        """Повертає (display_name, pid) якщо знайдений запущений VPN-процес."""
        try:
            import psutil
            for proc in psutil.process_iter(["name", "pid", "exe"]):
                try:
                    pname_lower = (proc.info.get("name") or "").lower()
                    exe_path = (proc.info.get("exe") or "").lower()
                    for keyword, display in self._VPN_PROCESS_KEYWORDS:
                        if keyword in pname_lower:
                            return (display, proc.info["pid"])
                    if exe_path:
                        for keyword, display in self._VPN_PROCESS_KEYWORDS:
                            if keyword in exe_path:
                                return (display, proc.info["pid"])
                except Exception: pass
        except ImportError:
            try:
                import subprocess
                r = subprocess.run(
                    ["tasklist", "/FO", "CSV", "/NH"],
                    capture_output=True, text=True, timeout=5,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                for line in (r.stdout or "").splitlines():
                    parts = line.replace('"', '').split(',')
                    if len(parts) < 2: continue
                    pname = parts[0].lower()
                    for keyword, display in self._VPN_PROCESS_KEYWORDS:
                        if keyword in pname:
                            try: pid = int(parts[1])
                            except: pid = 0
                            return (display, pid)
            except Exception: pass

        result = self._scan_vpn_windows()
        if result: return result
        return None

    def _scan_vpn_windows(self) -> Optional[tuple]:
        """Сканує вікна Windows на наявність VPN-заголовків (для UWP)."""
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.windll.user32
            EnumWindows = user32.EnumWindows
            GetWindowTextW = user32.GetWindowTextW
            GetWindowTextLengthW = user32.GetWindowTextLengthW
            IsWindowVisible = user32.IsWindowVisible
            GetWindowThreadProcessId = user32.GetWindowThreadProcessId

            EnumWindowsProc = ctypes.WINFUNCTYPE(
                wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            found = []

            def _enum_callback(hwnd, lparam):
                try:
                    if not IsWindowVisible(hwnd): return True
                    length = GetWindowTextLengthW(hwnd)
                    if length == 0: return True
                    buf = ctypes.create_unicode_buffer(length + 2)
                    GetWindowTextW(hwnd, buf, length + 2)
                    title = buf.value.lower()
                    if not title: return True
                    for keyword, display in self._VPN_PROCESS_KEYWORDS:
                        if keyword in title:
                            pid = wintypes.DWORD()
                            GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                            found.append((display, pid.value))
                            return False
                except Exception: pass
                return True

            EnumWindows(EnumWindowsProc(_enum_callback), 0)
            return found[0] if found else None
        except Exception as e:
            print(f"[VpnDetector] window scan error: {e}")
            return None

    def _on_external_vpn_detected(self, vpn_name: str):
        country_map = {
            "nordvpn": "US", "expressvpn": "US", "protonvpn": "CH",
            "surfshark": "NL", "cyberghost": "RO", "mullvad": "SE",
            "tunnelbear": "CA", "windscribe": "CA", "ipvanish": "US",
            "purevpn": "HK", "hide": "MY", "pia": "US",
            "radmin": "RU", "tailscale": "US", "zerotier": "US",
            "urban": "US", "vectera": "CZ", "m247": "CZ",
        }
        cc_fallback = "US"
        vpn_lower = vpn_name.lower()
        for key, code in country_map.items():
            if key in vpn_lower:
                cc_fallback = code; break

        self._auto_vpn_app_name = vpn_name
        self._ext_vpn_state = {
            "active":  True,
            "ip":      "Визначаю...",
            "country": cc_fallback,
            "city":    "?",
            "isp":     vpn_name,
            "cc":      cc_fallback,
        }

        def _fetch_real_data():
            import time
            time.sleep(3)
            try:
                public_ip = self._safe_get_public_ip()
                if not public_ip:
                    self._write_log_safe(
                        "⚠️ Не вдалось отримати публічну IP — VPN ще піднімається?")
                    time.sleep(5)
                    public_ip = self._safe_get_public_ip()
                if public_ip:
                    geo = self._safe_get_geo(public_ip) or {}
                    cc = (geo.get("country_code") or cc_fallback)[:2].upper()
                    self._ext_vpn_state = {
                        "active":  True,
                        "ip":      public_ip,
                        "country": geo.get("country", cc),
                        "city":    geo.get("city", "?"),
                        "isp":     geo.get("isp", vpn_name),
                        "cc":      cc,
                    }
                    self._write_log_safe(
                        f"✅ VPN активний — IP: {public_ip}, "
                        f"Країна: {geo.get('country', cc)}")
            except Exception as e:
                self._write_log_safe(f"⚠️ Помилка отримання геоданих: {e}")

        threading.Thread(target=_fetch_real_data, daemon=True).start()

    def _update_external_ip_panel(self, public_ip: str, geo: dict):
        """Оновлює IP-чіпи коли VPN запущено зовнішньо."""
        try: self._ip_lbl.configure(text=public_ip)
        except Exception: pass
        try:
            country = geo.get("country", "?")
            city = geo.get("city", "")
            loc_text = f"{country}{', ' + city if city else ''}"
            self._loc_lbl.configure(text=loc_text)
        except Exception: pass
        try: self._enc_lbl.configure(text="AES-256")
        except Exception: pass
        try: self._dns_lbl.configure(text="OK")
        except Exception: pass

    def _on_external_vpn_disconnected(self):
        self._ext_vpn_state = {"active": False}
        try:
            self._set_state_ui(ConnectionState.DISCONNECTED)
            self.world_map.clear_location()
            self._reset_ip_panel()
        except Exception: pass

    # ─────────────────────────────────────────────────────────────────────────
    #  NETWORK CHANGE WATCHER
    # ─────────────────────────────────────────────────────────────────────────

    def _start_network_change_watcher(self):
        """Раз на 15с перевіряє чи змінилась Wi-Fi мережа.
        При зміні — автоматично запускає VPN БЕЗ діалогу.
        """
        def _loop():
            time.sleep(5)
            try:
                self._last_network_id = self._get_current_network_id()
                print(f"[NetworkWatcher] baseline: '{self._last_network_id}'")
            except Exception:
                pass
            time.sleep(15)
            while True:
                try:
                    current = self._get_current_network_id()
                    if current and current != self._last_network_id:
                        old_net = self._last_network_id or "(none)"
                        self._last_network_id = current
                        self._write_log_safe(f"🔄 Зміна мережі: {old_net} → {current}")
                        self.after(0, lambda c=current: self._prompt_vpn_for_network(c))
                except Exception as e:
                    print(f"[NetworkWatcher] {e}")
                time.sleep(15)

        threading.Thread(target=_loop, daemon=True, name="NetworkWatcher").start()
        print("[VpnUI] ✅ Network change watcher запущено (авто-підключення)")

    def _auto_connect_on_network_change(self, network_name: str):
        """Авто-підключення при зміні мережі — БЕЗ діалогу."""
        # Якщо VPN вже активний — нічого не робимо
        if getattr(self, "_ext_vpn_state", {}).get("active"):
            self._write_log(f"ℹ️ VPN вже активний для мережі '{network_name}'")
            return
        if self._detected_vpn_process:
            return
        if self._vpn_launching:
            return

        self._write_log(f"🤖 Авто-VPN: нова мережа '{network_name}' — запускаю VPN...")

        def _scan_and_launch():
            try:
                installed = self._find_installed_vpns()
                if installed:
                    # Беремо перший знайдений без діалогу
                    name, path = installed[0]
                    self._write_log_safe(f"🚀 Авто-VPN запускає: {name}")
                    self.after(0, lambda n=name, p=path:
                               self._activate_app_based_auto_vpn(n, p))
                elif self.engine.profiles:
                    self._write_log_safe("🚀 Авто-VPN підключається через профіль")
                    self._activate_profile_based_auto_vpn()
                else:
                    self._write_log_safe(
                        f"ℹ️ Авто-VPN: VPN не знайдено для мережі '{network_name}'")
            except Exception as e:
                self._write_log_safe(f"❌ Авто-VPN помилка: {e}")

        threading.Thread(target=_scan_and_launch, daemon=True).start()

    def _get_current_network_id(self) -> Optional[str]:
        try:
            import platform
            if platform.system() != "Windows":
                return None
            import subprocess
            r = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True, text=True, timeout=5,
                encoding="cp866", errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            ssid = None
            state = None
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if line.lower().startswith("ssid") and ":" in line and \
                        not line.lower().startswith("bssid"):
                    ssid = line.split(":", 1)[1].strip()
                if (line.lower().startswith("state") or
                        "состояние" in line.lower() or "стан" in line.lower()):
                    state = line.split(":", 1)[1].strip() if ":" in line else ""
            if ssid and "connected" in (state or "").lower():
                return ssid
            if ssid and "підключ" in (state or "").lower():
                return ssid
            return ssid
        except Exception:
            return None

    def _send_tg_notification(self, text: str):
        try:
            from pathlib import Path
            import json, time as _t
            pending_dir = Path.home() / ".netguardian" / "pending_tg"
            pending_dir.mkdir(parents=True, exist_ok=True)
            fname = f"vpn_alert_{int(_t.time()*1000)}.json"
            with open(pending_dir / fname, "w", encoding="utf-8") as f:
                json.dump({"text": text, "from": "vpn_ui"}, f, ensure_ascii=False)
            print(f"[VpnUI] 📨 TG notification queued: {fname}")
        except Exception as e:
            print(f"[VpnUI] TG queue error: {e}")

    def _prompt_vpn_for_network(self, network_name: str):
        """PR #21: Стильний popup при зміні мережі."""
        if self._detected_vpn_process:
            self._write_log(f"ℹ️ VPN вже активний — пропуск пропозиції")
            return
        state = getattr(self, "_ext_vpn_state", {})
        if state.get("active"):
            self._write_log(f"ℹ️ VPN вже активний — пропуск пропозиції для '{network_name}'")
            return

        installed = []
        try:
            installed = self._find_installed_vpns()
        except Exception: pass

        tg_text = (
            f"🔄 *Зміна мережі виявлена*\n\n"
            f"📶 Нова мережа: `{network_name}`\n\n"
        )
        if installed:
            tg_text += (f"✅ На ПК доступно {len(installed)} VPN-додатків.\n"
                        f"_NetGuardian рекомендує увімкнути VPN для безпеки._")
        elif self.engine.profiles:
            tg_text += (f"📁 Доступно {len(self.engine.profiles)} VPN-профілів.\n"
                        f"_NetGuardian рекомендує підключитись._")
        else:
            tg_text += (f"⚠️ VPN-додатки на ПК не знайдено.\n"
                        f"_Рекомендується встановити VPN._")
        self._send_tg_notification(tg_text)

        dlg = ctk.CTkToplevel(self)
        dlg.title("🔐 NetGuardian — пропозиція безпеки")
        dlg.geometry("540x440")
        dlg.transient(self.winfo_toplevel())
        dlg.grab_set()
        dlg.configure(fg_color=COLORS.get("bg_primary", "#0a0f1a"))

        dlg.update_idletasks()
        try:
            parent_x = self.winfo_toplevel().winfo_x()
            parent_y = self.winfo_toplevel().winfo_y()
            parent_w = self.winfo_toplevel().winfo_width()
            parent_h = self.winfo_toplevel().winfo_height()
            x = parent_x + (parent_w - 540) // 2
            y = parent_y + (parent_h - 440) // 2
            dlg.geometry(f"540x440+{x}+{y}")
        except Exception: pass

        header = ctk.CTkFrame(dlg, fg_color="#0a1a2a", corner_radius=0, height=80)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(header, text="🔐", font=ctk.CTkFont(size=42)).pack(
            side="left", padx=(24, 14), pady=14)
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", fill="both", expand=True)
        ctk.CTkLabel(title_frame, text="NetGuardian Security",
                     font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
                     text_color=COLORS.get("accent_cyan", "#22d3ee"),
                     anchor="w").pack(anchor="w", pady=(18, 0))
        ctk.CTkLabel(title_frame, text="Виявлено зміну мережі",
                     font=ctk.CTkFont(family="Consolas", size=12),
                     text_color=COLORS.get("text_secondary", "#94a3b8"),
                     anchor="w").pack(anchor="w")

        body = ctk.CTkFrame(dlg, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=24, pady=(20, 0))

        net_card = ctk.CTkFrame(body, fg_color="#0a1a2a", corner_radius=10,
                                border_width=1,
                                border_color=COLORS.get("accent_cyan", "#22d3ee"))
        net_card.pack(fill="x", pady=(0, 16))
        ctk.CTkLabel(net_card, text=f"📶  {network_name}",
                     font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
                     text_color="#ffffff").pack(pady=14)

        if installed:
            desc = (f"Для вашої безпеки рекомендуємо увімкнути VPN.\n\n"
                    f"✅ На ПК знайдено {len(installed)} VPN-додатків.\n"
                    f"Бажаєте обрати один з них?")
            accent = COLORS.get("accent_green", "#22c55e")
        elif self.engine.profiles:
            desc = (f"Для вашої безпеки рекомендуємо увімкнути VPN.\n\n"
                    f"📁 Доступно {len(self.engine.profiles)} VPN-профілів.\n"
                    f"Підключитись до найкращого зараз?")
            accent = COLORS.get("accent_yellow", "#eab308")
        else:
            desc = (f"Для вашої безпеки рекомендуємо увімкнути VPN.\n\n"
                    f"⚠️ VPN-додатки на ПК не знайдено.\n"
                    f"Бажаєте обрати .exe файл VPN-клієнта?")
            accent = COLORS.get("accent_red", "#ef4444")

        ctk.CTkLabel(body, text=desc,
                     font=ctk.CTkFont(family="Consolas", size=13),
                     text_color=COLORS.get("text_primary", "#e0f0ff"),
                     justify="left", anchor="w").pack(fill="x", pady=(0, 20))

        btn_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        btn_frame.pack(side="bottom", fill="x", padx=24, pady=(0, 24))
        user_choice = {"connect": False}

        def _on_yes():
            user_choice["connect"] = True
            dlg.destroy()

        def _on_no():
            user_choice["connect"] = False
            dlg.destroy()

        ctk.CTkButton(btn_frame, text="✅  УВІМКНУТИ VPN", command=_on_yes,
                      fg_color=accent, hover_color="#16a34a", text_color="#0a0e1a",
                      font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                      height=46, corner_radius=10).pack(side="right", padx=(8, 0))
        ctk.CTkButton(btn_frame, text="⏭  ПРОПУСТИТИ", command=_on_no,
                      fg_color="transparent", hover_color="#1a1a2e",
                      text_color=COLORS.get("text_dim", "#94a3b8"),
                      border_width=2, border_color=COLORS.get("border", "#1e3040"),
                      font=ctk.CTkFont(family="Consolas", size=14),
                      height=46, corner_radius=10).pack(side="right")

        dlg.wait_window()

        if not user_choice["connect"]:
            self._write_log(f"ℹ️ Юзер відхилив пропозицію VPN для '{network_name}'")
            return

        if installed:
            self._show_auto_vpn_app_picker(installed)
        elif self.engine.profiles:
            self._activate_profile_based_auto_vpn()
        else:
            self._launch_custom_exe()

    # ─────────────────────────────────────────────────────────────────────────
    #  STATS POLLING
    # ─────────────────────────────────────────────────────────────────────────

    def _start_stats_poll(self):
        self._stats_poll_running = True
        self._poll_stats()

    def _poll_stats(self):
        if not self._stats_poll_running:
            return
        stats = self.engine.get_stats_snapshot()

        def fmt_bytes(b: int) -> str:
            if b < 1024:
                return f"{b} B"
            elif b < 1024 ** 2:
                return f"{b / 1024:.1f} KB"
            return f"{b / 1024 ** 2:.2f} MB"

        def fmt_speed(kbps: float) -> str:
            if kbps < 1000:
                return f"{kbps:.1f} KB/s"
            return f"{kbps / 1024:.2f} MB/s"

        if stats.state == ConnectionState.CONNECTED:
            self.stat_down.configure(text=fmt_speed(stats.rx_speed_kbps))
            self.stat_up.configure(text=fmt_speed(stats.tx_speed_kbps))
            self.stat_rx.configure(text=fmt_bytes(stats.rx_bytes))
            self.stat_tx.configure(text=fmt_bytes(stats.tx_bytes))
            self.stat_up_tm.configure(text=self.engine.get_uptime_str())
        elif self._detected_vpn_process or getattr(self, "_ext_vpn_state", {}).get("active", False):
            try:
                rx, tx, rx_speed, tx_speed = self._get_system_net_stats()
                self.stat_down.configure(text=fmt_speed(rx_speed))
                self.stat_up.configure(text=fmt_speed(tx_speed))
                self.stat_rx.configure(text=fmt_bytes(rx))
                self.stat_tx.configure(text=fmt_bytes(tx))
                if not hasattr(self, "_external_vpn_started_at"):
                    self._external_vpn_started_at = time.time()
                up = int(time.time() - self._external_vpn_started_at)
                h, r = divmod(up, 3600); m, s = divmod(r, 60)
                self.stat_up_tm.configure(text=f"{h:02d}:{m:02d}:{s:02d}")
            except Exception:
                for lbl in (self.stat_down, self.stat_up, self.stat_rx,
                            self.stat_tx, self.stat_up_tm):
                    lbl.configure(text="—")
        else:
            try:
                rx, tx, rx_speed, tx_speed = self._get_system_net_stats()
                self.stat_down.configure(text=fmt_speed(rx_speed))
                self.stat_up.configure(text=fmt_speed(tx_speed))
                self.stat_rx.configure(text=fmt_bytes(rx))
                self.stat_tx.configure(text=fmt_bytes(tx))
                self.stat_up_tm.configure(text="(не активний)")
                if hasattr(self, "_external_vpn_started_at"):
                    delattr(self, "_external_vpn_started_at")
            except Exception:
                for lbl in (self.stat_down, self.stat_up, self.stat_rx,
                            self.stat_tx, self.stat_up_tm):
                    lbl.configure(text="—")

        # ── ВИПРАВЛЕННЯ БАГ #1 ──────────────────────────────────────────────
        # Не перезаписуємо стан якщо зовнішній VPN активний.
        ext_active = getattr(self, "_ext_vpn_state", {}).get("active", False)
        if not ext_active:
            self._set_state_ui(stats.state)

        self.after(self.POLL_INTERVAL_MS, self._poll_stats)

    def _get_system_net_stats(self) -> tuple:
        try:
            import psutil
            io = psutil.net_io_counters()
            rx = io.bytes_recv
            tx = io.bytes_sent
            now = time.time()
            prev_rx = getattr(self, "_prev_net_rx", rx)
            prev_tx = getattr(self, "_prev_net_tx", tx)
            prev_t  = getattr(self, "_prev_net_t", now)
            dt = max(0.1, now - prev_t)
            rx_speed = max(0, (rx - prev_rx)) / dt / 1024.0
            tx_speed = max(0, (tx - prev_tx)) / dt / 1024.0
            self._prev_net_rx = rx
            self._prev_net_tx = tx
            self._prev_net_t = now
            return rx, tx, rx_speed, tx_speed
        except Exception:
            return 0, 0, 0.0, 0.0

    # ─────────────────────────────────────────────────────────────────────────
    #  UI HELPERS
    # ─────────────────────────────────────────────────────────────────────────

    def _set_state_ui(self, state: ConnectionState):
        text, color = STATE_STYLE.get(
            state,
            ("⬤  НЕВІДОМО", COLORS.get("text_dim", "#2a4a5a"))
        )
        self.state_label.configure(text=text, text_color=color)
        if state == ConnectionState.CONNECTED:
            self.btn_disconnect.configure(state="normal")
            self.btn_quick.configure(state="disabled")
        else:
            self.btn_disconnect.configure(state="disabled")
            self.btn_quick.configure(state="normal")

    def _update_ip_panel(self, stats, geo: dict):
        hidden = "🔒 Сховано"
        self._ip_lbl.configure(
            text=hidden, text_color=COLORS.get("accent_green", "#00ff88"))
        self._loc_lbl.configure(
            text=f"{geo['flag']} {geo['city']}, {geo['country']}",
            text_color=COLORS.get("accent_cyan", "#00d4ff"))
        proto = ""
        active = self.engine.profiles.get(stats.active_profile or "")
        if active:
            proto = "ChaCha20" if active.protocol == VpnProtocol.WIREGUARD else "AES-256"
        self._enc_lbl.configure(
            text=proto or "AES-256",
            text_color=COLORS.get("accent_green", "#00ff88"))
        dns_text = "Safe ✅" if stats.dns_leak_safe else "LEAK ⚠️"
        dns_color = (COLORS.get("accent_green", "#00ff88")
                     if stats.dns_leak_safe
                     else COLORS.get("accent_red", "#ff4060"))
        self._dns_lbl.configure(text=dns_text, text_color=dns_color)

        cc = (geo.get("country_code") or geo.get("countryCode") or "")
        if not cc and geo.get("country"):
            country_to_iso = {
                "united states": "US", "united kingdom": "GB",
                "germany": "DE", "netherlands": "NL", "france": "FR",
                "switzerland": "CH", "sweden": "SE", "norway": "NO",
                "finland": "FI", "denmark": "DK", "russia": "RU",
                "poland": "PL", "czech": "CZ", "romania": "RO",
                "hungary": "HU", "italy": "IT", "spain": "ES",
                "portugal": "PT", "ireland": "IE", "belgium": "BE",
                "japan": "JP", "korea": "KR", "china": "CN",
                "singapore": "SG", "india": "IN", "hong kong": "HK",
                "australia": "AU", "brazil": "BR", "canada": "CA",
                "ukraine": "UA", "turkey": "TR", "israel": "IL",
                "austria": "AT",
            }
            cc = country_to_iso.get(geo["country"].lower(), "")
        cc = cc[:2].upper() if cc else ""
        if cc:
            self.world_map.set_location(cc)
            print(f"[VpnUI] 🗺️ Map → {cc} ({geo.get('country', '?')})")
        else:
            print(f"[VpnUI] ⚠️ Не вдалось визначити країну з geo={geo}")

        self._ext_vpn_state = {
            "active":  True,
            "ip":      stats.public_ip_after or "—",
            "country": geo.get("country", "—"),
            "city":    geo.get("city", ""),
            "isp":     geo.get("isp", ""),
            "cc":      cc or "US",
        }

    def _reset_ip_panel(self):
        for lbl in (self._ip_lbl, self._loc_lbl, self._enc_lbl, self._dns_lbl):
            lbl.configure(text="—",
                          text_color=COLORS.get("text_secondary", "#607080"))

    # ─────────────────────────────────────────────────────────────────────────
    #  LOG
    # ─────────────────────────────────────────────────────────────────────────

    def _write_log(self, text: str):
        ts = time.strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {text}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _write_log_safe(self, text: str):
        """Thread-safe wrapper."""
        self.after(0, lambda t=text: self._write_log(t))

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")