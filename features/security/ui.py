import socket
"""
NetGuardian AI — LAN Security Audit UI v6.4
"""

import re
import threading
import time
import tkinter as tk
import tkinter.messagebox as mb
import concurrent.futures as _cf
import customtkinter as ctk

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.security.lan_security import (
    LanSecurityEngine, CRITICAL_PORTS, DANGEROUS_PORTS, trust_db,
    RouterClientReader
)
from features.security.lan_monitor import (
    get_device_display_name, get_device_icon,
    get_device_threat_summary, format_device_card
)


# ══════════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════════
def _threat_style(threat: str, is_trusted: bool = False,
                  alert_dismissed: bool = False) -> tuple:
    if is_trusted or alert_dismissed:
        return (COLORS.get("bg_card", "#1a1a2e"), COLORS.get("accent_green", "#00ff88"))
    return {
        "critical": ("#240000", "#ff2020"),
        "danger":   ("#1f0000", "#ff4444"),
        "warn":     ("#1e1400", "#ffd700"),
        "safe":     ("transparent", COLORS.get("border", "#2a2a4a")),
    }.get(threat, ("transparent", COLORS.get("border", "#2a2a4a")))


def _port_color(port: int) -> str:
    if port in DANGEROUS_PORTS:
        return COLORS.get("accent_red",    "#ff4444")
    if port in {25, 110, 8080, 9100}:
        return COLORS.get("accent_yellow", "#ffd700")
    return COLORS.get("accent_green", "#00ff88")


def _time_ago(ts: float) -> str:
    if not ts: return "—"
    diff = time.time() - ts
    if diff < 60:    return "щойно"
    if diff < 3600:  return f"{int(diff/60)} хв тому"
    if diff < 86400: return f"{int(diff/3600)} год тому"
    return f"{int(diff/86400)} дн тому"


def _signal_bar_widget(pct) -> tuple:
    if pct is None:
        return ("", COLORS.get("text_dim", "#444466"))
    pct   = int(pct)
    bars  = max(0, min(5, int(pct / 20)))
    bar   = "█" * bars + "░" * (5 - bars)
    color = (COLORS.get("accent_green","#00ff88")  if pct >= 70 else
             COLORS.get("accent_yellow","#ffd700") if pct >= 40 else
             COLORS.get("accent_red","#ff4444"))
    return (f"{bar} {pct}%", color)


def _device_sort_key(d: dict) -> tuple:
    threat = d.get("threat", "safe")
    threat_rank = (0 if threat in ("critical","danger")
                   and not d.get("alert_dismissed")
                   and not d.get("is_trusted") else 1)
    if d.get("is_gateway"):   cat = 1
    elif d.get("is_self"):    cat = 2
    else:
        icon    = d.get("icon","❓")
        devtype = (d.get("dev_type") or "").lower()
        if icon in ("💻",) or any(k in devtype for k in ("ноутбук","macbook","laptop","windows pc")): cat = 3
        elif icon == "🖥️": cat = 3
        elif icon == "📱" or any(k in devtype for k in ("phone","iphone","ipad","galaxy","смартфон","android","pixel","xiaomi","huawei","samsung")): cat = 4
        elif icon in ("📺","🎮","🔊"): cat = 5
        elif icon in ("🖨️","📷"): cat = 6
        else: cat = 7
    try:
        ip_parts = tuple(int(x) for x in d.get("ip","0.0.0.0").split("."))
    except Exception:
        ip_parts = (0,0,0,0)
    return (threat_rank, cat, ip_parts)


def _mac_tail(mac: str) -> str:
    """Повертає 3 останні байти MAC у форматі 'AABBCC' для унікальної ідентифікації."""
    if not mac or mac == "—":
        return ""
    try:
        cleaned = mac.replace(":", "").replace("-", "").upper()
        if len(cleaned) >= 6:
            return cleaned[-6:]
    except Exception:
        pass
    return ""


def _vendor_short(vendor: str) -> str:
    """Скорочує vendor до першого слова для компактності (напр. 'Samsung Electronics Co., Ltd' → 'Samsung')."""
    if not vendor:
        return ""
    # Беремо першу частину до коми, крапки або дужки
    cut = re.split(r"[,\.\(]", vendor, 1)[0].strip()
    # Якщо перше слово — беремо тільки його
    first_word = cut.split()[0] if cut.split() else cut
    # Перевірка на знайомі префікси
    known_short = {
        "apple": "Apple", "samsung": "Samsung", "xiaomi": "Xiaomi",
        "huawei": "Huawei", "google": "Google", "amazon": "Amazon",
        "microsoft": "Microsoft", "sony": "Sony", "lg": "LG",
        "dell": "Dell", "hp": "HP", "lenovo": "Lenovo", "asus": "ASUS",
        "acer": "Acer", "msi": "MSI", "gigabyte": "Gigabyte",
        "tp-link": "TP-Link", "d-link": "D-Link", "netgear": "Netgear",
        "mikrotik": "MikroTik", "ubiquiti": "Ubiquiti", "cisco": "Cisco",
        "zyxel": "ZyXEL", "realtek": "Realtek", "intel": "Intel",
        "qualcomm": "Qualcomm", "broadcom": "Broadcom",
    }
    low = first_word.lower().rstrip(",.")
    if low in known_short:
        return known_short[low]
    return first_word[:15] if first_word else ""


def _best_device_label(host: dict) -> str:
    """
    DEPRECATED — цей обгорточний метод лишається для backwards compat.
    Справжня логіка тепер у features.security.lan_monitor.get_device_display_name()
    яку імпортує бот і інші компоненти.
    """
    from features.security.lan_monitor import get_device_display_name
    return get_device_display_name(host)


def _legacy_best_device_label_backup(host: dict) -> str:
    if host.get("user_label"):
        return host["user_label"]

    # Tapo Smart-пристрої: HTTP Server header = "SHIP" (фірмовий сервер TP-Link Tapo)
    http_server = (host.get("http_server") or "").strip()
    if http_server.upper().startswith("SHIP"):
        vendor = (host.get("vendor") or "").strip()
        mac    = host.get("mac", "")
        tail   = _mac_tail(mac)
        # Пробуємо різні сигнатури для визначення моделі Tapo
        ports  = host.get("open_ports", [])
        # Визначаємо тип Tapo за поведінкою
        if 443 in ports and 80 in ports:
            base = "Tapo Smart Plug"        # P100/P110/P115 — розетки
        elif 554 in ports or 2020 in ports:
            base = "Tapo Camera"            # C100/C200/C310
        else:
            base = "Tapo пристрій"
        return f"{base}-{tail}" if tail else base

    hostname = (host.get("hostname") or "").strip()
    if hostname and hostname not in ("—", "N/A", "unknown", "localhost") \
            and not _looks_like_ip(hostname):
        if not host.get("phone_name") and not host.get("phone_model"):
            return hostname
    if host.get("phone_model"):
        brand = host.get("phone_brand", "")
        model = host["phone_model"]
        return f"{brand} {model}".strip() if brand and brand not in model else model

    if host.get("phone_name"):
        pn = host["phone_name"]
        # Пропускаємо generic android-xxxxxx hostname
        if not re.match(r"^android-[0-9a-f]{6,}$", pn, re.IGNORECASE):
            return pn

    # Якщо є phone_brand але немає моделі — показуємо бренд + загальну назву
    if host.get("phone_brand"):
        brand  = host["phone_brand"]
        os_ver = (host.get("phone_os") or "").strip()
        if brand in ("Apple",):
            return "Apple iPhone"
        if brand == "Android":
            if os_ver and os_ver != "Android":
                return f"Android-смартфон  [{os_ver}]"
            return "Android-смартфон"
        if brand == "Android TV":
            return "Android TV / Google TV"
        # Samsung/Xiaomi/Huawei/etc без конкретної моделі
        return f"{brand} (смартфон)"
    ssh_hn = (host.get("ssh_hostname") or "").strip()
    if ssh_hn and ssh_hn not in ("—", "N/A", "unknown", "*"):
        return ssh_hn
    for key in ("dhcp_hostname", "mdns_name", "netbios_name", "upnp_name"):
        val = (host.get(key) or "").strip()
        if val and val not in ("—", "N/A", "unknown", "*"):
            return val

    # Reverse DNS fallback (якщо scanner його зібрав)
    rdns = (host.get("reverse_dns") or "").strip()
    if rdns and rdns not in ("—", "N/A") and not _looks_like_ip(rdns):
        # Обрізаємо до hostname без домену, якщо занадто довго
        short = rdns.split(".")[0] if len(rdns) > 30 else rdns
        return short

    if hostname and hostname not in ("—", "N/A", "unknown", "localhost") \
            and not _looks_like_ip(hostname):
        return hostname
    cert = (host.get("cert_cn") or "").strip()
    if cert and cert not in ("—", "N/A") and not _looks_like_ip(cert) and len(cert) > 4:
        return cert
    snmp = (host.get("snmp_sysdescr") or "").strip()
    if snmp and len(snmp) > 6:
        first = snmp.split("\n")[0][:50].strip()
        if first:
            return first
    vendor  = (host.get("vendor")   or "").strip()
    devtype = (host.get("dev_type") or "").strip()
    mac     = host.get("mac", "")
    tail    = _mac_tail(mac)

    # "Приватний MAC" — додаємо MAC-tail для унікальної ідентифікації
    # Без цього всі Android/iPhone з рандомізацією матимуть однакову назву "Смартфон (Приватний MAC)"
    # і їх неможливо розрізнити
    if vendor == "Приватний MAC":
        suffix = f"-{tail}" if tail else ""
        # Підказки з open ports та phone_brand — якщо є
        brand = (host.get("phone_brand") or "").strip()
        if brand:
            return f"{brand}{suffix} (Приватний MAC)"
        # Evristika по портам:
        ports = host.get("open_ports", [])
        if 62078 in ports:                  # iTunes Sync port = iPhone/iPad
            return f"iPhone/iPad{suffix} (Приватний MAC)"
        if 5555 in ports:                   # ADB = Android
            return f"Android{suffix} (Приватний MAC)"
        if devtype and devtype not in ("—", "N/A", "Пристрій", "Смартфон"):
            return f"{devtype}{suffix} (Приватний MAC)"
        return f"Смартфон{suffix} (Приватний MAC)"

    # Новий покращений fallback: Vendor-MACTAIL (напр. "Samsung-AABBCC")
    # Це дає унікальну назву для КОЖНОГО пристрою, навіть коли нічого не знайшли
    if vendor and vendor not in ("—", "N/A", "Невідомо"):
        short_v = _vendor_short(vendor)
        if tail and short_v:
            # Додаємо devtype якщо він інформативний
            if devtype and devtype not in ("—", "N/A", "Пристрій"):
                return f"{short_v}-{tail} ({devtype})"
            return f"{short_v}-{tail}"
        # Якщо немає mac-хвоста — показуємо vendor як раніше
        if devtype and devtype not in ("—", "N/A", "Пристрій"):
            return f"{vendor} ({devtype})"
        return vendor

    # Random MAC без vendor — використовуємо MAC tail + іконку
    if _is_random_mac(mac):
        ico   = get_device_icon(host)
        brand = (host.get("phone_brand") or "").strip()
        suffix = f"-{tail}" if tail else ""
        # Evristika по портам:
        ports = host.get("open_ports", [])
        if 62078 in ports:
            return f"iPhone/iPad{suffix} (Приватний MAC)"
        if 5555 in ports:
            return f"Android{suffix} (Приватний MAC)"
        if brand:       return f"{brand}{suffix} (Приватний MAC)"
        if ico == "📱": return f"Смартфон{suffix} (Приватний MAC)"
        if ico == "💻": return f"Ноутбук{suffix} (Приватний MAC)"
        return f"Пристрій{suffix} (Приватний MAC)"

    # Остання зачіпка — MAC-тейл без vendor
    if tail:
        return f"Пристрій-{tail}"
    return host.get("ip") or "Невідомий пристрій"


def _name_source_badge(host: dict) -> tuple:
    if host.get("user_label"):
        return "✏️ ", COLORS.get("accent_green","#00ff88")
    if host.get("phone_name"):
        src = host.get("phone_id_method","")
        if "AirPlay" in src: return "AirPlay", COLORS.get("accent_cyan","#00d4ff")
        if "mDNS"    in src: return "mDNS",    COLORS.get("accent_cyan","#00d4ff")
        if "SSH"     in src: return "★SSH",    COLORS.get("accent_green","#00ff88")
        if "DHCP"    in src: return "DHCP",    COLORS.get("accent_cyan","#00d4ff")
        return "📱", COLORS.get("accent_cyan","#00d4ff")
    if host.get("phone_model"):
        return "OUI/UPnP", COLORS.get("text_secondary","#8888aa")
    if (host.get("ssh_hostname") or "").strip() not in ("","—","*"):
        return "★SSH", COLORS.get("accent_green","#00ff88")
    if (host.get("dhcp_hostname") or "").strip() not in ("","—"):
        src = host.get("dhcp_source","")
        label = "DHCP"
        if "Keenetic" in src: label = "Keenetic"
        elif "TP-Link" in src: label = "TP-Link"
        elif "MikroTik" in src: label = "MikroTik"
        elif "ASUS" in src: label = "ASUS"
        return label, COLORS.get("accent_cyan","#00d4ff")
    if (host.get("mdns_name") or "").strip():
        return "mDNS", COLORS.get("accent_cyan","#00d4ff")
    if (host.get("netbios_name") or "").strip():
        return "NetBIOS", COLORS.get("text_secondary","#8888aa")
    return "", ""


def _looks_like_ip(s: str) -> bool:
    import re
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s.strip()))


def _is_random_mac(mac: str) -> bool:
    if not mac or len(mac) < 2: return False
    try:
        return bool(int(mac.replace("-",":").split(":")[0], 16) & 0x02)
    except ValueError:
        return False


# ══════════════════════════════════════════════════════════════════
# FIX-5 — КАСТОМНИЙ CANVAS SCROLLBAR (у стилі утиліти)
# ══════════════════════════════════════════════════════════════════
class CyanScrollbar(tk.Canvas):
    """
    Canvas-based scrollbar повністю у стилі утиліти:
    тьмяний трек + cyan повзунок із заокругленими кутами.
    Замінює стандартний tk.Scrollbar що не підтримує стилізацію на Windows.
    """

    def __init__(self, parent, command=None, **kw):
        trough = COLORS.get("bg_secondary", "#0d0d1a")
        super().__init__(parent, width=10, bg=trough,
                         highlightthickness=0, bd=0, **kw)
        self._command       = command
        self._thumb_start   = 0.0
        self._thumb_end     = 1.0
        self._dragging      = False
        self._drag_y        = 0
        self._drag_ts       = 0.0
        self._hover         = False

        self.bind("<Configure>",      lambda e: self._draw())
        self.bind("<ButtonPress-1>",  self._on_press)
        self.bind("<B1-Motion>",      self._on_drag)
        self.bind("<ButtonRelease-1>",self._on_release)
        self.bind("<Enter>",          lambda e: self._set_hover(True))
        self.bind("<Leave>",          lambda e: self._set_hover(False))

    # public API — duck-typing для yscrollcommand
    def set(self, first, last):
        self._thumb_start = float(first)
        self._thumb_end   = float(last)
        self._draw()

    def _set_hover(self, val: bool):
        self._hover = val
        self._draw()

    def _draw(self):
        self.delete("all")
        w  = self.winfo_width()  or 10
        h  = self.winfo_height() or 300
        trough = COLORS.get("bg_secondary",  "#0d0d1a")
        thumb  = COLORS.get("accent_cyan",   "#00d4ff")
        thumb_h= COLORS.get("accent_cyan",   "#00a8cc")  # hover
        pad    = 2

        # Трек
        self.create_rectangle(0, 0, w, h, fill=trough, outline="")

        # Повзунок
        ty1 = max(pad, int(h * self._thumb_start) + pad)
        ty2 = min(h - pad, int(h * self._thumb_end) - pad)
        if ty2 - ty1 < 16:
            ty2 = min(h - pad, ty1 + 16)

        col  = thumb_h if self._hover or self._dragging else thumb
        r    = (w - 4) // 2  # радіус округлення
        x1, x2 = 2, w - 2
        self._round_rect(x1, ty1, x2, ty2, radius=r, fill=col, outline="")

        # Зберігаємо координати для click-detection
        self._ty1 = ty1
        self._ty2 = ty2

    def _round_rect(self, x1, y1, x2, y2, radius=4, **kw):
        r = min(radius, (x2-x1)//2, (y2-y1)//2)
        pts = [
            x1+r, y1,   x2-r, y1,   x2, y1,
            x2, y1+r,   x2, y2-r,   x2, y2,
            x2-r, y2,   x1+r, y2,   x1, y2,
            x1, y2-r,   x1, y1+r,   x1, y1,
        ]
        self.create_polygon(pts, smooth=True, **kw)

    def _on_press(self, event):
        y  = event.y
        h  = self.winfo_height()
        ty1, ty2 = getattr(self, "_ty1", 0), getattr(self, "_ty2", h)
        if ty1 <= y <= ty2:
            self._dragging    = True
            self._drag_y      = y
            self._drag_ts     = self._thumb_start
        else:
            # Клік на треку — гортаємо
            if self._command:
                units = -5 if y < ty1 else 5
                self._command("scroll", units, "units")

    def _on_drag(self, event):
        if not self._dragging: return
        h     = self.winfo_height() or 1
        delta = (event.y - self._drag_y) / h
        new   = max(0.0, min(1.0, self._drag_ts + delta))
        if self._command:
            self._command("moveto", str(new))
        self._draw()

    def _on_release(self, event):
        self._dragging = False
        self._draw()


# ══════════════════════════════════════════════════════════════════
# FIX-3 — SCAN TOAST (маленький тост для фонового авто-скану)
# ══════════════════════════════════════════════════════════════════
class ScanToast:
    """
    Маленький тост-сповіщення знизу праворуч під час авто-сканування.
    Список пристроїв залишається видимим.
    """
    _SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, parent):
        self._parent   = parent
        self._frame    = None
        self._spin_job = None
        self._tick     = 0
        self._lbl      = None

    def show(self):
        self._destroy()
        cyan   = COLORS.get("accent_cyan",  "#00d4ff")
        bg     = COLORS.get("bg_card",      "#1a1a2e")
        border = COLORS.get("border",        "#2a2a4a")
        dim    = COLORS.get("text_dim",      "#444466")

        self._frame = ctk.CTkFrame(self._parent,
            fg_color=bg, corner_radius=10,
            border_width=1, border_color=cyan)
        self._frame.place(relx=1.0, rely=1.0, anchor="se", x=-20, y=-20)
        self._frame.lift()

        inner = ctk.CTkFrame(self._frame, fg_color="transparent")
        inner.pack(padx=14, pady=10)

        self._spin_lbl = ctk.CTkLabel(inner, text="⠋",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=cyan)
        self._spin_lbl.pack(side="left", padx=(0, 8))

        self._lbl = ctk.CTkLabel(inner,
            text="Оновлення списку…",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=dim)
        self._lbl.pack(side="left")

        self._tick = 0
        self._animate()

    def update(self, text: str):
        if not self._frame or not self._lbl: return
        try:
            # Показуємо тільки коротку версію
            short = text.strip()[:55]
            self._lbl.configure(text=short or "Оновлення списку…")
        except Exception:
            pass

    def done(self, found_count: int):
        """Оновлює текст після завершення сканування."""
        if not self._frame or not self._lbl: return
        try:
            green = COLORS.get("accent_green", "#00ff88")
            self._spin_lbl.configure(text="✅", text_color=green)
            self._lbl.configure(text=f"Оновлено · {found_count} пристроїв")
            # Автозакриття через 4 сек
            self._frame.after(4000, self._destroy)
        except Exception:
            pass

    def hide(self):
        self._destroy()

    def _animate(self):
        if not self._frame: return
        try:
            self._spin_lbl.configure(text=self._SPIN[self._tick % len(self._SPIN)])
        except Exception:
            return
        self._tick += 1
        self._spin_job = self._frame.after(80, self._animate)

    def _destroy(self):
        if self._spin_job:
            try:
                if self._frame:
                    self._frame.after_cancel(self._spin_job)
            except Exception:
                pass
            self._spin_job = None
        if self._frame:
            try:
                self._frame.destroy()
            except Exception:
                pass
            self._frame = None


def _bring_to_front(win):
    """
    Виводить вікно tkinter/customtkinter на передній план у Windows.
    Використовує FindWindowW → SetForegroundWindow + SetWindowPos.
    """
    try:
        win.attributes("-topmost", True)
        win.lift()
        win.update()
        import platform as _plt
        if _plt.system() == "Windows":
            import ctypes as _ct
            title = win.title()
            hwnd  = _ct.windll.user32.FindWindowW(None, title)
            if hwnd:
                _ct.windll.user32.ShowWindow(hwnd, 9)          # SW_RESTORE
                _ct.windll.user32.SetForegroundWindow(hwnd)
                _ct.windll.user32.SetWindowPos(hwnd, -1, 0, 0, 0, 0, 3)  # TOPMOST
                _ct.windll.user32.BringWindowToTop(hwnd)
                _ct.windll.user32.SetActiveWindow(hwnd)
        win.focus_force()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════
# TOGGLE BUTTON — PILL SLIDER
# ══════════════════════════════════════════════════════════════════
class ToggleButton(ctk.CTkFrame):
    _TRACK_W = 52
    _TRACK_H = 28

    def __init__(self, parent, text_on="УВІМК", text_off="ВИМК",
                 initial=False, on_toggle=None,
                 color_on="#00ff88", color_off="#444466",
                 width=110, height=32, **kw):
        super().__init__(parent, fg_color="transparent", **kw)
        self._state   = initial
        self._on_cb   = on_toggle
        self._text_on = text_on; self._text_off = text_off
        self._col_on  = color_on; self._col_off = color_off
        card   = COLORS.get("bg_card","#1a1a2e")
        border = COLORS.get("border","#2a2a4a")
        dim    = COLORS.get("text_dim","#444466")
        tw = self._TRACK_W; th = self._TRACK_H
        self._track = ctk.CTkFrame(self, width=tw, height=th,
            corner_radius=th//2,
            fg_color=("#003322" if initial else card),
            border_width=2,
            border_color=(color_on if initial else border))
        self._track.pack(side="left")
        self._track.pack_propagate(False)
        self._track.bind("<Button-1>", lambda e: self._toggle())
        self._track.configure(cursor="hand2")
        dot_sz = th - 10
        self._dot_on_x  = tw - dot_sz - 6
        self._dot_off_x = 6
        self._dot_y     = (th - dot_sz) // 2
        self._dot = ctk.CTkFrame(self._track, width=dot_sz, height=dot_sz,
            corner_radius=dot_sz//2,
            fg_color=(color_on if initial else dim))
        x_start = self._dot_on_x if initial else self._dot_off_x
        self._dot.place(x=x_start, y=self._dot_y)
        self._dot.bind("<Button-1>", lambda e: self._toggle())
        self._dot.configure(cursor="hand2")
        self._lbl = ctk.CTkLabel(self,
            text=(text_on if initial else text_off),
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=(color_on if initial else color_off))
        self._lbl.pack(side="left", padx=(10,0))

    def _toggle(self):
        self._state = not self._state
        card   = COLORS.get("bg_card","#1a1a2e")
        border = COLORS.get("border","#2a2a4a")
        dim    = COLORS.get("text_dim","#444466")
        if self._state:
            self._track.configure(fg_color="#003322", border_color=self._col_on)
            self._dot.configure(fg_color=self._col_on)
            self._dot.place(x=self._dot_on_x, y=self._dot_y)
            self._lbl.configure(text=self._text_on, text_color=self._col_on)
        else:
            self._track.configure(fg_color=card, border_color=border)
            self._dot.configure(fg_color=dim)
            self._dot.place(x=self._dot_off_x, y=self._dot_y)
            self._lbl.configure(text=self._text_off, text_color=self._col_off)
        if self._on_cb: self._on_cb(self._state)

    def get(self) -> bool: return self._state
    def set(self, value: bool):
        if self._state != value: self._toggle()


# ══════════════════════════════════════════════════════════════════
# NEW DEVICE POPUP
# ══════════════════════════════════════════════════════════════════
class ManualBlockDialog(ctk.CTkToplevel):
    """
    Напів-автоматичне блокування для роутерів що не підтримуються API
    (D-Link, Tenda, Huawei, інші). Показує покрокову інструкцію:
      • автоматично відкриває admin-панель роутера у браузері
      • копіює MAC-адресу пристрою в буфер обміну
      • дає конкретну інструкцію для вендора
    """

    # Інструкції для різних виробників роутерів
    _VENDOR_INSTRUCTIONS = {
        "d-link":    {"path": "Міжмережевий екран → MAC-фільтр",
                      "en_path": "Firewall → MAC Filter / Network Filter",
                      "mode": "Заборонити (Deny) → Додати MAC → Зберегти"},
        "dlink":     {"path": "Міжмережевий екран → MAC-фільтр",
                      "en_path": "Firewall → MAC Filter / Network Filter",
                      "mode": "Заборонити (Deny) → Додати MAC → Зберегти"},
        "tenda":     {"path": "Advanced → Access Control / Filter Management",
                      "en_path": "Advanced → Access Control",
                      "mode": "Enable Blacklist → Add MAC → Save"},
        "huawei":    {"path": "More Functions → Security Settings → MAC Address Filter",
                      "en_path": "More Functions → Security → MAC Filter",
                      "mode": "Enable Blacklist → Add MAC → Apply"},
        "tp-link":   {"path": "Advanced → Security → Access Control",
                      "en_path": "Advanced → Security → Access Control",
                      "mode": "Blacklist → Add → Save"},
        "asus":      {"path": "Wireless → Wireless MAC Filter",
                      "en_path": "Wireless → Wireless MAC Filter",
                      "mode": "Reject → Add Client → Apply"},
        "netgear":   {"path": "Advanced → Security → Access Control",
                      "en_path": "Advanced → Security → Access Control",
                      "mode": "Block all new devices → Add MAC → Apply"},
        "zyxel":     {"path": "Network Setting → Wireless → MAC Authentication",
                      "en_path": "Wireless → MAC Authentication",
                      "mode": "Deny Association → Add MAC → Apply"},
        "cudy":      {"path": "Advanced → Security → MAC Filter",
                      "en_path": "Advanced → Security → MAC Filter",
                      "mode": "Blacklist → Add MAC → Save"},
    }

    def __init__(self, parent, host: dict, engine, reason: str = ""):
        super().__init__(parent)
        self._host   = host
        self._engine = engine

        self.title("🛡️  Ручне блокування пристрою")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, lambda: _bring_to_front(self))

        w, h = 620, 640
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        try: self.grab_set()
        except Exception: pass
        self.focus_force()

        green  = COLORS.get("accent_green", "#00ff88")
        cyan   = COLORS.get("accent_cyan",  "#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        red    = COLORS.get("accent_red",   "#ff4444")
        card   = COLORS.get("bg_card",      "#1a1a2e")
        border = COLORS.get("border",       "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",     "#444466")
        pri    = COLORS.get("text_primary", "#e0e0ff")

        # Дані пристрою
        mac = host.get("mac", "—")
        ip  = host.get("ip", "—")
        label = _best_device_label(host)

        # Визначаємо роутер
        gw = host.get("gateway","") or engine._detect_gateway() or "192.168.0.1"
        router_vendor = ""
        try:
            v, _, _ = engine.lookup_oui(gw)
            router_vendor = (v or "").lower()
        except Exception: pass

        # Інструкція для vendor
        instruction = None
        vendor_key = None
        for key in self._VENDOR_INSTRUCTIONS:
            if key in router_vendor:
                instruction = self._VENDOR_INSTRUCTIONS[key]
                vendor_key = key
                break

        # ── Жовта смуга зверху ─────────────────────
        ctk.CTkFrame(self, fg_color=yellow, height=4, corner_radius=0).pack(fill="x")

        # ── Заголовок ──────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr,
            text="🛠️  РУЧНЕ БЛОКУВАННЯ ЧЕРЕЗ АДМІН-ПАНЕЛЬ",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=yellow).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text="🔧", font=ctk.CTkFont(size=28)
            ).pack(side="right", padx=20)
        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        # ── Тіло ──────────────────────────────────
        body = ctk.CTkScrollableFrame(self, fg_color="transparent",
            scrollbar_button_color=cyan,
            scrollbar_button_hover_color="#00a8cc")
        body.pack(fill="both", expand=True, padx=20, pady=14)

        # Пояснення
        ctk.CTkLabel(body,
            text="Твій роутер не підтримується автоматичним API",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=yellow, anchor="w").pack(fill="x", pady=(0, 4))
        if reason:
            short = reason.split("\n")[0][:90]
            ctk.CTkLabel(body,
                text=f"Деталі: {short}",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=dim, anchor="w", justify="left").pack(fill="x", pady=(0, 8))

        ctk.CTkLabel(body,
            text="Але ти можеш заблокувати пристрій ВРУЧНУ за 30 секунд:",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=pri, anchor="w").pack(fill="x", pady=(0, 14))

        # ── Інфо-карта з даними пристрою ─────────
        info = ctk.CTkFrame(body, fg_color="#1a0000", corner_radius=10,
                            border_width=1, border_color=red)
        info.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(info,
            text="  🎯  ПРИСТРІЙ ДЛЯ БЛОКУВАННЯ",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=red).pack(anchor="w", padx=14, pady=(10, 4))

        info_rows = [
            ("Назва:", label),
            ("IP:",    ip),
            ("MAC:",   mac),
        ]
        for lbl, val in info_rows:
            row = ctk.CTkFrame(info, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(row, text=lbl,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=sec, width=80, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=val,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=red if lbl == "MAC:" else pri, anchor="w"
                ).pack(side="left", padx=(8, 0))
        ctk.CTkFrame(info, fg_color="transparent", height=8).pack()

        # ── Покрокова інструкція ─────────────────
        steps_card = ctk.CTkFrame(body, fg_color=card, corner_radius=10,
                                  border_width=1, border_color=border)
        steps_card.pack(fill="x", pady=(0, 12))
        vendor_title = (
            f"  📋  ІНСТРУКЦІЯ для {vendor_key.upper()} (твій роутер)"
            if vendor_key else "  📋  ЗАГАЛЬНА ІНСТРУКЦІЯ")
        ctk.CTkLabel(steps_card, text=vendor_title,
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=cyan).pack(anchor="w", padx=14, pady=(10, 6))

        if instruction:
            steps_text = (
                f"1️⃣  Натисни '🌐 Відкрити роутер' нижче\n"
                f"    (MAC вже у буфері обміну — CTRL+V у поле MAC)\n\n"
                f"2️⃣  Залогінься в адмін-панель\n\n"
                f"3️⃣  Перейди в:  {instruction['path']}\n"
                f"    ({instruction['en_path']})\n\n"
                f"4️⃣  {instruction['mode']}\n\n"
                f"5️⃣  Вставка MAC (CTRL+V):  {mac}\n\n"
                f"6️⃣  Натисни 'Натиснуто' нижче коли закінчив —\n"
                f"    додам пристрій у БД як заблокований"
            )
        else:
            steps_text = (
                f"1️⃣  Натисни '🌐 Відкрити роутер' нижче\n"
                f"    (MAC вже у буфері обміну)\n\n"
                f"2️⃣  Залогінься в адмін-панель\n\n"
                f"3️⃣  Знайди розділ:\n"
                f"    • 'MAC Filter' / 'Access Control'\n"
                f"    • 'Parental Controls' / 'Міжмережевий екран'\n\n"
                f"4️⃣  Додай MAC у чорний список (Blacklist / Deny)\n"
                f"    Вставка MAC (CTRL+V):  {mac}\n\n"
                f"5️⃣  Збережи налаштування\n\n"
                f"6️⃣  Натисни 'Натиснуто' нижче"
            )

        ctk.CTkLabel(steps_card, text=steps_text,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=pri, anchor="nw", justify="left"
            ).pack(fill="x", padx=14, pady=(0, 12))

        # ── Статус ─────────────────────────────
        self._status = ctk.CTkLabel(body, text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=dim, anchor="w", justify="left")
        self._status.pack(fill="x", pady=(0, 10))

        # ── Кнопки ──────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        btn_row.pack(fill="x", side="bottom")
        ctk.CTkFrame(btn_row, fg_color=border, height=1).pack(fill="x")
        inner = ctk.CTkFrame(btn_row, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)

        def _copy_mac():
            try:
                self.clipboard_clear()
                self.clipboard_append(mac)
                self._status.configure(
                    text=f"📋  MAC {mac} скопійовано у буфер обміну",
                    text_color=green)
            except Exception as e:
                self._status.configure(
                    text=f"❌  Не вдалось скопіювати: {e}",
                    text_color=red)

        def _open_router():
            """
            Смарт-відкриття роутера з автоматичним поетапним копіюванням:
              • Одразу: MAC у буфер (CTRL+V у поле MAC filter)
              • Через 4 сек: ЛОГІН у буфер (CTRL+V у username)
              • Через 8 сек: ПАРОЛЬ у буфер (CTRL+V у password)
              • Через 12 сек: знову MAC (бо користувач вже увійшов в роутер)
            """
            # Отримуємо credentials роутера якщо збережені
            router_user = ""
            router_pwd  = ""
            try:
                from features.security.lan_security import router_manager
                cfg = router_manager.get_router_by_ip(gw)
                if cfg:
                    router_user = cfg.get("http_user", "") or ""
                    router_pwd  = cfg.get("http_pwd", "") or ""
            except Exception: pass

            url = f"http://{gw}"

            # Крок 1: MAC у буфер одразу
            try:
                self.clipboard_clear()
                self.clipboard_append(mac)
                self.update()
            except Exception: pass

            # Крок 2: відкрити браузер
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception as e:
                self._status.configure(
                    text=f"❌  Не вдалось відкрити: {e}",
                    text_color=red)
                return

            # Якщо credentials збережені — автоматична послідовність копіювання
            if router_user and router_pwd:
                self._status.configure(
                    text=(
                        f"🌐  Роутер {gw} відкрито\n"
                        f"📋  MAC у буфері ({mac})\n"
                        f"⏱  Через 4 сек → копіюю ЛОГІН автоматично\n"
                        f"💡  Порядок: (1) вставити логін → (2) пароль → (3) MAC"
                    ),
                    text_color=cyan)

                def _step_login():
                    try:
                        self.clipboard_clear()
                        self.clipboard_append(router_user)
                        self.update()
                        self._status.configure(
                            text=(
                                f"🔑  ЛОГІН «{router_user}» у буфері → CTRL+V\n"
                                f"⏱  Через 4 сек → скопіюю ПАРОЛЬ"
                            ),
                            text_color=yellow)
                    except Exception: pass

                def _step_password():
                    try:
                        self.clipboard_clear()
                        self.clipboard_append(router_pwd)
                        self.update()
                        self._status.configure(
                            text=(
                                f"🔐  ПАРОЛЬ у буфері → CTRL+V → увійти\n"
                                f"⏱  Через 4 сек знову скопіюю MAC для фільтра"
                            ),
                            text_color=yellow)
                    except Exception: pass

                def _step_mac_again():
                    try:
                        self.clipboard_clear()
                        self.clipboard_append(mac)
                        self.update()
                        self._status.configure(
                            text=(
                                f"📋  MAC {mac} знову у буфері\n"
                                f"✅  Вставляй CTRL+V у поле MAC filter/Blacklist"
                            ),
                            text_color=green)
                    except Exception: pass

                try:
                    self.after(4000,  _step_login)
                    self.after(8000,  _step_password)
                    self.after(12000, _step_mac_again)
                except Exception: pass
            else:
                # Немає збережених credentials — просто MAC + підказка
                self._status.configure(
                    text=(
                        f"🌐  Роутер {gw} відкрито у браузері\n"
                        f"📋  MAC {mac} у буфері обміну — вставляй CTRL+V\n"
                        f"💡  Збережи credentials у '⭐ Налаштувати роутер'\n"
                        f"    і наступного разу логін+пароль теж будуть копіюватись"
                    ),
                    text_color=green)

        def _mark_blocked():
            """Після ручного блокування — записуємо в БД як заблокований."""
            try:
                self._engine.ban_device(
                    mac=mac, ip=ip,
                    vendor=host.get("vendor",""),
                    label=label,
                    reason="Заблоковано вручну через admin-панель роутера",
                    duration=0.0)
                mb.showinfo("✅ Готово",
                    f"Пристрій {label} позначений як заблокований у NetGuardian.\n\n"
                    f"MAC {mac} тепер у списку '🚫 Заблоковані'.\n"
                    f"Якщо розблокуєш через роутер — не забудь зняти бан\n"
                    f"і в NetGuardian (кнопкою '🔓 Розблокувати').",
                    parent=self)
                self.destroy()
            except Exception as e:
                mb.showerror("Помилка", f"Не вдалось: {e}", parent=self)

        ctk.CTkButton(inner, text="📋 Копіювати MAC",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary", "#0d0d1a"),
            text_color=sec, border_width=1, border_color=sec,
            font=ctk.CTkFont(family="Consolas", size=10),
            height=34, corner_radius=6, width=150,
            command=_copy_mac).pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner, text="🌐  Відкрити роутер",
            fg_color="#002a3a", hover_color="#003d55",
            text_color=cyan, border_width=2, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=180,
            command=_open_router).pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner, text="✅ Натиснуто, готово",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=2, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=170,
            command=_mark_blocked).pack(side="right")


class RouterSetupWizard(ctk.CTkToplevel):
    """
    Діалог-wizard для налаштування credentials роутера.
    Це ключ до РЕАЛЬНОГО постійного блокування пристроїв через Router API.
    """
    def __init__(self, parent, engine, on_saved=None):
        super().__init__(parent)
        self._engine   = engine
        self._on_saved = on_saved

        self.title("⚙️  Налаштування роутера для блокування")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, lambda: _bring_to_front(self))

        w, h = 640, 620
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        try: self.grab_set()
        except Exception: pass
        self.focus_force()

        green  = COLORS.get("accent_green", "#00ff88")
        cyan   = COLORS.get("accent_cyan",  "#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        red    = COLORS.get("accent_red",   "#ff4444")
        card   = COLORS.get("bg_card",      "#1a1a2e")
        border = COLORS.get("border",       "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",     "#444466")
        pri    = COLORS.get("text_primary", "#e0e0ff")

        # Детектуємо поточний шлюз
        gateway = ""
        try: gateway = engine._detect_gateway() or ""
        except Exception: pass

        # Підтягуємо SSID та vendor роутера з Dashboard (якщо доступно)
        wifi_ssid = ""
        router_vendor = ""
        try:
            from features.dashboard.ui import get_dashboard_snapshot
            snap = get_dashboard_snapshot()
            wifi_ssid = snap.get("wifi_ssid", "") or ""
            if wifi_ssid in ("—", "N/A", "Unknown"): wifi_ssid = ""
        except Exception: pass
        # Визначаємо vendor роутера за MAC/OUI чи vendor-рядком
        try:
            v, _, _ = engine.lookup_oui(gateway) if gateway else ("", "", "")
            router_vendor = v or ""
        except Exception: pass

        # Якщо вже є запис — підтягуємо значення
        existing = None
        try:
            from features.security.lan_security import router_manager
            existing = router_manager.get_router_by_ip(gateway)
        except Exception: pass

        # Ім'я роутера: ім'я зі збереженого → або SSID Wi-Fi → або vendor → фолбек
        default_name = "Мій роутер"
        if existing and existing.get("name"):
            default_name = existing["name"]
        elif wifi_ssid:
            default_name = wifi_ssid
        elif router_vendor:
            default_name = f"{router_vendor} Router"

        # ── Зелена смуга зверху ─────────────────────
        ctk.CTkFrame(self, fg_color=green, height=4, corner_radius=0).pack(fill="x")

        # ── Заголовок ──────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr,
            text="🛡️  НАЛАШТУВАННЯ БЛОКУВАННЯ ЧЕРЕЗ РОУТЕР",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=green).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text="⭐", font=ctk.CTkFont(size=28)
            ).pack(side="right", padx=20)
        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        # ── Тіло ──────────────────────────────────
        body = ctk.CTkScrollableFrame(self, fg_color="transparent",
            scrollbar_button_color=cyan,
            scrollbar_button_hover_color="#00a8cc")
        body.pack(fill="both", expand=True, padx=20, pady=14)

        # Інфо-карта з автовизначеними даними мережі
        info_card = ctk.CTkFrame(body, fg_color="#001a2e", corner_radius=8,
                                 border_width=1, border_color=cyan)
        info_card.pack(fill="x", pady=(0, 12))
        ctk.CTkLabel(info_card,
            text="  🔍  АВТОВИЗНАЧЕНІ ДАНІ ТВОЄЇ МЕРЕЖІ",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=cyan).pack(anchor="w", padx=12, pady=(8, 4))

        auto_rows = [
            ("Wi-Fi SSID:",   wifi_ssid or "(не виявлено)",
                green if wifi_ssid else dim),
            ("Шлюз (gateway):", gateway or "(не виявлено)",
                green if gateway else dim),
            ("Виробник роутера:", router_vendor or "(невідомий)",
                green if router_vendor else dim),
        ]
        for label, value, col in auto_rows:
            row = ctk.CTkFrame(info_card, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            ctk.CTkLabel(row, text=label,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=sec, width=150, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=col, anchor="w").pack(side="left", padx=(8, 0))
        ctk.CTkLabel(info_card,
            text="   ☝️  Ці дані взяті з Dashboard і використані нижче",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=dim).pack(anchor="w", padx=12, pady=(4, 10))

        # Пояснення
        ctk.CTkLabel(body,
            text="Чому це найкраще рішення:",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=yellow, anchor="w").pack(fill="x", pady=(0, 4))
        ctk.CTkLabel(body,
            text=(
                "• Блокування постійне — пристрій НЕ ЗМОЖЕ повернутись у мережу\n"
                "• Не потрібен Admin / Npcap / Scapy\n"
                "• Працює через стандартний HTTP API роутера\n"
                "• Автоматично: TP-Link Archer, Keenetic, ASUS, MikroTik\n"
                "• Напів-автоматично: D-Link, Tenda, Huawei, інші (допомагає через браузер)"
            ),
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=sec, anchor="w", justify="left").pack(fill="x", pady=(0, 14))

        # ── Form ─────────────────────────────────
        form = ctk.CTkFrame(body, fg_color=card, corner_radius=10,
                            border_width=1, border_color=border)
        form.pack(fill="x", pady=(0, 10))

        ctk.CTkLabel(form,
            text="  📡  CREDENTIALS АДМІН-ПАНЕЛІ РОУТЕРА",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=cyan).pack(anchor="w", padx=14, pady=(12, 4))

        def _field(label: str, initial: str = "", show: str = "") -> ctk.CTkEntry:
            fr = ctk.CTkFrame(form, fg_color="transparent")
            fr.pack(fill="x", padx=14, pady=4)
            ctk.CTkLabel(fr, text=label,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=sec, width=150, anchor="w").pack(side="left")
            e = ctk.CTkEntry(fr, font=ctk.CTkFont(family="Consolas", size=11),
                fg_color=COLORS.get("bg_secondary","#0d0d1a"),
                border_color=border, text_color=pri, width=300, show=show)
            if initial: e.insert(0, initial)
            e.pack(side="left", padx=(8, 0))
            return e

        self._e_name = _field("Назва роутера:", default_name)
        self._e_ip   = _field("IP адреса:", gateway or "192.168.0.1")
        self._e_user = _field("Логін адміна:",
            (existing.get("http_user") if existing else "admin"))
        self._e_pwd  = _field("Пароль адміна:",
            (existing.get("http_pwd") if existing else ""),
            show="•")

        # Підказка про паролі за замовчуванням
        hint = ctk.CTkFrame(form, fg_color="#0d1a15", corner_radius=6)
        hint.pack(fill="x", padx=14, pady=(10, 12))
        ctk.CTkLabel(hint,
            text=(
                "💡  Підказки для типових роутерів:\n"
                "    • TP-Link: зазвичай admin/admin або дивись наклейку на днищі\n"
                "    • Keenetic: admin/<свій_пароль>  (ти встановлював при налаштуванні)\n"
                "    • ASUS: admin/admin або admin/password\n"
                "    • Наклейка на роутері — SSID, WiFi, Admin password"
            ),
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=sec, anchor="w", justify="left"
            ).pack(anchor="w", padx=12, pady=8)

        # Статус тесту
        self._test_status = ctk.CTkLabel(body, text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=dim, anchor="w", justify="left")
        self._test_status.pack(fill="x", pady=(0, 10))

        # ── Кнопки ──────────────────────────────
        btn_row = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        btn_row.pack(fill="x", side="bottom")
        ctk.CTkFrame(btn_row, fg_color=border, height=1).pack(fill="x")
        inner = ctk.CTkFrame(btn_row, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=12)

        ctk.CTkButton(inner, text="🌐 Відкрити + авто-копіювання",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary", "#0d0d1a"),
            text_color=cyan, border_width=1, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=10),
            height=34, corner_radius=6, width=240,
            command=self._open_router_browser).pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner, text="🧪 Перевірити",
            fg_color="#1a1500", hover_color="#2d2500",
            text_color=yellow, border_width=1, border_color=yellow,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=120,
            command=self._test_connection).pack(side="left")

        ctk.CTkButton(inner, text="💾 Зберегти",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=2, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=140,
            command=self._save_credentials).pack(side="right", padx=(8, 0))

        ctk.CTkButton(inner, text="✖ Скасувати",
            fg_color="transparent", hover_color=card,
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=10),
            height=34, corner_radius=6, width=100,
            command=self.destroy).pack(side="right")

    def _open_router_browser(self):
        """
        Відкриває admin-панель роутера у браузері.
        Copy-paste workflow:
          1. Копіюємо ЛОГІН у буфер → користувач CTRL+V у поле Username
          2. Через 3 сек копіюємо ПАРОЛЬ → CTRL+V у поле Password
        Показуємо невеликий help-popup що пояснює процес.
        """
        import webbrowser
        import threading
        import tkinter.messagebox as _mb

        ip   = self._e_ip.get().strip() or "192.168.0.1"
        user = self._e_user.get().strip()
        pwd  = self._e_pwd.get()

        # Пробуємо URL з credentials (працює на деяких роутерах типу старий D-Link)
        # http://user:pass@ip — хоча більшість сучасних браузерів блокують це з 2017р
        url = f"http://{ip}"

        # 1. Копіюємо ЛОГІН у буфер обміну
        try:
            self.clipboard_clear()
            self.clipboard_append(user)
            self.update()  # обов'язково для Windows щоб буфер оновився
        except Exception: pass

        # 2. Відкриваємо браузер
        try:
            webbrowser.open(url)
        except Exception as e:
            _mb.showerror("Помилка", f"Не вдалось відкрити браузер: {e}", parent=self)
            return

        # 3. Показуємо підказку
        self._test_status.configure(
            text=f"📋  ЛОГІН «{user}» скопійовано → CTRL+V у поле Username\n"
                 f"⏱  Через 3 сек автоматично скопіюю ПАРОЛЬ",
            text_color=COLORS.get("accent_cyan","#00d4ff"))

        # 4. Через 3 секунди копіюємо пароль
        def _copy_pwd_later():
            try:
                self.clipboard_clear()
                self.clipboard_append(pwd)
                self.update()
                self._test_status.configure(
                    text=f"🔑  ПАРОЛЬ скопійовано у буфер → CTRL+V у поле Password",
                    text_color=COLORS.get("accent_green","#00ff88"))
            except Exception: pass

        try: self.after(3000, _copy_pwd_later)
        except Exception: pass

    def _test_connection(self):
        """Пробує залогінитись до роутера з введеними credentials."""
        import threading
        ip   = self._e_ip.get().strip()
        user = self._e_user.get().strip()
        pwd  = self._e_pwd.get()
        if not ip or not user:
            self._test_status.configure(
                text="❌ Вкажи IP і логін",
                text_color=COLORS.get("accent_red","#ff4444"))
            return

        self._test_status.configure(
            text="⏳ Перевіряю з'єднання...",
            text_color=COLORS.get("accent_cyan","#00d4ff"))

        def _worker():
            try:
                from features.security.lan_security import RouterClientReader
                reader = RouterClientReader(ip, timeout=5.0, username=user, password=pwd)
                # Спочатку пробуємо TP-Link
                ok = False
                reason = ""
                try:
                    if reader._tplink_login():
                        ok = True; reason = "TP-Link"
                except Exception as e:
                    reason = f"TP-Link err: {e}"
                if not ok:
                    # Пробуємо базову HTTP аутентифікацію (ASUS/Keenetic)
                    try:
                        import urllib.request, base64
                        auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                        req = urllib.request.Request(f"http://{ip}/",
                            headers={"Authorization": f"Basic {auth}"})
                        with urllib.request.urlopen(req, timeout=4) as r:
                            if r.status in (200, 302):
                                ok = True; reason = "HTTP Basic"
                    except Exception as e:
                        if not reason: reason = f"HTTP: {e}"

                def _show():
                    if ok:
                        self._test_status.configure(
                            text=f"✅ З'єднання успішне ({reason})",
                            text_color=COLORS.get("accent_green","#00ff88"))
                    else:
                        self._test_status.configure(
                            text=f"❌ Не вдалось: {reason[:60]}\n    Перевір логін/пароль або спробуй admin/admin",
                            text_color=COLORS.get("accent_red","#ff4444"))
                try: self.after(0, _show)
                except Exception: pass
            except Exception as e:
                def _err():
                    self._test_status.configure(
                        text=f"❌ Помилка: {str(e)[:80]}",
                        text_color=COLORS.get("accent_red","#ff4444"))
                try: self.after(0, _err)
                except Exception: pass

        threading.Thread(target=_worker, daemon=True).start()

    def _save_credentials(self):
        name = self._e_name.get().strip() or "Router"
        ip   = self._e_ip.get().strip()
        user = self._e_user.get().strip()
        pwd  = self._e_pwd.get()
        if not ip or not user:
            mb.showerror("Помилка", "Вкажи IP і логін.", parent=self)
            return
        try:
            from features.security.lan_security import router_manager
            router_manager.add_router(name=name, ip=ip,
                http_user=user, http_pwd=pwd, label=name)
            mb.showinfo("Збережено",
                f"✅ Роутер {name} ({ip}) збережено.\n\n"
                f"Тепер блокування пристроїв буде постійним — через "
                f"MAC Filter роутера.", parent=self)
            if self._on_saved:
                try: self._on_saved()
                except Exception: pass
            self.destroy()
        except Exception as e:
            mb.showerror("Помилка", f"Не вдалось зберегти: {e}", parent=self)


class WiFiPasswordChangeDialog(ctk.CTkToplevel):
    """
    Діалог-порада після блокування небезпечного пристрою.
    Пояснює чому важливо змінити пароль Wi-Fi і як це зробити.
    """
    def __init__(self, parent, device: dict):
        super().__init__(parent)
        self._device = device
        self.title("🔐  Рекомендація: зміна пароля Wi-Fi")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, lambda: _bring_to_front(self))

        w, h = 560, 480
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        try: self.grab_set()
        except Exception: pass
        self.focus_force()

        green  = COLORS.get("accent_green", "#00ff88")
        cyan   = COLORS.get("accent_cyan",  "#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        red    = COLORS.get("accent_red",   "#ff4444")
        card   = COLORS.get("bg_card",      "#1a1a2e")
        border = COLORS.get("border",       "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",     "#444466")
        pri    = COLORS.get("text_primary", "#e0e0ff")

        # ── Червона смуга зверху ─────────────────────────────
        ctk.CTkFrame(self, fg_color=red, height=4, corner_radius=0).pack(fill="x")

        # ── Заголовок ────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr,
            text="⚠️  ВАЖЛИВА РЕКОМЕНДАЦІЯ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=red).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text="🔐", font=ctk.CTkFont(size=32)
            ).pack(side="right", padx=20)
        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        # ── Тіло: пояснення ─────────────────────────────────
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=22, pady=14)

        ctk.CTkLabel(body,
            text="Пристрій заблоковано — але цього може бути недостатньо",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=yellow, anchor="w").pack(fill="x", pady=(0, 6))

        explain_text = (
            "Якщо цей пристрій був несанкціонованим — зловмисник:\n\n"
            "• МАЄ пароль твоєї Wi-Fi мережі\n"
            "• Може спробувати підключитись з іншим MAC-адресом\n"
            "• Міг перехопити трафік інших пристроїв\n"
            "• Міг скомпрометувати інші пристрої у мережі\n\n"
            "⚡  РЕКОМЕНДОВАНІ ДІЇ (у порядку важливості):\n\n"
            "1. ЗМІНИ ПАРОЛЬ Wi-Fi (пріоритет #1)\n"
            "   → Відкрий admin-панель роутера (192.168.0.1 / 192.168.1.1)\n"
            "   → Wireless → Security → Wi-Fi Password → новий складний пароль\n"
            "   → Використовуй WPA2/WPA3 (не WEP!)\n\n"
            "2. ЗМІНИ ПАРОЛЬ АДМІН-ПАНЕЛІ РОУТЕРА\n"
            "   → System / Administration → Password\n\n"
            "3. ПЕРЕВІР ЛОГИ РОУТЕРА на інші підозрілі пристрої\n\n"
            "4. УВІМКНИ MAC-FILTER у роутері (whitelist своїх пристроїв)"
        )
        ctk.CTkLabel(body,
            text=explain_text,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=pri, justify="left", anchor="nw").pack(fill="both", expand=True)

        # ── Кнопки ─────────────────────────────────────────
        btn_f = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        btn_f.pack(fill="x", side="bottom")
        ctk.CTkFrame(btn_f, fg_color=border, height=1).pack(fill="x")

        inner_f = ctk.CTkFrame(btn_f, fg_color="transparent")
        inner_f.pack(expand=True, fill="x", padx=18, pady=12)

        def open_router():
            """Відкрити admin-панель роутера в браузері."""
            gw = device.get("gateway") or "192.168.0.1"
            url = f"http://{gw}"
            try:
                import webbrowser
                webbrowser.open(url)
            except Exception:
                mb.showerror("Помилка", f"Не вдалось відкрити: {url}", parent=self)

        ctk.CTkButton(inner_f, text="🌐  Відкрити роутер",
            fg_color="#002a3a", hover_color="#003d55",
            text_color=cyan, border_width=2, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=40, corner_radius=8, width=200,
            command=open_router).pack(side="left", padx=(0, 8))

        ctk.CTkButton(inner_f, text="✓ Зрозуміло, закрити",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary", "#0d0d1a"),
            text_color=sec, border_width=1, border_color=sec,
            font=ctk.CTkFont(family="Consolas", size=12),
            height=40, corner_radius=8, width=180,
            command=self.destroy).pack(side="right")


class NewDevicePopup(ctk.CTkToplevel):
    def __init__(self, parent, device: dict, engine,
                 on_block_cb=None, on_close_cb=None,
                 is_auto_scan: bool = False):
        super().__init__(parent)
        self._device     = device
        self._engine     = engine
        self._on_block   = on_block_cb
        self._on_close   = on_close_cb

        # FIX-3: якщо це авто-скан — заголовок інакший
        title_text = ("🔔  Виявлено новий пристрій після оновлення"
                      if is_auto_scan else "🔔  Новий пристрій у мережі")
        self.title(title_text)
        self.resizable(False, False)
        self.attributes("-topmost", True)

        w, h = 520, 420
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.configure(fg_color=COLORS.get("bg_secondary","#0d0d1a"))

        threat  = device.get("threat","safe")
        tc      = {"critical":"#ff2020","danger":"#ff4444","warn":"#ffd700","safe":"#00ff88"}.get(threat,"#00d4ff")
        green   = COLORS.get("accent_green","#00ff88")
        cyan    = COLORS.get("accent_cyan","#00d4ff")
        yellow  = COLORS.get("accent_yellow","#ffd700")
        red     = COLORS.get("accent_red","#ff4444")
        card    = COLORS.get("bg_card","#1a1a2e")
        border  = COLORS.get("border","#2a2a4a")
        sec     = COLORS.get("text_secondary","#8888aa")
        dim     = COLORS.get("text_dim","#444466")
        pri     = COLORS.get("text_primary","#e0e0ff")

        ctk.CTkFrame(self, fg_color=tc, height=4, corner_radius=0).pack(fill="x")

        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        # FIX-3: різний підзаголовок для авто-скану
        hdr_text = ("🔄  ПІСЛЯ ОНОВЛЕННЯ ВИЯВЛЕНО" if is_auto_scan
                    else "🔔  НОВИЙ ПРИСТРІЙ ВИЯВЛЕНО")
        ctk.CTkLabel(hdr,
            text=hdr_text,
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=tc).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr,
            text=device.get("icon","❓"),
            font=ctk.CTkFont(size=32)).pack(side="right", padx=20)

        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=14)

        display = _best_device_label(device)
        ctk.CTkLabel(body,
            text=display,
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=cyan if not device.get("is_trusted") else green,
            anchor="w").pack(fill="x")

        vendor_str = f"{device.get('vendor','—')}  ·  {device.get('dev_type','—')}"
        ctk.CTkLabel(body, text=vendor_str,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=sec, anchor="w").pack(fill="x", pady=(2,8))

        ctk.CTkFrame(body, fg_color=border, height=1).pack(fill="x", pady=(0,10))

        info_f = ctk.CTkFrame(body, fg_color="transparent")
        info_f.pack(fill="x")
        info_f.grid_columnconfigure((0,1), weight=1)

        fields = [
            ("IP адреса",    device.get("ip","—"),       cyan),
            ("MAC адреса",   device.get("mac","—"),       pri),
            ("Тип пристрою", device.get("dev_type","—"),  sec),
            ("Рівень загрози", threat.upper(),            tc),
        ]
        ssh_hn = (device.get("ssh_hostname") or "").strip()
        if ssh_hn and ssh_hn not in ("—","*"):
            fields.append(("★ SSH ім'я", ssh_hn, green))
        dhcp_hn = (device.get("dhcp_hostname") or "").strip()
        if dhcp_hn and dhcp_hn not in ("—",""):
            fields.append(("DHCP ім'я", dhcp_hn, sec))
        if device.get("connection_type"):
            fields.append(("З'єднання", device["connection_type"] +
                           (f" {device.get('band','')}" if device.get("band") else ""), sec))

        for i, (label, val, col) in enumerate(fields):
            row, col_n = divmod(i, 2)
            cell = ctk.CTkFrame(info_f, fg_color="transparent")
            cell.grid(row=row, column=col_n, padx=(0,20), pady=3, sticky="w")
            ctk.CTkLabel(cell, text=f"{label}:",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=dim).pack(anchor="w")
            ctk.CTkLabel(cell, text=str(val),
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=col).pack(anchor="w")

        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        btn_f = ctk.CTkFrame(self, fg_color=card, corner_radius=0, height=72)
        btn_f.pack(fill="x"); btn_f.pack_propagate(False)
        inner_f = ctk.CTkFrame(btn_f, fg_color="transparent")
        inner_f.pack(expand=True, fill="both", padx=18, pady=12)

        mac_v = device.get("mac","")

        def do_trust():
            self._engine.set_trusted(mac_v, True)
            mb.showinfo("✅ Довіреним", f"Пристрій {display} додано до довірених.", parent=self)
            self._close()

        def do_block():
            # FIX: для небезпечних пристроїв — після блокування пропонуємо зміну пароля Wi-Fi
            is_dangerous = device.get("threat") in ("danger", "critical")
            self._close()
            if self._on_block:
                self._on_block(device)
            # Якщо пристрій небезпечний → показуємо додатковий попап про зміну пароля
            if is_dangerous:
                try:
                    parent.after(2000, lambda: WiFiPasswordChangeDialog(parent, device))
                except Exception: pass

        def do_skip():
            self._engine.dismiss_alert(mac_v)
            self._close()

        ctk.CTkButton(inner_f, text="✅  Довіряти",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=2, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=140,
            command=do_trust).pack(side="left", padx=(0,8))

        ctk.CTkButton(inner_f, text="🚫  Заблокувати",
            fg_color="#2a0000", hover_color="#3d0000",
            text_color=red, border_width=2, border_color=red,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=160,
            command=do_block).pack(side="left", padx=(0,8))

        ctk.CTkButton(inner_f, text="⏭  Пропустити",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary","#0d0d1a"),
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=12),
            height=44, corner_radius=8, width=140,
            command=do_skip).pack(side="right")

        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(60000, self._close)

    def _close(self):
        if self._on_close: self._on_close()
        try: self.destroy()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════
# BLOCK TIME DIALOG
# ══════════════════════════════════════════════════════════════════
class BlockTimeDialog(ctk.CTkToplevel):
    DURATIONS = [
        ("5 хвилин",   300),
        ("30 хвилин",  1800),
        ("1 година",   3600),
        ("1 день",     86400),
        ("1 тиждень",  604800),
        ("Назавжди",   0),
    ]

    def __init__(self, parent, host: dict, engine, on_done_cb=None):
        super().__init__(parent)
        self._host     = host
        self._engine   = engine
        self._on_done  = on_done_cb
        self._sel_dur  = tk.IntVar(value=1800)

        name = _best_device_label(host)
        self.title(f"🚫  Блокування: {name}")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.grab_set()
        self.after(100, lambda: _bring_to_front(self))

        w, h = 480, 420
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        try:
            px = parent.winfo_rootx(); py = parent.winfo_rooty()
            pw = parent.winfo_width(); ph = parent.winfo_height()
            x = px + (pw - w) // 2; y = py + (ph - h) // 2
        except Exception:
            x = (sw - w) // 2; y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.configure(fg_color=COLORS.get("bg_secondary","#0d0d1a"))

        red    = COLORS.get("accent_red","#ff4444")
        green  = COLORS.get("accent_green","#00ff88")
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        card   = COLORS.get("bg_card","#1a1a2e")
        border = COLORS.get("border","#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim","#444466")
        pri    = COLORS.get("text_primary","#e0e0ff")

        ctk.CTkFrame(self, fg_color=red, height=4, corner_radius=0).pack(fill="x")

        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr,
            text="🚫  БЛОКУВАННЯ ПРИСТРОЮ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=red).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text=host.get("icon","❓"),
            font=ctk.CTkFont(size=28)).pack(side="right", padx=20)

        # FIX-2: пояснення що ARP блокує трафік, але не WiFi
        info_bar = ctk.CTkFrame(self, fg_color="#1a0a00", corner_radius=0)
        info_bar.pack(fill="x")
        ctk.CTkLabel(info_bar,
            text="ℹ️  ARP-блокування перекриває Інтернет-трафік. "
                 "Пристрій може залишатись у Wi-Fi мережі.",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=yellow).pack(anchor="w", padx=16, pady=6)

        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=12)

        info = ctk.CTkFrame(body, fg_color=card, corner_radius=8)
        info.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(info,
            text=f"  {name}",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=pri).pack(anchor="w", padx=14, pady=(10,2))
        ctk.CTkLabel(info,
            text=f"  IP: {host.get('ip','—')}    MAC: {host.get('mac','—')}",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=sec).pack(anchor="w", padx=14, pady=(0,10))

        ctk.CTkLabel(body,
            text="Тривалість блокування:",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=pri).pack(anchor="w", pady=(0,8))

        grid_f = ctk.CTkFrame(body, fg_color="transparent")
        grid_f.pack(fill="x")

        for i, (label, secs) in enumerate(self.DURATIONS):
            r, c = divmod(i, 3)
            is_forever = (secs == 0)

            rb = ctk.CTkFrame(grid_f, fg_color=card, corner_radius=8,
                              border_width=2,
                              border_color=(red if secs == 1800 else border),
                              cursor="hand2")
            rb.grid(row=r, column=c, padx=4, pady=4, sticky="ew")
            grid_f.columnconfigure(c, weight=1)

            def make_select(s=secs, widget=rb):
                def _sel():
                    self._sel_dur.set(s)
                    for child in grid_f.winfo_children():
                        v = getattr(child, "_dur_val", None)
                        child.configure(
                            border_color=(red if v == s else border),
                            fg_color=("#2a0000" if v == s and v == 0
                                      else "#002200" if v == s
                                      else card))
                return _sel

            rb._dur_val = secs
            rb.bind("<Button-1>", lambda e, fn=make_select(): fn())

            col_lbl = (red if is_forever else
                       yellow if secs >= 604800 else
                       sec)
            lbl = ctk.CTkLabel(rb, text=label,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=col_lbl)
            lbl.pack(padx=16, pady=10)
            lbl.bind("<Button-1>", lambda e, fn=make_select(): fn())

        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")

        btn_f = ctk.CTkFrame(self, fg_color=card, corner_radius=0, height=72)
        btn_f.pack(fill="x"); btn_f.pack_propagate(False)
        inner_f = ctk.CTkFrame(btn_f, fg_color="transparent")
        inner_f.pack(expand=True, fill="both", padx=18, pady=12)

        def do_block():
            dur = self._sel_dur.get()
            ip  = host.get("ip","")
            gw  = host.get("gateway","") or engine._detect_gateway()
            mac = host.get("mac","—")
            if not ip or ip == "—":
                mb.showerror("Помилка","IP адреса невідома.", parent=self); return
            lbl_map = {v: k for k, v in self.DURATIONS}
            dur_label = lbl_map.get(dur, f"{dur}с")

            # duration=0 → назавжди (permanent ban manager + MAC filter)
            # duration>0 → тимчасово (ARP spoofing на N секунд)
            actual_duration = 0 if dur == 0 else dur

            engine.set_allowed(host.get("mac",""), False)

            # Записуємо в бан-базу БЕЗ запуску ARP (disconnect_device зробить це сам)
            if mac != "—":
                ban_duration = 0.0 if dur == 0 else float(dur)
                trust_db_entry = {
                    "mac": mac, "ip": ip,
                    "vendor": host.get("vendor",""),
                    "label": _best_device_label(host),
                    "reason": f"Заблоковано вручну ({dur_label})",
                    "duration": ban_duration,
                }
                # Записуємо тільки в БД (без запуску ARP — disconnect_device зробить)
                try:
                    engine._trust_db_ban_only(mac, ip, host.get("vendor",""),
                        _best_device_label(host),
                        f"Заблоковано вручну ({dur_label})", ban_duration)
                except Exception:
                    try: engine.ban_device(
                        mac=mac, ip=ip, vendor=host.get("vendor",""),
                        label=_best_device_label(host),
                        reason=f"Заблоковано вручну ({dur_label})",
                        duration=ban_duration)
                    except Exception: pass

            self.destroy()

            def run():
                ok, msg, method = engine.disconnect_device(
                    ip, mac, gw,
                    duration=actual_duration,
                    status_cb=None)
                def show():
                    if ok:
                        mb.showinfo(
                            "⚔️  Заблоковано",
                            f"Пристрій: {_best_device_label(host)}\n"
                            f"IP: {ip}   MAC: {mac}\n"
                            f"Тривалість: {dur_label}\n\n"
                            f"{msg}",
                            parent=parent)
                    elif method == "Manual":
                        # Метод Manual → показуємо інструкцію для ручного блокування
                        ManualBlockDialog(parent, host, engine, reason=msg)
                    else:
                        mb.showerror(
                            "❌  Помилка блокування", msg,
                            parent=parent)
                    if on_done_cb: on_done_cb(ok, msg, method)
                try: parent.after(0, show)
                except Exception: pass
            threading.Thread(target=run, daemon=True).start()

        def do_unblock():
            mac = host.get("mac","")
            engine.set_trusted(mac, True)
            mb.showinfo("🔓 Розблоковано",
                f"Пристрій {_best_device_label(host)} розблоковано\n"
                f"і позначений як довірений.", parent=self)
            self.destroy()
            if on_done_cb: on_done_cb(True, "unblocked")

        ctk.CTkButton(inner_f, text="🚫  Заблокувати",
            fg_color="#2a0000", hover_color="#3d0000",
            text_color=red, border_width=2, border_color=red,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=160,
            command=do_block).pack(side="left", padx=(0,8))

        ctk.CTkButton(inner_f, text="🔓  Розблокувати",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=2, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=170,
            command=do_unblock).pack(side="left")

        ctk.CTkButton(inner_f, text="✕ Скасувати",
            fg_color="transparent",
            hover_color=COLORS.get("bg_secondary","#0d0d1a"),
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=12),
            height=44, corner_radius=8, width=130,
            command=self.destroy).pack(side="right")

        self.bind("<Escape>", lambda e: self.destroy())


# ══════════════════════════════════════════════════════════════════
# PHONE INFO PANEL
# ══════════════════════════════════════════════════════════════════
class PhoneInfoPanel(ctk.CTkFrame):
    def __init__(self, parent, host: dict, **kw):
        card   = COLORS.get("bg_card","#1a1a2e")
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        super().__init__(parent, fg_color=card, corner_radius=8,
                         border_width=1, border_color=cyan, **kw)
        self._build(host)

    def _build(self, h: dict):
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        green  = COLORS.get("accent_green","#00ff88")
        yellow = COLORS.get("accent_yellow","#ffd700")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim","#444466")
        pi     = h.get("phone_info",{})

        hdr = ctk.CTkFrame(self, fg_color="transparent")
        hdr.pack(fill="x", padx=12, pady=(10,6))
        ctk.CTkLabel(hdr, text="📱  ІДЕНТИФІКАЦІЯ ПРИСТРОЮ",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=cyan).pack(side="left")
        method = h.get("phone_id_method","")
        if method:
            ctk.CTkLabel(hdr, text=f"  via {method}",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=dim).pack(side="left")

        grid = ctk.CTkFrame(self, fg_color="transparent")
        grid.pack(fill="x", padx=12, pady=(0,10))

        fields = []
        model = h.get("phone_model") or pi.get("phone_model","")
        if model:
            brand = h.get("phone_brand") or pi.get("phone_brand","")
            model_str = f"{brand} {model}".strip() if brand and brand not in model else model
            fields.append(("🔹 Модель", model_str, green))
        else:
            fields.append(("🔹 Модель", "Не визначено  🔍", dim))

        ssh_hn = (h.get("ssh_hostname") or "").strip()
        if ssh_hn and ssh_hn not in ("—","*"):
            fields.append(("★ SSH ім'я", ssh_hn, green))

        phone_name = h.get("phone_name") or pi.get("phone_name","")
        if phone_name and phone_name != ssh_hn:
            fields.append(("👤 Назва", phone_name, cyan))

        dhcp = (h.get("dhcp_hostname") or "").strip()
        if dhcp and dhcp not in ("—", phone_name, ssh_hn):
            src = h.get("dhcp_source","DHCP")
            fields.append((f"📋 {src}", dhcp, sec))

        phone_os = h.get("phone_os") or pi.get("phone_os","")
        if phone_os:   fields.append(("⚙️  ОС", phone_os, sec))
        elif h.get("os_hint"): fields.append(("⚙️  ОС", h["os_hint"], dim))

        if h.get("dhcp_fp_os"):     fields.append(("🔑 DHCP FP", h["dhcp_fp_os"], sec))
        vc = h.get("dhcp_vendor_class","")
        if vc and len(vc) > 3:      fields.append(("📦 VClass", vc[:40], dim))
        mdns = h.get("mdns_name","") or h.get("mdns_hardware_model","")
        if mdns:                     fields.append(("📡 mDNS", mdns[:40], sec))
        if h.get("netbios_name"):    fields.append(("🖧 NetBIOS", h["netbios_name"], sec))
        upnp = h.get("upnp_name","") or h.get("upnp_model","")
        if upnp:                     fields.append(("📺 UPnP", upnp[:40], sec))

        ttl = h.get("ttl")
        if ttl:
            hint = ("Linux/iOS/Android" if ttl<=64 else
                    "Windows" if ttl<=128 else "Мережевий пристрій" if ttl>=200 else "")
            fields.append(("⏱ TTL", f"{ttl}  [{hint}]", dim))

        for i, (label, value, color) in enumerate(fields):
            row, col = divmod(i, 2)
            cell = ctk.CTkFrame(grid, fg_color="transparent")
            cell.grid(row=row, column=col, padx=(0,20), pady=2, sticky="w")
            ctk.CTkLabel(cell, text=f"{label}:",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=dim).pack(anchor="w")
            ctk.CTkLabel(cell, text=str(value)[:48],
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=color).pack(anchor="w")


# ══════════════════════════════════════════════════════════════════
# DEVICE EDIT DIALOG
# ══════════════════════════════════════════════════════════════════
class DeviceDetailsDialog(ctk.CTkToplevel):
    """
    Діалог з усіма сирими технічними даними пристрою.
    Допомагає ідентифікувати невідомі пристрої коли автоматичне визначення не спрацювало.
    """
    def __init__(self, parent, host: dict):
        super().__init__(parent)
        self._host = host
        self.title(f"🔍  Технічні деталі — {host.get('ip','')}")
        self.resizable(True, True)
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        w  = min(720, sw - 100); h = min(720, sh - 80)
        self.minsize(520, 500)
        try:
            pw = parent.winfo_rootx(); py = parent.winfo_rooty()
            pw_w = parent.winfo_width(); pw_h = parent.winfo_height()
            x = max(0, min(pw + (pw_w - w) // 2, sw - w))
            y = max(0, min(py + (pw_h - h) // 2, sh - h))
        except Exception:
            x = (sw - w) // 2; y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        self.attributes("-topmost", True)
        self.grab_set(); self.focus_force()
        self.after(100, lambda: _bring_to_front(self))

        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self._build()

    def _build(self):
        h      = self._host
        green  = COLORS.get("accent_green", "#00ff88")
        cyan   = COLORS.get("accent_cyan", "#00d4ff")
        yellow = COLORS.get("accent_yellow", "#ffd700")
        red    = COLORS.get("accent_red", "#ff4444")
        sec    = COLORS.get("text_secondary", "#8888aa")
        dim    = COLORS.get("text_dim", "#444466")
        pri    = COLORS.get("text_primary", "#e0e0ff")
        card   = COLORS.get("bg_card", "#1a1a2e")
        border = COLORS.get("border", "#2a2a4a")

        # ── Заголовок ─────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")

        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", padx=18, pady=14, fill="x", expand=True)
        ctk.CTkLabel(left, text="🔍  ТЕХНІЧНІ ДЕТАЛІ ПРИСТРОЮ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=cyan).pack(anchor="w")
        ctk.CTkLabel(left, text=_best_device_label(h),
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=green).pack(anchor="w")
        ctk.CTkLabel(left,
            text="Усі дані що NetGuardian зібрав під час сканування.\n"
                 "Допоможе ідентифікувати пристрій вручну.",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=dim, justify="left").pack(anchor="w", pady=(4,0))
        ctk.CTkLabel(hdr, text=h.get("icon","❓"),
            font=ctk.CTkFont(size=36)).pack(side="right", padx=18)
        ctk.CTkFrame(self, fg_color=border, height=1).grid(row=0, column=0, sticky="sew")

        # ── Scroll area з усіма даними ────────────────────
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=COLORS.get("accent_cyan", "#00d4ff"),
            scrollbar_button_hover_color=COLORS.get("accent_cyan", "#00a8cc"))
        scroll.grid(row=1, column=0, sticky="nsew", padx=6)
        scroll.grid_columnconfigure(0, weight=1)

        # ── Секція: Базова ідентифікація ──────────────────
        self._build_section(scroll, "🆔  ІДЕНТИФІКАЦІЯ", cyan, [
            ("IP адреса",    h.get("ip", "—"),        green),
            ("MAC адреса",   h.get("mac", "—"),       green),
            ("MAC tail",     _mac_tail(h.get("mac", "")) or "—",  cyan),
            ("Vendor (OUI)", h.get("vendor", "—"),    pri),
            ("Тип пристрою", h.get("dev_type", "—"),  pri),
            ("Модель",       h.get("model", "—"),     pri),
            ("Hostname",     h.get("hostname", "—"),  pri),
            ("User label",   h.get("user_label", "—") or "—",  yellow),
        ])

        # ── Секція: Мережа ────────────────────────────────
        ports = h.get("open_ports", [])
        ports_str = ", ".join(str(p) for p in ports) if ports else "—"
        self._build_section(scroll, "🌐  МЕРЕЖА", cyan, [
            ("Gateway",      h.get("gateway", "—"),     pri),
            ("Connection",   h.get("connection_type", "—"), pri),
            ("Band",         h.get("band", "—") or "—", pri),
            ("Signal (dBm)", str(h.get("signal_dbm") or "—"), pri),
            ("Signal (%)",   str(h.get("signal_pct") or "—"), pri),
            ("TX Rate",      h.get("tx_rate", "—") or "—", pri),
            ("TTL",          str(h.get("ttl") or "—"),   cyan),
            ("Is online",    "✅ Так" if h.get("is_online") else "❌ Ні", green if h.get("is_online") else dim),
            ("Open ports",   ports_str, yellow if ports else dim),
        ])

        # ── Секція: Телефон ──────────────────────────────
        self._build_section(scroll, "📱  ТЕЛЕФОН / МОБІЛЬНИЙ ПРИСТРІЙ", cyan, [
            ("Phone brand",  h.get("phone_brand", "—") or "—", pri),
            ("Phone model",  h.get("phone_model", "—") or "—", pri),
            ("Phone name",   h.get("phone_name", "—") or "—",  pri),
            ("Phone OS",     h.get("phone_os", "—") or "—",    pri),
            ("ID method",    h.get("phone_id_method", "—") or "—", dim),
            ("Summary",      h.get("phone_summary", "—") or "—", dim),
        ])

        # ── Секція: Джерела даних ────────────────────────
        self._build_section(scroll, "📡  ДЖЕРЕЛА ДАНИХ", cyan, [
            ("NetBIOS name",    h.get("netbios_name", "—") or "—",    pri),
            ("mDNS name",       h.get("mdns_name", "—") or "—",       pri),
            ("DHCP hostname",   h.get("dhcp_hostname", "—") or "—",   pri),
            ("DHCP vendor",     h.get("dhcp_vendor_class", "—") or "—", dim),
            ("DHCP OS fp",      h.get("dhcp_fp_os", "—") or "—",      dim),
            ("DHCP device fp",  h.get("dhcp_fp_device", "—") or "—",  dim),
            ("SSH hostname",    h.get("ssh_hostname", "—") or "—",    pri),
            ("UPnP name",       h.get("upnp_name", "—") or "—",       pri),
            ("UPnP model",      h.get("upnp_model", "—") or "—",      pri),
            ("HTTP server",     h.get("http_server", "—") or "—",     pri),
            ("HTTP title",      h.get("http_title", "—") or "—",      pri),
            ("Cert CN",         h.get("cert_cn", "—") or "—",         pri),
            ("SNMP sysdescr",   (h.get("snmp_sysdescr", "") or "—")[:80], dim),
            ("OS hint",         h.get("os_hint", "—") or "—",         yellow),
        ])

        # ── Секція: Статус і довіра ──────────────────────
        self._build_section(scroll, "🛡️  БЕЗПЕКА І ДОВІРА", cyan, [
            ("Threat level",     h.get("threat", "—"),    red if h.get("threat") in ("danger","critical") else green),
            ("Is trusted",       "✅ Так" if h.get("is_trusted") else "❌ Ні",      green if h.get("is_trusted") else dim),
            ("Is allowed",       "✅ Так" if h.get("is_allowed") else "❌ Ні",      green if h.get("is_allowed") else dim),
            ("Alert dismissed",  "✅ Так" if h.get("alert_dismissed") else "❌ Ні", green if h.get("alert_dismissed") else dim),
            ("Is new",           "🆕 Так" if h.get("is_new") else "❌ Ні",          yellow if h.get("is_new") else dim),
            ("Is gateway",       "📡 Так" if h.get("is_gateway") else "❌ Ні",      green if h.get("is_gateway") else dim),
            ("Is self",          "🖥️ Так" if h.get("is_self") else "❌ Ні",          cyan if h.get("is_self") else dim),
        ])

        # ── Підказка ───────────────────────────────────
        hint_f = ctk.CTkFrame(scroll, fg_color=card, corner_radius=8,
                              border_width=1, border_color=yellow)
        hint_f.pack(fill="x", padx=12, pady=(8, 14))
        ctk.CTkLabel(hint_f, text="💡  ЯК ВПІЗНАТИ ПРИСТРІЙ?",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=yellow).pack(anchor="w", padx=14, pady=(10,4))
        ctk.CTkLabel(hint_f, text=(
            "• TTL=64 → Linux, Android, iOS, macOS\n"
            "• TTL=128 → Windows\n"
            "• TTL=255 → мережеве обладнання (роутери, комутатори)\n"
            "• Порт 62078 відкритий → iPhone/iPad (iOS)\n"
            "• Порт 5353 відкритий → є підтримка mDNS (зазвичай Apple)\n"
            "• Порт 5555 відкритий → Android Debug Bridge (часто планшет)\n"
            "• Vendor 'Apple' + немає hostname → iPhone з Private MAC\n"
            "• Vendor 'Samsung' + TTL=64 → Android (телефон або TV)\n"
            "\nКоли впізнав пристрій — закрий цей діалог і натисни\n"
            "'✏️ Змінити' щоб ввести власну назву ('Мій iPhone', 'Дружини ноут' і т.д.)"
        ), font=ctk.CTkFont(family="Consolas", size=10),
            text_color=pri, justify="left").pack(anchor="w", padx=14, pady=(0,10))

        # ── Футер з кнопками ──────────────────────────
        ftr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        ftr.grid(row=2, column=0, sticky="ew")

        def _copy_all():
            """Копіює всі дані пристрою в буфер обміну для діагностики."""
            lines = [f"=== Device Details: {h.get('ip','')} ==="]
            for key in sorted(h.keys()):
                val = h[key]
                if isinstance(val, (dict, list)):
                    val = str(val)[:100]
                lines.append(f"{key}: {val}")
            text = "\n".join(lines)
            try:
                self.clipboard_clear()
                self.clipboard_append(text)
                ctk.CTkLabel(ftr, text="✅ Скопійовано!", text_color=green,
                    font=ctk.CTkFont(size=10)).pack(side="left", padx=14)
            except Exception: pass

        ctk.CTkButton(ftr, text="📋 Копіювати все",
            fg_color="transparent", hover_color=card,
            text_color=sec, border_width=1, border_color=sec,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=32, corner_radius=6, width=140,
            command=_copy_all).pack(side="left", padx=12, pady=10)

        ctk.CTkButton(ftr, text="✖ Закрити",
            fg_color=cyan, hover_color="#00a8cc",
            text_color="#001a2e",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=32, corner_radius=6, width=120,
            command=self.destroy).pack(side="right", padx=12, pady=10)

    def _build_section(self, parent, title: str, title_color, rows: list):
        """Будує секцію з title і таблицею ключ-значення."""
        card_col = COLORS.get("bg_card", "#1a1a2e")
        sec_col  = COLORS.get("text_secondary", "#8888aa")

        sec = ctk.CTkFrame(parent, fg_color=card_col, corner_radius=8)
        sec.pack(fill="x", padx=12, pady=(8, 0))

        ctk.CTkLabel(sec, text=f"  {title}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=title_color).pack(anchor="w", padx=10, pady=(10, 6))

        grid = ctk.CTkFrame(sec, fg_color="transparent")
        grid.pack(fill="x", padx=14, pady=(0, 10))
        grid.grid_columnconfigure(1, weight=1)

        for i, (key, val, val_color) in enumerate(rows):
            # Skip empty/meaningless values to reduce clutter
            if val in (None, "", "—") and key not in ("IP адреса", "MAC адреса"):
                val = "—"

            ctk.CTkLabel(grid, text=f"{key}:",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=sec_col, anchor="w", width=150
            ).grid(row=i, column=0, sticky="w", pady=2)

            # Value може бути довгим — обмежуємо
            val_str = str(val) if val is not None else "—"
            if len(val_str) > 90:
                val_str = val_str[:87] + "..."

            ctk.CTkLabel(grid, text=val_str,
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=val_color, anchor="w", justify="left"
            ).grid(row=i, column=1, sticky="w", pady=2, padx=(4, 0))


class DeviceEditDialog(ctk.CTkToplevel):
    ICONS = ["📱","💻","🖥️","📡","📺","🎮","🔊","🖨️","📷","🔒","❓","🏠","👤","🏢"]

    def __init__(self, parent, host: dict, on_save_cb=None):
        super().__init__(parent)
        self._host = host; self._on_save = on_save_cb
        self._selected_icon = host.get("icon","❓")
        self.title(f"✏️  Редагування — {host.get('ip','')}")
        self.resizable(True, True)
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        w  = min(720, sw-100); h = min(900, sh-80)
        self.minsize(560, 600)
        try:
            pw = parent.winfo_rootx(); py2 = parent.winfo_rooty()
            pw_w = parent.winfo_width(); pw_h = parent.winfo_height()
            x = max(0, min(pw + (pw_w-w)//2, sw-w))
            y = max(0, min(py2 + (pw_h-h)//2, sh-h))
        except Exception:
            x = (sw-w)//2; y = (sh-h)//2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.configure(fg_color=COLORS.get("bg_secondary","#0d0d1a"))
        self.attributes("-topmost", True)
        self.grab_set(); self.focus_force()
        self.after(100, lambda: _bring_to_front(self))
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=1)
        self.grid_rowconfigure(2, weight=0)
        self.grid_columnconfigure(0, weight=1)
        self._build()

    def _build(self):
        h     = self._host
        green  = COLORS.get("accent_green","#00ff88")
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim","#444466")
        pri    = COLORS.get("text_primary","#e0e0ff")
        card   = COLORS.get("bg_card","#1a1a2e")
        border = COLORS.get("border","#2a2a4a")

        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        left = ctk.CTkFrame(hdr, fg_color="transparent")
        left.pack(side="left", padx=18, pady=14, fill="x", expand=True)
        ctk.CTkLabel(left, text="✏️  РЕДАГУВАННЯ ПРИСТРОЮ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=cyan).pack(anchor="w")
        ctk.CTkLabel(left, text=_best_device_label(h),
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=dim).pack(anchor="w")
        ssh_hn = (h.get("ssh_hostname") or "").strip()
        if ssh_hn and ssh_hn not in ("—","*"):
            ctk.CTkLabel(left, text=f"★  SSH: {ssh_hn}",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=green).pack(anchor="w")
        if h.get("phone_model"):
            ctk.CTkLabel(left, text=f"📱  {h['phone_model']}",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=green).pack(anchor="w")
        ctk.CTkLabel(hdr, text=h.get("icon","❓"),
            font=ctk.CTkFont(size=36)).pack(side="right", padx=18)
        ctk.CTkFrame(self, fg_color=border, height=1).grid(row=0, column=0, sticky="sew")

        # FIX-5: кастомний scrollbar і тут
        scroll = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0,
            scrollbar_button_color=COLORS.get("accent_cyan","#00d4ff"),
            scrollbar_button_hover_color=COLORS.get("accent_cyan","#00a8cc"))
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.grid_columnconfigure(0, weight=1)

        if h.get("phone_model") or h.get("phone_name") or h.get("phone_os") or h.get("ssh_hostname"):
            phone_f = ctk.CTkFrame(scroll, fg_color=card, corner_radius=10,
                                   border_width=1, border_color=cyan)
            phone_f.pack(fill="x", padx=16, pady=(14,0))
            ctk.CTkLabel(phone_f, text="  📱  ІДЕНТИФІКОВАНИЙ ПРИСТРІЙ",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=cyan).pack(anchor="w", padx=14, pady=(12,6))
            pf = []
            if ssh_hn and ssh_hn not in ("—","*"): pf.append(("★ SSH ім'я", ssh_hn, green))
            if h.get("phone_model"):
                brand = h.get("phone_brand","")
                model = h["phone_model"]
                ms = f"{brand} {model}".strip() if brand and brand not in model else model
                pf.append(("Модель", ms, green))
            if h.get("phone_name"): pf.append(("Назва", h["phone_name"], cyan))
            if h.get("phone_os"):   pf.append(("ОС", h["phone_os"], sec))
            if h.get("phone_id_method"): pf.append(("Метод", h["phone_id_method"], dim))
            pg = ctk.CTkFrame(phone_f, fg_color="transparent")
            pg.pack(fill="x", padx=14, pady=(0,12))
            for i, (label, value, color) in enumerate(pf):
                row, col = divmod(i, 2)
                cell = ctk.CTkFrame(pg, fg_color="transparent")
                cell.grid(row=row, column=col, padx=(0,24), pady=3, sticky="w")
                ctk.CTkLabel(cell, text=f"{label}:",
                    font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                    text_color=dim).pack(anchor="w")
                ctk.CTkLabel(cell, text=str(value)[:44],
                    font=ctk.CTkFont(family="Consolas", size=12),
                    text_color=color).pack(anchor="w")

        info_f = ctk.CTkFrame(scroll, fg_color=card, corner_radius=10,
                              border_width=1, border_color=border)
        info_f.pack(fill="x", padx=16, pady=(12,0))
        info_f.grid_columnconfigure((0,1), weight=1)
        ctk.CTkLabel(info_f, text="  📋  ВИЯВЛЕНО АВТОМАТИЧНО",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=dim).grid(row=0, column=0, columnspan=2, padx=14, pady=(12,8), sticky="w")

        auto_fields = [
            ("Виробник",  h.get("vendor","—")),
            ("Тип",       h.get("dev_type","—")),
            ("Hostname",  h.get("hostname","—")),
            ("DHCP ім'я", h.get("dhcp_hostname","") or "—"),
            ("Джерело",   h.get("dhcp_source","") or "—"),
            ("IP",        h.get("ip","—")),
            ("MAC",       h.get("mac","—")),
        ]
        if h.get("connection_type"): auto_fields.append(("З'єднання", h["connection_type"]))
        if h.get("band"):            auto_fields.append(("Діапазон",  h["band"]))
        if h.get("signal_pct") is not None:
            auto_fields.append(("Сигнал", f"{h['signal_pct']}% ({h.get('signal_dbm','?')} dBm)"))
        if h.get("bytes_sent") or h.get("bytes_recv"):
            sent = RouterClientReader._bytes_human(h.get("bytes_sent"))
            recv = RouterClientReader._bytes_human(h.get("bytes_recv"))
            auto_fields.append(("Трафік", f"↑{sent}  ↓{recv}"))
        if h.get("http_server"): auto_fields.append(("HTTP Server", h["http_server"][:40]))
        if h.get("netbios_name"): auto_fields.append(("NetBIOS", h["netbios_name"]))
        if h.get("cert_cn"):     auto_fields.append(("TLS Cert", h["cert_cn"][:40]))
        if h.get("mdns_name"):   auto_fields.append(("mDNS", h["mdns_name"]))
        if h.get("ttl"):         auto_fields.append(("TTL", str(h["ttl"])))
        if h.get("snmp_sysdescr"):
            auto_fields.append(("SNMP", h["snmp_sysdescr"][:44]))

        for i, (label, value) in enumerate(auto_fields):
            row, col = divmod(i, 2)
            sub = ctk.CTkFrame(info_f, fg_color="transparent")
            sub.grid(row=row+1, column=col, padx=(16,4), pady=(2,5), sticky="w")
            ctk.CTkLabel(sub, text=f"{label}:",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=dim).pack(anchor="w")
            ctk.CTkLabel(sub, text=str(value)[:44],
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=sec).pack(anchor="w")

        if h.get("open_ports"):
            ports_str = "  ".join(f"{p}/{CRITICAL_PORTS.get(p,('?',))[0]}" for p in h["open_ports"][:8])
            ctk.CTkLabel(info_f, text=f"  🔓 Порти: {ports_str}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=yellow).grid(row=99, column=0, columnspan=2, padx=14, pady=(8,14), sticky="w")
        else:
            ctk.CTkFrame(info_f, fg_color="transparent", height=6).grid(row=99, column=0)

        ctk.CTkFrame(scroll, fg_color=border, height=1).pack(fill="x", padx=16, pady=16)

        edit_f = ctk.CTkFrame(scroll, fg_color="transparent")
        edit_f.pack(fill="x", padx=16)
        ctk.CTkLabel(edit_f, text="  ✏️  ВАШІ НАЛАШТУВАННЯ",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=dim).pack(anchor="w", pady=(0,12))

        ctk.CTkLabel(edit_f, text="Назва пристрою:",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=sec).pack(anchor="w")
        self._name_var = ctk.StringVar(value=h.get("user_label",""))
        name_entry = ctk.CTkEntry(edit_f, textvariable=self._name_var,
            placeholder_text="напр. 'Мій iPhone 15', 'Smart TV зал'…",
            font=ctk.CTkFont(family="Consolas", size=13),
            fg_color=card, border_color=cyan,
            text_color=pri, height=44, corner_radius=8)
        name_entry.pack(fill="x", pady=(4,16)); name_entry.focus_set()

        ctk.CTkLabel(edit_f, text="Нотатки:",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=sec).pack(anchor="w")
        self._notes_box = ctk.CTkTextbox(edit_f,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=card, text_color=sec, height=76,
            corner_radius=8, border_color=border, border_width=1)
        self._notes_box.pack(fill="x", pady=(4,18))
        if h.get("user_notes"): self._notes_box.insert("0.0", h["user_notes"])

        ctk.CTkLabel(edit_f, text="Іконка пристрою:",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=sec).pack(anchor="w")
        icon_scroll = ctk.CTkScrollableFrame(edit_f, fg_color="transparent", height=60,
            orientation="horizontal",
            scrollbar_button_color=COLORS.get("accent_cyan","#00d4ff"),
            scrollbar_button_hover_color=COLORS.get("accent_cyan","#00a8cc"))
        icon_scroll.pack(fill="x", pady=(4,18))
        self._icon_btns: list = []
        for ico in self.ICONS:
            is_sel = (ico == self._selected_icon)
            btn = ctk.CTkButton(icon_scroll, text=ico,
                font=ctk.CTkFont(size=22), width=48, height=48, corner_radius=8,
                fg_color="#003322" if is_sel else card,
                hover_color=COLORS.get("bg_secondary","#0d0d1a"),
                border_width=2 if is_sel else 1,
                border_color=green if is_sel else border,
                text_color="white",
                command=lambda ic=ico: self._pick_icon(ic))
            btn.pack(side="left", padx=3)
            self._icon_btns.append(btn)

        ctk.CTkFrame(edit_f, fg_color=border, height=1).pack(fill="x", pady=(0,12))

        trust_f = ctk.CTkFrame(edit_f, fg_color=card, corner_radius=10,
                               border_width=1, border_color=border)
        trust_f.pack(fill="x", pady=(0,10))
        tl = ctk.CTkFrame(trust_f, fg_color="transparent")
        tl.pack(side="left", padx=16, pady=14)
        ctk.CTkLabel(tl, text="🛡️  Довірений пристрій",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=pri).pack(anchor="w")
        ctk.CTkLabel(tl, text="Алерти не показуватимуться",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=dim).pack(anchor="w")
        self._trust_toggle = ToggleButton(trust_f,
            text_on="ДОВІРЯЮ", text_off="НЕ ДОВІРЯЮ",
            initial=h.get("is_trusted",False),
            color_on=green, color_off=COLORS.get("text_dim","#444466"),
            width=140, height=34)
        self._trust_toggle.pack(side="right", padx=16)

        self._allow_toggle = None
        if h.get("threat") in ("warn","danger","critical"):
            allow_f = ctk.CTkFrame(edit_f, fg_color=card, corner_radius=10,
                                   border_width=1, border_color=border)
            allow_f.pack(fill="x", pady=(0,10))
            al = ctk.CTkFrame(allow_f, fg_color="transparent")
            al.pack(side="left", padx=16, pady=14)
            ctk.CTkLabel(al, text="🔕  Дозволити (зняти попередження)",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=pri).pack(anchor="w")
            ctk.CTkLabel(al, text="Пристрій вважатиметься безпечним",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=dim).pack(anchor="w")
            self._allow_toggle = ToggleButton(allow_f,
                text_on="ДОЗВОЛЕНО", text_off="СТЕЖИТИ",
                initial=h.get("alert_dismissed",False),
                color_on="#44ff88", color_off=COLORS.get("text_dim","#444466"),
                width=150, height=34)
            self._allow_toggle.pack(side="right", padx=16)

        ctk.CTkFrame(scroll, fg_color="transparent", height=20).pack()

        ctk.CTkFrame(self, fg_color=border, height=1).grid(row=1, column=0, sticky="sew")
        footer = ctk.CTkFrame(self, fg_color=card, corner_radius=0, height=70)
        footer.grid(row=2, column=0, sticky="ew"); footer.grid_propagate(False)
        btn_row = ctk.CTkFrame(footer, fg_color="transparent")
        btn_row.pack(fill="both", expand=True, padx=18, pady=12)
        ctk.CTkLabel(btn_row, text="Enter — зберегти  ·  Esc — скасувати",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=dim).pack(side="left")
        ctk.CTkButton(btn_row, text="✕  Скасувати",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary","#0d0d1a"),
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=12),
            height=44, corner_radius=8, width=140,
            command=self.destroy).pack(side="right", padx=(10,0))
        ctk.CTkButton(btn_row, text="💾  ЗБЕРЕГТИ",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=2, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=150,
            command=self._save).pack(side="right")
        self.bind("<Return>", lambda e: self._save())
        self.bind("<Escape>", lambda e: self.destroy())

    def _pick_icon(self, icon: str):
        self._selected_icon = icon
        green  = COLORS.get("accent_green","#00ff88")
        card   = COLORS.get("bg_card","#1a1a2e")
        border = COLORS.get("border","#2a2a4a")
        for btn in self._icon_btns:
            is_sel = (btn.cget("text") == icon)
            btn.configure(fg_color="#003322" if is_sel else card,
                          border_width=2 if is_sel else 1,
                          border_color=green if is_sel else border)

    def _save(self):
        if self._on_save:
            self._on_save({
                "mac":             self._host["mac"],
                "label":           self._name_var.get().strip(),
                "notes":           self._notes_box.get("0.0","end").strip(),
                "trusted":         self._trust_toggle.get(),
                "alert_dismissed": self._allow_toggle.get() if self._allow_toggle else False,
                "icon":            self._selected_icon,
            })
        self.destroy()


# ══════════════════════════════════════════════════════════════════
# SCAN OVERLAY — тільки для першого / ручного сканування
# ══════════════════════════════════════════════════════════════════
class ScanOverlay:
    _SPIN = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def __init__(self, parent):
        self._parent = parent; self._frame = None
        self._log_lbls: list = []; self._lines: list = []
        self._spin_job = self._bar_job = None; self._tick = 0

    def show(self):
        self._destroy()
        red  = COLORS.get("accent_red","#ff4444")
        bg   = COLORS.get("bg_secondary","#0d0d1a")
        card = COLORS.get("bg_card","#1a1a2e")
        self._frame = ctk.CTkFrame(self._parent, fg_color=bg, corner_radius=14,
                                   border_width=2, border_color=red)
        self._frame.place(relx=0.5, rely=0.5, anchor="center",
                          relwidth=0.72, relheight=0.78)
        self._frame.lift()
        self._frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self._frame, text="🛡️  АУДИТ БЕЗПЕКИ LAN",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=red).grid(row=0, column=0, pady=(28,6))
        ctk.CTkLabel(self._frame,
            text="Router API · ARP · mDNS · SSDP · NetBIOS · Ping · Port scan · Phone ID",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_secondary","#8888aa")).grid(row=1, column=0, pady=(0,18))
        ctk.CTkFrame(self._frame, fg_color=COLORS.get("border","#2a2a4a"),
                     height=1).grid(row=2, column=0, sticky="ew", padx=40, pady=(0,16))
        log_f = ctk.CTkFrame(self._frame, fg_color="transparent")
        log_f.grid(row=3, column=0, padx=40, sticky="ew")
        log_f.grid_columnconfigure(0, weight=1)
        self._log_lbls = []
        for i in range(10):
            lbl = ctk.CTkLabel(log_f, text="",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS.get("text_dim","#444466"), anchor="w")
            lbl.grid(row=i, column=0, sticky="ew", pady=1)
            self._log_lbls.append(lbl)
        self._spin_lbl = ctk.CTkLabel(self._frame, text="",
            font=ctk.CTkFont(family="Consolas", size=12), text_color=red)
        self._spin_lbl.grid(row=4, column=0, pady=(18,8))
        self._prog_bg = ctk.CTkFrame(self._frame, fg_color=card, height=10, corner_radius=5)
        self._prog_bg.grid(row=5, column=0, padx=40, pady=(0,28), sticky="ew")
        self._prog_bg.grid_propagate(False)
        self._prog_fill = ctk.CTkFrame(self._prog_bg, fg_color=red, height=10, corner_radius=5, width=10)
        self._prog_fill.place(x=0, y=0, relheight=1)
        self._lines = []; self._tick = 0
        self._animate_spinner(); self._animate_bar()

    def update(self, text: str):
        if not self._frame: return
        self._lines.append(text)
        if len(self._lines) > 10: self._lines = self._lines[-10:]
        for i, lbl in enumerate(self._log_lbls):
            line = self._lines[i] if i < len(self._lines) else ""
            col = (COLORS.get("accent_green","#00ff88") if "✅" in line else
                   COLORS.get("accent_red","#ff4444") if "⚠️" in line else
                   COLORS.get("accent_cyan","#00d4ff") if "📱" in line else
                   COLORS.get("text_secondary","#8888aa"))
            try: lbl.configure(text=line[:84], text_color=col)
            except Exception: pass

    def _animate_spinner(self):
        if not self._frame: return
        try: self._spin_lbl.configure(text=f"{self._SPIN[self._tick%len(self._SPIN)]}  сканую мережу…")
        except Exception: return
        self._tick += 1
        self._spin_job = self._frame.after(80, self._animate_spinner)

    def _animate_bar(self):
        if not self._frame: return
        import math
        pct = abs(math.sin(time.time()*0.9))
        try:
            w = max(10, int(self._prog_bg.winfo_width()*pct))
            self._prog_fill.configure(width=w)
        except Exception: pass
        self._bar_job = self._frame.after(40, self._animate_bar)

    def hide(self): self._destroy()

    def _destroy(self):
        for job in (self._spin_job, self._bar_job):
            if job:
                try: self._frame.after_cancel(job)
                except Exception: pass
        if self._frame:
            try: self._frame.destroy()
            except Exception: pass
            self._frame = None


# ══════════════════════════════════════════════════════════════════
# SECTION HEADER
# ══════════════════════════════════════════════════════════════════
class SectionHeader(ctk.CTkFrame):
    def __init__(self, parent, title: str, count: int, color: str = None, **kw):
        bg = COLORS.get("bg_secondary","#0d0d1a")
        super().__init__(parent, fg_color=bg, corner_radius=0, height=38, **kw)
        color = color or COLORS.get("text_dim","#444466")
        ctk.CTkFrame(self, fg_color=color, width=5, height=22,
                     corner_radius=3).pack(side="left", padx=(12,10), pady=8)
        ctk.CTkLabel(self, text=title,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=color).pack(side="left")
        badge = ctk.CTkFrame(self, fg_color=COLORS.get("bg_card","#1a1a2e"), corner_radius=12)
        badge.pack(side="left", padx=(10,0))
        ctk.CTkLabel(badge, text=f"  {count}  ",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=color).pack(padx=4, pady=3)
        ctk.CTkFrame(self, fg_color=COLORS.get("border","#2a2a4a"),
                     height=1).pack(side="left", fill="x", expand=True, padx=(12,0))


# ══════════════════════════════════════════════════════════════════
# DEVICE CARD
# ══════════════════════════════════════════════════════════════════
class DeviceCard(ctk.CTkFrame):
    def __init__(self, parent, host: dict,
                 on_edit=None, on_trust=None, on_block=None,
                 on_allow=None, on_dismiss=None, on_speed=None, **kw):
        bg, border = _threat_style(host["threat"],
                                   host.get("is_trusted",False),
                                   host.get("alert_dismissed",False))
        super().__init__(parent, fg_color=bg, corner_radius=12,
                         border_width=1, border_color=border, **kw)
        self._host = host; self._on_edit = on_edit; self._on_trust = on_trust
        self._on_block = on_block; self._on_allow = on_allow
        self._on_dismiss = on_dismiss; self._on_speed = on_speed
        self._phone_expanded = False; self._phone_panel = None
        self.grid_columnconfigure(2, weight=1)
        self._build()

    @staticmethod
    def _is_random_mac(mac: str) -> bool:
        try: return bool(int(mac.split(":")[0], 16) & 0x02)
        except Exception: return False

    def _build(self):
        h      = self._host
        green  = COLORS.get("accent_green","#00ff88")
        yellow = COLORS.get("accent_yellow","#ffd700")
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        red    = COLORS.get("accent_red","#ff4444")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim","#444466")
        pri    = COLORS.get("text_primary","#e0e0ff")
        card   = COLORS.get("bg_card","#1a1a2e")
        is_random = self._is_random_mac(h.get("mac",""))
        _, stripe_col = _threat_style(h["threat"], h.get("is_trusted"), h.get("alert_dismissed"))

        ctk.CTkFrame(self, fg_color=stripe_col, width=5, corner_radius=3).grid(
            row=0, column=0, padx=(6,0), pady=8, sticky="ns", rowspan=8)

        icon = get_device_icon(h)
        ctk.CTkLabel(self, text=icon, font=ctk.CTkFont(size=28)).grid(
            row=0, column=1, padx=(12,10), pady=(12,4), rowspan=2, sticky="n")

        info = ctk.CTkFrame(self, fg_color="transparent")
        info.grid(row=0, column=2, padx=(0,8), pady=(10,2), sticky="ew")

        name_row = ctk.CTkFrame(info, fg_color="transparent")
        name_row.pack(fill="x", anchor="w")

        display_name = _best_device_label(h)
        src_badge, src_color = _name_source_badge(h)

        name_color = (green if h.get("user_label") else
                      cyan  if h.get("phone_name") or
                               (h.get("ssh_hostname") or "").strip() not in ("","—","*","") else
                      cyan  if h.get("is_self") or h.get("is_gateway") else
                      cyan  if h.get("dhcp_hostname") or h.get("mdns_name") else
                      yellow if is_random and not h.get("user_label") else pri)

        threat_prefix = ("⛔ " if h.get("threat")=="critical" and not h.get("is_trusted") and not h.get("alert_dismissed") else
                         "⚠️ " if h.get("threat")=="danger"   and not h.get("is_trusted") and not h.get("alert_dismissed") else "")

        online_dot = "🟢 " if h.get("is_online", True) else "⚪ "
        ctk.CTkLabel(name_row, text=online_dot, font=ctk.CTkFont(size=13)).pack(side="left", padx=(0,2))
        ctk.CTkLabel(name_row, text=threat_prefix+display_name,
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=name_color).pack(side="left")

        if src_badge:
            src_f = ctk.CTkFrame(name_row, fg_color=COLORS.get("bg_secondary","#0d0d1a"), corner_radius=5)
            src_f.pack(side="left", padx=(8,0))
            ctk.CTkLabel(src_f, text=f" {src_badge} ",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=src_color).pack(padx=2, pady=1)

        if h.get("is_self"):    self._badge(name_row," YOU ",     "#003a6e", cyan)
        elif h.get("is_gateway"): self._badge(name_row," GATEWAY ","#002200", green)
        if h.get("is_new") and not h.get("is_self") and not h.get("is_gateway"):
            self._badge(name_row," 🆕 NEW ",       "#3a2200", yellow)
        if h.get("is_trusted") and not h.get("is_self"):
            self._badge(name_row," ✅ TRUSTED ",    "#002200", green)
        if h.get("alert_dismissed") and not h.get("is_trusted"):
            self._badge(name_row," ✓ ДОЗВОЛЕНО ",  "#001a00", "#44ff88")
        if is_random and not h.get("user_label") and not h.get("is_self"):
            self._badge(name_row," 🔒 RAND MAC ",   "#1a1a00", yellow)
        if h.get("is_mac_only") or not h.get("is_online",True):
            self._badge(name_row," 💤 СОН ",        "#1a1a1a", dim)

        if h.get("threat") in ("critical","danger") and not h.get("is_trusted") and not h.get("alert_dismissed"):
            t_row = ctk.CTkFrame(info, fg_color="transparent"); t_row.pack(fill="x", anchor="w", pady=(2,0))
            ctk.CTkLabel(t_row, text=("⛔  КРИТИЧНА ЗАГРОЗА" if h["threat"]=="critical" else "⚠️  НЕБЕЗПЕКА"),
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=red).pack(side="left")
        elif h.get("threat")=="warn" and not h.get("is_trusted") and not h.get("alert_dismissed"):
            t_row = ctk.CTkFrame(info, fg_color="transparent"); t_row.pack(fill="x", anchor="w", pady=(2,0))
            ctk.CTkLabel(t_row, text="🟡  ПІДОЗРІЛИЙ ПРИСТРІЙ",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"), text_color=yellow).pack(side="left")

        id_parts = []
        phone_summary = h.get("phone_summary","")
        phone_os_raw  = (h.get("phone_os") or "").strip()
        phone_brand   = (h.get("phone_brand") or "").strip()
        phone_model   = (h.get("phone_model") or "").strip()

        if not h.get("is_gateway") and not h.get("is_self"):
            if phone_summary and phone_summary not in ("Android", "Android-смартфон"):
                # phone_summary вже є — перевіряємо чи не дублюємо OS
                summary_has_os = phone_os_raw and (
                    phone_os_raw.split()[0].lower() in phone_summary.lower()
                )
                id_parts.append((phone_summary, cyan))
                if phone_os_raw and not summary_has_os:
                    id_parts.append((f"[{phone_os_raw}]", sec))
            elif phone_brand:
                # Немає summary або він generic — показуємо brand + OS окремо
                brand_str = f"{phone_brand} {phone_model}".strip() if phone_model else phone_brand
                id_parts.append((brand_str, cyan))
                if phone_os_raw and phone_os_raw not in brand_str:
                    id_parts.append((f"[{phone_os_raw}]", sec))
        dhcp_hn = (h.get("dhcp_hostname") or "").strip()
        if not phone_summary and dhcp_hn and dhcp_hn not in ("—", display_name) and not h.get("is_gateway"):
            id_parts.append((f"DHCP: {dhcp_hn}", sec))
        if id_parts:
            s_row = ctk.CTkFrame(info, fg_color="transparent"); s_row.pack(fill="x", anchor="w", pady=(2,0))
            for txt, col in id_parts:
                ctk.CTkLabel(s_row, text=f"  {txt}",
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    text_color=col).pack(side="left")

        # FIX-1/FIX-5: Роутер — назва гарантовано показується без дублювання
        if h.get("is_gateway"):
            vendor   = (h.get("vendor") or "").strip()
            hostname = (h.get("hostname") or "").strip()
            upnp     = (h.get("upnp_name") or h.get("upnp_model") or "").strip()
            user_lbl = h.get("user_label","")

            if user_lbl:
                # Назва вручну — показуємо тільки її
                gw_line = user_lbl
            elif hostname and hostname not in ("—","router","","unknown"):
                # hostname вже є повна назва (напр. "Archer C64 AC1200 MU-MIMO Wi-Fi Router")
                # Додаємо vendor-префікс ТІЛЬКИ якщо він відсутній у hostname
                if vendor and vendor.lower() not in hostname.lower():
                    gw_line = f"{vendor}  ·  {hostname}"
                else:
                    gw_line = hostname
            elif upnp:
                gw_line = (f"{vendor}  ·  {upnp}" if vendor and vendor.lower() not in upnp.lower()
                           else upnp)
            elif vendor and vendor not in ("Невідомо","Роутер",""):
                snmp = (h.get("snmp_sysdescr") or "").strip()
                gw_line = f"{vendor}  ·  {snmp.split(chr(10))[0][:44]}" if snmp else vendor
            else:
                gw_line = f"Роутер {h.get('ip','')}"

            ctk.CTkLabel(info, text=gw_line,
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=green).pack(anchor="w", pady=(2,0))

        vendor_str = self._build_vendor_str(h)
        if vendor_str:
            ctk.CTkLabel(info, text=vendor_str,
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=sec).pack(anchor="w", pady=(2,0))

        ip_parts = [f"IP: {h['ip'] if h['ip'] and h['ip']!='—' else 'IP не отримано'}",
                    f"MAC: {h['mac']}"]
        shown_names = {display_name.lower()}
        for key, label in [("dhcp_hostname","DHCP"),("netbios_name","NetBIOS"),("mdns_name","mDNS")]:
            val = (h.get(key) or "").strip()
            if val and val.lower() not in shown_names and val not in ("—","*"):
                shown_names.add(val.lower()); ip_parts.append(f"{label}: {val[:28]}"); break
        ctk.CTkLabel(info, text="   ·   ".join(ip_parts),
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=dim).pack(anchor="w")

        ct = h.get("connection_type","")
        if ct:
            conn_row = ctk.CTkFrame(info, fg_color="transparent"); conn_row.pack(anchor="w", pady=(3,0))
            conn_text = (f"📡  WiFi{' ' + h.get('band','') if h.get('band') else ''}" if ct=="WiFi"
                         else "🔌  LAN (дротовий)")
            conn_col  = cyan if ct=="WiFi" else green
            ctk.CTkLabel(conn_row, text=conn_text,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=conn_col).pack(side="left")
            if ct=="WiFi" and h.get("signal_pct") is not None:
                bar_str, sig_col = _signal_bar_widget(h["signal_pct"])
                dbm = h.get("signal_dbm","")
                ctk.CTkLabel(conn_row,
                    text=f"   {bar_str}" + (f"  {dbm} dBm" if dbm else ""),
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color=sig_col).pack(side="left")

        traffic_parts = []
        if h.get("bytes_sent") or h.get("bytes_recv"):
            sent = RouterClientReader._bytes_human(h.get("bytes_sent"))
            recv = RouterClientReader._bytes_human(h.get("bytes_recv"))
            if sent or recv: traffic_parts.append(f"↑{sent}  ↓{recv}")
        if h.get("tx_rate"):        traffic_parts.append(f"TX:{h['tx_rate']}")
        if h.get("connected_time"): traffic_parts.append(f"⏱ {RouterClientReader._seconds_human(h['connected_time'])}")
        if traffic_parts:
            ctk.CTkLabel(info, text="   ".join(traffic_parts),
                font=ctk.CTkFont(family="Consolas", size=11), text_color=dim).pack(anchor="w")

        detail = []
        if h.get("http_server"):  detail.append(f"Server: {h['http_server'][:38]}")
        if h.get("http_title"):   detail.append(f"Title: {h['http_title'][:35]}")
        if h.get("cert_cn"):      detail.append(f"TLS: {h['cert_cn'][:35]}")
        if h.get("user_notes"):   detail.append(f"📝 {h['user_notes'][:44]}")
        if detail:
            ctk.CTkLabel(info, text="   ·   ".join(detail[:2]),
                font=ctk.CTkFont(family="Consolas", size=11), text_color=sec).pack(anchor="w")

        if is_random and not h.get("user_label") and not h.get("is_self"):
            has_name = bool(h.get("phone_name") or h.get("dhcp_hostname") or
                           h.get("phone_model") or h.get("ssh_hostname"))
            if not has_name:
                rf = ctk.CTkFrame(info, fg_color="#1a1500", corner_radius=6)
                rf.pack(fill="x", pady=(6,2), padx=(0,6))
                ctk.CTkLabel(rf,
                    text="ℹ️  ЯК ІДЕНТИФІКУВАТИ ПРИСТРІЙ:",
                    font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                    text_color=yellow).pack(anchor="w", padx=10, pady=(6,2))
                ctk.CTkLabel(rf,
                    text=(
                        "   1. На телефоні: Налаштування Wi-Fi → твоя мережа → MAC → "
                        "побач останні 6 символів\n"
                        "   2. Порівняй з MAC вище → так зрозумієш який це пристрій\n"
                        "   3. Натисни '✏️ Змінити' → введи власну назву → збережеться назавжди\n"
                        "   💡 Щоб назви показувались автоматично — вимкни 'Private MAC' у "
                        "Wi-Fi налаштуваннях для домашньої мережі"
                    ),
                    font=ctk.CTkFont(family="Consolas", size=10),
                    text_color=sec, justify="left").pack(anchor="w", padx=10, pady=(0,6))

        if h["open_ports"]:
            ports_f = ctk.CTkFrame(self, fg_color="transparent")
            ports_f.grid(row=2, column=2, padx=(0,8), pady=(2,4), sticky="w")
            ctk.CTkLabel(ports_f, text="ПОРТИ:",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=dim).pack(side="left", padx=(0,6))
            for port in h["open_ports"][:10]:
                meta = CRITICAL_PORTS.get(port,("?","?","🟡"))
                ctk.CTkLabel(ports_f,
                    text=f" {port}/{meta[0]} ",
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                    text_color=_port_color(port), fg_color=card, corner_radius=5,
                    ).pack(side="left", padx=2)

        risk_txt = get_device_threat_summary(h)
        # FIX: is_banned має пріоритет над is_allowed — неможливо бути одночасно
        # "заблокованим" і "дозволеним"
        if h.get("is_banned"):
            risk_txt = "🚫 ЗАБЛОКОВАНО"
            risk_col = red
        else:
            risk_col = ("#44ff88" if h.get("alert_dismissed") or h.get("is_allowed") else
                        green if h.get("is_trusted") and h["threat"] in ("warn","safe") else
                        cyan  if h.get("is_self") else
                        green if h.get("is_gateway") else
                        {"critical":red,"danger":red,"warn":yellow,"safe":green}.get(h["threat"],green))

        # Sticky-cache позначка — пристрій зараз не відповів, але показуємо
        # бо бачили <5 хвилин тому (актуально для Android/iOS у doze)
        if h.get("_sticky") and not h.get("is_banned"):
            age = h.get("_sticky_age_sec", 0)
            if age < 60:
                age_str = f"{age}с"
            else:
                age_str = f"{age//60}хв"
            risk_txt = f"{risk_txt}  💾 sleep ({age_str} тому)"
            # Трохи приглушуємо колір щоб візуально відрізнити
            risk_col = "#88aa88" if risk_col == green else risk_col

        ctk.CTkLabel(self, text=risk_txt,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=risk_col).grid(row=3, column=2, padx=(0,8), pady=(0,8), sticky="w")

        act = ctk.CTkFrame(self, fg_color="transparent")
        act.grid(row=0, column=3, rowspan=8, padx=(0,12), pady=10, sticky="ns")

        # NEW: Для Private MAC без імені — виділена кнопка "Дати ім'я"
        # (помітніша за стандартну "✏️ Змінити")
        is_unnamed_random = (is_random and not h.get("user_label")
                            and not h.get("phone_model") and not h.get("phone_name")
                            and not h.get("is_self") and not h.get("is_gateway"))

        if is_unnamed_random:
            ctk.CTkButton(act, text="✏️ Дати ім'я",
                fg_color=yellow, hover_color="#cca300",
                text_color="#1a1500",
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=6, width=112,
                command=lambda hh=h: self._quick_rename(hh)
                ).pack(pady=(0,5))

        ctk.CTkButton(act, text="✏️ Змінити",
            fg_color="#0a2233", hover_color=card,
            text_color=cyan, border_width=1, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=112,
            command=lambda: self._on_edit(h) if self._on_edit else None
            ).pack(pady=(0,5))

        # NEW: кнопка "🔍 Деталі" — показує сирі технічні дані
        ctk.CTkButton(act, text="🔍 Деталі",
            fg_color="transparent", hover_color=card,
            text_color=sec, border_width=1, border_color=sec,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=34, corner_radius=6, width=112,
            command=lambda hh=h: DeviceDetailsDialog(self.master, hh)
            ).pack(pady=(0,5))

        is_phone = (h.get("icon")=="📱" or h.get("phone_model") or h.get("phone_brand") or h.get("phone_name"))
        if is_phone and not h.get("is_self") and not h.get("is_gateway"):
            has_data = bool(h.get("phone_model") or h.get("phone_name") or
                           h.get("phone_os") or h.get("mdns_name") or
                           h.get("ssh_hostname") or h.get("dhcp_hostname"))
            btn_text  = "📋 Деталі" if has_data else "🔍 Пошук"
            btn_color = cyan if has_data else dim
            self._detail_btn = ctk.CTkButton(act, text=btn_text,
                fg_color="#001a2e" if has_data else "transparent",
                hover_color=card, text_color=btn_color,
                border_width=1, border_color=btn_color,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=6, width=112,
                command=self._toggle_phone_panel)
            self._detail_btn.pack(pady=(0,5))

        if not h.get("is_self") and not h.get("is_gateway") and h["mac"] != "—":
            is_t = h.get("is_trusted",False)
            self._trust_btn = ctk.CTkButton(act,
                text="✅ Довіряю" if is_t else "❓ Довіряти?",
                fg_color="#002200" if is_t else "transparent",
                hover_color="#003300",
                text_color=green if is_t else yellow,
                border_width=1, border_color=green if is_t else dim,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=6, width=112,
                command=self._quick_trust)
            self._trust_btn.pack(pady=(0,5))

            if h.get("threat") in ("warn","danger","critical") and not h.get("alert_dismissed"):
                ctk.CTkButton(act, text="🔕 Дозволити",
                    fg_color="#001a00", hover_color="#002a00",
                    text_color="#44ff88", border_width=1, border_color="#44ff88",
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                    height=34, corner_radius=6, width=112,
                    command=self._quick_allow).pack(pady=(0,5))
            elif h.get("alert_dismissed"):
                ctk.CTkButton(act, text="🔔 Відновити",
                    fg_color="transparent", hover_color=card,
                    text_color=dim, border_width=1, border_color=dim,
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                    height=34, corner_radius=6, width=112,
                    command=self._restore_alert).pack(pady=(0,5))

            ctk.CTkButton(act, text="🚫 Блокувати",
                fg_color="transparent", hover_color="#2a0000",
                text_color=red, border_width=1, border_color=red,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=6, width=112,
                command=lambda: self._on_block(h) if self._on_block else None
                ).pack(pady=(0,5))

            # FIX-1: кнопка Speed Control
            ctk.CTkButton(act, text="⚡ Швидкість",
                fg_color="transparent", hover_color="#1a1a00",
                text_color=COLORS.get("accent_yellow","#ffd700"),
                border_width=1, border_color=COLORS.get("accent_yellow","#ffd700"),
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=6, width=112,
                command=lambda: self._on_speed(h) if self._on_speed else None
                ).pack()

    def _toggle_phone_panel(self):
        if self._phone_expanded and self._phone_panel:
            self._phone_panel.grid_forget(); self._phone_panel.destroy()
            self._phone_panel = None; self._phone_expanded = False
            try: self._detail_btn.configure(text="📋 Деталі")
            except Exception: pass
        else:
            self._phone_panel = PhoneInfoPanel(self, self._host)
            self._phone_panel.grid(row=6, column=1, columnspan=3, padx=(4,12), pady=(0,10), sticky="ew")
            self._phone_expanded = True
            try: self._detail_btn.configure(text="▲ Згорнути")
            except Exception: pass

    @staticmethod
    def _build_vendor_str(h: dict) -> str:
        vendor  = (h.get("vendor","") or "").strip()
        model   = (h.get("model","") or "").strip()
        devtype = (h.get("dev_type","") or "").strip()
        phone_brand = (h.get("phone_brand","") or "").strip()

        # FIX-3: якщо є phone_summary — vendor показуємо тільки якщо він відрізняється від phone_brand
        if h.get("phone_summary") or h.get("phone_brand"):
            # Apple/Samsung вже показані в phone_summary — не дублюємо
            if vendor and vendor not in ("Невідомо","Приватний MAC","") \
               and vendor.lower() != phone_brand.lower():
                return vendor
            return ""
        if h.get("is_gateway"):
            return ""
        parts = []
        if vendor and vendor not in ("Невідомо","Приватний MAC",""):
            parts.append(vendor)
        if model and model not in (devtype, "Пристрій", ""):
            parts.append(model)
        elif devtype and devtype not in ("Пристрій",""):
            parts.append(devtype)
        if not parts:
            try:
                if int(h.get("mac","00").split(":")[0], 16) & 0x02:
                    brand = h.get("phone_brand","")
                    if brand: return f"{brand} — Приватний MAC"
                    return "Смартфон / Планшет  (Приватний MAC)"
            except Exception:
                pass
            if devtype and devtype not in ("Пристрій",""):
                return devtype
            return ""
        return "  ·  ".join(parts)

    @staticmethod
    def _badge(parent, text: str, bg: str, fg: str):
        ctk.CTkLabel(parent, text=text,
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=fg, fg_color=bg, corner_radius=6).pack(side="left", padx=(7,0))

    def _quick_trust(self):
        new_state = not self._host.get("is_trusted",False)
        self._host["is_trusted"] = new_state
        green  = COLORS.get("accent_green","#00ff88")
        yellow = COLORS.get("accent_yellow","#ffd700")
        dim    = COLORS.get("text_dim","#444466")
        self._trust_btn.configure(
            text="✅ Довіряю" if new_state else "❓ Довіряти?",
            fg_color="#002200" if new_state else "transparent",
            text_color=green if new_state else yellow,
            border_color=green if new_state else dim)
        if self._on_trust: self._on_trust(self._host["mac"], new_state)

    def _quick_allow(self):
        self._host["alert_dismissed"] = True; self._host["is_allowed"] = True
        if self._on_allow: self._on_allow(self._host["mac"])

    def _restore_alert(self):
        self._host["alert_dismissed"] = False; self._host["is_allowed"] = False
        if self._on_dismiss: self._on_dismiss(self._host["mac"])

    def _quick_rename(self, host: dict):
        """Швидке перейменування через маленький popup — для пристроїв з Private MAC."""
        import tkinter.simpledialog as _sd
        import tkinter.messagebox as _mb

        mac = host.get("mac", "")
        ip  = host.get("ip", "")
        tail = mac.replace(":", "").replace("-", "").upper()[-6:] if mac and mac != "—" else ""

        prompt = (
            f"Введи назву для пристрою:\n"
            f"\n"
            f"IP:  {ip}\n"
            f"MAC: {mac}\n"
            f"MAC-tail: {tail}\n"
            f"\n"
            f"Порада: подивись на своєму телефоні у Wi-Fi налаштуваннях\n"
            f"останні 6 символів MAC — так зрозумієш який це пристрій."
        )

        current = host.get("user_label", "") or ""
        new_name = _sd.askstring("✏️ Перейменування пристрою",
                                 prompt, initialvalue=current,
                                 parent=self.winfo_toplevel())

        if new_name is None:
            return   # користувач скасував
        new_name = new_name.strip()

        # Знаходимо SecurityAuditPage в дереві — через engine.set_device_label
        try:
            # Піднімаємось по master до того хто має engine
            widget = self.master
            engine = None
            for _ in range(20):
                if widget is None: break
                engine = getattr(widget, "engine", None)
                if engine is not None and hasattr(engine, "set_device_label"):
                    break
                widget = getattr(widget, "master", None)

            if engine is None:
                _mb.showerror("Помилка", "Не вдалось знайти engine", parent=self)
                return

            engine.set_device_label(mac, new_name, host.get("user_notes", ""))
            host["user_label"] = new_name

            # Запитуємо ре-рендер через on_edit callback якщо є
            if self._on_edit is None and widget is not None:
                # Викликаємо _render_hosts якщо є
                if hasattr(widget, "_render_hosts") and hasattr(widget, "_hosts"):
                    widget._render_hosts(widget._hosts)
        except Exception as e:
            _mb.showerror("Помилка збереження", str(e), parent=self)


# ══════════════════════════════════════════════════════════════════
# STATS PANEL
# ══════════════════════════════════════════════════════════════════
class StatsPanel(ctk.CTkFrame):
    def __init__(self, parent, hosts: list, gateway: str = "",
                 suppress: bool = False, on_suppress_toggle=None,
                 auto_scan: bool = True, on_autoscan_toggle=None,
                 countdown: int = 0):
        super().__init__(parent,
            fg_color=COLORS.get("bg_card","#1a1a2e"), corner_radius=12,
            border_width=1, border_color=COLORS.get("border","#2a2a4a"))
        total   = len(hosts)
        trusted = sum(1 for h in hosts if h.get("is_trusted"))
        new_cnt = sum(1 for h in hosts if h.get("is_new"))
        danger  = sum(1 for h in hosts if h["threat"] in ("danger","critical"))
        wifi    = sum(1 for h in hosts if h.get("connection_type")=="WiFi")
        wired   = sum(1 for h in hosts if h.get("connection_type")=="LAN")
        phones_total = sum(1 for h in hosts if h.get("icon")=="📱" and not h.get("is_self") and not h.get("is_gateway"))
        phones_id    = sum(1 for h in hosts if (h.get("phone_model") or h.get("phone_name") or
                           h.get("dhcp_hostname") or h.get("ssh_hostname"))
                          and h.get("icon")=="📱" and not h.get("is_self") and not h.get("is_gateway"))

        stats = [
            (str(total),                "ПРИСТРОЇВ",    COLORS.get("accent_cyan","#00d4ff")),
            (str(wifi),                 "📡  Wi-Fi",    COLORS.get("accent_cyan","#00d4ff")),
            (str(wired),                "🔌  Дротових", COLORS.get("accent_cyan","#00d4ff")),
            (f"{phones_id}/{phones_total}", "📱  Телефонів", COLORS.get("accent_yellow","#ffd700")),
            (str(trusted),              "✅  Довірених", COLORS.get("accent_green","#00ff88")),
            (str(new_cnt),              "🆕  Нових",    COLORS.get("accent_yellow","#ffd700")),
            (str(danger),               "⚠️  Вразливих", COLORS.get("accent_red","#ff4444")),
        ]
        for col, (val, label, color) in enumerate(stats):
            if col > 0:
                ctk.CTkFrame(self, fg_color=COLORS.get("border","#2a2a4a"), width=1).grid(
                    row=0, column=col*2-1, padx=0, pady=12, sticky="ns")
            f = ctk.CTkFrame(self, fg_color="transparent")
            f.grid(row=0, column=col*2, padx=14, pady=18)
            ctk.CTkLabel(f, text=val,
                font=ctk.CTkFont(family="Consolas", size=24, weight="bold"),
                text_color=color).pack()
            ctk.CTkLabel(f, text=label,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=COLORS.get("text_dim","#444466")).pack()
        self.grid_columnconfigure(tuple(range(len(stats)*2)), weight=1)

        sep_col = len(stats)*2
        ctk.CTkFrame(self, fg_color=COLORS.get("border","#2a2a4a"), width=1).grid(
            row=0, column=sep_col, padx=0, pady=12, sticky="ns")
        ctrl_f = ctk.CTkFrame(self, fg_color="transparent")
        ctrl_f.grid(row=0, column=sep_col+1, padx=16, pady=18)

        ctk.CTkLabel(ctrl_f, text="⏱  Авто-скан",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=COLORS.get("text_dim","#444466")).pack()
        ToggleButton(ctrl_f,
            text_on="УВІМК", text_off="ВИМК",
            initial=auto_scan, on_toggle=on_autoscan_toggle,
            color_on=COLORS.get("accent_green","#00ff88"),
            color_off=COLORS.get("text_dim","#444466"),
            width=110, height=28).pack(pady=(4,6))
        if countdown > 0 and auto_scan:
            ctk.CTkLabel(ctrl_f, text=f"через {countdown}с",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS.get("text_dim","#444466")).pack()

        if gateway and on_suppress_toggle:
            ctk.CTkFrame(ctrl_f, fg_color=COLORS.get("border","#2a2a4a"), height=1).pack(fill="x", pady=4)
            ctk.CTkLabel(ctrl_f, text="🔕 Заглушити",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=COLORS.get("text_dim","#444466")).pack()
            ToggleButton(ctrl_f,
                text_on="ЗАГЛУШЕНО", text_off="АКТИВНО",
                initial=suppress, on_toggle=on_suppress_toggle,
                color_on=COLORS.get("accent_green","#00ff88"),
                color_off=COLORS.get("text_dim","#444466"),
                width=130, height=28).pack(pady=(4,0))


# ══════════════════════════════════════════════════════════════════
# SPEED CONTROL DIALOG — обмеження швидкості пристрою
# ══════════════════════════════════════════════════════════════════
class SpeedControlDialog(ctk.CTkToplevel):
    """Діалог обмеження швидкості інтернету для пристрою."""

    PRESETS = [
        ("Без обмежень", 0,    0),
        ("Повільний  128 Кбіт",  128,  128),
        ("1 Мбіт",      1024,  1024),
        ("2 Мбіт",      2048,  2048),
        ("5 Мбіт",      5120,  5120),
        ("10 Мбіт",     10240, 10240),
    ]

    def __init__(self, parent, host: dict, engine, on_done_cb=None):
        super().__init__(parent)
        self._host    = host
        self._engine  = engine
        self._on_done = on_done_cb

        name = _best_device_label(host)
        self.title(f"⚡  Швидкість: {name}")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.grab_set()
        self.after(100, lambda: _bring_to_front(self))

        w, h = 460, 440
        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        try:
            x = parent.winfo_rootx() + (parent.winfo_width() - w) // 2
            y = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        except Exception:
            x = (sw - w) // 2; y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.configure(fg_color=COLORS.get("bg_secondary","#0d0d1a"))

        cyan   = COLORS.get("accent_cyan",   "#00d4ff")
        green  = COLORS.get("accent_green",  "#00ff88")
        yellow = COLORS.get("accent_yellow", "#ffd700")
        red    = COLORS.get("accent_red",    "#ff4444")
        card   = COLORS.get("bg_card",       "#1a1a2e")
        border = COLORS.get("border",        "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",      "#444466")
        pri    = COLORS.get("text_primary",  "#e0e0ff")

        # Заголовок
        ctk.CTkFrame(self, fg_color=cyan, height=3, corner_radius=0).pack(fill="x")
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.pack(fill="x")
        ctk.CTkLabel(hdr, text="⚡  ОБМЕЖЕННЯ ШВИДКОСТІ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=cyan).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text=host.get("icon","📱"),
            font=ctk.CTkFont(size=28)).pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=20, pady=12)

        # Інфо
        info = ctk.CTkFrame(body, fg_color=card, corner_radius=8)
        info.pack(fill="x", pady=(0,14))
        ctk.CTkLabel(info, text=f"  {name}",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=pri).pack(anchor="w", padx=14, pady=(10,2))
        ctk.CTkLabel(info, text=f"  IP: {host.get('ip','—')}    MAC: {host.get('mac','—')}",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=sec).pack(anchor="w", padx=14, pady=(0,10))

        # Пресети
        ctk.CTkLabel(body, text="Швидкість (upload = download):",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=pri).pack(anchor="w", pady=(0,8))

        self._sel_upload   = 0
        self._sel_download = 0
        self._preset_btns  = []

        grid = ctk.CTkFrame(body, fg_color="transparent")
        grid.pack(fill="x")
        for i, (label, up, down) in enumerate(self.PRESETS):
            r, c = divmod(i, 3)
            col_l = (green if up == 0 else yellow if up <= 512 else red if up >= 10240 else sec)
            rb = ctk.CTkFrame(grid, fg_color=card, corner_radius=8,
                              border_width=2,
                              border_color=(cyan if i == 0 else border),
                              cursor="hand2")
            rb.grid(row=r, column=c, padx=4, pady=4, sticky="ew")
            grid.columnconfigure(c, weight=1)

            def make_sel(u=up, d=down, widget=rb, idx=i):
                def _sel():
                    self._sel_upload = u; self._sel_download = d
                    for j, btn in enumerate(self._preset_btns):
                        btn.configure(
                            border_color=cyan if j == idx else border,
                            fg_color="#003322" if j == idx else card)
                return _sel

            rb._idx = i
            rb.bind("<Button-1>", lambda e, fn=make_sel(): fn())
            lbl = ctk.CTkLabel(rb, text=label,
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                text_color=col_l)
            lbl.pack(padx=12, pady=10)
            lbl.bind("<Button-1>", lambda e, fn=make_sel(): fn())
            self._preset_btns.append(rb)

        # Ручне введення
        ctk.CTkFrame(body, fg_color=border, height=1).pack(fill="x", pady=(12,8))
        manual = ctk.CTkFrame(body, fg_color="transparent")
        manual.pack(fill="x")
        manual.grid_columnconfigure((1,3), weight=1)

        ctk.CTkLabel(manual, text="↑ Upload:",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=sec).grid(row=0, column=0, padx=(0,6), sticky="w")
        self._up_var = ctk.StringVar(value="0")
        ctk.CTkEntry(manual, textvariable=self._up_var, width=90,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=card, text_color=pri).grid(row=0, column=1, padx=(0,4))
        ctk.CTkLabel(manual, text="Кбіт/с   ↓ Download:",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=sec).grid(row=0, column=2, padx=(8,6))
        self._down_var = ctk.StringVar(value="0")
        ctk.CTkEntry(manual, textvariable=self._down_var, width=90,
            font=ctk.CTkFont(family="Consolas", size=12),
            fg_color=card, text_color=pri).grid(row=0, column=3, padx=(0,4))
        ctk.CTkLabel(manual, text="Кбіт/с",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=dim).grid(row=0, column=4)

        # Кнопки
        ctk.CTkFrame(self, fg_color=border, height=1).pack(fill="x")
        btn_f = ctk.CTkFrame(self, fg_color=card, corner_radius=0, height=70)
        btn_f.pack(fill="x"); btn_f.pack_propagate(False)
        inner = ctk.CTkFrame(btn_f, fg_color="transparent")
        inner.pack(expand=True, fill="both", padx=18, pady=12)

        def do_apply():
            try:
                up   = int(self._up_var.get())   if self._up_var.get()   else self._sel_upload
                down = int(self._down_var.get()) if self._down_var.get() else self._sel_download
            except ValueError:
                up = self._sel_upload; down = self._sel_download
            ip  = host.get("ip","")
            mac = host.get("mac","—")
            gw  = host.get("gateway","") or engine._detect_gateway()
            self.destroy()
            def run():
                ok, msg = engine.speed_limit_device(ip, mac, gw, up, down)
                def show():
                    if ok: mb.showinfo("⚡ Застосовано", msg, parent=parent)
                    else:  mb.showerror("❌ Помилка", msg, parent=parent)
                    if self._on_done: self._on_done(ok, msg)
                try: parent.after(0, show)
                except Exception: pass
            threading.Thread(target=run, daemon=True).start()

        ctk.CTkButton(inner, text="⚡  Застосувати",
            fg_color="#002233", hover_color="#003344",
            text_color=cyan, border_width=2, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, corner_radius=8, width=160,
            command=do_apply).pack(side="left", padx=(0,8))
        ctk.CTkButton(inner, text="✕ Скасувати",
            fg_color="transparent",
            hover_color=COLORS.get("bg_secondary","#0d0d1a"),
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=12),
            height=44, corner_radius=8, width=130,
            command=self.destroy).pack(side="right")
        self.bind("<Escape>", lambda e: self.destroy())



# ══════════════════════════════════════════════════════════════════
class BannedListPage(ctk.CTkToplevel):
    """Окреме вікно зі списком всіх забанених пристроїв."""

    def __init__(self, parent, engine, on_unban_cb=None):
        super().__init__(parent)
        self._engine    = engine
        self._on_unban  = on_unban_cb
        self.title("🚫  Список заблокованих пристроїв")
        self.resizable(True, True)
        # FIX #5: Topmost + grab + focus_force щоб вікно завжди було поверх
        self.attributes("-topmost", True)
        self.after(100, lambda: _bring_to_front(self))
        self.focus_force()
        try: self.grab_set()
        except Exception: pass
        self.lift()

        sw = self.winfo_screenwidth(); sh = self.winfo_screenheight()
        w, h = min(900, sw - 60), min(700, sh - 80)
        self.geometry(f"{w}x{h}+{(sw-w)//2}+{(sh-h)//2}")
        self.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        red    = COLORS.get("accent_red",    "#ff4444")
        green  = COLORS.get("accent_green",  "#00ff88")
        cyan   = COLORS.get("accent_cyan",   "#00d4ff")
        yellow = COLORS.get("accent_yellow", "#ffd700")
        card   = COLORS.get("bg_card",       "#1a1a2e")
        border = COLORS.get("border",        "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",      "#444466")
        pri    = COLORS.get("text_primary",  "#e0e0ff")

        # ── Заголовок ─────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=card, corner_radius=0)
        hdr.grid(row=0, column=0, sticky="ew")
        ctk.CTkFrame(hdr, fg_color=red, height=3, corner_radius=0).pack(fill="x")
        hdr_inner = ctk.CTkFrame(hdr, fg_color="transparent")
        hdr_inner.pack(fill="x", padx=20, pady=12)

        ctk.CTkLabel(hdr_inner, text="🚫  ЗАБЛОКОВАНІ ПРИСТРОЇ",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=red).pack(side="left")

        self._count_lbl = ctk.CTkLabel(hdr_inner, text="",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=dim)
        self._count_lbl.pack(side="left", padx=14)

        ctk.CTkButton(hdr_inner, text="✕  Закрити",
            fg_color="transparent", hover_color=COLORS.get("bg_secondary","#0d0d1a"),
            text_color=dim, border_width=1, border_color=border,
            font=ctk.CTkFont(family="Consolas", size=11),
            height=34, corner_radius=8, width=120,
            command=self.destroy).pack(side="right")

        ctk.CTkButton(hdr_inner, text="🔄  Оновити",
            fg_color="transparent", hover_color=card,
            text_color=cyan, border_width=1, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=11),
            height=34, corner_radius=8, width=120,
            command=self._load).pack(side="right", padx=(0,8))

        # ── Область списку ────────────────────────────────────────
        outer = ctk.CTkFrame(self, fg_color="transparent")
        outer.grid(row=1, column=0, sticky="nsew", padx=0, pady=0)
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=1)

        self._vsb = CyanScrollbar(outer)
        self._vsb.grid(row=0, column=1, sticky="ns", padx=(2,0))

        self._canvas = tk.Canvas(outer,
            bg=COLORS.get("bg_primary","#0a0a1a"), highlightthickness=0,
            yscrollcommand=self._vsb.set)
        self._canvas.grid(row=0, column=0, sticky="nsew")
        self._vsb._command = self._canvas.yview

        self._inner = ctk.CTkFrame(self._canvas, fg_color="transparent")
        self._inner.grid_columnconfigure(0, weight=1)
        self._cwin = self._canvas.create_window((0,0), window=self._inner, anchor="nw")

        self._canvas.bind("<Configure>",
            lambda e: self._canvas.itemconfig(self._cwin, width=e.width))
        self._inner.bind("<Configure>",
            lambda e: self._canvas.configure(scrollregion=self._canvas.bbox("all")))
        self._canvas.bind("<MouseWheel>",
            lambda e: self._canvas.yview_scroll(int(-1*(e.delta/120)), "units"))

        self._load()

    def _load(self):
        for w in self._inner.winfo_children():
            try: w.destroy()
            except Exception: pass
        self._canvas.yview_moveto(0)

        red    = COLORS.get("accent_red",    "#ff4444")
        green  = COLORS.get("accent_green",  "#00ff88")
        yellow = COLORS.get("accent_yellow", "#ffd700")
        cyan   = COLORS.get("accent_cyan",   "#00d4ff")
        card   = COLORS.get("bg_card",       "#1a1a2e")
        border = COLORS.get("border",        "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",      "#444466")
        pri    = COLORS.get("text_primary",  "#e0e0ff")

        banned = self._engine.get_banned()
        self._count_lbl.configure(
            text=f"  {len(banned)} пристроїв" if banned else "  список порожній")

        if not banned:
            ctk.CTkLabel(self._inner,
                text="\n✅  Список заблокованих пристроїв порожній\n\n"
                     "Коли ви заблокуєте пристрій — він з'явиться тут.",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=dim).grid(row=0, column=0, pady=60)
            return

        # Заголовок таблиці
        th = ctk.CTkFrame(self._inner, fg_color=card, corner_radius=0)
        th.grid(row=0, column=0, sticky="ew", pady=(0,2))
        for col_i, (text, w_) in enumerate([
            ("MAC адреса",   200), ("IP адреса",  130), ("Назва / Vendor", 200),
            ("Причина",      180), ("Залишилось", 130), ("Дія",            110),
        ]):
            ctk.CTkLabel(th, text=text,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=dim, width=w_, anchor="w").pack(side="left", padx=(12,0), pady=8)

        for row_i, entry in enumerate(banned):
            self._build_row(row_i + 1, entry)

    def _build_row(self, row_i: int, entry: dict):
        red    = COLORS.get("accent_red",    "#ff4444")
        green  = COLORS.get("accent_green",  "#00ff88")
        yellow = COLORS.get("accent_yellow", "#ffd700")
        card   = COLORS.get("bg_card",       "#1a1a2e")
        border = COLORS.get("border",        "#2a2a4a")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim",      "#444466")
        pri    = COLORS.get("text_primary",  "#e0e0ff")

        bg = "#1a0000" if row_i % 2 == 0 else card
        row = ctk.CTkFrame(self._inner, fg_color=bg, corner_radius=6,
                           border_width=1, border_color=border)
        row.grid(row=row_i, column=0, sticky="ew", padx=8, pady=2)

        mac    = entry.get("mac","—")
        ip     = entry.get("ip","—") or "—"
        label  = entry.get("label","") or entry.get("vendor","") or "Невідомий пристрій"
        reason = entry.get("reason","") or "—"
        is_perm= entry.get("is_permanent", True)
        rem    = entry.get("remaining")

        if is_perm:
            time_str = "♾  Назавжди"
            time_col = red
        elif rem is not None:
            h_, m_ = divmod(rem // 60, 60)
            s_     = rem % 60
            if h_:   time_str = f"⏱  {h_}г {m_:02d}хв"
            elif m_: time_str = f"⏱  {m_}хв {s_:02d}с"
            else:    time_str = f"⏱  {s_}с"
            time_col = yellow
        else:
            time_str = "—"; time_col = dim

        # MAC
        ctk.CTkLabel(row, text=mac,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=red, width=200, anchor="w").pack(side="left", padx=(12,0), pady=10)
        # IP
        ctk.CTkLabel(row, text=ip,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=sec, width=130, anchor="w").pack(side="left", padx=(0,0))
        # Назва
        ctk.CTkLabel(row, text=label[:32],
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=pri, width=200, anchor="w").pack(side="left")
        # Причина
        ctk.CTkLabel(row, text=reason[:28],
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=dim, width=180, anchor="w").pack(side="left")
        # Час
        ctk.CTkLabel(row, text=time_str,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=time_col, width=130, anchor="w").pack(side="left")
        # Кнопка розблокувати
        ctk.CTkButton(row, text="🔓 Розблокувати",
            fg_color="#002200", hover_color="#003a00",
            text_color=green, border_width=1, border_color=green,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=30, corner_radius=6, width=130,
            command=lambda m=mac, i=ip: self._do_unban(m, i)).pack(side="right", padx=8)

    def _do_unban(self, mac: str, ip: str = ""):
        self._engine.unban_device(mac, ip)
        if self._on_unban: self._on_unban(mac)
        self._load()
        green = COLORS.get("accent_green","#00ff88")


# ══════════════════════════════════════════════════════════════════
# MAIN PAGE
# ══════════════════════════════════════════════════════════════════
class SecurityAuditPage(ctk.CTkFrame):
    _CATEGORIES = {
        "suspicious": ("⚠️  ПІДОЗРІЛІ / НЕБЕЗПЕЧНІ",      "#ff4444"),
        "gateway":    ("📡  ШЛЮЗ / РОУТЕР",                "#00ff88"),
        "self":       ("🖥️  ЦЕЙ КОМ'ЮТЕР",                 "#00d4ff"),
        "pc":         ("💻  КОМ'ЮТЕРИ / НОУТБУКИ",         "#8888ff"),
        "phone":      ("📱  ТЕЛЕФОНИ / ПЛАНШЕТИ",           "#ffd700"),
        "tv":         ("📺  ТЕЛЕВІЗОРИ / ІГРОВІ / КОЛОНКИ", "#ff88aa"),
        "iot":        ("📷  ПРИНТЕРИ / КАМЕРИ / IoT",       "#aaaaaa"),
        "unknown":    ("❓  ІНШІ ПРИСТРОЇ",                 "#555577"),
    }

    AUTO_SCAN_INTERVAL = 60

    def __init__(self, parent, get_gateway_cb=None):
        super().__init__(parent, fg_color="transparent")
        self.get_gateway_cb = get_gateway_cb
        self.engine         = LanSecurityEngine()
        self._hosts: list   = []
        self._running       = False
        self._filter        = "all"
        self._overlay       = ScanOverlay(self)
        # FIX-3: тост для авто-скану
        self._toast         = ScanToast(self)
        self._current_gw    = ""
        # FIX-3: прапорці для розрізнення першого/ручного і авто-сканування
        self._is_first_scan  = True
        self._is_auto_scan   = False
        # Auto-scan
        self._auto_scan_enabled   = True
        self._auto_scan_after     = None
        self._auto_scan_countdown = self.AUTO_SCAN_INTERVAL
        self._countdown_after     = None
        # New device popups
        self._known_macs:  set  = set()
        self._popup_queue: list = []
        self._popup_open        = False

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(0, weight=0)
        self.grid_rowconfigure(1, weight=0)
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=0)   # NEW: preflight панель
        self.grid_rowconfigure(4, weight=0)
        self.grid_rowconfigure(5, weight=1)

        self._build_toolbar()
        self._build_net_info()
        self._build_preflight_panel()    # NEW
        self._build_filter_bar()
        self._build_results_area()

        self.after(1500, lambda: self._start_scan(manual=True))

    # ── Auto-scan ─────────────────────────────────────────────────
    def _schedule_auto_scan(self):
        if not self._auto_scan_enabled: return
        self._auto_scan_countdown = self.AUTO_SCAN_INTERVAL
        self._tick_countdown()
        self._auto_scan_after = self.after(
            self.AUTO_SCAN_INTERVAL * 1000, self._auto_trigger_scan)

    def _tick_countdown(self):
        if not self._auto_scan_enabled or self._running: return
        if self._auto_scan_countdown > 0:
            self._auto_scan_countdown -= 1
            self._countdown_after = self.after(1000, self._tick_countdown)

    def _auto_trigger_scan(self):
        if self._auto_scan_enabled and not self._running:
            # FIX-3: авто-скан = тост, не overlay
            self._start_scan(manual=False)

    def _toggle_auto_scan(self, value: bool):
        self._auto_scan_enabled = value
        if not value:
            for job in (self._auto_scan_after, self._countdown_after):
                if job:
                    try: self.after_cancel(job)
                    except Exception: pass
            self._auto_scan_after = self._countdown_after = None
            self._auto_scan_countdown = 0
        else:
            self._schedule_auto_scan()

    # ── New device popups ─────────────────────────────────────────
    def _check_new_devices(self, hosts: list, is_auto: bool = False):
        """
        Перевіряє які пристрої з нового скану не бачили у попередніх сканах.
        Показує popup для кожного нового пристрою.
        """
        first_scan = (len(self._known_macs) == 0)

        # КРИТИЧНО: спочатку знаходимо НОВІ (ті яких ще немає у _known_macs),
        # і лише ПОТІМ додаємо всі в _known_macs.
        # Старий код додавав все ДО порівняння, тому new_devices завжди був [].
        new_devices = []
        if not first_scan:
            for h in hosts:
                mac = h.get("mac","—")
                if (mac and mac != "—"
                    and mac not in self._known_macs
                    and not h.get("is_gateway")
                    and not h.get("is_self")
                    and not h.get("is_mac_only")):
                    new_devices.append(h)

        # Тепер оновлюємо known_macs всіма сьогоднішніми MAC
        for h in hosts:
            mac = h.get("mac","—")
            if mac and mac != "—":
                self._known_macs.add(mac)

        # Перший скан — просто запам'ятовуємо всі MAC, popups не показуємо
        if first_scan:
            return

        # Діагностика у консоль (щоб було видно при debug)
        if new_devices:
            print(f"[NewDevice] Виявлено {len(new_devices)} нових пристроїв: "
                  f"{[d.get('mac','—') for d in new_devices]}")

        # FIX: на додаток до GUI-попапу, тригеримо engine.on_new_device()
        # колбеки — це потрібно щоб Telegram-бот і інші слухачі
        # отримували сповіщення про нові пристрої
        for d in new_devices:
            try:
                self.engine._fire_new_device(d)
            except Exception as e:
                print(f"[NewDevice] Error firing engine callback: {e}")

        for d in new_devices:
            # FIX-3: передаємо прапорець is_auto_scan у popup
            self._popup_queue.append((d, is_auto))
        self._show_next_popup()

    def _show_next_popup(self):
        if self._popup_open or not self._popup_queue: return
        device, is_auto = self._popup_queue.pop(0)
        self._popup_open = True

        def on_close():
            self._popup_open = False
            self.after(600, self._show_next_popup)

        def _create_window():
            popup = NewDevicePopup(
                self.winfo_toplevel(), device, self.engine,
                on_block_cb=self._block_request,
                on_close_cb=on_close,
                is_auto_scan=is_auto)

            popup.attributes("-topmost", True)
            popup.lift()
            popup.update()  # примусово обробляємо події щоб вікно з'явилось

            # Пробиваємось на передній план у Windows через Win32 API
            try:
                import platform as _plt
                if _plt.system() == "Windows":
                    import ctypes as _ct
                    import ctypes.wintypes as _wt

                    # Знаходимо HWND за заголовком вікна
                    title = popup.title()
                    hwnd  = _ct.windll.user32.FindWindowW(None, title)

                    if hwnd:
                        SW_RESTORE   = 9
                        HWND_TOPMOST = -1
                        SWP_FLAGS    = 0x0001 | 0x0002  # NOMOVE | NOSIZE

                        # 1. Відновлюємо вікно якщо згорнуте
                        _ct.windll.user32.ShowWindow(hwnd, SW_RESTORE)
                        # 2. Переводимо на передній план
                        _ct.windll.user32.SetForegroundWindow(hwnd)
                        # 3. Фіксуємо TOPMOST
                        _ct.windll.user32.SetWindowPos(
                            hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_FLAGS)
                        # 4. Даємо фокус
                        _ct.windll.user32.BringWindowToTop(hwnd)
                        _ct.windll.user32.SetActiveWindow(hwnd)
            except Exception:
                pass

            popup.focus_force()

        self.after(0, _create_window)

    # ── Build UI ──────────────────────────────────────────────────
    def _scroll_target(self) -> ctk.CTkFrame:
        return self._inner

    def _clear_scroll(self):
        try:
            for w in self._inner.winfo_children():
                try: w.destroy()
                except Exception: pass
            self._canvas.yview_moveto(0)
        except Exception: pass

    def _build_toolbar(self):
        tb   = ctk.CTkFrame(self, fg_color="transparent")
        tb.grid(row=0, column=0, padx=24, pady=(20,8), sticky="ew")
        red  = COLORS.get("accent_red","#ff4444")
        dim  = COLORS.get("text_dim","#444466")
        cyan = COLORS.get("accent_cyan","#00d4ff")

        self.btn_scan = ctk.CTkButton(tb, text="🛡️  АУДИТ МЕРЕЖІ",
            fg_color="#2a0000", hover_color="#3d0000",
            text_color=red, border_width=2, border_color=red,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            height=46, corner_radius=10,
            command=lambda: self._start_scan(manual=True))
        self.btn_scan.grid(row=0, column=0, padx=(0,10))

        self.btn_rescan = ctk.CTkButton(tb, text="🔄  Оновити",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=dim, border_width=1, border_color=dim,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=46, corner_radius=10, state="disabled",
            command=lambda: self._start_scan(manual=True))
        self.btn_rescan.grid(row=0, column=1, padx=(0,10))

        self.btn_diag = ctk.CTkButton(tb, text="🔬 Діагностика",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=cyan, border_width=1, border_color=cyan,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=46, corner_radius=10, command=self._run_diagnostics)
        self.btn_diag.grid(row=0, column=2, padx=(0,8))

        self.btn_banned = ctk.CTkButton(tb, text="🚫 Заблоковані",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=COLORS.get("accent_red","#ff4444"),
            border_width=1, border_color=COLORS.get("accent_red","#ff4444"),
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=46, corner_radius=10, command=self._open_banned_list)
        self.btn_banned.grid(row=0, column=3, padx=(0,16))

        self.status_lbl = ctk.CTkLabel(tb,
            text="  Router API · ARP · mDNS · SSDP · NetBIOS · Phone ID",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_secondary","#8888aa"), anchor="w")
        self.status_lbl.grid(row=0, column=4, sticky="w")

        self.live_lbl = ctk.CTkLabel(tb, text="",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLORS.get("accent_cyan","#00d4ff"))
        self.live_lbl.grid(row=0, column=5, padx=10, sticky="e")

    def _build_net_info(self):
        net = self.engine.get_network_info()
        self._current_gw = net.get("gateway","")
        bar   = ctk.CTkFrame(self, fg_color=COLORS.get("bg_card","#1a1a2e"),
                              corner_radius=10, border_width=1,
                              border_color=COLORS.get("border","#2a2a4a"))
        bar.grid(row=1, column=0, padx=24, pady=(0,10), sticky="ew")
        cyan  = COLORS.get("accent_cyan","#00d4ff")
        green = COLORS.get("accent_green","#00ff88")
        red   = COLORS.get("accent_red","#ff4444")
        dim   = COLORS.get("text_dim","#444466")

        items = [
            ("МЕРЕЖА", net.get("local_subnet") or net.get("subnet","?"), cyan),
            ("МІЙ IP", net.get("my_ip","?"),   green),
            ("ШЛЮЗ",   net.get("gateway","?"), green),
        ]
        for col, (label, val, color) in enumerate(items):
            f = ctk.CTkFrame(bar, fg_color="transparent")
            f.grid(row=0, column=col, padx=(18,26), pady=10)
            ctk.CTkLabel(f, text=label,
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=dim).pack(anchor="w")
            ctk.CTkLabel(f, text=val,
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=color).pack(anchor="w")

        # FIX-1: назва роутера в net info bar — async
        gw_name_f = ctk.CTkFrame(bar, fg_color="transparent")
        gw_name_f.grid(row=0, column=3, padx=(0,14), pady=10, sticky="w")
        ctk.CTkLabel(gw_name_f, text="РОУТЕР",
            font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
            text_color=dim).pack(anchor="w")
        self._gw_name_lbl = ctk.CTkLabel(gw_name_f, text="…",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=green)
        self._gw_name_lbl.pack(anchor="w")

        def _fetch_name():
            try:
                gw = net.get("gateway","")
                if not gw: return
                r    = RouterClientReader(gw, timeout=4.0)
                v, _, _ = self.engine.lookup_oui(gw)
                name = self.engine._fetch_gateway_fullname(gw, v, reader=r)

                # Якщо ім'я вже містить vendor — не додаємо
                if name and v and v not in ("Невідомо","") and v.lower() not in name.lower():
                    name = f"{v}  ·  {name}"

                if not name or name in ("—",""):
                    brand = r._router_brand or ""
                    if brand and brand not in ("Generic",""):
                        name = f"{v} {brand}".strip() if v and v != "Невідомо" else f"{brand} Router"
                    elif v and v not in ("Невідомо",""):
                        name = f"{v} (шлюз)"

                # Fallback на вже відскановані пристрої
                if not name and self._hosts:
                    gw_dev = next((h for h in self._hosts if h.get("is_gateway")), None)
                    if gw_dev:
                        hn = gw_dev.get("hostname","")
                        if hn and hn not in ("—",""):
                            name = hn
                        else:
                            name = (gw_dev.get("snmp_sysdescr","") or "").split("\n")[0][:40] or \
                                   gw_dev.get("upnp_name","") or ""

                if not name or name in ("—",""):
                    name = v if v not in ("Невідомо","") else f"Роутер {gw}"

                def _upd(n=name):
                    try: self._gw_name_lbl.configure(text=n)
                    except Exception: pass
                self.after(0, _upd)
            except Exception:
                gw = net.get("gateway","?")
                try: self.after(0, lambda: self._gw_name_lbl.configure(text=f"Роутер {gw}"))
                except Exception: pass
        threading.Thread(target=_fetch_name, daemon=True).start()

        scapy_ok = net.get("scapy_available",False)
        ssh_ok   = net.get("ssh_available",False)
        for extra_col, (etext, ecol) in enumerate([
            ("⚡ Scapy ARP" if scapy_ok else "⚠️ Без Scapy", green if scapy_ok else red),
            ("📋 Router API", cyan),
            ("📱 Phone ID",   COLORS.get("accent_yellow","#ffd700")),
            ("🔒 SSH" if ssh_ok else "—  SSH", green if ssh_ok else dim),
        ]):
            ctk.CTkLabel(bar, text=etext,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=ecol,
                fg_color=COLORS.get("bg_secondary","#0d0d1a"), corner_radius=6,
                ).grid(row=0, column=4+extra_col, padx=8, pady=10)

    def _build_preflight_panel(self):
        """
        Панель готовності системи до блокування пристроїв.
        Показує 4 необхідні умови: Admin, Scapy, Npcap, Router API.
        Якщо хоч одна не виконана → дає інструкції як виправити.
        """
        import tkinter.messagebox as _mb

        # ── Перевірка умов ──────────────────────────────────
        is_admin    = self._check_is_admin()
        has_scapy   = self._check_has_scapy()
        has_npcap   = self._check_has_npcap()
        has_router  = self._check_router_configured()
        # Готово = або (ARP-стек повний) АБО (Router API налаштований)
        # Router API — КРАЩИЙ варіант (постійне блокування)
        ready       = has_router or (is_admin and has_scapy and has_npcap)

        green = COLORS.get("accent_green", "#00ff88")
        red   = COLORS.get("accent_red",   "#ff4444")
        yellow= COLORS.get("accent_yellow","#ffd700")
        cyan  = COLORS.get("accent_cyan",  "#00d4ff")
        card  = COLORS.get("bg_card",      "#1a1a2e")
        border= COLORS.get("border",       "#2a2a4a")
        dim   = COLORS.get("text_dim",     "#444466")

        main_color  = green if ready else red
        if has_router:
            main_status = "✅ БЛОКУВАННЯ АКТИВНЕ (Router API — постійне)"
        elif is_admin and has_scapy and has_npcap:
            main_status = "⚠️ БЛОКУВАННЯ ТИМЧАСОВЕ (ARP — ненадійно)"
            main_color  = yellow
        else:
            main_status = "⚠️ БЛОКУВАННЯ НЕДОСТУПНЕ"

        panel = ctk.CTkFrame(self, fg_color=card, corner_radius=10,
                             border_width=1, border_color=main_color)
        panel.grid(row=3, column=0, padx=24, pady=(0,10), sticky="ew")

        # ── Лівий блок: статус + індикатори ─────────────────
        left = ctk.CTkFrame(panel, fg_color="transparent")
        left.pack(side="left", padx=16, pady=10, fill="x", expand=True)

        ctk.CTkLabel(left, text=main_status,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=main_color).pack(anchor="w")

        # Чотири індикатори в ряд
        indicators = ctk.CTkFrame(left, fg_color="transparent")
        indicators.pack(anchor="w", pady=(4,0))

        def _mini(text: str, ok: bool, tooltip: str):
            col = green if ok else red
            lbl_text = f"{'✓' if ok else '✗'} {text}"
            lbl = ctk.CTkLabel(indicators, text=lbl_text,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=col,
                fg_color=COLORS.get("bg_secondary","#0d0d1a"),
                corner_radius=5)
            lbl.pack(side="left", padx=(0,8), ipadx=8, ipady=3)

        _mini("Router API ⭐", has_router, "Credentials роутера (НАЙКРАЩЕ)")
        _mini("Адмін", is_admin, "Права адміністратора")
        _mini("Scapy", has_scapy, "Python-бібліотека scapy")
        _mini("Npcap", has_npcap, "Драйвер захоплення пакетів")

        # ── Правий блок: кнопки дії ─────────────────────────
        right = ctk.CTkFrame(panel, fg_color="transparent")
        right.pack(side="right", padx=16, pady=8)

        # Кнопка "⚙️ Налаштувати роутер" — ЗАВЖДИ доступна
        router_btn_color = green if has_router else yellow
        router_btn_text  = "⚙️ Змінити роутер" if has_router else "⭐ Налаштувати роутер"
        ctk.CTkButton(right, text=router_btn_text,
            fg_color="#002200" if has_router else "#1a1500",
            hover_color=card,
            text_color=router_btn_color,
            border_width=1, border_color=router_btn_color,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=32, corner_radius=6, width=200,
            command=self._open_router_wizard
        ).pack(side="top", pady=(0, 4))

        if not has_router and not (is_admin and has_scapy and has_npcap):
            def _show_fix_instructions():
                msg_parts = [
                    "Є 2 способи блокувати пристрої:\n",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
                    "🏆  СПОСІБ #1: Router API  (РЕКОМЕНДОВАНО)\n"
                    "    • Постійне блокування на рівні роутера\n"
                    "    • Пристрій фізично не може підключитись\n"
                    "    • Не потрібен Адмін / Scapy / Npcap\n"
                    "    → Натисни '⭐ Налаштувати роутер' нижче\n",
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n",
                    "⚙️  СПОСІБ #2: ARP Spoofing  (ТИМЧАСОВЕ)\n"
                    "    Потрібно 3 умови:\n",
                ]
                if not is_admin:
                    msg_parts.append(
                        "    1️⃣  ЗАПУСТИТИ ЯК АДМІНІСТРАТОРА\n"
                        "       • ПКМ на ярлик → 'Запустити як адміністратор'\n"
                    )
                if not has_scapy:
                    msg_parts.append(
                        "    2️⃣  ВСТАНОВИТИ SCAPY\n"
                        "       • pip install scapy\n"
                    )
                if not has_npcap:
                    msg_parts.append(
                        "    3️⃣  ВСТАНОВИТИ NPCAP\n"
                        "       • https://npcap.com (з WinPcap API-compatible Mode)\n"
                    )
                msg_parts.append(
                    "\n⚠️  ARP-метод працює лише поки NetGuardian запущений.\n"
                    "     Пристрій оновить ARP-кеш через 30-60с і продовжить\n"
                    "     користуватись мережею. Для справжнього захисту —\n"
                    "     тільки СПОСІБ #1 (Router API)."
                )
                _mb.showinfo("Як увімкнути блокування пристроїв",
                            "\n".join(msg_parts), parent=self)

            ctk.CTkButton(right, text="❓ Як виправити?",
                fg_color="transparent", hover_color=card,
                text_color=dim, border_width=1, border_color=dim,
                font=ctk.CTkFont(family="Consolas", size=10),
                height=28, corner_radius=6, width=200,
                command=_show_fix_instructions
            ).pack(side="top")
        elif has_router:
            ctk.CTkLabel(right,
                text="💡 Блокування через роутер — постійне",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=green).pack(side="top")

    def _check_is_admin(self) -> bool:
        """Перевіряє права адміністратора (Windows)."""
        try:
            import platform
            if platform.system() != "Windows":
                import os
                return os.geteuid() == 0 if hasattr(os, "geteuid") else False
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    def _check_has_scapy(self) -> bool:
        """Перевіряє наявність scapy модуля."""
        try:
            import scapy.all  # noqa: F401
            return True
        except ImportError:
            return False

    def _check_has_npcap(self) -> bool:
        """Перевіряє наявність Npcap драйвера (Windows)."""
        try:
            import platform
            if platform.system() != "Windows":
                return True   # на Linux/Mac Npcap не потрібен
            # Перевірка через реєстр Windows
            import subprocess
            r = subprocess.run(
                ["sc", "query", "npcap"],
                capture_output=True, text=True, timeout=3,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            return r.returncode == 0 and "npcap" in (r.stdout or "").lower()
        except Exception:
            return False

    def _check_router_configured(self) -> bool:
        """Перевіряє чи у router_manager є credentials для поточного шлюзу."""
        try:
            from features.security.lan_security import router_manager
            gw = self.engine._detect_gateway()
            if not gw: return False
            cfg = router_manager.get_router_by_ip(gw)
            if not cfg: return False
            # Має бути або HTTP credentials (не дефолт), або SSH credentials
            has_http_creds = (cfg.get("http_user") and cfg.get("http_pwd")
                              and not (cfg.get("http_user") == "admin"
                                       and cfg.get("http_pwd") == "admin"))
            has_ssh_creds  = bool(cfg.get("ssh_user") and cfg.get("ssh_pwd"))
            return has_http_creds or has_ssh_creds
        except Exception:
            return False

    def _open_router_wizard(self):
        """Відкриває діалог налаштування credentials роутера для блокування через API."""
        RouterSetupWizard(self, engine=self.engine,
                          on_saved=self._refresh_preflight)

    def _refresh_preflight(self):
        """Перебудувати preflight-панель (напр. після додавання роутера)."""
        # Знайти поточну панель і знищити
        for child in self.grid_slaves(row=3, column=0):
            child.destroy()
        self._build_preflight_panel()

    def _build_filter_bar(self):
        bar = ctk.CTkFrame(self, fg_color="transparent")
        bar.grid(row=4, column=0, padx=24, pady=(0,8), sticky="ew")
        self._filters = [
            ("all",     "ВСІ",          COLORS.get("text_secondary","#8888aa")),
            ("danger",  "⚠️ ВРАЗЛИВІ",  COLORS.get("accent_red","#ff4444")),
            ("phone",   "📱 Телефони",  COLORS.get("accent_yellow","#ffd700")),
            ("new",     "🆕 НОВІ",      COLORS.get("accent_yellow","#ffd700")),
            ("trusted", "✅ ДОВІРЕНІ",  COLORS.get("accent_green","#00ff88")),
            ("allowed", "✓ ДОЗВОЛЕНІ", "#44ff88"),
            ("wifi",    "📡 Wi-Fi",     COLORS.get("accent_cyan","#00d4ff")),
            ("wired",   "🔌 Дротові",   COLORS.get("accent_cyan","#00d4ff")),
        ]
        self._filter_btns: dict = {}
        for col, (key, label, color) in enumerate(self._filters):
            active = (key == self._filter)
            btn = ctk.CTkButton(bar, text=label,
                fg_color=COLORS.get("bg_card","#1a1a2e") if active else "transparent",
                hover_color=COLORS.get("bg_card","#1a1a2e"),
                text_color=color, border_width=1,
                border_color=color if active else COLORS.get("border","#2a2a4a"),
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                height=34, corner_radius=8,
                command=lambda k=key: self._set_filter(k))
            btn.grid(row=0, column=col, padx=(0,7))
            self._filter_btns[key] = btn

    def _set_filter(self, key: str):
        self._filter = key
        for k, btn in self._filter_btns.items():
            active = (k == key)
            col = next(c for fk,_,c in self._filters if fk==k)
            btn.configure(
                fg_color=COLORS.get("bg_card","#1a1a2e") if active else "transparent",
                border_color=col if active else COLORS.get("border","#2a2a4a"))
        self._render_hosts(self._hosts)

    # FIX-5 — результуюча зона зі CyanScrollbar
    def _build_results_area(self):
        outer = ctk.CTkFrame(self, fg_color="transparent", corner_radius=0)
        outer.grid(row=5, column=0, padx=24, pady=(0,24), sticky="nsew")
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=1)

        bg = COLORS.get("bg_primary","#0a0a1a")

        # FIX-5: CyanScrollbar замість tk.Scrollbar
        self._vsb = CyanScrollbar(outer)
        self._vsb.grid(row=0, column=1, sticky="ns", padx=(2,0))

        self._canvas = tk.Canvas(outer, bg=bg, highlightthickness=0,
                                 yscrollcommand=self._vsb.set)
        self._canvas.grid(row=0, column=0, sticky="nsew")
        self._vsb._command = self._canvas.yview

        self._inner = ctk.CTkFrame(self._canvas, fg_color="transparent", corner_radius=0)
        self._inner.grid_columnconfigure(0, weight=1)
        self._canvas_window = self._canvas.create_window((0,0), window=self._inner, anchor="nw")

        def _on_canvas_resize(event):
            self._canvas.itemconfig(self._canvas_window, width=event.width)
        self._canvas.bind("<Configure>", _on_canvas_resize)

        def _on_inner_resize(event):
            self._canvas.configure(scrollregion=self._canvas.bbox("all"))
        self._inner.bind("<Configure>", _on_inner_resize)

        def _on_mousewheel(event):
            try: self._canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            except Exception: pass
        self._canvas.bind("<MouseWheel>", _on_mousewheel)

        def _bind_root():
            try:
                root = self.winfo_toplevel()
                root.bind("<MouseWheel>", _on_mousewheel, add="+")
            except Exception: pass
        self.after(500, _bind_root)
        self._draw_placeholder()

    def _draw_placeholder(self):
        self._clear_scroll(); target = self._scroll_target()
        target.grid_columnconfigure(0, weight=1)
        ph = GlowCard(target, accent=COLORS.get("accent_red","#ff4444"))
        ph.grid(row=0, column=0, sticky="ew")
        ctk.CTkLabel(ph, text=(
            "\n🛡️  LAN Security Auditor v6.3\n\n"
            "  Підтримує: TP-Link · ASUS · Keenetic · MikroTik · Xiaomi · Huawei\n\n"
            "  📱  Модель телефону: iPhone 15 Pro, Galaxy S24, Pixel 8...\n"
            "  👤  Ім'я пристрою задане власником (AirPlay, mDNS, DHCP)\n"
            "  ★   SSH пряме читання DHCP (найнадійніше джерело імен)\n"
            "  ⏱   Авто-сканування кожну хвилину (маленький тост, список видно)\n"
            "  🔔  Сповіщення при виявленні нових пристроїв після оновлення\n"
            "  🚫  Блокування на 5хв / 30хв / 1год / 1день / 1тиждень / Назавжди\n\n"
            "  Починаємо сканування…\n"),
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS.get("text_secondary","#8888aa"), justify="left"
        ).pack(padx=34, pady=26, anchor="w")

    # ── Scan ──────────────────────────────────────────────────────
    def _start_scan(self, manual: bool = True):
        if self._running: return
        # Скасовуємо заплановані задачі
        for job in (self._auto_scan_after, self._countdown_after):
            if job:
                try: self.after_cancel(job)
                except Exception: pass
        self._auto_scan_after = self._countdown_after = None

        self._running     = True
        self._is_auto_scan = not manual
        self._set_btns("disabled")
        self.live_lbl.configure(text="")

        # FIX-3: перший або ручний → повний overlay (список прибирається)
        #         авто-скан → маленький тост (список залишається)
        if manual or self._is_first_scan:
            self._clear_scroll()
            self._overlay.show()
        else:
            self._toast.show()

        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _safe_after(self, fn):
        try:
            if self.winfo_exists(): self.after(0, fn)
        except Exception: pass

    def _scan_thread(self):
        try:
            gw = self.get_gateway_cb() if self.get_gateway_cb else None
            hosts = self.engine.scan_network(
                gateway_ip=gw,
                progress_cb=lambda t: self._safe_after(lambda txt=t: self._on_progress(txt)),
                live_device_cb=lambda d: self._safe_after(lambda dev=d: self._on_live(dev)))
            self._safe_after(lambda h=hosts: self._on_done(h))
        except Exception as e:
            self._safe_after(lambda err=e: self._on_scan_error(err))

    def _on_scan_error(self, err):
        self._running = False
        self._overlay.hide(); self._toast.hide()
        self._set_btns("normal")
        self.status_lbl.configure(text=f"❌  Помилка: {err}",
                                   text_color=COLORS.get("accent_red","#ff4444"))
        if self._auto_scan_enabled: self._schedule_auto_scan()

    def _on_progress(self, txt: str):
        if self._is_auto_scan:
            self._toast.update(txt)
        else:
            self._overlay.update(txt)
        self.status_lbl.configure(text=txt[:78],
                                   text_color=COLORS.get("text_secondary","#8888aa"))

    def _on_live(self, device: dict):
        if not self._is_auto_scan:
            # Для повного overlay — підрахунок у реальному часі
            self._hosts.append(device)
        n = len(self._hosts) + (1 if self._is_auto_scan else 0)
        d = sum(1 for h in self._hosts if h["threat"] in ("danger","critical"))
        phones = sum(1 for h in self._hosts if h.get("icon")=="📱")
        p_id   = sum(1 for h in self._hosts if h.get("phone_model") or h.get("phone_name")
                     or h.get("dhcp_hostname") or h.get("ssh_hostname"))
        col = COLORS.get("accent_red","#ff4444") if d else COLORS.get("accent_cyan","#00d4ff")
        txt = f"↳ {n} знайдено"
        if d:      txt += f"  ⚠️{d}"
        if phones: txt += f"  📱{p_id}/{phones}"
        self.live_lbl.configure(text=txt, text_color=col)

    def _on_done(self, hosts: list):
        was_auto = self._is_auto_scan
        self._running = False
        self._is_first_scan = False

        # Ховаємо відповідний індикатор
        if was_auto:
            self._toast.done(len(hosts))
        else:
            self._overlay.hide()

        self._hosts = hosts
        self._set_btns("normal")
        self._render_hosts(hosts)
        self.live_lbl.configure(text="")

        # FIX-3: передаємо прапорець is_auto
        self._check_new_devices(hosts, is_auto=was_auto)

        danger  = sum(1 for h in hosts if h["threat"] in ("danger","critical"))
        wifi    = sum(1 for h in hosts if h.get("connection_type")=="WiFi")
        wired   = sum(1 for h in hosts if h.get("connection_type")=="LAN")
        phones  = sum(1 for h in hosts if h.get("icon")=="📱" and not h.get("is_self") and not h.get("is_gateway"))
        p_id    = sum(1 for h in hosts if (h.get("phone_model") or h.get("phone_name") or
                      h.get("dhcp_hostname") or h.get("ssh_hostname")) and h.get("icon")=="📱")

        if danger:
            self.status_lbl.configure(
                text=f"⚠️  {len(hosts)} пристроїв · {danger} ВРАЗЛИВИХ · 📡{wifi} Wi-Fi  🔌{wired} LAN  📱{p_id}/{phones} ідент.",
                text_color=COLORS.get("accent_red","#ff4444"))
        else:
            self.status_lbl.configure(
                text=f"✅  {len(hosts)} пристроїв · 📡{wifi} Wi-Fi  🔌{wired} LAN · 📱{p_id}/{phones} телефонів ідентифіковано",
                text_color=COLORS.get("accent_green","#00ff88"))

        if hosts: self._current_gw = hosts[0].get("gateway", self._current_gw)
        if self._auto_scan_enabled: self._schedule_auto_scan()

    # ── Render ────────────────────────────────────────────────────
    def _render_hosts(self, hosts: list):
        self._clear_scroll(); target = self._scroll_target()
        target.grid_columnconfigure(0, weight=1)
        if not hosts: self._draw_placeholder(); return

        filtered = self._apply_filter(hosts)
        gw       = self._current_gw or self.engine._detect_gateway()
        suppress = self.engine.get_router_suppress(gw)

        StatsPanel(target, hosts, gateway=gw, suppress=suppress,
            on_suppress_toggle=lambda v: self._on_suppress_toggle(v),
            auto_scan=self._auto_scan_enabled,
            on_autoscan_toggle=self._toggle_auto_scan,
            countdown=self._auto_scan_countdown,
        ).grid(row=0, column=0, sticky="ew", pady=(0,10))

        if not filtered:
            ctk.CTkLabel(target,
                text=f"Немає пристроїв для фільтру «{self._filter}»",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=COLORS.get("text_dim","#444466"),
                ).grid(row=1, column=0, pady=24)
            return

        sorted_hosts = sorted(filtered, key=_device_sort_key)
        groups: dict = {k: [] for k in self._CATEGORIES}

        _PHONE_VENDORS = {
            "apple","samsung","xiaomi","redmi","poco","huawei","honor",
            "oppo","realme","vivo","oneplus","motorola","nokia","lg",
            "sony","htc","zte","alcatel","google","pixel","meizu",
            "приватний mac",
        }
        _PC_VENDORS = {
            "dell","hp","lenovo","asus","acer","msi","gigabyte","intel",
            "realtek","vmware","virtualbox","microsoft surface",
        }

        for d in sorted_hosts:
            threat = d.get("threat","safe")
            if (threat in ("critical","danger") and not d.get("alert_dismissed") and not d.get("is_trusted")):
                groups["suspicious"].append(d)
            elif d.get("is_gateway"):
                groups["gateway"].append(d)
            elif d.get("is_self"):
                groups["self"].append(d)
            else:
                icon     = get_device_icon(d)
                icon_raw = d.get("icon", "❓")
                devtype  = (d.get("dev_type") or "").lower()
                vendor_l = (d.get("vendor")   or "").lower()
                brand_l  = (d.get("phone_brand") or "").lower()

                is_phone_vendor = (
                    any(v in vendor_l for v in _PHONE_VENDORS) or
                    any(v in brand_l  for v in _PHONE_VENDORS) or
                    _is_random_mac(d.get("mac",""))
                )
                is_pc_vendor = any(v in vendor_l for v in _PC_VENDORS)

                is_phone_type = (
                    icon in ("📱",) or icon_raw in ("📱",) or
                    any(k in devtype for k in (
                        "phone","смартфон","iphone","ipad","galaxy","android",
                        "приватний mac","планшет","pixel","xiaomi","huawei",
                        "samsung","realme","oppo","vivo","oneplus","motorola",
                        "nokia","xperia","linux / android",
                    ))
                )
                is_pc_type = (
                    icon in ("💻","🖥️") or icon_raw in ("💻","🖥️") or
                    any(k in devtype for k in (
                        "ноутбук","комп","laptop","desktop","windows pc",
                        "realtek","intel","macbook","linux server","ssh device",
                    ))
                )

                if is_pc_type and not is_phone_vendor:
                    groups["pc"].append(d)
                elif is_phone_type or is_phone_vendor:
                    groups["phone"].append(d)
                elif icon in ("📺","🎮","🔊") or icon_raw in ("📺","🎮","🔊"):
                    groups["tv"].append(d)
                elif icon in ("🖨️","📷") or icon_raw in ("🖨️","📷") or any(k in devtype for k in ("принт","камер","printer","camera")):
                    groups["iot"].append(d)
                else:
                    groups["unknown"].append(d)

        # Збираємо плоский список секцій + карток для чанкового рендеру
        render_queue: list = []  # кожен елемент: ("header", label, count, color) або ("card", device)
        for cat_key, cat_devices in groups.items():
            if not cat_devices: continue
            label, color = self._CATEGORIES[cat_key]
            if cat_key == "phone":
                id_count  = sum(1 for d in cat_devices if d.get("phone_model") or d.get("phone_name") or d.get("dhcp_hostname") or d.get("ssh_hostname"))
                unk_count = len(cat_devices) - id_count
                label = f"{label}  [{id_count} ідент." + (f" / {unk_count} без назви" if unk_count else "") + "]"
            render_queue.append(("header", label, len(cat_devices), color))
            for device in cat_devices:
                render_queue.append(("card", device))

        # FIX-3: чанковий рендер — 8 елементів за раз, решта через after()
        self._render_chunk(target, render_queue, row_idx=1, chunk_size=8)

    def _render_chunk(self, target, queue: list, row_idx: int, chunk_size: int = 8):
        """
        FIX-3: рендер по чанках — chunk_size елементів за раз,
        решта через after(16ms). Це не блокує UI і прокрутка не лагає.
        """
        if not queue:
            return

        chunk = queue[:chunk_size]
        rest  = queue[chunk_size:]

        for item in chunk:
            if item[0] == "header":
                _, label, count, color = item
                try:
                    SectionHeader(target, label, count, color=color).grid(
                        row=row_idx, column=0, sticky="ew", pady=(12,4), padx=2)
                except Exception as e:
                    print(f"SectionHeader error: {e}")
            else:
                _, device = item
                try:
                    DeviceCard(target, device,
                        on_edit=self._open_edit_dialog,
                        on_trust=self._quick_trust,
                        on_block=self._block_request,
                        on_allow=self._quick_allow,
                        on_dismiss=self._restore_alert,
                        on_speed=self._speed_request,
                    ).grid(row=row_idx, column=0, sticky="ew", pady=3)
                except Exception as e:
                    print(f"DeviceCard error ({device.get('ip')}): {e}")
            row_idx += 1

        # Ще є елементи — плануємо наступний чанк через 16мс
        if rest:
            try:
                if self.winfo_exists():
                    self.after(16, lambda q=rest, r=row_idx: self._render_chunk(target, q, r, chunk_size))
            except Exception:
                pass

    def _apply_filter(self, hosts: list) -> list:
        if self._filter == "danger":  return [h for h in hosts if h["threat"] in ("danger","critical")]
        if self._filter == "phone":
            _PHONE_BRANDS = {"apple","samsung","xiaomi","huawei","honor","oppo","realme",
                             "vivo","oneplus","motorola","nokia","lg","sony","google","htc","zte"}
            def is_phone(h):
                if h.get("is_self") or h.get("is_gateway"): return False
                if h.get("icon") == "📱" or get_device_icon(h) == "📱": return True
                vendor_l = (h.get("vendor") or "").lower()
                brand_l  = (h.get("phone_brand") or "").lower()
                devtype  = (h.get("dev_type") or "").lower()
                if any(b in vendor_l or b in brand_l for b in _PHONE_BRANDS): return True
                if any(k in devtype for k in ("смартфон","android","iphone","ipad","galaxy","pixel")): return True
                if _is_random_mac(h.get("mac","")): return True
                return False
            return [h for h in hosts if is_phone(h)]
        if self._filter == "new":     return [h for h in hosts if h.get("is_new")]
        if self._filter == "trusted": return [h for h in hosts if h.get("is_trusted")]
        if self._filter == "allowed": return [h for h in hosts if h.get("alert_dismissed") or h.get("is_allowed")]
        if self._filter == "wifi":    return [h for h in hosts if h.get("connection_type")=="WiFi"]
        if self._filter == "wired":   return [h for h in hosts if h.get("connection_type")=="LAN"]
        return hosts

    # FIX-4 — Діагностика: всі виклики з timeout, не зависає
    def _run_diagnostics(self):
        self._clear_scroll(); target = self._scroll_target()
        target.grid_columnconfigure(0, weight=1)
        card   = COLORS.get("bg_card","#1a1a2e")
        cyan   = COLORS.get("accent_cyan","#00d4ff")
        yellow = COLORS.get("accent_yellow","#ffd700")
        green  = COLORS.get("accent_green","#00ff88")
        red    = COLORS.get("accent_red","#ff4444")
        sec    = COLORS.get("text_secondary","#8888aa")
        dim    = COLORS.get("text_dim","#444466")

        hdr = ctk.CTkFrame(target, fg_color=card, corner_radius=12,
                           border_width=1, border_color=cyan)
        hdr.grid(row=0, column=0, sticky="ew", pady=(0,10))
        ctk.CTkLabel(hdr, text="🔬  ДІАГНОСТИКА МЕРЕЖЕВОГО СТЕКА",
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            text_color=cyan).pack(anchor="w", padx=18, pady=(14,4))
        ctk.CTkLabel(hdr,
            text="Перевірка шлюзу · ARP · Scapy · IP Forward · Router API · SSH",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=sec).pack(anchor="w", padx=18, pady=(0,12))

        # Результати — окремий фрейм на canvas (не знищується при _clear_scroll)
        res_f = ctk.CTkFrame(target, fg_color=card, corner_radius=12)
        res_f.grid(row=1, column=0, sticky="ew", pady=(0,10))
        res_f.grid_columnconfigure(0, weight=1)

        loading = ctk.CTkLabel(res_f,
            text="⏳  Виконую діагностику…",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=yellow)
        loading.grid(row=0, column=0, padx=18, pady=24)
        self.status_lbl.configure(text="🔬  Виконую діагностику…", text_color=cyan)

        # Зберігаємо посилання щоб _show міг перевірити чи вікно ще живе
        _res_f_ref  = res_f
        _loading_ref = loading

        def _add_result(results, text, color):
            results.append((text, color))

        def _do():
            results = []

            # 1. Мережа
            gw = ""
            try:
                with _cf.ThreadPoolExecutor(max_workers=2) as ex:
                    f_gw = ex.submit(self.engine._detect_gateway)
                    f_my = ex.submit(self.engine._detect_my_ip)
                    gw = f_gw.result(timeout=5)
                    my = f_my.result(timeout=5)
                subnet = gw.rsplit(".",1)[0]+".0/24" if "." in gw else "невідомо"
                _add_result(results, f"✅  Шлюз:       {gw}", green)
                _add_result(results, f"✅  Мій IP:     {my}", green)
                _add_result(results, f"✅  Підмережа:  {subnet}", green)
            except Exception as e:
                gw = gw or "невідомо"
                _add_result(results, f"❌  Мережа: {e}", red)

            # 2. ARP кеш
            try:
                with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                    arp = ex.submit(self.engine._get_arp_table).result(timeout=5)
                _add_result(results,
                    f"{'✅' if arp else '⚠️'}  ARP кеш: {len(arp)} записів",
                    green if arp else yellow)
            except Exception as e:
                _add_result(results, f"❌  ARP: {e}", red)

            # 3. Scapy + Npcap
            try:
                ok, msg = self.engine._check_scapy()
                _add_result(results,
                    f"{'✅' if ok else '❌'}  Scapy/Npcap: {msg}",
                    green if ok else red)
                if not ok:
                    _add_result(results,
                        "   👉  npcap.com → встановіть з 'WinPcap API-compatible Mode'", yellow)
                    _add_result(results,
                        "   👉  pip install scapy  +  запуск як Адміністратор", yellow)
            except Exception as e:
                _add_result(results, f"❌  Scapy: {e}", red)

            # 4. IP Forwarding стан
            try:
                import platform as _pl
                if _pl.system() == "Windows":
                    r = subprocess.run(
                        ["netsh","int","ipv4","show","global"],
                        capture_output=True, text=True, timeout=5)
                    fwd_on = "enabled" in r.stdout.lower() if r.returncode == 0 else None
                else:
                    with open("/proc/sys/net/ipv4/ip_forward") as f:
                        fwd_on = f.read().strip() == "1"
                if fwd_on is True:
                    _add_result(results,
                        "⚠️  IP Forwarding: УВІМКНЕНИЙ — блокування не ефективне!",
                        yellow)
                    _add_result(results,
                        "   NetGuardian вимкне його автоматично при блокуванні.", dim)
                elif fwd_on is False:
                    _add_result(results, "✅  IP Forwarding: вимкнений (правильно)", green)
            except Exception as e:
                _add_result(results, f"ℹ️  IP Forwarding: {e}", dim)

            # 5. Права адміністратора (Windows)
            try:
                import platform as _pl
                if _pl.system() == "Windows":
                    import ctypes as _ct
                    is_admin = bool(_ct.windll.shell32.IsUserAnAdmin())
                    _add_result(results,
                        f"{'✅' if is_admin else '❌'}  Права Адміністратора: {'ТАК' if is_admin else 'НІ — блокування не спрацює!'}",
                        green if is_admin else red)
            except Exception:
                pass

            # 6. SSH
            try:
                if gw and gw != "невідомо":
                    from features.security.lan_security import RouterSSHScanner
                    def _chk():
                        return RouterSSHScanner(gw, timeout=2.0).is_available()
                    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                        ssh_ok = ex.submit(_chk).result(timeout=4)
                    _add_result(results,
                        f"{'✅' if ssh_ok else 'ℹ️'}  SSH port 22 на {gw}: {'відкритий' if ssh_ok else 'закритий'}",
                        green if ssh_ok else sec)
            except Exception as e:
                _add_result(results, f"❌  SSH: {e}", red)

            # 7. Router API
            try:
                if gw and gw != "невідомо":
                    from features.security.lan_security import RouterClientReader as RCR
                    def _router():
                        r = RCR(gw, timeout=3.0)
                        return r, r.get_all_clients()
                    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                        reader, clients = ex.submit(_router).result(timeout=8)
                    if clients:
                        brand = reader._router_brand or "невідомо"
                        wifi  = sum(1 for c in clients if c.get("connection_type")=="WiFi")
                        lan   = sum(1 for c in clients if c.get("connection_type")=="LAN")
                        _add_result(results,
                            f"✅  Router API ({brand}): {len(clients)} клієнтів  (WiFi:{wifi} LAN:{lan})",
                            green)
                    else:
                        _add_result(results,
                            "⚠️  Router API: клієнтів не знайдено (перевірте логін/пароль)",
                            yellow)
            except _cf.TimeoutError:
                _add_result(results, "⚠️  Router API: timeout >8с", yellow)
            except Exception as e:
                _add_result(results, f"❌  Router API: {e}", red)

            # 8. Ping до шлюзу
            try:
                if gw and gw != "невідомо":
                    import platform as _pl
                    cmd = (["ping","-n","1","-w","1000",gw]
                           if _pl.system()=="Windows"
                           else ["ping","-c","1","-W","2",gw])
                    with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                        r = ex.submit(subprocess.run, cmd,
                                      capture_output=True, timeout=3).result(timeout=4)
                    _add_result(results,
                        f"{'✅' if r.returncode==0 else '⚠️'}  Ping {gw}",
                        green if r.returncode==0 else yellow)
            except Exception as e:
                _add_result(results, f"❌  Ping: {e}", red)

            # Передаємо в головний потік
            def _show(res=results):
                try:
                    # Перевіряємо чи фрейм ще живий
                    if not _res_f_ref.winfo_exists():
                        return
                except Exception:
                    return

                # Видаляємо "завантаження" — ігноруємо помилки
                try:
                    _loading_ref.destroy()
                except Exception:
                    pass

                # Показуємо результати
                for i, (line, col) in enumerate(res):
                    try:
                        ctk.CTkLabel(_res_f_ref, text=line,
                            font=ctk.CTkFont(family="Consolas", size=12),
                            text_color=col, anchor="w", justify="left",
                            wraplength=900,
                            ).grid(row=i, column=0, padx=18, pady=2, sticky="w")
                    except Exception:
                        pass  # продовжуємо, не break

                try:
                    self.status_lbl.configure(
                        text=f"🔬  Діагностика завершена ({len(res)} перевірок)",
                        text_color=green)
                except Exception:
                    pass

            self._safe_after(_show)

        threading.Thread(target=_do, daemon=True).start()

    def _on_suppress_toggle(self, value: bool):
        gw = self._current_gw or self.engine._detect_gateway()
        self.engine.set_router_suppress(gw, value)
        green  = COLORS.get("accent_green","#00ff88")
        yellow = COLORS.get("accent_yellow","#ffd700")

        # Оновлюємо тільки дані — БЕЗ повного перерендеру одразу
        for h in self._hosts:
            if not h.get("is_trusted") and not h.get("is_gateway") and not h.get("is_self"):
                if value and h["threat"] == "warn":
                    h["threat"] = "safe"
                elif not value and h.get("original_threat") == "warn":
                    h["threat"] = "warn"

        self.status_lbl.configure(
            text=f"{'🔕' if value else '🔔'}  Попередження: {'заглушено' if value else 'відновлено'}",
            text_color=green if value else yellow)

        # Відкладений перерендер щоб не блокувати UI
        if hasattr(self, "_suppress_render_job"):
            try: self.after_cancel(self._suppress_render_job)
            except Exception: pass
        self._suppress_render_job = self.after(
            150, lambda: self._render_hosts(self._hosts))

    def _open_edit_dialog(self, host: dict):
        def _save(data: dict):
            mac = data["mac"]
            self.engine.set_device_label(mac, data["label"], data["notes"])
            self.engine.set_trusted(mac, data["trusted"])
            if data.get("alert_dismissed"): self.engine.dismiss_alert(mac)
            else: self.engine.restore_alert(mac)
            for h in self._hosts:
                if h["mac"] == mac:
                    h.update({"user_label":data["label"],"user_notes":data["notes"],
                               "is_trusted":data["trusted"],"alert_dismissed":data.get("alert_dismissed",False),
                               "icon":data["icon"]})
                    if data["trusted"] and h["threat"]=="warn": h["threat"] = "safe"
                    break
            self._render_hosts(self._hosts)
            green  = COLORS.get("accent_green","#00ff88")
            yellow = COLORS.get("accent_yellow","#ffd700")
            saved_name = data["label"] or host.get("hostname") or host["ip"]
            self.status_lbl.configure(
                text=f"💾  '{saved_name}' збережено" + (" · 🛡️ Довірений" if data["trusted"] else ""),
                text_color=green if data["trusted"] else yellow)
        DeviceEditDialog(self, host, on_save_cb=_save)

    def _quick_trust(self, mac: str, trusted: bool):
        self.engine.set_trusted(mac, trusted)
        for h in self._hosts:
            if h["mac"] == mac:
                h["is_trusted"] = trusted
                if trusted and h["threat"]=="warn": h["threat"] = "safe"
        green  = COLORS.get("accent_green","#00ff88")
        yellow = COLORS.get("accent_yellow","#ffd700")
        self.status_lbl.configure(
            text=f"{'✅' if trusted else '❌'}  {mac} — {'додано до довірених' if trusted else 'видалено'}",
            text_color=green if trusted else yellow)

    def _quick_allow(self, mac: str):
        self.engine.dismiss_alert(mac)
        for h in self._hosts:
            if h["mac"] == mac:
                h["alert_dismissed"] = True; h["is_allowed"] = True
                if h["threat"]=="warn": h["threat"] = "safe"
                break
        self.status_lbl.configure(text=f"🔕  {mac} — попередження знято", text_color="#44ff88")
        self._render_hosts(self._hosts)

    def _restore_alert(self, mac: str):
        self.engine.restore_alert(mac)
        for h in self._hosts:
            if h["mac"] == mac:
                h["alert_dismissed"] = False; h["is_allowed"] = False; break
        self._render_hosts(self._hosts)

    def _open_banned_list(self):
        def on_unban(mac: str):
            # Оновлюємо картку якщо є в списку
            for h in self._hosts:
                if h.get("mac") == mac:
                    h["alert_dismissed"] = False
                    break
            green = COLORS.get("accent_green","#00ff88")
            self.status_lbl.configure(
                text=f"🔓  {mac} — розблоковано", text_color=green)
        BannedListPage(self.winfo_toplevel(), self.engine, on_unban_cb=on_unban)

    def _speed_request(self, host: dict):
        def on_done(ok: bool, msg: str):
            col  = COLORS.get("accent_cyan" if ok else "accent_red","#00d4ff")
            name = _best_device_label(host)
            self.status_lbl.configure(
                text=f"⚡  {name} — {'обмеження встановлено' if ok else 'помилка'}", text_color=col)
        SpeedControlDialog(self, host, self.engine, on_done_cb=on_done)

    def _block_request(self, host: dict):
        """
        Новий спрощений workflow: замість діалогу з вибором тривалості
        одразу показуємо інструкцію блокування через роутер.
        Автоматично копіюємо MAC у буфер і відкриваємо admin-панель.
        """
        # Викликаємо ManualBlockDialog — він сам:
        #   1. Покаже MAC + ім'я пристрою для блокування
        #   2. Інструкцію конкретно для твого вендора роутера (D-Link, TP-Link тощо)
        #   3. Кнопку "🌐 Відкрити роутер" що копіює MAC у буфер і відкриває браузер
        #   4. Кнопку "✅ Натиснуто, готово" що записує пристрій у БД як заблокований
        ManualBlockDialog(self, host, self.engine,
                          reason="Ручне блокування через адмін-панель роутера")

    def _refresh_banned_count(self):
        """Оновлює текст кнопки 'Заблоковані' з кількістю."""
        try:
            n = len(self.engine.get_banned())
            red = COLORS.get("accent_red","#ff4444")
            txt = f"🚫 Заблоковані  [{n}]" if n else "🚫 Заблоковані"
            self.btn_banned.configure(text=txt)
        except Exception:
            pass

    def _set_btns(self, state: str):
        for btn in (self.btn_scan, self.btn_rescan):
            try: btn.configure(state=state)
            except Exception: pass