# gui/pages/wifi_ui.py
"""
NetGuardian AI — Wi-Fi Analyzer  v5
Зміни відносно v4:
  • Arc-діаграма тепер займає більше місця (row 0 weight=5, row 1 weight=2)
  • Кнопка «?» поруч із заголовком arc-діаграми відкриває popup з поясненням
  • Власна мережа більше не рахується як перешкода (виправлення WifiEngine v6)
"""
from __future__ import annotations
import customtkinter as ctk
import tkinter as tk
import threading
import webbrowser

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.wifi.engine import (
    WifiEngine, WifiNetwork, ROUTER_PROFILES,
    NONOVERLAP_20MHZ, NONOVERLAP_40MHZ, CHANNELS_5GHZ,
)

NEON_PALETTE = [
    "#00ff88", "#00b4ff", "#a855f7", "#ff3366",
    "#00ffe7", "#ffaa00", "#ff00ff", "#39ff14",
    "#ff6b35", "#4ecdc4", "#45b7d1", "#96ceb4",
    "#f7971e", "#c471ed", "#12c2e9", "#f64f59",
]

BAND_TABS = ["2.4 GHz", "5 GHz"]

# ──────────────────────────────────────────────────────────
# Stat-картка
# ──────────────────────────────────────────────────────────

class _StatCard(ctk.CTkFrame):
    def __init__(self, parent, icon: str, title: str,
                 value: str = "—", accent: str = "#00b4ff", **kw):
        super().__init__(
            parent,
            fg_color=COLORS.get("bg_card", "#111827"),
            corner_radius=10,
            border_width=1,
            border_color=accent,
            **kw)
        ctk.CTkLabel(self, text=icon,
                     font=ctk.CTkFont(size=22),
                     text_color=accent).pack(pady=(10, 0))
        ctk.CTkLabel(self, text=title,
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=COLORS.get("text_dim", "#555")).pack()
        self._val = ctk.CTkLabel(
            self, text=value,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=accent)
        self._val.pack(pady=(2, 10))
        self._accent = accent

    def update(self, value: str, accent: str | None = None):
        if accent:
            self._accent = accent
            self._val.configure(text_color=accent)
            self.configure(border_color=accent)
        self._val.configure(text=value)


# ──────────────────────────────────────────────────────────
# Popup-пояснення Arc-діаграми
# ──────────────────────────────────────────────────────────

class _ArcHelpPopup(ctk.CTkToplevel):
    """
    Модальне вікно з поясненням як читати Arc (дуги перекриття) діаграму.
    Відкривається кнопкою «?» поруч із заголовком.
    """
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Як читати Channel Overlap")
        self.geometry("520x560")
        self.resizable(False, False)
        self.configure(fg_color=COLORS.get("bg_primary", "#0a0f1a"))
        self.grab_set()          # модальне вікно
        self.focus_force()
        self._build()

    def _build(self):
        pad = {"padx": 24, "pady": (0, 10), "sticky": "w"}

        ctk.CTkLabel(
            self,
            text="📡  Що таке Channel Overlap (дуги перекриття)?",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#00b4ff"),
            wraplength=470,
        ).pack(padx=24, pady=(20, 12), anchor="w")

        sections = [
            (
                "🌈  Кожна дуга = одна Wi-Fi мережа",
                "Кожна мережа зображена у вигляді дуги. Центр дуги — це канал, "
                "на якому вона працює. Ширина дуги показує, які сусідні канали "
                "вона «забруднює» (через накладання частот у діапазоні 2.4 GHz)."
            ),
            (
                "📏  Висота дуги = сила сигналу",
                "Чим вища дуга — тим сильніший сигнал мережі. Висока дуга від "
                "сусідньої мережі означає, що вона сильно заважатиме тобі, якщо "
                "твій роутер на тому ж або близькому каналі."
            ),
            (
                "⭐  Золота дуга = твоя мережа",
                "Твоя підключена мережа виділена жовтим/золотим кольором і "
                "намальована жирнішою лінією. Решта мереж — кольорові дуги сусідів."
            ),
            (
                "🔢  Канали 1 · 6 · 11 — незалежні (20 MHz)",
                "У діапазоні 2.4 GHz тільки канали 1, 6 і 11 не перекриваються "
                "між собою при ширині 20 MHz. Саме тому вертикальні лінії цих "
                "каналів підсвічені блакитним. Ідеальна ситуація — кожна мережа "
                "в будинку використовує один із цих трьох каналів."
            ),
            (
                "📊  Де перекриття — там проблема",
                "Якщо дуги кількох мереж перекриваються по горизонталі — ці "
                "мережі заважають одна одній. Чим більше перекриття і чим вищі "
                "дуги — тим більша інтерференція і нижча реальна швидкість Wi-Fi."
            ),
            (
                "✅  Ідеальна картина",
                "Мінімум дуг на одному каналі, твоя мережа на вільному каналі "
                "(1, 6 або 11), і жодних сусідніх дуг, які перекривають твою."
            ),
        ]

        for title, body in sections:
            ctk.CTkLabel(
                self, text=title,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=COLORS.get("accent_yellow", "#ffaa00"),
                wraplength=470,
                anchor="w",
            ).pack(padx=24, pady=(10, 2), anchor="w")
            ctk.CTkLabel(
                self, text=body,
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS.get("text_secondary", "#8899aa"),
                wraplength=470,
                justify="left",
                anchor="w",
            ).pack(padx=30, pady=(0, 4), anchor="w")

        ctk.CTkButton(
            self, text="Зрозуміло  ✓",
            command=self.destroy,
            fg_color=COLORS.get("border_accent", "#0d3d8a"),
            hover_color="#0d3d8a",
            text_color=COLORS.get("accent_cyan", "#00b4ff"),
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=36, corner_radius=8,
        ).pack(padx=24, pady=(16, 20), anchor="e")


# ══════════════════════════════════════════════════════════
# MAIN PAGE
# ══════════════════════════════════════════════════════════

class WifiAnalyzerPage(ctk.CTkFrame):
    def __init__(self, parent, get_gateway_cb=None):
        super().__init__(parent, fg_color="transparent")

        self.get_gateway_cb = get_gateway_cb
        self.engine         = WifiEngine()
        self._networks: list[WifiNetwork] = []
        self._rating:   dict              = {}
        self._scanning  = False
        self._has_data  = False
        self._band      = "2.4 GHz"
        self._router_key = tk.StringVar(value="cudy")
        self._sel_ch:   int | None = None

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self._build_ui()

    # ══════════════════════════════════════════════════════
    # BUILD
    # ══════════════════════════════════════════════════════

    def _build_ui(self):
        self._build_toolbar()      # row 0
        self._build_stat_cards()   # row 1
        self._build_main_area()    # row 2
        self._build_table()        # row 3

    # ── TOOLBAR ──────────────────────────────────────────
    def _build_toolbar(self):
        tb = ctk.CTkFrame(self,
                          fg_color=COLORS.get("bg_secondary", "#0d1117"),
                          corner_radius=12)
        tb.grid(row=0, column=0, padx=20, pady=(20, 6), sticky="ew")
        tb.grid_columnconfigure(1, weight=1)

        self.btn_scan = ctk.CTkButton(
            tb, text="📡  СКАНУВАТИ ЕФІР",
            command=self.start_scan,
            fg_color=COLORS["border_accent"],
            hover_color="#0d3d8a",
            text_color=COLORS["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=40, corner_radius=9, width=200)
        self.btn_scan.grid(row=0, column=0, padx=12, pady=10)

        self.status_lbl = ctk.CTkLabel(
            tb, text="  Натисни «СКАНУВАТИ» для аналізу ефіру",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_secondary"])
        self.status_lbl.grid(row=0, column=1, sticky="w")

        self._band_btns: dict[str, ctk.CTkButton] = {}
        for band in reversed(BAND_TABS):
            b = ctk.CTkButton(
                tb, text=band, width=78, height=30,
                corner_radius=8,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                fg_color=(COLORS["border_accent"] if band == "2.4 GHz"
                          else "transparent"),
                border_width=1,
                border_color=COLORS["accent_purple"],
                text_color=COLORS["accent_cyan"],
                hover_color="#1a2540",
                command=lambda x=band: self._switch_band(x))
            b.grid(row=0, column=2 if band == "5 GHz" else 3,
                   padx=4, pady=10)
            self._band_btns[band] = b

    # ── STAT CARDS ───────────────────────────────────────
    def _build_stat_cards(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, padx=20, pady=(0, 6), sticky="ew")
        for i in range(4):
            row.grid_columnconfigure(i, weight=1)

        self._c_mynet  = _StatCard(row, "📶", "МОЯ МЕРЕЖА",     "—", COLORS["accent_yellow"])
        self._c_ch     = _StatCard(row, "🔢", "МІЙ КАНАЛ",      "—", COLORS["accent_cyan"])
        self._c_best   = _StatCard(row, "✅", "КРАЩИЙ КАНАЛ",   "—", COLORS["accent_green"])
        self._c_total  = _StatCard(row, "🌐", "МЕРЕЖ ЗНАЙДЕНО", "—", COLORS["accent_purple"])

        self._c_mynet .grid(row=0, column=0, padx=6, sticky="ew")
        self._c_ch    .grid(row=0, column=1, padx=6, sticky="ew")
        self._c_best  .grid(row=0, column=2, padx=6, sticky="ew")
        self._c_total .grid(row=0, column=3, padx=6, sticky="ew")

    # ── MAIN AREA ─────────────────────────────────────────
    def _build_main_area(self):
        area = ctk.CTkFrame(self, fg_color="transparent")
        area.grid(row=2, column=0, padx=20, pady=(0, 6), sticky="nsew")
        area.grid_columnconfigure(1, weight=1)
        area.grid_rowconfigure(0, weight=1)

        # Left panel
        left = ctk.CTkFrame(area,
                            fg_color=COLORS.get("bg_secondary", "#0d1117"),
                            corner_radius=12,
                            border_width=1,
                            border_color=COLORS["accent_yellow"],
                            width=220)
        left.grid(row=0, column=0, padx=(0, 8), sticky="nsew")
        left.grid_columnconfigure(0, weight=1)
        left.grid_propagate(False)
        self._build_left_panel(left)

        # Right: charts
        right = ctk.CTkFrame(area, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew")
        right.grid_columnconfigure(0, weight=1)
        # Arc займає більше місця — weight=5 vs weight=2 для bar
        right.grid_rowconfigure(0, weight=5)
        right.grid_rowconfigure(1, weight=2)
        self._build_charts(right)

    def _build_left_panel(self, p):
        _lbl = lambda txt, r, size=9, color=None, bold=False: ctk.CTkLabel(
            p, text=txt,
            font=ctk.CTkFont(family="Consolas", size=size,
                             weight="bold" if bold else "normal"),
            text_color=color or COLORS["text_secondary"],
            anchor="w").grid(row=r, column=0, padx=14, pady=(6, 0), sticky="w")

        _lbl("📶  CHANNEL SWITCHER", 0, size=10, bold=True,
             color=COLORS["accent_yellow"])
        _lbl("Вибери канал → відкриє панель роутера", 1, size=8,
             color=COLORS["text_dim"])

        ctk.CTkFrame(p, height=1,
                     fg_color=COLORS["accent_yellow"]).grid(
            row=2, column=0, padx=10, pady=(6, 6), sticky="ew")

        ctk.CTkLabel(p, text="2.4 GHz  ·  канали 1–13:",
                     font=ctk.CTkFont(family="Consolas", size=8),
                     text_color=COLORS["text_dim"],
                     anchor="w").grid(row=3, column=0, padx=14,
                                       pady=(4, 4), sticky="w")

        grid_f = ctk.CTkFrame(p, fg_color="transparent")
        grid_f.grid(row=4, column=0, padx=8, pady=(0, 4), sticky="ew")
        for c in range(4):
            grid_f.grid_columnconfigure(c, weight=1)

        self._ch_btns: dict[int, ctk.CTkButton] = {}
        for ch in range(1, 14):
            r, c   = divmod(ch - 1, 4)
            is_key = ch in NONOVERLAP_20MHZ
            btn = ctk.CTkButton(
                grid_f, text=str(ch),
                height=32, corner_radius=7,
                font=ctk.CTkFont(
                    family="Consolas", size=11,
                    weight="bold" if is_key else "normal"),
                fg_color=(COLORS["border_accent"] if is_key
                          else COLORS.get("bg_card", "#111827")),
                border_width=1,
                border_color=(COLORS["accent_cyan"] if is_key
                              else COLORS["border"]),
                text_color=(COLORS["accent_cyan"] if is_key
                            else COLORS["text_secondary"]),
                hover_color="#1a3a5c",
                command=lambda x=ch: self._on_ch_click(x))
            btn.grid(row=r, column=c, padx=2, pady=2, sticky="ew")
            self._ch_btns[ch] = btn

        self._ch_hint = ctk.CTkLabel(
            p, text="1 · 6 · 11  — незалежні (20 MHz)\n3 · 11  — незалежні (40 MHz)",
            font=ctk.CTkFont(family="Consolas", size=7),
            text_color=COLORS["text_dim"],
            justify="left")
        self._ch_hint.grid(row=5, column=0, padx=14, pady=(0, 4), sticky="w")

        ctk.CTkFrame(p, height=1,
                     fg_color=COLORS["border"]).grid(
            row=6, column=0, padx=10, pady=(4, 6), sticky="ew")

        self.rec_lbl = ctk.CTkLabel(
            p, text="⬡  Очікування\nсканування...",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS["text_secondary"],
            justify="left", wraplength=190)
        self.rec_lbl.grid(row=7, column=0, padx=14, pady=(0, 8), sticky="w")

        self.btn_router = ctk.CTkButton(
            p, text="🌐  Відкрити панель роутера",
            command=self._open_router,
            fg_color="transparent",
            border_width=1, border_color=COLORS["accent_green"],
            text_color=COLORS["accent_green"],
            font=ctk.CTkFont(family="Consolas", size=9),
            height=30, corner_radius=8)
        self.btn_router.grid(row=8, column=0, padx=10, pady=(0, 14), sticky="ew")

    def _build_charts(self, parent):
        # ── ARC card ──────────────────────────────────────
        arc_card = ctk.CTkFrame(
            parent,
            fg_color=COLORS.get("bg_secondary", "#0d1117"),
            corner_radius=12,
            border_width=1,
            border_color=COLORS["accent_purple"])
        arc_card.grid(row=0, column=0, pady=(0, 6), sticky="nsew")
        arc_card.grid_columnconfigure(0, weight=1)
        arc_card.grid_rowconfigure(1, weight=1)   # canvas розтягується

        # Заголовок + кнопка «?»
        hdr = ctk.CTkFrame(arc_card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=10, pady=(10, 2), sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="  🌈  CHANNEL OVERLAP  ·  ДУГИ ПЕРЕКРИТТЯ  (inSSIDer style)",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS["text_dim"],
            anchor="w",
        ).grid(row=0, column=0, sticky="w")

        # Кнопка «?» відкриває popup-пояснення
        ctk.CTkButton(
            hdr, text="?",
            width=26, height=26,
            corner_radius=13,           # кругла
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            fg_color=COLORS.get("border_accent", "#0d3d8a"),
            hover_color="#1a4a9c",
            border_width=1,
            border_color=COLORS["accent_purple"],
            text_color=COLORS["accent_purple"],
            command=self._show_arc_help,
        ).grid(row=0, column=1, padx=(6, 6), sticky="e")

        self.arc_cv = tk.Canvas(arc_card,
                                bg=COLORS["bg_primary"],
                                highlightthickness=0)
        self.arc_cv.grid(row=1, column=0, padx=10, pady=(0, 10),
                         sticky="nsew", columnspan=2)

        # ── BAR card ──────────────────────────────────────
        bar_card = ctk.CTkFrame(
            parent,
            fg_color=COLORS.get("bg_secondary", "#0d1117"),
            corner_radius=12,
            border_width=1,
            border_color=COLORS["accent_cyan"])
        bar_card.grid(row=1, column=0, sticky="nsew")
        bar_card.grid_columnconfigure(0, weight=1)
        bar_card.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(
            bar_card,
            text="  📊  CHANNEL WAR  ·  ЗАВАНТАЖЕНІСТЬ КАНАЛІВ",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS["text_dim"]).grid(
            row=0, column=0, padx=16, pady=(10, 2), sticky="w")

        self.bar_cv = tk.Canvas(bar_card,
                                bg=COLORS["bg_primary"],
                                highlightthickness=0)
        self.bar_cv.grid(row=1, column=0, padx=10, pady=(0, 10), sticky="nsew")

        self.arc_cv.bind("<Configure>", lambda e: self._safe_redraw())
        self.bar_cv.bind("<Configure>", lambda e: self._safe_redraw())

        self._placeholder(self.arc_cv, "Arc-діаграма з'явиться після сканування")
        self._placeholder(self.bar_cv, "Гістограма каналів з'явиться після сканування")

    # ── Popup-пояснення ───────────────────────────────────
    def _show_arc_help(self):
        _ArcHelpPopup(self)

    # ── TABLE ─────────────────────────────────────────────
    def _build_table(self):
        card = ctk.CTkFrame(self,
                            fg_color=COLORS.get("bg_secondary", "#0d1117"),
                            corner_radius=12,
                            border_width=1,
                            border_color=COLORS["border"])
        card.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hb = ctk.CTkFrame(card, fg_color="transparent")
        hb.grid(row=0, column=0, padx=14, pady=(10, 4), sticky="ew")
        ctk.CTkLabel(hb, text="  📋  ЗНАЙДЕНІ МЕРЕЖІ",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS["text_secondary"]).pack(side="left")
        self._tbl_info = ctk.CTkLabel(hb, text="",
                                      font=ctk.CTkFont(family="Consolas", size=9),
                                      text_color=COLORS["text_dim"])
        self._tbl_info.pack(side="right", padx=8)

        COLS = [
            ("  SSID",      190, "w"),
            ("BSSID / MAC", 150, "w"),
            ("СМУГА",        60, "w"),
            ("CH",           40, "w"),
            ("RSSI",         80, "w"),
            ("БЕЗПЕКА",     110, "w"),
            ("СТАНДАРТ",     90, "w"),
            ("MAX RATE",     90, "w"),
            ("VENDOR",      100, "w"),
        ]
        hdr = ctk.CTkFrame(card,
                           fg_color=COLORS.get("bg_card", "#111827"),
                           corner_radius=8)
        hdr.grid(row=1, column=0, padx=14, pady=(0, 4), sticky="ew")
        for ci, (txt, w, anch) in enumerate(COLS):
            ctk.CTkLabel(hdr, text=txt, width=w,
                         font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=COLORS["text_dim"],
                         anchor=anch).grid(row=0, column=ci, padx=4, pady=5, sticky="w")

        self.net_list = ctk.CTkScrollableFrame(
            card, fg_color="transparent", height=200, corner_radius=0)
        self.net_list.grid(row=2, column=0, padx=10, pady=(0, 12), sticky="ew")
        self.net_list.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(self.net_list, text="  —  немає даних  —",
                     font=ctk.CTkFont(family="Consolas", size=11),
                     text_color=COLORS["text_dim"]).pack(padx=20, pady=10)

    # ══════════════════════════════════════════════════════
    # SCANNING
    # ══════════════════════════════════════════════════════

    def start_scan(self):
        if self._scanning:
            return
        self._scanning = True
        self.btn_scan.configure(state="disabled", text="⏳  СКАНУЮ ЕФІР...")
        self.status_lbl.configure(
            text="  Зчитую дані з радіомодуля...",
            text_color=COLORS["accent_yellow"])
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        networks = self.engine.scan_networks()
        rating   = self.engine.get_channel_rating(networks)
        self.after(0, lambda: self._on_done(networks, rating))

    def _on_done(self, networks, rating):
        self._networks = networks
        self._rating   = rating
        self._scanning = False
        self.btn_scan.configure(state="normal", text="📡  СКАНУВАТИ ЕФІР")

        if not networks:
            self.status_lbl.configure(
                text="  Не вдалося отримати дані. Увімкніть Wi-Fi адаптер.",
                text_color=COLORS["accent_red"])
            return

        my_ch   = rating["my_channel"]
        best_ch = rating["best_channel"]
        my_band = rating["my_band"]
        my_w    = rating["my_width"]
        n_24    = sum(1 for n in networks if n.band == "2.4 GHz")
        n_5     = sum(1 for n in networks if n.band == "5 GHz")
        mine    = next((n for n in networks if n.is_mine), None)

        self.status_lbl.configure(
            text=(f"  Знайдено {len(networks)} мереж  "
                  f"({n_24} × 2.4 GHz  /  {n_5} × 5 GHz)  ·  "
                  f"Канал: {my_ch}  →  Рекомендований: {best_ch}"),
            text_color=COLORS["accent_cyan"])

        self._c_mynet.update(
            (mine.ssid[:16] if mine else "невідомо"),
            COLORS["accent_yellow"])
        self._c_ch   .update(f"ch {my_ch}  {my_band}\n{my_w} MHz")
        self._c_best .update(
            f"ch {best_ch}",
            COLORS["accent_green"] if best_ch != my_ch else COLORS["accent_cyan"])
        self._c_total.update(f"{len(networks)}\n{n_24}×2.4 + {n_5}×5")

        rec        = rating["recommendation"]
        nonoverlap = rating.get("nonoverlap", [])
        rec_extra  = (f"\nНезалежні канали ({my_w} MHz): "
                      f"{', '.join(map(str, nonoverlap))}"
                      if nonoverlap else "")
        if rating.get("worth_switching"):
            self.rec_lbl.configure(
                text=f"⚠️  {rec}{rec_extra}",
                text_color=COLORS["accent_yellow"])
        else:
            self.rec_lbl.configure(
                text=f"✅  {rec}{rec_extra}",
                text_color=COLORS["accent_green"])

        self._has_data = True
        self._build_net_table(networks)
        self._highlight_ch_btns()
        self._tbl_info.configure(
            text=f"показано {min(len(networks), 60)} / {len(networks)}")
        self.update_idletasks()
        self._safe_redraw()

    # ══════════════════════════════════════════════════════
    # CHANNEL SWITCHER
    # ══════════════════════════════════════════════════════

    # Затримка перед авто-ресканом після зміни каналу (секунди).
    # Роутеру потрібно ~25-40 сек щоб перезавантажитись після зміни каналу.
    RESCAN_DELAY_SEC = 35

    def _on_ch_click(self, ch: int):
        self._sel_ch = ch
        self._highlight_ch_btns(selected=ch)
        gw  = (self.get_gateway_cb()
               if self.get_gateway_cb else self.engine.get_gateway_ip())
        url = f"http://{gw}/"
        webbrowser.open(url)

        # Запускаємо зворотний відлік і авто-ресcan
        self._start_rescan_countdown(ch)

    def _start_rescan_countdown(self, ch: int):
        """
        Показує зворотний відлік у підказці та запускає авто-ресcan
        через RESCAN_DELAY_SEC секунд.
        Причина: після зміни каналу роутер перезавантажує Wi-Fi (~25-40с),
        тому програма показуватиме старий канал поки не відбудеться ресcan.
        """
        import threading

        # Скасовуємо попередній відлік якщо є
        if hasattr(self, "_rescan_cancel") and self._rescan_cancel:
            self._rescan_cancel.set()

        cancel_evt = threading.Event()
        self._rescan_cancel = cancel_evt
        total = self.RESCAN_DELAY_SEC

        def countdown():
            for remaining in range(total, 0, -1):
                if cancel_evt.is_set():
                    return
                self.after(0, lambda r=remaining: self._ch_hint.configure(
                    text=(f"→ Канал {ch} обраний на роутері\n"
                          f"⏱ Авто-ресcan через {r} сек..."),
                    text_color=COLORS["accent_yellow"]))
                import time
                time.sleep(1)

            if cancel_evt.is_set():
                return

            # Оновлюємо підказку
            self.after(0, lambda: self._ch_hint.configure(
                text=f"🔄 Сканую ефір після зміни каналу {ch}...",
                text_color=COLORS["accent_cyan"]))

            # Запускаємо ресcan
            self.after(0, self.start_scan)

        threading.Thread(target=countdown, daemon=True,
                         name="RescanCountdown").start()

    def _highlight_ch_btns(self, selected: int | None = None):
        my_ch   = self._rating.get("my_channel", 0)
        best_ch = self._rating.get("best_channel", 0)

        for ch, btn in self._ch_btns.items():
            is_key = ch in NONOVERLAP_20MHZ
            if ch == selected:
                btn.configure(fg_color=COLORS["accent_yellow"],
                              text_color=COLORS["bg_primary"],
                              border_color=COLORS["accent_yellow"])
            elif ch == my_ch:
                btn.configure(fg_color="#2a1e00",
                              text_color=COLORS["accent_yellow"],
                              border_color=COLORS["accent_yellow"])
            elif ch == best_ch and ch != my_ch:
                btn.configure(fg_color="#002a10",
                              text_color=COLORS["accent_green"],
                              border_color=COLORS["accent_green"])
            else:
                btn.configure(
                    fg_color=(COLORS["border_accent"] if is_key
                              else COLORS.get("bg_card", "#111827")),
                    border_color=(COLORS["accent_cyan"] if is_key
                                  else COLORS["border"]),
                    text_color=(COLORS["accent_cyan"] if is_key
                                else COLORS["text_secondary"]))

    def _switch_band(self, band: str):
        self._band = band
        for b, btn in self._band_btns.items():
            btn.configure(fg_color=(COLORS["border_accent"] if b == band
                                    else "transparent"))
        if self._has_data:
            self._safe_redraw()

    # ══════════════════════════════════════════════════════
    # REDRAW
    # ══════════════════════════════════════════════════════

    def _safe_redraw(self):
        if self._has_data:
            self._draw_arc()
            self._draw_bar()

    # ══════════════════════════════════════════════════════
    # ARC CHART  (inSSIDer style)
    # ══════════════════════════════════════════════════════

    def _draw_arc(self):
        c = self.arc_cv
        c.update_idletasks()
        W = max(c.winfo_width(),  200)
        H = max(c.winfo_height(), 120)
        c.delete("all")

        nets = [n for n in self._networks if n.band == self._band]
        if not nets:
            self._placeholder(c, f"Немає мереж у смузі {self._band}")
            return

        is_24 = (self._band == "2.4 GHz")

        # Більші відступи щоб SSID-підписи не обрізались зверху та знизу
        PL, PR = 46, 18
        PB     = 30       # місце для підписів каналів знизу
        PT     = 36       # більший відступ зверху — для найвищих дуг і підписів

        if is_24:
            slots    = 14
            half_bw  = 4.5
            ch_list  = list(range(1, 14))
        else:
            ch_list = sorted({n.channel for n in nets
                              if n.channel in CHANNELS_5GHZ})
            if not ch_list:
                ch_list = sorted({n.channel for n in nets if n.channel > 14})
            if not ch_list:
                self._placeholder(c, "Немає 5 GHz мереж")
                return
            slots   = len(ch_list) + 2
            half_bw = 1.2

        chart_w  = W - PL - PR
        ch_px    = chart_w / slots
        baseline = H - PB

        # ── Grid ─────────────────────────────────────────
        if is_24:
            for ch in ch_list:
                x   = PL + (ch - 0.5) * ch_px
                key = ch in NONOVERLAP_20MHZ
                col = COLORS["accent_cyan"] if key else COLORS["text_dim"]
                c.create_line(x, PT, x, baseline,
                              fill=col,
                              dash=(2, 6) if not key else ())
                c.create_text(x, H - 14, text=str(ch),
                              fill=col, font=("Consolas", 8))
                if key:
                    c.create_text(x, PT + 2,
                                  text=f"ch{ch}",
                                  fill=self._dim(col, 0.5),
                                  font=("Consolas", 6), anchor="n")
        else:
            for i, ch in enumerate(ch_list):
                x = PL + (i + 1) * ch_px
                c.create_line(x, PT, x, baseline,
                              fill=COLORS["text_dim"], dash=(2, 6))
                c.create_text(x, H - 14, text=str(ch),
                              fill=COLORS["text_secondary"],
                              font=("Consolas", 7))

        c.create_line(PL, baseline, W - PR, baseline,
                      fill=COLORS["border"], width=1)

        # ── Arcs ─────────────────────────────────────────
        # Сортуємо: спочатку слабкі (щоб сильні малювались поверх),
        # власна мережа — останньою (завжди поверх усіх)
        sorted_nets = sorted(nets, key=lambda n: (n.is_mine, n.signal))
        col_i = 0

        for net in sorted_nets:
            ch  = net.channel
            sig = max(net.signal, 1)

            if is_24:
                if not 1 <= ch <= 13:
                    continue
                cx = PL + (ch - 0.5) * ch_px
            else:
                if ch not in ch_list:
                    idx = min(range(len(ch_list)),
                              key=lambda i: abs(ch_list[i] - ch))
                else:
                    idx = ch_list.index(ch)
                cx = PL + (idx + 1) * ch_px

            half_px = half_bw * ch_px
            x0 = max(PL,     cx - half_px)
            x1 = min(W - PR, cx + half_px)

            is_mine = net.is_mine
            color   = (COLORS["accent_yellow"] if is_mine
                       else NEON_PALETTE[col_i % len(NEON_PALETTE)])
            if not is_mine:
                col_i += 1

            # Максимальна висота дуги = вся доступна висота між PT і baseline
            max_h = baseline - PT - 4
            arc_h = max(12, int(sig / 100 * max_h))
            lw    = 3 if is_mine else 2

            # Glow (слабкий ореол)
            c.create_arc(x0 - 3, baseline - arc_h * 2 - 3,
                         x1 + 3, baseline + 3,
                         start=0, extent=180, style="arc",
                         outline=self._dim(color, 0.20), width=lw + 2)
            # Arc
            c.create_arc(x0, baseline - arc_h * 2,
                         x1, baseline,
                         start=0, extent=180, style="arc",
                         outline=color, width=lw)

            # SSID label над дугою
            # Показуємо тільки якщо дуга досить висока, щоб підпис не злипся
            if arc_h > 18:
                lbl = (net.ssid[:14] + "…") if len(net.ssid) > 15 else net.ssid
                # Позиція: трохи вище верхівки дуги
                label_y = max(PT + 2, baseline - arc_h - 5)
                c.create_text(cx, label_y,
                              text=lbl,
                              fill=color,
                              font=("Consolas", 8 if is_mine else 7),
                              anchor="s")

    # ══════════════════════════════════════════════════════
    # BAR CHART
    # ══════════════════════════════════════════════════════

    def _draw_bar(self):
        c = self.bar_cv
        c.update_idletasks()
        W = max(c.winfo_width(), 100)
        H = max(c.winfo_height(), 60)
        c.delete("all")

        if self._band == "5 GHz":
            self._draw_bar_5(c, W, H)
            return

        PL, PR, PT, PB = 46, 14, 22, 22
        chart_w = W - PL - PR
        chart_h = H - PT - PB
        if chart_h < 8:
            return

        col_w    = chart_w / 13
        baseline = PT + chart_h

        interf = self._rating.get("interference", {})
        count  = self._rating.get("network_count", {})
        my_ch  = self._rating.get("my_channel", 0)
        bst_ch = self._rating.get("best_channel", 0)

        my_ch  = my_ch  if 1 <= my_ch  <= 13 else 0
        bst_ch = bst_ch if 1 <= bst_ch <= 13 else 0
        max_v  = max((interf.get(ch, 0) for ch in range(1, 14)), default=1) or 1

        for i in range(5):
            y   = PT + i * chart_h / 4
            pct = int((1 - i / 4) * 100)
            c.create_line(PL, y, W - PR, y,
                          fill=COLORS["text_dim"], dash=(3, 9))
            c.create_text(PL - 4, y,
                          text=f"{pct}",
                          fill=COLORS["text_dim"],
                          font=("Consolas", 7), anchor="e")

        for ch in range(1, 14):
            val   = interf.get(ch, 0)
            cnt   = count.get(ch, 0)
            ratio = val / max_v
            cx    = PL + (ch - 1) * col_w + col_w / 2
            bw    = col_w * 0.62

            if ch == my_ch:
                col = COLORS["accent_yellow"]
            elif ch == bst_ch and bst_ch != my_ch:
                col = COLORS["accent_green"]
            elif ratio > 0.70:
                col = COLORS["accent_red"]
            elif ratio > 0.38:
                col = "#ff8c00"
            else:
                col = COLORS["accent_blue"]

            lbl_c = (COLORS["accent_yellow"] if ch == my_ch else
                     COLORS["accent_green"]  if ch == bst_ch else
                     COLORS["text_secondary"])
            c.create_text(cx, H - 10, text=str(ch),
                          fill=lbl_c, font=("Consolas", 8))

            if val > 0:
                bar_h = max(3, ratio * chart_h * 0.93)
                y_top = baseline - bar_h

                c.create_rectangle(cx - bw/2 - 2, y_top - 1,
                                   cx + bw/2 + 2, baseline,
                                   fill=self._dim(col, 0.14), outline="")
                c.create_rectangle(cx - bw/2, y_top,
                                   cx + bw/2, baseline,
                                   fill=col, outline="")

                if cnt > 0:
                    if bar_h >= 18:
                        c.create_text(cx, y_top + bar_h * 0.5,
                                      text=str(cnt),
                                      fill=COLORS["bg_primary"],
                                      font=("Consolas", 9, "bold"))
                    else:
                        c.create_text(cx, y_top - 3,
                                      text=str(cnt),
                                      fill=col,
                                      font=("Consolas", 8), anchor="s")

                if ch == my_ch:
                    c.create_text(cx, y_top - 2,
                                  text="▲ ТИ",
                                  fill=COLORS["accent_yellow"],
                                  font=("Consolas", 7, "bold"), anchor="s")
                elif ch == bst_ch and bst_ch != my_ch:
                    c.create_text(cx, y_top - 2,
                                  text="★ BEST",
                                  fill=COLORS["accent_green"],
                                  font=("Consolas", 7, "bold"), anchor="s")
            else:
                c.create_rectangle(cx - bw/2, baseline - 2,
                                   cx + bw/2, baseline,
                                   fill=self._dim(COLORS["text_dim"], 0.4),
                                   outline="")
                c.create_text(cx, baseline - 5,
                              text="FREE",
                              fill=self._dim(COLORS["accent_green"], 0.5),
                              font=("Consolas", 5), anchor="s")

        c.create_line(PL, baseline, W - PR, baseline,
                      fill=COLORS["border"], width=1)
        c.create_line(PL, PT, PL, baseline,
                      fill=COLORS["border"], width=1)

        legend = [
            (COLORS["accent_yellow"], f"ch{my_ch or '?'} — мій"),
            (COLORS["accent_green"],  f"ch{bst_ch or '?'} — кращий"),
            (COLORS["accent_red"],    "Висока інтерф."),
            (COLORS["accent_blue"],   "Вільний"),
        ]
        lx = PL + 4
        for col, txt in legend:
            c.create_rectangle(lx, 5, lx + 8, 14,
                               fill=col, outline="")
            c.create_text(lx + 12, 9, text=txt,
                          fill=COLORS["text_secondary"],
                          font=("Consolas", 7), anchor="w")
            lx += 128

    def _draw_bar_5(self, c, W, H):
        interf_5 = self._rating.get("interference_5", {})
        count_5  = self._rating.get("network_count_5", {})

        active = {ch for ch, cnt in count_5.items() if cnt > 0}
        if not active:
            self._placeholder(c, "Немає 5 GHz мереж")
            return

        show_chs = [ch for ch in CHANNELS_5GHZ
                    if ch in active or interf_5.get(ch, 0) > 0]
        if not show_chs:
            show_chs = sorted(active)

        PL, PR, PT, PB = 46, 14, 22, 22
        chart_w = W - PL - PR
        chart_h = H - PT - PB
        n       = len(show_chs)
        col_w   = chart_w / max(n, 1)
        baseline = PT + chart_h
        max_v   = max((interf_5.get(ch, 0) for ch in show_chs), default=1) or 1
        my_ch   = self._rating.get("my_channel", 0)

        for i, ch in enumerate(show_chs):
            val   = interf_5.get(ch, 0)
            cnt   = count_5.get(ch, 0)
            ratio = val / max_v
            cx    = PL + i * col_w + col_w / 2
            bw    = col_w * 0.68

            col = (COLORS["accent_yellow"] if ch == my_ch else
                   COLORS["accent_red"]    if ratio > 0.7  else
                   "#ff8c00"               if ratio > 0.35 else
                   COLORS["accent_blue"])

            bar_h = max(3, ratio * chart_h * 0.93)
            y_top = baseline - bar_h

            c.create_rectangle(cx - bw/2 - 2, y_top - 1,
                               cx + bw/2 + 2, baseline,
                               fill=self._dim(col, 0.13), outline="")
            c.create_rectangle(cx - bw/2, y_top,
                               cx + bw/2, baseline,
                               fill=col, outline="")

            if cnt > 0 and bar_h >= 16:
                c.create_text(cx, y_top + bar_h * 0.5,
                              text=str(cnt),
                              fill=COLORS["bg_primary"],
                              font=("Consolas", 8, "bold"))
            if ch == my_ch:
                c.create_text(cx, y_top - 2,
                              text="▲ ТИ",
                              fill=COLORS["accent_yellow"],
                              font=("Consolas", 7, "bold"), anchor="s")

            c.create_text(cx, H - 10, text=str(ch),
                          fill=(COLORS["accent_yellow"] if ch == my_ch
                                else COLORS["text_secondary"]),
                          font=("Consolas", 7))

        c.create_line(PL, baseline, W - PR, baseline,
                      fill=COLORS["border"], width=1)
        c.create_text(PL + 2, 9, text="5 GHz · Завантаженість каналів",
                      fill=COLORS["text_dim"],
                      font=("Consolas", 7), anchor="w")

    # ══════════════════════════════════════════════════════
    # TABLE
    # ══════════════════════════════════════════════════════

    def _build_net_table(self, networks: list[WifiNetwork]):
        for w in self.net_list.winfo_children():
            w.destroy()

        sorted_nets = sorted(networks, key=lambda n: (not n.is_mine, -n.signal))
        col_i = 0

        for i, net in enumerate(sorted_nets[:60]):
            bg  = COLORS.get("bg_card", "#111827") if i % 2 == 0 else "transparent"
            row = ctk.CTkFrame(self.net_list, fg_color=bg, corner_radius=6)
            row.grid(row=i, column=0, sticky="ew", pady=1)

            is_open = "open" in net.auth.lower()

            if net.is_mine:
                name_col = COLORS["accent_yellow"]
                prefix   = "★ "
            else:
                prefix   = "  "
                name_col = NEON_PALETTE[col_i % len(NEON_PALETTE)]
                col_i   += 1

            sig_col  = (COLORS["accent_green"]  if net.signal > 60 else
                        COLORS["accent_yellow"] if net.signal > 30 else
                        COLORS["accent_red"])
            auth_col = COLORS["accent_red"] if is_open else COLORS["text_secondary"]
            band_col = (COLORS["accent_purple"] if net.band == "5 GHz"
                        else COLORS["accent_cyan"])
            sig_bar  = self._sigbar(net.signal)

            data = [
                (prefix + net.ssid[:22],              190, name_col,               "w"),
                ((net.bssid or "—")[:17],              150, COLORS["text_dim"],     "w"),
                (net.band,                              60,  band_col,              "w"),
                (str(net.channel),                      40,  COLORS["accent_purple"],"w"),
                (f"{net.signal}% {sig_bar}",            80,  sig_col,               "w"),
                ((("⚠ " if is_open else "") + net.auth)[:14], 110, auth_col,        "w"),
                ((net.radio_type or "—")[:12],          90,  COLORS["text_secondary"],"w"),
                ((net.max_rate or "—"),                 90,  COLORS["text_dim"],    "w"),
                ((net.vendor or "—")[:13],             100,  COLORS["text_secondary"],"w"),
            ]

            for ci, (txt, w, col, anch) in enumerate(data):
                ctk.CTkLabel(row, text=txt, width=w,
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=col, anchor=anch).grid(
                    row=0, column=ci, padx=4, pady=4, sticky="w")

    # ══════════════════════════════════════════════════════
    # HELPERS
    # ══════════════════════════════════════════════════════

    def _open_router(self):
        gw  = (self.get_gateway_cb()
               if self.get_gateway_cb else self.engine.get_gateway_ip())
        url = f"http://{gw}/"
        webbrowser.open(url)

    @staticmethod
    def _placeholder(canvas: tk.Canvas, text: str):
        canvas.delete("all")
        canvas.create_text(200, 40, text=text,
                           fill=COLORS["text_dim"],
                           font=("Consolas", 10), anchor="nw")

    @staticmethod
    def _sigbar(sig: int) -> str:
        f = round(max(0, min(100, sig)) / 20)
        return "▓" * f + "░" * (5 - f)

    @staticmethod
    def _dim(hex_color: str, factor: float) -> str:
        try:
            h = hex_color.lstrip("#")
            r = int(h[0:2], 16)
            g = int(h[2:4], 16)
            b = int(h[4:6], 16)
            return "#{:02x}{:02x}{:02x}".format(
                int(r * factor), int(g * factor), int(b * factor))
        except Exception:
            return hex_color
