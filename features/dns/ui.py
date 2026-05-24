# gui/pages/dns_ui.py
"""
NetGuardian AI — DNS Benchmark & Optimizer UI
• Parallel live results, comparison panel, DNS leak test
• Tooltip (pros/cons) on card hover  —  DnsTooltip class
• Full-page overlay animation during DNS switch  —  SwitchAnimationOverlay
• InfoPopup — ? кнопки з детальним поясненням кожної функції
"""

import threading
import tkinter as tk
import customtkinter as ctk
from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.dns.engine import DNSBenchmarker, DNS_SERVERS


# ══════════════════════════════════════════════════════════════
# HELPERS
# ══════════════════════════════════════════════════════════════
def _speed_color(ms):
    if ms is None: return COLORS.get("accent_red",    "#ff4444")
    if ms < 25:    return COLORS.get("accent_green",  "#00ff88")
    if ms < 60:    return COLORS.get("accent_yellow", "#ffd700")
    return               COLORS.get("accent_red",    "#ff4444")

def _reliability_color(pct):
    if pct >= 90: return COLORS.get("accent_green",  "#00ff88")
    if pct >= 60: return COLORS.get("accent_yellow", "#ffd700")
    return              COLORS.get("accent_red",    "#ff4444")

_PROS_CONS: dict = {
    entry[1]: (entry[7], entry[8]) for entry in DNS_SERVERS
}


# ══════════════════════════════════════════════════════════════
# INFO POPUP  —  вікно-довідка при натисканні ?
# ══════════════════════════════════════════════════════════════

# Контент для кожної кнопки-довідки
_INFO_CONTENT = {
    "benchmark": {
        "title":  "🔬  DNS Benchmark",
        "color":  "#00d4ff",
        "sections": [
            ("Що це?", [
                "DNS Benchmark вимірює реальну затримку (latency) кожного",
                "DNS-сервера шляхом надсилання справжніх DNS-запитів.",
                "Всі сервери тестуються паралельно — займає ~3-5 секунд.",
            ]),
            ("Що вимірюється?", [
                "avg ms  — середня затримка по 5 запитах",
                "p95 ms  — 95-й перцентиль (максимум у реальних умовах)",
                "jitter  — різниця між min та max (стабільність)",
                "reliability % — відсоток успішних відповідей",
            ]),
            ("Поради", [
                "< 25 ms  🟢 Відмінно — для ігор та стрімінгу",
                "25–60 ms 🟡 Добре — для звичайного використання",
                "> 60 ms  🔴 Погано — розгляньте заміну DNS",
            ]),
        ],
    },
    "auto": {
        "title":  "⚡  Авто-оптимізація",
        "color":  "#00ff88",
        "sections": [
            ("Що це?", [
                "Автоматично запускає Benchmark та застосовує",
                "найшвидший DNS одним натисканням.",
                "Потребує прав Адміністратора для зміни DNS.",
            ]),
            ("Як це працює?", [
                "1. Паралельний тест усіх 13 серверів",
                "2. Вибір сервера з найменшим avg ms",
                "3. Запис DNS через netsh з прапором validate=no",
                "4. Додавання вторинного DNS (резерв)",
                "5. Очищення DNS кешу (ipconfig /flushdns)",
            ]),
            ("Важливо", [
                "validate=no — гарантує збереження навіть якщо",
                "сервер не відповів під час перевірки Windows.",
                "Зміна набирає чинності миттєво без перезавантаження.",
            ]),
        ],
    },
    "flush": {
        "title":  "🗑️  Очищення DNS кешу",
        "color":  "#8888aa",
        "sections": [
            ("Що це?", [
                "Виконує команду ipconfig /flushdns — очищає",
                "локальний кеш DNS-записів Windows.",
            ]),
            ("Коли використовувати?", [
                "• Після зміни DNS-сервера",
                "• Якщо сайт показує стару IP-адресу",
                "• При помилках з'єднання після зміни DNS",
                "• Якщо сайт недоступний хоча DNS працює",
            ]),
            ("Що відбувається?", [
                "Windows зберігає IP-адреси сайтів у кеші.",
                "Очищення змушує систему заново запитувати",
                "IP для всіх сайтів через новий DNS-сервер.",
                "Безпечно — не впливає на налаштування мережі.",
            ]),
        ],
    },
    "leak": {
        "title":  "🔍  DNS Leak Test",
        "color":  "#ffd700",
        "sections": [
            ("Що таке DNS Leak?", [
                "DNS витік — ситуація коли ваш реальний провайдер (ISP)",
                "бачить які сайти ви відвідуєте, навіть якщо ви",
                "використовуєте VPN або змінили DNS.",
            ]),
            ("Як відбувається витік?", [
                "• VPN не перехоплює DNS-запити системи",
                "• Windows ігнорує VPN-DNS і йде через ISP",
                "• WebRTC відкриває реальний IP через браузер",
                "• Split tunneling залишає DNS поза тунелем",
            ]),
            ("Як тест перевіряє?", [
                "1. Генерує унікальні тестові домени",
                "2. Запитує bash.ws/dnsleak API",
                "3. Якщо відповідей > 1 резолвер — є витік",
                "✅ 1 резолвер = ваш обраний DNS",
                "⚠️ 2+ резолвери = витік через ISP",
            ]),
            ("Що робити при витоку?", [
                "• Увімкніть DNS over HTTPS (DoH) у браузері",
                "• Використайте Cloudflare 1.1.1.1 або AdGuard",
                "• Налаштуйте DNS leak protection у VPN клієнті",
            ]),
        ],
    },
}


class InfoPopup:
    """
    Модальне вікно-довідка для кнопок ?
    Викликати: InfoPopup.show(root, key)
    де key — один з ключів _INFO_CONTENT
    """

    _instance = None  # Тільки одне вікно одночасно

    @classmethod
    def show(cls, root, key: str):
        # Закриваємо попереднє вікно якщо є
        if cls._instance is not None:
            try:
                cls._instance.destroy()
            except Exception:
                pass

        content = _INFO_CONTENT.get(key)
        if not content:
            return

        win = ctk.CTkToplevel(root)
        cls._instance = win
        win.title(content["title"])
        win.resizable(False, False)
        win.attributes("-topmost", True)
        win.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))
        win.grab_set()  # Модальне

        accent  = content["color"]
        bg_card = COLORS.get("bg_card", "#1a1a2e")
        brd     = COLORS.get("border", "#2a2a4a")
        dim     = COLORS.get("text_dim", "#444466")
        sec     = COLORS.get("text_secondary", "#8888aa")
        pri     = COLORS.get("text_primary", "#e0e0ff")

        outer = ctk.CTkFrame(win, fg_color=COLORS.get("bg_secondary", "#0d0d1a"),
                             border_color=accent, border_width=2, corner_radius=14)
        outer.pack(fill="both", expand=True, padx=2, pady=2)

        # ── Заголовок ──────────────────────────
        hdr = ctk.CTkFrame(outer, fg_color=bg_card, corner_radius=10)
        hdr.pack(fill="x", padx=14, pady=(14, 10))
        ctk.CTkLabel(
            hdr, text=content["title"],
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=accent
        ).pack(side="left", padx=14, pady=10)

        # ── Секції ─────────────────────────────
        for sec_title, lines in content["sections"]:
            sf = ctk.CTkFrame(outer, fg_color=bg_card, corner_radius=8)
            sf.pack(fill="x", padx=14, pady=4)

            ctk.CTkLabel(
                sf, text=f"  {sec_title}",
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=accent
            ).pack(anchor="w", padx=10, pady=(8, 2))

            ctk.CTkFrame(sf, fg_color=brd, height=1).pack(fill="x", padx=10, pady=(0, 6))

            for line in lines:
                ctk.CTkLabel(
                    sf, text=f"  {line}",
                    font=ctk.CTkFont(family="Consolas", size=10),
                    text_color=pri if not line.startswith(("•", "✅", "⚠️", "<", ">")) else sec,
                    anchor="w", justify="left"
                ).pack(anchor="w", padx=10, pady=1)
            ctk.CTkLabel(sf, text="").pack(pady=(0, 2))

        # ── Кнопка закрити ─────────────────────
        ctk.CTkButton(
            outer, text="✕   ЗАКРИТИ",
            fg_color="transparent", hover_color=bg_card,
            text_color=accent, border_width=1, border_color=accent,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=38, corner_radius=10,
            command=win.destroy
        ).pack(pady=(8, 14), padx=14, fill="x")

        # Центруємо відносно root
        win.update_idletasks()
        rw, rh = root.winfo_width(), root.winfo_height()
        rx, ry = root.winfo_rootx(), root.winfo_rooty()
        ww, wh = win.winfo_reqwidth(), win.winfo_reqheight()
        x = rx + (rw - ww) // 2
        y = ry + (rh - wh) // 2
        win.geometry(f"+{x}+{y}")
        win.protocol("WM_DELETE_WINDOW", win.destroy)


# ══════════════════════════════════════════════════════════════
# TOOLTIP
# ══════════════════════════════════════════════════════════════
class DnsTooltip:
    _SHOW_DELAY = 480
    _FADE_STEPS = 10
    _FADE_MS    = 15

    def __init__(self, root):
        self._root     = root
        self._win      = None
        self._after_id = None
        self._fade_job = None

    def attach(self, widget, ip: str, name: str):
        widget.bind("<Enter>",  lambda e: self._schedule(e, ip, name), add="+")
        widget.bind("<Leave>",  lambda e: self._hide(),                 add="+")
        widget.bind("<Motion>", lambda e: self._move(e),                add="+")

    def _schedule(self, event, ip, name):
        self._hide()
        self._after_id = self._root.after(
            self._SHOW_DELAY, lambda: self._show(event, ip, name)
        )

    def _show(self, event, ip, name):
        pros, cons = _PROS_CONS.get(ip, ([], []))
        if not pros and not cons:
            return
        self._destroy_win()

        win = ctk.CTkToplevel(self._root)
        win.overrideredirect(True)
        win.attributes("-topmost", True)
        win.attributes("-alpha", 0.0)
        win.configure(fg_color=COLORS.get("bg_secondary", "#0d0d1a"))

        outer = ctk.CTkFrame(
            win,
            fg_color=COLORS.get("bg_secondary", "#0d0d1a"),
            border_color=COLORS.get("border_accent", "#0a2d6e"),
            border_width=1, corner_radius=12
        )
        outer.pack(fill="both", expand=True, padx=1, pady=1)

        hdr = ctk.CTkFrame(outer, fg_color=COLORS.get("bg_card","#1a1a2e"), corner_radius=8)
        hdr.pack(fill="x", padx=10, pady=(10, 8))
        ctk.CTkLabel(
            hdr, text=f"  {name}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#00d4ff")
        ).pack(side="left", padx=8, pady=(6,6))
        ctk.CTkLabel(
            hdr, text=ip,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_dim", "#444466")
        ).pack(side="left", padx=(0, 8), pady=(6, 6))

        if pros:
            ctk.CTkLabel(
                outer, text="  ✦ ПЕРЕВАГИ",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=COLORS.get("accent_green", "#00ff88")
            ).pack(anchor="w", padx=12, pady=(2, 0))
            for p in pros:
                row = ctk.CTkFrame(outer, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=1)
                ctk.CTkLabel(row, text="✓",
                             font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                             text_color=COLORS.get("accent_green","#00ff88"), width=16).pack(side="left")
                ctk.CTkLabel(row, text=p,
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=COLORS.get("text_primary","#e0e0ff"), anchor="w").pack(side="left", padx=(4,0))

        if pros and cons:
            ctk.CTkFrame(outer, fg_color=COLORS.get("border","#2a2a4a"), height=1).pack(
                fill="x", padx=12, pady=7
            )

        if cons:
            ctk.CTkLabel(
                outer, text="  ✦ НЕДОЛІКИ",
                font=ctk.CTkFont(family="Consolas", size=9, weight="bold"),
                text_color=COLORS.get("accent_red", "#ff4444")
            ).pack(anchor="w", padx=12, pady=(0, 0))
            for c in cons:
                row = ctk.CTkFrame(outer, fg_color="transparent")
                row.pack(fill="x", padx=14, pady=1)
                ctk.CTkLabel(row, text="✗",
                             font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                             text_color=COLORS.get("accent_red","#ff4444"), width=16).pack(side="left")
                ctk.CTkLabel(row, text=c,
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=COLORS.get("text_secondary","#8888aa"), anchor="w").pack(side="left", padx=(4,0))

        ctk.CTkLabel(outer, text="").pack(pady=(4, 2))

        win.update_idletasks()
        tw = win.winfo_reqwidth()
        th = win.winfo_reqheight()
        sx, sy = event.x_root + 18, event.y_root + 12
        sw = self._root.winfo_screenwidth()
        sh = self._root.winfo_screenheight()
        if sx + tw > sw - 10: sx = event.x_root - tw - 10
        if sy + th > sh - 10: sy = event.y_root - th - 10
        win.geometry(f"+{sx}+{sy}")

        self._win = win
        self._fade_in(0)

    def _move(self, event):
        if self._win and self._win.winfo_exists():
            tw = self._win.winfo_width()
            th = self._win.winfo_height()
            sx, sy = event.x_root + 18, event.y_root + 12
            sw = self._root.winfo_screenwidth()
            sh = self._root.winfo_screenheight()
            if sx + tw > sw - 10: sx = event.x_root - tw - 10
            if sy + th > sh - 10: sy = event.y_root - th - 10
            self._win.geometry(f"+{sx}+{sy}")

    def _hide(self):
        if self._after_id:
            self._root.after_cancel(self._after_id)
            self._after_id = None
        if self._fade_job:
            self._root.after_cancel(self._fade_job)
            self._fade_job = None
        self._destroy_win()

    def _destroy_win(self):
        if self._win:
            try: self._win.destroy()
            except: pass
            self._win = None

    def _fade_in(self, step):
        if not self._win or not self._win.winfo_exists():
            return
        alpha = min(1.0, (step + 1) / self._FADE_STEPS)
        self._win.attributes("-alpha", alpha)
        if alpha < 1.0:
            self._fade_job = self._root.after(self._FADE_MS, lambda: self._fade_in(step + 1))


# ══════════════════════════════════════════════════════════════
# SWITCH ANIMATION OVERLAY
# ══════════════════════════════════════════════════════════════
class SwitchAnimationOverlay:
    _STEPS = [
        ("🔐", "Перевірка прав адміністратора"),
        ("🔍", "Визначення активного адаптера"),
        ("🔧", "Запис нового DNS через netsh"),
        ("💾", "Встановлення вторинного DNS"),
        ("🗑️", "Очищення DNS кешу"),
        ("🔄", "Перевірка нового з'єднання"),
    ]
    _STEP_MS = 460

    def __init__(self, parent):
        self._parent    = parent
        self._frame     = None
        self._step_lbls = []
        self._tick_lbls = []
        self._anim_job  = None
        self._spin_job  = None
        self._spinner   = None
        self._prog_bg   = None
        self._prog_fill = None

    def show(self, dns_name: str, dns_ip: str):
        self._destroy()

        yellow = COLORS.get("accent_yellow", "#ffd700")
        cyan   = COLORS.get("accent_cyan",   "#00d4ff")
        bg     = COLORS.get("bg_secondary",  "#0d0d1a")
        brd    = COLORS.get("border",        "#2a2a4a")

        self._frame = ctk.CTkFrame(
            self._parent, fg_color=bg, corner_radius=18, border_width=2, border_color=yellow
        )
        self._frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.72, relheight=0.88)
        self._frame.lift()
        self._frame.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            self._frame, text="⚡  ПЕРЕКЛЮЧЕННЯ DNS",
            font=ctk.CTkFont(family="Consolas", size=17, weight="bold"),
            text_color=yellow
        ).grid(row=0, column=0, pady=(30, 4))

        ctk.CTkLabel(
            self._frame, text=f"→  {dns_name}   ({dns_ip})",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=cyan
        ).grid(row=1, column=0, pady=(0, 18))

        ctk.CTkFrame(self._frame, fg_color=brd, height=1).grid(
            row=2, column=0, sticky="ew", padx=50, pady=(0, 20)
        )

        sf = ctk.CTkFrame(self._frame, fg_color="transparent")
        sf.grid(row=3, column=0, padx=60, sticky="ew")
        sf.grid_columnconfigure(1, weight=1)

        self._step_lbls = []
        self._tick_lbls = []
        dim = COLORS.get("text_dim", "#444466")

        for i, (icon, text) in enumerate(self._STEPS):
            if i > 0:
                ctk.CTkFrame(sf, fg_color=dim, width=2, height=16).grid(
                    row=i*2 - 1, column=0, padx=(16, 0))

            icon_lbl = ctk.CTkLabel(sf, text=icon, font=ctk.CTkFont(size=17),
                                    text_color=dim, width=36)
            icon_lbl.grid(row=i*2, column=0, padx=(0, 14), pady=3, sticky="w")

            step_lbl = ctk.CTkLabel(sf, text=text,
                                    font=ctk.CTkFont(family="Consolas", size=11),
                                    text_color=dim, anchor="w")
            step_lbl.grid(row=i*2, column=1, pady=3, sticky="w")

            tick = ctk.CTkLabel(sf, text="",
                                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                                text_color=COLORS.get("accent_green", "#00ff88"), width=22)
            tick.grid(row=i*2, column=2, sticky="e")

            self._step_lbls.append((icon_lbl, step_lbl))
            self._tick_lbls.append(tick)

        self._spinner = ctk.CTkLabel(
            self._frame, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=yellow
        )
        self._spinner.grid(row=4, column=0, pady=(22, 0))

        self._prog_bg = ctk.CTkFrame(
            self._frame, fg_color=COLORS.get("bg_card","#1a1a2e"),
            height=10, corner_radius=5
        )
        self._prog_bg.grid(row=5, column=0, padx=60, pady=(12, 30), sticky="ew")
        self._prog_bg.grid_propagate(False)

        self._prog_fill = ctk.CTkFrame(
            self._prog_bg, fg_color=yellow, height=10, corner_radius=5, width=6
        )
        self._prog_fill.place(x=0, y=0, relheight=1)

        self._animate_step(0)
        self._animate_spinner(0)

    def _animate_step(self, step: int):
        if self._frame is None: return
        yellow = COLORS.get("accent_yellow", "#ffd700")
        green  = COLORS.get("accent_green",  "#00ff88")
        total  = len(self._STEPS)

        if step > 0:
            il, sl = self._step_lbls[step-1]
            il.configure(text_color=green)
            sl.configure(text_color=green)
            self._tick_lbls[step-1].configure(text="✓")

        if step < total:
            il, sl = self._step_lbls[step]
            il.configure(text_color=yellow)
            sl.configure(text_color=yellow)
            self._tick_lbls[step].configure(text="›", text_color=yellow)

            try:
                pct   = step / total
                bar_w = max(6, int(self._prog_bg.winfo_width() * pct))
                self._prog_fill.configure(width=bar_w)
            except Exception:
                pass

            self._anim_job = self._frame.after(
                self._STEP_MS, lambda: self._animate_step(step + 1)
            )

    _SPIN_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"]

    def _animate_spinner(self, tick: int):
        if self._frame is None or self._spinner is None: return
        try:
            self._spinner.configure(
                text=f"{self._SPIN_FRAMES[tick % len(self._SPIN_FRAMES)]}  виконую операції…"
            )
        except Exception:
            return
        self._spin_job = self._frame.after(75, lambda: self._animate_spinner(tick + 1))

    def finish(self, ok: bool, meta: dict, dns_name: str):
        if self._frame is None: return

        for job in (self._anim_job, self._spin_job):
            if job:
                try: self._frame.after_cancel(job)
                except: pass

        green = COLORS.get("accent_green", "#00ff88")

        if ok:
            for i, (il, sl) in enumerate(self._step_lbls):
                il.configure(text_color=green)
                sl.configure(text_color=green)
                self._tick_lbls[i].configure(text="✓", text_color=green)
            try:
                self._prog_fill.configure(width=self._prog_bg.winfo_width(), fg_color=green)
            except: pass

        self._frame.after(350, lambda: self._show_result(ok, meta, dns_name))

    def _show_result(self, ok: bool, meta: dict, dns_name: str):
        if self._frame is None: return
        for w in self._frame.winfo_children():
            w.destroy()

        self._frame.grid_columnconfigure(0, weight=1)
        green = COLORS.get("accent_green",  "#00ff88")
        red   = COLORS.get("accent_red",    "#ff4444")
        sec   = COLORS.get("text_secondary","#8888aa")
        col   = green if ok else red

        self._frame.configure(border_color=col)

        ctk.CTkLabel(
            self._frame, text="✓" if ok else "✗",
            font=ctk.CTkFont(family="Consolas", size=72, weight="bold"),
            text_color=col
        ).grid(row=0, column=0, pady=(44, 6))

        ctk.CTkLabel(
            self._frame,
            text="DNS УСПІШНО ПЕРЕКЛЮЧЕНО" if ok else "ПОМИЛКА ПЕРЕКЛЮЧЕННЯ",
            font=ctk.CTkFont(family="Consolas", size=19, weight="bold"),
            text_color=col
        ).grid(row=1, column=0, pady=(0, 8))

        if ok:
            old_ip = meta.get("old_dns") or "—"
            new_ip = meta.get("new_dns", "?")
            iface  = meta.get("iface",  "?")

            ctk.CTkLabel(
                self._frame, text=f"{old_ip}  →  {new_ip}",
                font=ctk.CTkFont(family="Consolas", size=14),
                text_color=COLORS.get("text_primary","#e0e0ff")
            ).grid(row=2, column=0, pady=(0, 4))

            ctk.CTkLabel(
                self._frame,
                text=f"{dns_name}  ·  Адаптер: {iface}  ·  Кеш очищено",
                font=ctk.CTkFont(family="Consolas", size=10),
                text_color=sec
            ).grid(row=3, column=0, pady=(0, 36))
        else:
            ctk.CTkLabel(
                self._frame,
                text="Запустіть програму від імені Адміністратора",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=sec
            ).grid(row=2, column=0, pady=(0, 36))

        ctk.CTkButton(
            self._frame, text="✕   ЗАКРИТИ",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=col, border_width=1, border_color=col,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=40, corner_radius=10,
            command=self._destroy
        ).grid(row=4, column=0, pady=(0, 32))

    def _destroy(self):
        for job in (self._anim_job, self._spin_job):
            if job:
                try: self._frame.after_cancel(job)
                except: pass
        if self._frame:
            try: self._frame.destroy()
            except: pass
            self._frame = None
        self._step_lbls.clear()
        self._tick_lbls.clear()


# ══════════════════════════════════════════════════════════════
# MAIN PAGE
# ══════════════════════════════════════════════════════════════
class DnsBenchmarkPage(ctk.CTkFrame):

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.engine   = DNSBenchmarker()
        self._results: list = []
        self._live_cards: dict = {}
        self._running  = False
        self._last_known_dns = None

        root = self._get_root(parent)
        self._app_root    = root
        self._tooltip     = DnsTooltip(root)
        self._switch_anim = SwitchAnimationOverlay(self)

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)
        self._build_toolbar()
        self._build_info_bar()
        self._build_results_area()
        # State для поточного DNS — поллер це читає
        self._dns_state: dict = {}
        self.after(200, self._refresh_current_dns)
        # Поллер у main thread — оновлює UI з _dns_state
        self.after(500, self._sync_dns_ui_from_state)
        # Періодичний refresh кожні 30 секунд
        self.after(30000, self._periodic_dns_refresh)

    def _periodic_dns_refresh(self):
        """Періодично перевіряє DNS — раз на 30с."""
        try:
            self._refresh_current_dns()
        except Exception: pass
        try:
            self.after(30000, self._periodic_dns_refresh)
        except Exception: pass

    def _safe_after(self, delay_ms: int, callback):
        """Безпечний after — не падає при destroyed root (Python 3.14)."""
        try:
            return self.after(delay_ms, callback)
        except (RuntimeError, tk.TclError):
            return None
        except Exception:
            return None
        self.after(8000, self._auto_poll_dns)

    @staticmethod
    def _get_root(widget):
        w = widget
        while w.master:
            w = w.master
        return w

    # ──────────────────────────────────
    # TOOLBAR  +  кнопки ?
    # ──────────────────────────────────
    def _build_toolbar(self):
        tb = ctk.CTkFrame(self, fg_color="transparent")
        tb.grid(row=0, column=0, padx=24, pady=(20, 6), sticky="ew")

        btn_cfg = dict(font=ctk.CTkFont(family="Consolas", size=11, weight="bold"), height=40, corner_radius=10)
        q_cfg   = dict(font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                       height=40, width=40, corner_radius=10,
                       fg_color=COLORS.get("bg_card","#1a1a2e"),
                       hover_color=COLORS.get("bg_secondary","#0d0d1a"),
                       text_color=COLORS.get("text_dim","#444466"),
                       border_width=1, border_color=COLORS.get("border","#2a2a4a"))

        col = 0

        # ── BENCHMARK ────────────────────────────────────────
        self.btn_bench = ctk.CTkButton(
            tb, text="🔬  BENCHMARK",
            fg_color=COLORS.get("border_accent","#0a2d6e"), hover_color="#0d3d8a",
            text_color=COLORS.get("accent_cyan","#00d4ff"),
            command=self._start_benchmark, **btn_cfg
        )
        self.btn_bench.grid(row=0, column=col, padx=(0, 2))
        col += 1

        ctk.CTkButton(
            tb, text="?", command=lambda: InfoPopup.show(self._app_root, "benchmark"), **q_cfg
        ).grid(row=0, column=col, padx=(0, 10))
        col += 1

        # ── АВТО-ОПТИМІЗАЦІЯ ─────────────────────────────────
        self.btn_auto = ctk.CTkButton(
            tb, text="⚡  АВТО-ОПТИМІЗАЦІЯ",
            fg_color="#003a00", hover_color="#005200",
            text_color=COLORS.get("accent_green","#00ff88"),
            border_width=1, border_color=COLORS.get("accent_green","#00ff88"),
            command=self._auto_optimize, **btn_cfg
        )
        self.btn_auto.grid(row=0, column=col, padx=(0, 2))
        col += 1

        ctk.CTkButton(
            tb, text="?", command=lambda: InfoPopup.show(self._app_root, "auto"), **q_cfg
        ).grid(row=0, column=col, padx=(0, 10))
        col += 1

        # ── FLUSH DNS ─────────────────────────────────────────
        self.btn_flush = ctk.CTkButton(
            tb, text="🗑️  Очистити DNS кеш",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=COLORS.get("text_secondary","#8888aa"),
            border_width=1, border_color=COLORS.get("border","#2a2a4a"),
            command=self._flush_dns, **btn_cfg
        )
        self.btn_flush.grid(row=0, column=col, padx=(0, 2))
        col += 1

        ctk.CTkButton(
            tb, text="?", command=lambda: InfoPopup.show(self._app_root, "flush"), **q_cfg
        ).grid(row=0, column=col, padx=(0, 10))
        col += 1

        # ── DNS LEAK TEST ─────────────────────────────────────
        self.btn_leak = ctk.CTkButton(
            tb, text="🔍  DNS Leak Test",
            fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
            text_color=COLORS.get("accent_yellow","#ffd700"),
            border_width=1, border_color=COLORS.get("accent_yellow","#ffd700"),
            command=self._dns_leak_test, **btn_cfg
        )
        self.btn_leak.grid(row=0, column=col, padx=(0, 2))
        col += 1

        ctk.CTkButton(
            tb, text="?", command=lambda: InfoPopup.show(self._app_root, "leak"), **q_cfg
        ).grid(row=0, column=col, padx=(0, 0))

    # ──────────────────────────────────
    # INFO BAR
    # ──────────────────────────────────
    def _build_info_bar(self):
        bar = ctk.CTkFrame(self, fg_color=COLORS.get("bg_secondary","#0d0d1a"), corner_radius=8)
        bar.grid(row=1, column=0, padx=24, pady=(0,10), sticky="ew")
        bar.grid_columnconfigure(3, weight=1)

        cur_f = ctk.CTkFrame(bar, fg_color=COLORS.get("bg_card","#1a1a2e"), corner_radius=6)
        cur_f.grid(row=0, column=0, padx=(10,0), pady=7, ipady=2)

        ctk.CTkLabel(cur_f, text="ВАШ ПОТОЧНИЙ DNS",
                     font=ctk.CTkFont(family="Consolas", size=8, weight="bold"),
                     text_color=COLORS.get("text_dim","#444466")).grid(
            row=0, column=0, columnspan=2, padx=10, pady=(5,0), sticky="w")

        self.current_dns_lbl = ctk.CTkLabel(
            cur_f, text="…",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS.get("accent_cyan","#00d4ff"), width=130
        )
        self.current_dns_lbl.grid(row=1, column=0, padx=(10,6), pady=(0,5), sticky="w")

        self.current_dns_meta = ctk.CTkLabel(
            cur_f, text="",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS.get("text_secondary","#8888aa")
        )
        self.current_dns_meta.grid(row=1, column=1, padx=(0,10), pady=(0,5), sticky="w")

        ctk.CTkFrame(bar, fg_color=COLORS.get("border","#2a2a4a"), width=1).grid(
            row=0, column=1, padx=12, pady=8, sticky="ns"
        )

        self.status_icon = ctk.CTkLabel(
            bar, text="●", width=16,
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS.get("text_dim","#444466")
        )
        self.status_icon.grid(row=0, column=2, padx=(0,4), pady=8)

        self.status_lbl = ctk.CTkLabel(
            bar, text="Натисни BENCHMARK для початку",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_secondary","#8888aa"), anchor="w"
        )
        self.status_lbl.grid(row=0, column=3, pady=8, sticky="ew")

        self.admin_lbl = ctk.CTkLabel(
            bar,
            text="🔓 Без прав Адмін" if not self.engine.is_admin() else "🔒 Адмін",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("accent_yellow","#ffd700") if not self.engine.is_admin()
                       else COLORS.get("accent_green","#00ff88")
        )
        self.admin_lbl.grid(row=0, column=4, padx=12, pady=8)

    def _refresh_current_dns(self):
        """Шукає поточний DNS і пише результат у self._dns_state.
        Поллер _sync_dns_ui_from_state підхопить це з main thread."""
        def _work():
            try:
                ip, _ = self.engine.get_current_dns()
                if ip:
                    known = next((e for e in DNS_SERVERS if e[1] == ip), None)
                    name  = known[0] if known else "Невідомий"
                    from features.dns.engine import _query_dns
                    ms = _query_dns(ip, "google.com")
                    print(f"[DNS] state update: ip={ip}, name={name}, ms={ms}")
                    # Записуємо у state — поллер прочитає з main thread
                    self._dns_state = {
                        "ip": ip, "name": name, "ms": ms, "found": True
                    }
                else:
                    print("[DNS] state update: not found")
                    self._dns_state = {"found": False}
                # Спроба прямого виклику (запас)
                self._safe_after(0, lambda: self._update_current_dns(ip, None, None) if ip else None)
            except Exception as e:
                print(f"[DNS] _refresh_current_dns error: {e}")
        threading.Thread(target=_work, daemon=True).start()

    def _sync_dns_ui_from_state(self):
        """Поллер у main thread — оновлює UI з self._dns_state."""
        try:
            state = getattr(self, "_dns_state", None)
            if state:
                if state.get("found"):
                    ip   = state.get("ip", "")
                    name = state.get("name", "")
                    ms   = state.get("ms")
                    if ip:
                        try: self.current_dns_lbl.configure(text=ip)
                        except Exception: pass
                        if ms is not None:
                            col = _speed_color(ms)
                            try: self.current_dns_meta.configure(
                                text=f"{name}  ·  {ms:.0f} ms", text_color=col)
                            except Exception: pass
                        else:
                            try: self.current_dns_meta.configure(
                                text=f"{name}  ·  timeout",
                                text_color=COLORS.get("accent_red", "#ff4444"))
                            except Exception: pass
                else:
                    try: self.current_dns_lbl.configure(text="Не визначено")
                    except Exception: pass
        except Exception as e:
            print(f"[DNS] _sync_dns_ui_from_state error: {e}")
        # Перепланування
        try:
            self.after(2000, self._sync_dns_ui_from_state)
        except Exception: pass

    def _update_current_dns(self, ip, name, ms):
        self.current_dns_lbl.configure(text=ip)
        if ms is not None:
            col = _speed_color(ms)
            self.current_dns_meta.configure(text=f"{name}  ·  {ms:.0f} ms", text_color=col)
        else:
            self.current_dns_meta.configure(
                text=f"{name}  ·  timeout",
                text_color=COLORS.get("accent_red","#ff4444")
            )

    def _auto_poll_dns(self):
        """
        Автоматично перевіряє поточний DNS кожні 8 секунд.
        Якщо DNS змінився (наприклад через Telegram бот) — оновлює відображення
        і показує сповіщення у статус-рядку без перезапуску програми.
        """
        def _work():
            try:
                ip, _ = self.engine.get_current_dns()
                if ip and ip != self._last_known_dns:
                    known = next((e for e in DNS_SERVERS if e[1] == ip), None)
                    name  = known[0] if known else "Невідомий"
                    from features.dns.engine import _query_dns
                    ms = _query_dns(ip, "google.com")

                    def _apply():
                        self._last_known_dns = ip
                        self._update_current_dns(ip, name, ms)
                        # Якщо це зовнішня зміна (не поточний benchmark) — показуємо підказку
                        if not self._running:
                            self._set_status(
                                f"🔄  DNS оновлено: {ip}  ({name})",
                                COLORS.get("accent_cyan", "#00d4ff")
                            )
                    self.after(0, _apply)
            except Exception:
                pass

        threading.Thread(target=_work, daemon=True).start()
        # Плануємо наступне опитування через 8 секунд
        self.after(8000, self._auto_poll_dns)

    # ──────────────────────────────────
    # RESULTS AREA
    # ──────────────────────────────────
    def _build_results_area(self):
        self.results_frame = ctk.CTkScrollableFrame(self, fg_color="transparent", corner_radius=0)
        self.results_frame.grid(row=2, column=0, padx=24, pady=(0,24), sticky="nsew")
        self.results_frame.grid_columnconfigure(0, weight=1)
        self._draw_placeholder()

    def _draw_placeholder(self):
        self._clear_results()
        ph = GlowCard(self.results_frame)
        ph.grid(row=0, column=0, sticky="ew", pady=10)
        ctk.CTkLabel(
            ph,
            text=(
                "\n🔬  Benchmark тестує реальну DNS Query Latency\n\n"
                "  Всі сервери тестуються паралельно — займе ~3-5 секунд\n"
                "  💡  Наведи курсор на картку щоб побачити плюси та мінуси ↗\n"
                "  ❓  Натискай ? поруч з кнопками для детальної довідки\n\n"
                "  Категорії: ⚡ Ігрові · 🛡️ Безпечні · 🔒 AdBlock · 👨\u200d👩\u200d👧 Сімейні\n"
            ),
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS.get("text_secondary","#8888aa"),
            justify="left"
        ).pack(padx=30, pady=20, anchor="w")

    def _clear_results(self):
        for w in self.results_frame.winfo_children():
            w.destroy()
        self._live_cards.clear()

    # ──────────────────────────────────────────────
    # BENCHMARK
    # ──────────────────────────────────────────────
    def _start_benchmark(self):
        if self._running: return
        self._running = True
        self._results.clear()
        self._set_buttons_state("disabled")
        self._clear_results()
        self._draw_live_skeleton()
        self._set_status("⏳  Паралельний benchmark…", COLORS.get("accent_yellow","#ffd700"))
        threading.Thread(target=self._bench_thread, daemon=True).start()

    def _bench_thread(self):
        results = self.engine.run_benchmark(
            progress_cb=lambda txt: self.after(0, lambda t=txt: self._set_status(t)),
            live_result_cb=lambda r: self.after(0, lambda res=r: self._on_live_result(res)),
        )
        self._safe_after(0, lambda: self._on_bench_done(results))

    def _on_live_result(self, result):
        ip = result["ip"]
        if ip not in self._live_cards: return
        wg  = self._live_cards[ip]
        ms  = result.get("avg_ms")
        col = _speed_color(ms)

        if ms is not None:
            wg["ms_lbl"].configure(text=f"{ms:.1f} ms", text_color=col)
            wg["status_lbl"].configure(
                text=f"avg {ms:.1f} ms  ·  p95 {result.get('p95_ms', ms):.0f} ms  ·  {result['reliability']}% ok",
                text_color=col
            )
        else:
            wg["ms_lbl"].configure(text="TIMEOUT", text_color=COLORS.get("accent_red","#ff4444"))
            wg["status_lbl"].configure(text="Сервер недоступний", text_color=COLORS.get("accent_red","#ff4444"))

        badges = ""
        if result.get("dnssec"):         badges += " DNSSEC"
        if result.get("security_badge"): badges += " 🛡"
        if badges:
            wg["badge_lbl"].configure(text=badges.strip(), text_color=COLORS.get("accent_cyan","#00d4ff"))

    def _on_bench_done(self, results):
        self._results = results
        self._running = False
        self._set_buttons_state("normal")
        self._render_final(results)
        def _cmp():
            cmp = self.engine.compare_with_current(results)
            if cmp: self.after(0, lambda: self._render_comparison(cmp))
        threading.Thread(target=_cmp, daemon=True).start()

    # ──────────────────────────────────────────────
    # LIVE SKELETON
    # ──────────────────────────────────────────────
    def _draw_live_skeleton(self):
        for idx, entry in enumerate(DNS_SERVERS):
            name, ip, _, cat, feat = entry[0], entry[1], entry[2], entry[3], entry[4]

            card = GlowCard(self.results_frame, accent=COLORS.get("border","#2a2a4a"))
            card.grid(row=idx, column=0, sticky="ew", pady=2)
            card.grid_columnconfigure(3, weight=1)

            for w in [card]:
                self._tooltip.attach(w, ip, name)

            rank_lbl = ctk.CTkLabel(
                card, text=f"#{idx+1}",
                font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
                text_color=COLORS.get("text_dim","#444466"), width=40
            )
            rank_lbl.grid(row=0, column=0, padx=(14,6), pady=14, rowspan=2)
            self._tooltip.attach(rank_lbl, ip, name)

            info_f = ctk.CTkFrame(card, fg_color="transparent")
            info_f.grid(row=0, column=1, padx=5, pady=(10,2), sticky="w", rowspan=2)
            self._tooltip.attach(info_f, ip, name)

            name_lbl = ctk.CTkLabel(
                info_f, text=name,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=COLORS.get("text_primary","#e0e0ff")
            )
            name_lbl.pack(anchor="w")
            self._tooltip.attach(name_lbl, ip, name)

            sub_lbl = ctk.CTkLabel(
                info_f, text=f"{ip}  ·  {feat}",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS.get("text_secondary","#8888aa")
            )
            sub_lbl.pack(anchor="w")
            self._tooltip.attach(sub_lbl, ip, name)

            badge_lbl = ctk.CTkLabel(info_f, text="",
                                     font=ctk.CTkFont(family="Consolas", size=9),
                                     text_color=COLORS.get("accent_cyan","#00d4ff"))
            badge_lbl.pack(anchor="w")

            ctk.CTkLabel(card, text=cat,
                         font=ctk.CTkFont(family="Consolas", size=9),
                         text_color=COLORS.get("text_dim","#444466")).grid(
                row=0, column=2, padx=10, pady=(14,2), sticky="w")

            ms_lbl = ctk.CTkLabel(
                card, text="…",
                font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
                text_color=COLORS.get("text_dim","#444466"), width=90, anchor="e"
            )
            ms_lbl.grid(row=0, column=3, padx=(0,10), pady=(14,2), sticky="e")
            self._tooltip.attach(ms_lbl, ip, name)

            bar_bg = ctk.CTkFrame(card, fg_color=COLORS.get("bg_secondary","#0d0d1a"), height=6, corner_radius=3)
            bar_bg.grid(row=1, column=2, columnspan=2, padx=10, pady=(0,4), sticky="ew")
            bar_bg.grid_propagate(False)

            bar_fill = ctk.CTkFrame(bar_bg, fg_color=COLORS.get("text_dim","#444466"),
                                    corner_radius=3, height=6, width=10)
            bar_fill.place(x=0, y=0, relheight=1)

            status_lbl = ctk.CTkLabel(
                card, text="тестую…",
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS.get("text_dim","#444466")
            )
            status_lbl.grid(row=2, column=1, columnspan=3, padx=10, pady=(0,8), sticky="w")

            apply_btn = ctk.CTkButton(
                card, text="⚡ Apply",
                fg_color="transparent", hover_color=COLORS.get("bg_card","#1a1a2e"),
                text_color=COLORS.get("accent_cyan","#00d4ff"),
                font=ctk.CTkFont(family="Consolas", size=10),
                height=28, corner_radius=8,
                border_width=1, border_color=COLORS.get("accent_cyan","#00d4ff"),
                width=70, state="disabled"
            )
            apply_btn.grid(row=0, column=4, rowspan=3, padx=(0,14), pady=10)

            self._live_cards[ip] = {
                "card": card, "ms_lbl": ms_lbl, "bar_fill": bar_fill,
                "status_lbl": status_lbl, "badge_lbl": badge_lbl,
                "apply_btn": apply_btn, "rank_lbl": rank_lbl,
            }

    # ──────────────────────────────────────────────
    # FINAL RENDER
    # ──────────────────────────────────────────────
    def _render_final(self, results):
        best    = next((r for r in results if r["avg_ms"] is not None), None)
        max_avg = max((r["avg_ms"] for r in results if r["avg_ms"]), default=100)

        if best:
            self._insert_winner_banner(best)
            self._set_status(
                f"✅ Найшвидший: {best['name']} ({best['ip']})  ·  {best['avg_ms']:.1f} ms",
                COLORS.get("accent_green","#00ff88")
            )

        for rank, r in enumerate(results):
            ip = r["ip"]
            if ip not in self._live_cards: continue
            wg  = self._live_cards[ip]
            ms  = r.get("avg_ms")
            col = _speed_color(ms)
            is_best = ms is not None and best and ms == best["avg_ms"]

            if is_best:
                try: wg["card"].configure(border_color=COLORS.get("accent_green","#00ff88"), border_width=2)
                except: pass

            rank_col = (COLORS.get("accent_green","#00ff88") if is_best else
                        COLORS.get("accent_yellow","#ffd700") if rank == 0 else
                        COLORS.get("text_dim","#444466"))
            wg["rank_lbl"].configure(text=f"#{rank+1}", text_color=rank_col)

            if ms is not None:
                bar_pct = max(0.05, 1.0 - ms / max(max_avg, 1))
                wg["bar_fill"].configure(fg_color=col, width=max(10, int(bar_pct * 220)))
                wg["ms_lbl"].configure(text=f"{ms:.1f} ms", text_color=col)
                wg["status_lbl"].configure(
                    text=f"avg {ms:.1f} ms  ·  p95 {(r.get('p95_ms') or ms):.0f} ms  ·  jitter {(r.get('jitter_ms') or 0):.1f} ms  ·  {r['reliability']}%",
                    text_color=_reliability_color(r["reliability"])
                )
                sec_ip = next((e[2] for e in DNS_SERVERS if e[1] == ip), "8.8.8.8")
                wg["apply_btn"].configure(
                    state="normal",
                    command=lambda i=ip, n=r["name"], s=sec_ip: self._apply_dns(i, s, n)
                )
            else:
                wg["ms_lbl"].configure(text="N/A", text_color=COLORS.get("accent_red","#ff4444"))
                wg["bar_fill"].configure(fg_color=COLORS.get("accent_red","#ff4444"), width=10)
                wg["status_lbl"].configure(text="Сервер недоступний — timeout",
                                           text_color=COLORS.get("accent_red","#ff4444"))

    def _insert_winner_banner(self, best):
        green = COLORS.get("accent_green","#00ff88")
        banner = GlowCard(self.results_frame, accent=green)
        banner.grid(row=0, column=0, sticky="ew", pady=(0,10))
        for wg in self._live_cards.values():
            info = wg["card"].grid_info()
            wg["card"].grid(row=int(info["row"]) + 1, column=0)
        banner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(banner, text="🏆", font=ctk.CTkFont(size=28), text_color=green).grid(
            row=0, column=0, padx=(20,10), pady=16, rowspan=2)
        info_f = ctk.CTkFrame(banner, fg_color="transparent")
        info_f.grid(row=0, column=1, pady=(14,4), sticky="w")
        ctk.CTkLabel(info_f, text=f"TOP PICK — {best['name']} ({best['ip']})",
                     font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                     text_color=green).pack(anchor="w")
        ctk.CTkLabel(info_f, text=f"{best['category']}  ·  {best['features']}",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS.get("text_secondary","#8888aa")).pack(anchor="w")
        ctk.CTkLabel(info_f, text=f"avg {best['avg_ms']:.1f} ms  ·  {best['reliability']}% reliable",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=green).pack(anchor="w", pady=(2,0))

        sec = next((e[2] for e in DNS_SERVERS if e[1] == best["ip"]), "8.8.8.8")
        ctk.CTkButton(
            banner, text="⚡  ЗАСТОСУВАТИ",
            fg_color="#003a00", hover_color="#005200", text_color=green,
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=40, corner_radius=10, border_width=1, border_color=green,
            command=lambda: self._apply_dns(best["ip"], sec, best["name"])
        ).grid(row=0, column=2, rowspan=2, padx=20, pady=16)

    def _render_comparison(self, cmp):
        panel = GlowCard(self.results_frame, accent=COLORS.get("accent_yellow","#ffd700"))
        panel.grid(row=1, column=0, sticky="ew", pady=(0,8))
        for wg in self._live_cards.values():
            info = wg["card"].grid_info()
            wg["card"].grid(row=int(info["row"]) + 1, column=0)
        panel.grid_columnconfigure(0, weight=1)

        # FIX: замість відсотків (які дають абсурдні числа типу "141% повільніший")
        # порівнюємо за абсолютною різницею у мс — це те що відчуває юзер.
        # Обидві DNS у межах 100ms — непомітно для людини.
        cur_ms  = cmp["current_ms"]
        best_ms = cmp["best_ms"]
        diff_ms = cur_ms - best_ms

        if diff_ms < 5:
            # Різниця мізерна — людина не відчує
            v  = f"≈  Твій DNS зіставний з {cmp['best_name']} (різниця {diff_ms:+.1f} ms)"
            vc = COLORS.get("accent_yellow","#ffd700")
        elif diff_ms < 20:
            # Невелика різниця — міняти не обов'язково
            v  = f"ℹ️  {cmp['best_name']} трохи швидший (на {diff_ms:.0f} ms) — зміна не обов'язкова"
            vc = COLORS.get("accent_cyan","#00d4ff")
        elif diff_ms < 50:
            # Відчутна різниця — варто подумати
            v  = f"⚠️  {cmp['best_name']} помітно швидший (на {diff_ms:.0f} ms)"
            vc = COLORS.get("accent_yellow","#ffd700")
        else:
            # Велика різниця — рекомендую змінити
            v  = f"🚨  {cmp['best_name']} СИЛЬНО швидший (на {diff_ms:.0f} ms) — варто змінити"
            vc = COLORS.get("accent_red","#ff4444")

        ctk.CTkLabel(panel, text=f"📊  ПОРІВНЯННЯ  ({cmp['current_ip']})",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS.get("text_secondary","#8888aa")).grid(row=0, column=0, padx=20, pady=(12,4), sticky="w")
        ctk.CTkLabel(panel, text=v,
                     font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                     text_color=vc).grid(row=1, column=0, padx=20, pady=(0,4), sticky="w")
        ctk.CTkLabel(panel, text=f"Твій DNS: {cur_ms:.1f} ms  ·  {cmp['best_name']}: {best_ms:.1f} ms",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS.get("text_secondary","#8888aa")).grid(row=2, column=0, padx=20, pady=(0,12), sticky="w")

    # ──────────────────────────────────────────────
    # AUTO-OPTIMIZE
    # ──────────────────────────────────────────────
    def _auto_optimize(self):
        if self._running: return
        self._running = True
        self._set_buttons_state("disabled")
        self._clear_results()
        self._draw_live_skeleton()
        self._set_status("⚡  Авто-оптимізація…", COLORS.get("accent_yellow","#ffd700"))

        def _done(ok, msg, results, best, meta=None):
            self._results = results
            self._running = False
            self._set_buttons_state("normal")
            self._render_final(results)
            if ok and meta:
                self._finish_switch_animation(ok, msg, meta, best["name"] if best else "?")
            else:
                self._set_status(msg, COLORS.get("accent_red","#ff4444"))

        self.engine.auto_optimize(
            progress_cb=lambda txt: self.after(0, lambda t=txt: self._set_status(t)),
            done_cb=lambda ok, msg, res, best, meta=None: self.after(0, lambda: _done(ok, msg, res, best, meta))
        )

    # ──────────────────────────────────────────────
    # FLUSH / LEAK
    # ──────────────────────────────────────────────
    def _flush_dns(self):
        self._set_status("🗑️  Очищую DNS кеш…", COLORS.get("accent_yellow","#ffd700"))
        def _work():
            ok = self.engine.flush_dns()
            msg = "✅ DNS кеш успішно очищено!" if ok else "❌ Помилка очищення кешу"
            col = COLORS.get("accent_green" if ok else "accent_red","#00ff88")
            self.after(0, lambda: self._set_status(msg, col))
        threading.Thread(target=_work, daemon=True).start()

    def _dns_leak_test(self):
        self._set_status("🔍  Перевіряю DNS Leak…", COLORS.get("accent_yellow","#ffd700"))
        self.btn_leak.configure(state="disabled")
        def _work():
            res = self.engine.dns_leak_test()
            self.after(0, lambda: self._show_leak_result(res))
        threading.Thread(target=_work, daemon=True).start()

    def _show_leak_result(self, res):
        self.btn_leak.configure(state="normal")
        col = COLORS.get("accent_red","#ff4444") if res["leaked"] else COLORS.get("accent_green","#00ff88")
        self._set_status(res["summary"], col)
        panel = GlowCard(self.results_frame, accent=COLORS.get("accent_red" if res["leaked"] else "accent_green","#00ff88"))
        panel.grid(row=0, column=0, sticky="ew", pady=(0,10))
        panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(panel, text="🔍  DNS LEAK TEST",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS.get("text_secondary","#8888aa")).grid(row=0, column=0, padx=20, pady=(12,4), sticky="w")
        ctk.CTkLabel(panel, text=res["summary"],
                     font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                     text_color=col).grid(row=1, column=0, padx=20, pady=(0,4), sticky="w")
        if res["resolvers"]:
            for i, r in enumerate(res["resolvers"]):
                ctk.CTkLabel(panel, text=f"  Resolver {i+1}: {r['ip']}  ·  {r['country']}  ·  {r['isp']}",
                             font=ctk.CTkFont(family="Consolas", size=10),
                             text_color=COLORS.get("text_secondary","#8888aa")).grid(
                    row=2+i, column=0, padx=20, pady=1, sticky="w")
        else:
            ctk.CTkLabel(panel, text="  Не вдалося визначити резолвери",
                         font=ctk.CTkFont(family="Consolas", size=10),
                         text_color=COLORS.get("text_dim","#444466")).grid(
                row=2, column=0, padx=20, pady=(0,12), sticky="w")
        ctk.CTkLabel(panel, text="").grid(row=99, column=0, pady=(0,8))

    # ══════════════════════════════════════════════
    # APPLY DNS
    # ══════════════════════════════════════════════
    def _apply_dns(self, dns_ip: str, secondary_ip: str, dns_name: str):
        self._set_buttons_state("disabled")
        self._set_status(f"⚡  Переключаю на {dns_name}…", COLORS.get("accent_yellow","#ffd700"))
        self._switch_anim.show(dns_name, dns_ip)

        def _work():
            ok, msg, meta = self.engine.apply_dns(dns_ip, secondary_ip)
            self.after(0, lambda: self._finish_switch_animation(ok, msg, meta, dns_name))
        threading.Thread(target=_work, daemon=True).start()

    def _finish_switch_animation(self, ok, msg, meta, dns_name):
        self._set_buttons_state("normal")
        col = COLORS.get("accent_green" if ok else "accent_red","#00ff88")
        self.status_icon.configure(text_color=col)
        self._set_status(f"{'✅' if ok else '❌'}  {('DNS переключено на ' + dns_name + '!') if ok else msg}", col)
        self._switch_anim.finish(ok, meta, dns_name)
        if ok:
            self.after(600, self._refresh_current_dns)

    # ──────────────────────────────────────────────
    # HELPERS
    # ──────────────────────────────────────────────
    def _set_status(self, text, color=None):
        if color is None: color = COLORS.get("text_secondary","#8888aa")
        self.status_lbl.configure(text=text, text_color=color)
        if "✅" in text:
            self.status_icon.configure(text_color=COLORS.get("accent_green","#00ff88"))
        elif "❌" in text or "⚠️" in text:
            self.status_icon.configure(text_color=COLORS.get("accent_red","#ff4444"))
        elif "⏳" in text or "⚡" in text:
            self.status_icon.configure(text_color=COLORS.get("accent_yellow","#ffd700"))
        else:
            self.status_icon.configure(text_color=COLORS.get("text_dim","#444466"))

    def _set_buttons_state(self, state):
        for btn in (self.btn_bench, self.btn_auto, self.btn_flush, self.btn_leak):
            try: btn.configure(state=state)
            except: pass