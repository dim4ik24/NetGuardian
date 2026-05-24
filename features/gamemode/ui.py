# gui/pages/gamemode_ui.py
# ─────────────────────────────────────────────────────────────────────────────
#  NetGuardian AI  ·  Game Latency Optimizer  ·  UI
#  Cyberpunk Dark Theme  ·  customtkinter
# ─────────────────────────────────────────────────────────────────────────────

import customtkinter as ctk
import tkinter as tk
import threading
import queue
import time
import random
import datetime

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.gamemode.engine import (
    GameBoosterEngine, GAMING_DNS, PING_TARGETS,
    DANGEROUS_TO_KILL, NET_PRIORITY_NAMES
)

# ─── Константи UI ─────────────────────────────────────────────────────────────

FONT_MONO    = ("Consolas", 13)
FONT_MONO_SM = ("Consolas", 12)
FONT_MONO_XS = ("Consolas", 11)
FONT_TITLE   = ("Consolas", 16, "bold")

GRAPH_POINTS = 40
GRAPH_H      = 120

# Windows Priority Class → назва (psutil.Process.nice() на Windows)
_NICE_TO_PRIORITY_UI = {
    64:    "Idle",
    16384: "BelowNormal",
    32:    "Normal",
    32768: "AboveNormal",
    128:   "High",
    256:   "Realtime",
    # Linux fallback
    19: "Idle", 10: "BelowNormal", 0: "Normal",
    -5: "AboveNormal", -10: "High", -20: "Realtime",
}

# ─── Мережеві пріоритети — відображення ──────────────────────────────────────

NET_PRIORITY_LABELS = {
    "maximum": "🔴 MAX",
    "high":    "🟠 HIGH",
    "normal":  "🟢 NRM",
    "low":     "⚫ LOW",
    None:      "——",
}

NET_PRIORITY_COLORS = {
    "maximum": "#ef4444",
    "high":    "#f97316",
    "normal":  "#22c55e",
    "low":     "#64748b",
    None:      "#334155",
}

NET_PRIORITY_TOOLTIPS = {
    "maximum": (
        "🔴 МАКСИМАЛЬНИЙ (DSCP 46 — EF)\n\n"
        "Expedited Forwarding — найвищий клас обслуговування.\n"
        "Роутер пропускає пакети цієї програми ПОЗАЧЕРГОВО.\n\n"
        "✅ Коли використовувати:\n"
        "  • CS2, Valorant, Dota2 — будь-яка онлайн-гра\n"
        "  • Відео-дзвінки (Discord, Zoom)\n\n"
        "📉 Ефект: пінг може впасти на 10-50 ms якщо\n"
        "хтось паралельно качає файли / дивиться YouTube."
    ),
    "high": (
        "🟠 ВИСОКИЙ (DSCP 34 — AF41)\n\n"
        "Affirmative Forwarding — другий по пріоритету клас.\n\n"
        "✅ Коли використовувати:\n"
        "  • Стрімінг (OBS, Streamlabs)\n"
        "  • Відео-конференції (Teams, Google Meet)\n"
        "  • Браузер під час важливої роботи"
    ),
    "normal": (
        "🟢 НОРМАЛЬНИЙ (без QoS)\n\n"
        "Стандартний Best Effort — без пріоритету.\n"
        "Знімає будь-яке QoS правило для цього процесу."
    ),
    "low": (
        "⚫ НИЗЬКИЙ (DSCP 8 — CS1)\n\n"
        "Background/Scavenger — найнижчий клас.\n"
        "Пакети цієї програми обслуговуються ОСТАННІМИ.\n\n"
        "✅ Коли використовувати:\n"
        "  • Торрент-клієнти під час гри\n"
        "  • Фонові оновлення / синхронізація хмари\n"
        "  • OneDrive, Dropbox під час гри"
    ),
}

# ─── Опис кожного Advanced Tweak для tooltip ─────────────────────────────────

TWEAK_TOOLTIPS = {
    "🔇  Disable Windows Update": {
        "title": "Disable Windows Update",
        "what":  "Зупиняє служби wuauserv, BITS та dosvc на час гри.",
        "why":   "Windows Update може в будь-який момент почати завантажувати оновлення "
                 "на сотні МБ, забираючи весь канал. Класична причина раптового зростання пінгу з 30 до 300 ms.",
        "risk":  "🟡 Низький — після вимкнення ігрового режиму Update відновлюється автоматично.",
        "gain":  "⬇ Пінг: до −50 ms у піковий момент завантаження.",
    },
    "🌐  DNS Fast-Switch → 1.1.1.1": {
        "title": "DNS Fast-Switch",
        "what":  "Перемикає DNS-сервер на обраний профіль (Cloudflare / Quad9 / Google).",
        "why":   "Стандартний DNS провайдера часто має RTT 80–150 ms. "
                 "Cloudflare 1.1.1.1 має середній RTT ~5 ms до EU дата-центрів.",
        "risk":  "🟢 Мінімальний — DNS відновлюється через DHCP при вимкненні.",
        "gain":  "⬇ Час з'єднання з сервером: −20–80 ms при першому підключенні.",
    },
    "⚡  TCP NoDelay (No-Nagle)": {
        "title": "Вимкнення алгоритму Нагла",
        "what":  "Встановлює TcpAckFrequency=1 та TCPNoDelay=1 у реєстрі для всіх адаптерів.",
        "why":   "Алгоритм Нагла буферизує маленькі TCP-пакети. В іграх кожен пакет "
                 "критичний — без буферизації пакети йдуть миттєво.",
        "risk":  "🟡 Низький — може незначно збільшити трафік.",
        "gain":  "⬇ Джиттер: −10–40 ms. Найпомітніше в CS2, Valorant.",
    },
    "🖥  High Performance Power": {
        "title": "Схема живлення: Максимальна продуктивність",
        "what":  "Активує план живлення 'High Performance' через powercfg.",
        "why":   "Balanced знижує частоту CPU у моменти простою. High Performance "
                 "тримає максимальну частоту постійно.",
        "risk":  "🟠 Помірний — збільшує нагрів на ~10–15%. Для ноутбуків — тільки від мережі.",
        "gain":  "⬆ FPS: +5–15% у CPU-залежних сценах.",
    },
    "🧠  CPU Core Unpark": {
        "title": "CPU Core Unparking",
        "what":  "Встановлює мінімальний стан процесора = 100% у схемі High Performance.",
        "why":   "Windows може 'паркувати' ядра CPU для економії. "
                 "Пробудження займає 0.5–2 мс — критично для tick rate 64–128.",
        "risk":  "🟠 Помірний — аналогічно до High Performance Power.",
        "gain":  "⬇ Latency spikes: менше різких стрибків FPS.",
    },
    "🗑  Flush DNS Cache": {
        "title": "Очищення DNS-кешу",
        "what":  "Виконує ipconfig /flushdns — видаляє всі кешовані DNS-записи.",
        "why":   "Старі записи можуть вести на застарілі IP-адреси ігрових серверів.",
        "risk":  "🟢 Відсутній — кеш відновлюється автоматично.",
        "gain":  "🔄 Усуває проблеми 'сервер недоступний' після патчів.",
    },
    "🎯  High Priority for Games": {
        "title": "Підвищення пріоритету ігор",
        "what":  "Шукає запущені ігрові процеси та встановлює їм Windows-пріоритет 'High'.",
        "why":   "High = гра отримує більше CPU-часу порівняно з фоновими процесами.",
        "risk":  "🟡 Низький — не впливає на стабільність системи.",
        "gain":  "⬆ FPS: +3–10% на слабших процесорах.",
    },
    "🧹  Clean RAM": {
        "title": "Очищення оперативної пам'яті",
        "what":  "EmptyWorkingSet для фонових процесів + очищення Standby List Windows.",
        "why":   "Фонові програми накопичують RAM навіть коли мінімізовані. "
                 "Очищення повертає 200–800 МБ вільної RAM для гри.",
        "risk":  "🟢 Мінімальний — процеси підвантажать дані назад при потребі.",
        "gain":  "⬆ Більше RAM для гри. ⬇ Мікрофрізи через swap.",
    },
}

# ─── Tooltips для Ping Boost tweaks (hover підказки) ─────────────────────────

PING_TWEAK_TOOLTIPS = {
    "⚡  Timer 0.5ms (ОС реагує швидше)": {
        "title": "Windows Timer Resolution 0.5 ms",
        "what":  "Викликає NtSetTimerResolution(5000) щоб підняти точність системного таймера з 15.6 ms до 0.5 ms.",
        "why":   "За замовчуванням Windows оновлює внутрішній годинник кожні 15.6 ms. "
                 "Це означає, що мережеві пакети обробляються квантами по 15 ms. "
                 "При 0.5 ms — кожен пакет обробляється практично миттєво.",
        "risk":  "🟡 Помірний — збільшує споживання CPU на ~1–3%. Скидається при вимкненні ігрового режиму.",
        "gain":  "⬇ Джиттер: −5–15 ms. Найпомітніше в CS2 та Valorant.",
    },
    "🔔  Interrupt Moderation → OFF": {
        "title": "Interrupt Moderation (IMR)",
        "what":  "Вимикає групування апаратних переривань мережевої карти через реєстр або PowerShell + драйвер.",
        "why":   "Коли IMR увімкнено — NIC накопичує кілька пакетів і лише потім перериває CPU. "
                 "Це додає 0.5–2 ms затримки на кожен пакет. "
                 "При IMR=OFF кожен пакет миттєво перериває CPU.",
        "risk":  "🟠 Помірний — збільшує навантаження на CPU на 3–8%.",
        "gain":  "⬇ Мінімальна латентність кожного пакету. Відчутно при tick 128.",
    },
    "💤  NIC Power Save → OFF": {
        "title": "NIC Energy-Efficient Ethernet (EEE)",
        "what":  "Вимикає Energy Efficient Ethernet та Wake-on-LAN через драйвер мережевої карти.",
        "why":   "Режим економії переводить NIC у сплячий стан між пакетами. "
                 "Вихід зі сплячого стану займає 50–250 мікросекунд — "
                 "цього достатньо щоб пакет встав у чергу і пінг стрибнув.",
        "risk":  "🟢 Мінімальний — NIC споживає на ~0.5 Вт більше.",
        "gain":  "⬇ Виключає мікрострибки пінгу (ping spikes) від 30 мс і вище.",
    },
    "📦  LSO (Large Send Offload) → OFF": {
        "title": "Large Send Offload v1 / v2",
        "what":  "Вимикає LSO/LSOv2 через PowerShell Set-NetAdapterAdvancedProperty.",
        "why":   "LSO дозволяє NIC самостійно ділити великі TCP-сегменти. "
                 "Це корисно для торентів, але додає 1–3 ms джиттеру для маленьких "
                 "пакетів (UDP 64 байти) типових для ігор.",
        "risk":  "🟡 Низький — незначно знижує пропускну здатність при великих передачах.",
        "gain":  "⬇ Стабільний джиттер для UDP трафіку (ігрові пакети).",
    },
    "🧵  RSS → P-ядра CPU": {
        "title": "Receive Side Scaling (RSS)",
        "what":  "Прив'язує обробку мережевих переривань до P-ядер (ядра продуктивності) процесора через реєстр.",
        "why":   "За замовчуванням Windows розподіляє мережеві переривання на всі ядра, "
                 "включно з E-ядрами (ефективності) на Intel 12th+. "
                 "E-ядра мають нижчу частоту — обробка пакетів повільніша.",
        "risk":  "🟡 Потребує перезавантаження для повного ефекту.",
        "gain":  "⬇ Консистентна латентність — пакети завжди на швидких ядрах.",
    },
    "🎯  MMCSS Games Profile": {
        "title": "Multimedia Class Scheduler Service",
        "what":  "Встановлює SystemResponsiveness=0 та NetworkThrottlingIndex=0xFFFFFFFF у реєстрі MMCSS.",
        "why":   "MMCSS за замовчуванням резервує 20% CPU для мультимедіа і обмежує "
                 "мережевий трафік. SystemResponsiveness=0 знімає це обмеження.",
        "risk":  "🟡 Низький — може трохи сповільнити відтворення відео у фоні.",
        "gain":  "⬇ Пінг: −5–20 ms. Windows перестає дроселювати мережевий трафік.",
    },
    "🔗  Delayed ACK + Nagle Extended": {
        "title": "Розширений пакет анти-Nagle tweaks",
        "what":  "TcpAckFrequency=1, TCPNoDelay=1 + вимкнення Delayed ACK через реєстр всіх адаптерів.",
        "why":   "Delayed ACK чекає 200 ms перед відповіддю ACK щоб об'єднати з даними. "
                 "В іграх це додає 200 ms затримки підтвердження кожного пакету. "
                 "При вимкненні — ACK іде миттєво.",
        "risk":  "🟡 Низький — незначно збільшує кількість ACK пакетів.",
        "gain":  "⬇ Джиттер: −10–40 ms. Найефективніший твік для TCP-ігор.",
    },
}

PRIORITY_COLORS = {
    "High":         "#ef4444",
    "AboveNormal":  "#f97316",
    "Normal":       "#22c55e",
    "BelowNormal":  "#64748b",
    "Idle":         "#334155",
    "Unknown":      "#1e293b",
}
PRIORITY_LABELS = {
    "High":        "🔴 HIGH",
    "AboveNormal": "🟠 ABV",
    "Normal":      "🟢 NRM",
    "BelowNormal": "⚫ BLW",
    "Idle":        "⚫ IDL",
    "Unknown":     "— —",
}


# ─── Tooltip-клас (hover popup) ───────────────────────────────────────────────

class HoverTooltip:
    def __init__(self, widget, data):
        self._widget  = widget
        self._data    = data   # може бути dict або str
        self._tip_win = None
        widget.bind("<Enter>", self._show)
        widget.bind("<Leave>", self._hide)

    def _show(self, event=None):
        if self._tip_win:
            return
        x = self._widget.winfo_rootx() + self._widget.winfo_width() + 8
        y = self._widget.winfo_rooty()

        win = tk.Toplevel(self._widget)
        win.wm_overrideredirect(True)
        win.wm_attributes("-topmost", True)
        win.geometry(f"+{x}+{y}")
        win.configure(bg="#0d0d1a")

        frame = tk.Frame(win, bg="#1a0a3a", bd=1, relief="flat",
                         highlightbackground="#7c3aed", highlightthickness=1)
        frame.pack(padx=1, pady=1, fill="both", expand=True)

        # Якщо data — рядок (для net priority)
        if isinstance(self._data, str):
            tk.Label(frame, text=self._data,
                     bg="#1a0a3a", fg="#cbd5e1",
                     font=("Consolas", 11),
                     wraplength=300, justify="left",
                     ).pack(anchor="w", padx=12, pady=10)
        else:
            d = self._data
            tk.Label(frame, text=d.get("title", ""),
                     bg="#1a0a3a", fg="#a855f7",
                     font=("Consolas", 12, "bold"),
                     wraplength=280, justify="left",
                     ).pack(anchor="w", padx=12, pady=(10, 4))

            tk.Frame(frame, bg="#3a1a6a", height=1).pack(fill="x", padx=8)

            rows = [
                ("ЩО РОБИТЬ:", d.get("what", ""),  "#94a3b8"),
                ("НАВІЩО:",    d.get("why", ""),   "#cbd5e1"),
                ("РИЗИК:",     d.get("risk", ""),  "#fbbf24"),
                ("ЕФЕКТ:",     d.get("gain", ""),  "#4ade80"),
            ]
            for lbl, val, color in rows:
                if not val:
                    continue
                row_f = tk.Frame(frame, bg="#1a0a3a")
                row_f.pack(anchor="w", padx=12, pady=(6, 0), fill="x")
                tk.Label(row_f, text=lbl,
                         bg="#1a0a3a", fg="#6366f1",
                         font=("Consolas", 11, "bold"),
                         ).pack(anchor="w")
                tk.Label(row_f, text=val,
                         bg="#1a0a3a", fg=color,
                         font=("Consolas", 11),
                         wraplength=290, justify="left",
                         ).pack(anchor="w")

        tk.Frame(frame, height=8, bg="#1a0a3a").pack()
        self._tip_win = win
        win.after(10000, self._hide)

    def _hide(self, event=None):
        if self._tip_win:
            try:
                self._tip_win.destroy()
            except Exception:
                pass
            self._tip_win = None


class GameModePage(ctk.CTkFrame):
    """Головна сторінка Game Latency Optimizer."""

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent")
        self.engine = GameBoosterEngine()

        # ── Стан ──
        self._game_mode_active = False
        self._ping_running     = False

        self._ping_history: dict[str, list] = {
            name: [] for name in PING_TARGETS
        }

        # Пріоритети CPU: {pid: "High" | "Normal" | ...}
        self._proc_priority_map: dict[int, str] = {}

        # Мережеві пріоритети QoS: {exe_name.lower(): "maximum"|"high"|"normal"|"low"}
        self._net_priority_map:    dict[str, str]   = {}
        self._bandwidth_limit_map: dict[str, float] = {}  # {exe_lower: Mbps, 0=no limit}

        # Row-фрейми для анімації: {pid: frame_widget}
        self._proc_row_widgets: dict[int, ctk.CTkFrame] = {}

        # Усі процеси для фільтрації
        self._all_procs: list[dict] = []
        self._active_filter = "all"

        # FIX: токен для скасування старих render-задач при сортуванні
        self._render_token: int = 0
        # FIX: checkboxes вибору серверів для Ping Monitor
        self._server_enabled: dict[str, tk.BooleanVar] = {}

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_body()

        # Завантажуємо існуючі QoS правила
        # Черга для thread-safe UI-оновлень (Python 3.14 сумісність)
        self._ui_queue: queue.Queue = queue.Queue()
        threading.Thread(target=self._load_net_priorities, daemon=True).start()
        # Запускаємо поллер черги
        self.after(100, self._poll_ui_queue)

        # ── Масштабування Ctrl+/-/0 (як у Spotify) ─────────────────────
        self._ui_scale = 1.0
        self._bind_scale_hotkeys()

    def _bind_scale_hotkeys(self):
        """Прив'язує Ctrl+= / Ctrl+- / Ctrl+0 до масштабування."""
        try:
            top = self.winfo_toplevel()
            top.bind("<Control-equal>", lambda e: self._scale_change(+0.1), add="+")
            top.bind("<Control-plus>",  lambda e: self._scale_change(+0.1), add="+")
            top.bind("<Control-KP_Add>",lambda e: self._scale_change(+0.1), add="+")
            top.bind("<Control-minus>", lambda e: self._scale_change(-0.1), add="+")
            top.bind("<Control-KP_Subtract>", lambda e: self._scale_change(-0.1), add="+")
            top.bind("<Control-0>",     lambda e: self._scale_reset(), add="+")
            top.bind("<Control-KP_0>",  lambda e: self._scale_reset(), add="+")
        except Exception as e:
            print(f"[GameMode] hotkey bind failed: {e}")

    def _scale_change(self, delta: float):
        new_scale = round(max(0.7, min(2.0, self._ui_scale + delta)), 2)
        if new_scale == self._ui_scale: return
        self._ui_scale = new_scale
        try:
            ctk.set_widget_scaling(new_scale)
            print(f"[GameMode] UI scale: {int(new_scale * 100)}%")
        except Exception as e:
            print(f"[GameMode] scale change failed: {e}")

    def _scale_reset(self):
        self._ui_scale = 1.0
        try:
            ctk.set_widget_scaling(1.0)
            print("[GameMode] UI scale: 100% (reset)")
        except Exception as e:
            print(f"[GameMode] scale reset failed: {e}")

    def _poll_ui_queue(self):
        """Головний потік — читає чергу і виконує callback-и."""
        try:
            while True:
                cb = self._ui_queue.get_nowait()
                cb()
        except queue.Empty:
            pass
        except Exception:
            pass
        self.after(150, self._poll_ui_queue)

    def _safe_after(self, func, delay: int = 0):
        """Потокобезпечно: кладе func у чергу; головний потік виконає через _poll_ui_queue."""
        if delay == 0:
            self._ui_queue.put(func)
        else:
            # Для затриманих викликів — просто плануємо put через звичайний after
            # (цей after викликається з головного потоку — watchdog, анімація)
            try:
                self.after(delay, func)
            except Exception:
                self._ui_queue.put(func)

    # ═══════════════════════════════════════════════════════════════════════
    #  HEADER
    # ═══════════════════════════════════════════════════════════════════════

    def _build_header(self):
        card = GlowCard(self, accent=COLORS["accent_purple"])
        card.grid(row=0, column=0, padx=24, pady=(24, 10), sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=0, column=0, padx=28, pady=22, sticky="w")

        ctk.CTkLabel(
            left, text="🎮  GAME LATENCY OPTIMIZER",
            font=ctk.CTkFont(family="Consolas", size=17, weight="bold"),
            text_color=COLORS["accent_purple"]
        ).pack(anchor="w")

        ctk.CTkLabel(
            left,
            text=(
                "Вбиває фонові пожирачі каналу · Оптимізує реєстр Windows\n"
                "Вимикає Nagle's Algorithm · DNS Fast-Switch · QoS per-Process"
            ),
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text_secondary"],
            justify="left"
        ).pack(anchor="w", pady=(6, 0))

        right = ctk.CTkFrame(card, fg_color="transparent")
        right.grid(row=0, column=1, padx=28, pady=22, sticky="e")

        self._lbl_status = ctk.CTkLabel(
            right, text="⬤  РЕЖИМ ВИМКНЕНИЙ",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS["text_secondary"]
        )
        self._lbl_status.pack(pady=(0, 10))

        self._btn_toggle = ctk.CTkButton(
            right,
            text="🚀  ACTIVATE GAME MODE",
            command=self._on_toggle,
            fg_color="#2d0a5a",
            hover_color="#4a0d8a",
            text_color=COLORS["accent_purple"],
            font=ctk.CTkFont(family="Consolas", size=15, weight="bold"),
            height=50, corner_radius=14,
            border_width=2, border_color=COLORS["accent_purple"],
        )
        self._btn_toggle.pack(pady=(0, 8), fill="x")

        self._btn_restore = ctk.CTkButton(
            right,
            text="↩  RESTORE DEFAULTS",
            command=self._on_restore,
            fg_color="#0a0a0a", hover_color="#1a0a0a",
            text_color=COLORS["accent_red"],
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=32, corner_radius=10,
            border_width=1, border_color=COLORS["accent_red"],
        )
        self._btn_restore.pack(fill="x")

    # ═══════════════════════════════════════════════════════════════════════
    #  BODY
    # ═══════════════════════════════════════════════════════════════════════

    def _build_body(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, padx=24, pady=(0, 24), sticky="nsew")
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_columnconfigure(2, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_tweaks_panel(body)
        self._build_center_panel(body)
        self._build_process_panel(body)

    # ── Advanced Tweaks ───────────────────────────────────────────────────

    def _build_tweaks_panel(self, parent):
        card = GlowCard(parent, accent=COLORS["accent_purple"])
        card.grid(row=0, column=0, padx=(0, 10), sticky="nsew")
        card.grid_rowconfigure(0, weight=1)
        card.grid_columnconfigure(0, weight=1)

        # ── Canvas-скролер (той самий патерн що і в панелі процесів) ──────
        _BG = COLORS.get("bg_primary", "#0d0d1a")

        scroll_frame = tk.Frame(card, bg=_BG)
        scroll_frame.grid(row=0, column=0, sticky="nsew")
        scroll_frame.grid_rowconfigure(0, weight=1)
        scroll_frame.grid_columnconfigure(0, weight=1)

        _canvas = tk.Canvas(scroll_frame, bg=_BG, highlightthickness=0, bd=0)
        _canvas.grid(row=0, column=0, sticky="nsew")

        # ── Кастомний scrollbar в стилі утиліти (фіолетовий, pill-форма) ──
        _SB_W = 6
        _SB_BG  = "#0d0d1a"
        _SB_FG  = "#7c3aed"
        _SB_HOV = "#a855f7"

        _tsb = tk.Canvas(scroll_frame, width=_SB_W + 4, bg=_SB_BG,
                         highlightthickness=0, bd=0, cursor="hand2")
        _tsb.grid(row=0, column=1, sticky="ns", padx=(1, 0))

        _ts = {"drag": False, "y0": 0, "y1": 0, "y2": 0}

        def _tsb_draw(*_):
            _tsb.delete("all")
            h = _tsb.winfo_height()
            if h < 2: return
            try: top, bot = _canvas.yview()
            except: return
            if bot - top >= 1.0: return
            th = max(20, int(h * (bot - top)))
            ty = int(h * top)
            _ts["y1"], _ts["y2"] = ty, ty + th
            _tsb.create_rectangle(2, 0, _SB_W+2, h, fill=_SB_BG, outline="")
            _tsb.create_oval(2, ty, _SB_W+2, ty+_SB_W, fill=_SB_FG, outline="", tags="t")
            _tsb.create_rectangle(2, ty+_SB_W//2, _SB_W+2, ty+th-_SB_W//2, fill=_SB_FG, outline="", tags="t")
            _tsb.create_oval(2, ty+th-_SB_W, _SB_W+2, ty+th, fill=_SB_FG, outline="", tags="t")

        def _tsb_press(e):
            if _ts["y1"] <= e.y <= _ts["y2"]:
                _ts["drag"], _ts["y0"] = True, e.y
            else:
                h = _tsb.winfo_height()
                if h: _canvas.yview_moveto(e.y / h); _tsb_draw()

        def _tsb_drag(e):
            if not _ts["drag"]: return
            h = _tsb.winfo_height()
            if not h: return
            _canvas.yview_scroll(int((e.y - _ts["y0"]) / 2) or (1 if e.y > _ts["y0"] else -1), "units")
            _ts["y0"] = e.y; _tsb_draw()

        _tsb.bind("<ButtonPress-1>",   _tsb_press)
        _tsb.bind("<B1-Motion>",       _tsb_drag)
        _tsb.bind("<ButtonRelease-1>", lambda e: _ts.update(drag=False))
        _tsb.bind("<Enter>",  lambda e: _tsb.itemconfig("t", fill=_SB_HOV))
        _tsb.bind("<Leave>",  lambda e: _tsb.itemconfig("t", fill=_SB_FG))
        _tsb.bind("<Configure>", _tsb_draw)
        _canvas.configure(yscrollcommand=lambda f, l: _tsb_draw())

        _inner = tk.Frame(_canvas, bg=_BG)
        _win_id = _canvas.create_window((0, 0), window=_inner, anchor="nw")

        def _on_inner_configure(e):
            _canvas.configure(scrollregion=_canvas.bbox("all"))

        def _on_canvas_configure(e):
            _canvas.itemconfig(_win_id, width=e.width)

        _inner.bind("<Configure>", _on_inner_configure)
        _canvas.bind("<Configure>", _on_canvas_configure)

        def _scroll_fn(e):
            _canvas.yview_scroll(int(-1 * (e.delta / 120)), "units")

        _canvas.bind("<MouseWheel>", _scroll_fn, add="+")
        _canvas.bind("<Button-4>",   lambda e: _canvas.yview_scroll(-1, "units"), add="+")
        _canvas.bind("<Button-5>",   lambda e: _canvas.yview_scroll( 1, "units"), add="+")

        # ── Прив'язка скролу ─────────────────────────────────────────────
        # ВАЖЛИВО: bind_scroll викликається ПІСЛЯ додавання всіх віджетів,
        # бо <Map> спрацьовує до появи PING BOOST секції.
        # CTkCheckBox має внутрішні tk-фрейми — проходимо рекурсивно.

        def _deep_bind(widget):
            try:
                widget.bind("<MouseWheel>", _scroll_fn, add="+")
            except Exception:
                pass
            try:
                for child in widget.winfo_children():
                    _deep_bind(child)
            except Exception:
                pass

        # Прив'язуємо зараз (всі віджети вже створені)
        _deep_bind(_inner)

        # І ще раз через 200мс — коли CTk розгорне свої внутрішні фрейми
        def _late_bind():
            _deep_bind(_inner)
            # Зберігаємо функцію для повторного виклику при появі нових віджетів
            self._tweaks_deep_bind = _deep_bind
            self._tweaks_inner = _inner

        _canvas.after(200, _late_bind)

        # Прибираємо старий <Map> bind щоб не дублювати
        _inner.unbind("<Map>")

        # Далі весь контент кладемо в _inner замість card ─────────────────

        ctk.CTkLabel(
            _inner, text="⚙  ADVANCED TWEAKS",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS["accent_purple"]
        ).pack(anchor="w", padx=18, pady=(16, 10))

        self._tweaks: list[tuple[ctk.CTkCheckBox, callable]] = []

        ctk.CTkLabel(
            _inner,
            text="  ℹ  Наведи мишку на пункт — побачиш що саме змінюється в системі",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
            justify="left"
        ).pack(anchor="w", padx=18, pady=(0, 6))

        tweaks_cfg = [
            ("🔇  Disable Windows Update",    self._tweak_wu),
            ("🌐  DNS Fast-Switch → 1.1.1.1", self._tweak_dns),
            ("⚡  TCP NoDelay (No-Nagle)",     self._tweak_nagle),
            ("🖥  High Performance Power",     self._tweak_power),
            ("🧠  CPU Core Unpark",           self._tweak_unpark),
            ("🗑  Flush DNS Cache",           self._tweak_flush_dns),
            ("🎯  High Priority for Games",   self._tweak_hi_priority),
            ("🧹  Clean RAM",                 self._tweak_clean_ram),
        ]

        for label, cb in tweaks_cfg:
            var = tk.BooleanVar(value=False)
            chk = ctk.CTkCheckBox(
                _inner, text=label, variable=var,
                command=lambda v=var, fn=cb: self._on_tweak(v, fn),
                font=ctk.CTkFont(family="Consolas", size=12),
                text_color=COLORS["text_primary"],
                fg_color=COLORS["accent_purple"],
                hover_color="#5a1aaa",
                border_color=COLORS["border"],
                width=220,
            )
            chk.pack(anchor="w", padx=18, pady=5)
            self._tweaks.append((chk, cb))

            tooltip_data = TWEAK_TOOLTIPS.get(label)
            if tooltip_data:
                HoverTooltip(chk, tooltip_data)

        tk.Frame(_inner, bg=COLORS["border"], height=1).pack(fill="x", padx=18, pady=12)

        ctk.CTkLabel(
            _inner, text="🌐  DNS ПРОФІЛЬ",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=18)

        self._dns_var = tk.StringVar(value=list(GAMING_DNS.keys())[0])
        dns_menu = ctk.CTkOptionMenu(
            _inner,
            values=list(GAMING_DNS.keys()),
            variable=self._dns_var,
            fg_color=COLORS["bg_secondary"],
            button_color=COLORS["accent_purple"],
            button_hover_color="#4a0d8a",
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=12),
            width=220,
        )
        dns_menu.pack(padx=18, pady=(4, 16))

        # ── PING BOOST ─────────────────────────────────────────────────────
        tk.Frame(_inner, bg=COLORS["border"], height=1).pack(fill="x", padx=18, pady=(0, 10))

        ctk.CTkLabel(
            _inner, text="⚡  PING BOOST  (NIC-рівень)",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#22d3ee"
        ).pack(anchor="w", padx=18, pady=(0, 6))

        self._btn_ping_all = ctk.CTkButton(
            _inner,
            text="🚀  APPLY ALL PING TWEAKS",
            command=self._ping_boost_all,
            fg_color="#0a1a1a",
            hover_color="#0d2a2a",
            text_color="#22d3ee",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=36, corner_radius=10,
            border_width=2, border_color="#22d3ee",
        )
        self._btn_ping_all.pack(fill="x", padx=18, pady=(0, 8))

        ping_tweaks_cfg = [
            ("⚡  Timer 0.5ms (ОС реагує швидше)",   self._tweak_timer),
            ("🔔  Interrupt Moderation → OFF",        self._tweak_imr),
            ("💤  NIC Power Save → OFF",              self._tweak_nic_power),
            ("📦  LSO (Large Send Offload) → OFF",    self._tweak_lso),
            ("🧵  RSS → P-ядра CPU",                  self._tweak_rss),
            ("🎯  MMCSS Games Profile",               self._tweak_mmcss),
            ("🔗  Delayed ACK + Nagle Extended",      self._tweak_nagle_ext),
        ]
        self._ping_tweak_refs = {}

        ctk.CTkLabel(
            _inner,
            text="  ℹ  Наведи мишку на будь-який пункт — побачиш детальне пояснення",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
            justify="left"
        ).pack(anchor="w", padx=18, pady=(0, 4))

        for label, cb in ping_tweaks_cfg:
            var = tk.BooleanVar(value=False)
            chk = ctk.CTkCheckBox(
                _inner, text=label, variable=var,
                command=lambda v=var, fn=cb: self._on_ping_tweak(v, fn),
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color="#94a3b8",
                fg_color="#22d3ee",
                hover_color="#0891b2",
                border_color=COLORS["border"],
                width=220,
            )
            chk.pack(anchor="w", padx=18, pady=3)
            self._ping_tweak_refs[label] = (chk, var)

            tip = PING_TWEAK_TOOLTIPS.get(label)
            if tip:
                HoverTooltip(chk, tip)

        self._lbl_nic_status = ctk.CTkLabel(
            _inner, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"]
        )
        self._lbl_nic_status.pack(anchor="w", padx=20, pady=(4, 8))
        threading.Thread(target=self._detect_nic, daemon=True).start()

        tk.Frame(_inner, bg=COLORS["border"], height=1).pack(fill="x", padx=18, pady=(2, 8))
        ctk.CTkLabel(
            _inner, text="🎮  PER-GAME AFFINITY",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color="#a855f7"
        ).pack(anchor="w", padx=18)

        self._btn_affinity = ctk.CTkButton(
            _inner,
            text="🔗  Прив'язати гру до P-ядер",
            command=self._apply_game_affinity,
            fg_color="#0a0614",
            hover_color="#1a0a3a",
            text_color="#a855f7",
            font=ctk.CTkFont(family="Consolas", size=11),
            height=30, corner_radius=8,
            border_width=1, border_color="#a855f7",
        )
        self._btn_affinity.pack(fill="x", padx=18, pady=(4, 8))

        # ── ДІАГНОСТИКА ПІНГУ ───────────────────────────────────────────────
        tk.Frame(_inner, bg=COLORS["border"], height=1).pack(fill="x", padx=18, pady=(4, 8))
        ctk.CTkLabel(
            _inner, text="🔍  ДІАГНОСТИКА ПІНГУ",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#f59e0b"
        ).pack(anchor="w", padx=18)
        ctk.CTkLabel(
            _inner, text="Знаходить де саме виникає затримка:\nПК → Роутер → Провайдер → Сервер",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"], justify="left"
        ).pack(anchor="w", padx=20, pady=(2, 6))

        self._btn_diagnose = ctk.CTkButton(
            _inner,
            text="🔍  Запустити діагностику",
            command=self._run_ping_diagnose,
            fg_color="#0a0800",
            hover_color="#1a1200",
            text_color="#f59e0b",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=34, corner_radius=10,
            border_width=2, border_color="#f59e0b",
        )
        self._btn_diagnose.pack(fill="x", padx=18, pady=(0, 4))

        ctk.CTkLabel(
            _inner, text="🎯  Ціль (IP або домен):",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"]
        ).pack(anchor="w", padx=20)

        self._diag_target_var = tk.StringVar(value="8.8.8.8")
        ctk.CTkEntry(
            _inner, textvariable=self._diag_target_var,
            fg_color=COLORS["bg_secondary"], border_width=1,
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=11),
            height=26,
        ).pack(fill="x", padx=18, pady=(2, 8))

        # ── 🆕 VERIFY TWEAKS ───────────────────────────────────────────────
        ctk.CTkButton(
            _inner,
            text="✔  Перевірити чи твіки застосовані",
            command=self._run_verify_tweaks,
            fg_color="#080d1a",
            hover_color="#0f1530",
            text_color="#6366f1",
            font=ctk.CTkFont(family="Consolas", size=11),
            height=28, corner_radius=8,
            border_width=1, border_color="#6366f1",
        ).pack(fill="x", padx=18, pady=(0, 8))

        # ── AUTO-BOOST ─────────────────────────────────────────────────────
        tk.Frame(_inner, bg=COLORS["border"], height=1).pack(fill="x", padx=18, pady=(4, 8))
        ctk.CTkLabel(
            _inner, text="🤖  AUTO-BOOST (при запуску гри)",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color="#22ff88"
        ).pack(anchor="w", padx=18)
        ctk.CTkLabel(
            _inner, text="Авто: High priority + RAM clean + Timer\nпри виявленні запущеної гри",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"], justify="left"
        ).pack(anchor="w", padx=20, pady=(2, 6))

        self._autoboost_var = tk.BooleanVar(value=False)
        self._btn_autoboost = ctk.CTkButton(
            _inner,
            text="🤖  Увімкнути Auto-Boost",
            command=self._toggle_autoboost,
            fg_color="#061206",
            hover_color="#0a2010",
            text_color="#22ff88",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=34, corner_radius=10,
            border_width=2, border_color="#22ff88",
        )
        self._btn_autoboost.pack(fill="x", padx=18, pady=(0, 20))

    def _on_tweak(self, var: tk.BooleanVar, callback: callable):
        enabled = var.get()
        threading.Thread(target=callback, args=(enabled,), daemon=True).start()

    def _on_ping_tweak(self, var: tk.BooleanVar, callback: callable):
        enabled = var.get()
        threading.Thread(target=callback, args=(enabled,), daemon=True).start()

    # ── NIC детект ──────────────────────────────────────────────────────
    def _detect_nic(self):
        try:
            adapter = self.engine._get_active_adapter()
            text = f"🌐 Адаптер: {adapter}" if adapter else "⚠️ Адаптер не знайдено"
            self._safe_after(lambda: self._lbl_nic_status.configure(text=text))
        except Exception:
            pass

    # ── ДІАГНОСТИКА ПІНГУ ───────────────────────────────────────────────
    def _run_ping_diagnose(self):
        """Запускає traceroute діагностику і показує результат у попапі."""
        self._btn_diagnose.configure(
            text="⏳  Діагностика...", state="disabled"
        )
        target = self._diag_target_var.get().strip() or "8.8.8.8"

        def _work():
            def _prog(msg, pct):
                self._safe_after(lambda m=msg: self._btn_diagnose.configure(
                    text=f"⏳  {m[:28]}"
                ))
                self._safe_after(lambda m=msg: self._log(f"  🔍 {m}"))

            result = self.engine.diagnose_ping(
                target_host=target,
                progress_cb=_prog,
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
            self._safe_after(lambda: self._show_diagnose_result(result, target))

        threading.Thread(target=_work, daemon=True, name="diagnose").start()

    def _show_diagnose_result(self, result: dict, target: str):
        """Показує результат діагностики у popup вікні."""
        self._btn_diagnose.configure(
            text="🔍  Запустити діагностику", state="normal"
        )

        popup = tk.Toplevel(self)
        popup.title("🔍 Діагностика пінгу")
        popup.geometry("500x520")
        popup.configure(bg="#080810")
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        tk.Label(popup, text="🔍  ДІАГНОСТИКА ПІНГУ",
                 bg="#080810", fg="#f59e0b",
                 font=("Consolas", 15, "bold")).pack(pady=(16, 2))
        tk.Label(popup, text=f"Ціль: {target}",
                 bg="#080810", fg="#6b7280",
                 font=("Consolas", 11)).pack()

        tk.Frame(popup, bg="#2a1a0a", height=1).pack(fill="x", padx=20, pady=8)

        # Сегменти маршруту
        segments = [
            ("🖥  Ваш ПК → Роутер",      result.get("router_ms"),   "#22c55e", 5),
            ("🌐  Роутер → Провайдер",    result.get("isp_ms"),      "#38bdf8", 20),
            ("🛰  Провайдер → Інтернет",  result.get("target_ms"),   "#a855f7", 60),
        ]

        max_ms = max((v for _, v, _, _ in segments if v), default=100)

        for label, ms, color, ok_threshold in segments:
            f = tk.Frame(popup, bg="#0d0d1a")
            f.pack(fill="x", padx=20, pady=3)

            status = "✅" if ms and ms <= ok_threshold * 3 else "⚠️" if ms else "❓"
            ms_txt = f"{ms:.0f} ms" if ms else "timeout"
            tk.Label(f, text=f"{status} {label}",
                     bg="#0d0d1a", fg=color,
                     font=("Consolas", 11, "bold"), anchor="w",
                     width=32).pack(side="left", padx=8, pady=4)
            tk.Label(f, text=ms_txt,
                     bg="#0d0d1a", fg=color,
                     font=("Consolas", 13, "bold"), width=9).pack(side="right", padx=8)

            # Прогрес-бар
            if ms:
                bar_frame = tk.Frame(popup, bg="#0d0d22", height=4)
                bar_frame.pack(fill="x", padx=28, pady=(0, 2))
                rel = min(ms / (max_ms + 10), 1.0)
                bar_color = "#ef4444" if ms > ok_threshold * 4 else "#f97316" if ms > ok_threshold * 2 else color
                tk.Frame(bar_frame, bg=bar_color, height=4).place(
                    relwidth=rel, relheight=1.0
                )

        # Хопи
        hops = result.get("hops", [])
        if hops:
            tk.Frame(popup, bg="#2a2a1a", height=1).pack(fill="x", padx=20, pady=8)
            tk.Label(popup, text="📡  МАРШРУТ (Traceroute)",
                     bg="#080810", fg="#94a3b8",
                     font=("Consolas", 11, "bold")).pack(anchor="w", padx=20)

            hops_frame = tk.Frame(popup, bg="#080810")
            hops_frame.pack(fill="x", padx=20, pady=4)

            for hop in hops[:10]:
                ms   = hop.get("ms")
                ms_s = f"{ms:.0f}ms" if ms else " * "
                is_bot = hop.get("is_bottleneck", False)
                jump   = hop.get("jump", 0)
                color  = "#ef4444" if is_bot else "#94a3b8"
                bot_mark = f"  ⚠️ +{jump:.0f}ms!" if is_bot else ""
                ip = hop.get("ip") or "*"
                tk.Label(hops_frame,
                         text=f"  {hop['hop']:2d}  {ms_s:>6}  {ip:<16}{bot_mark}",
                         bg="#080810", fg=color,
                         font=("Consolas", 11), anchor="w").pack(fill="x")

        # Рекомендація
        tk.Frame(popup, bg="#2a1a0a", height=1).pack(fill="x", padx=20, pady=8)
        rec  = result.get("recommendation", "")
        stat = result.get("status", "ok")
        rec_color = {
            "wifi_issue":  "#ef4444",
            "isp_issue":   "#f97316",
            "server_far":  "#eab308",
            "ok":          "#22c55e",
        }.get(stat, "#94a3b8")

        tk.Label(popup, text="💡  ВИСНОВОК:",
                 bg="#080810", fg=rec_color,
                 font=("Consolas", 11, "bold")).pack(anchor="w", padx=20)
        tk.Label(popup, text=rec, bg="#080810", fg=rec_color,
                 font=("Consolas", 11), wraplength=440, justify="left").pack(
            anchor="w", padx=24, pady=(2, 12))

        ctk.CTkButton(
            popup, text="Закрити", command=popup.destroy,
            fg_color="#1a0a00", hover_color="#2a1a00",
            text_color="#f59e0b",
            font=ctk.CTkFont(family="Consolas", size=12),
            height=30, corner_radius=8
        ).pack(pady=(0, 14))

    # ── VERIFY TWEAKS ───────────────────────────────────────────────────
    def _run_verify_tweaks(self):
        """Перевіряє чи реально застосовані оптимізації."""
        self._log("🔎 Перевірка застосованих твіків...")

        def _work():
            results = self.engine.verify_tweaks()
            self._safe_after(lambda: self._show_verify_result(results))

        threading.Thread(target=_work, daemon=True, name="verify").start()

    def _show_verify_result(self, results: dict):
        popup = tk.Toplevel(self)
        popup.title("✔ Перевірка твіків")
        popup.geometry("440x420")
        popup.configure(bg="#080810")
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        tk.Label(popup, text="✔  СТАТУС ОПТИМІЗАЦІЙ",
                 bg="#080810", fg="#6366f1",
                 font=("Consolas", 14, "bold")).pack(pady=(16, 4))
        tk.Frame(popup, bg="#1a1a3a", height=1).pack(fill="x", padx=20, pady=6)

        applied = sum(1 for v in results.values() if v.get("applied"))
        total   = len(results)
        pct_col = "#22c55e" if applied == total else "#f97316" if applied > total // 2 else "#ef4444"
        tk.Label(popup, text=f"{applied} / {total} застосовано",
                 bg="#080810", fg=pct_col,
                 font=("Consolas", 13, "bold")).pack()

        for key, info in results.items():
            ok    = info.get("applied", False)
            name  = info.get("name", key)
            value = info.get("value", "?")
            tip   = info.get("tip", "")

            row = tk.Frame(popup, bg="#0d0d1a" if ok else "#120a0a")
            row.pack(fill="x", padx=16, pady=2)

            icon  = "✅" if ok else "❌"
            color = "#22c55e" if ok else "#ef4444"
            tk.Label(row, text=f"{icon}  {name}",
                     bg=row.cget("bg"), fg=color,
                     font=("Consolas", 11, "bold"), anchor="w",
                     width=28).pack(side="left", padx=8, pady=5)
            tk.Label(row, text=value,
                     bg=row.cget("bg"), fg="#64748b",
                     font=("Consolas", 11), anchor="e").pack(side="right", padx=8)

            if tip and not ok:
                tk.Label(popup, text=f"     ↳ {tip}",
                         bg="#080810", fg="#374151",
                         font=("Consolas", 11), anchor="w").pack(fill="x", padx=24)

        tk.Frame(popup, bg="#1a1a3a", height=1).pack(fill="x", padx=20, pady=8)
        ctk.CTkButton(
            popup, text="Закрити", command=popup.destroy,
            fg_color="#0d0d2a", hover_color="#1a1a4a",
            text_color="#6366f1",
            font=ctk.CTkFont(family="Consolas", size=12),
            height=28, corner_radius=8
        ).pack(pady=(0, 12))

    # ── AUTO-BOOST ──────────────────────────────────────────────────────
    def _toggle_autoboost(self):
        if self._autoboost_var.get():
            # Вимкнути
            self._autoboost_var.set(False)
            self.engine.stop_game_watch()
            self._btn_autoboost.configure(
                text="🤖  Увімкнути Auto-Boost",
                fg_color="#061206", text_color="#22ff88",
                border_color="#22ff88",
            )
            self._log("🤖 Auto-Boost вимкнено")
        else:
            # Увімкнути
            self._autoboost_var.set(True)
            self.engine.start_game_watch(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
            self._btn_autoboost.configure(
                text="🟢  Auto-Boost АКТИВНИЙ",
                fg_color="#062206", text_color="#4ade80",
                border_color="#4ade80",
            )
            self._log("🤖 Auto-Boost увімкнено — слідкую за іграми кожні 10с")

    # ── PING BOOST ALL ──────────────────────────────────────────────────
    def _ping_boost_all(self):
        """Застосовує ВСІ ping tweaks одним кліком."""
        self._btn_ping_all.configure(
            text="⏳  Оптимізую...", state="disabled"
        )
        self._log("\n> ⚡ PING OPTIMIZER — запуск усіх оптимізацій...")

        def _work():
            # Збираємо PID ігор
            game_pids = [
                p["pid"] for p in self._all_procs
                if p.get("category") == "game" and p["pid"] > 0
            ]
            results = self.engine.apply_all_ping_tweaks(
                game_pids=game_pids,
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
            ok_n = sum(1 for v in results.values() if v)
            total = len(results)

            def _done():
                color = "#22d3ee" if ok_n > total // 2 else "#eab308"
                self._btn_ping_all.configure(
                    text=f"✅  ЗАСТОСОВАНО ({ok_n}/{total})",
                    state="normal",
                    text_color=color,
                    border_color=color,
                )
                # Тікаємо checkboxes які успішні
                label_map = {
                    "timer":    "⚡  Timer 0.5ms (ОС реагує швидше)",
                    "imr":      "🔔  Interrupt Moderation → OFF",
                    "power":    "💤  NIC Power Save → OFF",
                    "lso":      "📦  LSO (Large Send Offload) → OFF",
                    "rss":      "🧵  RSS → P-ядра CPU",
                    "mmcss":    "🎯  MMCSS Games Profile",
                    "nagle":    "🔗  Delayed ACK + Nagle Extended",
                }
                for key, label in label_map.items():
                    if results.get(key) and label in self._ping_tweak_refs:
                        chk, var = self._ping_tweak_refs[label]
                        var.set(True)

            self._safe_after(_done)

        threading.Thread(target=_work, daemon=True).start()

    # ── Окремі ping tweaks ──────────────────────────────────────────────
    def _tweak_timer(self, enabled: bool):
        if enabled:
            self.engine.set_timer_resolution(
                0.5, log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            self.engine.restore_timer_resolution(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )

    def _tweak_imr(self, enabled: bool):
        if enabled:
            self.engine.disable_interrupt_moderation(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            self.engine.restore_interrupt_moderation(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )

    def _tweak_nic_power(self, enabled: bool):
        if enabled:
            self.engine.disable_nic_power_save(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            self._log("  ℹ️ NIC Power Save — відновлюється при перезавантаженні")

    def _tweak_lso(self, enabled: bool):
        if enabled:
            self.engine.disable_lso(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            self._log("  ℹ️ LSO — відновлюється через netsh int tcp reset")

    def _tweak_rss(self, enabled: bool):
        if enabled:
            self.engine.set_rss_affinity(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            self._log("  ℹ️ RSS — відновлюється при перезавантаженні")

    def _tweak_mmcss(self, enabled: bool):
        if enabled:
            self.engine.apply_mmcss_tweaks(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )

    def _tweak_nagle_ext(self, enabled: bool):
        if enabled:
            self.engine.disable_nagle_extended(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )

    def _apply_game_affinity(self):
        """Прив'язує всі запущені ігри до P-ядер."""
        game_procs = [p for p in self._all_procs if p.get("category") == "game"]
        if not game_procs:
            self._log("  ⚠️ Запущені ігри не знайдено. Спочатку зроби скан (🔄)")
            return
        self._btn_affinity.configure(text="⏳...", state="disabled")

        def _work():
            count = 0
            for p in game_procs:
                ok = self.engine.set_game_affinity_pcores(
                    p["pid"], p["name"],
                    log_cb=lambda t: self._safe_after(lambda: self._log(t))
                )
                if ok:
                    count += 1
            def _done():
                self._btn_affinity.configure(
                    text=f"✅  {count}/{len(game_procs)} ігор → P-ядра",
                    state="normal"
                )
            self._safe_after(_done)

        threading.Thread(target=_work, daemon=True).start()

    def _tweak_wu(self, enabled: bool):
        if enabled:
            self.engine.stop_windows_update(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            from features.gamemode.engine import run
            run(["sc", "start", "wuauserv"])
            self._log("  🔁 Windows Update → відновлено")

    def _tweak_dns(self, enabled: bool):
        if enabled:
            profile = self._dns_var.get()
            self.engine.switch_dns(
                profile, log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            from features.gamemode.engine import run
            adapter = self.engine._get_active_adapter()
            if adapter:
                run(["netsh", "interface", "ip", "set", "dns",
                     f"name={adapter}", "dhcp"])
            self._log("  🌐 DNS → DHCP (відновлено)")

    def _tweak_nagle(self, enabled: bool):
        if enabled:
            self.engine.disable_nagle(log_cb=lambda t: self._safe_after(lambda: self._log(t)))
        else:
            self.engine._restore_nagle(log_cb=lambda t: self._safe_after(lambda: self._log(t)))

    def _tweak_power(self, enabled: bool):
        if enabled:
            self.engine.set_high_performance_power(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
        else:
            from features.gamemode.engine import run
            run(["powercfg", "-setactive", "381b4222-f694-41f0-9685-ff5bb260df2e"])
            self._log("  ⚡ Схема живлення → Balanced")

    def _tweak_unpark(self, enabled: bool):
        if enabled:
            self.engine.unpark_cpu_cores(log_cb=lambda t: self._safe_after(lambda: self._log(t)))

    def _tweak_flush_dns(self, enabled: bool):
        if enabled:
            self.engine.flush_dns(log_cb=lambda t: self._safe_after(lambda: self._log(t)))

    def _tweak_hi_priority(self, enabled: bool):
        from features.gamemode.engine import KNOWN_GAMES
        procs = self._all_procs or self.engine.scan_processes()
        count = 0
        for p in procs:
            if p["name"].lower() in KNOWN_GAMES and p["pid"] > 0:
                self.engine.set_priority(p["pid"], "High" if enabled else "Normal")
                count += 1
        self._log(f"  🎯 Пріоритет {'→ High' if enabled else '→ Normal'} "
                  f"для {count} ігрових процесів")

    def _tweak_clean_ram(self, enabled: bool):
        """Очищення RAM — одноразова дія при вмиканні."""
        if enabled:
            self._log("  🧹 Очищення RAM...")
            self.engine.clean_ram(log_cb=lambda t: self._safe_after(lambda: self._log(t)))
        else:
            self._log("  ℹ️ RAM Clean — не потребує відновлення")

    # ── Центральна панель: Ping Graph + Лог ──────────────────────────────

    def _build_center_panel(self, parent):
        center = ctk.CTkFrame(parent, fg_color="transparent")
        center.grid(row=0, column=1, padx=(0, 10), sticky="nsew")
        center.grid_rowconfigure(0, weight=0)
        center.grid_rowconfigure(1, weight=1)
        center.grid_columnconfigure(0, weight=1)

        ping_card = GlowCard(center, accent=COLORS["border"])
        ping_card.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        ping_card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(ping_card, fg_color="transparent")
        hdr.pack(fill="x", padx=16, pady=(14, 4))
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="📡  LIVE PING MONITOR",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS["accent_purple"]
        ).pack(side="left")

        self._btn_ping = ctk.CTkButton(
            hdr, text="▶ Start",
            command=self._toggle_ping,
            fg_color=COLORS["bg_secondary"], hover_color=COLORS["bg_card"],
            text_color=COLORS["accent_green"],
            font=ctk.CTkFont(family="Consolas", size=11),
            height=24, width=70, corner_radius=8,
            border_width=1, border_color=COLORS["accent_green"]
        )
        self._btn_ping.pack(side="right")

        legend_frame = ctk.CTkFrame(ping_card, fg_color="transparent")
        legend_frame.pack(fill="x", padx=16, pady=(0, 4))

        # FIX: кольори точно збігаються з ключами PING_TARGETS (10 серверів)
        self._ping_colors = {
            "Cloudflare (EU)":  "#22d3ee",
            "Google DNS":       "#84cc16",
            "Quad9 (EU)":       "#a855f7",
            "Steam / Valve":    "#1e90ff",
            "Riot Games":       "#ef4444",
            "Battle.net (EU)":  "#0ea5e9",
            "Epic Games":       "#f97316",
            "Discord":          "#818cf8",
            "EA / Origin":      "#f59e0b",
            "Hetzner (DE)":     "#4ade80",
        }
        # FIX: 2 рядки по 5 checkboxes для вибору серверів
        servers = list(self._ping_colors.keys())
        for i, name in enumerate(servers):
            var = tk.BooleanVar(value=True)
            self._server_enabled[name] = var
            color = self._ping_colors[name]
            col_idx = i % 5; row_idx = i // 5
            chk = ctk.CTkCheckBox(
                legend_frame, text=name[:14], variable=var,
                text_color=color, fg_color=color, hover_color=color,
                font=ctk.CTkFont(family="Consolas", size=10),
                width=130, height=18,
            )
            chk.grid(row=row_idx, column=col_idx, padx=2, pady=1, sticky="w")

        self._graph_canvas = tk.Canvas(
            ping_card, height=GRAPH_H,
            bg=COLORS.get("bg_primary", "#0d0d1a"), highlightthickness=0,
        )
        self._graph_canvas.pack(fill="x", padx=10, pady=(0, 12))

        self._ping_labels_frame = ctk.CTkFrame(ping_card, fg_color="transparent")
        self._ping_labels_frame.pack(fill="x", padx=16, pady=(0, 10))

        # FIX: 10 серверів у 2 рядки по 5
        self._ping_value_labels: dict[str, ctk.CTkLabel] = {}
        for i, (name, color) in enumerate(self._ping_colors.items()):
            col_frame = ctk.CTkFrame(self._ping_labels_frame, fg_color="transparent")
            col_frame.grid(row=i // 5, column=i % 5, padx=4, pady=2, sticky="w")
            ctk.CTkLabel(
                col_frame, text=name[:13],
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS["text_dim"]
            ).pack()
            lbl = ctk.CTkLabel(
                col_frame, text="-- ms",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=color
            )
            lbl.pack()
            self._ping_value_labels[name] = lbl

        log_card = GlowCard(center, accent=COLORS["border"])
        log_card.grid(row=1, column=0, sticky="nsew")
        log_card.grid_rowconfigure(1, weight=1)
        log_card.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            log_card, text="📟  SYSTEM LOG",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=COLORS["text_dim"]
        ).grid(row=0, column=0, padx=16, pady=(12, 4), sticky="w")

        self._log_box = ctk.CTkTextbox(
            log_card,
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["accent_purple"],
            fg_color=COLORS["bg_primary"],
            corner_radius=8,
        )
        self._log_box.grid(row=1, column=0, padx=12, pady=(0, 12), sticky="nsew")

        self._log("> NetGuardian Game Optimizer готовий.")
        self._log("> Натисни ACTIVATE або вибери окремі Tweaks.")
        self._log("> 🌐 Кнопка [NET] в кожному рядку — пріоритет мережі для процесу.")

    # ── Панель процесів ───────────────────────────────────────────────────

    def _build_process_panel(self, parent):
        card = GlowCard(parent, accent=COLORS["border"])
        card.grid(row=0, column=2, sticky="nsew")
        card.grid_rowconfigure(4, weight=1)
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=14, pady=(12, 6), sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr, text="🔍  ПРОЦЕСИ  &  ВПЛИВ НА ГРУ",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS["accent_purple"]
        ).grid(row=0, column=0, sticky="w")

        self._lbl_proc_count = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"]
        )
        self._lbl_proc_count.grid(row=0, column=1, sticky="e", padx=(0, 6))

        self._btn_refresh_proc = ctk.CTkButton(
            hdr, text="🔄  Оновити",
            command=self._refresh_processes,
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["bg_card"],
            text_color="#38bdf8",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=28, width=90, corner_radius=8,
            border_width=1, border_color="#1e3a4a",
        )
        self._btn_refresh_proc.grid(row=0, column=2, sticky="e")

        # Пошук
        search_frame = ctk.CTkFrame(card, fg_color=COLORS["bg_secondary"], corner_radius=8)
        search_frame.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="ew")
        search_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            search_frame, text="🔎",
            font=ctk.CTkFont(size=13), text_color=COLORS["text_dim"]
        ).grid(row=0, column=0, padx=(10, 4), pady=5)

        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self._apply_filter())
        ctk.CTkEntry(
            search_frame,
            textvariable=self._search_var,
            placeholder_text="Пошук: telegram, chrome...",
            fg_color="transparent", border_width=0,
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=12),
            height=28,
        ).grid(row=0, column=1, padx=(0, 8), sticky="ew")

        # Фільтри
        filter_row = ctk.CTkFrame(card, fg_color="transparent")
        filter_row.grid(row=2, column=0, padx=10, pady=(0, 4), sticky="ew")

        self._filter_var = tk.StringVar(value="all")
        filter_buttons = [
            ("ВСІ",    "all",       COLORS["text_secondary"]),
            ("⚠️ HOG", "hog",       COLORS["accent_red"]),
            ("🌐",     "browser",   "#38bdf8"),
            ("💬",     "messenger", "#a78bfa"),
            ("🎵",     "media",     "#4ade80"),
            ("🎮",     "game",      "#22ff88"),
            ("🚀",     "launcher",  "#a855f7"),
        ]
        self._filter_btn_refs = {}
        for label, val, color in filter_buttons:
            btn = ctk.CTkButton(
                filter_row, text=label,
                command=lambda v=val: self._set_filter(v),
                fg_color=COLORS["bg_secondary"], hover_color=COLORS["bg_card"],
                text_color=color,
                font=ctk.CTkFont(family="Consolas", size=11),
                height=22, corner_radius=6, border_width=1,
                border_color=COLORS["border"], width=44,
            )
            btn.pack(side="left", padx=2)
            self._filter_btn_refs[val] = btn

        # ── Заголовки колонок ————————————————————————————————————
        self._sort_col = "ram_mb"
        self._sort_asc = False

        HDR_BG     = "#0b0b1e"
        HDR_BORDER = "#3a1a7a"

        # ── ЄДИНА таблиця ширин — і заголовок і рядки беруть звідси ──────
        # pack_propagate(False) гарантує ТОЧНУ ширину незалежно від контейнера
        self._COL_DEFS = [
            ("name",    "ПРОЦЕС",  148, "w"),
            ("cpu",     "CPU%",     50, "center"),
            ("ram_mb",  "RAM",      52, "center"),
            ("net_kb",  "NET K/s",  78, "center"),
            ("net_qos", "QoS",      50, "center"),
            ("cpu_pri", "PRIOR.",   64, "center"),
        ]
        ACTION_W = 42   # ширина колонки ДІЇ
        # Разом: 148+50+52+78+50+64+42 + 6 роздільників = 490px

        cols = tk.Frame(card, bg=HDR_BG,
                        highlightbackground=HDR_BORDER, highlightthickness=1)
        cols.grid(row=3, column=0, padx=10, pady=(2, 0), sticky="ew")

        self._col_btns = {}

        for i, (key, label, px, anchor) in enumerate(self._COL_DEFS):
            if i > 0:
                tk.Frame(cols, bg="#1e1e3a", width=1).pack(
                    side="left", fill="y", pady=4)

            cell = tk.Frame(cols, bg=HDR_BG, width=px)
            cell.pack_propagate(False)
            cell.pack(side="left")

            btn = tk.Button(
                cell, text=label,
                font=("Consolas", 11, "bold"),
                fg="#8b7cf8", bg=HDR_BG,
                activeforeground="#e0d0ff", activebackground="#1a0a4a",
                relief="flat", bd=0, cursor="hand2",
                anchor=anchor, padx=0,
                command=self._make_sort_fn(key),
            )
            btn.pack(fill="both", expand=True, ipady=5)
            self._col_btns[key] = btn

        # ДІЇ
        tk.Frame(cols, bg="#1e1e3a", width=1).pack(side="left", fill="y", pady=4)
        act_cell = tk.Frame(cols, bg=HDR_BG, width=ACTION_W)
        act_cell.pack_propagate(False)
        act_cell.pack(side="left")
        tk.Label(act_cell, text="ДІЇ", font=("Consolas", 11, "bold"),
                 fg="#3a3a6a", bg=HDR_BG, anchor="center"
                 ).pack(fill="both", expand=True, ipady=5)

        self._refresh_col_headers()

        # ── Canvas Virtual Scroller (замість CTkScrollableFrame) ──────────
        # Плавне гортання завдяки нативним tk-віджетам і canvas scroll
        _BG = "#0a0a14"
        scroll_outer = tk.Frame(card, bg=_BG)
        scroll_outer.grid(row=4, column=0, padx=6, pady=(0, 8), sticky="nsew")
        scroll_outer.grid_rowconfigure(0, weight=1)
        scroll_outer.grid_columnconfigure(0, weight=1)

        self._proc_canvas = tk.Canvas(
            scroll_outer, bg=_BG, highlightthickness=0, bd=0
        )

        # ── Кастомний Canvas-скролер в стилі утиліти ─────────────────────
        _SB_W   = 6          # ширина треку
        _SB_BG  = "#0d0d1a"  # колір треку
        _SB_FG  = "#7c3aed"  # колір повзунка (фіолетовий акцент)
        _SB_HOV = "#a855f7"  # hover

        _sb_canvas = tk.Canvas(
            scroll_outer, width=_SB_W + 4, bg=_SB_BG,
            highlightthickness=0, bd=0, cursor="hand2"
        )
        _sb_canvas.grid(row=0, column=1, sticky="ns", padx=(1, 0))
        self._proc_canvas.grid(row=0, column=0, sticky="nsew")

        # Стан повзунка
        _sb_state = {"dragging": False, "drag_y": 0, "thumb_y1": 0, "thumb_y2": 0}

        def _sb_draw():
            """Перемальовує повзунок відповідно до поточної позиції canvas."""
            _sb_canvas.delete("all")
            h = _sb_canvas.winfo_height()
            if h < 2:
                return
            # Трек
            _sb_canvas.create_rectangle(
                2, 0, _SB_W + 2, h,
                fill=_SB_BG, outline="", tags="track"
            )
            # Визначаємо позицію thumb через yview
            try:
                top, bot = self._proc_canvas.yview()
            except Exception:
                return
            if bot - top >= 1.0:
                return  # весь контент видимий — не малюємо thumb
            thumb_h = max(20, int(h * (bot - top)))
            thumb_y = int(h * top)
            y1, y2 = thumb_y, thumb_y + thumb_h
            _sb_state["thumb_y1"] = y1
            _sb_state["thumb_y2"] = y2
            # Заокруглений thumb
            r = _SB_W // 2
            _sb_canvas.create_oval(
                2, y1, _SB_W + 2, y1 + _SB_W,
                fill=_SB_FG, outline="", tags="thumb"
            )
            _sb_canvas.create_rectangle(
                2, y1 + r, _SB_W + 2, y2 - r,
                fill=_SB_FG, outline="", tags="thumb"
            )
            _sb_canvas.create_oval(
                2, y2 - _SB_W, _SB_W + 2, y2,
                fill=_SB_FG, outline="", tags="thumb"
            )

        def _sb_set(first, last):
            """Викликається canvas при зміні yview — просто перемальовує thumb."""
            _sb_draw()

        def _sb_on_press(e):
            y = e.y
            if _sb_state["thumb_y1"] <= y <= _sb_state["thumb_y2"]:
                _sb_state["dragging"] = True
                _sb_state["drag_y"] = y
                _sb_state["last_draw_ms"] = 0.0
            else:
                # Клік по треку — переходимо туди
                h = _sb_canvas.winfo_height()
                if h > 0:
                    frac = y / h
                    self._proc_canvas.yview_moveto(frac)
                    _sb_draw()

        def _sb_on_drag(e):
            if not _sb_state["dragging"]:
                return
            h = _sb_canvas.winfo_height()
            if h <= 0:
                return

            import time as _time
            now_ms = _time.monotonic() * 1000
            # Throttle до 60 fps — не перемальовуємо частіше ніж 16ms
            if now_ms - _sb_state.get("last_draw_ms", 0) < 16:
                return
            _sb_state["last_draw_ms"] = now_ms

            dy   = e.y - _sb_state["drag_y"]
            _sb_state["drag_y"] = e.y
            self._proc_canvas.yview_scroll(int(dy / 2) or (1 if dy > 0 else -1), "units")
            _sb_draw()

        def _sb_on_release(e):
            _sb_state["dragging"] = False

        def _sb_on_hover(e):
            _sb_canvas.itemconfig("thumb", fill=_SB_HOV)

        def _sb_on_leave(e):
            _sb_canvas.itemconfig("thumb", fill=_SB_FG)

        _sb_canvas.bind("<ButtonPress-1>",   _sb_on_press)
        _sb_canvas.bind("<B1-Motion>",       _sb_on_drag)
        _sb_canvas.bind("<ButtonRelease-1>", _sb_on_release)
        _sb_canvas.bind("<Enter>",           _sb_on_hover)
        _sb_canvas.bind("<Leave>",           _sb_on_leave)
        _sb_canvas.bind("<Configure>",       lambda e: _sb_draw())

        self._proc_canvas.configure(yscrollcommand=_sb_set)
        self._proc_vbar = _sb_canvas   # зберігаємо ref для сумісності
        self._sb_draw   = _sb_draw     # щоб викликати ззовні при оновленні

        # Внутрішній фрейм для рядків процесів
        self._proc_inner = tk.Frame(self._proc_canvas, bg=_BG)
        self._proc_window = self._proc_canvas.create_window(
            (0, 0), window=self._proc_inner, anchor="nw"
        )
        self._proc_inner.bind(
            "<Configure>",
            lambda e: self._proc_canvas.configure(
                scrollregion=self._proc_canvas.bbox("all")
            )
        )
        self._proc_canvas.bind(
            "<Configure>",
            lambda e: self._proc_canvas.itemconfigure(
                self._proc_window, width=e.width
            )
        )
        # Плавне гортання мишею
        def _on_mousewheel(e):
            self._proc_canvas.yview_scroll(int(-1 * (e.delta / 60)), "units")
        def _on_scroll_linux_up(e):
            self._proc_canvas.yview_scroll(-2, "units")
        def _on_scroll_linux_down(e):
            self._proc_canvas.yview_scroll(2, "units")

        self._proc_canvas.bind("<MouseWheel>", _on_mousewheel)
        self._proc_inner.bind("<MouseWheel>", _on_mousewheel)
        self._proc_canvas.bind("<Button-4>", _on_scroll_linux_up)
        self._proc_canvas.bind("<Button-5>", _on_scroll_linux_down)
        # Прокидаємо scroll від дочірніх віджетів
        self._scroll_fn = _on_mousewheel
        # Відкладаємо перший скан на 300мс — щоб mainloop встиг запуститись
        self.after(300, self._refresh_processes)

    # ═══════════════════════════════════════════════════════════════════════
    #  ЗАВАНТАЖЕННЯ ІСНУЮЧИХ NET-ПРІОРИТЕТІВ
    # ═══════════════════════════════════════════════════════════════════════

    def _load_net_priorities(self):
        """Читає існуючі QoS та bandwidth-limit правила при старті."""
        try:
            existing = self.engine.get_all_network_priorities()
            if existing:
                self._net_priority_map.update(existing)
                self._safe_after(lambda: self._log(
                    f"  🌐 Завантажено {len(existing)} QoS правил"
                ))
        except Exception:
            pass
        try:
            limits = self.engine.get_all_bandwidth_limits()
            if limits:
                self._bandwidth_limit_map.update(limits)
                self._safe_after(lambda: self._log(
                    f"  🚧 Завантажено {len(limits)} лімітів швидкості"
                ))
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    #  КНОПКИ HEADER
    # ═══════════════════════════════════════════════════════════════════════

    def _on_toggle(self):
        self._game_mode_active = not self._game_mode_active

        if self._game_mode_active:
            self._btn_toggle.configure(
                text="⏹  DEACTIVATE GAME MODE",
                fg_color="#0d1a0d", hover_color="#1a2d1a",
                text_color=COLORS["accent_green"],
                border_color=COLORS["accent_green"],
            )
            self._lbl_status.configure(
                text="⬤  GAME MODE ACTIVE",
                text_color=COLORS["accent_green"]
            )
            self._log("\n> 🚀 GAME MODE ACTIVATED")
            self._log("> 🛡️ Захищені процеси: ігри, лаунчери, система")

            threading.Thread(
                target=self.engine.apply_network_tweaks,
                kwargs={"log_cb": lambda t: self._safe_after(lambda: self._log(t))},
                daemon=True
            ).start()
            self.engine.start_auto_mode(
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )

            if not self._ping_running:
                self._toggle_ping()
        else:
            self._btn_toggle.configure(
                text="🚀  ACTIVATE GAME MODE",
                fg_color="#2d0a5a", hover_color="#4a0d8a",
                text_color=COLORS["accent_purple"],
                border_color=COLORS["accent_purple"],
            )
            self._lbl_status.configure(
                text="⬤  РЕЖИМ ВИМКНЕНИЙ",
                text_color=COLORS["text_secondary"]
            )
            self._log("\n> ⏹ GAME MODE DEACTIVATED")
            self.engine.stop_auto_mode()

            if self._ping_running:
                self._toggle_ping()

    def _on_restore(self):
        self._log("\n> 🔄 Відновлення налаштувань...")
        threading.Thread(
            target=self.engine.restore_defaults,
            kwargs={"log_cb": lambda t: self._safe_after(lambda: self._log(t))},
            daemon=True
        ).start()
        # Відновлюємо ping tweaks
        threading.Thread(
            target=self.engine.restore_ping_tweaks,
            kwargs={"log_cb": lambda t: self._safe_after(lambda: self._log(t))},
            daemon=True
        ).start()
        for chk, _ in self._tweaks:
            chk.deselect()
        # Скидаємо ping checkboxes
        for label, (chk, var) in self._ping_tweak_refs.items():
            var.set(False)
        self._btn_ping_all.configure(
            text="🚀  APPLY ALL PING TWEAKS",
            text_color="#22d3ee", border_color="#22d3ee"
        )
        self._net_priority_map.clear()
        self.after(500, self._refresh_processes)

    # ═══════════════════════════════════════════════════════════════════════
    #  PING GRAPH
    # ═══════════════════════════════════════════════════════════════════════

    def _toggle_ping(self):
        self._ping_running = not self._ping_running
        if self._ping_running:
            self._btn_ping.configure(text="⏹ Stop", text_color=COLORS["accent_red"],
                                     border_color=COLORS["accent_red"])
            threading.Thread(target=self._ping_loop, daemon=True).start()
        else:
            self._btn_ping.configure(text="▶ Start", text_color=COLORS["accent_green"],
                                     border_color=COLORS["accent_green"])

    def _ping_loop(self):
        """FIX: паралельний пінг через ThreadPoolExecutor. fast=True = 1 пакет 500мс.
        Всі сервери пінгуються одночасно — не блокує UI між ітераціями."""
        import concurrent.futures
        while self._ping_running:
            # Тільки увімкнені сервери
            enabled = {
                name: host for name, host in PING_TARGETS.items()
                if self._server_enabled.get(name, tk.BooleanVar(value=True)).get()
            }
            results: dict[str, float | None] = {}

            def _measure(item):
                name, host = item
                return name, self.engine.ping_ms(host, fast=True)

            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                    futs = {ex.submit(_measure, item): item[0] for item in enabled.items()}
                    done, _ = concurrent.futures.wait(futs, timeout=6)
                    for fut in done:
                        try:
                            name, ms = fut.result()
                            results[name] = ms
                            if ms is not None:
                                history = self._ping_history[name]
                                history.append(ms)
                                if len(history) > GRAPH_POINTS:
                                    history.pop(0)
                        except Exception:
                            pass
            except Exception:
                pass

            self._safe_after(lambda r=dict(results): self._update_ping_ui(r))
            time.sleep(3)

    def _update_ping_ui(self, results: dict):
        for name, ms in results.items():
            lbl = self._ping_value_labels.get(name)
            if lbl:
                color = self._ping_ms_color(ms)
                lbl.configure(text=f"{ms:.0f} ms", text_color=color)
        self._draw_ping_graph()

    def _ping_ms_color(self, ms: float) -> str:
        if ms < 50:   return COLORS.get("accent_green",  "#22c55e")
        elif ms < 100: return COLORS.get("accent_yellow", "#eab308")
        return COLORS.get("accent_red", "#ef4444")

    def _draw_ping_graph(self):
        canvas = self._graph_canvas
        canvas.delete("all")
        w = canvas.winfo_width()
        h = canvas.winfo_height()
        if w < 10 or h < 10:
            return

        padding = {"left": 36, "right": 8, "top": 8, "bottom": 18}
        plot_w = w - padding["left"] - padding["right"]
        plot_h = h - padding["top"] - padding["bottom"]

        grid_color = "#1e1e3a"
        max_ms = 200

        for ms_val in [0, 50, 100, 150, 200]:
            y = padding["top"] + plot_h - (ms_val / max_ms) * plot_h
            canvas.create_line(
                padding["left"], y, w - padding["right"], y,
                fill=grid_color, dash=(3, 6)
            )
            canvas.create_text(
                padding["left"] - 4, y,
                text=str(ms_val), fill="#444466",
                font=("Consolas", 10), anchor="e"
            )

        canvas.create_line(
            padding["left"], padding["top"],
            padding["left"], h - padding["bottom"],
            fill="#333355"
        )
        canvas.create_line(
            padding["left"], h - padding["bottom"],
            w - padding["right"], h - padding["bottom"],
            fill="#333355"
        )

        for name, color in self._ping_colors.items():
            # FIX: малюємо тільки увімкнені сервери
            if not self._server_enabled.get(name, tk.BooleanVar(value=True)).get():
                continue
            history = self._ping_history.get(name, [])
            if len(history) < 2:
                continue
            n    = len(history)
            step = plot_w / (GRAPH_POINTS - 1)
            points = []
            for i, ms in enumerate(history):
                offset = GRAPH_POINTS - n
                x = padding["left"] + (offset + i) * step
                y_val = min(ms, max_ms)
                y = padding["top"] + plot_h - (y_val / max_ms) * plot_h
                points.extend([x, y])

            if len(points) >= 4:
                canvas.create_line(*points, fill=color, width=1.5, smooth=True)

            if points:
                lx, ly = points[-2], points[-1]
                r = 3
                canvas.create_oval(
                    lx - r, ly - r, lx + r, ly + r,
                    fill=color, outline=""
                )

    # ═══════════════════════════════════════════════════════════════════════
    #  СПИСОК ПРОЦЕСІВ
    # ═══════════════════════════════════════════════════════════════════════

    def _refresh_col_headers(self):
        arrow = " ▲" if self._sort_asc else " ▼"
        base = {
            "name":    "ПРОЦЕС",
            "cpu":     "CPU %",
            "ram_mb":  "RAM",
            "net_kb":  "NET KB/s",
            "net_qos": "QoS▲",
            "cpu_pri": "ПРІОРИТЕТ",
        }
        for key, btn in self._col_btns.items():
            active = (key == self._sort_col)
            btn.configure(
                text=base.get(key, key) + (arrow if active else ""),
                fg="#e0d0ff" if active else "#8b7cf8",
                bg="#1a0a4a" if active else "#0d0d22",
                command=self._make_sort_fn(key),
            )

    def _make_sort_fn(self, key: str):
        def _fn():
            if self._sort_col == key:
                self._sort_asc = not self._sort_asc
            else:
                self._sort_col = key
                self._sort_asc = (key == "name")
            self._refresh_col_headers()
            self._apply_filter()
        return _fn

    def _set_filter(self, value: str):
        self._active_filter = value
        for val, btn in self._filter_btn_refs.items():
            btn.configure(
                fg_color=COLORS["accent_purple"] if val == value
                else COLORS["bg_secondary"]
            )
        self._apply_filter()

    def _apply_filter(self):
        if not self._all_procs:
            return
        query = self._search_var.get().lower().strip()
        filt  = self._active_filter
        filtered = [
            p for p in self._all_procs
            if (filt == "all" or p["category"] == filt)
            and (not query or query in p["name"].lower())
        ]
        # ── Сортування ──
        col = getattr(self, "_sort_col", "ram_mb")
        asc = getattr(self, "_sort_asc", False)
        if col == "name":
            filtered.sort(key=lambda p: p.get("name", "").lower(), reverse=not asc)
        elif col == "cpu":
            filtered.sort(key=lambda p: p.get("cpu", 0), reverse=not asc)
        elif col == "ram_mb":
            filtered.sort(key=lambda p: p.get("ram_mb", 0), reverse=not asc)
        elif col == "net_kb":
            filtered.sort(key=lambda p: p.get("net_kb", 0), reverse=not asc)
        elif col == "net_qos":
            _qos_ord = {"maximum": 0, "high": 1, "normal": 2, "low": 3, None: 4}
            filtered.sort(key=lambda p: _qos_ord.get(
                self._net_priority_map.get(p.get("name","").lower()), 4), reverse=not asc)
        elif col == "cpu_pri":
            _pri_order = {"High": 0, "AboveNormal": 1, "Normal": 2, "BelowNormal": 3, "Idle": 4}
            filtered.sort(key=lambda p: _pri_order.get(p.get("cpu_priority", "Normal"), 2),
                          reverse=not asc)
        # FIX: after(0) — не блокуємо поточний обробник події (кліки по заголовку колонки)
        self.after(0, lambda f=filtered: self._render_procs(f))

    def _refresh_processes(self):
        """Запускає сканування у фоновому потоці з обробкою помилок."""
        # Анімуємо кнопку
        try:
            self._btn_refresh_proc.configure(
                text="⏳  Сканування...", state="disabled",
                text_color="#64748b",
            )
        except Exception:
            pass

        # FIX: frame swap замість w.destroy() — O(1)
        _BG = "#0a0a14"
        self._render_token += 1
        new_inner = tk.Frame(self._proc_canvas, bg=_BG)
        new_inner.bind(
            "<Configure>",
            lambda e: self._proc_canvas.configure(scrollregion=self._proc_canvas.bbox("all"))
        )
        new_inner.bind("<MouseWheel>", self._scroll_fn)
        old_inner = self._proc_inner
        self._proc_inner = new_inner
        self._proc_canvas.itemconfigure(self._proc_window, window=new_inner)
        self._proc_row_widgets.clear()
        self.after(200, lambda w=old_inner: w.destroy() if w.winfo_exists() else None)
        try:
            self._proc_canvas.yview_moveto(0)
        except Exception:
            pass

        self._scan_waiting_lbl = tk.Label(
            self._proc_inner,
            text="⏳  Сканування процесів...",
            bg="#0a0a14", fg=COLORS["text_dim"],
            font=("Consolas", 13),
        )
        self._scan_waiting_lbl.pack(pady=30)

        # Анімація крапок — показує що процес іде
        self._scan_anim_step = 0
        self._scan_anim_id   = None

        def _animate():
            if not hasattr(self, '_scan_waiting_lbl'):
                return
            try:
                dots = "." * (self._scan_anim_step % 4)
                self._scan_waiting_lbl.configure(
                    text=f"⏳  Сканування{dots}"
                )
                self._scan_anim_step += 1
                self._scan_anim_id = self.after(400, _animate)
            except Exception:
                pass

        self._scan_anim_id = self.after(400, _animate)

        # ── Watchdog 8с ────────────────────────────────────────────────
        self._scan_done_flag = False

        def _watchdog():
            if not self._scan_done_flag:
                self._safe_after(lambda: self._on_scan_error(
                    "Сканування зависло (8с).\n"
                    "Спробуй запустити від Адміністратора,\n"
                    "або тимчасово вимкни антивірус."
                ))

        self._watchdog_timer = self.after(8_000, _watchdog)

        def scan():
            try:
                procs = self.engine.scan_processes()
                method = getattr(self.engine, "_last_scan_method", "")
                self._scan_done_flag = True
                self._safe_after(lambda p=procs, m=method: self._on_scan_done(p, m))
            except Exception as e:
                self._scan_done_flag = True
                self._safe_after(lambda err=str(e): self._on_scan_error(err))

        threading.Thread(target=scan, daemon=True, name="scan").start()

    def _on_scan_done(self, procs: list, method: str = ""):
        # Скасовуємо watchdog і анімацію
        if hasattr(self, '_watchdog_timer'):
            try: self.after_cancel(self._watchdog_timer)
            except Exception: pass
        if hasattr(self, '_scan_anim_id') and self._scan_anim_id:
            try: self.after_cancel(self._scan_anim_id)
            except Exception: pass
        self._scan_anim_id = None

        # Відновлюємо кнопку оновлення
        try:
            self._btn_refresh_proc.configure(
                text="🔄  Оновити", state="normal",
                text_color="#38bdf8",
            )
        except Exception:
            pass

        self._all_procs = procs

        if not procs:
            self._on_scan_error("Процеси не знайдено. Переконайся що запущено від Адміністратора.")
            return

        counts = {}
        for p in procs:
            counts[p["category"]] = counts.get(p["category"], 0) + 1

        total   = len(procs)
        summary = (
            f"Всього: {total}  ·  "
            f"⚠️{counts.get('hog',0)} "
            f"🌐{counts.get('browser',0)} "
            f"💬{counts.get('messenger',0)} "
            f"🎵{counts.get('media',0)} "
            f"🎮{counts.get('game',0)+counts.get('launcher',0)}"
        )
        self._lbl_proc_count.configure(text=summary)

        if method:
            self._log(f"  ℹ️ Сканування: {method}")

        self._apply_filter()

        # ── CPU% через psutil — окремий потік, не блокує UI ───────────────
        # Запускаємо після рендеру: читаємо nice + cpu_percent з інтервалом
        threading.Thread(
            target=self._enrich_cpu, args=(list(procs),), daemon=True, name="cpu_enrich"
        ).start()

    def _enrich_cpu(self, procs: list):
        """
        Фоновий потік: CPU%, I/O KB/s (мережа+диск), CPU priority.
        Використовує io_counters() — надійніший ніж net_connections (не падає від AccessDenied).
        """
        try:
            import psutil
        except ImportError:
            return

        cpu_count = max(1, psutil.cpu_count(logical=True) or 1)

        # Snapshot 1 — ініціалізуємо CPU та I/O лічильники
        snap:    dict = {}
        io_snap: dict = {}  # {pid: (read_bytes, write_bytes)}

        for item in procs:
            pid = item.get("pid", 0)
            if pid <= 4:
                continue
            try:
                p = psutil.Process(pid)
                p.cpu_percent(interval=None)
                snap[pid] = p
                io = p.io_counters()
                io_snap[pid] = (io.read_bytes, io.write_bytes)
            except Exception:
                pass

        time.sleep(0.7)  # 700ms для точного I/O delta

        updates = []
        for item in procs:
            pid = item.get("pid", 0)
            p   = snap.get(pid)
            if not p:
                continue

            try:
                cpu  = round(p.cpu_percent(interval=None) / cpu_count, 1)
                nice = p.nice()
                pri  = _NICE_TO_PRIORITY_UI.get(nice, "Normal")
            except Exception:
                cpu, pri = 0.0, "Normal"

            # I/O KB/s — дельта за 0.7с (включає мережу і диск)
            net_kb = 0.0
            try:
                io_new = p.io_counters()
                io_old = io_snap.get(pid)
                if io_old:
                    delta  = (io_new.read_bytes  - io_old[0]) + \
                             (io_new.write_bytes - io_old[1])
                    net_kb = round((delta / 0.7) / 1024, 1)  # KB/s
            except Exception:
                pass

            item["cpu"]          = cpu
            item["net_kb"]       = max(0.0, net_kb)
            item["cpu_priority"] = pri

            updates.append((pid, cpu, net_kb, pri))

        # Оновлення UI через чергу
        for pid, cpu, net_kb, pri in updates:
            def _update(pid=pid, cpu=cpu, net_kb=net_kb, pri=pri):
                row = self._proc_row_widgets.get(pid)
                if not row:
                    return
                try:
                    if not row.winfo_exists():
                        return
                except Exception:
                    return

                def gc(col):
                    # FIX: використовуємо збережені refs замість grid_slaves
                    if col == 2: return getattr(row, "_cpu_lbl", None)
                    if col == 6: return getattr(row, "_net_lbl", None)
                    if col == 10: return getattr(row, "_pri_lbl", None)
                    return None

                # CPU% — col 2
                cpu_lbl = gc(2)
                if cpu_lbl:
                    try:
                        c    = "#ff4444" if cpu > 15 else "#ffaa00" if cpu > 5 else "#4a5568"
                        bg_c = "#1a0000" if cpu > 15 else "#131000" if cpu > 5 else row.cget("bg")
                        cpu_lbl.configure(text=f"{cpu:.0f}%", fg=c, bg=bg_c)
                    except Exception:
                        pass

                # I/O KB/s — col 6
                net_lbl = gc(6)
                if net_lbl:
                    try:
                        if net_kb >= 1024:
                            ns = f"{net_kb/1024:.1f} M/s"
                        elif net_kb > 0:
                            ns = f"{net_kb:.0f} K/s"
                        else:
                            ns = "\u2014"
                        nc = ("#ef4444" if net_kb > 1024 else
                              "#f97316" if net_kb > 200  else
                              "#38bdf8" if net_kb > 0    else "#2a3a5a")
                        net_lbl.configure(text=ns, fg=nc)
                    except Exception:
                        pass

                # CPU пріоритет — col 10
                if not self._proc_priority_map.get(pid):
                    pri_lbl = gc(10)
                    if pri_lbl:
                        try:
                            pri_lbl.configure(
                                text=PRIORITY_LABELS.get(pri, "\u00b7 NRM"),
                                fg=PRIORITY_COLORS.get(pri, "#2d3748")
                            )
                        except Exception:
                            pass

            self._safe_after(_update)

    def _on_scan_error(self, error: str):
        """Показує помилку сканування з підказкою. Викликається через self.after() → safe."""
        if hasattr(self, '_watchdog_timer'):
            try: self.after_cancel(self._watchdog_timer)
            except Exception: pass
        if hasattr(self, '_scan_anim_id') and self._scan_anim_id:
            try: self.after_cancel(self._scan_anim_id)
            except Exception: pass
        self._scan_anim_id = None
        # FIX: frame swap
        _BG = "#0a0a14"
        self._render_token += 1
        new_inner = tk.Frame(self._proc_canvas, bg=_BG)
        new_inner.bind("<Configure>",
            lambda e: self._proc_canvas.configure(scrollregion=self._proc_canvas.bbox("all")))
        old_inner = self._proc_inner
        self._proc_inner = new_inner
        self._proc_canvas.itemconfigure(self._proc_window, window=new_inner)
        self._proc_row_widgets.clear()
        self.after(200, lambda w=old_inner: w.destroy() if w.winfo_exists() else None)
        err_frame = tk.Frame(self._proc_inner, bg="#1a0a0a", bd=1, relief="flat",
                             highlightbackground=COLORS["accent_red"],
                             highlightthickness=1)
        err_frame.pack(pady=20, padx=10, fill="x")

        tk.Label(err_frame, text="❌  Помилка сканування",
                 bg="#1a0a0a", fg=COLORS["accent_red"],
                 font=("Consolas", 13, "bold")).pack(pady=(16, 4))

        tk.Label(err_frame, text=error[:200],
                 bg="#1a0a0a", fg=COLORS["text_secondary"],
                 font=("Consolas", 11), wraplength=280, justify="center").pack(pady=(0, 8))

        tk.Label(err_frame,
                 text="💡 Поради:\n"
                      "• Запусти NetGuardian від Адміністратора\n"
                      "• Встанови psutil: pip install psutil\n"
                      "• Натисни 🔄 щоб спробувати ще раз",
                 bg="#1a0a0a", fg=COLORS["text_dim"],
                 font=("Consolas", 11), justify="left").pack(pady=(0, 16))

        ctk.CTkButton(
            err_frame, text="🔄  Повторити сканування",
            command=self._refresh_processes,
            fg_color=COLORS["bg_secondary"],
            hover_color=COLORS["accent_purple"] + "33",
            text_color=COLORS["accent_purple"],
            font=ctk.CTkFont(family="Consolas", size=12),
            height=32, corner_radius=8,
            border_width=1, border_color=COLORS["accent_purple"]
        ).pack(pady=(0, 16))

    def _render_procs(self, procs: list):
        """FIX: O(1) swap inner frame замість O(n) destroy 1500+ widget-ів.
        render_token скасовує попередні chunked-render якщо прийшов новий."""
        self._render_token += 1
        token = self._render_token

        _BG     = "#0a0a14"
        _BG_ALT = "#0e0e1a"

        # Новий inner frame — O(1) замість w.destroy() у циклі
        new_inner = tk.Frame(self._proc_canvas, bg=_BG)
        new_inner.bind(
            "<Configure>",
            lambda e: self._proc_canvas.configure(scrollregion=self._proc_canvas.bbox("all"))
        )
        new_inner.bind("<MouseWheel>", self._scroll_fn)

        old_inner = self._proc_inner
        self._proc_inner = new_inner
        self._proc_canvas.itemconfigure(self._proc_window, window=new_inner)
        self._proc_row_widgets.clear()
        self._proc_canvas.yview_moveto(0)

        # Знищуємо старий фрейм відкладено — не блокуємо UI
        self.after(300, lambda w=old_inner: w.destroy() if w.winfo_exists() else None)
        _BG_GAME  = "#061206"      # темно-зелений фон для ігор
        _BG_LAUN  = "#080612"      # темно-фіолетовий для лаунчерів
        _BG_HOG   = "#120606"      # темно-червоний для пожирачів

        CAT_COLORS = {
            "hog":       "#ef4444",
            "browser":   "#38bdf8",
            "messenger": "#a78bfa",
            "media":     "#4ade80",
            "game":      "#22ff88",   # яскравіший зелений для ігор
            "launcher":  "#a855f7",   # фіолетовий для лаунчерів
            "dangerous": "#ff6b35",
            "protected": "#64748b",
            "normal":    "#94a3b8",
        }
        CAT_ICONS = {
            "hog": "⚠", "browser": "🌐", "messenger": "💬",
            "media": "🎵", "game": "🎮", "launcher": "🚀",
            "dangerous": "☠", "protected": "🛡", "normal": "·",
        }
        CAT_BG = {
            "game":    _BG_GAME,
            "launcher": _BG_LAUN,
            "hog":     _BG_HOG,
        }

        if not procs:
            tk.Label(
                self._proc_inner, text="Нічого не знайдено",
                bg=_BG, fg=COLORS["text_dim"],
                font=("Consolas", 13),
            ).pack(pady=20)
            return

        # ─── Заголовок "ІГРИ & ЛАУНЧЕРИ" якщо є ──────────────────────
        games_and_launchers = [p for p in procs if p.get("category") in ("game", "launcher")]
        if games_and_launchers:
            sep = tk.Frame(self._proc_inner, bg="#1a0a3a", height=1)
            sep.pack(fill="x", padx=4, pady=(4, 0))
            tk.Label(self._proc_inner,
                     text="  🎮  ІГРИ  &  ЛАУНЧЕРИ",
                     bg="#0a0614", fg="#a855f7",
                     font=("Consolas", 11, "bold"),
                     anchor="w").pack(fill="x", padx=6, pady=(2, 2))
            sep2 = tk.Frame(self._proc_inner, bg="#1a0a3a", height=1)
            sep2.pack(fill="x", padx=4, pady=(0, 2))

        # Рендеримо порціями (chunk) щоб не блокувати UI
        def _render_chunk(items, idx=0):
            # FIX: перевіряємо токен — якщо прийшов новий render, скасовуємо цей
            if self._render_token != token:
                return
            CHUNK = 25
            for proc in items[idx: idx + CHUNK]:
                self._render_one_row(proc, CAT_COLORS, CAT_ICONS, CAT_BG, _BG, _BG_ALT)
            if idx + CHUNK < len(items):
                self.after(16, lambda i=idx + CHUNK: _render_chunk(items, i))
            else:
                if hasattr(self, '_sb_draw'):
                    self.after(50, self._sb_draw)

        _render_chunk(procs)

    def _render_one_row(self, proc: dict,
                         CAT_COLORS: dict, CAT_ICONS: dict, CAT_BG: dict,
                         _BG: str, _BG_ALT: str):
        """Рендерить один рядок процесу. pack+pack_propagate(False) = pixel-perfect вирівнювання."""
        cat   = proc.get("category", "normal")
        color = CAT_COLORS.get(cat, "#94a3b8")
        icon  = CAT_ICONS.get(cat, "·")
        pid   = proc["pid"]
        name  = proc["name"]

        row_count = len(self._proc_row_widgets)
        bg = CAT_BG.get(cat, _BG if row_count % 2 == 0 else _BG_ALT)

        is_protected = proc.get("protected", False)
        net_level    = self._net_priority_map.get(name.lower())
        net_color    = NET_PRIORITY_COLORS.get(net_level, "#4a4a7a")

        ROW_H = 28   # висота рядка в пікселях — однакова для всіх клітинок

        row = tk.Frame(self._proc_inner, bg=bg, cursor="hand2")
        row.pack(fill="x", pady=0, padx=0)
        tk.Frame(self._proc_inner, bg="#14142a", height=1).pack(fill="x")
        self._proc_row_widgets[pid] = row
        sf = self._scroll_fn
        row.bind("<MouseWheel>", sf)

        # ── helper: фіксована клітинка ────────────────────────────────────
        def cell(width: int, bg_c: str = bg) -> tk.Frame:
            f = tk.Frame(row, bg=bg_c, width=width, height=ROW_H)
            f.pack_propagate(False)   # КЛЮЧОВЕ: фрейм не стискається/розтягується
            f.pack(side="left")
            f.bind("<MouseWheel>", sf)
            return f

        def div() -> None:
            f = tk.Frame(row, bg="#1e1e3a", width=1, height=ROW_H)
            f.pack(side="left", fill="y")
            f.bind("<MouseWheel>", sf)

        # ── COL: ПРОЦЕС (148px) ───────────────────────────────────────────
        c = cell(148)
        nl = tk.Label(c, text=f"{icon} {name[:16]}", fg=color, bg=bg,
                      font=("Consolas", 11), anchor="w", cursor="hand2", padx=5)
        nl.pack(fill="both", expand=True)
        nl.bind("<MouseWheel>", sf)
        nl.bind("<Button-1>", lambda e, p=proc: self._show_impact(p))

        div()

        # ── COL: CPU% (50px) ─────────────────────────────────────────────
        cpu    = proc.get("cpu", 0)
        cpu_fg = "#ff4444" if cpu > 15 else "#ffaa00" if cpu > 5 else "#4a5568"
        cpu_bg = "#1a0000" if cpu > 15 else "#131000" if cpu > 5 else bg
        c = cell(50, cpu_bg)
        cpu_lbl = tk.Label(c, text=f"{cpu:.0f}%", fg=cpu_fg, bg=cpu_bg,
                           font=("Consolas", 11, "bold"), anchor="center")
        cpu_lbl.pack(fill="both", expand=True)
        cpu_lbl.bind("<MouseWheel>", sf)
        row._cpu_lbl = cpu_lbl  # type: ignore

        div()

        # ── COL: RAM (52px) ──────────────────────────────────────────────
        ram     = proc.get("ram_mb", 0)
        ram_txt = f"{ram:.0f}M" if ram < 1024 else f"{ram/1024:.1f}G"
        ram_fg  = "#94a3b8" if ram < 500 else "#eab308" if ram < 1000 else "#ef4444"
        c = cell(52)
        tk.Label(c, text=ram_txt, fg=ram_fg, bg=bg,
                 font=("Consolas", 11), anchor="center").pack(fill="both", expand=True)

        div()

        # ── COL: NET K/s (78px) ──────────────────────────────────────────
        net_kb  = proc.get("net_kb", 0.0)
        net_str = (f"{net_kb/1024:.1f}M/s" if net_kb >= 1024 else
                   f"{net_kb:.0f}K/s"      if net_kb >= 1    else "—")
        net_fg  = ("#ef4444" if net_kb > 500 else
                   "#f97316" if net_kb > 100 else
                   "#38bdf8" if net_kb > 0   else "#2a3a5a")
        c = cell(78)
        net_lbl = tk.Label(c, text=net_str, fg=net_fg, bg=bg,
                           font=("Consolas", 11, "bold"), anchor="center", cursor="hand2")
        net_lbl.pack(fill="both", expand=True)
        net_lbl.bind("<MouseWheel>", sf)
        net_lbl.bind("<Button-1>", lambda e, p=proc: self._net_priority_popup(p))
        row._net_lbl = net_lbl  # type: ignore

        div()

        # ── COL: QoS (50px) ──────────────────────────────────────────────
        qos_bg  = "#0d1a30" if net_level else bg
        qos_txt = NET_PRIORITY_LABELS.get(net_level, "· —")
        c = cell(50, qos_bg)
        net_btn = tk.Button(c, text=qos_txt, bg=qos_bg, fg=net_color,
                            font=("Consolas", 10, "bold"), relief="flat", bd=0,
                            cursor="hand2", anchor="center",
                            activebackground="#1a0a3a", activeforeground="#c084fc",
                            command=lambda p=proc: self._net_priority_popup(p))
        net_btn.pack(fill="both", expand=True)
        net_btn.bind("<MouseWheel>", sf)
        row._net_btn = net_btn  # type: ignore

        div()

        # ── COL: PRIOR. (64px) ───────────────────────────────────────────
        scanned_pri  = proc.get("cpu_priority", "")
        cur_priority = self._proc_priority_map.get(pid) or scanned_pri
        pri_text  = PRIORITY_LABELS.get(cur_priority, "· NRM")
        pri_color = PRIORITY_COLORS.get(cur_priority, "#2d3748")
        c = cell(64)
        pri_lbl = tk.Label(c, text=pri_text, fg=pri_color, bg=bg,
                           font=("Consolas", 10), anchor="center")
        pri_lbl.pack(fill="both", expand=True)
        pri_lbl.bind("<MouseWheel>", sf)
        row._priority_label = pri_lbl  # type: ignore
        row._pri_lbl        = pri_lbl  # type: ignore  (alias для _enrich_cpu)

        div()

        # ── COL: ДІЇ (42px) ──────────────────────────────────────────────
        c = cell(42)
        is_dangerous = (cat == "dangerous")
        can_kill = (not is_protected and not is_dangerous
                    and cat in ("hog", "browser", "messenger", "media") and pid > 0)

        if can_kill:
            kb = tk.Button(c, text="⊘", bg=bg, fg="#ef4444",
                           font=("Consolas", 11, "bold"), relief="flat", bd=0,
                           activebackground="#2d0a0a", activeforeground="#ef4444",
                           cursor="hand2", width=2,
                           command=lambda p=proc: self._kill(p))
            kb.pack(side="left", fill="y")
            kb.bind("<MouseWheel>", sf)
        elif is_dangerous:
            wb = tk.Button(c, text="☠", bg=bg, fg="#ff6b35",
                           font=("Consolas", 11, "bold"), relief="flat", bd=0,
                           activebackground="#1a0a00", activeforeground="#ff6b35",
                           cursor="hand2", width=2,
                           command=lambda p=proc: self._warn_dangerous(p))
            wb.pack(side="left", fill="y")
            wb.bind("<MouseWheel>", sf)

        if not is_protected and pid > 0:
            ub = tk.Button(c, text="↑", bg=bg, fg=COLORS["accent_purple"],
                           font=("Consolas", 11, "bold"), relief="flat", bd=0,
                           activebackground="#1a0a3a", activeforeground=COLORS["accent_purple"],
                           cursor="hand2", width=2,
                           command=lambda p=proc: self._priority_popup(p))
            ub.pack(side="left", fill="y")
            ub.bind("<MouseWheel>", sf)

    # ═══════════════════════════════════════════════════════════════════════
    #  🆕 МЕРЕЖЕВИЙ ПРІОРИТЕТ PER-PROCESS
    # ═══════════════════════════════════════════════════════════════════════

    def _net_priority_popup(self, proc: dict):
        """
        Popup для встановлення мережевого QoS пріоритету процесу.
        Дозволяє підняти пріоритет мережі для гри → пінг падає.
        """
        name    = proc["name"]
        pid     = proc["pid"]
        cur_lvl = self._net_priority_map.get(name.lower())

        popup = tk.Toplevel(self)
        popup.title(f"🌐 Мережевий пріоритет: {name}")
        popup.geometry("420x580")
        popup.configure(bg="#0d0d1a")
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        # ── Заголовок ──
        tk.Label(popup, text="🌐  МЕРЕЖЕВИЙ ПРІОРИТЕТ",
                 bg="#0d0d1a", fg="#a855f7",
                 font=("Consolas", 14, "bold")).pack(pady=(16, 2))
        tk.Label(popup, text=name,
                 bg="#0d0d1a", fg="#ffffff",
                 font=("Consolas", 13)).pack()
        tk.Label(popup, text=f"PID: {pid}",
                 bg="#0d0d1a", fg="#555577",
                 font=("Consolas", 11)).pack()

        tk.Frame(popup, bg="#2a1a4a", height=1).pack(fill="x", padx=20, pady=8)

        # ── Пояснення ──
        tk.Label(popup,
                 text="Роутер буде обслуговувати пакети цієї програми\n"
                      "з відповідним пріоритетом (QoS DSCP tagging).",
                 bg="#0d0d1a", fg="#94a3b8",
                 font=("Consolas", 11), justify="center").pack(pady=(0, 8))

        # ── Кнопки рівнів ──
        LEVELS = [
            ("🔴 МАКСИМАЛЬНИЙ",  "maximum", "#ef4444",
             "DSCP 46 — EF. Для ігор, VoIP. Пакети йдуть першими."),
            ("🟠 ВИСОКИЙ",       "high",    "#f97316",
             "DSCP 34 — AF41. Для стрімінгу, відео-дзвінків."),
            ("🟢 НОРМАЛЬНИЙ",    "normal",  "#22c55e",
             "Без QoS — стандартний трафік. Знімає правило."),
            ("⚫ НИЗЬКИЙ",       "low",     "#64748b",
             "DSCP 8 — CS1. Фоновий трафік. Торренти, хмари."),
        ]

        for btn_text, level, btn_color, desc in LEVELS:
            is_active = (cur_lvl == level) or (cur_lvl is None and level == "normal")

            btn_frame = tk.Frame(popup, bg="#0d0d1a")
            btn_frame.pack(fill="x", padx=18, pady=3)

            # Активний рівень підсвічений
            bg_color = btn_color + "22" if is_active else "#0f0f1f"
            border   = tk.Frame(btn_frame,
                                bg=btn_color if is_active else "#2a2a4a",
                                padx=1, pady=1)
            border.pack(fill="x")

            inner = tk.Frame(border, bg=bg_color, cursor="hand2")
            inner.pack(fill="x", padx=1, pady=1)

            tk.Label(inner,
                     text=("► " if is_active else "  ") + btn_text,
                     bg=bg_color, fg=btn_color,
                     font=("Consolas", 12, "bold" if is_active else "normal"),
                     anchor="w").pack(side="left", padx=12, pady=6)

            tk.Label(inner, text=desc,
                     bg=bg_color, fg="#64748b",
                     font=("Consolas", 11), anchor="e").pack(side="right", padx=8)

            inner.bind("<Button-1>",
                       lambda e, l=level, w=popup: self._apply_net_priority(proc, l, w))
            for child in inner.winfo_children():
                child.bind("<Button-1>",
                           lambda e, l=level, w=popup: self._apply_net_priority(proc, l, w))

        tk.Frame(popup, bg="#2a1a4a", height=1).pack(fill="x", padx=20, pady=8)

        # ── Секція обмеження швидкості ─────────────────────────────
        tk.Label(popup, text="🚧  ОБМЕЖЕННЯ ШВИДКОСТІ  (Traffic Shaping)",
                 bg="#0d0d1a", fg="#f97316",
                 font=("Consolas", 11, "bold")).pack(pady=(0, 4))

        cur_limit = self._bandwidth_limit_map.get(name.lower(), 0.0)

        limits_frame = tk.Frame(popup, bg="#0d0d1a")
        limits_frame.pack(fill="x", padx=18, pady=(0, 4))

        LIMIT_PRESETS = [
            ("∞",        0.0,  "#4a4a6a"),
            ("0.5 M",    0.5,  "#ef4444"),
            ("1 M",      1.0,  "#f97316"),
            ("2 M",      2.0,  "#eab308"),
            ("5 M",      5.0,  "#22c55e"),
            ("10 M",    10.0,  "#38bdf8"),
            ("25 M",    25.0,  "#a855f7"),
        ]

        for lbl_txt, mbps, lc in LIMIT_PRESETS:
            is_cur = (cur_limit == mbps) or (cur_limit == 0.0 and mbps == 0.0)
            btn = tk.Button(
                limits_frame, text=lbl_txt,
                bg="#1a0a30" if is_cur else "#0d0d22",
                fg=lc, font=("Consolas", 11, "bold"),
                relief="flat", bd=0, cursor="hand2",
                padx=6, pady=4,
                activebackground="#1a0a4a", activeforeground=lc,
                command=lambda m=mbps, w=popup: self._apply_bandwidth_limit(proc, m, w),
            )
            btn.pack(side="left", padx=2)
            if is_cur:
                tk.Frame(limits_frame, bg=lc, height=2).place(
                    in_=btn, relx=0, rely=1.0, relwidth=1.0)

        tk.Label(popup,
                 text="∞ = без ліміту   |   значення в Мбіт/с",
                 bg="#0d0d1a", fg="#333355",
                 font=("Consolas", 10)).pack()

        tk.Frame(popup, bg="#2a1a4a", height=1).pack(fill="x", padx=20, pady=6)

        # ── Підказка про роутер ──
        tk.Label(popup,
                 text="⚠️ QoS — ефект залежить від підтримки роутером.\n"
                      "ASUS, TP-Link, MikroTik — ✅  |  Потрібен Адміністратор.",
                 bg="#0d0d1a", fg="#444466",
                 font=("Consolas", 11), justify="center").pack(pady=(0, 8))

        ctk.CTkButton(
            popup, text="Закрити", command=popup.destroy,
            fg_color="#1a0a3a", hover_color="#2a1a4a",
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(family="Consolas", size=12),
            height=28, corner_radius=8

        ).pack(pady=(0, 12))

    def _apply_net_priority(self, proc: dict, level: str, popup: tk.Toplevel):
        """Застосовує мережевий пріоритет і оновлює UI."""
        popup.destroy()
        name = proc["name"]

        def do():
            ok, msg = self.engine.set_process_network_priority(
                name, level,
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
            if ok:
                self._net_priority_map[name.lower()] = level
                self._safe_after(lambda: self._update_net_badge(proc["pid"], name.lower(), level))
                level_name = NET_PRIORITY_NAMES.get(level, level)
                self._safe_after(lambda: self._log(f"  ✅ {name} → {level_name}"))
            else:
                self._safe_after(lambda: self._log(f"  ❌ {msg}"))

        threading.Thread(target=do, daemon=True).start()

    def _apply_bandwidth_limit(self, proc: dict, limit_mbps: float, popup: tk.Toplevel):
        """Застосовує або знімає обмеження швидкості мережі для процесу."""
        popup.destroy()
        name = proc["name"]

        def do():
            ok, msg = self.engine.set_process_bandwidth_limit(
                name, limit_mbps,
                log_cb=lambda t: self._safe_after(lambda: self._log(t))
            )
            if ok:
                self._bandwidth_limit_map[name.lower()] = limit_mbps
                # Оновлюємо кнопку QoS — показуємо ліміт якщо встановлено
                self._safe_after(lambda: self._update_bandwidth_badge(proc["pid"], name.lower(), limit_mbps))
            else:
                self._safe_after(lambda: self._log(f"  ❌ {msg}"))

        threading.Thread(target=do, daemon=True).start()

    def _update_bandwidth_badge(self, pid: int, exe_key: str, limit_mbps: float):
        """Оновлює текст QoS кнопки після зміни ліміту швидкості."""
        row = self._proc_row_widgets.get(pid)
        if not row:
            return
        try:
            net_btn = getattr(row, "_net_btn", None)
            if not net_btn or not net_btn.winfo_exists():
                return
            if limit_mbps > 0:
                txt   = f"🚧 {limit_mbps:.0f}M"
                color = "#f97316"
                bg    = "#0d1a00"
            else:
                # Повертаємо до QoS стану
                level = self._net_priority_map.get(exe_key)
                txt   = NET_PRIORITY_LABELS.get(level, "· встан.")
                color = NET_PRIORITY_COLORS.get(level, "#4a4a7a")
                bg    = "#0d1a30" if level else row.cget("bg")
            net_btn.configure(text=txt, fg=color, bg=bg)
            self._flash_net_badge(row, color)
        except Exception:
            pass

    def _update_net_badge(self, pid: int, exe_key: str, level: str):
        """Оновлює QoS кнопку і NET KB/s лейбл без повного перемальовування."""
        row = self._proc_row_widgets.get(pid)
        if not row:
            return
        try:
            net_btn = getattr(row, "_net_btn", None)
            if net_btn and net_btn.winfo_exists():
                net_txt   = NET_PRIORITY_LABELS.get(level, "· встан.")
                net_color = NET_PRIORITY_COLORS.get(level, "#4a4a7a")
                qos_bg    = "#0d1a30" if level and level != "normal" else row.cget("bg")
                net_btn.configure(fg=net_color, text=net_txt, bg=qos_bg)
                self._flash_net_badge(row, net_color)
        except Exception:
            pass

    def _flash_net_badge(self, row: tk.Frame, color: str):
        """Швидкий спалах рядка після зміни мережевого пріоритету."""
        if not row.winfo_exists():
            return
        original = row.cget("bg")
        row.configure(bg=color + "44" if len(color) == 7 else color)
        row.after(300, lambda: row.configure(bg=original) if row.winfo_exists() else None)

    # ═══════════════════════════════════════════════════════════════════════
    #  POPUP: детальний вплив процесу
    # ═══════════════════════════════════════════════════════════════════════

    def _show_impact(self, proc: dict):
        popup = tk.Toplevel(self)
        popup.title(proc["name"])
        popup.geometry("420x260")
        popup.configure(bg=COLORS["bg_primary"])
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        net_level = self._net_priority_map.get(proc["name"].lower())
        net_txt   = NET_PRIORITY_NAMES.get(net_level, "Нормальний (без QoS)")
        net_pct   = proc.get("net_pct", 0.0)
        net_kb    = proc.get("net_bytes", 0.0)

        tk.Label(popup, text=proc["name"],
                 bg=COLORS["bg_primary"], fg=COLORS["text_primary"],
                 font=("Consolas", 15, "bold")).pack(pady=(14, 2))

        # Рядок статистики
        stats_txt = (
            f"PID: {proc['pid']}  │  "
            f"CPU: {proc.get('cpu', 0):.1f}%  │  "
            f"RAM: {proc.get('ram_mb', 0):.0f} MB  │  "
            f"NET: {net_pct:.0f}% ({net_kb:.0f} KB/s)"
        )
        tk.Label(popup, text=stats_txt,
                 bg=COLORS["bg_primary"], fg="#a0aec0",
                 font=("Consolas", 12)).pack()

        # NET bar — візуальна шкала використання мережі
        if net_pct > 0:
            bar_frame = tk.Frame(popup, bg=COLORS["bg_secondary"], height=6)
            bar_frame.pack(fill="x", padx=24, pady=(8, 2))
            bar_color = "#ef4444" if net_pct > 30 else "#f97316" if net_pct > 10 else "#38bdf8"
            bar_inner = tk.Frame(bar_frame, bg=bar_color, height=6)
            bar_inner.place(relwidth=min(net_pct / 100, 1.0), relheight=1.0)
            tk.Label(popup, text=f"🌐 Мережа: {net_pct:.1f}% від загального трафіку",
                     bg=COLORS["bg_primary"], fg=bar_color,
                     font=("Consolas", 12)).pack()

        tk.Label(popup, text=proc.get("impact", ""),
                 bg=COLORS["bg_primary"],
                 fg=COLORS.get("accent_yellow", "#eab308"),
                 font=("Consolas", 12, "bold")).pack(pady=(8, 2))
        tk.Label(popup, text=proc.get("impact_desc", ""),
                 bg=COLORS["bg_primary"], fg=COLORS["text_secondary"],
                 font=("Consolas", 11), wraplength=340).pack()

        tk.Frame(popup, bg=COLORS["border"], height=1).pack(fill="x", padx=20, pady=6)
        net_color = NET_PRIORITY_COLORS.get(net_level, "#64748b")
        tk.Label(popup,
                 text=f"🌐 Мережевий пріоритет: {net_txt}",
                 bg=COLORS["bg_primary"], fg=net_color,
                 font=("Consolas", 11)).pack()

        ctk.CTkButton(
            popup, text="Закрити", command=popup.destroy,
            fg_color=COLORS["bg_secondary"], hover_color=COLORS["bg_card"],
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=12),
            height=28, corner_radius=8
        ).pack(pady=10)

    # ═══════════════════════════════════════════════════════════════════════
    #  KILL + WARN DANGEROUS
    # ═══════════════════════════════════════════════════════════════════════

    def _kill(self, proc: dict):
        """Підтвердження перед завершенням процесу."""
        confirm = tk.Toplevel(self)
        confirm.title("Підтвердження")
        confirm.geometry("340x160")
        confirm.configure(bg="#1a0000")
        confirm.resizable(False, False)
        confirm.attributes("-topmost", True)

        tk.Label(confirm,
                 text=f"⊘  Завершити процес?",
                 bg="#1a0000", fg="#ef4444",
                 font=("Consolas", 14, "bold")).pack(pady=(16, 4))
        tk.Label(confirm, text=f"{proc['name']} (PID {proc['pid']})",
                 bg="#1a0000", fg="#ffffff",
                 font=("Consolas", 12)).pack()
        tk.Label(confirm,
                 text=f"RAM: {proc.get('ram_mb', 0):.0f} MB  |  "
                      f"Категорія: {proc.get('impact', '?')}",
                 bg="#1a0000", fg="#94a3b8",
                 font=("Consolas", 11)).pack(pady=4)

        btn_row = tk.Frame(confirm, bg="#1a0000")
        btn_row.pack(pady=10)

        def do_kill():
            confirm.destroy()
            def _work():
                ok, msg = self.engine.kill_process(proc["pid"], proc["name"])
                self._safe_after(lambda: self._log(msg))
                if ok:
                    self.after(800, self._refresh_processes)
            threading.Thread(target=_work, daemon=True).start()

        tk.Button(btn_row, text="⊘  Завершити",
                  bg="#3a0000", fg="#ef4444",
                  font=("Consolas", 12, "bold"),
                  relief="flat", padx=14, pady=6,
                  command=do_kill).pack(side="left", padx=8)
        tk.Button(btn_row, text="Скасувати",
                  bg="#1a1a2a", fg="#94a3b8",
                  font=("Consolas", 12),
                  relief="flat", padx=14, pady=6,
                  command=confirm.destroy).pack(side="left", padx=8)

    def _warn_dangerous(self, proc: dict):
        popup = tk.Toplevel(self)
        popup.title("⚠️ НЕБЕЗПЕЧНА ДІЯ")
        popup.geometry("380x230")
        popup.configure(bg="#1a0000")
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        tk.Label(popup, text="☠️  НЕБЕЗПЕЧНО ЗАВЕРШУВАТИ",
                 bg="#1a0000", fg="#ff6b35",
                 font=("Consolas", 14, "bold")).pack(pady=(16, 4))
        tk.Label(popup, text=proc["name"],
                 bg="#1a0000", fg="#ffffff",
                 font=("Consolas", 13)).pack()
        tk.Frame(popup, bg="#3a0000", height=1).pack(fill="x", padx=20, pady=10)
        tk.Label(popup,
                 text=proc.get("impact_desc",
                               "Завершення цього процесу може призвести до\n"
                               "BSOD, втрати даних або нестабільності системи."),
                 bg="#1a0000", fg="#fca5a5",
                 font=("Consolas", 11), wraplength=340, justify="center").pack()
        tk.Label(popup,
                 text="✅ Рекомендація: знизити пріоритет (кнопка ↑ → Low)\n"
                      "або встановити низький мережевий пріоритет (кнопка NET).",
                 bg="#1a0000", fg="#86efac",
                 font=("Consolas", 11), justify="center").pack(pady=(10, 0))
        ctk.CTkButton(popup, text="Зрозуміло", command=popup.destroy,
                      fg_color="#3a0000", hover_color="#5a0000",
                      text_color="#ff6b35",
                      font=ctk.CTkFont(family="Consolas", size=12),
                      height=30, corner_radius=8).pack(pady=12)

    # ═══════════════════════════════════════════════════════════════════════
    #  POPUP: CPU-пріоритет
    # ═══════════════════════════════════════════════════════════════════════

    def _priority_popup(self, proc: dict):
        pid = proc["pid"]
        popup = tk.Toplevel(self)
        popup.title(f"Priority: {proc['name']}")
        popup.geometry("310x310")
        popup.configure(bg=COLORS["bg_primary"])
        popup.resizable(False, False)
        popup.attributes("-topmost", True)

        tk.Label(popup, text=proc["name"],
                 bg=COLORS["bg_primary"], fg=COLORS["text_primary"],
                 font=("Consolas", 13, "bold")).pack(pady=(14, 2))
        tk.Label(popup, text=f"PID: {pid}   CPU: {proc.get('cpu', 0):.1f}%",
                 bg=COLORS["bg_primary"], fg=COLORS["text_secondary"],
                 font=("Consolas", 11)).pack()

        cur = self._proc_priority_map.get(pid)
        if not cur:
            cur = self.engine.get_process_priority(pid)
            if cur and cur != "Unknown":
                self._proc_priority_map[pid] = cur

        cur_color = PRIORITY_COLORS.get(cur, "#555")
        cur_label = PRIORITY_LABELS.get(cur, "невідомо")

        tk.Frame(popup, bg=COLORS["border"], height=1).pack(fill="x", padx=16, pady=8)
        tk.Label(popup, text="ПОТОЧНИЙ ПРІОРИТЕТ CPU:",
                 bg=COLORS["bg_primary"], fg=COLORS["text_dim"],
                 font=("Consolas", 11)).pack()
        cur_lbl_widget = tk.Label(popup, text=cur_label,
                 bg=COLORS["bg_primary"], fg=cur_color,
                 font=("Consolas", 14, "bold"))
        cur_lbl_widget.pack(pady=(2, 8))
        tk.Frame(popup, bg=COLORS["border"], height=1).pack(fill="x", padx=16, pady=(0, 8))

        tk.Label(popup, text="ВСТАНОВИТИ:",
                 bg=COLORS["bg_primary"], fg=COLORS["text_dim"],
                 font=("Consolas", 11)).pack(pady=(0, 4))

        LEVELS = [
            ("🔴 HIGH — максимум для гри",   "High",         "#ef4444"),
            ("🟠 ABOVE NORMAL",              "Above Normal", "#f97316"),
            ("🟢 NORMAL — за замовчуванням", "Normal",       "#22c55e"),
            ("⚫ LOW — мінімум ресурсів",    "Low",          "#64748b"),
        ]
        for btn_text, level, btn_color in LEVELS:
            is_active = (cur == level or
                         (cur == "AboveNormal" and level == "Above Normal") or
                         (cur == "Idle" and level == "Low"))
            ctk.CTkButton(
                popup, text=btn_text,
                command=lambda l=level, w=popup, lw=cur_lbl_widget: (
                    self._apply_priority(proc, l, w, lw)
                ),
                fg_color=btn_color + "33" if is_active else COLORS["bg_card"],
                hover_color=btn_color + "55",
                text_color=btn_color if is_active else COLORS["text_primary"],
                border_width=2 if is_active else 1,
                border_color=btn_color if is_active else COLORS["border"],
                font=ctk.CTkFont(family="Consolas", size=12),
                height=30, corner_radius=8
            ).pack(fill="x", padx=18, pady=2)

    def _apply_priority(self, proc: dict, level: str, popup: tk.Toplevel,
                        cur_label_widget: tk.Label | None = None):
        popup.destroy()
        PRIORITY_PS_MAP = {
            "High": "High", "Above Normal": "AboveNormal",
            "Normal": "Normal", "Below Normal": "BelowNormal", "Low": "Idle",
        }
        pid = proc["pid"]

        def do():
            ok, msg = self.engine.set_priority(pid, level)
            ps_key = PRIORITY_PS_MAP.get(level, "Normal")
            if ok:
                self._proc_priority_map[pid] = ps_key
                self._safe_after(lambda: self._flash_priority(pid, ps_key))
            self._safe_after(lambda: self._log(msg))

        threading.Thread(target=do, daemon=True).start()

    def _flash_priority(self, pid: int, priority: str):
        row = self._proc_row_widgets.get(pid)
        if not row or not row.winfo_exists():
            return
        flash_color = PRIORITY_COLORS.get(priority, "#7c3aed")
        original_bg = row.cget("bg")

        def step(n, going_in=True):
            if not row.winfo_exists():
                return
            if going_in:
                row.configure(bg=flash_color)
                if n < 3:
                    row.after(60, lambda: step(n + 1, True))
                else:
                    row.after(200, lambda: step(3, False))
            else:
                if n > 0:
                    row.after(60, lambda: step(n - 1, False))
                else:
                    row.configure(bg=original_bg)
                    if hasattr(row, "_priority_label"):
                        try:
                            lbl = row._priority_label  # type: ignore
                            if lbl.winfo_exists():
                                lbl.configure(
                                    text=PRIORITY_LABELS.get(priority, priority),
                                    fg=PRIORITY_COLORS.get(priority, "#888")
                                )
                        except Exception:
                            pass
        step(0, True)

    # ═══════════════════════════════════════════════════════════════════════
    #  УТИЛІТИ
    # ═══════════════════════════════════════════════════════════════════════

    def _log(self, text: str):
        try:
            self._log_box.configure(state="normal")
            ts = datetime.datetime.now().strftime("%H:%M:%S")
            self._log_box.insert("end", f"[{ts}] {text}\n")
            self._log_box.see("end")
            self._log_box.configure(state="disabled")
        except Exception:
            pass