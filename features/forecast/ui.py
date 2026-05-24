# gui/pages/forecast_ui.py  v4
# ─────────────────────────────────────────────────────────────────────────────
#  NetGuardian AI  ·  Internet Weather Forecast  ·  UI  v4
#  ✅ v4 зміни:
#    1. Пояснення → спливаюче вікно при кліку на кнопку "?"
#    2. Шрифти суттєво збільшені, ключові числа виділені розміром/кольором
#    3. Повзунок в кіберпанк-стилі
#    4. Global Service Status — авто-завантаження при старті
#    5. Live Ping Sparkline + Найкращий час
# ─────────────────────────────────────────────────────────────────────────────

import customtkinter as ctk
import tkinter as tk
import threading
import datetime
import time

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.forecast.engine import ForecastEngine, WeatherCondition, HistoricalAnalysis


# ─── Шрифти ───────────────────────────────────────────────────────────────────
# Кортежі — не потребують tkinter root при імпорті модуля.
# ctk.CTkFont() допускається лише всередині класів (після App.__init__).

F_PAGE_TITLE = ("Consolas", 20, "bold")   # назва сторінки
F_SECTION    = ("Consolas", 17, "bold")   # заголовок секції
F_HEADING    = ("Consolas", 14, "bold")   # підзаголовок
F_BODY       = ("Consolas", 13)           # основний текст
F_BODY_B     = ("Consolas", 13, "bold")   # важливий текст
F_METRIC_S   = ("Consolas", 22, "bold")   # числа середні (пінг/джиттер/лосс)
F_METRIC_L   = ("Consolas", 34, "bold")   # велике головне число (індекс)
F_VALUE      = ("Consolas", 18, "bold")   # значення в картках
F_LABEL      = ("Consolas", 11)           # підписи до значень
F_SMALL      = ("Consolas", 11)           # допоміжний дрібний текст
F_TINY       = ("Consolas", 10)           # найдрібніший (мітки осей)

AUTO_REFRESH_SEC = 120
SPARKLINE_MAX    = 40

INDEX_GRADIENT = [
    (0,  20,  "#22c55e"),
    (20, 40,  "#84cc16"),
    (40, 60,  "#eab308"),
    (60, 80,  "#f97316"),
    (80, 100, "#ef4444"),
]

CAT_LABELS = {
    "general":   "🌐 Інтернет",
    "gaming":    "🎮 Ігри",
    "streaming": "📺 Стрімінг",
    "work":      "💼 Робота",
}

# ─── Тексти для спливаючих вікон ──────────────────────────────────────────────
SECTION_HINTS = {
    "station": {
        "title": "📡  Стан мережі — як це читати?",
        "body": (
            "Ця секція вимірює твою мережу прямо зараз і показує три ключових параметри:\n\n"
            "🌡️  ПІНГ (мс)\n"
            "   Час відповіді від твого комп'ютера до сервера.\n"
            "   ✅ < 20 мс — ідеально для ігор\n"
            "   🟡 20–80 мс — норма для більшості задач\n"
            "   🔴 > 150 мс — проблема, відеодзвінки та ігри страждають\n\n"
            "💨  ДЖИТТЕР (мс)\n"
            "   Нестабільність пінгу — «трясіння» з'єднання.\n"
            "   ✅ < 5 мс — відмінно\n"
            "   🟡 5–30 мс — прийнятно\n"
            "   🔴 > 30 мс — голосові дзвінки та FPS-ігри «смикаються»\n\n"
            "🌧️  ВТРАТА ПАКЕТІВ (%)\n"
            "   Відсоток даних, які «загубились» по дорозі.\n"
            "   ✅ 0% — ідеально\n"
            "   🟡 0.1–1% — допустимо\n"
            "   🔴 > 1% — критично, контент буде переривчастим\n\n"
            "⬤  WEATHER INDEX (0–100)\n"
            "   Загальна оцінка якості. 100 = ідеал, 0 = повний колапс.\n"
            "   Розраховується на основі всіх трьох параметрів вище."
        ),
    },
    "weekly": {
        "title": "📅  Прогноз на 7 днів — як це читати?",
        "body": (
            "Прогноз будується на основі твоєї ВЛАСНОЇ статистики за останні 7 днів.\n"
            "Це не погода в інтернеті — це твій особистий патерн.\n\n"
            "📅  СТОВПЕЦЬ ДНЯ\n"
            "   Жовта рамка = сьогодні.\n"
            "   Іконка = очікуваний стан мережі цього дня.\n"
            "   Число = середній пінг для цього дня тижня.\n\n"
            "📊  БАР РИЗИКУ\n"
            "   Показує ймовірність проблем протягом дня:\n"
            "   🟢 < 30% — спокійний день\n"
            "   🟡 30–60% — можливі сповільнення\n"
            "   🔴 > 60% — висока ймовірність проблем\n\n"
            "💡  ПОРАДА\n"
            "   Чим більше даних накопичено в базі — тим точніший прогноз.\n"
            "   NetGuardian збирає статистику автоматично у фоні."
        ),
    },
    "services": {
        "title": "☁️  Global Service Status — як це читати?",
        "body": (
            "Перевіряє реальну доступність популярних сервісів з ТВОГО підключення.\n"
            "Це TCP-з'єднання — так само, як відкриває браузер чи гра.\n\n"
            "🎮  ІГРОВІ СЕРВЕРИ\n"
            "   Steam, Battle.net, Epic, Riot, EA — якщо один червоний,\n"
            "   ігри на ньому можуть не запускатись або лагати.\n\n"
            "📺  СТРІМІНГ\n"
            "   Netflix, YouTube, Twitch — висока затримка означає\n"
            "   буферизацію та зниження якості.\n\n"
            "💼  РОБОЧІ СЕРВІСИ\n"
            "   Google, Discord, Zoom — критично для відеодзвінків.\n\n"
            "🚦  ЗНАЧЕННЯ ЗАТРИМКИ\n"
            "   🟢 < 50 мс    — відмінно\n"
            "   🟡 50–150 мс  — нормально\n"
            "   🟠 > 150 мс   — повільно\n"
            "   🔴 offline    — сервіс недоступний з твоєї мережі\n\n"
            "⚠️  Якщо сервіс недоступний — з'явиться червоне сповіщення вгорі."
        ),
    },
    "chart": {
        "title": "📈  Графік по годинах — як це читати?",
        "body": (
            "Показує середній пінг для кожної години доби на основі всіх\n"
            "накопичених даних. Чим більше даних — тим точніший графік.\n\n"
            "🟢  ЗЕЛЕНІ СТОВПЦІ\n"
            "   Пінг близький до норми — ідеальний час для ігор та роботи.\n\n"
            "🟡  ЖОВТІ СТОВПЦІ\n"
            "   Незначне підвищення пінгу відносно норми.\n\n"
            "🔴  ЧЕРВОНІ СТОВПЦІ  (ЦИКЛОНИ ⚡)\n"
            "   Провайдер перевантажений — мережа сповільнена.\n"
            "   Уникай цих годин для ігор та великих завантажень!\n\n"
            "━━  ЖОВТА ПУНКТИРНА ЛІНІЯ\n"
            "   Твоя середня норма пінгу. Стовпці вище = гірше за норму.\n\n"
            "📍  ПОТОЧНА ГОДИНА\n"
            "   Виділена темно-синім фоном — де ти зараз."
        ),
    },
    "heatmap": {
        "title": "🗓️  Тижневий Heatmap — як це читати?",
        "body": (
            "Теплова карта 7 днів × 24 години. Показує патерни провайдера —\n"
            "коли він регулярно перевантажується щотижня.\n\n"
            "🎨  КОЛЬОРОВА ШКАЛА\n"
            "   Зелений = нормальний пінг для цієї години\n"
            "   Жовтий  = незначне підвищення\n"
            "   Червоний = підвищений пінг, провайдер під навантаженням\n"
            "   Темний  = немає даних для цієї комірки\n\n"
            "⬜  БІЛИЙ КОНТУР\n"
            "   Поточний момент часу (день + година).\n\n"
            "📊  ЯК ВИКОРИСТОВУВАТИ\n"
            "   Подивись на регулярні «червоні смуги» — це пікові години\n"
            "   провайдера. Наприклад, щосереди з 20:00 до 22:00 — пік.\n"
            "   Плануй ігри та завантаження ДО або ПІСЛЯ цих годин."
        ),
    },
    "sparkline": {
        "title": "📶  Live Ping — як це читати?",
        "body": (
            "Графік останніх 40 вимірювань пінгу в реальному часі.\n"
            "Оновлюється автоматично кожні 5 секунд.\n\n"
            "🔵  СИНЯ ЛІНІЯ\n"
            "   Пінг у нормі (< 50 мс) — з'єднання стабільне.\n\n"
            "🟡  ЖОВТИЙ КОЛІР\n"
            "   Підвищений пінг (50–150 мс) — незначна деградація.\n\n"
            "🔴  ЧЕРВОНИЙ КОЛІР\n"
            "   Критичний пінг (> 150 мс) — проблема з'єднання!\n\n"
            "📍  ОСТАННЯ ТОЧКА\n"
            "   Крапка в кінці = найсвіжіше вимірювання.\n"
            "   Велике число праворуч = поточний пінг.\n\n"
            "💡  ДЛЯ ЧОГО КОРИСНО\n"
            "   Щоб одразу побачити короткочасні стрибки, які\n"
            "   середній показник може «сховати»."
        ),
    },
    "besttime": {
        "title": "🏆  Найкращий час — як це читати?",
        "body": (
            "Аналізує твою статистику і рекомендує оптимальні години\n"
            "для різних типів активності в мережі.\n\n"
            "🎮  ІГРИ\n"
            "   Години з мінімальним пінгом + відсутністю «циклонів».\n"
            "   Пінг і стабільність критичні для онлайн-ігор.\n\n"
            "📥  ЗАВАНТАЖЕННЯ\n"
            "   Нічні/ранкові години з мінімальним навантаженням на\n"
            "   вузол провайдера. Ідеально для великих файлів.\n\n"
            "📺  СТРІМІНГ\n"
            "   Денні/вечірні години без «циклонів» у розкладі.\n"
            "   Важлива стабільність, а не мінімальний пінг.\n\n"
            "💡  ПРИМІТКА\n"
            "   Показуються 3 найкращі години для кожного типу.\n"
            "   Накопичуй більше даних — рекомендації стануть точнішими."
        ),
    },
}


# ─── Утиліти ──────────────────────────────────────────────────────────────────

def _index_color(index: int) -> str:
    for lo, hi, color in INDEX_GRADIENT:
        if lo <= index < hi:
            return color
    return "#ef4444"


def _get_hint(cond: WeatherCondition,
              history: "HistoricalAnalysis | None") -> tuple[str, str]:
    checks = [
        (lambda c, h: c.packet_loss > 5,
         "🌧️", "Висока втрата пакетів — відеодзвінки та ігри нестабільні."),
        (lambda c, h: c.ping_ms > 150,
         "🔴", "Критичний пінг! Перевірте кабель або зверніться до провайдера."),
        (lambda c, h: c.jitter_ms > 30,
         "💨", "Сильний джиттер — голосові чати та FPS-ігри будуть «смикатись»."),
        (lambda c, h: (h is not None
                       and datetime.datetime.now().hour in getattr(h, "cyclone_hours", [])),
         "⚡", "Зараз — пікова година навантаження. Краще відкласти важкі задачі."),
        (lambda c, h: (h is not None and getattr(h, "sla_pct", 100) < 90),
         "📉", "Надійність провайдера < 90% за тиждень — зафіксуйте для скарги."),
        (lambda c, h: (c.nominal_mbps > 0 and c.perceived_mbps > 0
                       and c.perceived_mbps < c.nominal_mbps * 0.5),
         "🐢", "Реальна швидкість < 50% від тарифної. Можливий throttling."),
        (lambda c, h: c.ping_ms < 20 and c.packet_loss < 0.5,
         "☀️", "Ідеальний стан! Чудовий час для ігор або завантажень у 4K."),
        (lambda c, h: True,
         "💡", "Моніторинг активний. Чим більше даних — тим точніший прогноз."),
    ]
    for fn, icon, text in checks:
        try:
            if fn(cond, history):
                return icon, text
        except Exception:
            continue
    return "💡", "Моніторинг активний."


# ─── Кіберпанк повзунок ───────────────────────────────────────────────────────

def _apply_cyberpunk_scrollbar(frame: ctk.CTkScrollableFrame):
    try:
        sb = frame._scrollbar
        sb.configure(
            width=8,
            fg_color=COLORS.get("bg_secondary", "#13132b"),
            button_color=COLORS.get("accent_yellow", "#eab308"),
            button_hover_color=COLORS.get("accent_green", "#22c55e"),
            corner_radius=4,
        )
    except Exception:
        pass


# ─── Спливаюче вікно-пояснення ────────────────────────────────────────────────

class HintPopup(ctk.CTkToplevel):
    """
    Спливаюче вікно з детальним поясненням секції.
    Відкривається кліком на кнопку «?» поруч із заголовком.
    """

    def __init__(self, parent, section_key: str):
        super().__init__(parent)

        hint = SECTION_HINTS.get(section_key, {
            "title": "ℹ️  Довідка",
            "body":  "Опис для цієї секції відсутній.",
        })

        # ── Вікно ────────────────────────────────────────────────────────
        self.title(hint["title"])
        self.resizable(False, False)
        self.configure(fg_color=COLORS.get("bg_primary", "#0d0d1a"))
        self.attributes("-topmost", True)

        # Центруємо відносно батьківського вікна
        self.after(10, lambda: self._center(parent))

        # ── Шапка ────────────────────────────────────────────────────────
        header = ctk.CTkFrame(
            self,
            fg_color=COLORS.get("bg_card", "#1a1a2e"),
            corner_radius=0,
        )
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text=hint["title"],
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=COLORS.get("accent_yellow", "#eab308"),
            anchor="w",
        ).pack(side="left", padx=20, pady=14)

        ctk.CTkButton(
            header,
            text="✕",
            command=self.destroy,
            width=36, height=36,
            corner_radius=8,
            fg_color="transparent",
            hover_color=COLORS.get("bg_secondary", "#13132b"),
            text_color=COLORS.get("text_dim", "#475569"),
            font=ctk.CTkFont(size=16),
        ).pack(side="right", padx=12, pady=10)

        # ── Тіло ─────────────────────────────────────────────────────────
        body_frame = ctk.CTkFrame(
            self,
            fg_color=COLORS.get("bg_primary", "#0d0d1a"),
            corner_radius=0,
        )
        body_frame.pack(fill="both", expand=True, padx=0, pady=0)

        # Декоративна ліва смуга
        ctk.CTkFrame(
            body_frame,
            width=4,
            fg_color=COLORS.get("accent_yellow", "#eab308"),
            corner_radius=0,
        ).pack(side="left", fill="y")

        ctk.CTkLabel(
            body_frame,
            text=hint["body"],
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS.get("text_primary", "#e2e8f0"),
            justify="left",
            anchor="nw",
            wraplength=440,
        ).pack(side="left", padx=20, pady=20)

        # ── Кнопка «Зрозуміло» ───────────────────────────────────────────
        ctk.CTkButton(
            self,
            text="✅  Зрозуміло",
            command=self.destroy,
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            fg_color="#3a2a00",
            hover_color="#5a3d00",
            text_color=COLORS.get("accent_yellow", "#eab308"),
            corner_radius=10,
            height=42,
            border_width=1,
            border_color=COLORS.get("accent_yellow", "#eab308"),
        ).pack(padx=20, pady=(0, 16), fill="x")

    def _center(self, parent):
        try:
            pw = parent.winfo_toplevel()
            px = pw.winfo_x() + pw.winfo_width()  // 2
            py = pw.winfo_y() + pw.winfo_height() // 2
            w  = self.winfo_width()
            h  = self.winfo_height()
            self.geometry(f"+{px - w // 2}+{py - h // 2}")
        except Exception:
            pass


def _hint_button(parent, section_key: str) -> ctk.CTkButton:
    """
    Повертає маленьку кнопку «?».
    При кліку відкриває HintPopup для відповідної секції.
    """
    btn = ctk.CTkButton(
        parent,
        text=" ? ",
        width=32, height=32,
        corner_radius=8,
        fg_color=COLORS.get("bg_secondary", "#13132b"),
        hover_color=COLORS.get("bg_card", "#1a1a2e"),
        text_color=COLORS.get("accent_yellow", "#eab308"),
        font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
        border_width=1,
        border_color=COLORS.get("accent_yellow", "#eab308"),
        command=lambda: HintPopup(parent, section_key),
    )
    return btn


# ─── Storm Alert банер ────────────────────────────────────────────────────────

class StormAlertBanner(ctk.CTkFrame):

    def __init__(self, parent, message: str):
        super().__init__(
            parent,
            fg_color="#0d0005", corner_radius=10,
            border_width=2, border_color="#ef4444",
        )
        inner = ctk.CTkFrame(self, fg_color="transparent")
        inner.pack(fill="x", padx=16, pady=14)
        inner.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(inner, text="⚡",
                     font=ctk.CTkFont(size=30)
                     ).grid(row=0, column=0, padx=(0, 16), rowspan=2)

        ctk.CTkLabel(
            inner, text="STORM ALERT",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color="#ef4444",
        ).grid(row=0, column=1, sticky="w")

        self._msg_lbl = ctk.CTkLabel(
            inner, text=message,
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color="#fca5a5", justify="left", wraplength=720,
        )
        self._msg_lbl.grid(row=1, column=1, sticky="w")

        ctk.CTkButton(
            inner, text="✕", command=self._hide,
            fg_color="transparent", hover_color="#3a0000",
            text_color="#ef4444",
            font=ctk.CTkFont(family="Consolas", size=16),
            width=36, height=36, corner_radius=6,
        ).grid(row=0, column=2, rowspan=2, padx=(16, 0))

        self.after(15_000, self._hide)
        self._pulse()

    def update_message(self, msg: str):
        self._msg_lbl.configure(text=msg)

    def _pulse(self):
        if not self.winfo_exists(): return
        colors = ["#ef4444", "#7f1d1d", "#ef4444"]
        def step(i=0):
            if not self.winfo_exists(): return
            self.configure(border_color=colors[i % len(colors)])
            self.after(600, lambda: step(i + 1))
        step()

    def _hide(self):
        try: self.destroy()
        except Exception: pass


# ══════════════════════════════════════════════════════════════════════════════
#  ЗАГОЛОВОК СЕКЦІЇ — окремий хелпер
#  Рендерить: [ІКОНКА + НАЗВА СЕКЦІЇ]   [? кнопка]
# ══════════════════════════════════════════════════════════════════════════════

def _section_header(parent, icon_text: str, title_text: str,
                    hint_key: str, accent_color: str = None) -> ctk.CTkFrame:
    """
    Повертає рядок-заголовок секції з кнопкою «?» праворуч.
    parent       — батьківський фрейм (зазвичай hdr або card)
    icon_text    — іконка (емоджі)
    title_text   — назва секції великими літерами
    hint_key     — ключ зі словника SECTION_HINTS
    accent_color — колір підкреслення/тексту (за замовчуванням text_primary)
    """
    color = accent_color or COLORS.get("text_primary", "#e2e8f0")

    row = ctk.CTkFrame(parent, fg_color="transparent")

    ctk.CTkLabel(
        row,
        text=f"{icon_text}  {title_text}",
        font=ctk.CTkFont(family="Consolas", size=17, weight="bold"),
        text_color=color,
        anchor="w",
    ).pack(side="left")

    _hint_button(row, hint_key).pack(side="right", padx=(8, 0))

    return row



# ═════════════════════════════════════════════════════════════════════════════
#  NETWORK SWITCHER WINDOW
# ═════════════════════════════════════════════════════════════════════════════

class NetworkSwitcherWindow(ctk.CTkToplevel):
    """
    Вікно переключення між відомими мережами.
    Показує список усіх мереж, їх статистику та дозволяє:
      • Переключитись на іншу мережу (перегляд її статистики)
      • Перейменувати будь-яку мережу
    """

    def __init__(self, parent, engine, on_switch=None):
        super().__init__(parent)
        self._engine    = engine
        self._on_switch = on_switch

        self.title("🗂️  Усі мережі — NetGuardian")
        self.resizable(False, False)
        self.configure(fg_color=COLORS.get("bg_primary", "#0d0d1a"))
        self.attributes("-topmost", True)
        self.geometry("680x480")
        self.after(20, lambda: self._center(parent))

        self._build()

    def _center(self, parent):
        try:
            pw = parent.winfo_toplevel()
            px = pw.winfo_x() + pw.winfo_width()  // 2
            py = pw.winfo_y() + pw.winfo_height() // 2
            self.geometry(f"+{px - 340}+{py - 240}")
        except Exception:
            pass

    def _build(self):
        # ── Шапка ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(
            self, fg_color=COLORS.get("bg_card", "#1a1a2e"), corner_radius=0)
        header.pack(fill="x")

        ctk.CTkLabel(
            header,
            text="🗂️  Усі відомі мережі",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=COLORS.get("accent_yellow", "#eab308"),
        ).pack(side="left", padx=20, pady=14)

        ctk.CTkButton(
            header, text="✕", command=self.destroy,
            width=36, height=36, corner_radius=8,
            fg_color="transparent",
            hover_color=COLORS.get("bg_secondary", "#13132b"),
            text_color=COLORS.get("text_dim", "#475569"),
            font=ctk.CTkFont(size=16),
        ).pack(side="right", padx=12, pady=10)

        # ── Пояснення ─────────────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text=(
                "Кожна мережа (Wi-Fi або Ethernet) зберігає ОКРЕМУ статистику пінгу,\n"
                "прогноз і SLA. Переключіться, щоб переглянути дані іншої мережі."
            ),
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_dim", "#475569"),
            justify="left",
        ).pack(anchor="w", padx=20, pady=(10, 4))

        # ── Список мереж ──────────────────────────────────────────────────────
        scroll = ctk.CTkScrollableFrame(
            self,
            fg_color=COLORS.get("bg_primary", "#0d0d1a"),
            corner_radius=0,
        )
        scroll.pack(fill="both", expand=True, padx=0, pady=0)

        networks = self._engine.get_all_networks()
        current_id = self._engine.net_id

        if not networks:
            ctk.CTkLabel(
                scroll,
                text="Поки немає даних. Запустіть кілька вимірювань.",
                font=ctk.CTkFont(family="Consolas", size=13),
                text_color=COLORS.get("text_dim", "#475569"),
            ).pack(pady=40)
            return

        for net in networks:
            is_current = (net.net_id == current_id)
            self._net_row(scroll, net, is_current)

        # ── Підказка внизу ────────────────────────────────────────────────────
        ctk.CTkLabel(
            self,
            text="💡  Дані зберігаються за відбитком: SSID + MAC-адреса роутера",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_dim", "#334155"),
        ).pack(pady=(4, 10))

    def _net_row(self, parent, net, is_current: bool):
        """Рядок однієї мережі в списку."""
        border_color = (
            COLORS.get("accent_yellow", "#eab308") if is_current
            else COLORS.get("border", "#1e1e3a")
        )
        bg_color = (
            "#2a2200" if is_current
            else COLORS.get("bg_card", "#1a1a2e")
        )

        row = ctk.CTkFrame(
            parent,
            fg_color=bg_color,
            corner_radius=10,
            border_width=2 if is_current else 1,
            border_color=border_color,
        )
        row.pack(fill="x", padx=16, pady=5)
        row.grid_columnconfigure(1, weight=1)

        # Іконка типу
        icon = "📶" if net.ssid and net.ssid != "Ethernet" else "🔌"
        ctk.CTkLabel(
            row, text=icon,
            font=ctk.CTkFont(size=28),
        ).grid(row=0, column=0, rowspan=2, padx=(14, 10), pady=12)

        # Назва + SSID
        name_color = (
            COLORS.get("accent_yellow", "#eab308") if is_current
            else COLORS.get("text_primary", "#e2e8f0")
        )
        name_line = net.display_name
        if is_current:
            name_line += "  ◀ ПОТОЧНА"

        ctk.CTkLabel(
            row, text=name_line,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=name_color,
            anchor="w",
        ).grid(row=0, column=1, sticky="w", pady=(10, 0))

        # Деталі
        gw_str   = f"Шлюз: {net.gateway_ip}" if net.gateway_ip else ""
        mac_str  = f"MAC: {net.gateway_mac[:14]}..." if len(net.gateway_mac) > 14 else f"MAC: {net.gateway_mac}"
        cnt_str  = f"{net.measurement_count} вимірювань"
        seen_str = f"Востаннє: {net.last_seen[:10]}" if net.last_seen else ""

        details = "  ·  ".join(filter(None, [gw_str, mac_str, cnt_str, seen_str]))
        ctk.CTkLabel(
            row, text=details,
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS.get("text_dim", "#475569"),
            anchor="w",
        ).grid(row=1, column=1, sticky="w", pady=(0, 10))

        # Кнопки
        btn_frame = ctk.CTkFrame(row, fg_color="transparent")
        btn_frame.grid(row=0, column=2, rowspan=2, padx=(0, 12), pady=8, sticky="e")

        if not is_current:
            ctk.CTkButton(
                btn_frame,
                text="👁  Переглянути",
                command=lambda nid=net.net_id: self._switch(nid),
                fg_color=COLORS.get("bg_secondary", "#13132b"),
                hover_color="#1a3a00",
                text_color=COLORS.get("accent_green", "#22c55e"),
                font=ctk.CTkFont(family="Consolas", size=12),
                height=32, corner_radius=8,
                border_width=1,
                border_color=COLORS.get("accent_green", "#22c55e"),
            ).pack(pady=(0, 4), fill="x")

        ctk.CTkButton(
            btn_frame,
            text="✏️  Перейменувати",
            command=lambda n=net: self._rename(n),
            fg_color=COLORS.get("bg_secondary", "#13132b"),
            hover_color=COLORS.get("bg_card", "#1a1a2e"),
            text_color=COLORS.get("text_secondary", "#94a3b8"),
            font=ctk.CTkFont(family="Consolas", size=12),
            height=32, corner_radius=8,
            border_width=1,
            border_color=COLORS.get("border", "#1e1e3a"),
        ).pack(fill="x")

    def _switch(self, net_id: str):
        if self._on_switch:
            self._on_switch(net_id)
        self.destroy()

    def _rename(self, net):
        dialog = ctk.CTkInputDialog(
            text=f"Нова назва для мережі\n«{net.display_name}»:",
            title="✏️  Перейменувати",
        )
        new_name = dialog.get_input()
        if new_name and new_name.strip():
            self._engine.rename_network(net.net_id, new_name.strip())
            # Перебудувати вікно
            for w in self.winfo_children():
                w.destroy()
            self._build()


# ═════════════════════════════════════════════════════════════════════════════
#  ГОЛОВНА СТОРІНКА
# ═════════════════════════════════════════════════════════════════════════════

class ForecastPage(ctk.CTkScrollableFrame):

    def __init__(self, parent):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.engine = ForecastEngine()

        self._last_condition: WeatherCondition | None = None
        self._last_history:   HistoricalAnalysis | None = None
        self._storm_banner:   StormAlertBanner | None = None
        self._auto_timer:     str | None = None
        self._sparkline_data: list[float] = []
        self._spark_timer:    str | None  = None

        # ── Фікс #4: підтягуємо останні ~30 ping з історії БД ──
        # Це робить sparkline безперервним після перезапуску — раніше
        # він починався з нуля, що створювало враження "штучно рівного" графіка.
        try:
            import sqlite3
            with sqlite3.connect(self.engine.db_path, timeout=3) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT ping_ms FROM ping_log
                    WHERE ping_ms > 0 AND net_id = ?
                    ORDER BY id DESC LIMIT 30
                """, (self.engine.net_id,))
                rows = c.fetchall()
                if rows:
                    self._sparkline_data = [r[0] for r in reversed(rows)]
                    print(f"[ForecastUI] Sparkline preloaded: {len(self._sparkline_data)} точок з історії")
        except Exception as e:
            print(f"[ForecastUI] Sparkline preload error: {e}")

        # PR #4: запускаємо ПОСТІЙНЕ вимірювання, щоб дані писались
        # навіть коли користувач не на цій сторінці
        self.engine.start_continuous_measurement(interval_seconds=300)

        self.grid_columnconfigure(0, weight=1)
        self._build_ui()

        # Показуємо overlay-анімацію поки синхронізуємось з Pi
        self._show_pi_sync_overlay()

        self.after(150, lambda: _apply_cyberpunk_scrollbar(self))
        self.after(300, self._sync_with_pi_async)   # ← синхронізація на старті
        self.after(500, self._run_full_refresh)

        # PR #11: запускаємо перевірку pending popups
        self.after(3000, self._check_pending_popups)
        self.after(900, self._run_service_check)
        self.after(2000, self._spark_tick)
        # PR #4: показуємо звіт за добу / тиждень (з дедуплікацією — лише раз)
        self.after(4000, self._check_and_show_reports)

    # ═══════════════════════════════════════════════════════════════════════
    #  PI SYNC OVERLAY
    # ═══════════════════════════════════════════════════════════════════════
    def _show_pi_sync_overlay(self):
        """Показує overlay з анімованим спіннером під час підгрузки з Pi."""
        self._sync_overlay = ctk.CTkFrame(
            self, fg_color="#0a0e1a", corner_radius=12,
            border_width=2, border_color=COLORS["accent_cyan"],
        )
        self._sync_overlay.place(relx=0.5, rely=0.1, anchor="n",
                                 relwidth=0.55)

        inner = ctk.CTkFrame(self._sync_overlay, fg_color="transparent")
        inner.pack(padx=24, pady=20, fill="x")

        # Спіннер
        self._spinner_chars = ["⣾", "⣽", "⣻", "⢿", "⡿", "⣟", "⣯", "⣷"]
        self._spinner_idx = 0

        self._sync_spinner = ctk.CTkLabel(
            inner, text="⣾",
            font=ctk.CTkFont(family="Consolas", size=32, weight="bold"),
            text_color=COLORS["accent_cyan"],
        )
        self._sync_spinner.pack(side="left", padx=(0, 12))

        text_frame = ctk.CTkFrame(inner, fg_color="transparent")
        text_frame.pack(side="left", fill="x", expand=True)

        ctk.CTkLabel(
            text_frame, text="📡 СИНХРОНІЗАЦІЯ З RASPBERRY PI",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color=COLORS["accent_cyan"], anchor="w",
        ).pack(fill="x")

        self._sync_status_label = ctk.CTkLabel(
            text_frame, text="підключення до MQTT-брокера...",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"], anchor="w",
        )
        self._sync_status_label.pack(fill="x", pady=(2, 0))

        # Запускаємо анімацію
        self._animate_spinner()

    def _animate_spinner(self):
        if not hasattr(self, "_sync_spinner") or not self._sync_spinner.winfo_exists():
            return
        self._spinner_idx = (self._spinner_idx + 1) % len(self._spinner_chars)
        try:
            self._sync_spinner.configure(text=self._spinner_chars[self._spinner_idx])
            self.after(100, self._animate_spinner)
        except Exception:
            pass

    def _update_sync_status(self, text: str):
        if hasattr(self, "_sync_status_label") and self._sync_status_label.winfo_exists():
            try:
                self._sync_status_label.configure(text=text)
            except Exception:
                pass

    def _hide_sync_overlay(self):
        if hasattr(self, "_sync_overlay") and self._sync_overlay.winfo_exists():
            try:
                self._sync_overlay.destroy()
            except Exception:
                pass

    def _check_and_show_reports(self):
        """
        PR #5 — При старті програми перевіряємо:
          1. Чи є непоказаний звіт за вчорашню добу → показуємо у popup
          2. Якщо понеділок — чи є непоказаний тижневий звіт → показуємо

        Використовуємо SmartScheduler для рендеру (там багаті звіти з категоріями
        і циклонами). НЕ викликаємо send_telegram — це бот робить окремо.
        """
        try:
            from features.forecast.smart_scheduler import SmartScheduler
            scheduler = SmartScheduler(self.engine)

            # ── Daily для вчорашньої дати ──
            from datetime import datetime, timedelta
            yesterday = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
            if not scheduler._was_shown("popup_daily", yesterday):
                daily = scheduler._build_daily_for_yesterday()
                if daily:
                    self._show_report_popup("daily", daily)
                    scheduler._mark_shown("popup_daily", yesterday)
                    return  # показуємо тільки 1 popup за раз

            # ── Weekly для понеділка ──
            now = datetime.now()
            if now.weekday() == 0:  # понеділок
                last_week = (now - timedelta(days=7))
                week_key  = last_week.strftime("%Y-W%V")
                if not scheduler._was_shown("popup_weekly", week_key):
                    weekly = scheduler._build_weekly_for_last_week()
                    if weekly:
                        self._show_report_popup("weekly", weekly)
                        scheduler._mark_shown("popup_weekly", week_key)
        except Exception as e:
            import traceback
            print(f"[Forecast UI] _check_and_show_reports error: {e}")
            traceback.print_exc()

    def _show_day_details(self, date_str: str):
        """ФІКС #6: Popup з деталями за конкретний день при кліку на іконку.
        Показує середній/мін/макс пінг, найкращий час, найгірші години,
        категорії для гри/стрімінгу/роботи.
        """
        try:
            summary = self.engine.get_day_summary(date_str)
        except Exception as e:
            print(f"[Forecast UI] day summary error: {e}")
            return

        if not summary:
            try:
                from tkinter import messagebox
                messagebox.showinfo(
                    "Немає даних",
                    f"За {date_str} ще немає достатньо даних.\n"
                    "Можливо це майбутній день або програма ще не "
                    "встигла зібрати статистику."
                )
            except Exception:
                pass
            return

        # ── Будуємо popup ──
        popup = ctk.CTkToplevel(self)
        popup.title(f"📅 Деталі за {date_str}")
        popup.geometry("540x680")
        popup.resizable(False, True)
        popup.transient(self.winfo_toplevel())

        self.after(50, lambda: popup.lift())
        self.after(100, lambda: popup.focus_force())

        # Header
        try:
            dt = datetime.datetime.strptime(date_str, "%Y-%m-%d")
            DAY_FULL = ["Понеділок", "Вівторок", "Середа", "Четвер",
                        "П'ятниця", "Субота", "Неділя"]
            day_name = DAY_FULL[dt.weekday()]
            pretty = f"{day_name}, {dt.strftime('%d.%m.%Y')}"
        except Exception:
            pretty = date_str

        header = ctk.CTkFrame(popup, fg_color="#0a0e1a", height=70)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header, text=f"📅  {pretty}",
            font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
            text_color=COLORS["accent_cyan"],
        ).pack(pady=20, padx=20, anchor="w")

        content = ctk.CTkScrollableFrame(popup, fg_color="#0f1420")
        content.pack(fill="both", expand=True, padx=12, pady=12)

        def _title(text, color=COLORS["accent_cyan"]):
            ctk.CTkLabel(
                content, text=text, anchor="w",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=color,
            ).pack(fill="x", pady=(10, 4), padx=8)

        def _row(parent, label, value, color=COLORS["text_primary"]):
            r = ctk.CTkFrame(parent, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=2)
            ctk.CTkLabel(
                r, text=label,
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS["text_dim"]
            ).pack(side="left")
            ctk.CTkLabel(
                r, text=value,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=color
            ).pack(side="right")

        # ── Основна статистика ──
        avg_p = summary["avg_ping"]
        ping_color = (
            COLORS["accent_green"] if avg_p < 30 else
            COLORS["accent_yellow"] if avg_p < 80 else
            COLORS["accent_red"]
        )
        _title("📈 Статистика пінгу")
        stats = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
        stats.pack(fill="x", pady=2, padx=4)

        _row(stats, "Середній:", f"{avg_p:.1f} мс", ping_color)
        _row(stats, "Мін / Макс:",
             f"{summary['min_ping']:.1f} / {summary['max_ping']:.1f} мс")
        _row(stats, "Jitter:", f"{summary['avg_jitter']:.1f} мс")
        _row(stats, "Втрати:", f"{summary['avg_loss']:.2f}%")
        _row(stats, "Замірів:", f"{summary['samples']}")
        if summary['blackouts']:
            _row(stats, "⚠ Обривів:", f"{summary['blackouts']}",
                 COLORS["accent_red"])

        # ── Найкращі години ──
        if summary["best_hours"]:
            _title("🏆 Найкращі години", COLORS["accent_green"])
            bh = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
            bh.pack(fill="x", pady=2, padx=4)
            for hr, ms in summary["best_hours"]:
                _row(bh, f"{hr:02d}:00", f"{ms:.0f} мс",
                     COLORS["accent_green"])

        # ── Категорії ──
        cat_keys = [
            ("best_for_gaming",    "🎮", "Ігри",     "(≤ 50 мс)"),
            ("best_for_streaming", "📺", "Стрімінг", "(≤ 80 мс)"),
            ("best_for_work",      "💼", "Робота",   "(≤ 150 мс)"),
        ]
        if any(summary.get(k[0]) for k in cat_keys):
            _title("⏰ Найкращий час для активностей")
            cat_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"],
                                      corner_radius=8)
            cat_frame.pack(fill="x", pady=2, padx=4)
            for key, emoji, name, cond in cat_keys:
                hours = summary.get(key, [])
                if hours:
                    hours_str = ", ".join(f"{h:02d}:00" for h in hours)
                    _row(cat_frame, f"{emoji} {name} {cond}", hours_str,
                         COLORS["accent_green"])

        # ── Найгірші години ──
        if summary["worst_hours"] and summary["worst_hours"][0][1] > 80:
            _title("🌪 Найгірші години", COLORS["accent_red"])
            wh = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
            wh.pack(fill="x", pady=2, padx=4)
            for hr, avg, mx in summary["worst_hours"]:
                _row(wh, f"{hr:02d}:00",
                     f"avg {avg:.0f} / max {mx:.0f} мс",
                     COLORS["accent_red"])

        # ── Mini bar-chart годинного пінгу ──
        if summary.get("hourly"):
            _title("📊 Пінг по годинах", COLORS["accent_cyan"])
            chart_card = ctk.CTkFrame(content, fg_color=COLORS["bg_card"],
                                       corner_radius=8)
            chart_card.pack(fill="x", pady=2, padx=4)
            chart_canvas = tk.Canvas(
                chart_card, bg=COLORS.get("bg_primary", "#0d0d1a"),
                highlightthickness=0, height=100, width=480
            )
            chart_canvas.pack(padx=10, pady=10)
            self._draw_day_mini_chart(chart_canvas, summary["hourly"])

        # Кнопка закриття
        ctk.CTkButton(
            popup, text="✓ Закрити",
            command=popup.destroy,
            fg_color=COLORS["accent_cyan"],
            hover_color=COLORS["accent_blue"],
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            height=40,
        ).pack(fill="x", padx=20, pady=(0, 16))

    def _draw_day_mini_chart(self, canvas, hourly_data: dict):
        """Малює маленький bar-chart 24 годин у popup деталей дня."""
        canvas.delete("all")
        W, H = 480, 100
        pl, pr, pt, pb = 30, 10, 8, 18
        cw, ch = W - pl - pr, H - pt - pb
        if not hourly_data:
            return
        max_v = max(hourly_data.values())
        if max_v < 80: max_v = 80
        col_w = cw / 24

        for h in range(24):
            x = pl + h * col_w
            v = hourly_data.get(h)
            if v is None:
                continue
            bh = (v / max_v) * ch * 0.9
            y_top = pt + ch - bh
            color = (
                COLORS["accent_green"]  if v < 50 else
                COLORS["accent_yellow"] if v < 100 else
                COLORS["accent_red"]
            )
            bw = col_w * 0.7
            bx = x + col_w / 2
            canvas.create_rectangle(bx - bw/2, y_top, bx + bw/2, pt + ch,
                                     fill=color, outline="")
            if h % 4 == 0:
                canvas.create_text(x + col_w/2, H - 8, text=f"{h}",
                                    fill=COLORS["text_dim"], font=("Consolas", 8))

    def _check_pending_popups(self):
        """PR #11: Періодично перевіряє ~/.netguardian/pending_popups/
        і показує звіти, які SmartScheduler передав через callback.

        Цей механізм відв'язує SmartScheduler (працює у фоні bot.py)
        від ForecastUI (працює у головному tkinter-потоці).
        """
        try:
            from pathlib import Path
            import json
            pending_dir = Path.home() / ".netguardian" / "pending_popups"
            if pending_dir.exists():
                for f in sorted(pending_dir.glob("*.json")):
                    try:
                        with open(f, "r", encoding="utf-8") as fh:
                            data = json.load(fh)
                        # Видаляємо файл щоб не показати знов
                        f.unlink(missing_ok=True)
                        # Показуємо popup
                        rtype = data.get("type", "daily")
                        report = data.get("report", {})
                        print(f"[ForecastUI] 📋 Показую popup: {rtype}")
                        self._show_report_popup(rtype, report)
                    except Exception as e:
                        print(f"[ForecastUI] popup load error: {e}")
                        try:
                            f.unlink(missing_ok=True)
                        except Exception:
                            pass
        except Exception as e:
            print(f"[ForecastUI] _check_pending_popups error: {e}")
        finally:
            # Перевірка кожні 5 секунд
            self.after(5000, self._check_pending_popups)

    def _show_report_popup(self, report_type: str, report: dict):
        """Показує модальне вікно зі звітом (РОЗШИРЕНА версія)."""
        try:
            popup = ctk.CTkToplevel(self)
            popup.title(f"📊 {'Звіт за добу' if report_type == 'daily' else 'Звіт за тиждень'}")
            popup.geometry("620x720")
            popup.resizable(False, True)
            popup.transient(self.winfo_toplevel())

            # Центрування
            self.after(50, lambda: popup.lift())
            self.after(100, lambda: popup.focus_force())

            # ── Заголовок ──
            header = ctk.CTkFrame(popup, fg_color="#0a0e1a", height=70)
            header.pack(fill="x", padx=0, pady=0)
            header.pack_propagate(False)

            icon = "📅" if report_type == "daily" else "📆"
            title_text = (
                f"Звіт за добу: {report.get('date', '—')}"
                if report_type == "daily"
                else f"Тижневий звіт: {report.get('week', '—')}"
            )

            ctk.CTkLabel(
                header, text=f"{icon}  {title_text}",
                font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                text_color=COLORS["accent_cyan"],
            ).pack(pady=18, padx=20, anchor="w")

            # ── Контент ──
            content = ctk.CTkScrollableFrame(popup, fg_color="#0f1420")
            content.pack(fill="both", expand=True, padx=12, pady=12)

            # Мережа
            ctk.CTkLabel(
                content,
                text=f"🌐 Мережа: {report.get('network', 'unknown')}",
                anchor="w", justify="left",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS["text_dim"],
            ).pack(fill="x", pady=(4, 8), padx=8)

            # ── Helper для виводу рядків ──
            def _section_title(text: str):
                ctk.CTkLabel(
                    content, text=text,
                    anchor="w", justify="left",
                    font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                    text_color=COLORS["accent_cyan"],
                ).pack(fill="x", pady=(10, 4), padx=8)

            def _make_row(parent, label: str, value: str,
                          color: str = COLORS["text_primary"]):
                r = ctk.CTkFrame(parent, fg_color="transparent")
                r.pack(fill="x", padx=12, pady=2)
                ctk.CTkLabel(
                    r, text=label, anchor="w",
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color=COLORS["text_dim"],
                ).pack(side="left")
                ctk.CTkLabel(
                    r, text=value, anchor="e",
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    text_color=color,
                ).pack(side="right")

            # ── Ping stats ──
            _section_title("📈 Статистика пінгу")
            stats = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
            stats.pack(fill="x", pady=2, padx=4)

            avg_p = report.get("avg_ping", 0)
            ping_color = (
                COLORS["accent_green"] if avg_p < 30 else
                COLORS["accent_yellow"] if avg_p < 80 else
                COLORS["accent_red"]
            )
            _make_row(stats, "Середній ping:", f"{avg_p:.1f} мс", ping_color)
            _make_row(stats, "Мін / Макс:",
                      f"{report.get('min_ping', 0):.1f} / {report.get('max_ping', 0):.1f} мс")
            _make_row(stats, "Jitter:", f"{report.get('avg_jitter', 0):.1f} мс")
            _make_row(stats, "Втрати пакетів:", f"{report.get('avg_loss', 0):.2f}%")
            _make_row(stats, "Замірів зроблено:", f"{report.get('measurements', 0)}")

            blackouts = report.get("blackouts", 0)
            if blackouts:
                _make_row(stats, "⚠ Обривів інтернету:",
                          f"{blackouts}", COLORS["accent_red"])

            # ── Найкращий час/день ──
            if report_type == "daily":
                best_hours = report.get("best_hours", [])
                if best_hours:
                    _section_title("🏆 Найкращі години")
                    bh_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                    bh_frame.pack(fill="x", pady=2, padx=4)
                    for h in best_hours:
                        _make_row(bh_frame,
                                  f"{h['hour']:02d}:00",
                                  f"{h['avg_ping']:.0f} мс",
                                  COLORS["accent_green"])
            else:
                best = report.get("best_day")
                worst = report.get("worst_day")
                if best is not None or worst is not None:
                    _section_title("🏆 Рекорди тижня")
                    bw_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                    bw_frame.pack(fill="x", pady=2, padx=4)
                    DAY_FULL = ["Понеділок", "Вівторок", "Середа", "Четвер",
                                "П'ятниця", "Субота", "Неділя"]
                    if best is not None:
                        _make_row(bw_frame, "🏆 Найкращий день:",
                                  f"{DAY_FULL[best]} ({report.get('best_day_ping', 0):.0f} мс)",
                                  COLORS["accent_green"])
                    if worst is not None:
                        _make_row(bw_frame, "😔 Найгірший день:",
                                  f"{DAY_FULL[worst]} ({report.get('worst_day_ping', 0):.0f} мс)",
                                  COLORS["accent_red"])

            # ── Найкращий час за категоріями ──
            cat_keys_daily = [
                ("best_for_gaming",    "🎮", "Ігри",     "(пінг ≤ 50 мс)"),
                ("best_for_streaming", "📺", "Стрімінг", "(пінг ≤ 80 мс)"),
                ("best_for_work",      "💼", "Робота",   "(пінг ≤ 150 мс)"),
            ]
            has_cat = any(report.get(k[0]) for k in cat_keys_daily)
            if has_cat:
                title_lbl = "⏰ Найкращий час за категоріями" if report_type == "daily" \
                            else "⏰ Найкращі години (за тиждень)"
                _section_title(title_lbl)
                cat_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                cat_frame.pack(fill="x", pady=2, padx=4)
                for key, emoji, name, cond in cat_keys_daily:
                    hours = report.get(key, [])
                    if hours:
                        hour_strs = ", ".join(f"{h['hour']:02d}:00" for h in hours)
                        _make_row(cat_frame, f"{emoji} {name}", hour_strs,
                                  COLORS["accent_green"])

            # ── Найкращі ДНІ за категоріями (тільки для weekly) ──
            if report_type == "weekly":
                cat_keys_w = [
                    ("best_days_gaming",    "🎮", "Ігри"),
                    ("best_days_streaming", "📺", "Стрімінг"),
                    ("best_days_work",      "💼", "Робота"),
                ]
                has_cat_d = any(report.get(k[0]) for k in cat_keys_w)
                if has_cat_d:
                    _section_title("📆 Найкращі дні за категоріями")
                    cd_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                    cd_frame.pack(fill="x", pady=2, padx=4)
                    DAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]
                    for key, emoji, name in cat_keys_w:
                        days = report.get(key, [])
                        if days:
                            day_strs = ", ".join(
                                f"{DAYS[d['weekday']]} ({d['avg_ping']:.0f}мс)"
                                for d in days
                            )
                            _make_row(cd_frame, f"{emoji} {name}", day_strs,
                                      COLORS["accent_green"])

            # ── Глобальні сервіси ──
            services = report.get("services", {})
            if services:
                _section_title("🌍 Глобальні сервіси (стан)")
                svc_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                svc_frame.pack(fill="x", pady=2, padx=4)
                cat_names = [
                    ("gaming",    "🎮", "Ігри"),
                    ("streaming", "📺", "Стрімінг"),
                    ("work",      "💼", "Робота"),
                    ("general",   "🌐", "DNS / Інші"),
                ]
                for cat_key, emoji, name in cat_names:
                    cat = services.get(cat_key, {})
                    up   = cat.get("up", 0)
                    down = cat.get("down", 0)
                    if up + down > 0:
                        if down == 0:
                            status_icon, color = "🟢", COLORS["accent_green"]
                        elif up > down:
                            status_icon, color = "🟡", COLORS["accent_yellow"]
                        else:
                            status_icon, color = "🔴", COLORS["accent_red"]
                        _make_row(svc_frame,
                                  f"{emoji} {name}",
                                  f"{status_icon} {up}/{up+down}",
                                  color)

            # ── Циклони провайдера ──
            if report_type == "weekly":
                worst_days = report.get("worst_days", [])
                if worst_days and worst_days[0].get("avg_ping", 0) > 80:
                    _section_title("🌪 Циклони (найгірші дні)")
                    cw_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"],
                                            corner_radius=8)
                    cw_frame.pack(fill="x", pady=2, padx=4)
                    DAYS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]
                    for d in worst_days:
                        loss_str = f" ({d['loss']:.1f}% loss)" if d['loss'] > 1 else ""
                        _make_row(cw_frame, f"{DAYS[d['weekday']]}",
                                  f"avg {d['avg_ping']:.0f} / max {d['max_ping']:.0f} мс{loss_str}",
                                  COLORS["accent_red"])

            worst_hours = report.get("worst_hours", [])
            if worst_hours and worst_hours[0].get("avg_ping", 0) > 80:
                title_lbl = ("🌪 Циклони (найгірші години)" if report_type == "daily"
                             else "🕐 Найгірші години тижня")
                _section_title(title_lbl)
                ch_frame = ctk.CTkFrame(content, fg_color=COLORS["bg_card"], corner_radius=8)
                ch_frame.pack(fill="x", pady=2, padx=4)
                for h in worst_hours:
                    loss_str = f" ({h['loss']:.1f}% loss)" if h['loss'] > 1 else ""
                    _make_row(ch_frame, f"{h['hour']:02d}:00",
                              f"avg {h['avg_ping']:.0f} / max {h['max_ping']:.0f} мс{loss_str}",
                              COLORS["accent_red"])

            # ── Кнопка закриття ──
            ctk.CTkButton(
                popup, text="✓ Зрозуміло",
                command=popup.destroy,
                fg_color=COLORS["accent_cyan"],
                hover_color=COLORS["accent_blue"],
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                height=40,
            ).pack(fill="x", padx=20, pady=(0, 16))
        except Exception as e:
            import traceback
            print(f"[Forecast UI] _show_report_popup error: {e}")
            traceback.print_exc()

    def _sync_with_pi_async(self):
        """Викликає fill_gaps_from_pi у фоновому потоці, оновлює overlay.

        ВАЖЛИВО: Python 3.14 забороняє tk.after() з не-головного потоку!
        Тому worker лише ПИШЕ стан, а головний потік ЧИТАЄ через polling.
        """
        # Стан синхронізації (доступний з обох потоків)
        sync_state = {
            "status_text": "читаємо кеш Pi-агента...",
            "done": False,
            "result": None,
            "error": None,
            "started": time.time(),
        }
        self._sync_state = sync_state

        def worker():
            """Фоновий потік — НЕ викликає tk.after()!"""
            try:
                # Маркуємо статус через атрибут (не через after)
                sync_state["status_text"] = "читаємо кеш Pi-агента..."

                # Запускаємо fill_gaps з ВЛАСНИМ timeout через queue
                import queue
                result_queue = queue.Queue()

                def do_fill():
                    try:
                        added = self.engine.fill_gaps_from_pi()
                        result_queue.put(("ok", added))
                    except Exception as e:
                        result_queue.put(("error", str(e)))

                fill_thread = threading.Thread(target=do_fill, daemon=True)
                fill_thread.start()

                try:
                    status, value = result_queue.get(timeout=15.0)
                    if status == "ok":
                        sync_state["result"] = value
                        if value > 0:
                            sync_state["status_text"] = f"✅ синхронізовано: +{value} записів з Pi"
                        else:
                            sync_state["status_text"] = "ℹ️ Pi-кеш порожній або вже синхронізовано"
                    else:
                        sync_state["error"] = value
                        sync_state["status_text"] = f"⚠️ помилка: {value[:60]}"
                except queue.Empty:
                    sync_state["status_text"] = "⏱️ Pi-агент не відповідає за 15с, працюємо з локальними"
                    sync_state["error"] = "timeout"
            except Exception as e:
                sync_state["error"] = str(e)
                sync_state["status_text"] = f"⚠️ помилка: {str(e)[:60]}"
            finally:
                sync_state["done"] = True

        # ──────────── ГОЛОВНИЙ ПОТІК — POLLER через tk.after() ────────────
        def poll_state():
            """Опитує стан і оновлює UI. Викликається з головного потоку."""
            if not sync_state.get("done"):
                # Оновлюємо статус у UI
                try:
                    self._update_sync_status(sync_state.get("status_text", ""))
                except Exception:
                    pass
                # Перевіряємо timeout (на випадок якщо worker завис)
                if time.time() - sync_state["started"] > 20:
                    sync_state["done"] = True
                    sync_state["status_text"] = "⏱️ timeout 20с — перериваємо"
                # Полтрусь ще через 200мс
                self.after(200, poll_state)
            else:
                # Worker завершився — фінальне оновлення і ховаємо overlay
                try:
                    self._update_sync_status(sync_state.get("status_text", "готово"))
                except Exception:
                    pass
                # Затримка 1.5с щоб користувач побачив результат
                self.after(1500, self._hide_sync_overlay)

        # Стартуємо worker і поллер
        threading.Thread(target=worker, daemon=True).start()
        self.after(200, poll_state)

    # ═══════════════════════════════════════════════════════════════════════
    def _build_ui(self):
        row = 0
        self._alert_placeholder = ctk.CTkFrame(self, fg_color="transparent", height=0)
        self._alert_placeholder.grid(row=row, column=0, sticky="ew"); row += 1

        # PR #8: ОКРЕМИЙ ПОМІТНИЙ БАНЕР СИНХРОНІЗАЦІЇ
        self._build_sync_banner(row);       row += 1

        self._build_control_card(row);      row += 1
        self._build_weather_station(row);   row += 1
        self._build_sparkline_card(row);    row += 1
        self._build_weekly_outlook(row);    row += 1
        self._build_besttime_card(row);     row += 1
        self._build_services_panel(row);    row += 1
        self._build_hourly_chart_card(row); row += 1
        self._build_heatmap_card(row);      row += 1

    def _build_sync_banner(self, row: int):
        """ВЕЛИКА ПОМІТНА панель синхронізації — на всю ширину сторінки.

        Гарантовано видима — не може заховатись за іншими елементами.
        """
        banner = ctk.CTkFrame(
            self,
            fg_color="#0a2a1a",
            corner_radius=12,
            border_width=2,
            border_color=COLORS.get("accent_green", "#22c55e"),
            height=72,
        )
        banner.grid(row=row, column=0, padx=24, pady=(24, 0), sticky="ew")
        banner.grid_columnconfigure(1, weight=1)
        banner.grid_propagate(False)

        # Іконка
        ctk.CTkLabel(
            banner, text="🍓",
            font=ctk.CTkFont(size=32),
        ).grid(row=0, column=0, rowspan=2, padx=(20, 14), pady=12)

        # Текст
        ctk.CTkLabel(
            banner,
            text="СИНХРОНІЗАЦІЯ З RASPBERRY PI",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_green", "#22c55e"),
            anchor="w",
        ).grid(row=0, column=1, sticky="w", pady=(12, 0))

        self._lbl_sync_hint = ctk.CTkLabel(
            banner,
            text="Натисни кнопки справа щоб запросити дані з Pi або просто оновити сторінку",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_dim", "#94a3b8"),
            anchor="w",
        )
        self._lbl_sync_hint.grid(row=1, column=1, sticky="w", pady=(0, 12))

        # Контейнер для двох кнопок справа
        btns = ctk.CTkFrame(banner, fg_color="transparent")
        btns.grid(row=0, column=2, rowspan=2, padx=(0, 20), pady=12, sticky="e")

        # ВЕЛИКА ЗЕЛЕНА КНОПКА — СИНХРОНІЗАЦІЯ З Pi
        self._btn_big_sync = ctk.CTkButton(
            btns,
            text="🔄  СИНХРОНІЗУВАТИ",
            command=self._refresh_with_sync,
            fg_color=COLORS.get("accent_green", "#22c55e"),
            hover_color="#16a34a",
            text_color="#0a0e1a",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            height=48,
            corner_radius=10,
            width=180,
        )
        self._btn_big_sync.pack(side="left", padx=(0, 8))

        # КНОПКА ОНОВЛЕННЯ СТОРІНКИ
        self._btn_reload = ctk.CTkButton(
            btns,
            text="↻  ОНОВИТИ",
            command=self._run_full_refresh,
            fg_color="#1a1a2e",
            hover_color="#252548",
            text_color=COLORS.get("accent_cyan", "#22d3ee"),
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            height=48,
            corner_radius=10,
            width=140,
            border_width=2,
            border_color=COLORS.get("accent_cyan", "#22d3ee"),
        )
        self._btn_reload.pack(side="left")

    # ─────────────────────────────────────────────────────────────────────
    #  ПАНЕЛЬ КЕРУВАННЯ
    # ─────────────────────────────────────────────────────────────────────

    def _build_control_card(self, row: int):
        card = GlowCard(self, accent=COLORS["accent_yellow"])
        card.grid(row=row, column=0, padx=24, pady=(24, 10), sticky="ew")
        card.grid_columnconfigure(1, weight=1)

        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=0, column=0, padx=28, pady=22, sticky="w")

        ctk.CTkLabel(
            left,
            text="🌦️  INTERNET WEATHER FORECAST",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=COLORS["accent_yellow"],
        ).pack(anchor="w")

        ctk.CTkLabel(
            left,
            text="Аналізує твою мережу як метеостанція — прогноз на 7 днів",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS["text_secondary"],
        ).pack(anchor="w", pady=(6, 2))

        ctk.CTkLabel(
            left,
            text="Пінг = Температура  ·  Джиттер = Вітер  ·  Втрата пакетів = Опади",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w")

        right = ctk.CTkFrame(card, fg_color="transparent")
        right.grid(row=0, column=1, padx=28, pady=22, sticky="e")

        self._lbl_last_update = ctk.CTkLabel(
            right, text="Останнє оновлення: —",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
        )
        self._lbl_last_update.pack(anchor="e", pady=(0, 8))

        self._btn_refresh = ctk.CTkButton(
            right,
            text="🔄  ОНОВИТИ + СИНХРОНІЗАЦІЯ",
            command=self._refresh_with_sync,
            fg_color="#3a2a00", hover_color="#5a3d00",
            text_color=COLORS["accent_yellow"],
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            height=50, corner_radius=12,
            border_width=1, border_color=COLORS["accent_yellow"],
        )
        self._btn_refresh.pack(pady=(0, 8), fill="x")

        ctk.CTkButton(
            right,
            text="📡  Throttling Test",
            command=self._run_throttling,
            fg_color="#1a1a00", hover_color="#2a2800",
            text_color=COLORS["accent_yellow"],
            font=ctk.CTkFont(family="Consolas", size=13),
            height=38, corner_radius=10,
            border_width=1, border_color=COLORS["accent_yellow"],
        ).pack(fill="x")

        # ─── PR #4: Плашка статусу Raspberry Pi ────────────────────────────
        # Видно одразу — Pi працює чи ні
        pi_frame = ctk.CTkFrame(
            right, fg_color="#0a1018", corner_radius=10,
            border_width=1, border_color="#1a2540",
        )
        pi_frame.pack(fill="x", pady=(10, 0))

        self._pi_status_icon = ctk.CTkLabel(
            pi_frame, text="🍓",
            font=ctk.CTkFont(size=18),
        )
        self._pi_status_icon.pack(side="left", padx=(10, 5), pady=8)

        pi_text_frame = ctk.CTkFrame(pi_frame, fg_color="transparent")
        pi_text_frame.pack(side="left", fill="x", expand=True, pady=6)

        self._pi_status_label = ctk.CTkLabel(
            pi_text_frame, text="Raspberry Pi",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color="#a0c8ff",
            anchor="w",
        )
        self._pi_status_label.pack(fill="x")

        self._pi_status_detail = ctk.CTkLabel(
            pi_text_frame, text="перевіряємо...",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color="#607080",
            anchor="w",
        )
        self._pi_status_detail.pack(fill="x")

        # Запускаємо поллер статусу
        self._update_pi_status()
        self.after(5000, self._pi_status_loop)

    def _pi_status_loop(self):
        """Поллер, оновлює статус Pi кожні 5 секунд."""
        try:
            self._update_pi_status()
        except Exception:
            pass
        # Наступний апдейт через 5с
        self.after(5000, self._pi_status_loop)

    def _update_pi_status(self):
        """Перевіряє стан Raspberry Pi і оновлює плашку.

        Логіка:
          🟢 ONLINE  — є свіжий heartbeat за останні 90 секунд
          🟡 SYNCING — є записи у remote_ping, але heartbeat застарів
          🔴 OFFLINE — нічого не отримували > 5 хвилин
          ⚫ NO DATA — БД пуста, Pi ніколи не підключався
        """
        try:
            import sqlite3, os
            from datetime import datetime
            db = os.path.expanduser("~/.netguardian/pi_agent_cache.db")
            if not os.path.exists(db):
                self._set_pi_status("⚫", "BД відсутня", "subscriber не запущено", "#607080")
                return

            with sqlite3.connect(db, timeout=3) as conn:
                c = conn.cursor()

                # Heartbeat
                try:
                    c.execute("""
                        SELECT MAX(ts) FROM remote_heartbeat
                        WHERE ts >= datetime('now', '-10 minutes', 'localtime')
                    """)
                    hb_row = c.fetchone()
                    hb_ts = hb_row[0] if hb_row else None
                except Exception:
                    hb_ts = None

                # Кількість ping за останні 5 хв
                try:
                    c.execute("""
                        SELECT COUNT(*), MAX(ts) FROM remote_ping
                        WHERE ts >= datetime('now', '-5 minutes', 'localtime')
                    """)
                    row = c.fetchone()
                    ping_5min = row[0] if row else 0
                    ping_last_ts = row[1] if row else None
                except Exception:
                    ping_5min = 0
                    ping_last_ts = None

                # Тотал ping за день
                try:
                    c.execute("""
                        SELECT COUNT(*) FROM remote_ping
                        WHERE ts >= datetime('now', '-24 hours', 'localtime')
                    """)
                    ping_24h = c.fetchone()[0]
                except Exception:
                    ping_24h = 0

            # Визначаємо статус
            if hb_ts:
                # Парсимо timestamp
                try:
                    hb_dt = datetime.strptime(hb_ts, "%Y-%m-%d %H:%M:%S")
                    age = (datetime.now() - hb_dt).total_seconds()
                except Exception:
                    age = 999

                if age < 90:
                    self._set_pi_status(
                        "🟢", "Raspberry Pi · ONLINE",
                        f"heartbeat {int(age)}с · {ping_24h} вимірів/24г",
                        "#00ff88"
                    )
                    return

            if ping_5min > 0:
                self._set_pi_status(
                    "🟡", "Raspberry Pi · СИНХРОНІЗАЦІЯ",
                    f"{ping_5min} нових вимірів · загалом {ping_24h}/24г",
                    "#ffaa00"
                )
                return

            if ping_24h > 0:
                self._set_pi_status(
                    "🟠", "Raspberry Pi · НЕМАЄ СВІЖИХ ДАНИХ",
                    f"останні 5хв тиша · є {ping_24h} за 24г",
                    "#ff7700"
                )
                return

            self._set_pi_status(
                "🔴", "Raspberry Pi · OFFLINE",
                "немає даних — перевір агент",
                "#ff4444"
            )
        except Exception as e:
            try:
                self._set_pi_status("⚫", "Pi status error", str(e)[:30], "#607080")
            except Exception:
                pass

    def _set_pi_status(self, icon: str, title: str, detail: str, color: str):
        """Оновлює плашку статусу Pi."""
        try:
            self._pi_status_icon.configure(text=icon)
            self._pi_status_label.configure(text=title, text_color=color)
            self._pi_status_detail.configure(text=detail)
        except Exception:
            pass

    def _build_network_selector(self, card):
        """
        Панель вибору мережі.
        Показує поточну мережу, дозволяє перемикатись між відомими
        та перейменовувати їх.
        """
        sep = ctk.CTkFrame(card, fg_color=COLORS.get("border", "#1e1e3a"), height=1)
        sep.grid(row=1, column=0, padx=20, pady=(0, 0), sticky="ew")

        net_panel = ctk.CTkFrame(
            card,
            fg_color=COLORS.get("bg_secondary", "#0f0f1e"),
            corner_radius=0,
        )
        net_panel.grid(row=2, column=0, padx=0, pady=(0, 0), sticky="ew")
        net_panel.grid_columnconfigure(1, weight=1)

        # Іконка + підпис
        ctk.CTkLabel(
            net_panel,
            text="📶  МЕРЕЖА:",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=COLORS.get("text_dim", "#475569"),
        ).grid(row=0, column=0, padx=(20, 8), pady=12, sticky="w")

        # Назва поточної мережі (велика, яскрава)
        self._lbl_net_name = ctk.CTkLabel(
            net_panel,
            text=self.engine.display_name,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS.get("accent_yellow", "#eab308"),
            anchor="w",
        )
        self._lbl_net_name.grid(row=0, column=1, sticky="w", padx=(0, 12))

        # Кількість вимірювань для цієї мережі
        self._lbl_net_stats = ctk.CTkLabel(
            net_panel,
            text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("text_dim", "#475569"),
        )
        self._lbl_net_stats.grid(row=0, column=2, padx=(0, 12), sticky="e")

        # Кнопки праворуч
        btn_frame = ctk.CTkFrame(net_panel, fg_color="transparent")
        btn_frame.grid(row=0, column=3, padx=(0, 14), pady=8, sticky="e")

        # ✏️ Перейменувати
        ctk.CTkButton(
            btn_frame,
            text="✏️  Перейменувати",
            command=self._rename_current_network,
            fg_color=COLORS.get("bg_card", "#1a1a2e"),
            hover_color=COLORS.get("bg_secondary", "#13132b"),
            text_color=COLORS.get("text_secondary", "#94a3b8"),
            font=ctk.CTkFont(family="Consolas", size=12),
            height=34, corner_radius=8,
            border_width=1,
            border_color=COLORS.get("border", "#1e1e3a"),
            width=160,
        ).pack(side="left", padx=(0, 8))

        # 🗂️ Переключити мережу (якщо є кілька)
        self._btn_switch_net = ctk.CTkButton(
            btn_frame,
            text="🗂️  Всі мережі",
            command=self._open_network_switcher,
            fg_color=COLORS.get("bg_card", "#1a1a2e"),
            hover_color=COLORS.get("bg_secondary", "#13132b"),
            text_color=COLORS.get("accent_cyan", "#22d3ee"),
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=34, corner_radius=8,
            border_width=2,
            border_color=COLORS.get("accent_cyan", "#22d3ee"),
            width=140,
        )
        self._btn_switch_net.pack(side="left")

        # _btn_force_sync ВЖЕ НЕ ТУТ — він у sync banner зверху.
        # Створюємо stub щоб старий код не падав
        self._btn_force_sync = self._btn_big_sync if hasattr(self, "_btn_big_sync") else None

        # Оновлюємо статистику мережі в фоні
        self.after(600, self._refresh_net_stats)

    def _refresh_net_stats(self):
        """Оновлює лічильник вимірювань для поточної мережі."""
        def _work():
            nets = self.engine.get_all_networks()
            current = next((n for n in nets if n.net_id == self.engine.net_id), None)
            if current:
                txt = f"({current.measurement_count} вимірювань  ·  з {current.first_seen[:10]})"
                self.after(0, lambda: self._lbl_net_stats.configure(text=txt))
        threading.Thread(target=_work, daemon=True).start()

    def _rename_current_network(self):
        """Відкриває діалог перейменування поточної мережі."""
        prompt = f"Введіть нову назву для мережі\n«{self.engine.display_name}»:"
        dialog = ctk.CTkInputDialog(
            text=prompt,
            title="✏️  Перейменувати мережу",
        )
        new_name = dialog.get_input()
        if new_name and new_name.strip():
            self.engine.rename_network(self.engine.net_id, new_name.strip())
            self._lbl_net_name.configure(text=self.engine.display_name)

    def _redetect_network(self):
        """Перевизначає поточну мережу (якщо змінили підключення)."""
        def _work():
            info = self.engine.detect_network()
            self.after(0, lambda: self._lbl_net_name.configure(
                text=info["display_name"]))
            self.after(0, self._refresh_net_stats)
            self.after(0, self._run_full_refresh)
        threading.Thread(target=_work, daemon=True).start()

    def _open_network_switcher(self):
        """Відкриває вікно-список усіх відомих мереж для переключення."""
        NetworkSwitcherWindow(self, self.engine, on_switch=self._on_network_switched)

    def _refresh_with_sync(self):
        """ВЕЛИКА кнопка "СИНХРОНІЗУВАТИ ЗАРАЗ" / "ОНОВИТИ + СИНХРОНІЗАЦІЯ".

        Виконує в одну дію:
          1. Шле cmd/send_history у Pi через MQTT
          2. Чекає 5 сек щоб дані прийшли
          3. Викликає fill_gaps_from_pi() → доллює у forecast.db
          4. Повна перерисовка усіх карток UI
        """
        # Показуємо busy-стан на ОБИДВОХ кнопках
        self._btn_refresh.configure(
            state="disabled",
            text="⏳  СИНХРОНІЗУЮ З Pi..."
        )
        if hasattr(self, "_btn_big_sync"):
            self._btn_big_sync.configure(
                state="disabled",
                text="⏳  СИНХРОНІЗУЮ..."
            )
        if hasattr(self, "_lbl_sync_hint"):
            self._lbl_sync_hint.configure(
                text="Шлю запит Pi-агенту і чекаю 5 секунд...",
                text_color=COLORS.get("accent_yellow", "#eab308"),
            )

        def worker():
            # ── Крок 1: послати команду Pi ──
            try:
                from features.forecast.mqtt_subscriber import get_global_subscriber
                sub = get_global_subscriber()
                if sub and sub.is_connected:
                    sub.send_command("send_history", {"hours": 24})
                    print("[ForecastUI] 📡 cmd/send_history → Pi")
                else:
                    print("[ForecastUI] ⚠️ MQTT subscriber недоступний")
            except Exception as e:
                print(f"[ForecastUI] sync command error: {e}")

            time.sleep(5)

            added = 0
            try:
                added = self.engine.fill_gaps_from_pi()
                print(f"[ForecastUI] ✅ refresh+sync: +{added} рядків")
            except Exception as e:
                print(f"[ForecastUI] fill_gaps error: {e}")

            def update_ui():
                badge = f"+{added}" if added > 0 else "OK"

                # Маленька жовта кнопка
                self._btn_refresh.configure(
                    state="normal",
                    text=f"🔄  ОНОВИТИ + СИНХРОНІЗАЦІЯ  ({badge})"
                )

                # Велика зелена кнопка
                if hasattr(self, "_btn_big_sync"):
                    self._btn_big_sync.configure(
                        state="normal",
                        text=f"✅  ГОТОВО  ({badge})"
                    )
                if hasattr(self, "_lbl_sync_hint"):
                    if added > 0:
                        self._lbl_sync_hint.configure(
                            text=f"Додано {added} нових записів з Pi-кешу!",
                            text_color=COLORS.get("accent_green", "#22c55e"),
                        )
                    else:
                        self._lbl_sync_hint.configure(
                            text="Дані вже актуальні — нових записів немає.",
                            text_color=COLORS.get("text_dim", "#94a3b8"),
                        )

                # Через 5 сек повертаємо звичайний текст
                def restore():
                    self._btn_refresh.configure(
                        text="🔄  ОНОВИТИ + СИНХРОНІЗАЦІЯ")
                    if hasattr(self, "_btn_big_sync"):
                        self._btn_big_sync.configure(
                            text="🔄  СИНХРОНІЗУВАТИ")
                    if hasattr(self, "_lbl_sync_hint"):
                        self._lbl_sync_hint.configure(
                            text="Натисни кнопки справа щоб запросити дані з Pi або просто оновити сторінку",
                            text_color=COLORS.get("text_dim", "#94a3b8"),
                        )
                self.after(5000, restore)

                try:
                    self._run_full_refresh()
                except Exception as e:
                    print(f"[ForecastUI] refresh error: {e}")

            self.after(0, update_ui)

        threading.Thread(target=worker, daemon=True,
                         name="RefreshWithSync").start()

    def _force_sync_with_pi(self):
        """PR #8: ПРИМУСОВА синхронізація з Pi.

        1. Шле cmd/send_history → Pi надсилає всі дані
        2. Чекає ~5 секунд щоб дані надійшли в pi_agent_cache.db
        3. Викликає fill_gaps_from_pi() → доллює у forecast.db
        4. Перебудовує всі картки UI

        Корисно коли автосинхронізація не спрацювала після пробудження ПК.
        """
        self._btn_force_sync.configure(state="disabled", text="⏳  синхронізація...")

        def worker():
            try:
                from features.forecast.mqtt_subscriber import get_global_subscriber
                sub = get_global_subscriber()
            except Exception:
                sub = None

            # ── Крок 1: команда send_history ──
            if sub:
                try:
                    sub.send_command("send_history", {"hours": 24})
                    print("[ForecastUI] 🔄 sent cmd/send_history to Pi")
                except Exception as e:
                    print(f"[ForecastUI] send_history error: {e}")

            # ── Крок 2: чекаємо щоб дані надійшли ──
            print("[ForecastUI] чекаємо 6 секунд щоб Pi надіслав дані...")
            time.sleep(6)

            # ── Крок 3: fill_gaps_from_pi ──
            added = 0
            try:
                added = self.engine.fill_gaps_from_pi()
                print(f"[ForecastUI] ✅ force sync: +{added} рядків")
            except Exception as e:
                print(f"[ForecastUI] fill_gaps error: {e}")

            # ── Крок 4: оновити UI з головного потоку ──
            def update_ui():
                msg = f"✅ +{added} запис(ів)" if added > 0 else "ℹ️ дані вже актуальні"
                self._btn_force_sync.configure(state="normal",
                                                text=f"🔄  Sync ({msg})")
                # Через 3 сек повертаємо звичайний текст
                self.after(3000, lambda: self._btn_force_sync.configure(
                    text="🔄  Sync з Pi"))
                # Перебудовуємо картки
                try:
                    self._run_full_refresh()
                except Exception:
                    pass

            self.after(0, update_ui)

        threading.Thread(target=worker, daemon=True,
                         name="ForceSync").start()

    def _on_network_switched(self, net_id: str):
        """Callback при виборі іншої мережі в switcher-вікні."""
        ok = self.engine.switch_network(net_id)
        if ok:
            self._lbl_net_name.configure(text=self.engine.display_name)
            self._refresh_net_stats()
            self._run_full_refresh()

    # ─────────────────────────────────────────────────────────────────────
    #  МЕТЕОСТАНЦІЯ
    # ─────────────────────────────────────────────────────────────────────

    def _build_weather_station(self, row: int):
        card = GlowCard(self, accent=COLORS["border"])
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_columnconfigure(1, weight=0)
        card.grid_columnconfigure(2, weight=1)

        # ── Заголовок секції з кнопкою ? ──────────────────────────────────
        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, columnspan=3, padx=24, pady=(18, 4), sticky="ew")

        sh = _section_header(hdr, "📡", "СТАН МЕРЕЖІ  ·  ПРЯМО ЗАРАЗ",
                             "station", COLORS["text_primary"])
        sh.pack(fill="x")

        # ── Ліво: іконка + заголовок + порада ────────────────────────────
        left = ctk.CTkFrame(card, fg_color="transparent")
        left.grid(row=1, column=0, padx=30, pady=20, sticky="w")

        self._lbl_weather_icon = ctk.CTkLabel(
            left, text="🌐",
            font=ctk.CTkFont(size=90),
        )
        self._lbl_weather_icon.pack()

        self._lbl_weather_title = ctk.CTkLabel(
            left, text="Вимірювання...",
            font=ctk.CTkFont(family="Consolas", size=20, weight="bold"),
            text_color=COLORS["accent_yellow"],
        )
        self._lbl_weather_title.pack(pady=(8, 0))

        self._lbl_weather_desc = ctk.CTkLabel(
            left, text="Зачекайте...",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS["text_secondary"],
            justify="center", wraplength=260,
        )
        self._lbl_weather_desc.pack(pady=(4, 0))

        # Порада Метеоролога
        hint_box = ctk.CTkFrame(
            left,
            fg_color=COLORS.get("bg_secondary", "#13132b"),
            corner_radius=10, border_width=1, border_color=COLORS["border"],
        )
        hint_box.pack(fill="x", pady=(18, 0))

        ctk.CTkLabel(
            hint_box,
            text="💡  ПОРАДА МЕТЕОРОЛОГА",
            font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
            text_color=COLORS["text_dim"],
        ).pack(anchor="w", padx=14, pady=(10, 0))

        self._lbl_hint = ctk.CTkLabel(
            hint_box, text="Аналіз мережі...",
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color=COLORS["text_secondary"],
            justify="left", wraplength=250,
        )
        self._lbl_hint.pack(anchor="w", padx=14, pady=(2, 12))

        # ── Центр: Weather Index ──────────────────────────────────────────
        center = ctk.CTkFrame(card, fg_color="transparent")
        center.grid(row=1, column=1, padx=24, pady=20)

        ctk.CTkLabel(
            center, text="WEATHER INDEX",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=COLORS["text_dim"], justify="center",
        ).pack()

        self._index_canvas = tk.Canvas(
            center, width=130, height=130,
            bg=COLORS.get("bg_primary", "#0d0d1a"), highlightthickness=0,
        )
        self._index_canvas.pack(pady=8)
        self._draw_index_gauge(0)

        self._lbl_index_value = ctk.CTkLabel(
            center, text="—",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS["text_secondary"],
        )
        self._lbl_index_value.pack()

        # ── Право: три метрики + швидкість + SLA ─────────────────────────
        right = ctk.CTkFrame(card, fg_color="transparent")
        right.grid(row=1, column=2, padx=30, pady=20, sticky="e")

        self._metric_labels: dict[str, ctk.CTkLabel] = {}

        for icon_txt, label_txt, key in [
            ("🌡️", "ПІНГ",           "ping"),
            ("💨", "ДЖИТТЕР",        "jitter"),
            ("🌧️", "ВТРАТА ПАКЕТІВ", "loss"),
        ]:
            block = ctk.CTkFrame(right, fg_color="transparent")
            block.pack(anchor="e", pady=6)

            # Підпис маленький зверху
            ctk.CTkLabel(
                block,
                text=f"{icon_txt}  {label_txt}",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS["text_dim"],
            ).pack(anchor="e")

            # Значення велике знизу
            val = ctk.CTkLabel(
                block, text="—",
                font=ctk.CTkFont(family="Consolas", size=26, weight="bold"),
                text_color=COLORS["text_primary"],
                anchor="e",
            )
            val.pack(anchor="e")
            self._metric_labels[key] = val

        tk.Frame(right, bg=COLORS["border"], height=1).pack(fill="x", pady=14)

        # Швидкість
        ctk.CTkLabel(right, text="ВІДЧУВАЄТЬСЯ ЯК",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS["text_dim"]).pack(anchor="e")

        self._lbl_perceived = ctk.CTkLabel(
            right, text="— Мбіт/с",
            font=ctk.CTkFont(family="Consolas", size=26, weight="bold"),
            text_color=COLORS["accent_green"],
        )
        self._lbl_perceived.pack(anchor="e")

        self._lbl_nominal = ctk.CTkLabel(
            right, text="номінал: —",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_dim"],
        )
        self._lbl_nominal.pack(anchor="e")

        tk.Frame(right, bg=COLORS["border"], height=1).pack(fill="x", pady=14)

        # SLA
        ctk.CTkLabel(right, text="НАДІЙНІСТЬ ISP (SLA)",
                     font=ctk.CTkFont(family="Consolas", size=10),
                     text_color=COLORS["text_dim"]).pack(anchor="e")

        self._lbl_sla = ctk.CTkLabel(
            right, text="— %",
            font=ctk.CTkFont(family="Consolas", size=26, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee"),
        )
        self._lbl_sla.pack(anchor="e")

        self._sla_bar_bg = ctk.CTkFrame(
            right, fg_color=COLORS.get("bg_secondary", "#13132b"),
            height=8, corner_radius=4,
        )
        self._sla_bar_bg.pack(fill="x", pady=(4, 0))
        self._sla_bar = ctk.CTkFrame(
            self._sla_bar_bg, fg_color=COLORS.get("accent_cyan", "#22d3ee"),
            height=8, corner_radius=4, width=0,
        )
        self._sla_bar.place(x=0, y=0)

    # ─────────────────────────────────────────────────────────────────────
    #  LIVE PING SPARKLINE
    # ─────────────────────────────────────────────────────────────────────

    def _build_sparkline_card(self, row: int):
        card = GlowCard(self, accent=COLORS.get("accent_cyan", "#22d3ee"))
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=24, pady=(18, 4), sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)

        sh = _section_header(hdr, "📶", "LIVE PING  ·  РЕАЛЬНИЙ ЧАС",
                             "sparkline", COLORS.get("accent_cyan", "#22d3ee"))
        sh.grid(row=0, column=0, sticky="w")

        self._lbl_live_ping = ctk.CTkLabel(
            hdr, text="— мс",
            font=ctk.CTkFont(family="Consolas", size=28, weight="bold"),
            text_color=COLORS.get("accent_cyan", "#22d3ee"),
        )
        self._lbl_live_ping.grid(row=0, column=1, sticky="e")

        self._spark_canvas = tk.Canvas(
            card, bg=COLORS.get("bg_primary", "#0d0d1a"),
            highlightthickness=0, height=90,
        )
        self._spark_canvas.grid(row=1, column=0, padx=15, pady=(4, 14), sticky="ew")
        self._draw_spark_placeholder()

    def _spark_tick(self):
        """Запускає вимір у фоновому потоці.
        Python 3.14: НЕ можна викликати tk.after() з потоку!
        Тому worker лише пише результат у self._spark_pending,
        а poll-метод читає його з головного потоку.
        """
        def measure():
            import socket, time
            try:
                t0 = time.perf_counter()
                with socket.create_connection(("8.8.8.8", 443), timeout=2):
                    pass
                ms = round((time.perf_counter() - t0) * 1000, 1)
            except Exception:
                ms = -1.0
            # Записуємо результат у атрибут (НЕ викликаємо after!)
            self._spark_pending = ms

        # Запускаємо worker
        self._spark_pending = None
        threading.Thread(target=measure, daemon=True).start()

        # Поллер у головному потоці — перевіряє результат через 100мс
        self._poll_spark_result(attempts=30)

        # Наступний tick через 5 секунд
        self._spark_timer = self.after(5000, self._spark_tick)

    def _poll_spark_result(self, attempts: int = 30):
        """Опитує результат measure() з головного потоку (БЕЗПЕЧНО)."""
        if self._spark_pending is not None:
            ms = self._spark_pending
            self._spark_pending = None
            try:
                self._spark_push(ms)
            except Exception:
                pass
            return
        if attempts > 0:
            # Спробуємо ще раз через 100мс
            self.after(100, lambda: self._poll_spark_result(attempts - 1))

    def _spark_push(self, ms: float):
        if ms > 0:
            self._sparkline_data.append(ms)
            if len(self._sparkline_data) > SPARKLINE_MAX:
                self._sparkline_data = self._sparkline_data[-SPARKLINE_MAX:]
            color = (
                COLORS["accent_red"]    if ms > 150 else
                COLORS["accent_yellow"] if ms > 50  else
                COLORS.get("accent_cyan", "#22d3ee")
            )
            self._lbl_live_ping.configure(
                text=f"{ms:.0f} мс", text_color=color)
        self._draw_sparkline()

    def _draw_sparkline(self):
        canvas = self._spark_canvas
        canvas.delete("all")
        W    = canvas.winfo_width() or 800
        H    = 90
        data = self._sparkline_data
        if not data:
            self._draw_spark_placeholder(); return

        pl, pr, pt, pb = 10, 10, 8, 22
        cw, ch = W - pl - pr, H - pt - pb
        max_v  = max(max(data), 1)
        min_v  = max(min(data) - 5, 0)
        rng    = max(max_v - min_v, 1)
        step   = cw / max(len(data) - 1, 1)

        for threshold, bg in [(150 / max_v, "#180404"), (50 / max_v, "#181400")]:
            zy = pt + ch - min(1.0, threshold) * ch
            canvas.create_rectangle(pl, zy, W - pr, pt + ch, fill=bg, outline="")

        pts = [
            (pl + i * step, pt + ch - ((v - min_v) / rng) * ch * 0.9)
            for i, v in enumerate(data)
        ]

        poly = [pl, pt + ch] + [c for p in pts for c in p] + [pts[-1][0], pt + ch]
        canvas.create_polygon(poly, fill="#062230", outline="")

        if len(pts) > 1:
            canvas.create_line(
                *[c for p in pts for c in p],
                fill=COLORS.get("accent_cyan", "#22d3ee"),
                width=2, smooth=True,
            )

        lx, ly = pts[-1]
        canvas.create_oval(lx - 5, ly - 5, lx + 5, ly + 5,
                           fill=COLORS.get("accent_cyan", "#22d3ee"), outline="")

        canvas.create_text(pl, H - 6, text=f"–{len(data)*5}с",
                           fill=COLORS["text_dim"], font=("Consolas", 8), anchor="w")
        canvas.create_text(W - pr, H - 6, text="зараз",
                           fill=COLORS["text_dim"], font=("Consolas", 8), anchor="e")

    def _draw_spark_placeholder(self):
        c = self._spark_canvas
        c.delete("all")
        c.create_text(400, 44, text="Live дані з'являться через ~10 секунд...",
                      fill="#334155", font=("Consolas", 11))

    # ─────────────────────────────────────────────────────────────────────
    #  ТИЖНЕВИЙ ПРОГНОЗ
    # ─────────────────────────────────────────────────────────────────────

    def _build_weekly_outlook(self, row: int):
        """
        Замість прогнозу-передбачення тепер показуємо РЕАЛЬНУ ІСТОРІЮ.
        Перемикач: 7д (рядок) ↔ 30д (календарна сітка).
        """
        card = GlowCard(self, accent=COLORS["border"])
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(18, 4))
        hdr.grid_columnconfigure(0, weight=1)

        sh = _section_header(hdr, "📅", "ІСТОРІЯ ПОГОДИ  ·  РЕАЛЬНІ ДАНІ",
                             "weekly", COLORS["text_primary"])
        sh.grid(row=0, column=0, sticky="w")

        # Перемикач: 7д / 30д (2 кнопки)
        self._history_range = 7  # за замовчуванням
        switch_frame = ctk.CTkFrame(hdr, fg_color="transparent")
        switch_frame.grid(row=0, column=1, sticky="e")
        self._range_buttons = {}
        for d in (7, 30):
            b = ctk.CTkButton(
                switch_frame, text=f"{d} днів", width=80, height=30,
                corner_radius=8,
                fg_color=COLORS["accent_blue"] if d == 7 else COLORS["bg_secondary"],
                hover_color=COLORS["accent_cyan"],
                text_color=COLORS["text_primary"],
                font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                command=lambda days=d: self._switch_history_range(days),
            )
            b.pack(side="left", padx=3)
            self._range_buttons[d] = b

        # Контейнер для двох режимів
        # PR #13: fill="both" + достатня минімум висота для 30-денного режиму
        self._weekly_container = ctk.CTkFrame(card, fg_color="transparent")
        self._weekly_container.pack(fill="both", expand=True,
                                     padx=16, pady=(10, 18))
        self._weekly_container.grid_columnconfigure(0, weight=1)
        self._weekly_container.grid_rowconfigure(0, weight=1)

        # ── РЕЖИМ 7 ДНІВ: горизонтальний рядок ──
        self._weekly_row_frame = ctk.CTkFrame(
            self._weekly_container, fg_color="transparent"
        )
        self._weekly_row_frame.grid(row=0, column=0, sticky="ew")
        for i in range(7):
            self._weekly_row_frame.grid_columnconfigure(i, weight=1)

        # ── РЕЖИМ 30 ДНІВ: календарна сітка 5×7 ──
        # 1 рядок заголовків + 5 рядків днів
        self._calendar_frame = ctk.CTkFrame(
            self._weekly_container, fg_color="transparent"
        )
        for i in range(7):
            self._calendar_frame.grid_columnconfigure(i, weight=1, uniform="cal")
        # Робимо рядки однакової висоти
        for r in range(1, 6):
            self._calendar_frame.grid_rowconfigure(r, weight=1, uniform="row",
                                                     minsize=100)

        # Заголовки днів тижня в календарі
        DAY_HEADERS = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]
        for col, day_name in enumerate(DAY_HEADERS):
            ctk.CTkLabel(
                self._calendar_frame, text=day_name,
                font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                text_color=COLORS["text_dim"],
            ).grid(row=0, column=col, sticky="ew", pady=(0, 4))

        # ── Widgets створюються динамічно у _render_history ──
        # (для уникнення проблем з grid_configure(in_=...))
        self._weekly_day_widgets: list[dict] = []

        # Підпис унизу
        self._history_info = ctk.CTkLabel(
            card, text="", anchor="center",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
        )
        self._history_info.pack(pady=(0, 10))

    def _switch_history_range(self, days: int):
        """Перемикає діапазон історії 7д/30д."""
        self._history_range = days
        for d, btn in self._range_buttons.items():
            btn.configure(
                fg_color=COLORS["accent_blue"] if d == days else COLORS["bg_secondary"]
            )
        # Для 30 днів потрібно більше місця
        if days == 30:
            # Робимо контейнер вище — мінімум 550px для 5 рядків
            try:
                self._weekly_container.configure(height=580)
                self._weekly_container.pack_propagate(False)
            except Exception:
                pass
        else:
            # Для 7 днів — компактна висота
            try:
                self._weekly_container.configure(height=180)
                self._weekly_container.pack_propagate(False)
            except Exception:
                pass

        try:
            self._render_history()
        except Exception as e:
            print(f"[Forecast UI] _switch_history_range error: {e}")

    def _render_history(self):
        """Рендерить історію у одному з двох режимів:
          • 7 днів  — горизонтальний рядок
          • 30 днів — календарна сітка 5×7

        ПРОСТА ЛОГІКА: знищуємо старі віджети, створюємо нові у потрібному
        контейнері. Це уникає проблем з grid_configure(in_=...) у CTk.
        """
        try:
            history_data = self.engine.get_monthly_history(days=self._history_range)
        except Exception as e:
            print(f"[Forecast UI] get_monthly_history error: {e}")
            return

        days = history_data.get("days", [])
        days = days[-self._history_range:]

        today_str = datetime.datetime.now().strftime("%Y-%m-%d")

        # Знищуємо всі старі віджети
        for w in self._weekly_day_widgets:
            try:
                w["frame"].destroy()
            except Exception:
                pass
        self._weekly_day_widgets = []

        print(f"[Forecast UI] Render history: range={self._history_range}, "
              f"got {len(days)} days from engine")

        if not days:
            self._history_info.configure(
                text="📊 Немає даних за вибраний період")
            return

        # ── РЕЖИМ 7 ДНІВ: горизонтальний рядок ──
        if self._history_range == 7:
            self._calendar_frame.grid_forget()
            self._weekly_row_frame.grid(row=0, column=0, sticky="ew")

            # Очищуємо row_frame від ВСІХ дітей
            for child in self._weekly_row_frame.winfo_children():
                child.destroy()
            for i in range(7):
                self._weekly_row_frame.grid_columnconfigure(i, weight=1)

            for i, day in enumerate(days):
                is_today = (day["date"] == today_str)
                widget = self._make_day_widget(
                    self._weekly_row_frame, i,
                    day["icon"], day["day_name"],
                    day["avg_ping"], int((day["loss"] or 0) * 20)
                )
                widget["frame"].grid(row=0, column=i, padx=4, sticky="nsew")
                self._update_day_widget(widget, day, is_today)
                self._weekly_day_widgets.append(widget)

        # ── РЕЖИМ 30 ДНІВ: календарна сітка ──
        else:
            self._weekly_row_frame.grid_forget()
            self._calendar_frame.grid(row=0, column=0, sticky="nsew")

            # Очищуємо календар (КРІМ заголовків днів тижня у row=0)
            for child in self._calendar_frame.winfo_children():
                info = child.grid_info()
                if info.get("row", 0) != 0:  # не заголовок
                    child.destroy()

            # Розрахунок позиції першого дня
            try:
                first_dt = datetime.datetime.strptime(days[0]["date"], "%Y-%m-%d")
                first_wd = first_dt.weekday()
            except Exception:
                first_wd = 0

            for i, day in enumerate(days):
                is_today = (day["date"] == today_str)

                # Позиція у календарі
                pos = first_wd + i
                grid_row = (pos // 7) + 1   # +1 бо row=0 — заголовки
                grid_col = pos % 7

                widget = self._make_day_widget(
                    self._calendar_frame, i,
                    day["icon"], day["day_name"],
                    day["avg_ping"], int((day["loss"] or 0) * 20)
                )
                widget["frame"].grid(row=grid_row, column=grid_col,
                                       padx=3, pady=3, sticky="nsew")
                self._update_day_widget(widget, day, is_today)
                self._weekly_day_widgets.append(widget)

        # ── Підпис унизу ──
        from_date = days[0]["date"]
        to_date = days[-1]["date"]
        try:
            from_dt = datetime.datetime.strptime(from_date, "%Y-%m-%d")
            to_dt = datetime.datetime.strptime(to_date, "%Y-%m-%d")
            pretty = f"{from_dt.strftime('%d.%m')} — {to_dt.strftime('%d.%m')}"
        except Exception:
            pretty = f"{from_date} — {to_date}"
        self._history_info.configure(
            text=f"📊 Період: {pretty}  ·  {len(days)} днів з даними  ·  "
                 f"Клікни на день щоб побачити деталі"
        )

    def _update_day_widget(self, widgets: dict, day: dict, is_today: bool):
        """Оновлює дані у віджеті дня (іконка, ping, ризик, click handler)."""
        widgets["frame"].configure(
            border_color=COLORS["accent_yellow"] if is_today else COLORS["border"],
            border_width=2 if is_today else 1,
            fg_color="#2a2200" if is_today else COLORS["bg_card"],
        )

        # Зберігаємо дату для click handler
        widgets["frame"]._day_date = day["date"]

        def make_click_handler(date_str):
            def handler(event):
                now = time.time()
                last = getattr(self, "_last_day_click", 0)
                if now - last < 0.5:  # 500мс debounce
                    return
                self._last_day_click = now
                self._show_day_details(date_str)
            return handler

        handler = make_click_handler(day["date"])
        widgets["frame"].bind("<Button-1>", handler)
        for w_key in ("day", "icon", "ping"):
            if w_key in widgets:
                widgets[w_key].bind("<Button-1>", handler)

        # Формат дати: "10.05" + день тижня "Сб"
        try:
            dt = datetime.datetime.strptime(day["date"], "%Y-%m-%d")
            date_label = dt.strftime("%d.%m")
        except Exception:
            date_label = day["date"]

        # Для 30-денного режиму компактніше показуємо
        if self._history_range == 30:
            day_text = f"{date_label}"
            if is_today: day_text += " ★"
        else:
            day_text = f"{date_label}\n{day['day_name']}"
            if is_today: day_text += "\n← сьогодні"

        widgets["day"].configure(
            text=day_text,
            text_color=COLORS["accent_yellow"] if is_today else COLORS["text_dim"],
            font=ctk.CTkFont(family="Consolas", size=10,
                              weight="bold" if is_today else "normal"),
        )
        widgets["icon"].configure(text=day["icon"])

        ping_font_size = 11 if self._history_range == 30 else (14 if is_today else 12)
        widgets["ping"].configure(
            text=f"{day['avg_ping']:.0f} мс",
            text_color=COLORS["text_primary"] if is_today else COLORS["text_secondary"],
            font=ctk.CTkFont(family="Consolas", size=ping_font_size, weight="bold"),
        )

        # Risk bar за loss
        risk_pct = min(100, int((day["loss"] or 0) * 20))
        risk_color = (
            "#22c55e" if risk_pct < 30 else
            "#eab308" if risk_pct < 60 else "#ef4444"
        )
        try:
            widgets["risk_bar"].configure(
                fg_color=risk_color,
                width=max(4, int(risk_pct / 100 * 60))
            )
        except Exception:
            pass

    def _make_day_widget(self, parent, col: int, icon: str,
                          day_name: str, avg_ping: float, risk_pct: int) -> dict:
        frame = ctk.CTkFrame(
            parent, fg_color=COLORS["bg_card"],
            corner_radius=10, border_width=1, border_color=COLORS["border"],
        )
        # PR #13: grid placement виконує _render_history залежно від режиму
        # (7д row vs 30д calendar). Створюємо тільки сам віджет.

        day_lbl = ctk.CTkLabel(
            frame, text=day_name,
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            text_color=COLORS["text_dim"],
        )
        day_lbl.pack(pady=(12, 2))

        icon_lbl = ctk.CTkLabel(frame, text=icon, font=ctk.CTkFont(size=30))
        icon_lbl.pack(pady=2)

        ping_lbl = ctk.CTkLabel(
            frame,
            text=f"{avg_ping:.0f} мс" if avg_ping else "—",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=COLORS["text_secondary"],
        )
        ping_lbl.pack(pady=(4, 6))

        risk_bar_bg = ctk.CTkFrame(frame, fg_color=COLORS["bg_secondary"],
                                    height=6, corner_radius=3)
        risk_bar_bg.pack(fill="x", padx=10, pady=(0, 12))

        risk_color = "#22c55e" if risk_pct < 30 else "#eab308" if risk_pct < 60 else "#ef4444"
        risk_bar   = ctk.CTkFrame(risk_bar_bg, fg_color=risk_color,
                                   height=6, corner_radius=3,
                                   width=max(4, int(risk_pct / 100 * 60)))
        risk_bar.place(x=0, y=0)

        # ── ФІКС #6: ROBLEM КЛІКАБЕЛЬНІ ДНІ ──
        # Курсор-вказівник + hover-ефект + bind на всі child-елементи
        def on_enter(_e):
            try:
                frame.configure(border_color=COLORS.get("accent_cyan", "#22d3ee"),
                                border_width=2)
            except Exception:
                pass

        def on_leave(_e):
            try:
                date_attr = getattr(frame, "_day_date", None)
                today_str = datetime.datetime.now().strftime("%Y-%m-%d")
                if date_attr == today_str:
                    frame.configure(border_color=COLORS["accent_yellow"],
                                    border_width=2)
                else:
                    frame.configure(border_color=COLORS["border"], border_width=1)
            except Exception:
                pass

        for w in (frame, day_lbl, icon_lbl, ping_lbl):
            try:
                w.configure(cursor="hand2")
            except Exception:
                pass
            w.bind("<Enter>", on_enter)
            w.bind("<Leave>", on_leave)

        return {"frame": frame, "day": day_lbl, "icon": icon_lbl,
                "ping": ping_lbl, "risk_bar": risk_bar, "risk_bar_bg": risk_bar_bg}

    # ─────────────────────────────────────────────────────────────────────
    #  НАЙКРАЩИЙ ЧАС
    # ─────────────────────────────────────────────────────────────────────

    def _build_besttime_card(self, row: int):
        card = GlowCard(self, accent=COLORS.get("accent_green", "#22c55e"))
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=24, pady=(18, 4), sticky="ew")

        sh = _section_header(hdr, "🏆", "НАЙКРАЩИЙ ЧАС  ·  РЕКОМЕНДАЦІЇ",
                             "besttime", COLORS.get("accent_green", "#22c55e"))
        sh.pack(fill="x")

        body = ctk.CTkFrame(card, fg_color="transparent")
        body.grid(row=1, column=0, padx=24, pady=(12, 20), sticky="ew")
        body.grid_columnconfigure((0, 1, 2), weight=1)

        self._besttime_labels: dict[str, ctk.CTkLabel] = {}
        for col_i, (key, title) in enumerate([
            ("gaming",    "🎮  Ігри"),
            ("download",  "📥  Завантаження"),
            ("streaming", "📺  Стрімінг"),
        ]):
            cell = ctk.CTkFrame(body, fg_color=COLORS["bg_card"],
                                 corner_radius=12, border_width=1,
                                 border_color=COLORS["border"])
            cell.grid(row=0, column=col_i, padx=6, sticky="nsew")

            ctk.CTkLabel(cell, text=title,
                         font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                         text_color=COLORS["text_secondary"]).pack(pady=(14, 4))

            lbl = ctk.CTkLabel(
                cell, text="Немає даних",
                font=ctk.CTkFont(family="Consolas", size=17, weight="bold"),
                text_color=COLORS.get("accent_green", "#22c55e"),
            )
            lbl.pack(pady=(0, 2))

            sub = ctk.CTkLabel(
                cell, text="—",
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS["text_dim"],
            )
            sub.pack(pady=(0, 14))

            self._besttime_labels[key]          = lbl
            self._besttime_labels[key + "_sub"] = sub

    def _render_besttime(self, history: HistoricalAnalysis):
        if history.status != "ok" or not history.hourly_data:
            return
        hd       = history.hourly_data
        cyclones = set(history.cyclone_hours)
        safe     = sorted([(h, v) for h, v in hd.items() if h not in cyclones],
                          key=lambda x: x[1])
        if not safe: safe = sorted(hd.items(), key=lambda x: x[1])

        def fmt(lst, n=3):
            t = lst[:n]
            ts  = "  ".join(f"{h:02d}:00" for h, _ in t)
            avg = sum(v for _, v in t) / len(t) if t else 0
            return ts or "—", f"avg {avg:.0f} мс"

        game_t, game_s = fmt(safe)
        night  = [(h, v) for h, v in safe if h < 7 or h == 23]
        dl_t, dl_s     = fmt(night if night else safe)
        stream = [(h, v) for h, v in safe if 7 <= h <= 23]
        st_t, st_s     = fmt(stream if stream else safe)

        self._besttime_labels["gaming"].configure(text=game_t)
        self._besttime_labels["gaming_sub"].configure(text=game_s)
        self._besttime_labels["download"].configure(text=dl_t)
        self._besttime_labels["download_sub"].configure(text=dl_s)
        self._besttime_labels["streaming"].configure(text=st_t)
        self._besttime_labels["streaming_sub"].configure(text=st_s)

    # ─────────────────────────────────────────────────────────────────────
    #  GLOBAL SERVICE STATUS
    # ─────────────────────────────────────────────────────────────────────

    def _build_services_panel(self, row: int):
        card = GlowCard(self, accent=COLORS["border"])
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.pack(fill="x", padx=24, pady=(18, 4))
        hdr.grid_columnconfigure(0, weight=1)

        sh = _section_header(hdr, "☁️", "GLOBAL SERVICE STATUS  ·  CLOUD MONITOR",
                             "services", COLORS["text_primary"])
        sh.grid(row=0, column=0, sticky="w")

        self._btn_check_services = ctk.CTkButton(
            hdr,
            text="🔄  Перевірити",
            command=self._run_service_check,
            fg_color=COLORS["bg_secondary"], hover_color=COLORS["bg_card"],
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(family="Consolas", size=13),
            height=36, width=140, corner_radius=8,
        )
        self._btn_check_services.grid(row=0, column=1, sticky="e")

        self._lbl_gaming_alert = ctk.CTkLabel(
            card, text="⏳  Перевірка сервісів...",
            font=ctk.CTkFont(family="Consolas", size=13),
            text_color=COLORS["text_dim"],
            justify="left", wraplength=860,
        )
        self._lbl_gaming_alert.pack(anchor="w", padx=24, pady=(6, 2))

        self._services_frame = ctk.CTkFrame(card, fg_color="transparent")
        self._services_frame.pack(fill="x", padx=16, pady=(6, 18))
        self._service_rows: dict[str, tuple] = {}
        self._render_service_placeholders()

    def _render_service_placeholders(self):
        for w in self._services_frame.winfo_children():
            w.destroy()
        self._service_rows.clear()

        from features.forecast.engine import MONITORED_SERVICES, CAT_LABELS
        categories: dict[str, list] = {}
        for s in MONITORED_SERVICES:
            categories.setdefault(s.category, []).append(s)

        col = 0
        for cat_key, services in categories.items():
            cat_frame = ctk.CTkFrame(
                self._services_frame,
                fg_color=COLORS["bg_card"], corner_radius=10,
            )
            cat_frame.grid(row=0, column=col, padx=6, sticky="nsew")
            self._services_frame.grid_columnconfigure(col, weight=1)
            col += 1

            ctk.CTkLabel(
                cat_frame, text=CAT_LABELS.get(cat_key, cat_key),
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=COLORS["text_secondary"],
            ).pack(anchor="w", padx=14, pady=(12, 6))

            for svc in services:
                rf = ctk.CTkFrame(cat_frame, fg_color="transparent")
                rf.pack(fill="x", padx=10, pady=3)

                icon_lbl = ctk.CTkLabel(rf, text="⬜",
                                         font=ctk.CTkFont(size=14), width=22)
                icon_lbl.pack(side="left", padx=(0, 6))

                ctk.CTkLabel(rf, text=svc.name,
                             font=ctk.CTkFont(family="Consolas", size=13),
                             text_color=COLORS["text_secondary"]).pack(side="left")

                ms_lbl = ctk.CTkLabel(rf, text="чекаємо...",
                                       font=ctk.CTkFont(family="Consolas", size=13),
                                       text_color=COLORS["text_dim"],
                                       width=90, anchor="e")
                ms_lbl.pack(side="right", padx=(0, 8))

                self._service_rows[f"{svc.category}:{svc.name}"] = (icon_lbl, ms_lbl)

            ctk.CTkFrame(cat_frame, height=10, fg_color="transparent").pack()

    # ─────────────────────────────────────────────────────────────────────
    #  24-ГОДИННИЙ ГРАФІК
    # ─────────────────────────────────────────────────────────────────────

    def _build_hourly_chart_card(self, row: int):
        card = GlowCard(self, accent=COLORS["border"])
        card.grid(row=row, column=0, padx=24, pady=(0, 4), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=24, pady=(18, 4), sticky="ew")

        # ФІКС #3: "24 ГОДИНИ" → "ЗА ДОБУ" — щоб не виглядало як майбутнє
        sh = _section_header(hdr, "📈", "СЕРЕДНІЙ ПІНГ  ·  ПАТЕРН ДОБИ (00:00 — зараз)",
                             "chart", COLORS["text_primary"])
        sh.pack(fill="x")

        self._hourly_canvas = tk.Canvas(
            card, bg=COLORS.get("bg_primary", "#0d0d1a"),
            highlightthickness=0, height=210,
        )
        self._hourly_canvas.grid(row=1, column=0, padx=15, pady=(6, 16), sticky="ew")
        self._draw_placeholder(self._hourly_canvas, 210,
                               "Дані з'являться після накопичення статистики")

        # ── ПЛАШКА «Вчора в цей час було погано» ──
        # Окремий чистий рядок під графіком — без візуального шуму на самому графіку
        self._yesterday_echo_panel = ctk.CTkFrame(
            card,
            fg_color="#1a1208",
            corner_radius=8,
            border_width=1,
            border_color=COLORS.get("accent_yellow", "#eab308"),
        )
        # Спочатку не показуємо — з'явиться коли будуть дані
        self._yesterday_echo_panel.grid(row=2, column=0, padx=15, pady=(0, 16),
                                          sticky="ew")
        self._yesterday_echo_panel.grid_remove()  # ховаємо доки немає даних
        self._yesterday_echo_panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            self._yesterday_echo_panel,
            text="⚠️",
            font=ctk.CTkFont(size=20),
        ).grid(row=0, column=0, padx=(14, 10), pady=10)

        self._lbl_yesterday_echo = ctk.CTkLabel(
            self._yesterday_echo_panel,
            text="",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS.get("accent_yellow", "#eab308"),
            anchor="w",
            justify="left",
        )
        self._lbl_yesterday_echo.grid(row=0, column=1, sticky="w", pady=10,
                                       padx=(0, 14))

    # ─────────────────────────────────────────────────────────────────────
    #  ТИЖНЕВИЙ HEATMAP
    # ─────────────────────────────────────────────────────────────────────

    def _build_heatmap_card(self, row: int):
        card = GlowCard(self, accent=COLORS["border"])
        card.grid(row=row, column=0, padx=24, pady=(0, 24), sticky="ew")
        card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, padx=24, pady=(18, 4), sticky="ew")

        # PR #12: показуємо ПОТОЧНИЙ КАЛЕНДАРНИЙ ТИЖДЕНЬ (Пн → Нд)
        try:
            from datetime import datetime, timedelta
            today = datetime.now()
            monday = today - timedelta(days=today.weekday())
            sunday = monday + timedelta(days=6)
            date_range = (f"{monday.strftime('%d.%m')} (Пн) — "
                          f"{sunday.strftime('%d.%m')} (Нд)")
        except Exception:
            date_range = ""

        title_text = f"ТИЖНЕВИЙ HEATMAP  ·  {date_range}"
        sh = _section_header(hdr, "🗓️", title_text,
                             "heatmap", COLORS["text_primary"])
        sh.pack(fill="x")

        # Підзаголовок з нагадуванням що оновлюється щотижня
        self._lbl_heatmap_subtitle = ctk.CTkLabel(
            hdr,
            text=f"Поточний тиждень · обнуляється в понеділок · "
                 f"Сьогодні: {today.strftime('%A, %d.%m.%Y')}"
                 if date_range else "",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"],
            anchor="w",
        )
        self._lbl_heatmap_subtitle.pack(fill="x", pady=(2, 0))

        self._heatmap_canvas = tk.Canvas(
            card, bg=COLORS.get("bg_primary", "#0d0d1a"),
            highlightthickness=0, height=170,
        )
        self._heatmap_canvas.grid(row=1, column=0, padx=15, pady=(6, 16), sticky="ew")
        self._draw_placeholder(self._heatmap_canvas, 170, "Немає даних за тиждень")

    # ═══════════════════════════════════════════════════════════════════════
    #  РЕНДЕР — WEATHER STATION
    # ═══════════════════════════════════════════════════════════════════════

    def _render_weather(self, cond: WeatherCondition):
        self._last_condition = cond

        self._lbl_weather_icon.configure(text=cond.icon)
        self._lbl_weather_title.configure(text=cond.title, text_color=cond.color)
        self._lbl_weather_desc.configure(text=cond.desc)

        self._metric_labels["ping"].configure(
            text=f"{cond.ping_ms:.0f} мс",
            text_color=self._metric_color(cond.ping_ms, 20, 100))
        self._metric_labels["jitter"].configure(
            text=f"{cond.jitter_ms:.0f} мс",
            text_color=self._metric_color(cond.jitter_ms, 10, 50))
        self._metric_labels["loss"].configure(
            text=f"{cond.packet_loss:.1f} %",
            text_color=self._metric_color(cond.packet_loss, 0.5, 5))

        self._draw_index_gauge(cond.weather_index)
        self._lbl_index_value.configure(
            text=f"{100 - cond.weather_index}/100",
            text_color=_index_color(cond.weather_index),
        )

        if cond.perceived_mbps > 0:
            spd_c = (
                self._metric_color(
                    cond.perceived_mbps,
                    cond.nominal_mbps * 0.7,
                    cond.nominal_mbps * 0.4,
                    reverse=True,
                ) if cond.nominal_mbps else COLORS["accent_green"]
            )
            self._lbl_perceived.configure(
                text=f"{cond.perceived_mbps:.0f} Мбіт/с", text_color=spd_c)
            self._lbl_nominal.configure(
                text=f"номінал: {cond.nominal_mbps:.0f} Мбіт/с")
        else:
            self._lbl_perceived.configure(text="— Мбіт/с")

        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._lbl_last_update.configure(text=f"Останнє оновлення: {ts}")

        icon_h, text_h = _get_hint(cond, self._last_history)
        self._lbl_hint.configure(text=f"{icon_h}  {text_h}")

    def _render_sla(self, sla_pct: float):
        color = (
            COLORS.get("accent_green", "#22c55e") if sla_pct >= 99 else
            COLORS.get("accent_cyan",  "#22d3ee") if sla_pct >= 95 else
            "#eab308"                              if sla_pct >= 90 else
            COLORS.get("accent_red",   "#ef4444")
        )
        self._lbl_sla.configure(text=f"{sla_pct:.1f} %", text_color=color)
        try:
            total_w = self._sla_bar_bg.winfo_width() or 140
            self._sla_bar.configure(fg_color=color,
                                     width=max(4, int(sla_pct / 100 * total_w)))
        except Exception:
            pass

    def _draw_index_gauge(self, index: int):
        c = self._index_canvas
        c.delete("all")
        cx, cy, R = 65, 65, 56

        c.create_arc(cx-R, cy-R, cx+R, cy+R,
                     start=225, extent=-270,
                     style="arc", outline="#1e1e3a", width=16)
        if index > 0:
            c.create_arc(cx-R, cy-R, cx+R, cy+R,
                         start=225, extent=-int(270 * index / 100),
                         style="arc", outline=_index_color(index), width=16)

        quality = 100 - index
        c.create_text(cx, cy - 4, text=str(quality),
                      fill="#e2e8f0" if quality > 50 else "#ef4444",
                      font=("Consolas", 24, "bold"))
        c.create_text(cx, cy + 18, text="якість",
                      fill="#475569", font=("Consolas", 10))

    # ═══════════════════════════════════════════════════════════════════════
    #  РЕНДЕР — ТИЖНЕВИЙ ПРОГНОЗ
    # ═══════════════════════════════════════════════════════════════════════

    def _render_weekly_forecast(self, history: HistoricalAnalysis):
        days = history.forecast_days
        if not days: return
        today_wd = datetime.datetime.now().weekday()

        for i, (widgets, forecast) in enumerate(zip(self._weekly_day_widgets, days)):
            is_today = (i == today_wd)

            widgets["frame"].configure(
                border_color=COLORS["accent_yellow"] if is_today else COLORS["border"],
                border_width=2 if is_today else 1,
                fg_color="#2a2200" if is_today else COLORS["bg_card"],
            )
            widgets["day"].configure(
                text=forecast.day_name + ("\n← сьогодні" if is_today else ""),
                text_color=COLORS["accent_yellow"] if is_today else COLORS["text_dim"],
                font=ctk.CTkFont(family="Consolas", size=12,
                                  weight="bold" if is_today else "normal"),
            )
            widgets["icon"].configure(text=forecast.icon)
            widgets["ping"].configure(
                text=f"{forecast.avg_ping:.0f} мс" if forecast.avg_ping else "—",
                text_color=COLORS["text_primary"] if is_today else COLORS["text_secondary"],
                font=ctk.CTkFont(family="Consolas", size=16 if is_today else 14,
                                  weight="bold"),
            )

            risk_color = (
                "#22c55e" if forecast.risk_pct < 30 else
                "#eab308" if forecast.risk_pct < 60 else "#ef4444"
            )
            try:
                bar_w = widgets["risk_bar_bg"].winfo_width()
                new_w = max(4, int(forecast.risk_pct / 100 * max(bar_w, 60)))
                widgets["risk_bar"].configure(fg_color=risk_color, width=new_w)
            except Exception:
                pass

    # ═══════════════════════════════════════════════════════════════════════
    #  РЕНДЕР — СЕРВІСИ
    # ═══════════════════════════════════════════════════════════════════════

    def _render_services(self, services):
        alert = self.engine.get_gaming_alert(services)
        if alert:
            self._lbl_gaming_alert.configure(
                text=alert,
                text_color=COLORS.get("accent_red", "#ef4444"))
        else:
            self._lbl_gaming_alert.configure(
                text="✅  Всі ігрові та хмарні сервіси доступні",
                text_color=COLORS.get("accent_green", "#22c55e"))

        for svc in services:
            key  = f"{svc.category}:{svc.name}"
            row_w = self._service_rows.get(key)
            if not row_w: continue
            icon_lbl, ms_lbl = row_w
            icon_lbl.configure(text=svc.icon)

            # ── Фікс #6: Колір на основі величини пінгу ──
            # Раніше: тільки зелений (is_up) або червоний (offline)
            # Тепер: градація за значенням пінгу
            if not svc.is_up:
                color = "#ef4444"  # червоний
                text  = "offline"
            else:
                ms = svc.ping_ms
                if ms < 50:
                    color = "#22c55e"   # зелений — відмінно
                elif ms < 100:
                    color = "#84cc16"   # світло-зелений — добре
                elif ms < 150:
                    color = "#eab308"   # жовтий — стерпно
                elif ms < 250:
                    color = "#f97316"   # помаранчевий — повільно
                else:
                    color = "#ef4444"   # червоний — поганий пінг
                text = f"{ms:.0f} мс"

            ms_lbl.configure(text=text, text_color=color)

    # ═══════════════════════════════════════════════════════════════════════
    #  РЕНДЕР — CANVAS
    # ═══════════════════════════════════════════════════════════════════════

    def _render_hourly_chart(self, hourly_data: dict, global_avg: float,
                              cyclone_hours: list):
        canvas = self._hourly_canvas
        canvas.delete("all")
        W  = canvas.winfo_width() or 800
        H  = 210
        pl, pr, pt, pb = 60, 16, 16, 38
        cw, ch = W - pl - pr, H - pt - pb

        # PR #9: «ПРОГНОЗНЕ ЕХО» — вчорашні дані для майбутніх годин
        yesterday_hourly = {}
        try:
            yesterday_hourly = self.engine.get_yesterday_hourly_data()
        except Exception as e:
            print(f"[ForecastUI] yesterday data error: {e}")

        values = [hourly_data.get(h) for h in range(24)]
        # Включаємо і вчорашні значення у max_v щоб шкала вмістила
        all_values = [v for v in values if v is not None]
        all_values += [v for v in yesterday_hourly.values()]
        max_v  = max(all_values) if all_values else 100
        if max_v < global_avg * 1.5: max_v = global_avg * 1.5

        col_w = cw / 24
        now_h = datetime.datetime.now().hour

        # ── Зберігаємо координати стовпців для tooltip ──
        self._hourly_bars = []  # (x1, y1, x2, y2, hour, value, yesterday_value)

        # ── Сітка ──
        for i in range(5):
            y    = pt + i * ch / 4
            ms_v = max_v * (1 - i / 4)
            canvas.create_line(pl, y, W - pr, y, fill="#1e1e3a", dash=(3, 7))
            canvas.create_text(pl - 5, y, text=f"{ms_v:.0f}",
                               fill="#334155", font=("Consolas", 9), anchor="e")

        avg_y = pt + ch - (global_avg / max_v) * ch
        canvas.create_line(pl, avg_y, W - pr, avg_y,
                            fill=COLORS["accent_yellow"], dash=(6, 4), width=1)
        canvas.create_text(pl - 5, avg_y, text="норма",
                           fill=COLORS["accent_yellow"], font=("Consolas", 8), anchor="e")

        # ── ВЧОРАШНЄ ЕХО ВИДАЛЕНО з графіку ──
        # Тепер інформація про вчора показується в окремій плашці під графіком.
        # Це чистіше і не плутає реальні дані з прогнозом.
        echoes_drawn = 0
        problem_hours_yesterday = []
        for h in range(24):
            yest_v = yesterday_hourly.get(h)
            if yest_v is None or yest_v < 80:
                continue
            if h < now_h:
                continue
            problem_hours_yesterday.append((h, yest_v))

        # Зберігаємо для відображення під графіком
        self._yesterday_echo_hours = problem_hours_yesterday
        print(f"[ForecastUI] Yesterday data: {len(yesterday_hourly)} hours, "
              f"problem future hours: {len(problem_hours_yesterday)}")

        # ── Другий прохід: реальні стовпці сьогоднішнього дня ──
        for h in range(24):
            v = values[h]
            x = pl + h * col_w
            # Тільки виділення поточної години — БЕЗ червоного тла "циклонних" годин
            # (раніше це створювало фантомні червоні квадрати від попередніх днів)
            if h == now_h:
                canvas.create_rectangle(x, pt, x + col_w, pt + ch,
                                         fill="#1a1a2e", outline="")

            # Зберігаємо для tooltip (включно з вчорашнім)
            self._hourly_bars.append((
                x, pt, x + col_w, pt + ch, h, v, yesterday_hourly.get(h)
            ))

            if v is not None:
                bh    = (v / max_v) * ch * 0.92
                y_top = pt + ch - bh
                color = (
                    COLORS["accent_red"]    if v > global_avg * 1.4 else
                    COLORS["accent_yellow"] if v > global_avg * 1.1 else
                    COLORS["accent_green"]
                )
                bw = col_w * 0.7
                bx = x + col_w / 2
                canvas.create_rectangle(bx - bw/2, y_top, bx + bw/2, pt + ch,
                                         fill=color, outline="")
                # Циклон-індикатор з числом видалений — він теж створював
                # фантомне червоне число над минулими днями
            if h % 3 == 0:
                canvas.create_text(x + col_w/2, H - 16, text=f"{h}h",
                                   fill=COLORS["text_secondary"], font=("Consolas", 10))

        canvas.create_line(pl, pt + ch, W - pr, pt + ch,
                            fill=COLORS["border"], width=1)

        # ── Легенда ──
        lx = pl
        for color, txt in [
            (COLORS["accent_green"],  "≤ 50мс"),
            (COLORS["accent_yellow"], "50-150мс"),
            (COLORS["accent_red"],    "> 150мс"),
        ]:
            canvas.create_rectangle(lx, H - 10, lx + 12, H, fill=color, outline="")
            canvas.create_text(lx + 16, H - 5, text=txt,
                               fill=COLORS["text_dim"], font=("Consolas", 9), anchor="w")
            lx += 92

        # ── tooltip handlers ──
        canvas.unbind("<Motion>")
        canvas.unbind("<Leave>")
        canvas.bind("<Motion>", self._on_hourly_motion)
        canvas.bind("<Leave>", self._on_hourly_leave)
        self._hourly_tooltip_rect = None

        # ── Оновлюємо плашку «Вчора в цей час» ──
        self._update_yesterday_echo_panel()

    def _update_yesterday_echo_panel(self):
        """Оновлює плашку «Вчора в цей час» під hourly chart.

        Показує проблемні години які ще НЕ настали сьогодні:
          "Вчора у 19:00 був ping 152мс, у 20:00 — 84мс"

        Якщо проблем немає — ховаємо плашку.
        """
        try:
            problems = getattr(self, "_yesterday_echo_hours", [])
            if not problems or not hasattr(self, "_yesterday_echo_panel"):
                if hasattr(self, "_yesterday_echo_panel"):
                    self._yesterday_echo_panel.grid_remove()
                return

            # Сортуємо за годиною
            problems_sorted = sorted(problems, key=lambda x: x[0])

            # Будуємо текст
            parts = []
            for h, v in problems_sorted[:5]:  # максимум 5 годин
                level = "🔴" if v >= 150 else "🟡"
                parts.append(f"{level} {h:02d}:00 — {v:.0f}мс")

            extra = ""
            if len(problems_sorted) > 5:
                extra = f"  …та ще {len(problems_sorted) - 5} год"

            text = (
                "Вчора у цей час був поганий інтернет:\n"
                + "    ".join(parts)
                + extra
            )

            self._lbl_yesterday_echo.configure(text=text)
            self._yesterday_echo_panel.grid()  # показуємо
        except Exception as e:
            print(f"[ForecastUI] echo panel error: {e}")

    def _on_hourly_motion(self, event):
        """Показує tooltip над стовпцем bar-chart.
        ВКЛЮЧАЄ дані за вчорашній день в цей час (прогнозне ехо)."""
        try:
            for bar in getattr(self, "_hourly_bars", []):
                # bar: (x1, y1, x2, y2, hour, today_value, yesterday_value)
                x1, y1, x2, y2, hour, value = bar[:6]
                yest_v = bar[6] if len(bar) > 6 else None

                if x1 <= event.x <= x2 and y1 <= event.y <= y2:
                    lines = [f"{hour:02d}:00"]

                    if value is not None:
                        # Якщо ця година вже настала
                        lines.append(f"• Зараз сьогодні: {value:.1f} мс")
                    else:
                        lines.append(f"• Сьогодні: ще не настало")

                    if yest_v is not None:
                        emoji = "🔴" if yest_v > 150 else ("🟡" if yest_v > 80 else "🟢")
                        lines.append(f"• Вчора: {emoji} {yest_v:.1f} мс")

                        # Прогнозне попередження
                        now_h = datetime.datetime.now().hour
                        if hour > now_h and yest_v > 80:
                            lines.append(f"⚠ Вчора у цей час було погано")

                    self._hourly_show_tooltip(event.x, event.y,
                                              "\n".join(lines))
                    return
            self._hourly_hide_tooltip()
        except Exception as e:
            print(f"[Hourly motion] error: {e}")

    def _on_hourly_leave(self, _event):
        self._hourly_hide_tooltip()

    def _hourly_show_tooltip(self, x, y, text):
        """Створює tooltip для bar-chart. Використовує tkfont.measure()."""
        try:
            import tkinter.font as tkfont
            canvas = self._hourly_canvas
            self._hourly_hide_tooltip()

            lines = text.split("\n")

            font = tkfont.Font(family="Consolas", size=10, weight="bold")
            line_h = font.metrics("linespace") + 2
            max_text_w = max(font.measure(line) for line in lines)
            box_w = max_text_w + 18
            box_h = line_h * len(lines) + 10

            canvas_w = canvas.winfo_width()
            tx = x + 15
            if tx + box_w > canvas_w - 5:
                tx = x - box_w - 10
            if tx < 5:
                tx = 5

            ty = y - box_h - 8
            if ty < 5:
                ty = y + 18

            self._hourly_tooltip_rect = canvas.create_rectangle(
                tx, ty, tx + box_w, ty + box_h,
                fill="#0a0e1a",
                outline=COLORS.get("accent_cyan", "#22d3ee"),
                width=1
            )
            self._hourly_tooltip_text = canvas.create_text(
                tx + 9, ty + 5,
                text=text, anchor="nw",
                fill=COLORS.get("text_primary", "#e0e0e0"),
                font=("Consolas", 10, "bold")
            )
        except Exception as e:
            print(f"[Hourly tooltip] error: {e}")

    def _hourly_hide_tooltip(self):
        try:
            canvas = self._hourly_canvas
            if hasattr(self, "_hourly_tooltip_rect") and self._hourly_tooltip_rect:
                canvas.delete(self._hourly_tooltip_rect)
                self._hourly_tooltip_rect = None
            if hasattr(self, "_hourly_tooltip_text"):
                canvas.delete(self._hourly_tooltip_text)
                self._hourly_tooltip_text = None
        except Exception:
            pass

    def _render_heatmap(self, weekly_data: dict, global_avg: float):
        canvas = self._heatmap_canvas
        canvas.delete("all")
        W  = canvas.winfo_width() or 800
        H  = 170
        pl, pr, pt, pb = 34, 8, 20, 24
        cw, ch = W - pl - pr, H - pt - pb

        DAY_NAMES_SHORT = ["Пн", "Вт", "Ср", "Чт", "Пт", "Сб", "Нд"]
        DAY_FULL = ["Понеділок", "Вівторок", "Середа", "Четвер",
                    "П'ятниця", "Субота", "Неділя"]
        cell_w, cell_h = cw / 24, ch / 7

        # ── Фікс #2: АБСОЛЮТНА шкала кольорів за нормами пінгу ──
        # Раніше: max_v = max(all_vals) — якщо у тебе 1 значення 19мс,
        # то воно ставало "максимумом" і малювалось помаранчевим. Тепер
        # шкала прив'язана до реальних порогів якості мережі:
        #   0-30мс   → зелений (відмінно)
        #   30-80мс  → жовтий  (стерпно)
        #   80-150мс → помаранч (повільно)
        #   >150мс   → червоний (критично)
        def _ping_to_color(avg_ping: float) -> str:
            if avg_ping <= 30:
                # Зелений: 30→жовтий
                t = avg_ping / 30
                r = int(10 + t * 220)
                g = 200
                b = int(40 * (1 - t * 0.5))
            elif avg_ping <= 80:
                # Жовтий→помаранч
                t = (avg_ping - 30) / 50
                r = 230
                g = int(200 - t * 80)
                b = 20
            elif avg_ping <= 150:
                # Помаранч→червоний
                t = (avg_ping - 80) / 70
                r = 240
                g = int(120 - t * 80)
                b = int(20 + t * 20)
            else:
                # Червоний для будь-чого >150
                r, g, b = 230, 30, 40
            return f"#{min(r,255):02x}{min(g,255):02x}{min(b,255):02x}"

        today_wd = datetime.datetime.now().weekday()
        now_h    = datetime.datetime.now().hour

        # ── Зберігаємо координати чарунок для tooltip ──
        self._heatmap_cells = []  # (x1, y1, x2, y2, day, hour, avg_ping)

        for d in range(7):
            y = pt + d * cell_h
            canvas.create_text(
                pl - 3, y + cell_h / 2,
                text=DAY_NAMES_SHORT[d],
                fill=COLORS["accent_yellow"] if d == today_wd else COLORS["text_secondary"],
                font=("Consolas", 9, "bold" if d == today_wd else ""), anchor="e",
            )
            for h in range(24):
                x   = pl + h * cell_w
                avg = weekly_data.get(d, {}).get(h)
                if avg is not None:
                    color = _ping_to_color(avg)
                else:
                    color = COLORS.get("bg_card", "#1a1a2e")

                canvas.create_rectangle(
                    x+1, y+1, x+cell_w-1, y+cell_h-1,
                    fill=color, outline=COLORS.get("border","#1e1e3a"))

                # Запам'ятовуємо координати для tooltip (фікс #7)
                self._heatmap_cells.append((
                    x+1, y+1, x+cell_w-1, y+cell_h-1,
                    d, h, avg
                ))

                if d == today_wd and h == now_h:
                    canvas.create_rectangle(
                        x+1, y+1, x+cell_w-1, y+cell_h-1,
                        fill="", outline="#ffffff", width=1)

        for h in range(0, 24, 4):
            x = pl + h * cell_w + cell_w / 2
            canvas.create_text(x, H - 8, text=f"{h}h",
                               fill=COLORS["text_secondary"], font=("Consolas", 9))

        # ── Шкала з підписами діапазонів ──
        gx, gy, gw = pl, H - 20, 80
        for i in range(gw):
            ping_val = (i / gw) * 200  # 0..200мс
            canvas.create_line(gx+i, gy, gx+i, gy+7,
                               fill=_ping_to_color(ping_val))
        canvas.create_text(gx - 2, gy + 3, text="0мс",
                           fill=COLORS["text_dim"], font=("Consolas", 8), anchor="e")
        canvas.create_text(gx + gw + 2, gy + 3, text="200+мс",
                           fill=COLORS["text_dim"], font=("Consolas", 8), anchor="w")

        # ── Фікс #7: tooltip ──
        # Відписуємо старий handler якщо був
        canvas.unbind("<Motion>")
        canvas.unbind("<Leave>")
        canvas.bind("<Motion>", self._on_heatmap_motion)
        canvas.bind("<Leave>", self._on_heatmap_leave)
        self._heatmap_tooltip_id = None

    def _on_heatmap_motion(self, event):
        """Показує tooltip над чарункою heatmap."""
        try:
            canvas = self._heatmap_canvas
            for x1, y1, x2, y2, d, h, avg in getattr(self, "_heatmap_cells", []):
                if x1 <= event.x <= x2 and y1 <= event.y <= y2:
                    DAY_FULL = ["Понеділок", "Вівторок", "Середа", "Четвер",
                                "П'ятниця", "Субота", "Неділя"]
                    if avg is not None:
                        text = f"{DAY_FULL[d]}  {h:02d}:00\n• Середній пінг: {avg:.1f} мс"
                    else:
                        text = f"{DAY_FULL[d]}  {h:02d}:00\n• Немає даних"

                    # Створюємо/оновлюємо tooltip
                    self._heatmap_show_tooltip(event.x, event.y, text)
                    return
            # Якщо курсор не над чаркою — приховуємо
            self._heatmap_hide_tooltip()
        except Exception:
            pass

    def _on_heatmap_leave(self, _event):
        self._heatmap_hide_tooltip()

    def _heatmap_show_tooltip(self, x, y, text):
        """Створює невелике вікно з підказкою біля курсора.

        Використовує tkfont.measure() для ТОЧНОГО підрахунку ширини
        (раніше було len(line) * 6 — погано для української мови + emoji).
        """
        try:
            import tkinter.font as tkfont
            canvas = self._heatmap_canvas
            # Видаляємо старий
            self._heatmap_hide_tooltip()

            lines = text.split("\n")

            # ТОЧНИЙ підрахунок ширини через шрифт
            font = tkfont.Font(family="Consolas", size=10, weight="bold")
            line_h = font.metrics("linespace") + 2
            max_text_w = max(font.measure(line) for line in lines)
            box_w = max_text_w + 18   # padding 9 з кожного боку
            box_h = line_h * len(lines) + 10

            # Позиція з урахуванням країв canvas
            canvas_w = canvas.winfo_width()
            tx = x + 15
            if tx + box_w > canvas_w - 5:
                tx = x - box_w - 10   # показуємо ЛІВОРУЧ від курсора
            if tx < 5:
                tx = 5

            ty = y - box_h - 8
            if ty < 5:
                ty = y + 18           # показуємо НИЖЧЕ курсора

            # Прямокутник з невеликим скругленням ефект через 2 шари
            self._heatmap_tooltip_rect = canvas.create_rectangle(
                tx, ty, tx + box_w, ty + box_h,
                fill="#0a0e1a",
                outline=COLORS.get("accent_cyan", "#22d3ee"),
                width=1
            )
            self._heatmap_tooltip_text = canvas.create_text(
                tx + 9, ty + 5,
                text=text, anchor="nw",
                fill=COLORS.get("text_primary", "#e0e0e0"),
                font=("Consolas", 10, "bold")
            )
        except Exception as e:
            print(f"[Heatmap tooltip] error: {e}")

    def _heatmap_hide_tooltip(self):
        try:
            canvas = self._heatmap_canvas
            if hasattr(self, "_heatmap_tooltip_rect"):
                canvas.delete(self._heatmap_tooltip_rect)
                del self._heatmap_tooltip_rect
            if hasattr(self, "_heatmap_tooltip_text"):
                canvas.delete(self._heatmap_tooltip_text)
                del self._heatmap_tooltip_text
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════════════════
    #  THREADING
    # ═══════════════════════════════════════════════════════════════════════

    def _run_full_refresh(self):
        self._btn_refresh.configure(state="disabled", text="⏳  Вимірювання...")
        threading.Thread(target=self._refresh_thread, daemon=True).start()

    def _refresh_thread(self):
        cond    = self.engine.measure_current()
        self.after(0, lambda: self._render_weather(cond))

        history = self.engine.analyze_history()
        self._last_history = history

        if history.status == "ok":
            self.after(0, lambda: self._render_history())

            # ФІКС #3: для bar-chart беремо ТІЛЬКИ сьогоднішні дані (з 00:00)
            # щоб графік не показував години які ще не настали
            today_hourly = self.engine.get_today_hourly_data()
            self.after(0, lambda: self._render_hourly_chart(
                today_hourly, history.global_avg, history.cyclone_hours))
            self.after(0, lambda: self._render_heatmap(
                history.weekly_data, history.global_avg))
            self.after(0, lambda: self._render_besttime(history))

            sla = getattr(history, "sla_pct", None)
            if sla is not None:
                self.after(0, lambda s=sla: self._render_sla(s))

            self.after(0, lambda: self._lbl_hint.configure(
                text="{} {}".format(*_get_hint(cond, history))))

        alert = self.engine.check_storm_alert(cond, history)
        if alert:
            self.after(0, lambda: self._show_storm_alert(alert))
            self.engine.send_windows_notification("⚡ NetGuardian Alert", alert[:100])

        self.after(0, lambda: self._btn_refresh.configure(
            state="normal", text="🔄  ОНОВИТИ ПРОГНОЗ"))
        self.after(0, self._schedule_auto_refresh)

    def _run_service_check(self):
        self._btn_check_services.configure(state="disabled", text="⏳ Перевірка...")
        self._services_pending = None
        threading.Thread(target=self._service_check_thread, daemon=True).start()
        # Стартуємо поллер у головному потоці
        self.after(200, self._poll_services_result)

    def _service_check_thread(self):
        """Перевіряє сервіси у потоці.
        Python 3.14: НЕ викликаємо tk.after() з потоку!
        Зберігаємо результат у атрибуті, головний потік опитує через poll.
        """
        try:
            services = self.engine.check_services(force=True)
            self._services_pending = services
        except Exception as e:
            print(f"[Forecast] _service_check_thread error: {e}")
            self._services_pending = []

    def _poll_services_result(self, attempts: int = 60):
        """Опитує результат _service_check_thread з головного потоку."""
        pending = getattr(self, "_services_pending", None)
        if pending is not None:
            self._services_pending = None
            try:
                self._render_services(pending)
                self._btn_check_services.configure(
                    state="normal", text="🔄  Перевірити"
                )
            except Exception as e:
                print(f"[Forecast] _poll_services_result error: {e}")
            return
        if attempts > 0:
            self.after(200, lambda: self._poll_services_result(attempts - 1))

    def _run_throttling(self):
        self._btn_refresh.configure(state="disabled", text="⏳ Throttling test...")
        threading.Thread(target=self._throttling_thread, daemon=True).start()

    def _throttling_thread(self):
        res = self.engine.check_throttling()
        self.after(0, lambda: self._show_throttling_result(res))
        self.after(0, lambda: self._btn_refresh.configure(
            state="normal", text="🔄  ОНОВИТИ ПРОГНОЗ"))

    def _show_throttling_result(self, res: dict):
        if not res.get("success"):
            self._show_storm_alert(f"❌ Throttling test: {res.get('msg','помилка')}")
            return

        if res["is_throttled"]:
            msg = (
                f"🔴 THROTTLING DETECTED! {res.get('throttle_desc','')}\n"
                f"UA: {res['ua_ms']:.0f} мс  |  EU: {res['eu_ms']:.0f} мс  "
                f"|  Різниця: {res['ratio']:.1f}×"
            )
        else:
            msg = (
                f"✅ Throttling не виявлено. "
                f"UA: {res['ua_ms']:.0f} мс | EU: {res['eu_ms']:.0f} мс | {res.get('throttle_desc','')}"
            )

        trace = res.get("trace", [])
        if trace:
            msg += "\n\n📍 Traceroute:\n"
            for hop in trace:
                ms   = hop.get("ms", 0)
                dot  = "🟢" if ms < 20 else "🟡" if ms < 80 else "🔴"
                hint = ""
                if hop.get("hop") == 1:
                    hint = "  ← Ваш роутер" + (" ⚠️" if ms > 10 else "")
                elif hop.get("hop") == 2:
                    hint = "  ← Провайдер (DSLAM)"
                msg += f"  {hop['hop']:>2}. {dot} {ms:>5.1f} мс  {hop['ip']}{hint}\n"
        else:
            msg += "\n\n📍 Traceroute: дані недоступні (можливо, провайдер блокує)."

        self._show_storm_alert(msg)

    def _show_storm_alert(self, message: str):
        if self._storm_banner and self._storm_banner.winfo_exists():
            self._storm_banner.update_message(message)
        else:
            banner = StormAlertBanner(self._alert_placeholder, message)
            banner.pack(fill="x", padx=24, pady=(8, 0))
            self._storm_banner = banner

    def _schedule_auto_refresh(self):
        if self._auto_timer:
            try: self.after_cancel(self._auto_timer)
            except Exception: pass
        self._auto_timer = self.after(AUTO_REFRESH_SEC * 1000, self._run_full_refresh)

    # ═══════════════════════════════════════════════════════════════════════
    #  УТИЛІТИ
    # ═══════════════════════════════════════════════════════════════════════

    @staticmethod
    def _draw_placeholder(canvas: tk.Canvas, height: int, text: str):
        canvas.delete("all")
        canvas.create_text(400, height // 2, text=text,
                           fill="#334155", font=("Consolas", 12))

    @staticmethod
    def _metric_color(value: float, good_max: float, bad_min: float,
                       reverse: bool = False) -> str:
        good, mid, bad = "#22c55e", "#eab308", "#ef4444"
        if reverse: good, bad = bad, good
        if value <= good_max: return good
        if value >= bad_min:  return bad
        return mid