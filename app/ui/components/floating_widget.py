# gui/components/floating_widget.py
import customtkinter as ctk
from app.ui.theme import COLORS


class FloatingWidget(ctk.CTkToplevel):
    """
    Маленьке напівпрозоре вікно-оверлей (Always on Top).
    Показує поточний пінг поверх будь-яких вікон/ігор.
    Можна перетягувати мишею.
    """

    def __init__(self):
        super().__init__()

        # ── Налаштування вікна ─────────────────────────────
        self.title("")
        self.geometry("180x70+40+40")
        self.resizable(False, False)
        self.overrideredirect(True)          # без рамки/заголовку
        self.wm_attributes("-topmost", True) # Always on Top
        self.wm_attributes("-alpha", 0.88)   # напівпрозорість
        self.configure(fg_color="#0d0d14")

        # ── UI ────────────────────────────────────────────
        outer = ctk.CTkFrame(self, fg_color="#0d0d14",
                             border_width=1, border_color=COLORS["accent_cyan"],
                             corner_radius=12)
        outer.pack(fill="both", expand=True, padx=2, pady=2)

        top_bar = ctk.CTkFrame(outer, fg_color="transparent", height=18)
        top_bar.pack(fill="x", padx=8, pady=(6, 0))

        ctk.CTkLabel(top_bar, text="⬡ NetGuardian",
                     font=ctk.CTkFont(family="Consolas", size=8),
                     text_color=COLORS["text_dim"]).pack(side="left")

        self.btn_close = ctk.CTkButton(
            top_bar, text="✕", width=16, height=16,
            fg_color="transparent", hover_color=COLORS["accent_red"],
            text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(size=9),
            command=self._on_close)
        self.btn_close.pack(side="right")

        center = ctk.CTkFrame(outer, fg_color="transparent")
        center.pack(fill="both", expand=True, padx=10, pady=(2, 8))

        self.lbl_ping = ctk.CTkLabel(
            center, text="-- ms",
            font=ctk.CTkFont(family="Consolas", size=26, weight="bold"),
            text_color=COLORS["accent_cyan"])
        self.lbl_ping.pack(side="left")

        self.lbl_status = ctk.CTkLabel(
            center, text="PING",
            font=ctk.CTkFont(family="Consolas", size=8),
            text_color=COLORS["text_dim"])
        self.lbl_status.pack(side="left", padx=(6, 0), anchor="s")

        # ── Перетягування ─────────────────────────────────
        self._drag_x = 0
        self._drag_y = 0
        outer.bind("<ButtonPress-1>",   self._drag_start)
        outer.bind("<B1-Motion>",       self._drag_move)

        # зовнішній колбек — викликається при закритті через ✕
        self.on_close_callback = None

    # ── Drag & Drop ───────────────────────────────────────
    def _drag_start(self, event):
        self._drag_x = event.x_root - self.winfo_x()
        self._drag_y = event.y_root - self.winfo_y()

    def _drag_move(self, event):
        x = event.x_root - self._drag_x
        y = event.y_root - self._drag_y
        self.geometry(f"+{x}+{y}")

    # ── Оновлення даних ───────────────────────────────────
    def update_ping(self, ms: int, color: str):
        if not self.winfo_exists():
            return
        self.lbl_ping.configure(
            text=f"{ms} ms" if ms >= 0 else "OFFLINE",
            text_color=color)
        self.lbl_status.configure(
            text="PING" if ms >= 0 else "⚠",
            text_color=color)
        # Колір рамки відповідає статусу
        self.configure()   # force refresh

    # ── Закриття ──────────────────────────────────────────
    def _on_close(self):
        if self.on_close_callback:
            self.on_close_callback()
        else:
            self.destroy()
