# gui/components/widgets.py
import customtkinter as ctk
from app.ui.theme import COLORS

class GlowCard(ctk.CTkFrame):
    """Картка з неоновим обрамленням"""
    def __init__(self, parent, accent=None, **kwargs):
        kwargs.setdefault("fg_color", COLORS["bg_card"])
        kwargs.setdefault("corner_radius", 16)
        kwargs.setdefault("border_width", 1)
        kwargs.setdefault("border_color", accent or COLORS["border"])
        super().__init__(parent, **kwargs)


class StatusDot(ctk.CTkLabel):
    """Пульсуючий індикатор статусу"""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, text="●", font=("Consolas", 18), **kwargs)
        self._pulse_step = 0
        self._pulse_id = None
        self._color = COLORS["accent_green"]

    def start_pulse(self, color=None):
        if color is not None:
            self._color = color
        self.configure(text_color=self._color)
        if self._pulse_id:
            self.after_cancel(self._pulse_id)
        self._pulse_step = 0
        self._do_pulse(self._color)

    def _do_pulse(self, color):
        alpha = [255, 200, 140, 80, 140, 200][self._pulse_step % 6]
        try:
            r = int(color[1:3], 16)
            g = int(color[3:5], 16)
            b = int(color[5:7], 16)
            faded = "#{:02x}{:02x}{:02x}".format(
                int(r * alpha / 255),
                int(g * alpha / 255),
                int(b * alpha / 255)
            )
            self.configure(text_color=faded)
        except Exception:
            pass
        self._pulse_step += 1
        self._pulse_id = self.after(180, lambda: self._do_pulse(color))

    def stop_pulse(self):
        if self._pulse_id:
            self.after_cancel(self._pulse_id)
            self._pulse_id = None


class SidebarButton(ctk.CTkButton):
    """Кнопка бокової панелі з іконкою"""
    def __init__(self, parent, icon, label, **kwargs):
        kwargs.setdefault("fg_color", "transparent")
        kwargs.setdefault("hover_color", COLORS["bg_card"])
        kwargs.setdefault("text_color", COLORS["text_secondary"])
        kwargs.setdefault("anchor", "w")
        kwargs.setdefault("height", 48)
        kwargs.setdefault("corner_radius", 10)
        kwargs.setdefault("font", ctk.CTkFont(family="Segoe UI", size=13))
        super().__init__(parent, text=f"  {icon}  {label}", **kwargs)

    def set_active(self, active: bool):
        if active:
            self.configure(
                fg_color=COLORS["bg_card"],
                text_color=COLORS["accent_cyan"],
                border_width=1,
                border_color=COLORS["border_accent"]
            )
        else:
            self.configure(
                fg_color="transparent",
                text_color=COLORS["text_secondary"],
                border_width=0
            )
