# gui/theme.py
import customtkinter as ctk

COLORS = {
    "bg_primary":    "#0a0e1a",
    "bg_secondary":  "#0f1526",
    "bg_card":       "#131929",
    "bg_card_hover": "#1a2238",
    "border":        "#1e2d4a",
    "border_accent": "#0d47a1",
    "accent_blue":   "#00b4ff",
    "accent_cyan":   "#00ffe7",
    "accent_green":  "#00ff88",
    "accent_yellow": "#ffcc00",
    "accent_red":    "#ff3366",
    "accent_purple": "#a855f7",
    "text_primary":  "#e0eaff",
    "text_secondary":"#5a7099",
    "text_dim":      "#2a3a5a",
}

def get_fonts():
    """Повертає шрифти. Функція, щоб уникнути помилок ініціалізації ctk."""
    return {
        "title":   ctk.CTkFont(family="Consolas", size=26, weight="bold"),
        "heading": ctk.CTkFont(family="Consolas", size=16, weight="bold"),
        "mono":    ctk.CTkFont(family="Consolas", size=13),
        "mono_lg": ctk.CTkFont(family="Consolas", size=42, weight="bold"),
        "mono_sm": ctk.CTkFont(family="Consolas", size=11),
        "label":   ctk.CTkFont(family="Segoe UI", size=12),
        "label_sm":ctk.CTkFont(family="Segoe UI", size=10),
    }
