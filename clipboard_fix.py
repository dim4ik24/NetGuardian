"""
clipboard_fix.py
─────────────────
Виправлення copy-paste для всіх tk/ctk віджетів НЕЗАЛЕЖНО від
розкладки клавіатури.

ПРОБЛЕМА:
  У Windows коли активна українська/російська розкладка, натискання
  Ctrl+C/V/X/A не генерує події <<Copy>>, <<Paste>>, <<Cut>>, <<Selection-All>>.
  Це баг tkinter — він прив'язує операції до "англійських" клавіш.
  Натискання `Ctrl+С` (українське С) або `Ctrl+В` (українське В) обробляється
  як невідомий keysym і ігнорується.

РІШЕННЯ:
  Перехоплюємо подію <Control-KeyPress> на рівні root і вручну
  згенеруємо потрібну подію <<Copy/Paste/Cut/SelectAll>> на основі
  RAW keycode (фізичної клавіші), а не keysym (логічної літери).

  Keycode фізичних клавіш у Windows:
    C → 67    (на кирилиці = "С")
    V → 86    (на кирилиці = "М")
    X → 88    (на кирилиці = "Ч")
    A → 65    (на кирилиці = "Ф")

USAGE:
  В main.py одразу після створення CTk-кореня:
    >>> from clipboard_fix import enable_universal_clipboard
    >>> enable_universal_clipboard(root)

  Все. Працює для всіх Entry/Textbox/CTkEntry/CTkTextbox у вікні.
"""

from __future__ import annotations
import tkinter as tk


# Windows keycodes — фізичні клавіші, не залежать від розкладки
KEYCODE_MAP = {
    67: "<<Copy>>",         # C
    86: "<<Paste>>",        # V
    88: "<<Cut>>",          # X
    65: "<<SelectAll>>",    # A
    90: "<<Undo>>",         # Z
    89: "<<Redo>>",         # Y
}


def enable_universal_clipboard(root: tk.Tk | tk.Toplevel | tk.Misc) -> None:
    """Вмикає cross-layout copy-paste для всіх віджетів вікна.

    Підключає bind_all що працює з будь-якою розкладкою:
    англійською, українською, російською тощо.

    Args:
        root: tk.Tk або CTk корінь.
    """
    def handler(event):
        kc = event.keycode

        # Перевіряємо чи натиснутий Ctrl (state містить 0x4)
        if not (event.state & 0x4):
            return None

        action = KEYCODE_MAP.get(kc)
        if not action:
            return None

        widget = event.widget

        # Перевіряємо чи widget підтримує clipboard-операції
        # (Entry, Text, CTkEntry, CTkTextbox містять _entry чи _textbox)
        target = widget

        # Якщо це CTkEntry/CTkTextbox — спробуємо знайти внутрішній віджет
        if hasattr(widget, "_entry"):
            target = widget._entry
        elif hasattr(widget, "_textbox"):
            target = widget._textbox

        # Перевіряємо чи це editable widget
        widget_class = target.winfo_class()
        if widget_class not in ("Entry", "TEntry", "Text", "TText"):
            return None

        try:
            target.event_generate(action)
            return "break"   # припиняємо подальше поширення
        except Exception:
            return None

    # bind_all — працює для всіх віджетів у вікні (всіх Toplevel теж)
    try:
        root.bind_all("<Control-KeyPress>", handler, add="+")
    except Exception as e:
        print(f"[ClipboardFix] bind_all failed: {e}")


def add_context_menu(widget) -> None:
    """Додає контекстне меню (правий клік) з copy/paste для віджета.

    Підтримує: tk.Entry, tk.Text, ctk.CTkEntry, ctk.CTkTextbox.
    """
    # Знаходимо внутрішній віджет
    target = widget
    if hasattr(widget, "_entry"):
        target = widget._entry
    elif hasattr(widget, "_textbox"):
        target = widget._textbox

    menu = tk.Menu(target, tearoff=0,
                    bg="#1a1a2e", fg="#e0e0e0",
                    activebackground="#3a3a5a", activeforeground="#ffffff",
                    borderwidth=0, relief="flat")

    menu.add_command(
        label="✂  Вирізати",
        command=lambda: target.event_generate("<<Cut>>"),
        accelerator="Ctrl+X")
    menu.add_command(
        label="📋  Копіювати",
        command=lambda: target.event_generate("<<Copy>>"),
        accelerator="Ctrl+C")
    menu.add_command(
        label="📥  Вставити",
        command=lambda: target.event_generate("<<Paste>>"),
        accelerator="Ctrl+V")
    menu.add_separator()
    menu.add_command(
        label="🔘  Виділити все",
        command=lambda: target.event_generate("<<SelectAll>>"),
        accelerator="Ctrl+A")

    def show_menu(event):
        try:
            target.focus_set()
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    target.bind("<Button-3>", show_menu)        # ПКМ
    target.bind("<Control-Button-1>", show_menu)  # Ctrl+ЛКМ (для Mac)


def patch_ctk_widgets_globally() -> None:
    """Patch CTkEntry/CTkTextbox щоб у них автоматично було контекстне меню.

    Викликати ОДИН раз перед створенням віджетів.
    """
    try:
        import customtkinter as ctk

        # Patch CTkEntry
        if hasattr(ctk, "CTkEntry"):
            original_entry_init = ctk.CTkEntry.__init__
            def patched_entry_init(self, *args, **kwargs):
                original_entry_init(self, *args, **kwargs)
                try: add_context_menu(self)
                except Exception: pass
            ctk.CTkEntry.__init__ = patched_entry_init

        # Patch CTkTextbox
        if hasattr(ctk, "CTkTextbox"):
            original_textbox_init = ctk.CTkTextbox.__init__
            def patched_textbox_init(self, *args, **kwargs):
                original_textbox_init(self, *args, **kwargs)
                try: add_context_menu(self)
                except Exception: pass
            ctk.CTkTextbox.__init__ = patched_textbox_init

        print("[ClipboardFix] ✅ CTkEntry/CTkTextbox patched (right-click menus)")
    except Exception as e:
        print(f"[ClipboardFix] patch_ctk failed: {e}")