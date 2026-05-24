# gui/components/thread_safe_mixin.py
"""
NetGuardian AI — Thread-Safe Tkinter Mixin  v2.0
═══════════════════════════════════════════════════
Вирішує RuntimeError: main thread is not in main loop

ЗАСТОСУВАННЯ — додати до будь-якої GUI сторінки:

    class GameModePage(ctk.CTkFrame, ThreadSafeMixin):
        def __init__(self, ...):
            super().__init__(...)
            # Замість:  self.after(0, callback)
            # Пиши:     self._safe_after(0, callback)

ОДНОЧАСНО виправляє проблему з AI аналізатором:
  • Безпечна передача результатів з фонових потоків у GUI
  • Чергова обробка помилок (queue-based)
  • _run_in_bg() — запускає функцію в потоці з auto-callback
"""

import threading
import queue
import traceback
import logging

log = logging.getLogger("thread_safe")


class ThreadSafeMixin:
    """
    Mixin для Tkinter/CTk сторінок що використовують фонові потоки.
    Вирішує всі 3 типи RuntimeError пов'язані з threading у Tkinter.
    """

    # ── ОСНОВНИЙ МЕТОД: безпечний self.after() ────────────
    def _safe_after(self, ms: int, callback):
        """
        Безпечна заміна self.after().
        Викликай з будь-якого фонового потоку — ніколи не впаде.
        """
        try:
            if self.winfo_exists():
                self.after(ms, callback)
        except RuntimeError:
            pass  # main thread not in main loop — app закривається
        except Exception:
            pass

    # ── ОНОВЛЕННЯ ВЛАСТИВОСТЕЙ ВІДЖЕТА ────────────────────
    def _safe_update(self, widget_method, *args, **kwargs):
        """
        Безпечно оновлює будь-який CTk/Tk віджет з фонового потоку.

        Приклад:
            self._safe_update(self.status_label.configure, text="Готово")
            self._safe_update(self.progress_bar.set, 0.75)
        """
        def _do():
            try:
                widget_method(*args, **kwargs)
            except Exception:
                pass
        self._safe_after(0, _do)

    # ── ЗАПУСК ФУНКЦІЇ В ФОНОВОМУ ПОТОЦІ + CALLBACK ───────
    def _run_in_bg(self, func, on_done=None, on_error=None, *args, **kwargs):
        """
        Запускає func(*args, **kwargs) у фоновому daemon-потоці.
        Після завершення безпечно викликає on_done(result) або on_error(exc) у GUI.

        Приклад:
            def _do_scan():
                return network_scan()   # займає 5 секунд

            def _on_result(result):
                self.update_table(result)  # вже в GUI потоці

            self._run_in_bg(_do_scan, on_done=_on_result)
        """
        def _worker():
            try:
                result = func(*args, **kwargs)
                if on_done:
                    self._safe_after(0, lambda: on_done(result))
            except Exception as e:
                log.error(f"_run_in_bg error in {func.__name__}: {traceback.format_exc()}")
                if on_error:
                    self._safe_after(0, lambda: on_error(e))

        t = threading.Thread(target=_worker, daemon=True, name=f"bg_{func.__name__}")
        t.start()
        return t

    # ── ЧЕРГА ПОВІДОМЛЕНЬ (для AI аналізатора) ────────────
    def _init_error_queue(self):
        """
        Ініціалізує чергу для безпечної передачі помилок з AI аналізатора.
        Виклич у __init__ сторінки де є AI аналіз.
        """
        if not hasattr(self, "_error_queue"):
            self._error_queue = queue.Queue()
        self._safe_after(100, self._process_error_queue)

    def _push_error(self, error_data: dict):
        """
        Відправляє результат AI аналізу в чергу (можна з будь-якого потоку).
        error_data: {"title": str, "message": str, "severity": str, "kb_code": str}
        """
        if hasattr(self, "_error_queue"):
            self._error_queue.put_nowait(error_data)

    def _process_error_queue(self):
        """Обробляє чергу AI помилок у головному потоці (викликається рекурсивно)."""
        try:
            while True:
                error_data = self._error_queue.get_nowait()
                self._on_ai_error_received(error_data)
        except queue.Empty:
            pass
        except Exception as e:
            log.error(f"Error queue processing: {e}")
        finally:
            self._safe_after(200, self._process_error_queue)

    def _on_ai_error_received(self, error_data: dict):
        """
        Перевизнач цей метод у своїй сторінці щоб обробляти AI помилки.
        За замовчуванням — логує у консоль.
        """
        severity = error_data.get("severity", "INFO")
        title    = error_data.get("title", "AI Аналіз")
        message  = error_data.get("message", "")
        kb_code  = error_data.get("kb_code", "")
        log.info(f"[{severity}] {title}: {message} (KB: {kb_code})")


# ══════════════════════════════════════════════════════════
# ПАТЧ для наявних GUI файлів
# ══════════════════════════════════════════════════════════
"""
ШВИДКИЙ ПАТЧ (gamemode_ui.py, wifi_ui.py, etc.):
═══════════════════════════════════════════════════

КРОК 1 — Додай імпорт у кожен файл:
    from app.ui.components.thread_safe_mixin import ThreadSafeMixin

КРОК 2 — Додай до класу:
    class GameModePage(ctk.CTkFrame, ThreadSafeMixin):
        #                             ↑ додати це

КРОК 3 — Знайди всі self.after(0, ...) у методах scan/thread:
    # БУЛО:
    self.after(0, lambda: self._on_scan_done(result))

    # СТАЛО:
    self._safe_after(0, lambda: self._on_scan_done(result))

КРОК 4 — Якщо є AI аналіз що падає:
    def __init__(self, ...):
        ...
        self._init_error_queue()  # ← додати

    def _on_ai_error_received(self, error_data):
        # перевизнач для відображення в своєму UI
        self.show_alert(error_data["title"], error_data["message"])

    # У фоновому потоці замість прямого виклику GUI:
    # БУЛО:   self.show_alert(title, msg)   ← ПАДАЄ
    # СТАЛО:  self._push_error({"title": title, "message": msg})  ← БЕЗПЕЧНО

ФАЙЛИ ДЕ ТРЕБА ЗАСТОСУВАТИ:
  - gui/pages/gamemode_ui.py      (рядок 923)
  - gui/pages/wifi_ui.py
  - gui/pages/security_ui.py
  - gui/pages/dns_ui.py
  - gui/pages/forecast_ui.py
"""
