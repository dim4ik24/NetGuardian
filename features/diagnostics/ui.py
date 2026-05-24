# gui/pages/diagnostics_ui.py
"""
NetGuardian AI — AI Diagnostics Page
Анімоване сканування 100+ сценаріїв, Fix Panel, Auto-Fix.

PR #25: Додано фільтрацію проблем за severity (Всі/Критичні/Попередження/Інфо)
"""
import re
import customtkinter as ctk
import threading
from tkinter import messagebox
from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from features.diagnostics.engine import DiagnosticEngine


class DiagnosticsPage(ctk.CTkFrame):
    def __init__(self, parent, get_gateway_cb=None):
        super().__init__(parent, fg_color="transparent")

        self.get_gateway_cb = get_gateway_cb
        self.engine         = DiagnosticEngine()
        self._scanning      = False

        # PR #25: state для фільтрації за severity
        self._active_filter = "ALL"   # ALL | CRITICAL | WARNING | INFO
        self._all_issues    = []      # повний список (без фільтру)
        self._root_cause    = ""      # для рендерингу пустого стану

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        self._build_ui()

    # ──────────────────────────────────────────────────────
    # UI
    # ──────────────────────────────────────────────────────

    def _build_ui(self):
        """ФІКС #3 + #4: Повна перебудова layout.

        Раніше:
          • Усі 4 кнопки + QuickFix-панель в одному row=0 → переповнення
          • prog_card перекривав toolbar через pady=(74, 0) хак
          • Висоти панелей фіксовані — не регулюються

        Тепер:
          • toolbar (row=0)            — головні AI-кнопки
          • quick_fix_bar (row=1)      — окремий рядок для Quick Fix
          • prog_card (row=2)          — прогрес-бар без перекриттів
          • PanedWindow (row=3, weight=1):
              • Top pane: fix_panel    (можна тягнути за роздільник)
              • Bottom pane: console
        """
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        # ═══════════════════════════════════════════════
        # ROW 0 — TOOLBAR (4 головні кнопки)
        # ═══════════════════════════════════════════════
        tb = ctk.CTkFrame(self, fg_color="transparent")
        tb.grid(row=0, column=0, padx=24, pady=(24, 8), sticky="ew")
        tb.grid_columnconfigure(4, weight=1)  # пуста колонка для пуша вправо

        self.btn_run = ctk.CTkButton(
            tb, text="▶  ДІАГНОСТИКА",
            command=self.start_diagnostics,
            fg_color=COLORS["border_accent"],
            hover_color="#0d3d8a",
            text_color=COLORS["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=42, corner_radius=10, width=170)
        self.btn_run.grid(row=0, column=0, padx=(0, 8))

        self.btn_ai = ctk.CTkButton(
            tb, text="🤖  AI ВИСНОВОК",
            command=self.start_ai_diagnostics,
            fg_color="#1a0d3a",
            hover_color="#2d1858",
            text_color="#a78bfa",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=42, corner_radius=10,
            border_width=1, border_color="#6d28d9",
            width=170)
        self.btn_ai.grid(row=0, column=1, padx=(0, 8))

        self.btn_ai_chat = ctk.CTkButton(
            tb, text="💬  ЗАПИТАТИ AI",
            command=self._open_ai_chat,
            fg_color="#0d2e3a",
            hover_color="#0f4358",
            text_color="#7dd3fc",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            height=42, corner_radius=10,
            border_width=1, border_color="#0284c7",
            width=170)
        self.btn_ai_chat.grid(row=0, column=2, padx=(0, 8))

        ctk.CTkButton(
            tb, text="🗑  Очистити",
            command=self._clear_all,
            fg_color=COLORS["bg_card"],
            hover_color=COLORS["bg_secondary"],
            text_color=COLORS["text_dim"],
            font=ctk.CTkFont(family="Consolas", size=11),
            height=42, corner_radius=10,
            border_width=1, border_color=COLORS["border"],
            width=110).grid(row=0, column=3, padx=(0, 8))

        # ═══════════════════════════════════════════════
        # ROW 1 — QUICK FIX (окремий рядок)
        # ═══════════════════════════════════════════════
        qf = ctk.CTkFrame(self, fg_color=COLORS["bg_secondary"], corner_radius=10)
        qf.grid(row=1, column=0, padx=24, pady=(0, 8), sticky="ew")

        ctk.CTkLabel(qf, text=" ⚡ QUICK FIX: ",
                     font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                     text_color=COLORS["text_dim"]).pack(side="left", padx=(12, 8), pady=6)

        for text, method, color in [
            ("DNS Flush",     "flush_dns",     COLORS["accent_green"]),
            ("Winsock Reset", "reset_tcp_ip",  COLORS["accent_red"]),
            ("Renew IP",      "dhcp_renew",    COLORS["accent_yellow"]),
            ("DNS → 1.1.1.1", "set_fast_dns",  COLORS["accent_cyan"]),
        ]:
            ctk.CTkButton(
                qf, text=text,
                command=lambda m=method: self._trigger_fix(m),
                fg_color="transparent",
                hover_color=COLORS["bg_card"],
                text_color=color,
                font=ctk.CTkFont(family="Consolas", size=10),
                height=30, corner_radius=8,
                border_width=1, border_color=color,
                width=110).pack(side="left", padx=4, pady=6)

        # ═══════════════════════════════════════════════
        # ROW 2 — PROGRESS BAR
        # ═══════════════════════════════════════════════
        prog_card = ctk.CTkFrame(
            self, fg_color=COLORS["bg_secondary"], corner_radius=10,
            height=50)
        prog_card.grid(row=2, column=0, padx=24, pady=(0, 8), sticky="ew")
        prog_card.grid_columnconfigure(0, weight=1)
        prog_card.grid_propagate(False)

        self.progress_bar = ctk.CTkProgressBar(
            prog_card,
            fg_color=COLORS["bg_card"],
            progress_color=COLORS["accent_cyan"],
            height=6, corner_radius=3)
        self.progress_bar.set(0)
        self.progress_bar.grid(row=0, column=0, padx=15, pady=(15, 4), sticky="ew")

        self.progress_lbl = ctk.CTkLabel(
            prog_card, text="Готовий до сканування",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS["text_dim"])
        self.progress_lbl.grid(row=1, column=0, padx=15, pady=(0, 8), sticky="w")

        # ═══════════════════════════════════════════════
        # ROW 3 — PANED WINDOW (fix_panel ↕ console)
        # ФІКС #4: можна тягнути роздільник вгору/вниз
        # ═══════════════════════════════════════════════
        import tkinter as tk
        paned = tk.PanedWindow(
            self,
            orient="vertical",
            bg=COLORS["bg_primary"],
            sashwidth=6,
            sashrelief="flat",
            borderwidth=0,
            sashpad=2,
        )
        paned.grid(row=3, column=0, padx=24, pady=(0, 24), sticky="nsew")

        # ── TOP PANE: Fix Panel (із заголовком + ФІЛЬТРАМИ) ──
        fix_container = ctk.CTkFrame(paned, fg_color=COLORS["bg_secondary"],
                                      corner_radius=10)
        fix_container.grid_columnconfigure(0, weight=1)
        fix_container.grid_rowconfigure(2, weight=1)

        # Заголовок Fix Panel
        fix_header = ctk.CTkFrame(fix_container, fg_color="transparent")
        fix_header.grid(row=0, column=0, padx=12, pady=(8, 2), sticky="ew")
        self.fix_panel_title = ctk.CTkLabel(
            fix_header,
            text="🔧  Знайдені проблеми",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=COLORS["accent_yellow"])
        self.fix_panel_title.pack(side="left")
        ctk.CTkLabel(
            fix_header,
            text="↕ тягни роздільник для зміни висоти",
            font=ctk.CTkFont(family="Consolas", size=9),
            text_color=COLORS["text_dim"]).pack(side="right")

        # PR #25: РЯДОК ФІЛЬТРІВ за severity
        filter_row = ctk.CTkFrame(fix_container, fg_color="transparent")
        filter_row.grid(row=1, column=0, padx=12, pady=(0, 6), sticky="ew")

        ctk.CTkLabel(
            filter_row, text=" Фільтр: ",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"]
        ).pack(side="left")

        self._filter_btns = {}
        filters = [
            ("ALL",      "Всі",            COLORS["text_primary"],         COLORS["border"]),
            ("CRITICAL", "🔴 Критичні",     COLORS.get("accent_red", "#ff4060"), "#7f1d1d"),
            ("WARNING",  "🟡 Попередження", COLORS.get("accent_yellow", "#eab308"), "#78350f"),
            ("INFO",     "🔵 Інфо",         COLORS.get("accent_blue", "#3b82f6"),   "#1e3a8a"),
        ]
        for key, label, color, hover_bg in filters:
            btn = ctk.CTkButton(
                filter_row, text=label,
                command=lambda k=key: self._apply_filter(k),
                fg_color=("transparent" if key != self._active_filter else hover_bg),
                hover_color=hover_bg,
                text_color=color,
                font=ctk.CTkFont(family="Consolas", size=10,
                                  weight="bold" if key == self._active_filter else "normal"),
                height=26, corner_radius=6,
                border_width=1, border_color=color,
                width=110)
            btn.pack(side="left", padx=3)
            self._filter_btns[key] = (btn, color, hover_bg)

        # Прокручувана панель з картками проблем
        self.fix_panel = ctk.CTkScrollableFrame(
            fix_container, fg_color="transparent", corner_radius=0)
        self.fix_panel.grid(row=2, column=0, padx=8, pady=(0, 8), sticky="nsew")
        self.fix_panel.grid_columnconfigure(0, weight=1)

        paned.add(fix_container, minsize=120, height=200)

        # ── BOTTOM PANE: Console ──
        console_card = GlowCard(paned, accent=COLORS["accent_green"])
        console_card.grid_rowconfigure(1, weight=1)
        console_card.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(console_card, fg_color=COLORS["bg_secondary"], corner_radius=10)
        hdr.grid(row=0, column=0, padx=3, pady=(3, 0), sticky="ew")
        hdr.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            hdr,
            text="  ◉  NetGuardian AI  ·  Expert Rule-Based Diagnostic Engine  (100+ rules)",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["accent_green"]).grid(
                row=0, column=0, padx=10, pady=8, sticky="w")

        self.hdr_stat = ctk.CTkLabel(
            hdr, text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["accent_cyan"])
        self.hdr_stat.grid(row=0, column=1, padx=10, pady=8, sticky="e")

        self.console = ctk.CTkTextbox(
            console_card,
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["accent_green"],
            fg_color=COLORS["bg_primary"],
            wrap="word", corner_radius=0)
        self.console.grid(row=1, column=0, padx=3, pady=(0, 3), sticky="nsew")
        self._cwrite(
            "> Модуль готовий. Натисни [▶ ДІАГНОСТИКА] для запуску 100+ перевірок.\n")

        paned.add(console_card, minsize=200)

        self._paned = paned

    # ──────────────────────────────────────────────────────
    # PR #25: ФІЛЬТРАЦІЯ
    # ──────────────────────────────────────────────────────

    def _apply_filter(self, severity: str):
        """Застосовує фільтр за severity і перемальовує fix_panel."""
        if self._active_filter == severity:
            return  # вже активний

        self._active_filter = severity

        # Оновлюємо вигляд кнопок-фільтрів
        for key, (btn, color, hover_bg) in self._filter_btns.items():
            is_active = (key == severity)
            btn.configure(
                fg_color=hover_bg if is_active else "transparent",
                font=ctk.CTkFont(family="Consolas", size=10,
                                  weight="bold" if is_active else "normal"),
            )

        # Перемальовуємо панель з фільтром
        self._render_fix_panel_filtered()

    def _render_fix_panel_filtered(self):
        """Рендерить fix_panel з урахуванням active_filter."""
        if self._active_filter == "ALL":
            filtered = self._all_issues
        else:
            filtered = [i for i in self._all_issues
                        if i.get("sev") == self._active_filter]

        # Викликаємо оригінальний рендер з фільтрованим списком
        self._render_fix_panel(filtered, self._root_cause, _store=False)

    # ──────────────────────────────────────────────────────
    # КОНСОЛЬ
    # ──────────────────────────────────────────────────────

    def _cwrite(self, text: str):
        self.console.configure(state="normal")
        self.console.insert("end", text + "\n")
        self.console.see("end")
        self.console.configure(state="disabled")

    def _clear_all(self):
        self.console.configure(state="normal")
        self.console.delete("0.0", "end")
        self.console.configure(state="disabled")
        for w in self.fix_panel.winfo_children():
            w.destroy()
        self.progress_bar.set(0)
        self.progress_lbl.configure(text="Готовий до сканування")
        self.hdr_stat.configure(text="")
        # PR #25: скидаємо стан фільтрів
        self._all_issues = []
        self._root_cause = ""
        self._active_filter = "ALL"
        for key, (btn, color, hover_bg) in self._filter_btns.items():
            is_active = (key == "ALL")
            btn.configure(
                fg_color=hover_bg if is_active else "transparent",
                font=ctk.CTkFont(family="Consolas", size=10,
                                  weight="bold" if is_active else "normal"),
            )
        if hasattr(self, "fix_panel_title"):
            self.fix_panel_title.configure(text="🔧  Знайдені проблеми")

    # ──────────────────────────────────────────────────────
    # AI CHAT — спливаюче вікно для запитань до Gemini
    # ──────────────────────────────────────────────────────

    def _open_ai_chat(self):
        """Відкриває окреме вікно з AI чатом (Gemini)."""
        # Якщо вже відкрите — фокус на нього
        if hasattr(self, "_ai_chat_dlg") and self._ai_chat_dlg is not None:
            try:
                if self._ai_chat_dlg.winfo_exists():
                    self._ai_chat_dlg.lift()
                    self._ai_chat_dlg.focus_force()
                    return
            except Exception: pass

        # Перевіряємо доступність Gemini
        try:
            from app.core.gemini_client import get_gemini_client
            gemini = get_gemini_client()
            if not gemini.is_available():
                messagebox.showerror(
                    "AI недоступне",
                    "Налаштуй ключ Gemini у Налаштуваннях:\n"
                    "Settings → 🤖 AI Діагностика → встав ключ → Зберегти")
                return
        except Exception as e:
            messagebox.showerror("AI Помилка", str(e)[:200])
            return

        # Створюємо вікно
        dlg = ctk.CTkToplevel(self)
        dlg.title("💬 Запитати AI (Gemini)")
        dlg.geometry("700x600")
        dlg.configure(fg_color=COLORS.get("bg_primary", "#0a0a14"))
        try: dlg.transient(self.winfo_toplevel())
        except Exception: pass
        self._ai_chat_dlg = dlg

        # Header
        hdr = ctk.CTkFrame(dlg, fg_color="#0d2e3a", corner_radius=0, height=50)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(
            hdr, text="💬  AI ЧАТ  ·  GEMINI",
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color="#7dd3fc"
        ).pack(side="left", padx=20, pady=12)
        ctk.CTkLabel(
            hdr, text="🧠 Знає всі дані утиліти",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"]
        ).pack(side="right", padx=20)

        # Чат-історія
        chat_frame = ctk.CTkFrame(dlg, fg_color="transparent")
        chat_frame.pack(fill="both", expand=True, padx=14, pady=14)

        self._ai_chat_history = ctk.CTkTextbox(
            chat_frame,
            fg_color="#0a0a14",
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=11),
            wrap="word",
            border_width=1, border_color="#1e293b", corner_radius=8,
        )
        self._ai_chat_history.pack(fill="both", expand=True)

        # ── КОЛЬОРОВІ ТЕГИ для виділення повідомлень ────────────
        # Доступаємось до внутрішнього tk.Text через ._textbox
        try:
            tb = self._ai_chat_history._textbox
            # ВАЖЛИВО: використовуємо .tag_configure (повна назва, не tag_config),
            # plus передаємо параметри як **dict — це виключає Tcl abbreviation
            # ambiguity (раніше Tk інтерпретував "background" як "bitmap").
            tb.tag_configure("user_label", **{
                "background": "#0d2a3a", "foreground": "#7dd3fc",
                "font": ("Consolas", 11, "bold"),
                "spacing1": 8, "spacing3": 2,
                "lmargin1": 4, "lmargin2": 4,
            })
            tb.tag_configure("user_text", **{
                "background": "#0a1f2e", "foreground": "#e0e7ff",
                "font": ("Consolas", 11),
                "spacing3": 10,
                "lmargin1": 4, "lmargin2": 4,
            })
            tb.tag_configure("ai_label", **{
                "background": "#1a0d3a", "foreground": "#a78bfa",
                "font": ("Consolas", 11, "bold"),
                "spacing1": 8, "spacing3": 2,
                "lmargin1": 4, "lmargin2": 4,
            })
            tb.tag_configure("ai_label_kb", **{
                "background": "#0d2a3a", "foreground": "#0ea5e9",
                "font": ("Consolas", 11, "bold"),
                "spacing1": 8, "spacing3": 2,
                "lmargin1": 4, "lmargin2": 4,
            })
            tb.tag_configure("ai_text", **{
                "background": "#0d0a1a", "foreground": "#f1f5f9",
                "font": ("Consolas", 11),
                "spacing3": 10,
                "lmargin1": 4, "lmargin2": 4,
            })
            tb.tag_configure("system", **{
                "foreground": "#64748b",
                "font": ("Consolas", 10, "italic"),
                "spacing3": 4,
            })
            tb.tag_configure("separator", **{
                "foreground": "#1e293b",
                "spacing1": 6, "spacing3": 6,
            })
        except Exception as e:
            print(f"[AI Chat] tag_configure failed: {e}")

        self._ai_chat_history.insert("end",
            "🤖 Привіт! Я AI-асистент NetGuardian.\n"
            "Я бачу всі дані твоєї утиліти — мережу, VPN, Pi, Tapo, історію.\n"
            "Запитуй: 'Як справи з мережею?', 'Скільки електрики споживає Tapo?',\n"
            "'Чи був сьогодні обрив?', 'Чому повільний інтернет?'\n\n",
            "system")
        self._ai_chat_history.configure(state="disabled")

        # Input row
        input_row = ctk.CTkFrame(dlg, fg_color="transparent", height=60)
        input_row.pack(fill="x", padx=14, pady=(0, 14))
        input_row.pack_propagate(False)

        self._ai_chat_entry = ctk.CTkEntry(
            input_row,
            fg_color="#0d1117",
            border_color="#0284c7",
            text_color=COLORS["text_primary"],
            font=ctk.CTkFont(family="Consolas", size=12),
            placeholder_text="Введи питання...  (Enter для надсилання)",
            height=44,
        )
        self._ai_chat_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self._ai_chat_entry.bind("<Return>", lambda e: self._ai_chat_send())
        self._ai_chat_entry.focus_set()

        self._ai_chat_btn = ctk.CTkButton(
            input_row, text="➤  Надіслати",
            command=self._ai_chat_send,
            fg_color="#0d2e3a",
            hover_color="#0f4358",
            text_color="#7dd3fc",
            font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
            height=44, width=120, corner_radius=8,
            border_width=1, border_color="#0284c7",
        )
        self._ai_chat_btn.pack(side="right")

        def _on_close():
            self._ai_chat_dlg = None
            try: dlg.destroy()
            except Exception: pass
        dlg.protocol("WM_DELETE_WINDOW", _on_close)

    def _ai_chat_send(self):
        """Надсилає питання до AI."""
        try:
            question = self._ai_chat_entry.get().strip()
            if not question:
                return

            # Додаємо в історію з кольоровими тегами
            self._ai_chat_history.configure(state="normal")
            self._ai_chat_history.insert("end", "👤 ТИ:\n", "user_label")
            self._ai_chat_history.insert("end", f"{question}\n\n", "user_text")
            self._ai_chat_history.insert("end", "🤖 AI думає...\n", "system")
            self._ai_chat_history.see("end")
            self._ai_chat_history.configure(state="disabled")

            # Очищаємо input + блокуємо кнопку
            self._ai_chat_entry.delete(0, "end")
            self._ai_chat_btn.configure(state="disabled", text="⏳")

            # Запускаємо запит у фоні (state-pattern)
            self._ai_chat_state = {"answer": None, "error": None, "done": False}
            threading.Thread(
                target=lambda q=question: self._ai_chat_worker(q),
                daemon=True).start()
            self._ai_chat_poll()
        except Exception as e:
            print(f"[AI Chat] send error: {e}")

    def _ai_chat_worker(self, question: str):
        """Worker — НЕ викликає self.after().

        PR #25: Використовує HybridAIClient з ПОВНИМ контекстом усієї утиліти
        (snapshot, vpn, forecast, pi, lan, tapo, recent_diagnostics).

        Завжди повертає відповідь, навіть коли інтернет лежить.
        """
        try:
            # PR #25: НЕ передаємо ctx вручну — hybrid сам збере через
            # gather_full_context() (snapshot + vpn + forecast + pi + tapo + diag)
            try:
                from hybrid_ai import get_hybrid_client
                hybrid = get_hybrid_client()
                # context=None → автоматичний збір повного контексту
                answer = hybrid.quick_answer(question, context=None)
                # Зберігаємо source для UI індикатора
                self._ai_chat_state["source"] = hybrid.last_source
            except ImportError:
                # Fallback на чистий Gemini якщо hybrid_ai.py відсутній
                try:
                    from app.core.gemini_client import get_gemini_client, gather_network_context
                    ctx = gather_network_context()
                    gemini = get_gemini_client()
                    answer = gemini.quick_answer(question, context=ctx)
                    self._ai_chat_state["source"] = "gemini"
                except Exception as e:
                    answer = f"❌ Помилка: {e}"
                    self._ai_chat_state["source"] = "error"

            self._ai_chat_state["answer"] = answer
        except Exception as e:
            self._ai_chat_state["error"] = str(e)
        finally:
            self._ai_chat_state["done"] = True

    def _ai_chat_poll(self):
        """Polling — кожні 200мс перевіряє чи готова відповідь."""
        try:
            st = self._ai_chat_state
            if not st.get("done"):
                try: self.after(200, self._ai_chat_poll)
                except Exception: pass
                return

            # Готово — рендеримо
            self._ai_chat_history.configure(state="normal")
            # Видаляємо "🤖 AI думає...\n" — 14 символів
            try:
                self._ai_chat_history.delete("end-15c", "end")
            except Exception: pass

            if st.get("error"):
                self._ai_chat_history.insert("end",
                    f"❌ Помилка: {st['error'][:200]}\n\n", "system")
            else:
                answer = st.get("answer", "Пуста відповідь")
                source = st.get("source", "unknown")

                # Витягуємо префікс з answer (HybridAIClient додає
                # "🌐 **Gemini AI:**\n\n..." або "📦 **Локальна база...**")
                # і використовуємо різний колір label для Gemini vs KB
                label_tag = "ai_label_kb" if source == "knowledge_base" else "ai_label"
                if source == "knowledge_base":
                    label_text = "📦 ЛОКАЛЬНА БАЗА (offline):\n"
                else:
                    label_text = "🤖 GEMINI AI:\n"

                # Видаляємо префікс з answer (бо тепер у label)
                clean_answer = answer
                for prefix in ("🌐 **Gemini AI:**", "📦 **Локальна база знань**"):
                    if clean_answer.lstrip().startswith(prefix):
                        idx = clean_answer.find(prefix) + len(prefix)
                        # Прибираємо також "_(інтернет недоступний)_"
                        rest = clean_answer[idx:].lstrip()
                        if rest.startswith("_(інтернет недоступний)_"):
                            rest = rest[len("_(інтернет недоступний)_"):].lstrip()
                        clean_answer = rest
                        break

                self._ai_chat_history.insert("end", label_text, label_tag)
                self._ai_chat_history.insert("end", f"{clean_answer}\n\n", "ai_text")

            # Розділювач між діалогами
            self._ai_chat_history.insert("end", "─" * 70 + "\n\n", "separator")
            self._ai_chat_history.see("end")
            self._ai_chat_history.configure(state="disabled")

            # Розблоковуємо
            self._ai_chat_btn.configure(state="normal", text="➤  Надіслати")
            self._ai_chat_entry.focus_set()
        except Exception as e:
            print(f"[AI Chat] poll error: {e}")

    # ──────────────────────────────────────────────────────
    # ЗАПУСК ДІАГНОСТИКИ
    # ──────────────────────────────────────────────────────

    def start_diagnostics(self):
        if self._scanning:
            return
        self._scanning = True
        self.btn_run.configure(state="disabled", text="⏳  Сканування...")
        self.btn_ai.configure(state="disabled")
        self._clear_all()
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def start_ai_diagnostics(self):
        """Запускає rule-engine + Gemini AI-аналіз."""
        if self._scanning:
            return
        self._scanning = True
        self.btn_run.configure(state="disabled")
        self.btn_ai.configure(state="disabled", text="⏳  AI аналізує...")
        self._clear_all()
        threading.Thread(target=self._scan_thread_ai, daemon=True).start()

    def _scan_thread_ai(self):
        """Виконує гібридну діагностику з AI."""
        gw = self.get_gateway_cb() if self.get_gateway_cb else "192.168.1.1"
        self._check_idx   = 0
        self._check_total = 1

        def on_log(txt: str):
            if txt.strip().startswith(("✅", "🔴", "🟡", "🔵")):
                self._check_idx += 1
                pct = min(self._check_idx / max(self._check_total, 1), 1.0)
                self.after(0, lambda p=pct: self.progress_bar.set(p))
            self.after(0, lambda t=txt: self._cwrite(t))

        def on_prog(txt: str):
            m = re.match(r"Перевірка (\d+)/(\d+)", txt)
            if m:
                self._check_idx   = int(m.group(1))
                self._check_total = int(m.group(2))
                pct = self._check_idx / self._check_total
                self.after(0, lambda p=pct, t=txt: (
                    self.progress_bar.set(p),
                    self.progress_lbl.configure(text=t)))
            else:
                self.after(0, lambda t=txt: self.progress_lbl.configure(text=t))

        try:
            result = self.engine.analyze_with_ai(
                gateway_ip=gw, log_cb=on_log, prog_cb=on_prog)
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda msg=err_msg: self._on_scan_error(msg))
            return

        self.after(0, lambda: self._render_results_ai(result))

    def _scan_thread(self):
        gw = self.get_gateway_cb() if self.get_gateway_cb else "192.168.1.1"

        self._check_idx   = 0
        self._check_total = 1

        def on_log(txt: str):
            if txt.strip().startswith(("✅", "🔴", "🟡", "🔵")):
                self._check_idx += 1
                pct = min(self._check_idx / max(self._check_total, 1), 1.0)
                self.after(0, lambda p=pct: self.progress_bar.set(p))
            self.after(0, lambda t=txt: self._cwrite(t))

        def on_prog(txt: str):
            m = re.match(r"Перевірка (\d+)/(\d+)", txt)
            if m:
                self._check_idx   = int(m.group(1))
                self._check_total = int(m.group(2))
                pct = self._check_idx / self._check_total
                self.after(0, lambda p=pct, t=txt: (
                    self.progress_bar.set(p),
                    self.progress_lbl.configure(text=t)))
            else:
                self.after(0, lambda t=txt: self.progress_lbl.configure(text=t))

        # ── ЗАХИЩЕНИЙ ВИКЛИК ──────────────────────────────
        try:
            report = self.engine.run_full_diagnostics(
                gateway_ip=gw, log_cb=on_log, prog_cb=on_prog)
        except Exception as e:
            err_msg = str(e)
            self.after(0, lambda msg=err_msg: self._on_scan_error(msg))
            return

        self.after(0, lambda: self._render_results(report))

    def _on_scan_error(self, err_msg: str):
        """Викликається з головного потоку коли діагностика впала з exception."""
        self._cwrite(f"\n{'═' * 54}")
        self._cwrite(f"❌  КРИТИЧНА ПОМИЛКА ДІАГНОСТИКИ:")
        self._cwrite(f"    {err_msg}")
        self._cwrite(f"{'═' * 54}")
        self._cwrite("💡  Спробуй запустити програму від імені Адміністратора.")
        self.progress_bar.set(0)
        self.progress_lbl.configure(text=f"Помилка: {err_msg[:80]}")
        self.hdr_stat.configure(text="❌ Помилка діагностики")
        self._scanning = False
        self.btn_run.configure(
            state="normal",
            text="▶  AI ДІАГНОСТИКА  (100+ перевірок)")

    # ──────────────────────────────────────────────────────
    # РЕНДЕР РЕЗУЛЬТАТІВ
    # ──────────────────────────────────────────────────────

    def _render_results(self, report: dict):
        self.progress_bar.set(1.0)
        total  = report.get("total_checks", 0)
        issues = report.get("issues", [])
        crit   = sum(1 for i in issues if i["sev"] == "CRITICAL")
        warn   = sum(1 for i in issues if i["sev"] == "WARNING")

        stat_txt = (f"{total} перевірок  ·  {crit} критичних  ·  {warn} попереджень"
                    if issues else f"{total} перевірок  ·  все OK ✅")
        self.hdr_stat.configure(text=stat_txt)
        self.progress_lbl.configure(text=report.get("root_cause", ""))

        self._render_fix_panel(issues, report.get("root_cause", ""))

        self._scanning = False
        self.btn_run.configure(state="normal", text="▶  AI ДІАГНОСТИКА  (100+ перевірок)")
        self.btn_ai.configure(state="normal", text="🤖  AI ВИСНОВОК (Gemini)")

    def _render_results_ai(self, result: dict):
        """Рендерить результат гібридної діагностики (rule + AI)."""
        rule_report = result.get("rule_based", {})
        ai_data     = result.get("ai")
        has_ai      = result.get("has_ai", False)

        # 1. Спочатку як завжди — rule-based результати
        self.progress_bar.set(1.0)
        total  = rule_report.get("total_checks", 0)
        issues = rule_report.get("issues", [])
        crit   = sum(1 for i in issues if i["sev"] == "CRITICAL")
        warn   = sum(1 for i in issues if i["sev"] == "WARNING")

        stat_txt = (f"{total} перевірок  ·  {crit} критичних  ·  {warn} попереджень"
                    if issues else f"{total} перевірок  ·  все OK ✅")
        if has_ai:
            stat_txt = "🤖 AI · " + stat_txt
        self.hdr_stat.configure(text=stat_txt)
        self.progress_lbl.configure(text=rule_report.get("root_cause", ""))

        # 2. Якщо AI спрацювало — рендеримо AI-картку перед rule-based
        if has_ai and ai_data:
            # Зберігаємо для AI чату — щоб chat бачив останній аналіз
            self._last_ai_data = ai_data
            self._render_ai_card(ai_data)
            self._cwrite(f"\n{'═' * 58}")
            self._cwrite(f"  🤖 AI ВИСНОВОК (Google Gemini)")
            self._cwrite(f"{'═' * 58}")
            self._cwrite(f"\n📋 {ai_data.get('summary', '')}\n")

            for line in ai_data.get("good", []):
                self._cwrite(f"  {line}")
            if ai_data.get("good"):
                self._cwrite("")
            for line in ai_data.get("warnings", []):
                self._cwrite(f"  {line}")
            if ai_data.get("warnings"):
                self._cwrite("")
            for line in ai_data.get("critical", []):
                self._cwrite(f"  {line}")
            if ai_data.get("critical"):
                self._cwrite("")

            tips = ai_data.get("tips", [])
            if tips:
                self._cwrite(f"💡 ПОРАДИ:")
                for i, tip in enumerate(tips, 1):
                    self._cwrite(f"  {i}. {tip}")
                self._cwrite("")
        else:
            err = result.get("ai_error", "")
            if err:
                self._cwrite(f"\n⚠️ AI-аналіз не вдався: {err}\n")
                self._cwrite("    Налаштуй ключ Gemini у Settings → AI")
                # Показуємо звичайний rule-based fix panel
                self._render_fix_panel(issues, rule_report.get("root_cause", ""))

        # Rule-based fix panel — завжди показуємо
        if has_ai and ai_data:
            # AI-картка вже зрендерена, додаємо rule-based знизу як деталі
            self._render_fix_panel(issues, rule_report.get("root_cause", ""))

        self._scanning = False
        self.btn_run.configure(state="normal", text="▶  AI ДІАГНОСТИКА  (100+ перевірок)")
        self.btn_ai.configure(state="normal", text="🤖  AI ВИСНОВОК (Gemini)")

    def _render_ai_card(self, ai_data: dict):
        """Рендерить красиву AI-картку у fix_panel."""
        # Очищаємо панель
        for w in self.fix_panel.winfo_children():
            w.destroy()

        overall = ai_data.get("overall", "good")
        color_map = {
            "excellent": ("#00ff88", "#002800", "🟢"),
            "good":      ("#00ff88", "#002800", "🟢"),
            "warning":   (COLORS.get("accent_yellow", "#eab308"), "#281800", "🟡"),
            "critical":  (COLORS.get("accent_red",    "#ef4444"), "#280000", "🔴"),
        }
        border, bg, icon = color_map.get(overall, ("#a78bfa", "#1a0d3a", "🤖"))

        # AI-картка з фіолетовим акцентом
        card = ctk.CTkFrame(
            self.fix_panel,
            fg_color="#1a0d3a", corner_radius=12,
            border_width=2, border_color="#a78bfa")
        card.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        card.grid_columnconfigure(0, weight=1)

        # Header — показуємо ДЖЕРЕЛО (Gemini vs KB) щоб юзер розумів режим
        source = ai_data.get("source", "gemini")
        if source == "knowledge_base":
            header_title = "📦  ЛОКАЛЬНА БАЗА ЗНАНЬ"
            header_color = "#0ea5e9"   # блакитний — offline режим
            card.configure(border_color=header_color)
        else:
            header_title = "🤖  AI ВИСНОВОК (Google Gemini)"
            header_color = "#a78bfa"   # фіолетовий — online AI

        hdr = ctk.CTkFrame(card, fg_color="transparent")
        hdr.grid(row=0, column=0, sticky="ew", padx=20, pady=(16, 8))
        ctk.CTkLabel(
            hdr, text=header_title,
            font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            text_color=header_color
        ).pack(side="left")
        ctk.CTkLabel(
            hdr, text=f"{icon}  Загальний стан: {overall.upper()}",
            font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
            text_color=border
        ).pack(side="right")

        # Якщо offline — невелика підказка чому
        if source == "knowledge_base":
            offline_hint = ctk.CTkLabel(
                card,
                text="⚠️ Інтернет недоступний — AI працює в офлайн-режимі. "
                     "Поради базуються на локальній базі мережевих проблем.",
                font=ctk.CTkFont(family="Consolas", size=10, slant="italic"),
                text_color="#7dd3fc",
                wraplength=900, justify="left",
            )
            offline_hint.grid(row=10, column=0, sticky="ew",
                               padx=20, pady=(2, 0))

        # Summary
        summary_frame = ctk.CTkFrame(card, fg_color=bg, corner_radius=8)
        summary_frame.grid(row=1, column=0, sticky="ew", padx=20, pady=4)
        ctk.CTkLabel(
            summary_frame, text=ai_data.get("summary", ""),
            font=ctk.CTkFont(family="Consolas", size=12),
            text_color="#ffffff", wraplength=900, justify="left"
        ).pack(anchor="w", padx=14, pady=12)

        # Good / Warnings / Critical
        sections = [
            ("good",     "✅ Що працює добре",       "#22c55e"),
            ("warnings", "🟡 Попередження",           "#eab308"),
            ("critical", "🔴 Критичні проблеми",      "#ef4444"),
        ]
        for key, title, col in sections:
            items = ai_data.get(key, [])
            if not items: continue
            sec = ctk.CTkFrame(card, fg_color="transparent")
            sec.grid(row=len(card.winfo_children()), column=0,
                      sticky="ew", padx=20, pady=(6, 4))
            ctk.CTkLabel(
                sec, text=title,
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=col
            ).pack(anchor="w")
            for line in items:
                ctk.CTkLabel(
                    sec, text=f"  {line}",
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color=COLORS.get("text_secondary", "#9ca3af"),
                    wraplength=900, justify="left"
                ).pack(anchor="w", padx=10)

        # Tips (поради)
        tips = ai_data.get("tips", [])
        if tips:
            tips_frame = ctk.CTkFrame(card, fg_color="#0d1f3a", corner_radius=8)
            tips_frame.grid(row=99, column=0, sticky="ew",
                             padx=20, pady=(10, 16))
            ctk.CTkLabel(
                tips_frame, text="💡 ПОРАДИ ДЛЯ ВИПРАВЛЕННЯ",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color="#00d4ff"
            ).pack(anchor="w", padx=14, pady=(10, 4))
            for i, tip in enumerate(tips, 1):
                ctk.CTkLabel(
                    tips_frame, text=f"  {i}. {tip}",
                    font=ctk.CTkFont(family="Consolas", size=11),
                    text_color="#bfdbfe", wraplength=900, justify="left"
                ).pack(anchor="w", padx=14, pady=2)
            ctk.CTkFrame(tips_frame, height=8, fg_color="transparent").pack()

        # ── AUTO-FIX WIZARD (NEW!) ─────────────────────────────────────
        # AI може запропонувати конкретні fix-и які користувач може
        # виконати в один клік
        fixes = ai_data.get("fixes", [])
        if fixes:
            fix_frame = ctk.CTkFrame(card, fg_color="#1a3a0d", corner_radius=8,
                                      border_width=1, border_color="#22c55e")
            fix_frame.grid(row=100, column=0, sticky="ew", padx=20, pady=(8, 16))
            fix_frame.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                fix_frame, text="🔧 АВТОМАТИЧНІ ФІКСИ ВІД AI",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color="#22c55e"
            ).grid(row=0, column=0, sticky="w", padx=14, pady=(10, 4))

            risk_emoji = {"low": "🟢", "medium": "🟡", "high": "🔴"}

            for fix_idx, fix in enumerate(fixes):
                if not isinstance(fix, dict): continue
                fix_id = fix.get("id", f"fix_{fix_idx}")
                label = fix.get("label", "Невідома дія")
                cmd = fix.get("command", "")
                reason = fix.get("reason", "")
                risk = fix.get("risk", "medium").lower()
                emoji = risk_emoji.get(risk, "⚪")

                # Картка одного фіксу
                fc = ctk.CTkFrame(fix_frame, fg_color="#0d2a14", corner_radius=6)
                fc.grid(row=fix_idx + 1, column=0, sticky="ew", padx=14, pady=4)
                fc.grid_columnconfigure(0, weight=1)

                # Заголовок + кнопка
                head = ctk.CTkFrame(fc, fg_color="transparent")
                head.grid(row=0, column=0, sticky="ew", padx=10, pady=(8, 2))
                head.grid_columnconfigure(0, weight=1)

                ctk.CTkLabel(
                    head, text=f"{emoji}  {label}",
                    font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                    text_color="#86efac",
                    anchor="w"
                ).grid(row=0, column=0, sticky="ew")

                # Кнопка для high-risk вимагає підтвердження
                btn_text = "▶ Виконати" if risk != "high" else "⚠ Виконати (HIGH RISK)"
                ctk.CTkButton(
                    head, text=btn_text,
                    command=lambda f=fix: self._execute_ai_fix(f),
                    fg_color="#0d3a1a" if risk != "high" else "#3a0d0d",
                    hover_color="#155d2c" if risk != "high" else "#5d1515",
                    text_color="#22c55e" if risk != "high" else "#ef4444",
                    font=ctk.CTkFont(family="Consolas", size=10, weight="bold"),
                    height=28, width=170, corner_radius=6,
                    border_width=1,
                    border_color="#22c55e" if risk != "high" else "#ef4444",
                ).grid(row=0, column=1, padx=(8, 0))

                # Reason
                if reason:
                    ctk.CTkLabel(
                        fc, text=f"  💡 {reason}",
                        font=ctk.CTkFont(family="Consolas", size=10),
                        text_color="#bbf7d0",
                        wraplength=850, justify="left"
                    ).grid(row=1, column=0, sticky="w", padx=10, pady=(0, 2))

                # Command
                if cmd:
                    ctk.CTkLabel(
                        fc, text=f"  $ {cmd}",
                        font=ctk.CTkFont(family="Consolas", size=10, slant="italic"),
                        text_color="#94a3b8", anchor="w"
                    ).grid(row=2, column=0, sticky="w", padx=10, pady=(0, 8))

        self.fix_panel.configure(height=800)

    def _execute_ai_fix(self, fix: dict):
        """Виконує AI-запропонований фікс."""
        from tkinter import messagebox
        cmd = fix.get("command", "").strip()
        if not cmd:
            messagebox.showinfo("AI Fix", "Команда не вказана для цієї дії.")
            return

        risk = fix.get("risk", "medium").lower()
        label = fix.get("label", "AI Fix")

        # Підтвердження для middle/high risk
        if risk in ("medium", "high"):
            ok = messagebox.askyesno(
                f"Підтвердження ({risk.upper()} RISK)",
                f"AI пропонує виконати:\n\n"
                f"📛 {label}\n"
                f"💡 {fix.get('reason', '')}\n\n"
                f"Команда: {cmd}\n\n"
                f"Виконати?")
            if not ok: return

        # Виконуємо
        try:
            import subprocess
            self._cwrite(f"\n🔧 Виконую AI-фікс: {label}")
            self._cwrite(f"   $ {cmd}")
            r = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if r.returncode == 0:
                self._cwrite(f"   ✅ Успішно")
                if r.stdout: self._cwrite(f"   {r.stdout.strip()[:300]}")
            else:
                self._cwrite(f"   ❌ Код помилки {r.returncode}")
                if r.stderr: self._cwrite(f"   {r.stderr.strip()[:300]}")
        except Exception as e:
            self._cwrite(f"   ❌ {e}")

    # ──────────────────────────────────────────────────────
    # FIX PANEL
    # ──────────────────────────────────────────────────────

    def _render_fix_panel(self, issues: list, root_cause: str, _store: bool = True):
        """PR #25: _store=True зберігає список для пізнішого фільтрування."""
        # Зберігаємо повний список для перемикання фільтрів
        if _store:
            self._all_issues = list(issues)
            self._root_cause = root_cause
            self._active_filter = "ALL"
            # Скидаємо вигляд кнопок-фільтрів на ALL
            for key, (btn, color, hover_bg) in self._filter_btns.items():
                is_active = (key == "ALL")
                btn.configure(
                    fg_color=hover_bg if is_active else "transparent",
                    font=ctk.CTkFont(family="Consolas", size=10,
                                      weight="bold" if is_active else "normal"),
                )

        for w in self.fix_panel.winfo_children():
            w.destroy()

        if not issues:
            # Якщо є повний список — це фільтр повернув 0
            if _store is False and self._all_issues:
                msg = ctk.CTkFrame(
                    self.fix_panel,
                    fg_color=COLORS["bg_card"], corner_radius=12,
                    border_width=1, border_color=COLORS["border"])
                msg.grid(row=0, column=0, sticky="ew", pady=4)
                ctk.CTkLabel(
                    msg,
                    text=f"  Немає проблем з рівнем '{self._active_filter}'.",
                    font=ctk.CTkFont(family="Consolas", size=12),
                    text_color=COLORS["text_dim"]).pack(padx=24, pady=18, anchor="w")
                self.fix_panel.configure(height=80)
                return

            # Інакше — все справді гаразд
            ok = ctk.CTkFrame(
                self.fix_panel,
                fg_color="#002800", corner_radius=12,
                border_width=1, border_color=COLORS["accent_green"])
            ok.grid(row=0, column=0, sticky="ew", pady=4)
            ctk.CTkLabel(
                ok,
                text=f"  ✅  {root_cause}",
                font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
                text_color=COLORS["accent_green"]).pack(padx=24, pady=18, anchor="w")
            self.fix_panel.configure(height=80)
            return

        # ── СОРТУВАННЯ ЗА ТЯЖКІСТЮ ──
        # CRITICAL (0) → WARNING (1) → INFO (2)
        SEV_ORDER = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        issues = sorted(issues, key=lambda x: SEV_ORDER.get(x.get("sev", "INFO"), 99))

        # PR #25: рахуємо ВСІ issues (не тільки відфільтровані) для заголовка
        full_list = self._all_issues if self._all_issues else issues
        n_crit = sum(1 for i in full_list if i.get("sev") == "CRITICAL")
        n_warn = sum(1 for i in full_list if i.get("sev") == "WARNING")
        n_info = sum(1 for i in full_list if i.get("sev") == "INFO")

        # Оновлюємо заголовок панелі з лічильниками
        summary_parts = []
        if n_crit: summary_parts.append(f"🔴 {n_crit}")
        if n_warn: summary_parts.append(f"🟡 {n_warn}")
        if n_info: summary_parts.append(f"🔵 {n_info}")
        summary = " · ".join(summary_parts) if summary_parts else ""

        if hasattr(self, "fix_panel_title"):
            filter_label = ""
            if self._active_filter != "ALL":
                filter_label = f"  [фільтр: {self._active_filter}]"
            self.fix_panel_title.configure(
                text=f"🔧  Знайдені проблеми ({len(full_list)})  {summary}{filter_label}"
            )

        SEV = {
            "CRITICAL": (COLORS["accent_red"],    "#280000", "🔴"),
            "WARNING":  (COLORS["accent_yellow"], "#281800", "🟡"),
            "INFO":     (COLORS["accent_blue"],   "#001428", "🔵"),
        }

        for idx, item in enumerate(issues):
            sev = item.get("sev", "INFO")
            border, bg, icon = SEV.get(sev, (COLORS["border"], COLORS["bg_card"], "⚪"))

            card = ctk.CTkFrame(
                self.fix_panel, fg_color=bg,
                corner_radius=12, border_width=1, border_color=border)
            card.grid(row=idx, column=0, sticky="ew", pady=3)
            card.grid_columnconfigure(0, weight=1)

            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, padx=15, pady=(10, 3), sticky="ew")
            top.grid_columnconfigure(0, weight=1)

            ctk.CTkLabel(
                top,
                text=f"{icon}  [{item.get('code','?')}]  {item.get('title','')}",
                font=ctk.CTkFont(family="Consolas", size=12, weight="bold"),
                text_color=border).grid(row=0, column=0, sticky="w")

            fix_key = item.get("fix")
            if fix_key:
                lbl = item.get("fix_lbl") or "🔧 Виправити"
                ctk.CTkButton(
                    top, text=lbl,
                    command=lambda m=fix_key: self._trigger_fix(m),
                    fg_color=border,
                    hover_color=border,
                    text_color="#000000" if sev == "WARNING" else COLORS["text_primary"],
                    font=ctk.CTkFont(family="Consolas", size=11, weight="bold"),
                    height=30, corner_radius=8).grid(
                        row=0, column=1, sticky="e", padx=(10, 0))

            ctk.CTkLabel(
                top,
                text=item.get("group", ""),
                font=ctk.CTkFont(family="Consolas", size=9),
                text_color=COLORS["text_dim"]).grid(
                    row=0, column=2, sticky="e", padx=(8, 0))

            ctk.CTkLabel(
                card, text=item.get("desc", ""),
                font=ctk.CTkFont(family="Consolas", size=11),
                text_color=COLORS["text_secondary"],
                justify="left").grid(
                    row=1, column=0, padx=20, pady=(0, 10), sticky="w")

        self.fix_panel.configure(height=min(300, len(issues) * 90))

    # ──────────────────────────────────────────────────────
    # AUTO-FIX
    # ──────────────────────────────────────────────────────

    def _trigger_fix(self, method_name: str):
        self._cwrite("\n" + "═" * 54)
        self._cwrite(f"⚕  Auto-Fix: {method_name}...")

        def do():
            fn = getattr(self.engine, method_name, None)
            if fn:
                ok, msg = fn()
                res = f"  {'✅' if ok else '❌'} {msg}"
            else:
                res = "  ❌ Метод не знайдено"
            self.after(0, lambda r=res: self._cwrite(r))

        threading.Thread(target=do, daemon=True).start()