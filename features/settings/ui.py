# gui/pages/settings_ui.py
import customtkinter as ctk
import tkinter as tk
import os
import json
import re
import threading

from app.ui.theme import COLORS
from app.ui.components.widgets import GlowCard
from app.core.utils import NetworkScanner
from app.bot.bot import TelegramAlerter

class SettingsPage(ctk.CTkScrollableFrame):
    def __init__(self, parent, on_save_callback=None):
        super().__init__(parent, fg_color="transparent", corner_radius=0)
        self.on_save_callback = on_save_callback
        
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.config_file = os.path.join(base_dir, "config.json")
        
        self.gateway_ip = ""
        self.tg_chat_id = ""
        self.heartbeat_url = ""
        self.tg_token = os.environ.get("TG_BOT_TOKEN", "") # Беремо токен з .env
        
        self._load_config()
        
        self.grid_columnconfigure(0, weight=1)
        self._build_ui()

    def _load_config(self):
        self.gateway_ip = NetworkScanner.get_default_gateway()
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self.gateway_ip = data.get("ip", self.gateway_ip)
                    self.tg_chat_id = data.get("chat_id", "")
                    self.heartbeat_url = data.get("heartbeat_url", "")
            except: pass

    def _build_ui(self):
        def add_ctx(w):
            m = tk.Menu(w, tearoff=0, bg="#1a2238", fg="white", relief="flat")
            m.add_command(label="📋 Вставити", command=lambda: w.event_generate("<<Paste>>"))
            w.bind("<Button-3>", lambda e: m.tk_popup(e.x_root, e.y_root))

        # ─── 1. МЕРЕЖЕВІ НАЛАШТУВАННЯ ───
        net_card = GlowCard(self, accent=COLORS["border_accent"])
        net_card.grid(row=0, column=0, padx=24, pady=(24, 12), sticky="ew")
        net_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(net_card, text="🌐  МЕРЕЖЕВІ ПАРАМЕТРИ", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=COLORS["accent_cyan"]).grid(row=0, column=0, columnspan=2, padx=24, pady=(20, 15), sticky="w")
        ctk.CTkLabel(net_card, text="IP шлюзу / роутера:", font=ctk.CTkFont(family="Consolas", size=11), text_color=COLORS["text_secondary"]).grid(row=1, column=0, padx=24, pady=5, sticky="w")

        self.entry_gateway = ctk.CTkEntry(net_card, width=220, font=ctk.CTkFont(family="Consolas", size=12), fg_color=COLORS["bg_secondary"], border_color=COLORS["border"], text_color=COLORS["text_primary"])
        self.entry_gateway.grid(row=1, column=1, padx=24, pady=5, sticky="w")
        self.entry_gateway.insert(0, self.gateway_ip)
        add_ctx(self.entry_gateway)

        ctk.CTkButton(
            net_card, text="🔍 Знайти автоматично", command=self._auto_detect_ip,
            fg_color=COLORS["bg_secondary"], hover_color=COLORS["bg_card"], text_color=COLORS["text_secondary"],
            font=ctk.CTkFont(family="Consolas", size=11), height=36, corner_radius=8
        ).grid(row=2, column=0, padx=24, pady=(5, 20), sticky="w")

        # ─── 2. TELEGRAM ТА ХМАРА ───
        tg_card = GlowCard(self, accent=COLORS["border"])
        tg_card.grid(row=1, column=0, padx=24, pady=12, sticky="ew")
        tg_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(tg_card, text="☁️  ХМАРНА ІНТЕГРАЦІЯ  ·  TELEGRAM + HEARTBEAT", font=ctk.CTkFont(family="Consolas", size=13, weight="bold"), text_color=COLORS["accent_cyan"]).grid(row=0, column=0, columnspan=2, padx=24, pady=(20, 15), sticky="w")

        ctk.CTkLabel(tg_card, text="Telegram Chat ID:", font=ctk.CTkFont(family="Consolas", size=11), text_color=COLORS["text_secondary"]).grid(row=1, column=0, padx=24, pady=5, sticky="w")
        self.entry_tg_chat = ctk.CTkEntry(tg_card, width=280, font=ctk.CTkFont(family="Consolas", size=12), fg_color=COLORS["bg_secondary"], border_color=COLORS["border"], text_color=COLORS["text_primary"])
        self.entry_tg_chat.grid(row=1, column=1, padx=24, pady=5, sticky="w")
        self.entry_tg_chat.insert(0, self.tg_chat_id)
        add_ctx(self.entry_tg_chat)

        ctk.CTkLabel(tg_card, text="Healthchecks URL:", font=ctk.CTkFont(family="Consolas", size=11), text_color=COLORS["text_secondary"]).grid(row=2, column=0, padx=24, pady=5, sticky="w")
        self.entry_heartbeat = ctk.CTkEntry(tg_card, width=420, font=ctk.CTkFont(family="Consolas", size=12), fg_color=COLORS["bg_secondary"], border_color=COLORS["border"], text_color=COLORS["text_primary"])
        self.entry_heartbeat.grid(row=2, column=1, padx=24, pady=5, sticky="w")
        self.entry_heartbeat.insert(0, self.heartbeat_url)
        add_ctx(self.entry_heartbeat)

        self.btn_test_tg = ctk.CTkButton(
            tg_card, text="📨 Відправити тест", command=self._test_telegram,
            fg_color=COLORS["border_accent"], hover_color="#0d3d8a", text_color=COLORS["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=11), height=38, corner_radius=8
        )
        self.btn_test_tg.grid(row=3, column=0, padx=24, pady=(10, 20), sticky="w")

        # ─── 3. AI / GEMINI ───
        ai_card = GlowCard(self, accent="#a78bfa")
        ai_card.grid(row=2, column=0, padx=24, pady=12, sticky="ew")
        ai_card.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            ai_card, text="🤖  AI ДІАГНОСТИКА  ·  GOOGLE GEMINI",
            font=ctk.CTkFont(family="Consolas", size=13, weight="bold"),
            text_color="#a78bfa"
        ).grid(row=0, column=0, columnspan=2, padx=24, pady=(20, 8), sticky="w")

        ctk.CTkLabel(
            ai_card,
            text=("Безкоштовний AI-аналіз результатів діагностики мережі.\n"
                  "Отримай ключ на https://aistudio.google.com/apikey  →  Create API key"),
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"], justify="left"
        ).grid(row=1, column=0, columnspan=2, padx=24, pady=(0, 14), sticky="w")

        ctk.CTkLabel(
            ai_card, text="Gemini API Key:",
            font=ctk.CTkFont(family="Consolas", size=11),
            text_color=COLORS["text_secondary"]
        ).grid(row=2, column=0, padx=24, pady=5, sticky="w")

        # Завантажуємо існуючий ключ з config (показуємо masked)
        existing_key = self._load_gemini_key()
        self.entry_gemini = ctk.CTkEntry(
            ai_card, width=420,
            font=ctk.CTkFont(family="Consolas", size=11),
            fg_color=COLORS["bg_secondary"],
            border_color=COLORS["border"],
            text_color=COLORS["text_primary"],
            placeholder_text="AIzaSy...  (введи ключ і натисни Зберегти)",
            show="•"   # masked, як пароль
        )
        self.entry_gemini.grid(row=2, column=1, padx=24, pady=5, sticky="ew")
        if existing_key:
            self.entry_gemini.insert(0, existing_key)
        add_ctx(self.entry_gemini)

        # Toggle show/hide
        self._gemini_visible = False
        self.btn_show_gemini = ctk.CTkButton(
            ai_card, text="👁",
            command=self._toggle_gemini_visibility,
            fg_color="transparent", hover_color=COLORS["bg_card"],
            text_color=COLORS["text_dim"], width=36, height=28,
            font=ctk.CTkFont(family="Consolas", size=12),
            corner_radius=6
        )
        self.btn_show_gemini.grid(row=2, column=2, padx=(0, 10), pady=5)

        btn_row = ctk.CTkFrame(ai_card, fg_color="transparent")
        btn_row.grid(row=3, column=0, columnspan=3, padx=24,
                      pady=(10, 4), sticky="w")

        self.btn_save_gemini = ctk.CTkButton(
            btn_row, text="💾 Зберегти ключ", command=self._save_gemini_key,
            fg_color="#1a0d3a", hover_color="#2d1858",
            text_color="#a78bfa",
            font=ctk.CTkFont(family="Consolas", size=11),
            height=36, corner_radius=8,
            border_width=1, border_color="#6d28d9", width=160
        )
        self.btn_save_gemini.pack(side="left", padx=(0, 10))

        self.btn_test_gemini = ctk.CTkButton(
            btn_row, text="🧪 Тест з'єднання", command=self._test_gemini,
            fg_color=COLORS["border_accent"], hover_color="#0d3d8a",
            text_color=COLORS["accent_cyan"],
            font=ctk.CTkFont(family="Consolas", size=11),
            height=36, corner_radius=8, width=160
        )
        self.btn_test_gemini.pack(side="left", padx=(0, 10))

        self.lbl_gemini_status = ctk.CTkLabel(
            ai_card, text="",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"]
        )
        self.lbl_gemini_status.grid(row=4, column=0, columnspan=3,
                                      padx=24, pady=(4, 18), sticky="w")
        self._update_gemini_status()

        # ─── 3. КНОПКА ЗБЕРЕЖЕННЯ ───
        self.btn_save_settings = ctk.CTkButton(
            self, text="💾  ЗБЕРЕГТИ НАЛАШТУВАННЯ", command=self._save_settings,
            height=50, font=ctk.CTkFont(family="Consolas", size=14, weight="bold"),
            fg_color=COLORS["border_accent"], hover_color="#0d3d8a", text_color=COLORS["accent_cyan"],
            corner_radius=12, border_width=1, border_color=COLORS["accent_blue"]
        )
        self.btn_save_settings.grid(row=3, column=0, padx=24, pady=20, sticky="ew")

    def _auto_detect_ip(self):
        detected = NetworkScanner.get_default_gateway()
        self.entry_gateway.delete(0, "end")
        self.entry_gateway.insert(0, detected)

    def _test_telegram(self):
        chat_id = self.entry_tg_chat.get().strip()
        if not chat_id or not self.tg_token:
            self.btn_test_tg.configure(text="❌ Немає Chat ID або Токену", fg_color=COLORS["accent_red"])
            self.after(3000, lambda: self.btn_test_tg.configure(text="📨 Відправити тест", fg_color=COLORS["border_accent"]))
            return
            
        self.btn_test_tg.configure(text="⏳ Відправка...", state="disabled")
        def run():
            success, _ = TelegramAlerter.send_message(self.tg_token, chat_id, "📡 <b>NetGuardian AI v3.0:</b>\nТестовий звіт отримано! ✅")
            if success:
                self.after(0, lambda: self.btn_test_tg.configure(text="✅ Надіслано!", fg_color=COLORS["accent_green"], text_color="black", state="normal"))
            else:
                self.after(0, lambda: self.btn_test_tg.configure(text="❌ Помилка", fg_color=COLORS["accent_red"], state="normal"))
            self.after(3000, lambda: self.btn_test_tg.configure(text="📨 Відправити тест", fg_color=COLORS["border_accent"], text_color=COLORS["accent_cyan"]))
        threading.Thread(target=run, daemon=True).start()

    def _save_settings(self):
        new_ip = self.entry_gateway.get().strip()
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", new_ip):
            self.gateway_ip = new_ip
        else:
            self.btn_save_settings.configure(text="❌ Невірний формат IP", fg_color=COLORS["accent_red"])
            self.after(2000, lambda: self.btn_save_settings.configure(text="💾 ЗБЕРЕГТИ НАЛАШТУВАННЯ", fg_color=COLORS["border_accent"]))
            return

        self.tg_chat_id = self.entry_tg_chat.get().strip()
        self.heartbeat_url = self.entry_heartbeat.get().strip()

        try:
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump({"ip": self.gateway_ip, "chat_id": self.tg_chat_id, "heartbeat_url": self.heartbeat_url}, f, indent=4)
        except: pass

        self.btn_save_settings.configure(text="✅ ЗБЕРЕЖЕНО!", fg_color=COLORS["accent_green"], text_color="black")
        self.after(2500, lambda: self.btn_save_settings.configure(text="💾 ЗБЕРЕГТИ НАЛАШТУВАННЯ", fg_color=COLORS["border_accent"], text_color=COLORS["accent_cyan"]))
        
        # Сповіщаємо головний файл про зміни
        if self.on_save_callback:
            self.on_save_callback(self.gateway_ip, self.tg_chat_id, self.heartbeat_url)

    # ──────────────────────────────────────────────────────
    # GEMINI AI API
    # ──────────────────────────────────────────────────────

    def _load_gemini_key(self) -> str:
        """Зчитує ключ через GeminiClient (env або файл)."""
        try:
            from app.core.gemini_client import GeminiClient
            tmp = GeminiClient()
            return tmp.api_key or ""
        except Exception:
            return ""

    def _toggle_gemini_visibility(self):
        """Показати/сховати ключ як зірочки."""
        self._gemini_visible = not self._gemini_visible
        self.entry_gemini.configure(show="" if self._gemini_visible else "•")
        self.btn_show_gemini.configure(
            text="🙈" if self._gemini_visible else "👁")

    def _save_gemini_key(self):
        """Зберігає ключ у ~/.netguardian/ai_config.json."""
        key = self.entry_gemini.get().strip()
        if not key:
            self.lbl_gemini_status.configure(
                text="❌ Введи ключ", text_color=COLORS["accent_red"])
            return
        if not key.startswith("AIzaSy"):
            self.lbl_gemini_status.configure(
                text="⚠️ Ключ має починатися з 'AIzaSy'",
                text_color=COLORS["accent_yellow"])
            return
        try:
            from app.core.gemini_client import get_gemini_client, reset_gemini_client
            reset_gemini_client()        # скинути старий instance
            client = get_gemini_client() # створити новий
            ok = client.save_api_key(key)
            if ok:
                self.btn_save_gemini.configure(text="✅ Збережено")
                self.lbl_gemini_status.configure(
                    text="✅ Ключ збережено у ~/.netguardian/ai_config.json",
                    text_color=COLORS["accent_green"])
                self.after(2500, lambda: self.btn_save_gemini.configure(
                    text="💾 Зберегти ключ"))
            else:
                self.lbl_gemini_status.configure(
                    text=f"❌ Помилка: {client.get_last_error()[:80]}",
                    text_color=COLORS["accent_red"])
        except Exception as e:
            self.lbl_gemini_status.configure(
                text=f"❌ {str(e)[:80]}", text_color=COLORS["accent_red"])

    def _test_gemini(self):
        """Робить тестовий запит до Gemini API."""
        self.btn_test_gemini.configure(text="⏳ Тестую...", state="disabled")
        self.lbl_gemini_status.configure(
            text="Перевіряю з'єднання з Gemini...",
            text_color=COLORS["text_dim"])

        def run():
            try:
                from app.core.gemini_client import get_gemini_client, reset_gemini_client
                # Якщо в полі є щось — використовуємо його (ще не збережене)
                key = self.entry_gemini.get().strip()
                if key and key.startswith("AIzaSy"):
                    reset_gemini_client()
                    from app.core.gemini_client import GeminiClient
                    tmp = GeminiClient(api_key=key)
                    ok, msg = tmp.test_connection()
                else:
                    client = get_gemini_client()
                    ok, msg = client.test_connection()

                color = COLORS["accent_green"] if ok else COLORS["accent_red"]
                icon  = "✅" if ok else "❌"
                self.after(0, lambda m=msg, c=color, i=icon:
                    self.lbl_gemini_status.configure(
                        text=f"{i} {m}", text_color=c))
            except Exception as e:
                self.after(0, lambda err=str(e):
                    self.lbl_gemini_status.configure(
                        text=f"❌ {err[:80]}",
                        text_color=COLORS["accent_red"]))
            finally:
                self.after(0, lambda: self.btn_test_gemini.configure(
                    text="🧪 Тест з'єднання", state="normal"))

        threading.Thread(target=run, daemon=True).start()

    def _update_gemini_status(self):
        """Оновлює статусний рядок під полем ключа."""
        try:
            from app.core.gemini_client import get_gemini_client
            client = get_gemini_client()
            if client.is_available():
                self.lbl_gemini_status.configure(
                    text=f"✅ Готово (модель: {client.model_name})",
                    text_color=COLORS["accent_green"])
            elif client.api_key:
                err = client.get_last_error()
                if "google-generativeai" in err.lower() or "не встановлено" in err:
                    self.lbl_gemini_status.configure(
                        text=("⚠️ pip install google-generativeai — "
                              "не встановлено бібліотеку"),
                        text_color=COLORS["accent_yellow"])
                else:
                    self.lbl_gemini_status.configure(
                        text=f"⚠️ {err[:90]}",
                        text_color=COLORS["accent_yellow"])
            else:
                self.lbl_gemini_status.configure(
                    text="ℹ️ Введи ключ і натисни 'Зберегти' щоб увімкнути AI",
                    text_color=COLORS["text_dim"])
        except Exception as e:
            self.lbl_gemini_status.configure(
                text=f"⚠️ {str(e)[:80]}", text_color=COLORS["text_dim"])