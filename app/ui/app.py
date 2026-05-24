# gui/app.py
import customtkinter as ctk
import threading
import time
import os
import requests
import urllib3

from app.core.utils import NetworkScanner
from app.bot.bot import TelegramAlerter
from app.core.database import db
from features.dashboard.ui import get_dashboard_snapshot
from app.ui.theme import COLORS
from app.ui.components.widgets import SidebarButton

from features.dashboard.ui import DashboardPage
from features.diagnostics.ui import DiagnosticsPage
from features.wifi.ui import WifiAnalyzerPage
from features.dns.ui import DnsBenchmarkPage
from features.security.ui import SecurityAuditPage
from features.gamemode.ui import GameModePage
from features.forecast.ui import ForecastPage
from features.vpn.ui import AutoVpnPage
from features.settings.ui import SettingsPage

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


# ════════════════════════════════════════════════════════════════════
#  PI AGENT MQTT — глобальна конфігурація
# ════════════════════════════════════════════════════════════════════
# Має співпадати з MQTT_TOPIC_PREFIX на Raspberry Pi.
# Якщо змінив prefix у netguardian_agent.py на Pi — зміни і тут.
PI_AGENT_MQTT_PREFIX = os.environ.get(
    "NETGUARDIAN_MQTT_PREFIX", "netguardian/dim4ik2003")


class NetGuardianApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("NetGuardian AI - Enterprise Edition")
        self.geometry("1250x780")
        self.minsize(1050, 700)
        self.configure(fg_color=COLORS["bg_primary"])

        self.tg_token   = os.environ.get("TG_BOT_TOKEN", "")
        self.tg_chat_id = os.environ.get("TG_CHAT_ID", "")

        self.current_gateway_ip  = NetworkScanner.get_default_gateway()
        self.heartbeat_url       = ""

        self.is_monitoring       = True
        self.last_network_status = True
        self.offline_time        = None

        self.floating_widget  = None
        self.is_widget_active = False

        self._bot_instance   = None
        self._smart_agent    = None   # SmartAgent instance
        self.pi_subscriber   = None   # Raspberry Pi MQTT subscriber

        self._build_ui()
        self._load_config_from_settings()

        self.update_network_status()
        self.start_heartbeat_engine()

        self.after(2000, self._start_bot)
        self.after(3000, self._start_pi_subscriber)
        self.show_page("dashboard")

    def _safe_after(self, delay_ms: int, callback):
        """Безпечний self.after() — не падає якщо Tk-loop ще не готовий або
        вже знищений (Python 3.14 сувор до cross-thread tk-операцій)."""
        try:
            return self.after(delay_ms, callback)
        except RuntimeError:
            # Tk loop не активний — пропускаємо
            return None
        except Exception as e:
            print(f"[_safe_after] {type(e).__name__}: {e}")
            return None

    # ─── UI ───────────────────────────────────────────────────────────

    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(
            self, width=240, corner_radius=0,
            fg_color=COLORS["bg_secondary"],
            border_width=1, border_color=COLORS["border"])
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)
        self.sidebar.grid_rowconfigure(14, weight=1)

        logo_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        logo_frame.grid(row=0, column=0, padx=20, pady=(25, 30), sticky="w")
        ctk.CTkLabel(logo_frame, text="⬡",
                     font=("Consolas", 28),
                     text_color=COLORS["accent_cyan"]).pack(side="left", padx=(0, 10))
        title_col = ctk.CTkFrame(logo_frame, fg_color="transparent")
        title_col.pack(side="left")
        ctk.CTkLabel(title_col, text="NetGuardian",
                     font=ctk.CTkFont(family="Consolas", size=16, weight="bold"),
                     text_color=COLORS["text_primary"]).pack(anchor="w")
        ctk.CTkLabel(title_col, text="v3.2  AI EDITION",
                     font=ctk.CTkFont(family="Consolas", size=9),
                     text_color=COLORS["text_secondary"]).pack(anchor="w")

        nav_items = [
            ("dashboard",   "📊", "Дашборд"),
            ("diagnostics", "🧠", "AI Діагностика"),
            ("wifi",        "📡", "Wi-Fi Аналізатор"),
            ("dns",         "🔬", "DNS Benchmark"),
            ("security",    "🛡",  "LAN Аудит"),
            ("gamemode",    "🎮", "Ігровий Режим"),
            ("forecast",    "🌦",  "Погода Інтернету"),
            ("vpn",         "🔒", "Auto-VPN"),
            ("settings",    "⚙️",  "Налаштування"),
        ]

        self._nav_btns = {}
        for idx, (key, icon, label) in enumerate(nav_items):
            btn = SidebarButton(
                self.sidebar, icon=icon, label=label,
                command=lambda k=key: self.show_page(k))
            btn.grid(row=2 + idx, column=0, padx=12, pady=3, sticky="ew")
            self._nav_btns[key] = btn

        self.sidebar_status = ctk.CTkLabel(
            self.sidebar, text="● ІНІЦІАЛІЗУЮСЬ...",
            font=ctk.CTkFont(family="Consolas", size=10),
            text_color=COLORS["text_dim"])
        self.sidebar_status.grid(row=16, column=0, padx=20, pady=(0, 20), sticky="w")

        self.main_frame = ctk.CTkFrame(
            self, corner_radius=0, fg_color=COLORS["bg_primary"])
        self.main_frame.grid(row=0, column=1, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)

        self.header_bar = ctk.CTkFrame(
            self.main_frame, height=64, corner_radius=0,
            fg_color=COLORS["bg_secondary"],
            border_width=1, border_color=COLORS["border"])
        self.header_bar.grid(row=0, column=0, sticky="ew")
        self.header_bar.grid_propagate(False)

        self.page_title_lbl = ctk.CTkLabel(
            self.header_bar, text="",
            font=ctk.CTkFont(family="Consolas", size=18, weight="bold"),
            text_color=COLORS["text_primary"])
        self.page_title_lbl.grid(row=0, column=0, padx=30, pady=15, sticky="w")

        self.content = ctk.CTkFrame(
            self.main_frame, fg_color=COLORS["bg_primary"], corner_radius=0)
        self.content.grid(row=1, column=0, sticky="nsew")
        self.content.grid_columnconfigure(0, weight=1)
        self.content.grid_rowconfigure(0, weight=1)

        self._init_pages()

    def _init_pages(self):
        self.pages = {
            "dashboard":   DashboardPage(self.content,
                                         toggle_widget_callback=self.toggle_widget),
            "diagnostics": DiagnosticsPage(self.content,
                                           get_gateway_cb=lambda: self.current_gateway_ip),
            "wifi":        WifiAnalyzerPage(self.content,
                                            get_gateway_cb=lambda: self.current_gateway_ip),
            "dns":         DnsBenchmarkPage(self.content),
            "security":    SecurityAuditPage(self.content,
                                             get_gateway_cb=lambda: self.current_gateway_ip),
            "gamemode":    GameModePage(self.content),
            "forecast":    ForecastPage(self.content),
            "vpn":         AutoVpnPage(self.content),
            "settings":    SettingsPage(self.content,
                                        on_save_callback=self._on_settings_saved),
        }

    PAGE_TITLES = {
        "dashboard":   "📊 Головна панель",
        "diagnostics": "🧠 AI Діагностика (OSI L4)",
        "wifi":        "📡 Wi-Fi Channel Analyzer",
        "dns":         "🔬 DNS Benchmark",
        "security":    "🛡 LAN Security Audit",
        "gamemode":    "🎮 Game Latency Optimizer",
        "forecast":    "🌦 AI Connectivity Forecast",
        "vpn":         "🔒 Auto-VPN · Auto-Secure",
        "settings":    "⚙️ Налаштування Системи",
    }

    def show_page(self, key: str):
        for frame in self.pages.values():
            frame.grid_forget()
        for btn_key, btn in self._nav_btns.items():
            btn.set_active(btn_key == key)
        self.page_title_lbl.configure(text=self.PAGE_TITLES.get(key, ""))
        self.pages[key].grid(row=0, column=0, sticky="nsew")

    # ─── КОНФІГ ───────────────────────────────────────────────────────

    def _load_config_from_settings(self):
        gw = getattr(self.pages["settings"], "gateway_ip",    None)
        ci = getattr(self.pages["settings"], "tg_chat_id",    None)
        hu = getattr(self.pages["settings"], "heartbeat_url", None)
        tk = getattr(self.pages["settings"], "tg_token",      None)

        if gw: self.current_gateway_ip = gw
        if ci: self.tg_chat_id         = ci
        if hu: self.heartbeat_url      = hu
        if tk: self.tg_token           = tk

    def _on_settings_saved(self, gw: str, chat_id: str, hb_url: str):
        if gw:      self.current_gateway_ip = gw
        if chat_id: self.tg_chat_id         = chat_id
        if hb_url:  self.heartbeat_url      = hb_url
        self._start_bot()

    # ─── PI AGENT MQTT SUBSCRIBER ────────────────────────────────────

    def _start_pi_subscriber(self):
        """Запускає MQTT subscriber для отримання даних з Raspberry Pi.

        Дані Pi-агента (ping/speedtest/lan/heartbeat) надходять у real-time
        через broker.hivemq.com і кешуються у локальній БД
        ~/.netguardian/pi_agent_cache.db. Forecast page потім може
        використовувати ці дані замість локальних замірів ноута —
        це дає 24/7 моніторинг навіть коли ПК вимкнений.
        """
        try:
            from features.forecast.mqtt_subscriber import RemoteAgentSubscriber
        except ImportError as e:
            print(f"[App] ⚠️ Pi subscriber: модуль не знайдено — {e}")
            print(f"[App]   Встанови: pip install paho-mqtt")
            print(f"[App]   Поклади mqtt_subscriber.py у features/forecast/")
            return

        try:
            self.pi_subscriber = RemoteAgentSubscriber(
                prefix=PI_AGENT_MQTT_PREFIX,
                on_data=self._on_pi_data,
            )
            ok = self.pi_subscriber.start()
            if ok:
                print(f"[App] ✅ Pi MQTT subscriber: prefix={PI_AGENT_MQTT_PREFIX}")
            else:
                print(f"[App] ⚠️ Pi subscriber start() повернув False — paho-mqtt?")
        except Exception as e:
            print(f"[App] ⚠️ Pi subscriber init failed: {e}")
            self.pi_subscriber = None

    def _on_pi_data(self, kind: str, data: dict):
        """Callback що викликається при отриманні даних з Pi-агента.

        kind: 'ping' / 'speedtest' / 'lan' / 'heartbeat'
        data: dict з самим payload'ом
        """
        # Логуємо тільки важливі події щоб не спамити консоль
        if kind == "speedtest":
            print(f"[Pi] 📊 Speedtest: DL={data.get('dl_mbps')} "
                  f"UL={data.get('ul_mbps')} Mbps")
        elif kind == "lan":
            cnt = data.get("count", 0)
            if cnt > 0:
                print(f"[Pi] 📶 LAN scan: {cnt} пристроїв")
        # ping/heartbeat — мовчазні (надто часто)

    def is_pi_online(self) -> bool:
        """Перевіряє чи Pi надсилав heartbeat останні 90с."""
        if self.pi_subscriber is None:
            return False
        try:
            return self.pi_subscriber.is_pi_online()
        except Exception:
            return False

    def get_pi_subscriber(self):
        """Повертає Pi MQTT subscriber (для використання в інших сторінках)."""
        return self.pi_subscriber

    # ─── SPEEDTEST ДЛЯ БОТА ───────────────────────────────────────────

    def _run_speedtest_for_bot(self) -> tuple:
        """Запускає speedtest напряму (не через GUI) і повертає (dl, ul).

        ВАЖЛИВО: раніше це викликало self.pages['dashboard']._run_speedtest()
        через self.after(0, ...), але:
          1) Якщо _speedtest_running=True (залишкове з GUI) — callback не викличеться
          2) self.after(0) залежить від main-loop — якщо GUI зайнятий, пропускається
          3) GUI-версія оновлює labels — для бота це зайве

        Тепер — прямий виклик _speedtest_worker в потоці, без UI.
        """
        # 0. Спочатку пробуємо результати Pi-агента (найсвіжіші, з 24/7 джерела)
        if self.pi_subscriber is not None:
            try:
                pi_st = self.pi_subscriber.get_latest_speedtest()
                if pi_st:
                    # Перевіряємо що дані не старіші 70 хвилин
                    from datetime import datetime
                    ts_str = pi_st.get("ts", "")
                    if ts_str:
                        try:
                            ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                            age_min = (datetime.now() - ts).total_seconds() / 60
                            if age_min < 70:
                                print(f"[App] speedtest_for_bot → Pi cache "
                                      f"({pi_st['dl_mbps']:.1f}/"
                                      f"{pi_st['ul_mbps']:.1f} Mbps, "
                                      f"age={age_min:.0f}хв)")
                                return pi_st["dl_mbps"], pi_st["ul_mbps"]
                        except Exception:
                            pass
            except Exception as e:
                print(f"[App] Pi speedtest cache check error: {e}")

        # 1. Локальний cached результат
        try:
            from features.dashboard.ui import _DASHBOARD_STATE
            dl_cached = _DASHBOARD_STATE.get("dl_mbps")
            ul_cached = _DASHBOARD_STATE.get("ul_mbps")
            ts_cached = _DASHBOARD_STATE.get("speedtest_ts", 0)
            age = time.time() - ts_cached if ts_cached else 999

            # Повертаємо cache тільки якщо результат валідний (не нульовий)
            if age < 60 and dl_cached and dl_cached > 1.0 and ul_cached and ul_cached > 0.1:
                print(f"[App] speedtest_for_bot → cache hit "
                      f"({dl_cached:.1f}/{ul_cached:.1f} Mbps, age={age:.0f}с)")
                return dl_cached, ul_cached
        except Exception as e:
            print(f"[App] cache check error: {e}")

        # 2. Прямий виклик worker'а
        try:
            from features.dashboard.ui import _speedtest_worker, _DASHBOARD_STATE
            event  = threading.Event()
            result = {"dl": 0.0, "ul": 0.0}

            def on_progress(direction, mbps, samples):
                # Не спамимо в консоль — worker сам логує
                pass

            def on_done(dl, ul):
                result["dl"] = dl or 0.0
                result["ul"] = ul or 0.0
                # Оновлюємо snapshot щоб наступний виклик пішов з кешу
                if dl and dl > 0:
                    _DASHBOARD_STATE["dl_mbps"] = dl
                if ul and ul > 0:
                    _DASHBOARD_STATE["ul_mbps"] = ul
                if dl and ul:
                    _DASHBOARD_STATE["speedtest_ts"] = time.time()
                event.set()

            # Тривалість тесту — 10 сек
            duration = 10
            t = threading.Thread(
                target=_speedtest_worker,
                args=(on_progress, on_done, duration),
                daemon=True)
            t.start()

            # Максимум 60 сек (probe + DL + UL + fallback)
            event.wait(timeout=duration * 4 + 20)
            return result["dl"], result["ul"]
        except Exception as e:
            print(f"[App] speedtest_for_bot error: {e}")
            import traceback; traceback.print_exc()
            return 0.0, 0.0

    # ─── Wi-Fi СКАН ДЛЯ БОТА ─────────────────────────────────────────

    def _run_wifi_scan_for_bot(self) -> tuple:
        wifi_page = self.pages.get("wifi")

        if (wifi_page is not None
                and getattr(wifi_page, "_has_data", False)
                and getattr(wifi_page, "_networks", None)
                and getattr(wifi_page, "_rating",   None)):
            print("[App] wifi_scan_for_bot → використовую кеш GUI")
            return wifi_page._networks, wifi_page._rating

        print("[App] wifi_scan_for_bot → запускаю WifiEngine напряму")
        try:
            from features.wifi.engine import WifiEngine
            engine   = WifiEngine()
            networks = engine.scan_networks()
            rating   = engine.get_channel_rating(networks)

            if wifi_page is not None:
                self.after(0, lambda: self._apply_wifi_to_page(
                    wifi_page, networks, rating))

            return networks, rating
        except Exception as e:
            print(f"[App] wifi_scan_for_bot error: {e}")
            return [], {}

    def _apply_wifi_to_page(self, page, networks, rating):
        try:
            page._networks  = networks
            page._rating    = rating
            page._has_data  = True
            page._build_net_table(networks)
            page._highlight_ch_btns()
            page._safe_redraw()
        except Exception as e:
            print(f"[App] _apply_wifi_to_page error: {e}")

    # ─── АВТО-ПЕРЕВІРКА Wi-Fi КОЖНІ 30 ХВ ────────────────────────────

    def _start_wifi_monitor(self):
        def loop():
            time.sleep(300)
            while self.is_monitoring:
                try:
                    networks, rating = self._run_wifi_scan_for_bot()
                    if (networks
                            and self._bot_instance is not None
                            and rating.get("worth_switching")):
                        self._bot_instance.notify_wifi_interference(
                            networks=networks, rating=rating)
                except Exception as e:
                    print(f"[WifiMonitor] error: {e}")
                time.sleep(1800)

        threading.Thread(target=loop, daemon=True, name="WifiMonitor").start()
        print("[WifiMonitor] ✅ Запущено (перевірка кожні 30 хв)")

    # ─── МОНІТОРИНГ МЕРЕЖІ ────────────────────────────────────────────

    def update_network_status(self):
        if not self.is_monitoring:
            return

        def task():
            ms             = NetworkScanner.check_ping()
            current_status = ms >= 0

            if current_status != self.last_network_status:
                if not current_status:
                    self.offline_time = time.time()
                elif self.tg_chat_id and self.tg_token:
                    dt = int(time.time() - self.offline_time) if self.offline_time else 0
                    self.offline_time = None
                    TelegramAlerter.send_message(
                        self.tg_token, self.tg_chat_id,
                        f"🟢 <b>ЗВ'ЯЗОК ВІДНОВЛЕНО!</b>\n"
                        f"⏱️ Простою: {dt} сек.\n📡 Пінг: {ms} ms")
                self.last_network_status = current_status

            if ms >= 0:
                db.add_ping_record(ms)

            def update_ui():
                if 0 <= ms < 50:
                    color = COLORS["accent_green"]
                elif 50 <= ms < 150:
                    color = COLORS["accent_yellow"]
                else:
                    color = COLORS["accent_red"]

                status_txt = "СТАТУС: ОНЛАЙН" if ms >= 0 else "ОФЛАЙН"
                ping_info  = f"· {ms} ms" if ms >= 0 else ""

                self.sidebar_status.configure(
                    text=f"● {status_txt} {ping_info}",
                    text_color=color)
                self.pages["dashboard"].update_ping(ms, status_txt, color)
                self._update_float_widget(ms, color)

            self._safe_after(0, update_ui)

        threading.Thread(target=task, daemon=True).start()
        self._safe_after(2000, self.update_network_status)

    # ─── HEARTBEAT ────────────────────────────────────────────────────

    def start_heartbeat_engine(self):
        def task():
            while self.is_monitoring:
                if self.heartbeat_url and self.heartbeat_url.startswith("http"):
                    try:
                        requests.get(self.heartbeat_url, timeout=5, verify=False)
                    except Exception:
                        pass
                time.sleep(10)
        threading.Thread(target=task, daemon=True).start()

    # ─── TELEGRAM БОТ ─────────────────────────────────────────────────

    def _start_bot(self):
        token   = self.tg_token.strip()
        chat_id = self.tg_chat_id.strip()

        if not token:
            print("[BOT] ❌ TG_BOT_TOKEN не вказано (.env або Налаштування)")
            return
        if not chat_id:
            print("[BOT] ❌ TG_CHAT_ID не вказано (.env або Налаштування)")
            return

        print(f"[BOT] ✅ Старт  токен={token[:10]}***  chat_id={chat_id}")

        # ── Функція діагностики для бота ──────────────────────────────
        from features.diagnostics.engine import DiagnosticEngine
        _diag_engine = DiagnosticEngine()

        def diagnose_fn():
            return _diag_engine.run_full_diagnostics(
                gateway_ip=self.current_gateway_ip)

        # ── Smart Agent з підтримкою Tapo та авто-сповіщень ───────────
        from app.core.smart_agent import SmartAgent

        def _tg_send(txt: str):
            TelegramAlerter.send_message(token, chat_id, txt)

        # Якщо агент вже запущений — зупиняємо (перезапуск після зміни налаштувань)
        if self._smart_agent is not None:
            try:
                self._smart_agent.stop()
            except Exception:
                pass

        agent = SmartAgent(
            telegram_send_fn = _tg_send,
            get_snapshot_fn  = get_dashboard_snapshot,
            diagnose_fn      = diagnose_fn,
        )
        agent.start()
        self._smart_agent = agent

        # ── Хендлери для сумісності ────────────────────────────────────
        handlers = {
            "/heal": lambda t, c, s=None: TelegramAlerter.send_message(
                t, c, NetworkScanner.flush_dns()),
        }

        # Створюємо єдині instance'и engines, які ДІЛЯТЬСЯ між GUI і ботом.
        # Це критично: якщо бот створить окремий instance — вони
        # не знатимуть про дії один одного.
        shared_game_engine = None
        shared_lan_engine  = None
        shared_vpn_engine  = None
        try:
            from features.gamemode.engine import GameBoosterEngine
            shared_game_engine = GameBoosterEngine()
        except Exception as e:
            print(f"[BOT] ⚠️ GameBoosterEngine init failed: {e}")
        try:
            from features.security.lan_security import LanSecurityEngine
            shared_lan_engine = LanSecurityEngine()
        except Exception as e:
            print(f"[BOT] ⚠️ LanSecurityEngine init failed: {e}")
        try:
            from features.vpn.engine import VpnManagerEngine
            shared_vpn_engine = VpnManagerEngine()
            # Ділимось VPN engine з GUI-вкладкою VPN — щоб бот і UI мали
            # ті самі імпортовані профілі і той самий стан підключення
            try:
                if "vpn" in self.pages and hasattr(self.pages["vpn"], "engine"):
                    gui_vpn_engine = self.pages["vpn"].engine
                    if gui_vpn_engine.profiles:
                        shared_vpn_engine.profiles = gui_vpn_engine.profiles
                    self.pages["vpn"].engine = shared_vpn_engine
            except Exception: pass
        except Exception as e:
            print(f"[BOT] ⚠️ VpnManagerEngine init failed: {e}")

        self._bot_instance = TelegramAlerter.start_polling(
            token            = token,
            allowed_chat_id  = chat_id,
            handlers         = handlers,
            snapshot_fn      = get_dashboard_snapshot,
            speedtest_fn     = self._run_speedtest_for_bot,
            diagnose_fn      = diagnose_fn,
            smart_agent      = agent,
            wifi_scan_fn     = self._run_wifi_scan_for_bot,
            wifi_gateway_fn  = lambda: self.current_gateway_ip,
            game_engine      = shared_game_engine,
            lan_engine       = shared_lan_engine,
            vpn_engine       = shared_vpn_engine,
        )
        print("[BOT] ✅ Polling запущено. Smart Agent активний.")

        # ── Підключаємо LAN Security → Telegram сповіщення ──
        # Коли сканер виявляє новий пристрій / небезпечний —
        # бот автоматично надсилає сповіщення у Telegram.
        try:
            lan_eng = shared_lan_engine   # те саме instance що в боті
            if not lan_eng:
                from features.security.lan_security import LanSecurityEngine
                lan_eng = LanSecurityEngine()

            def _notify_new_device(device):
                """Callback для нових пристроїв."""
                try:
                    from features.security.lan_monitor import get_device_display_name
                    name = get_device_display_name(device)
                    mac  = device.get("mac","—")
                    ip   = device.get("ip","—")
                    vendor = device.get("vendor","")
                    threat = device.get("threat","safe")

                    # FIX: додаємо пристрій у бот _lan_last_scan ОДРАЗУ —
                    # щоб /block /details /deep відразу працювали
                    # без вимоги робити спочатку /lan scan
                    try:
                        if self._bot_instance and hasattr(self._bot_instance, "_lan_last_scan"):
                            existing_scan = self._bot_instance._lan_last_scan or []
                            # Видаляємо старий запис з тим же MAC якщо є
                            existing_scan = [d for d in existing_scan
                                             if d.get("mac","").upper() != mac.upper()]
                            existing_scan.append(device)
                            self._bot_instance._lan_last_scan = existing_scan
                            # Приєднуємо LanSecurity engine якщо ще немає
                            if not getattr(self._bot_instance, "_lan_engine", None):
                                self._bot_instance._lan_engine = lan_eng
                            print(f"[BOT] Додано в _lan_last_scan: {mac} "
                                  f"(всього: {len(existing_scan)})")
                    except Exception as e:
                        print(f"[BOT] sync last_scan error: {e}")

                    threat_icon = {
                        "critical":"🔴 КРИТИЧНИЙ",
                        "danger":  "🔴 НЕБЕЗПЕЧНИЙ",
                        "warn":    "🟡 ПІДОЗРІЛИЙ",
                        "safe":    "🟢 БЕЗПЕЧНИЙ",
                    }.get(threat, "⚪ НЕВІДОМИЙ")

                    msg = (
                        f"🆕 *НОВИЙ ПРИСТРІЙ У МЕРЕЖІ*\n"
                        f"━━━━━━━━━━━━━━━━━━━\n\n"
                        f"📱 *{name}*\n"
                        f"🌐 IP:  `{ip}`\n"
                        f"🏷️ MAC: `{mac}`\n"
                        f"🏢 Vendor: {vendor or '—'}\n"
                        f"🎯 Статус: {threat_icon}\n"
                    )

                    # Показуємо відкриті порти якщо небезпечні
                    ports = device.get("open_ports", [])
                    if ports:
                        dangerous = [p for p in ports if p in (21,22,23,135,139,445,3389,5900)]
                        if dangerous:
                            msg += f"\n⚠️ *Небезпечні порти:* `{', '.join(map(str, dangerous[:5]))}`\n"

                    msg += (
                        f"\n*Що робити:*\n"
                        f"• `/details {mac}` — деталі\n"
                        f"• `/trust {mac}` — довіряти\n"
                        f"• `/block {mac}` — заблокувати\n"
                        f"• `/deep {ip}` — глибока ідентифікація\n"
                    )

                    if self._bot_instance and hasattr(self._bot_instance, "send_notification"):
                        self._bot_instance.send_notification(msg)
                    elif self._bot_instance and hasattr(self._bot_instance, "_api"):
                        self._bot_instance._api.send(str(chat_id), msg)
                except Exception as e:
                    print(f"[BOT] notify_new_device error: {e}")

            def _notify_suspicious(device):
                """Callback для небезпечних пристроїв."""
                try:
                    from features.security.lan_monitor import get_device_display_name
                    name = get_device_display_name(device)
                    mac  = device.get("mac","—")
                    ip   = device.get("ip","—")
                    ports = device.get("open_ports", [])
                    threat = device.get("threat","warn")
                    icon = "🔴" if threat == "critical" else "⚠️"

                    msg = (
                        f"{icon} *ПІДОЗРІЛИЙ ПРИСТРІЙ*\n"
                        f"━━━━━━━━━━━━━━━━━━━\n\n"
                        f"📱 *{name}*\n"
                        f"🌐 IP:  `{ip}`\n"
                        f"🏷️ MAC: `{mac}`\n"
                    )
                    if ports:
                        msg += f"🔌 Порти: `{', '.join(map(str, ports[:6]))}`\n"
                    msg += (
                        f"\n*Дії:*\n"
                        f"• `/ports {ip}` — повний скан портів\n"
                        f"• `/block {mac}` — заблокувати"
                    )

                    if self._bot_instance and hasattr(self._bot_instance, "send_notification"):
                        self._bot_instance.send_notification(msg)
                    elif self._bot_instance and hasattr(self._bot_instance, "_api"):
                        self._bot_instance._api.send(str(chat_id), msg)
                except Exception as e:
                    print(f"[BOT] notify_suspicious error: {e}")

            lan_eng.on_new_device(_notify_new_device)
            lan_eng.on_suspicious(_notify_suspicious) if hasattr(lan_eng, "on_suspicious") else None
            print("[BOT] ✅ LAN Security hooked → нові пристрої будуть надіслані у Telegram")
        except Exception as e:
            print(f"[BOT] ⚠️ Не вдалось підключити LAN hooks: {e}")

        # ── Підключаємо Game Mode state-change → Telegram сповіщення ──
        try:
            if shared_game_engine and hasattr(shared_game_engine, "on_mode_change"):
                def _notify_game_mode(new_state: bool, source: str):
                    """Надсилає сповіщення про зміну Game Mode."""
                    try:
                        source_label = {
                            "gui": "утиліта (GUI)",
                            "bot": "Telegram бот",
                            "auto": "авто-режим",
                        }.get(source, source)

                        if new_state:
                            msg = (
                                f"🚀 *GAME MODE УВІМКНЕНО*\n"
                                f"━━━━━━━━━━━━━━━━━━━\n\n"
                                f"📌 Джерело: _{source_label}_\n\n"
                                f"✅ Активовано оптимізації:\n"
                                f"  • Registry tweaks (MMCSS, GPU Priority)\n"
                                f"  • Nagle's Algorithm OFF\n"
                                f"  • High Performance Power Plan\n"
                                f"  • CPU Core Unpark\n"
                                f"  • DNS Cache flush\n"
                                f"  • QoS DSCP 46 для 130 ігор\n\n"
                                f"💡 `/game verify` — перевірити стан\n"
                                f"⏹ `/game off` — вимкнути"
                            )
                        else:
                            msg = (
                                f"⏹ *GAME MODE ВИМКНЕНО*\n"
                                f"━━━━━━━━━━━━━━━━━━━\n\n"
                                f"📌 Джерело: _{source_label}_\n\n"
                                f"✅ Всі оптимізації відкотилось\n"
                                f"до стандартних Windows налаштувань.\n\n"
                                f"🚀 `/game on` — увімкнути знов"
                            )

                        if self._bot_instance and hasattr(self._bot_instance, "send_notification"):
                            self._bot_instance.send_notification(msg)
                        elif self._bot_instance and hasattr(self._bot_instance, "_api"):
                            self._bot_instance._api.send(str(chat_id), msg)
                    except Exception as e:
                        print(f"[BOT] notify_game_mode error: {e}")

                shared_game_engine.on_mode_change(_notify_game_mode)
                print("[BOT] ✅ Game Mode hooked → зміни стану будуть надіслані у Telegram")
        except Exception as e:
            print(f"[BOT] ⚠️ Не вдалось підключити Game Mode hooks: {e}")

        # Запускаємо фоновий моніторинг Wi-Fi
        self._start_wifi_monitor()

    def setup_bot_commands(self):
        self._start_bot()

    # ─── FLOATING WIDGET ──────────────────────────────────────────────

    def toggle_widget(self):
        if self.is_widget_active:
            self._destroy_float_widget()
        else:
            self._create_float_widget()

    def _create_float_widget(self):
        from app.ui.components.floating_widget import FloatingWidget
        self.floating_widget = FloatingWidget()
        self.floating_widget.on_close_callback = self._on_widget_closed
        self.is_widget_active = True
        self.pages["dashboard"].set_widget_button_state(True)

    def _destroy_float_widget(self):
        self.is_widget_active = False
        if self.floating_widget:
            try:
                if self.floating_widget.winfo_exists():
                    self.floating_widget.destroy()
            except Exception:
                pass
        self.floating_widget = None
        self.pages["dashboard"].set_widget_button_state(False)

    def _on_widget_closed(self):
        self.is_widget_active = False
        self.floating_widget  = None
        self.pages["dashboard"].set_widget_button_state(False)

    def _update_float_widget(self, ms: int, color: str):
        if not self.is_widget_active or not self.floating_widget:
            return
        try:
            if self.floating_widget.winfo_exists():
                self.floating_widget.update_ping(ms, color)
        except Exception:
            pass