"""
hybrid_ai.py
─────────────
Гібридний AI клієнт для NetGuardian.

СТРАТЕГІЯ:
    1. Спочатку пробує Gemini AI (якщо є інтернет + ключ)
    2. Якщо Gemini не вдається (offline/quota/error):
        → автоматично падає на KnowledgeBase fallback
    3. KB fallback використовує:
        - Поточний snapshot мережі (для контексту)
        - Rule-engine результати (для розуміння проблеми)
        - search_kb() — для пошуку релевантних рішень
    4. Завжди повертає поле 'source': "gemini" або "knowledge_base"

PR #25 v2: ВИПРАВЛЕНО — gather_full_context() тепер знаходить
екземпляр NetGuardianApp через gc.get_objects() (атрибути живуть
ВСЕРЕДИНІ класу, не на module-level), і вбудовує повний контекст
ПРЯМО у текст запитання до Gemini — тому AI ТОЧНО його бачить.

UI може показувати індикатор:
    🌐 Gemini AI — коли source="gemini"
    📦 Локальна база — коли source="knowledge_base"
    ❌ — коли і те і те не вдалось
"""

from __future__ import annotations
import time
import socket
import gc
from typing import Optional, Any


# ══════════════════════════════════════════════════════════════════════
#  ПЕРЕВІРКА ДОСТУПНОСТІ ІНТЕРНЕТУ
# ══════════════════════════════════════════════════════════════════════

_INTERNET_CACHE = {"is_online": None, "checked_at": 0}
_CACHE_TTL = 15  # секунд


def is_internet_available() -> bool:
    """PR #27 fix: Швидка перевірка наявності інтернету.

    БУЛО: робив raw TCP-handshake до 1.1.1.1:443. Це часто блокується
    Windows Firewall, корпоративними проксі, або VPN-маршрутами —
    видавав хибне False навіть коли інтернет цілком робочий.

    СТАЛО: спочатку швидкий DNS lookup (працює навіть з обмеженим
    фаєрволом), потім TCP до DNS-портів 53 (рідко блокуються).
    Кешування скорочено до 5 секунд щоб false-negative не залипав.

    КЕШ: позитивний результат кешується на 30 секунд, негативний — на 5с,
    щоб швидко відновлюватись коли інтернет повернувся.
    """
    now = time.time()
    cached = _INTERNET_CACHE["is_online"]
    age = now - _INTERNET_CACHE["checked_at"]
    # Позитив кешуємо довше, негатив — коротше
    ttl = 30 if cached else 5
    if cached is not None and age < ttl:
        return cached

    is_online = False

    # ── Спроба 1: DNS lookup (найшвидше, найменше блокується) ──
    try:
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(2.0)
        try:
            socket.gethostbyname("cloudflare.com")
            is_online = True
        finally:
            socket.setdefaulttimeout(old_to)
    except Exception:
        pass

    # ── Спроба 2: TCP до DNS-порту (53 рідко блокується) ──
    if not is_online:
        for host, port in [("1.1.1.1", 53), ("8.8.8.8", 53), ("9.9.9.9", 53)]:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2.0)
                rc = s.connect_ex((host, port))
                s.close()
                if rc == 0:
                    is_online = True
                    break
            except Exception:
                pass

    _INTERNET_CACHE["is_online"] = is_online
    _INTERNET_CACHE["checked_at"] = now
    if not is_online:
        print(f"[hybrid_ai] ⚠️ is_internet_available=False "
              f"(перевірив DNS lookup та TCP:53 — не пройшло)")
    return is_online


def reset_internet_cache():
    """Скидає кеш доступності — корисно коли користувач натискає Refresh."""
    _INTERNET_CACHE["is_online"] = None
    _INTERNET_CACHE["checked_at"] = 0


# ══════════════════════════════════════════════════════════════════════
#  PR #25 v2: ПОШУК ІНСТАНСА NetGuardianApp ЧЕРЕЗ gc
# ══════════════════════════════════════════════════════════════════════
# Атрибути живуть всередині класу: app.pages["vpn"], app._smart_agent,
# app.pi_subscriber. Module-level доступу немає. Тому шукаємо інстанс
# через gc.get_objects() і кешуємо на сесію.

_APP_INSTANCE: Optional[Any] = None


def _find_app_instance() -> Optional[Any]:
    """Знаходить екземпляр NetGuardianApp через gc.get_objects()
    та кешує його. Повертає None якщо ще не створений."""
    global _APP_INSTANCE

    # Перевіряємо кеш
    if _APP_INSTANCE is not None:
        try:
            # Перевірка що інстанс ще живий і має очікувані атрибути
            _ = _APP_INSTANCE.pages
            return _APP_INSTANCE
        except (ReferenceError, AttributeError, Exception):
            _APP_INSTANCE = None

    # Шукаємо через gc
    try:
        for obj in gc.get_objects():
            try:
                cls_name = obj.__class__.__name__
                if cls_name == "NetGuardianApp":
                    # Подвійна перевірка — є потрібні атрибути
                    if (hasattr(obj, "pages")
                            and isinstance(getattr(obj, "pages", None), dict)
                            and "vpn" in obj.pages):
                        _APP_INSTANCE = obj
                        print(f"[hybrid_ai] ✅ Знайдено NetGuardianApp "
                              f"({len(obj.pages)} pages)")
                        return obj
            except (ReferenceError, AttributeError):
                continue
            except Exception:
                continue
    except Exception as e:
        print(f"[hybrid_ai] _find_app_instance gc walk failed: {e}")

    return None


def _safe_get(obj, *attrs, default=None):
    """Безпечне отримання вкладеного атрибута: _safe_get(app, 'pages', 'vpn')."""
    try:
        for attr in attrs:
            if obj is None: return default
            if isinstance(obj, dict):
                obj = obj.get(attr, default)
            else:
                obj = getattr(obj, attr, default)
            if obj is None and attr != attrs[-1]:
                return default
        return obj
    except Exception:
        return default


# ══════════════════════════════════════════════════════════════════════
#  ПОВНИЙ КОНТЕКСТ УТИЛІТИ ДЛЯ AI
# ══════════════════════════════════════════════════════════════════════

_CONTEXT_CACHE = {"data": None, "ts": 0}
_CONTEXT_TTL = 5  # секунд


def gather_full_context() -> dict:
    """PR #25 v2: Збирає СТАН ВСІХ МОДУЛІВ утиліти для AI.

    Знаходить інстанс NetGuardianApp через gc та збирає:
      • Snapshot мережі (ping, jitter, loss, public_ip, ISP)
      • VPN-стан (app.pages["vpn"]._ext_vpn_state)
      • Forecast (тижнева статистика)
      • Pi-agent (app.pi_subscriber)
      • LAN-пристрої (app.pages["security"]._devices якщо є)
      • Tapo (app._smart_agent.tapo.get_stats())
      • Останню діагностику (app.pages["diagnostics"]._last_ai_data)
      • Загальну інфу (gateway IP, current network status)

    Кешується на 5 секунд.
    """
    now = time.time()
    if (_CONTEXT_CACHE["data"] is not None
            and now - _CONTEXT_CACHE["ts"] < _CONTEXT_TTL):
        return _CONTEXT_CACHE["data"]

    ctx = {}
    app = _find_app_instance()

    # ── 1. SNAPSHOT мережі ────────────────────────────────────────────
    try:
        from features.dashboard.ui import get_dashboard_snapshot
        snap = get_dashboard_snapshot() or {}
        ctx["snapshot"] = snap
    except Exception as e:
        print(f"[gather_full_context] snapshot: {e}")
        ctx["snapshot"] = {}

    # Доповнюємо snapshot з gemini_client.gather_network_context (там
    # додатково public_ip, ISP, geo)
    try:
        from app.core.gemini_client import gather_network_context
        gn = gather_network_context()
        if isinstance(gn, dict):
            # Якщо gn повертає {"snapshot": {...}} — мерджимо
            extra = gn.get("snapshot", gn)
            for k, v in extra.items():
                if k not in ctx["snapshot"] or not ctx["snapshot"].get(k):
                    ctx["snapshot"][k] = v
    except Exception as e:
        print(f"[gather_full_context] gemini_ctx: {e}")

    if app is None:
        # Без app instance — все, що можемо віддати, це snapshot
        ctx["_app_found"] = False
        _CONTEXT_CACHE["data"] = ctx
        _CONTEXT_CACHE["ts"]   = now
        return ctx

    ctx["_app_found"] = True

    # ── 2. VPN-стан ───────────────────────────────────────────────────
    try:
        vpn_page = _safe_get(app, "pages", "vpn")
        if vpn_page is not None:
            ext = _safe_get(vpn_page, "_ext_vpn_state")
            if isinstance(ext, dict):
                ctx["vpn"] = {
                    "active":  ext.get("active", False),
                    "ip":      ext.get("ip", "—"),
                    "country": ext.get("country", "—"),
                    "city":    ext.get("city", "—"),
                    "isp":     ext.get("isp", "—"),
                    "provider": ext.get("provider", ""),
                }
            else:
                # Спробуємо альтернативні атрибути
                engine = _safe_get(vpn_page, "engine")
                is_conn = _safe_get(engine, "is_connected")
                ctx["vpn"] = {
                    "active": bool(is_conn) if is_conn is not None else False,
                }
    except Exception as e:
        print(f"[gather_full_context] vpn: {e}")
        ctx["vpn"] = {"active": False}

    # ── 3. FORECAST ────────────────────────────────────────────────────
    try:
        from features.forecast.engine import ForecastEngine
        fe = ForecastEngine(enable_background=False, auto_detect=True)
        hist = fe.analyze_history()
        if hist and getattr(hist, "status", "") == "ok":
            ctx["forecast"] = {
                "weekly_avg_ping_ms":  round(getattr(hist, "weekly_avg_ping", 0) or 0, 1),
                "peak_hour":            str(getattr(hist, "peak_hour", "—")),
                "anomalies_count":      int(getattr(hist, "anomalies_count", 0) or 0),
                "sla_pct":              round(getattr(hist, "sla_pct", 100) or 100, 1),
                "total_samples":        int(getattr(hist, "total_samples", 0) or 0),
            }
    except Exception as e:
        print(f"[gather_full_context] forecast: {e}")
        ctx["forecast"] = {}

    # ── 4. PI-AGENT ───────────────────────────────────────────────────
    try:
        pi_sub = _safe_get(app, "pi_subscriber")
        if pi_sub is not None:
            is_conn = _safe_get(pi_sub, "is_connected", default=False)
            is_online = False
            try:
                is_online = pi_sub.is_pi_online() if hasattr(pi_sub, "is_pi_online") else bool(is_conn)
            except Exception:
                is_online = bool(is_conn)

            db_recs = 0
            try:
                if hasattr(pi_sub, "get_record_count"):
                    db_recs = pi_sub.get_record_count()
                elif hasattr(pi_sub, "db_path"):
                    # Спробуємо порахувати через SQLite
                    import sqlite3
                    with sqlite3.connect(str(pi_sub.db_path), timeout=2) as c:
                        rows = c.execute(
                            "SELECT COUNT(*) FROM ping_log").fetchone()
                        db_recs = rows[0] if rows else 0
            except Exception: pass

            ctx["pi"] = {
                "online":      bool(is_online),
                "connected":   bool(is_conn),
                "db_records":  int(db_recs),
            }

            # Спробуємо отримати останній speedtest з Pi
            try:
                if hasattr(pi_sub, "get_latest_speedtest"):
                    st = pi_sub.get_latest_speedtest()
                    if st:
                        ctx["pi"]["last_speedtest"] = {
                            "dl_mbps": st.get("dl_mbps"),
                            "ul_mbps": st.get("ul_mbps"),
                            "ts":      st.get("ts"),
                        }
            except Exception: pass
        else:
            ctx["pi"] = {"online": False}
    except Exception as e:
        print(f"[gather_full_context] pi: {e}")
        ctx["pi"] = {"online": False}

    # ── 5. LAN-пристрої ───────────────────────────────────────────────
    try:
        sec_page = _safe_get(app, "pages", "security")
        devices = _safe_get(sec_page, "_devices") or _safe_get(sec_page, "devices")
        if isinstance(devices, list):
            new_devs   = sum(1 for d in devices if isinstance(d, dict) and d.get("is_new"))
            suspicious = sum(1 for d in devices if isinstance(d, dict)
                             and d.get("threat") in ("warn", "danger", "critical"))
            ctx["lan"] = {
                "device_count":  len(devices),
                "new_devices":   new_devs,
                "suspicious":    suspicious,
            }
    except Exception as e:
        print(f"[gather_full_context] lan: {e}")

    # ── 6. TAPO P110 ──────────────────────────────────────────────────
    try:
        agent = _safe_get(app, "_smart_agent")
        tapo  = _safe_get(agent, "tapo")
        if tapo is not None:
            stats = {}
            try:
                if hasattr(tapo, "get_stats"):
                    stats = tapo.get_stats() or {}
            except Exception: pass

            if stats:
                ctx["tapo"] = {
                    "online":         True,
                    "voltage":        stats.get("volt_now") or stats.get("voltage", 0),
                    "current_amps":   stats.get("amp_now") or stats.get("current", 0),
                    "power_watts":    stats.get("watt_now") or stats.get("power", 0),
                    "stability_pct":  stats.get("stability_pct", 100),
                    "guard_events":   stats.get("guard_events", 0),
                    "ip":             getattr(tapo, "ip", "—"),
                    "is_monitoring":  bool(getattr(tapo, "is_monitoring", False)),
                }
            else:
                ctx["tapo"] = {"online": True, "ip": getattr(tapo, "ip", "—"),
                               "no_data": True}
        else:
            ctx["tapo"] = {"online": False}
    except Exception as e:
        print(f"[gather_full_context] tapo: {e}")
        ctx["tapo"] = {"online": False}

    # ── 7. ОСТАННЯ ДІАГНОСТИКА ────────────────────────────────────────
    try:
        diag_page = _safe_get(app, "pages", "diagnostics")
        last = _safe_get(diag_page, "_last_ai_data")
        if isinstance(last, dict) and last:
            ctx["recent_diagnostics"] = {
                "summary":         (last.get("summary", "") or "")[:300],
                "critical_count":  len(last.get("critical", []) or []),
                "warnings_count":  len(last.get("warnings", []) or []),
                "good_count":      len(last.get("good", []) or []),
                "overall":         last.get("overall", "unknown"),
                "top_tips":        [t for t in (last.get("tips", []) or [])][:3],
            }
    except Exception as e:
        print(f"[gather_full_context] diagnostics: {e}")

    # ── 8. ЗАГАЛЬНА ІНФА УТИЛІТИ ──────────────────────────────────────
    try:
        ctx["utility_info"] = {
            "gateway_ip":   _safe_get(app, "current_gateway_ip", default="?"),
            "tg_configured": bool(_safe_get(app, "tg_token") and _safe_get(app, "tg_chat_id")),
            "monitoring":    bool(_safe_get(app, "is_monitoring", default=False)),
        }
    except Exception as e:
        print(f"[gather_full_context] utility: {e}")

    _CONTEXT_CACHE["data"] = ctx
    _CONTEXT_CACHE["ts"]   = now

    # Друкуємо що зібрали (для дебагу)
    keys_with_data = [k for k, v in ctx.items()
                      if v and not k.startswith("_")]
    print(f"[hybrid_ai] 📊 Контекст зібрано: {', '.join(keys_with_data)}")

    return ctx


def _format_context_for_ai(ctx: dict) -> str:
    """PR #25 v2: ФОРМАТУЄ контекст у markdown-блок для вбудовування
    у запитання Gemini. Без цього AI не побачить ніяких даних утиліти.
    """
    if not ctx:
        return ""

    lines = ["=" * 60]
    lines.append("📊 ПОТОЧНИЙ СТАН УТИЛІТИ NETGUARDIAN")
    lines.append("=" * 60)

    # SNAPSHOT мережі
    snap = ctx.get("snapshot") or {}
    if snap:
        lines.append("\n🌐 МЕРЕЖА:")
        ping = snap.get("ping_ms")
        if ping is not None and ping >= 0:
            lines.append(f"  • Ping: {ping} мс")
        jitter = snap.get("jitter_ms")
        if jitter is not None and jitter > 0:
            lines.append(f"  • Jitter: {jitter} мс")
        loss = snap.get("loss_pct")
        if loss is not None and loss > 0:
            lines.append(f"  • Packet loss: {loss}%")
        wifi = snap.get("wifi_signal_pct")
        if wifi is not None:
            lines.append(f"  • Wi-Fi сигнал: {wifi}%")
        pub_ip = snap.get("public_ip")
        if pub_ip:
            lines.append(f"  • Public IP: {pub_ip}")
        isp = snap.get("isp")
        if isp:
            lines.append(f"  • ISP: {isp}")
        city = snap.get("city")
        country = snap.get("country")
        if city or country:
            loc = ", ".join(filter(None, [city, country]))
            lines.append(f"  • Локація: {loc}")
        local_ip = snap.get("local_ip")
        gateway = snap.get("gateway") or (ctx.get("utility_info") or {}).get("gateway_ip")
        if local_ip:
            lines.append(f"  • Local IP: {local_ip}")
        if gateway and gateway != "?":
            lines.append(f"  • Gateway: {gateway}")
        dl = snap.get("dl_mbps")
        ul = snap.get("ul_mbps")
        if dl or ul:
            lines.append(f"  • Speed: DL={dl or '?'} / UL={ul or '?'} Mbps")

    # VPN
    vpn = ctx.get("vpn") or {}
    if vpn:
        active = vpn.get("active", False)
        if active:
            lines.append(f"\n🛡️ VPN: АКТИВНИЙ")
            if vpn.get("country") and vpn.get("country") != "—":
                lines.append(f"  • Країна: {vpn['country']}")
            if vpn.get("city") and vpn.get("city") != "—":
                lines.append(f"  • Місто: {vpn['city']}")
            if vpn.get("ip") and vpn.get("ip") != "—":
                lines.append(f"  • Зовнішня IP: {vpn['ip']}")
            if vpn.get("isp") and vpn.get("isp") != "—":
                lines.append(f"  • ISP: {vpn['isp']}")
        else:
            lines.append(f"\n🛡️ VPN: не активний")

    # FORECAST
    fc = ctx.get("forecast") or {}
    if fc:
        lines.append(f"\n📈 ПОГОДА ІНТЕРНЕТУ (за тиждень):")
        if fc.get("weekly_avg_ping_ms"):
            lines.append(f"  • Середній ping: {fc['weekly_avg_ping_ms']} мс")
        if fc.get("peak_hour") and fc.get("peak_hour") != "—":
            lines.append(f"  • Пікова година навантаження: {fc['peak_hour']}")
        if fc.get("anomalies_count") is not None:
            lines.append(f"  • Аномалій (різких падінь): {fc['anomalies_count']}")
        if fc.get("sla_pct") is not None:
            lines.append(f"  • SLA провайдера: {fc['sla_pct']}%")
        if fc.get("total_samples"):
            lines.append(f"  • Всього вимірів: {fc['total_samples']}")

    # PI AGENT
    pi = ctx.get("pi") or {}
    if pi:
        if pi.get("online"):
            lines.append(f"\n🍓 RASPBERRY PI АГЕНТ: online")
            if pi.get("db_records"):
                lines.append(f"  • Записів у БД: {pi['db_records']}")
            last_st = pi.get("last_speedtest")
            if last_st:
                lines.append(
                    f"  • Останній speedtest: "
                    f"DL={last_st.get('dl_mbps')} / UL={last_st.get('ul_mbps')} Mbps "
                    f"({last_st.get('ts', '?')})")
        else:
            lines.append(f"\n🍓 RASPBERRY PI АГЕНТ: offline")

    # LAN
    lan = ctx.get("lan") or {}
    if lan and lan.get("device_count") is not None:
        lines.append(f"\n🏠 LAN-МЕРЕЖА:")
        lines.append(f"  • Всього пристроїв: {lan['device_count']}")
        if lan.get("new_devices"):
            lines.append(f"  • Нових (нерозпізнаних): {lan['new_devices']}")
        if lan.get("suspicious"):
            lines.append(f"  • Підозрілих: {lan['suspicious']}")

    # TAPO P110
    tapo = ctx.get("tapo") or {}
    if tapo and tapo.get("online"):
        lines.append(f"\n🔌 TAPO P110 (Voltage Guardian):")
        if tapo.get("ip"):
            lines.append(f"  • IP: {tapo['ip']}")
        if tapo.get("voltage"):
            lines.append(f"  • Напруга: {tapo['voltage']} V")
        if tapo.get("power_watts") is not None:
            lines.append(f"  • Потужність: {tapo['power_watts']} W")
        if tapo.get("current_amps") is not None:
            lines.append(f"  • Струм: {tapo['current_amps']} A")
        if tapo.get("stability_pct") is not None:
            lines.append(f"  • Стабільність живлення: {tapo['stability_pct']}%")
        if tapo.get("guard_events"):
            lines.append(f"  • Спрацювань захисту: {tapo['guard_events']}")
        if tapo.get("is_monitoring"):
            lines.append(f"  • Voltage Monitor: активний ✅")
    elif tapo and not tapo.get("online"):
        lines.append(f"\n🔌 TAPO P110: не налаштована")

    # ОСТАННЯ ДІАГНОСТИКА
    rd = ctx.get("recent_diagnostics") or {}
    if rd:
        lines.append(f"\n🩺 ОСТАННЯ ДІАГНОСТИКА:")
        if rd.get("summary"):
            lines.append(f"  • Висновок: {rd['summary']}")
        if rd.get("overall") and rd.get("overall") != "unknown":
            lines.append(f"  • Загальний стан: {rd['overall']}")
        c = rd.get("critical_count", 0)
        w = rd.get("warnings_count", 0)
        g = rd.get("good_count", 0)
        if c or w or g:
            lines.append(f"  • Знахідки: 🔴 {c} критичних, 🟡 {w} попереджень, ✅ {g} OK")
        tips = rd.get("top_tips", [])
        if tips:
            lines.append(f"  • Поради:")
            for tip in tips[:3]:
                lines.append(f"    – {tip}")

    # УТИЛІТА
    ui = ctx.get("utility_info") or {}
    if ui:
        lines.append(f"\n⚙️ КОНФІГУРАЦІЯ:")
        if ui.get("gateway_ip") and ui.get("gateway_ip") != "?":
            lines.append(f"  • Поточний шлюз: {ui['gateway_ip']}")
        if ui.get("tg_configured"):
            lines.append(f"  • Telegram-бот: налаштований ✅")
        if ui.get("monitoring"):
            lines.append(f"  • Авто-моніторинг: активний ✅")

    lines.append("\n" + "=" * 60)

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════════════
#  HYBRID AI CLIENT
# ══════════════════════════════════════════════════════════════════════

class HybridAIClient:
    """Обгортка яка робить hybrid online/offline AI.

    Метод-обгортки замість прямого виклику gemini_client:
        • quick_answer(question, context) → text (з полем source у логах)
        • analyze_diagnostics(rule_data) → dict з полем 'source'

    Використання:
        client = get_hybrid_client()
        answer = client.quick_answer("чому повільний інтернет?")
        # answer тепер працює навіть коли Gemini недоступний
    """

    def __init__(self):
        self._last_source = "unknown"
        self._last_error = ""

    @property
    def last_source(self) -> str:
        """Повертає звідки прийшла остання відповідь: gemini / knowledge_base / unknown."""
        return self._last_source

    @property
    def last_error(self) -> str:
        return self._last_error

    # ──────────────────────────────────────────────────────────────────
    #  QUICK ANSWER — швидке Q&A
    # ──────────────────────────────────────────────────────────────────

    def quick_answer(self, question: str, context: dict = None) -> str:
        """Шукає відповідь.

        PR #25 v2: Тепер вбудовує ПОВНИЙ контекст УТИЛІТИ ПРЯМО У ТЕКСТ
        запитання — щоб Gemini ТОЧНО бачив усі дані (мережа, VPN, Pi,
        Tapo, історія, остання діагностика).

        1. Збирає контекст через gather_full_context()
        2. Формує enriched-питання з контекстом
        3. Пробує Gemini
        4. Якщо Gemini недоступний → KB fallback з тим самим контекстом

        Returns: текст відповіді з префіксом-індикатором source
        """
        question = (question or "").strip()
        if not question:
            return "❓ Введи питання"

        # PR #25: автоматичний збір контексту якщо не передано
        if context is None or not context:
            try:
                context = gather_full_context()
            except Exception as e:
                print(f"[HybridAI] gather_full_context failed: {e}")
                context = {}

        # PR #25 v2: формуємо ОБОГАЧЕНЕ питання з контекстом
        ctx_block = _format_context_for_ai(context)
        if ctx_block:
            enriched_question = (
                f"{ctx_block}\n\n"
                f"ПИТАННЯ КОРИСТУВАЧА:\n{question}\n\n"
                f"Дай відповідь на питання, використовуючи КОНКРЕТНІ числа "
                f"та факти з 'ПОТОЧНОГО СТАНУ УТИЛІТИ' вище. "
                f"Не кажи що не маєш даних — вони ВИЩЕ у блоці."
            )
        else:
            enriched_question = question

        # ── СПРОБА 1: Gemini — ВЖЕ БЕЗ preflight перевірки інтернету ──
        # PR #27: is_internet_available() часто блокувався Windows Firewall
        # і повертав хибне False. Тепер просто пробуємо Gemini — він сам
        # швидко (~1-2с timeout) поверне ConnectionError якщо інтернет лежить.
        print("[HybridAI] 🌐 Спроба 1: Gemini AI...")
        gemini_answer = self._try_gemini(enriched_question, context)
        if gemini_answer:
            self._last_source = "gemini"
            print(f"[HybridAI] ✅ Gemini OK ({len(gemini_answer)} chars)")
            return f"🌐 **Gemini AI:**\n\n{gemini_answer}"

        # Якщо Gemini не вдався — лог чому
        print(f"[HybridAI] ⚠️ Gemini failed: {self._last_error[:120]}")

        # ── СПРОБА 2: Knowledge Base fallback ────────────────────
        print("[HybridAI] 📦 Спроба 2: Knowledge Base...")
        kb_answer = self._kb_fallback(question, context)
        if kb_answer:
            self._last_source = "knowledge_base"
            # PR #27: правильніше пояснення чому KB замість Gemini
            reason = self._gemini_failure_reason()
            return (f"📦 **Локальна база знань** "
                    f"_({reason})_\n\n{kb_answer}")

        # ── СПРОБА 3: Raspberry Pi AI (PR #4) ─────────────────────
        # Останній шанс — питаємо Pi, він має свою KB + 24/7 збір помилок
        print("[HybridAI] 🍓 Спроба 3: Raspberry Pi AI...")
        pi_answer = self._try_pi_ai(question, context)
        if pi_answer:
            self._last_source = "raspberry_pi"
            return (f"🍓 **Raspberry Pi AI** "
                    f"_(локальний агент)_\n\n{pi_answer}")

        # ── НІЧОГО НЕ ВДАЛОСЬ ────────────────────────────────────
        # PR #27.1: замість порожніх "не знаю" — показуємо реальний
        # стан мережі з контексту (snapshot + VPN + Pi + Tapo) щоб
        # користувач отримав ХОЧА Б базовий відповідь з фактів.
        self._last_source = "context_only"
        reason = self._gemini_failure_reason()

        # Будуємо чесну відповідь з фактів утиліти
        bits = ["⚠️ AI не зміг відповісти, але ось що я бачу з твоєї утиліти:\n"]

        snap = context.get("snapshot") if context else None
        if snap:
            analysis = self._analyze_context_locally(snap)
            if analysis:
                bits.append("**📊 Поточний стан мережі:**")
                bits.append(analysis)
                bits.append("")

        extra = self._format_extra_context(context) if context else ""
        if extra:
            bits.append(extra)
            bits.append("")

        bits.append(f"_AI недоступне: {reason}_")
        bits.append("")
        bits.append("Спробуй переформулювати питання конкретніше "
                    "(наприклад: 'високий ping', 'DNS не резолвить').")

        return "\n".join(bits)

    def _try_pi_ai(self, question: str, context: dict = None) -> str:
        """
        PR #4 — Третій fallback: запит до локального AI на Raspberry Pi.

        Pi у нас має:
          • свою KB (pi_kb.py)
          • збирач помилок 24/7 (pi_error_collector.py)
          • метод analyze_situation() що повертає готовий діагноз

        Тут є дві стратегії:
          A) Прочитати вже наявний останній AI-аналіз з БД (швидко)
          B) Надіслати свіжий запит і ЧЕКАТИ 2-3 секунди на відповідь

        Використовуємо обидві: спочатку (A), якщо порожньо — (B).
        """
        try:
            # Спочатку спробуємо знайти підписника через app instance
            sub = None
            app = _find_app_instance()
            if app is not None:
                sub = _safe_get(app, "pi_subscriber")

            # Fallback на singleton-функцію
            if sub is None:
                try:
                    from features.forecast.mqtt_subscriber import get_subscriber
                    sub = get_subscriber()
                except Exception:
                    pass
        except Exception as e:
            self._last_error = f"Pi MQTT не доступний: {e}"
            return ""

        if not sub or not getattr(sub, "is_connected", False):
            self._last_error = "Pi-агент офлайн"
            return ""

        # СТРАТЕГІЯ A: останній свіжий аналіз (за 5 хв)
        latest = None
        try:
            latest = sub.get_latest_ai_analysis(max_age_seconds=300)
        except Exception: pass

        # СТРАТЕГІЯ B: якщо нема свіжого — просимо зробити зараз
        if not latest:
            try:
                if sub.request_ai_analysis(period_sec=3600):
                    # Чекаємо 3 секунди на відповідь Pi
                    for _ in range(6):
                        time.sleep(0.5)
                        latest = sub.get_latest_ai_analysis(max_age_seconds=15)
                        if latest:
                            break
            except Exception: pass

        if not latest:
            self._last_error = "Pi не відповів на запит analyze"
            return ""

        # Форматуємо відповідь Pi у читабельний markdown
        return self._format_pi_analysis(latest, question)

    def _format_pi_analysis(self, analysis: dict, question: str = "") -> str:
        """Форматує JSON-відповідь Pi у markdown для UI."""
        lines = []

        # Summary
        summary = analysis.get("summary", "")
        if summary:
            lines.append(f"**{summary}**\n")

        # Критичні проблеми
        critical = analysis.get("critical", [])
        if critical:
            lines.append("**🔴 Критично:**")
            for item in critical[:4]:
                lines.append(f"• {item}")
            lines.append("")

        # Попередження
        warnings = analysis.get("warnings", [])
        if warnings:
            lines.append("**🟡 Попередження:**")
            for item in warnings[:4]:
                lines.append(f"• {item}")
            lines.append("")

        # Tips з KB
        tips = analysis.get("tips", [])
        if tips:
            lines.append("**💡 Рекомендації:**")
            for tip in tips[:5]:
                lines.append(f"• {tip}")
            lines.append("")

        # Auto-fixes
        fixes = analysis.get("fixes", [])
        if fixes:
            lines.append("**🔧 Швидкі виправлення:**")
            for fix in fixes[:3]:
                lines.append(
                    f"• `{fix.get('id')}` — {fix.get('label')}"
                )
            lines.append("")

        # Метаінформація
        net_id = analysis.get("net_id", "")
        errors_count = analysis.get("errors_count", 0)
        period_sec = analysis.get("period_sec", 3600)
        period_min = period_sec // 60

        meta = (
            f"\n---\n"
            f"_📊 Pi зафіксував {errors_count} помилок за останні "
            f"{period_min} хв на мережі `{net_id[:8]}`_"
        )
        lines.append(meta)

        return "\n".join(lines) if lines else ""

    def _try_gemini(self, question: str, context: dict = None) -> str:
        """Пробує Gemini. Повертає текст або порожній рядок.

        PR #25 v2: question вже містить вбудований контекст у тексті.
        PR #27: context=None щоб gemini_client не додавав JSON-контекст
        повторно (він уже в тексті question). Також краще класифікуємо
        помилки для діагностики.
        """
        try:
            from app.core.gemini_client import get_gemini_client
            client = get_gemini_client()
            if not client.is_available():
                self._last_error = "no_api_key"
                return ""
            # PR #27: context=None — щоб НЕ дублювати контекст.
            # Він уже у тексті question у блоці "ПОТОЧНИЙ СТАН УТИЛІТИ".
            answer = client.quick_answer(question, context=None)
            # Перевіряємо що це не error message від клієнта
            if (answer and not answer.startswith("❌")
                    and not answer.startswith("⚠️")
                    and len(answer.strip()) > 5):
                self._last_error = ""
                return answer
            self._last_error = answer[:120] if answer else "empty_response"
            return ""
        except Exception as e:
            err_str = str(e)
            self._last_error = err_str
            print(f"[HybridAI] Gemini exception: {err_str[:150]}")
            return ""

    def _gemini_failure_reason(self) -> str:
        """PR #27/28.1: Людино-читабельне пояснення чому Gemini не спрацював."""
        err = (self._last_error or "").lower()

        # PR #28.1: спочатку перевіряємо чи зараз активний quota lockout
        # (нам глобально цікаво, навіть якщо last_error не quota)
        try:
            from app.core.gemini_client import get_gemini_client
            client = get_gemini_client()
            locked, secs = client.is_quota_locked()
            if locked:
                mins = max(1, secs // 60)
                return (f"ліміт запитів Gemini вичерпано — "
                        f"відновиться через ~{mins} хв")
        except Exception:
            pass

        if not err:
            return "Gemini не відповів"
        if "no_api_key" in err or "не налаштован" in err:
            return "Gemini не налаштований у Settings"
        if ("quota" in err or "429" in err or "exhausted" in err
                or "exceeded" in err or "rate" in err):
            return "ліміт запитів Gemini вичерпано (відновиться за 5 хв)"
        if "api_key" in err or "401" in err or "403" in err:
            return "невірний API-ключ Gemini"
        if ("connection" in err or "network" in err or "timeout" in err
                or "unreachable" in err or "ssl" in err
                or "name resolution" in err or "dns" in err):
            return "інтернет недоступний"
        if "empty" in err:
            return "Gemini повернув пусту відповідь"
        return f"Gemini error: {err[:60]}"

    def _kb_fallback(self, question: str, context: dict = None) -> str:
        """PR #28.2: МАКСИМАЛЬНО розумний Local Analyzer.

        Новий 4-шаровий алгоритм:
          1) Intent + sub-intent розпізнавання (status/control/howto/capability)
          2) Перевірка чи модуль АКТИВНИЙ (а не лозунги про "не налаштовано")
          3) Експерт-функція для конкретної теми
          4) Fallback на keyword-based KB пошук
        """
        if not question or not isinstance(question, str):
            return ""

        q = question.lower().strip()

        if not context:
            context = {}

        # ── 1. Інтент-аналіз: на тему + дію ──
        topic    = self._detect_topic(q)            # tapo/pi/vpn/forecast/lan/diag/network/utility
        action   = self._detect_action(q)           # status/control/howto/capability/diagnose
        print(f"[SmartLocal] 🎯 topic='{topic}' action='{action}' "
              f"q='{question[:60]}'")

        # ── 2. Спеціальні відповіді на capability/control ──
        if action == "capability":
            # "Ти можеш X?", "ти маєш доступ до Y?"
            return self._answer_capability(topic, context, q)

        if action == "control":
            # "Вимкни X", "перезапусти Y", "запусти Z"
            return self._answer_control(topic, context, q)

        if action == "howto":
            # "Як зробити X", "як налаштувати Y"
            return self._answer_howto(topic, context, q)

        # ── 3. status / diagnose — повноцінні модульні відповіді ──
        if topic == "tapo":
            return self._answer_tapo(context, q)
        if topic == "pi":
            return self._answer_pi(context, q)
        if topic == "vpn":
            return self._answer_vpn(context, q)
        if topic == "forecast":
            return self._answer_forecast(context, q)
        if topic == "lan":
            return self._answer_lan(context, q)
        if topic == "diag" or action == "diagnose":
            return self._answer_diagnose(context, q)
        if topic == "utility":
            return self._answer_utility_capabilities(context, q)

        # network / default — загальний звіт
        return self._answer_status(context)

    # ──────────────────────────────────────────────────────────────────
    #  PR #28.2: ТЕМА + ДІЯ
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_topic(q: str) -> str:
        """Розпізнає ТЕМУ питання."""
        # Tapo / електрика / розетка
        if any(w in q for w in ["tapo", "тапо", "напруг", "вольт", "електрик",
                                  "розетк", "ват", "потужн", "струм",
                                  "споживає", "споживанн", "живлен"]):
            return "tapo"

        # Pi (увага: "пай" може бути частина "пайплайн", тому додатковий context)
        if any(w in q for w in ["raspberry", "малинка", "малин",
                                  "pi-агент", "піагент"]):
            return "pi"
        if " pi " in f" {q} " or q.startswith("pi"):
            return "pi"
        if "агент" in q and "вимик" not in q:  # "Pi-агент" а не "агент вимкнення"
            return "pi"

        # VPN
        if any(w in q for w in ["vpn", "впн", "radmin", "тунель",
                                  "openvpn", "wireguard"]):
            return "vpn"

        # Forecast / weekly / history
        if any(w in q for w in ["тижн", "тижден", "погод", "прогноз",
                                  "статистик", "істор", "за тиждень",
                                  "тренд", "збір даних", "збирає дан"]):
            return "forecast"

        # LAN / пристрої / сканування мережі
        if any(w in q for w in ["пристро", " lan ", " lan?", "локальн",
                                  "хто в мережі", "хто підключ",
                                  "скільки в мережі", "device", "сосед",
                                  "сканувати мереж", "скан мереж"]):
            return "lan"

        # Утиліта / можливості
        if any(w in q for w in ["утиліт", "ти вмієш", "ти можеш", "що ти",
                                  "які функ", "можливост", "доступ до"]):
            return "utility"

        # Діагноз
        if any(w in q for w in ["діагност", "проблем", "не працю", "обрив",
                                  "лаги", "лагає", "повільн", "гальм",
                                  "буфер", "не запус", "не відкрив"]):
            return "diag"

        # Мережа / status
        return "network"

    @staticmethod
    def _detect_action(q: str) -> str:
        """Розпізнає ДІЮ/ТИП ЗАПИТУ."""
        # Capability: "ти можеш", "маєш доступ", "вмієш"
        if any(w in q for w in ["ти можеш", "ти вмієш", "вмієш ти",
                                  "можеш ти", "маєш доступ", "маєш змог",
                                  "доступ до", "контроль над", "керуєш"]):
            return "capability"

        # Control: дієслова в наказовому стані
        if any(w in q for w in ["вимкни", "увімкни", "перезапуст",
                                  "перезавантаж", "запусти", "зупини",
                                  "відключи", "підключи", "очисти", "скинь"]):
            return "control"

        # How-to: "як зробити", "як налаштувати"
        if any(w in q for w in ["як зробити", "як налашту", "як включит",
                                  "як виключит", "як перезаванта",
                                  "як підключит", "як виправ", "як змін",
                                  "як знайти", "як перевір"]):
            return "howto"

        # Діагноз
        if any(w in q for w in ["чому", "що не так", "що з ", "проблема",
                                  "не працю", "лагає", "повільно"]):
            return "diagnose"

        # Status / default
        return "status"

    # ──────────────────────────────────────────────────────────────────
    #  PR #28.2: ВІДПОВІДІ НА CAPABILITY / CONTROL / HOWTO
    # ──────────────────────────────────────────────────────────────────

    def _answer_capability(self, topic: str, context: dict, q: str) -> str:
        """Відповіді на 'Ти можеш X?' / 'Маєш доступ до Y?'

        Утиліта насправді МОЖЕ багато чого — описуємо ЧЕСНО що уміє.
        """
        if topic == "tapo":
            tapo = context.get("tapo") or {}
            online = tapo.get("online", False)

            if online:
                return ("✅ **Так, утиліта має повний доступ до Tapo P110.**\n\n"
                        "**🔌 Що я можу робити з розеткою:**\n"
                        "• 📊 Читати поточну напругу, струм, потужність\n"
                        "• 📈 Зберігати історію в БД (графіки за години/дні)\n"
                        "• 🛡️ Спрацьовувати захист — вимикати живлення "
                        "коли напруга падає <190V або підіймається >250V\n"
                        "• 🔄 Перезапускати роутер (вимкнути на 30с і "
                        "увімкнути назад)\n"
                        "• ⏰ Розклад — вимикати/вмикати за часом\n\n"
                        "**🛠 Як вимкнути зараз:**\n"
                        "1. Зайди у вкладку 🔌 **Voltage Guardian**\n"
                        "2. Натисни кнопку **Вимкнути розетку**\n"
                        "3. Підтверди дію\n\n"
                        "⚠️ Якщо вимкнеш — інтернет миттєво пропаде "
                        "до повторного увімкнення.")

            return ("🟡 **Tapo P110 поки не підключена до утиліти.**\n\n"
                    "Якщо розетка фізично є в мережі — її можна додати:\n"
                    "1. Відкрий 🔌 **Voltage Guardian**\n"
                    "2. Введи її IP (наприклад 192.168.0.104)\n"
                    "3. Введи логін/пароль від акаунта **TP-Link**\n"
                    "4. Натисни **Підключитись**\n\n"
                    "Після цього зможу і керувати, і моніторити напругу.")

        if topic == "pi":
            pi = context.get("pi") or {}
            online = pi.get("online", False)

            if online:
                recs = pi.get("db_records", 0)
                return (f"✅ **Так, Raspberry Pi-агент підключений** і вже "
                        f"зібрав **{recs:,}** записів.\n\n"
                        f"**🍓 Що я роблю через Pi:**\n"
                        f"• 24/7 моніторинг ping/jitter/loss до Cloudflare/Google\n"
                        f"• Збір даних навіть коли твій ПК вимкнено\n"
                        f"• Незалежна верифікація — якщо твій ПК каже "
                        f"\"інтернету нема\" а Pi каже \"є\", значить "
                        f"проблема в ПК\n"
                        f"• Speedtest по розкладу\n"
                        f"• MQTT-трансляція даних у головну утиліту\n\n"
                        f"Вкладка 🍓 **Дані з Pi** показує всі метрики "
                        f"і графіки.")

            return ("🟡 **Pi-агент офлайн або не налаштований.**\n\n"
                    "Це окремий міні-комп'ютер який стоїть біля роутера "
                    "і збирає телеметрію 24/7. Налаштовується один раз — "
                    "потім працює сам.\n\n"
                    "**📚 Як підключити Pi:**\n"
                    "1. Постав Raspbian і клонуй repo з `pi_agent/`\n"
                    "2. Налаштуй MQTT-broker у головній утиліті\n"
                    "3. Запусти `python pi_agent.py` на Pi\n"
                    "4. У NetGuardian → 🍓 Дані з Pi → Підключитись")

        if topic == "vpn":
            vpn = context.get("vpn") or {}
            active = vpn.get("active", False)

            return (f"✅ **Так, утиліта керує VPN через панель Auto-VPN.**\n\n"
                    f"Зараз стан: **{'АКТИВНИЙ' if active else 'НЕ активний'}**.\n\n"
                    f"**🛡️ Що я вмію з VPN:**\n"
                    f"• Запускати/зупиняти Radmin, OpenVPN, WireGuard\n"
                    f"• Авто-визначати ProxyType через ipconfig + публічну IP\n"
                    f"• Anti-flicker детектор (2/3-ON, 3/3-OFF) щоб "
                    f"не моргало\n"
                    f"• Kill-switch — блокує інтернет якщо VPN падає\n"
                    f"• Geo-аналіз — показує країну і ISP VPN-сервера\n"
                    f"• Тригер пере-діагностики при підключенні VPN "
                    f"(інші правила!)\n\n"
                    f"Вкладка 🛡️ **Auto-VPN**.")

        if topic == "lan":
            return ("✅ **Так, утиліта сканує локальну мережу.**\n\n"
                    "**🏠 Що я роблю з LAN:**\n"
                    "• ARP-скан всієї підмережі (192.168.X.0/24)\n"
                    "• Визначення виробника пристрою за MAC-адресою (OUI)\n"
                    "• Класифікація: телефони / ПК / IoT / невідоме\n"
                    "• Виявлення НОВИХ пристроїв (яких не було раніше)\n"
                    "• Виявлення ПІДОЗРІЛИХ (дивний MAC, дивне ім'я)\n"
                    "• Push-сповіщення в Telegram коли з'являється новий\n"
                    "• Збереження історії — \"хто був у мережі позавчора\"\n\n"
                    "**🛠 Як запустити скан:**\n"
                    "1. Відкрий вкладку 🛡️ **Security**\n"
                    "2. Натисни **Сканувати мережу**\n"
                    "3. За 10-15с побачиш повний список\n\n"
                    "_Поки що локальна AI ще не отримала результати "
                    "сканування — запусти скан і питай знов._")

        if topic == "forecast":
            fc = context.get("forecast") or {}
            samples = fc.get("total_samples", 0)
            return (f"✅ **Так, я веду статистику ping/jitter/обривів.**\n\n"
                    f"Це називається **Погода інтернету** — аналіз "
                    f"тенденцій за тиждень/місяць. Зараз у БД "
                    f"**{samples:,}** записів.\n\n"
                    f"**📈 Що я аналізую:**\n"
                    f"• Середній ping за день/тиждень\n"
                    f"• SLA % (скільки часу інтернет був стабільним)\n"
                    f"• Пікові години навантаження провайдера\n"
                    f"• Аномалії — раптові падіння\n"
                    f"• Тренди — інтернет стає кращим чи гіршим?\n\n"
                    f"Вкладка 📈 **Погода інтернету** — графіки + AI-висновки.")

        # Загальна capability — про всю утиліту
        return self._answer_utility_capabilities(context, q)

    def _answer_control(self, topic: str, context: dict, q: str) -> str:
        """Відповіді на дії: 'вимкни X', 'перезапусти Y'."""
        if topic == "tapo":
            tapo = context.get("tapo") or {}
            if "вимкн" in q or "відключ" in q:
                if tapo.get("online"):
                    return ("⚠️ **Команда розпізнана: вимкнути Tapo.**\n\n"
                            "Я не можу натиснути за тебе кнопку з чату, "
                            "але можу показати точно як це зробити:\n\n"
                            "**🛠 Покроково:**\n"
                            "1. Перейди у вкладку 🔌 **Voltage Guardian**\n"
                            "2. Натисни велику кнопку **Вимкнути розетку**\n"
                            "3. Підтверди дію у спливаючому вікні\n\n"
                            "⚠️ Це **миттєво** вимкне роутер. "
                            "Інтернет пропаде — і у тебе у Wi-Fi і у "
                            "пристроях підключених кабелем.")
                return ("🟡 Tapo не підключена — нема чим керувати. "
                        "Спочатку додай розетку в 🔌 Voltage Guardian.")

            if "увімкн" in q or "включ" in q:
                return ("🛠 **Увімкнути Tapo:** перейди у 🔌 Voltage Guardian "
                        "→ кнопка **Увімкнути розетку**.")

            if "перезапуст" in q or "ребут" in q:
                return ("🔄 **Перезапуск роутера через Tapo:**\n\n"
                        "1. 🔌 Voltage Guardian → **Перезапустити роутер**\n"
                        "2. Розетка вимкнеться на 30 секунд\n"
                        "3. Потім увімкнеться автоматично\n"
                        "4. Роутер завантажиться 1-2 хв\n\n"
                        "_Це часто рятує коли роутер завис._")

        if topic == "vpn":
            if "вимкн" in q or "відключ" in q or "зупин" in q:
                return ("**🛠 Вимкнути VPN:**\n"
                        "1. Вкладка 🛡️ **Auto-VPN**\n"
                        "2. Натисни **Зупинити VPN**\n"
                        "3. За 2-3 секунди публічна IP повернеться "
                        "до твого провайдера")
            if "увімкн" in q or "запуст" in q:
                return ("**🛠 Увімкнути VPN:**\n"
                        "1. Вкладка 🛡️ **Auto-VPN**\n"
                        "2. Обери провайдера (Radmin / OpenVPN / WireGuard)\n"
                        "3. Натисни **Запустити VPN**\n"
                        "4. За 5-10 секунд побачиш нову Geo на карті")

        if topic == "network":
            if "очисти" in q and ("dns" in q or "днс" in q):
                return ("**🛠 Очистити DNS-кеш:**\n"
                        "**Через NetGuardian (швидко):**\n"
                        "1. Вкладка 🩺 **Діагностика**\n"
                        "2. У панелі Quick Fix → кнопка **DNS Flush**\n"
                        "3. Готово за 1 секунду\n\n"
                        "**Або вручну через cmd:**\n"
                        "Win+R → cmd → `ipconfig /flushdns` → Enter\n\n"
                        "🧪 Перевірка: відкрий нову сторінку в браузері — "
                        "має завантажитись швидше.")

            if "перезавантаж" in q and ("роутер" in q or "інтернет" in q):
                tapo = context.get("tapo") or {}
                if tapo.get("online"):
                    return ("**🔄 Перезавантажити роутер через Tapo:**\n"
                            "1. 🔌 Voltage Guardian → **Перезапустити роутер**\n"
                            "2. Розетка автоматично вимкне і увімкне\n\n"
                            "Або фізично — вимкни кабель живлення з "
                            "роутера на 30 секунд.")
                return ("**🛠 Перезавантажити роутер:**\n"
                        "1. Вийми кабель живлення з роутера\n"
                        "2. Зачекай **30 секунд** (не менше)\n"
                        "3. Встроми кабель назад\n"
                        "4. Зачекай 1-2 хв поки роутер завантажиться\n\n"
                        "🧪 Перевірка: відкрий 192.168.0.1 в браузері — "
                        "якщо адмінка роутера відкрилась, то він живий.")

        return (f"🛠 **Розпізнав команду** але не знаю точно як її виконати "
                f"в чаті.\n\nТема: {topic}\nПитання: \"{q[:80]}\"\n\n"
                f"Запитай конкретніше — наприклад: \"Як вимкнути Tapo?\" "
                f"або \"Перезавантаж роутер\".")

    def _answer_howto(self, topic: str, context: dict, q: str) -> str:
        """Відповіді на 'Як зробити X?'."""
        if topic == "tapo":
            return self._answer_capability("tapo", context, q)
        if topic == "pi":
            return self._answer_capability("pi", context, q)
        if topic == "vpn":
            return self._answer_capability("vpn", context, q)
        if topic == "lan":
            return self._answer_capability("lan", context, q)

        if "ping" in q or "пінг" in q:
            return ("**🛠 Як виміряти/покращити ping:**\n\n"
                    "**Виміряти:**\n"
                    "• NetGuardian → ▶ ДІАГНОСТИКА — показує ping до GW, "
                    "Cloudflare, Google\n"
                    "• Win+R → cmd → `ping 1.1.1.1`\n\n"
                    "**Покращити:**\n"
                    "1. Перейди на 5GHz Wi-Fi (швидше і менше завад)\n"
                    "2. Закрий фонові програми (Steam, OneDrive, торренти)\n"
                    "3. Перезапусти роутер (на 30с з розетки)\n"
                    "4. Зміни DNS на Cloudflare 1.1.1.1 — в Діагностика → "
                    "Quick Fix → **DNS → 1.1.1.1**\n\n"
                    "🧪 Норма для України: <30мс — відмінно, <70мс — норма")

        return self._answer_diagnose(context, q)

    # ──────────────────────────────────────────────────────────────────
    #  PR #28.2: ЗАГАЛЬНІ МОЖЛИВОСТІ УТИЛІТИ
    # ──────────────────────────────────────────────────────────────────

    def _answer_utility_capabilities(self, context: dict, q: str) -> str:
        """Опис того що УМІЄ NetGuardian."""
        return (
            "🧠 **Що вміє NetGuardian:**\n\n"
            "**🩺 Діагностика мережі (100+ перевірок):**\n"
            "• L1 фізика — Wi-Fi сила, кабель, MTU, APIPA\n"
            "• L3 маршрутизація — пінги, втрати пакетів, шлюз\n"
            "• L4 DNS — резолвинг, кеш, DoH, hosts-файл\n"
            "• L7 безпека — порти, firewall, proxy, RDP, SMB\n\n"
            "**📈 Погода інтернету:**\n"
            "• Збір метрик ping/jitter/loss кожну хвилину 24/7\n"
            "• Графіки за день/тиждень/місяць\n"
            "• Детекція аномалій (раптові падіння)\n"
            "• SLA-розрахунок провайдера\n"
            "• Прогноз пікових годин\n\n"
            "**🛡️ Безпека:**\n"
            "• LAN-скан: хто підключений, нові пристрої\n"
            "• Виявлення підозрілих MAC-адрес\n"
            "• Сповіщення в Telegram про події\n\n"
            "**🌐 VPN (Auto-VPN):**\n"
            "• Керування Radmin/OpenVPN/WireGuard\n"
            "• Kill-switch, Geo-визначення\n"
            "• Anti-flicker детектор\n\n"
            "**🔌 Voltage Guardian (Tapo P110):**\n"
            "• Моніторинг напруги/потужності\n"
            "• Захист від стрибків напруги\n"
            "• Дистанційний перезапуск роутера\n\n"
            "**🍓 Pi-агент:**\n"
            "• 24/7 моніторинг навіть коли ПК вимкнено\n"
            "• Speedtest по розкладу\n"
            "• Незалежний MQTT-канал даних\n\n"
            "**🎮 Game Mode:**\n"
            "• Оптимізація QoS, MTU, TCP-tuning для ігор\n\n"
            "**🤖 Telegram-бот:**\n"
            "• /status — поточний стан мережі\n"
            "• /diag — швидка діагностика\n"
            "• Сповіщення про обриви\n\n"
            "Запитай конкретніше — наприклад: "
            "\"Як перезапустити роутер?\" або \"Що з ping?\""
        )

    # ──────────────────────────────────────────────────────────────────
    #  PR #28.2: РОЗУМНІ ВІДПОВІДІ ЗА ТЕМАМИ
    # ──────────────────────────────────────────────────────────────────

    def _answer_tapo(self, context: dict, q: str) -> str:
        """Розумна відповідь про Tapo P110 (живлення роутера).

        PR #28.2: відрізняємо 'не налаштована' від 'нема свіжих даних'.
        Якщо в context tapo.online=True але voltage=0 — це означає що
        SmartAgent ще не зібрав дані, а не що розетка зломана.
        """
        tapo = context.get("tapo") or {}

        # Чітко не налаштована
        if not tapo.get("online") and not tapo.get("ip"):
            return ("🔌 **Tapo P110 ще не додана до утиліти**\n\n"
                    "Це розумна розетка яка моніторить напругу і захищає "
                    "роутер від стрибків живлення.\n\n"
                    "**🛠 Як підключити:**\n"
                    "1. Відкрий вкладку 🔌 **Voltage Guardian**\n"
                    "2. Введи IP розетки (зазвичай 192.168.X.X)\n"
                    "3. Введи логін/пароль від акаунта Tapo (TP-Link)\n"
                    "4. Натисни **Підключитись**\n\n"
                    "Після цього програма буде:\n"
                    "• Показувати графік напруги в реальному часі\n"
                    "• Автоматично вимикати при критичних стрибках\n"
                    "• Дозволяти перезапускати роутер одним кліком")

        volt = tapo.get("voltage", 0) or 0
        watt = tapo.get("power_watts", 0) or 0
        amp = tapo.get("current_amps", 0) or 0
        stab = tapo.get("stability_pct", 100) or 100
        guard = tapo.get("guard_events", 0) or 0
        ip = tapo.get("ip", "—")

        # Особливий випадок: розетка є, але дані нульові — ще не зібралися
        if volt == 0 and watt == 0 and amp == 0:
            return (f"🔌 **Tapo P110 підключена ({ip})**, але свіжих "
                    f"даних ще нема\n\n"
                    f"Можливо причини:\n"
                    f"• Smart-агент щойно стартував — дай йому 30 секунд\n"
                    f"• Розетка тимчасово недоступна по мережі\n"
                    f"• Опитування ще не виконано\n\n"
                    f"**🛠 Як перевірити:**\n"
                    f"1. Зайди у вкладку 🔌 **Voltage Guardian**\n"
                    f"2. Натисни **Оновити вручну**\n"
                    f"3. Якщо там теж 0V — пінганути розетку: "
                    f"Win+R → cmd → `ping {ip}`\n"
                    f"4. Якщо не пінгуєцца — розетка зависла, "
                    f"перезавантаж її кнопкою на корпусі")

        bits = []
        bits.append(f"🔌 **Поточний стан Tapo P110 ({ip}):**\n")
        bits.append(f"• ⚡ Напруга в розетці: **{volt} V**")

        if 220 <= volt <= 240:
            bits.append(f"  └ ✅ Норма для України (220–240V)")
        elif 200 <= volt < 220:
            bits.append(f"  └ 🟡 Нижче норми, але прийнятно "
                        f"(норма від 220V)")
        elif volt < 200:
            bits.append(f"  └ 🔴 Дуже низька напруга — роутер може "
                        f"зависати або перезавантажуватись сам")
        elif 240 < volt <= 250:
            bits.append(f"  └ 🟡 Вище норми, але в межах допустимого")
        else:
            bits.append(f"  └ 🔴 Висока напруга — ризик пошкодження "
                        f"блока живлення роутера!")

        bits.append(f"• 💡 Потужність зараз: **{watt} W**")
        if watt < 1:
            bits.append(f"  └ 🟡 Майже нуль — пристрій або вимкнений, "
                        f"або датчик не оновився")
        elif watt < 15:
            bits.append(f"  └ ✅ Стандартне споживання роутера "
                        f"(зазвичай 5-15 Вт)")
        else:
            bits.append(f"  └ 🟡 Підвищене споживання — є щось ще "
                        f"крім роутера?")

        if watt > 0:
            cost_day = (watt * 24 / 1000) * 4.32  # тариф 4.32 грн/кВт·год
            cost_month = cost_day * 30
            bits.append(f"  └ 💰 За добу = {watt * 24 / 1000:.2f} кВт·год "
                        f"≈ {cost_day:.2f} грн")
            bits.append(f"  └ 💰 За місяць ≈ **{cost_month:.0f} грн** "
                        f"(при тарифі 4.32 грн/кВт·год)")

        if amp > 0:
            bits.append(f"• 🔋 Струм: **{amp} A**")

        bits.append(f"• 📈 Стабільність живлення: **{stab}%**")
        if stab >= 99:
            bits.append(f"  └ ✅ Майже ідеально — стрибки практично "
                        f"відсутні")
        elif stab >= 95:
            bits.append(f"  └ 🟡 Прийнятно — інколи невеликі коливання")
        else:
            bits.append(f"  └ 🔴 Нестабільне живлення — можливі обриви "
                        f"через перезавантаження роутера")

        if guard > 0:
            bits.append(f"\n⚠️ **Захист спрацював {guard} раз(ів)**")
            bits.append(f"Розетка вже {guard} раз вимикала живлення через "
                        f"критичну напругу. Якщо часто — звернись до "
                        f"електрика, можливо потрібен стабілізатор.")

        bits.append(f"\n💡 **Що ще можна:**")
        bits.append(f"• 🔌 Voltage Guardian — графік напруги по годинах")
        bits.append(f"• Натисни **Перезапустити роутер** — Tapo вимкне і "
                    f"увімкне його за 30с (часто рятує від зависань)")
        bits.append(f"• Якщо помітив що інтернет пропадає в один і той же "
                    f"час — глянь графік напруги саме на ту годину, "
                    f"можливо це стрибки в електромережі")

        return "\n".join(bits)

    def _answer_pi(self, context: dict, q: str) -> str:
        """PR #28.2: Розумна відповідь про Pi-агента.

        Не каже "офлайн" якщо просто немає freshness інфи.
        """
        pi = context.get("pi") or {}

        # Чітко не налаштований Pi
        if not pi or (not pi.get("online") and not pi.get("connected")
                      and pi.get("db_records", 0) == 0):
            return ("🍓 **Raspberry Pi-агент не налаштований**\n\n"
                    "Pi-агент — це міні-комп'ютер що стоїть поряд з "
                    "роутером і незалежно перевіряє інтернет 24/7. "
                    "Корисно бо коли твій ПК спить, Pi далі збирає "
                    "статистику.\n\n"
                    "**🛠 Як підключити:**\n"
                    "1. Постав Raspbian + Python 3.11+\n"
                    "2. Скопіюй папку `pi_agent/` з утиліти на Pi\n"
                    "3. Налаштуй MQTT-broker (HiveMQ безкоштовний)\n"
                    "4. Запусти на Pi: `python pi_agent.py`\n"
                    "5. У NetGuardian → 🍓 Дані з Pi → Підключитись")

        # Pi мав хоча б колись активність
        recs = pi.get("db_records", 0) or 0
        is_online_now = pi.get("online", False)
        is_conn = pi.get("connected", False)

        bits = []
        if is_online_now:
            bits.append(f"🍓 **Raspberry Pi-агент online** ✅\n")
        elif is_conn:
            bits.append(f"🍓 **Pi-агент підключений але не відповідає "
                        f"на heartbeat**\n")
        else:
            bits.append(f"🍓 **Pi-агент тимчасово офлайн** (раніше працював)\n")

        if recs > 0:
            bits.append(f"• 📊 Записів у базі: **{recs:,}**")
            days = recs / (60 * 24)
            bits.append(f"  └ Це ~{days:.1f} днів безперервного "
                        f"моніторингу")

        last_st = pi.get("last_speedtest")
        if last_st:
            dl = last_st.get("dl_mbps", 0)
            ul = last_st.get("ul_mbps", 0)
            ts = last_st.get("ts", "?")
            bits.append(f"• 🚀 Останній speedtest: "
                        f"**{dl} ↓ / {ul} ↑ Mbps** ({ts})")

        bits.append(f"\n**🍓 Що Pi дає тобі:**")
        bits.append(f"• Непереривний моніторинг навіть коли ПК спить")
        bits.append(f"• Незалежне джерело даних — якщо твоя машина каже "
                    f"\"інтернету немає\" а Pi каже \"є\", то проблема в ПК")
        bits.append(f"• Історія за всі дні — у 📈 Погода інтернету "
                    f"графіки за тиждень")

        if not is_online_now and recs > 0:
            bits.append(f"\n**🛠 Як повернути Pi онлайн:**")
            bits.append(f"1. Перевір що Pi увімкнений (індикатор)")
            bits.append(f"2. Перевір кабель Ethernet")
            bits.append(f"3. У 🍓 Дані з Pi → **Перепідключити**")

        return "\n".join(bits)

    def _answer_vpn(self, context: dict, q: str) -> str:
        """PR #28.2: відповідь про VPN."""
        vpn = context.get("vpn") or {}

        if not vpn.get("active"):
            return ("🛡️ **VPN зараз не активний**\n\n"
                    "Ти у звичайному інтернеті через свого провайдера. "
                    "VPN — це наче ходити з підробленим паспортом: твій "
                    "справжній IP ховається, сайти бачать IP "
                    "сервера-посередника.\n\n"
                    "**🛡️ Коли VPN корисний:**\n"
                    "1. Розблокувати сайти заблоковані провайдером\n"
                    "2. Бути у публічному Wi-Fi (кафе/готель) безпечно\n"
                    "3. Грати на закордонних серверах\n"
                    "4. Не показувати провайдеру які сайти відвідуєш\n\n"
                    "**🛠 Як увімкнути:**\n"
                    "1. Вкладка 🛡️ **Auto-VPN**\n"
                    "2. Обери провайдера (Radmin/OpenVPN/WireGuard)\n"
                    "3. Натисни **Запустити VPN**")

        ip = vpn.get("ip", "—")
        country = vpn.get("country", "—")
        city = vpn.get("city", "—")
        isp = vpn.get("isp", "—")

        bits = []
        bits.append(f"🛡️ **VPN АКТИВНИЙ** ✅\n")
        bits.append(f"Зараз твій справжній IP захований, сайти бачать ось ці дані:\n")
        bits.append(f"• 🌍 IP: **{ip}**")
        bits.append(f"• 🏳️ Країна: **{country}**")
        if city and city != "—":
            bits.append(f"• 🏙️ Місто: **{city}**")
        if isp and isp != "—":
            bits.append(f"• 🏢 ISP VPN: **{isp}**")

        bits.append(f"\n**💡 Що це означає:**")
        bits.append(f"• Сайти бачать тебе як ніби з **{country}**")
        bits.append(f"• Український провайдер бачить факт VPN-з'єднання, "
                    f"але НЕ бачить які сайти ти відкриваєш")
        bits.append(f"• Швидкість зазвичай на 10-30% нижча через "
                    f"додатковий шлях даних")

        snap = context.get("snapshot") or {}
        ping = snap.get("ping_ms")
        if ping is not None and ping > 0:
            bits.append(f"\n📊 Поточний ping через VPN: **{ping} мс** — "
                        f"{'відмінно' if ping < 50 else 'нормально' if ping < 100 else 'трохи високо для VPN'}")

        return "\n".join(bits)

    def _answer_forecast(self, context: dict, q: str) -> str:
        """PR #28.2: Погода інтернету.

        КРИТИЧНО: відрізняємо реальний 'нема даних' від 'дані є, але
        forecast не повернув'. Якщо fc=={} але pi.db_records>0 або
        snapshot живий — значить дані ТОЧНО збираються.
        """
        fc = context.get("forecast") or {}
        pi = context.get("pi") or {}
        snap = context.get("snapshot") or {}

        has_real_data = (
            fc.get("total_samples", 0) > 0
            or pi.get("db_records", 0) > 0
            or (snap.get("ping_ms") is not None and snap.get("ping_ms") >= 0)
        )

        # Якщо forecast порожній але дані ТОЧНО збираються
        if not fc and has_real_data:
            bits = ["📈 **Збір даних активний** ✅\n"]

            pi_recs = pi.get("db_records", 0) or 0
            if pi_recs > 0:
                days = pi_recs / (60 * 24)
                bits.append(f"🍓 Pi-агент зберіг **{pi_recs:,}** записів "
                            f"(~{days:.1f} днів моніторингу).")

            if snap.get("ping_ms") is not None:
                bits.append(f"📊 Поточний ping: **{snap['ping_ms']} мс**")

            bits.append(f"\n**🤔 Чому AI не показує тижневий аналіз?**")
            bits.append(f"Forecast-engine ще не побудував агрегати — це "
                        f"відбувається раз на годину. Дані у БД є, "
                        f"але аналіз ще не запустився.")

            bits.append(f"\n**🛠 Як побачити графіки прямо зараз:**")
            bits.append(f"1. Відкрий вкладку 📈 **Погода інтернету**")
            bits.append(f"2. Натисни кнопку **Перерахувати** (зверху справа)")
            bits.append(f"3. За 2-3 секунди побачиш графіки і висновки")

            bits.append(f"\n💡 Якщо у вкладці теж порожньо — Pi мабуть "
                        f"щойно почав збір, потрібна година даних щоб "
                        f"був сенс рахувати тренди.")
            return "\n".join(bits)

        # Дійсно нема даних
        if not fc:
            return ("📈 **Погода інтернету ще не зібрана**\n\n"
                    "Програма зберігає історію ping/jitter/обривів і "
                    "робить аналіз тенденцій. Потрібно щоб зібралось "
                    "хоча б годину-дві даних.\n\n"
                    "**🛠 Як почати:**\n"
                    "1. Запусти основний моніторинг (▶ у Dashboard)\n"
                    "2. Залиш утиліту працювати фоном\n"
                    "3. Або краще — постав Pi-агента (моніторить 24/7 "
                    "незалежно від ПК)")

        # Дані є — показуємо повний аналіз
        avg_ping = fc.get("weekly_avg_ping_ms", 0)
        peak_hour = fc.get("peak_hour", "—")
        anomalies = fc.get("anomalies_count", 0)
        sla = fc.get("sla_pct", 100)
        samples = fc.get("total_samples", 0)

        bits = ["📈 **Тижнева погода інтернету:**\n"]

        # SLA
        if sla >= 99.5:
            sla_v = "🟢 відмінно"
            sla_x = "Інтернет працював майже без обривів — >99.5% часу в нормі."
        elif sla >= 98:
            sla_v = "🟢 добре"
            sla_x = ("Стабільний з рідкими короткими збоями — норма для "
                     "домашнього з'єднання.")
        elif sla >= 95:
            sla_v = "🟡 посередньо"
            mins_down = (100 - sla) * 7 * 24 * 60 / 100
            sla_x = (f"Інтернет падав ~{mins_down:.0f} хв за тиждень — "
                     f"1-2 короткі обриви на день.")
        else:
            sla_v = "🔴 погано"
            hrs_down = (100 - sla) * 7 * 24 / 100
            sla_x = (f"Інтернет падав ~{hrs_down:.1f} годин за тиждень — "
                     f"це серйозно, треба скаржитись провайдеру.")

        bits.append(f"• 📊 **SLA: {sla:.1f}%** — {sla_v}")
        bits.append(f"  └ {sla_x}")

        # Avg ping
        bits.append(f"• ⚡ **Середній ping: {avg_ping} мс**")
        if avg_ping < 30:
            bits.append(f"  └ ✅ Швидкий зв'язок — як у людини з оптикою "
                        f"в Києві")
        elif avg_ping < 70:
            bits.append(f"  └ 🟢 Норма для домашнього інтернету в Україні")
        elif avg_ping < 150:
            bits.append(f"  └ 🟡 Повільно — відео ОК, але в іграх лаги")
        else:
            bits.append(f"  └ 🔴 Дуже повільно — пора міняти провайдера "
                        f"або кабель")

        # Peak hour
        if peak_hour and peak_hour != "—":
            bits.append(f"• 🕐 **Найгірша година: {peak_hour}**")
            bits.append(f"  └ Провайдер найбільш завантажений — всі "
                        f"сусіди дивляться YouTube/Netflix. Якщо треба "
                        f"гарантовано стабільний зв'язок (важливий дзвінок) "
                        f"— уникай цієї години.")

        # Anomalies
        if anomalies > 0:
            bits.append(f"• ⚠️ **Аномалій (різких падінь): {anomalies}**")
            if anomalies > 10:
                bits.append(f"  └ 🔴 Багато — глянь у 📈 Погода інтернету "
                            f"графік і відправ скріншот провайдеру")
            elif anomalies > 3:
                bits.append(f"  └ 🟡 Помітно — у графіку видно у яку годину")
            else:
                bits.append(f"  └ ✅ Норма для домашнього інтернету")

        if samples:
            days = samples / (60 * 24)
            bits.append(f"\n📅 Дані за {days:.1f} днів безперервного "
                        f"спостереження ({samples:,} вимірів).")

        return "\n".join(bits)

    def _answer_lan(self, context: dict, q: str) -> str:
        """PR #28.2: розумна відповідь про LAN.

        Якщо security-page не зібрав devices ще — кажемо це чесно
        а НЕ "LAN-сканер не запустився".
        """
        lan = context.get("lan") or {}

        cnt = lan.get("device_count")
        if cnt is None:
            # Спробуємо здогадатись з інших джерел
            snap = context.get("snapshot") or {}
            gw = snap.get("gateway") or ""

            return ("🏠 **LAN-сканер ще не запускався в цій сесії**\n\n"
                    "Утиліта вміє повний скан мережі (ARP, OUI lookup, "
                    "класифікація пристроїв) — просто треба натиснути "
                    "кнопку.\n\n"
                    "**🛠 Як подивитись хто у мережі:**\n"
                    "1. Відкрий вкладку 🛡️ **Security**\n"
                    "2. Натисни **Сканувати мережу**\n"
                    "3. Чекай 10-15 секунд\n"
                    "4. Побачиш список з MAC, IP, виробником і типом\n\n"
                    "_Після цього запитай знов — я зможу проаналізувати "
                    "результати, попередити про нові/підозрілі пристрої._" +
                    (f"\n\nПоточний шлюз: {gw}" if gw else ""))

        new = lan.get("new_devices", 0) or 0
        sus = lan.get("suspicious", 0) or 0

        bits = []
        bits.append(f"🏠 **У твоїй мережі {cnt} пристроїв:**\n")
        bits.append(f"• 📱 Всього виявлено: **{cnt}**")

        if new > 0:
            bits.append(f"• 🆕 Нових (нерозпізнаних): **{new}**")
            bits.append(f"  └ Або щойно підключився, або чужий гаджет. "
                        f"У 🛡️ Security клацни на запис — побачиш "
                        f"MAC-адресу, по виробнику можна визначити "
                        f"(Apple=iPhone, Samsung=Android, тощо).")
        if sus > 0:
            bits.append(f"• 🚨 Підозрілих: **{sus}**")
            bits.append(f"  └ MAC-адреса з невідомого виробника або "
                        f"дивне ім'я. Не обов'язково загроза, але варто "
                        f"перевірити — можливо це твій старий девайс.")

        if cnt > 15:
            bits.append(f"\n💡 **Багато пристроїв ({cnt})** впливає на:")
            bits.append(f"• Швидкість Wi-Fi (канал ділиться)")
            bits.append(f"• Стабільність (кожне з'єднання — навантаження)")
            bits.append(f"\nВідключи старі гаджети які не використовуєш "
                        f"через адмінку роутера (192.168.0.1).")

        return "\n".join(bits)

    def _answer_diagnose(self, context: dict, q: str) -> str:
        """'Чому повільно?' / 'Що не так?'"""
        snap = context.get("snapshot") or {}
        problems = self._detect_problems(snap, context)

        if not problems:
            ping = snap.get("ping_ms")
            bits = ["✅ **За даними утиліти все працює нормально**\n"]
            if ping is not None and ping >= 0:
                v = ("чудовий показник" if ping < 50
                     else "у межах норми" if ping < 100
                     else "трохи високо")
                bits.append(f"Поточний ping = **{ping} мс**, це {v}.")

            bits.append(f"\n**🛠 Якщо все ж щось не так:**")
            bits.append(f"1. Натисни **▶ ДІАГНОСТИКА** — повне сканування "
                        f"(100+ перевірок)")
            bits.append(f"2. Зайди у 📈 **Погода інтернету** — обриви "
                        f"за тиждень")
            bits.append(f"3. Опиши проблему конкретніше: \"відео буферить "
                        f"на YouTube\", \"Steam лагає\", \"сторінки "
                        f"повільно відкриваються\" — дам точніший діагноз")
            return "\n".join(bits)

        bits = ["🔍 **Виявлено можливі причини:**\n"]
        for i, prob in enumerate(problems, 1):
            bits.append(f"\n**{i}. {prob['icon']} {prob['title']}**")
            bits.append(f"   {prob['eli5']}")
            if prob.get('consequence'):
                bits.append(f"   💥 _{prob['consequence']}_")
            if prob.get('steps'):
                bits.append(f"\n   **🛠 Як виправити:**")
                for j, step in enumerate(prob['steps'], 1):
                    bits.append(f"   {j}. {step}")
            if prob.get('verify'):
                bits.append(f"\n   **🧪 Перевірка:** {prob['verify']}")

        return "\n".join(bits)

    def _answer_status(self, context: dict) -> str:
        """Загальний звіт про стан мережі та модулів утиліти.

        PR #28.2: краще відрізняє "офлайн" vs "немає свіжих даних".
        """
        snap = context.get("snapshot") or {}
        vpn = context.get("vpn") or {}
        pi = context.get("pi") or {}
        tapo = context.get("tapo") or {}
        fc = context.get("forecast") or {}

        problems = self._detect_problems(snap, context)
        n_critical = sum(1 for p in problems if p.get('severity') == 'critical')
        n_warning  = sum(1 for p in problems if p.get('severity') == 'warning')

        bits = []
        if n_critical > 0:
            bits.append("🔴 **Є серйозні проблеми з мережею**\n")
        elif n_warning > 0:
            bits.append("🟡 **Мережа працює, але є на що звернути увагу**\n")
        else:
            bits.append("✅ **Усе працює нормально!**\n")

        bits.append("📊 **Поточні показники:**")
        ping = snap.get("ping_ms")
        if ping is not None and ping >= 0:
            v = ("✅ відмінно" if ping < 30
                 else "🟢 норма" if ping < 80
                 else "🟡 повільно" if ping < 200
                 else "🔴 дуже повільно")
            bits.append(f"• Ping: **{ping} мс** — {v}")

        jitter = snap.get("jitter_ms")
        if jitter is not None and jitter > 0:
            jv = ("✅ стабільно" if jitter < 5
                  else "🟡 трохи скаче" if jitter < 20
                  else "🔴 нестабільно")
            bits.append(f"• Jitter: **{jitter} мс** — {jv}")

        loss = snap.get("loss_pct")
        if loss is not None and loss > 0:
            bits.append(f"• Втрата пакетів: **{loss}%** — "
                        f"{'⚠️ є' if loss < 5 else '🔴 серйозна'}")

        isp = snap.get("isp")
        if isp:
            bits.append(f"• Провайдер: **{isp}**")

        wifi = snap.get("wifi_signal_pct")
        if wifi is not None:
            wv = ("✅ відмінний" if wifi > 70
                  else "🟢 норма" if wifi > 50
                  else "🟡 слабкий")
            bits.append(f"• Сигнал Wi-Fi: **{wifi}%** — {wv}")

        bits.append("\n🛠 **Модулі утиліти:**")
        if vpn.get("active"):
            bits.append(f"• 🛡️ VPN: **активний** ({vpn.get('country', '—')})")
        else:
            bits.append(f"• 🛡️ VPN: не активний")

        # PR #28.2: для Pi не пишемо "офлайн" якщо є db_records>0
        pi_recs = pi.get("db_records", 0) or 0
        if pi.get("online"):
            bits.append(f"• 🍓 Pi-агент: **online** ({pi_recs:,} записів)")
        elif pi_recs > 0:
            bits.append(f"• 🍓 Pi-агент: тимч. без зв'язку "
                        f"({pi_recs:,} записів у БД)")
        else:
            bits.append(f"• 🍓 Pi-агент: не налаштований")

        # Tapo: розрізняємо "нема" / "є але 0V" / "OK"
        if tapo.get("online") and (tapo.get("voltage", 0) or 0) > 0:
            bits.append(f"• 🔌 Tapo: **{tapo['voltage']}V**, "
                        f"стабільність {tapo.get('stability_pct', 100)}%")
        elif tapo.get("online") and tapo.get("ip"):
            bits.append(f"• 🔌 Tapo: підключена ({tapo['ip']}), "
                        f"чекає першого опитування")
        elif tapo.get("ip"):
            bits.append(f"• 🔌 Tapo: налаштована ({tapo['ip']}), "
                        f"але зараз недоступна")
        else:
            bits.append(f"• 🔌 Tapo: не додана")

        if fc:
            sla = fc.get("sla_pct", 100)
            bits.append(f"• 📈 Тижневий SLA: **{sla:.1f}%**")
        elif pi_recs > 0:
            bits.append(f"• 📈 Дані для прогнозу збираються "
                        f"({pi_recs:,} записів)")

        if problems:
            bits.append("\n⚠️ **Що варто виправити:**")
            for i, prob in enumerate(problems[:3], 1):
                bits.append(f"\n**{i}. {prob['icon']} {prob['title']}**")
                bits.append(f"   {prob['eli5']}")
                if prob.get('steps'):
                    bits.append(f"   _Виправлення:_ " +
                                " → ".join(prob['steps'][:2]))
            if len(problems) > 3:
                bits.append(f"\n_(і ще {len(problems) - 3} рекомендацій — "
                            f"запитай 'чому повільно?' для повного списку)_")
        else:
            bits.append("\n💡 **Що можна зробити:**")
            bits.append("• **▶ ДІАГНОСТИКА** — повне сканування (100+ перевірок)")
            bits.append("• 📈 **Погода інтернету** — графіки за тиждень")

        return "\n".join(bits)

    # ──────────────────────────────────────────────────────────────────
    #  PR #28: PROBLEM DETECTION ENGINE
    # ──────────────────────────────────────────────────────────────────

    @staticmethod
    def _detect_problems(snap: dict, full_context: dict) -> list:
        """Виявляє конкретні проблеми з контексту і будує детальні
        об'єкти проблем з ELI5-поясненням і кроками виправлення.

        Returns: list of dict з полями:
          icon, severity (critical/warning/info), title, eli5,
          consequence, steps, verify
        """
        problems = []
        snap = snap or {}

        # ── Високий ping ──
        ping = snap.get("ping_ms")
        if ping is not None and ping >= 0:
            if ping > 200:
                problems.append({
                    'icon': '🔴',
                    'severity': 'critical',
                    'title': f'Дуже високий ping ({ping} мс)',
                    'eli5': (f'Ping {ping}мс означає що від твого ПК до '
                             f'інтернет-сервера сигнал йде {ping} '
                             f'мілісекунд. Це як розмовляти через рацію з '
                             f'затримкою — кожне натискання реагує через '
                             f'півсекунди.'),
                    'consequence': ('Сторінки відкриватимуться повільно, в '
                                    'іграх будуть лаги, відеодзвінки '
                                    'зависатимуть.'),
                    'steps': [
                        'Підійди ближче до роутера (якщо Wi-Fi)',
                        ('Перевір чи хтось не вантажить інтернет — '
                         'наприклад торрентами або streaming'),
                        ('Натисни Win+R → введи cmd → введи: '
                         '`ipconfig /release && ipconfig /renew`'),
                        ('Якщо не допомогло — перезапусти роутер '
                         '(вийми з розетки на 30 секунд)'),
                    ],
                    'verify': ('Натисни ▶ ДІАГНОСТИКА у NetGuardian — '
                               'ping має впасти нижче 100мс'),
                })
            elif ping > 100:
                problems.append({
                    'icon': '🟡',
                    'severity': 'warning',
                    'title': f'Підвищений ping ({ping} мс)',
                    'eli5': (f'Ping {ping}мс — це повільніше ніж "норма" '
                             f'для України (~30-70мс). Для серфінгу і '
                             f'відео це ок, але для ігор буде помітно.'),
                    'steps': [
                        'Перейди на 5GHz Wi-Fi (якщо роутер підтримує)',
                        ('Закрий фонові программи що можуть качати дані '
                         '(Steam, Windows Update, OneDrive)'),
                        'Перевір кількість підключених до Wi-Fi пристроїв',
                    ],
                    'verify': 'Запусти ▶ ДІАГНОСТИКА — ping має впасти',
                })

        # ── Втрата пакетів ──
        loss = snap.get("loss_pct", 0) or 0
        if loss > 10:
            problems.append({
                'icon': '🔴',
                'severity': 'critical',
                'title': f'Серйозна втрата пакетів ({loss}%)',
                'eli5': (f'Втрата пакетів {loss}% означає що з кожних 10 '
                         f'твоїх запитів {int(loss / 10)} губляться по '
                         f'дорозі. Це як кидати листи в поштову скриньку, '
                         f'але до адресата доходить тільки {100-loss}%.'),
                'consequence': ('Сторінки можуть не повністю завантажуватись, '
                                'у відеодзвінках перериватиметься звук, '
                                'у іграх постійні \"стрибки\" персонажа.'),
                'steps': [
                    ('Перевір фізичний кабель Ethernet — чи не пошкоджений, '
                     'чи щільно встромлений'),
                    'Якщо через Wi-Fi — підійди ближче до роутера',
                    ('Перезапусти роутер (вимкнути з розетки на 30 секунд)'),
                    ('Зателефонуй провайдеру і скажи "у мене втрата '
                     'пакетів X%" — це їх обов\'язок розібратись'),
                ],
                'verify': ('Запусти ▶ ДІАГНОСТИКА. У звіті має бути '
                           '0% втрат до Cloudflare і Google.'),
            })
        elif loss > 2:
            problems.append({
                'icon': '🟡',
                'severity': 'warning',
                'title': f'Невелика втрата пакетів ({loss}%)',
                'eli5': (f'З кожних 100 запитів губиться {loss} — у '
                         f'повсякденному використанні непомітно, але в '
                         f'іграх і VoIP можуть бути дрібні \"шумові\" збої.'),
                'steps': [
                    'Перейди на провідний Ethernet якщо можливо',
                    'Перевір чи нема перешкод між тобою і роутером (стіни)',
                ],
                'verify': 'Запусти ▶ ДІАГНОСТИКА — втрата має впасти до 0',
            })

        # ── Високий jitter ──
        jitter = snap.get("jitter_ms", 0) or 0
        if jitter > 30:
            problems.append({
                'icon': '🔴',
                'severity': 'critical',
                'title': f'Дуже нестабільне з\'єднання (jitter {jitter}мс)',
                'eli5': (f'Jitter {jitter}мс — це сильні стрибки часу '
                         f'відгуку. То 10мс, то 50мс — нестабільно. Це як '
                         f'автомобіль що то прискорюється, то різко гальмує.'),
                'consequence': ('Відеодзвінки дратівливо булькатимуть, '
                                'голосовий чат у Discord/іграх перериватиметься.'),
                'steps': [
                    'Перейди на Ethernet-кабель замість Wi-Fi',
                    'Перевір чи у твоїй мережі немає сильних завад '
                    '(інші Wi-Fi мережі на тому самому каналі)',
                    'У налаштуваннях роутера → Wi-Fi → канал → постав '
                    'один з 1, 6 або 11 (для 2.4GHz)',
                ],
                'verify': 'Зроби тестовий дзвінок у Discord — звук має '
                          'бути стабільним',
            })
        elif jitter > 10:
            problems.append({
                'icon': '🟡',
                'severity': 'warning',
                'title': f'Нестабільне з\'єднання (jitter {jitter}мс)',
                'eli5': (f'Затримка стрибає на ±{jitter}мс — це помітно у '
                         f'real-time активностях (Discord-дзвінки, ігри).'),
                'steps': [
                    'Скоротити кількість активних Wi-Fi пристроїв',
                    'Перейти ближче до роутера або на 5GHz',
                ],
                'verify': 'Подивись Jitter у ▶ ДІАГНОСТИКА — має впасти '
                          'нижче 5мс',
            })

        # ── Слабкий Wi-Fi сигнал ──
        wifi = snap.get("wifi_signal_pct")
        if wifi is not None and wifi < 40:
            problems.append({
                'icon': '🔴',
                'severity': 'critical',
                'title': f'Дуже слабкий Wi-Fi сигнал ({wifi}%)',
                'eli5': (f'Сигнал Wi-Fi всього {wifi}% — це як кричати '
                         f'через дві кімнати, чують погано. Через це і '
                         f'швидкість падає, і обриви часті.'),
                'steps': [
                    'Підійди ближче до роутера',
                    'Прибери перешкоди між собою і роутером (стіни, '
                    'мікрохвильовка, металеві предмети)',
                    'Якщо роутер у далекій кімнаті — постав Wi-Fi '
                    'extender або mesh-точку',
                ],
                'verify': 'Подивись %% сигналу у NetGuardian — має бути >60%',
            })
        elif wifi is not None and wifi < 60:
            problems.append({
                'icon': '🟡',
                'severity': 'warning',
                'title': f'Посередній Wi-Fi сигнал ({wifi}%)',
                'eli5': f'Сигнал {wifi}% — працює, але є запас для покращення.',
                'steps': ['Перейди на 5GHz якщо роутер підтримує — там '
                          'менше завад'],
                'verify': 'Сигнал у NetGuardian',
            })

        # ── Tapo критичні події ──
        tapo = full_context.get("tapo") or {}
        if tapo.get("guard_events", 0) > 0:
            problems.append({
                'icon': '⚡',
                'severity': 'warning',
                'title': f'Захист Tapo спрацював {tapo["guard_events"]} раз(ів)',
                'eli5': ('Розумна розетка вимикала живлення роутера через '
                         'критичну напругу — це може ламати інтернет.'),
                'steps': [
                    'Зайди у 🔌 Voltage Guardian → побачиш графік напруги',
                    'Якщо напруга часто стрибає — звернись до електрика',
                    'Розглянь покупку стабілізатора напруги',
                ],
                'verify': 'Спостерігай за графіком напруги наступні дні',
            })

        volt = tapo.get("voltage", 0) or 0
        if 0 < volt < 200:
            problems.append({
                'icon': '🔴',
                'severity': 'critical',
                'title': f'Дуже низька напруга ({volt}V)',
                'eli5': ('Норма для України — 220V±10% (від 198 до 242V). '
                         f'У тебе {volt}V — це нижче норми. Роутер може '
                         f'зависати або перезавантажуватись.'),
                'consequence': 'Обриви інтернету, перезавантаження роутера',
                'steps': [
                    'Зверніться до сусідів — чи у них теж низька напруга?',
                    'Якщо так — це проблема магістралі, дзвоніть в '
                    'енергопостачальну компанію',
                    'Якщо тільки у вас — електрик має перевірити '
                    'квартирну проводку',
                ],
                'verify': 'Графік напруги у 🔌 Voltage Guardian',
            })

        # ── Останні діагностики критичні ──
        rd = full_context.get("recent_diagnostics") or {}
        if rd.get("critical_count", 0) > 0:
            problems.append({
                'icon': '🩺',
                'severity': 'warning',
                'title': f'У минулій діагностиці знайдено '
                         f'{rd["critical_count"]} критичних проблем',
                'eli5': ('Остання сесія діагностики закінчилась з '
                         'червоними прапорцями. Деталі — у Diagnostics.'),
                'steps': [
                    'Зайди у 🩺 Діагностика → подивись список знайдених проблем',
                    'Для кожної критичної проблеми є кнопка "🔧 Виправити"',
                ],
                'verify': 'Запусти діагностику знов — критичних має не бути',
            })

        # ── Багато аномалій за тиждень ──
        fc = full_context.get("forecast") or {}
        if fc.get("anomalies_count", 0) > 10:
            problems.append({
                'icon': '📊',
                'severity': 'warning',
                'title': f'За тиждень {fc["anomalies_count"]} аномалій',
                'eli5': ('Інтернет регулярно \"моргає\" — короткі стрибки '
                         'пінгу або обриви. Це системна проблема, не разова.'),
                'steps': [
                    'Зайди у 📈 Погода інтернету → подивись на якій годині '
                    'найбільше аномалій',
                    'Якщо у вечірній час — це перевантаження провайдера',
                    'Якщо випадково — проблема з фізичним кабелем',
                    'Зробіть скріншот і відправте провайдеру з вимогою '
                    'розібратися',
                ],
                'verify': 'Спостерігайте кілька днів — кількість аномалій '
                          'має падати',
            })

        return problems

    @staticmethod
    def _format_extra_context(context: dict) -> str:
        """PR #25: Форматує VPN/Pi/Tapo state для KB-відповіді."""
        bits = []

        vpn = context.get("vpn") or {}
        if vpn.get("active"):
            bits.append(f"🛡️ VPN активний: {vpn.get('country', '?')} "
                        f"({vpn.get('ip', '?')})")

        pi = context.get("pi") or {}
        if pi.get("online"):
            recs = pi.get("db_records", 0)
            bits.append(f"🍓 Pi-агент online ({recs} записів у БД)")

        tapo = context.get("tapo") or {}
        if tapo.get("online") and tapo.get("voltage"):
            volt = tapo.get("voltage", 0)
            stab = tapo.get("stability_pct", 100)
            bits.append(f"🔌 Tapo: {volt}V, стабільність {stab}%")

        diag = context.get("recent_diagnostics") or {}
        if diag and (diag.get("critical_count", 0) + diag.get("warnings_count", 0)) > 0:
            bits.append(f"⚠️ Остання діагностика: "
                        f"{diag.get('critical_count', 0)} критичних, "
                        f"{diag.get('warnings_count', 0)} попереджень")

        forecast = context.get("forecast") or {}
        if forecast.get("anomalies_count", 0) > 0:
            bits.append(f"📊 За тиждень: {forecast['anomalies_count']} аномалій, "
                        f"SLA {forecast.get('sla_pct', 100):.1f}%")

        if bits:
            return "📋 **Поточний стан утиліти:**\n" + "\n".join(f"• {b}" for b in bits)
        return ""

    @staticmethod
    def _analyze_context_locally(snap: dict) -> str:
        """Локальний rule-based аналіз снапшоту мережі.

        Повертає короткий висновок без AI: "ping ОК, jitter високий" тощо.
        """
        if not snap: return ""
        bits = []
        ping = snap.get("ping_ms")
        if ping is not None:
            if ping < 0:
                bits.append("• ❌ Ping недоступний — мережа лежить")
            elif ping < 30:
                bits.append(f"• ✅ Ping={ping}мс — відмінно")
            elif ping < 100:
                bits.append(f"• 🟢 Ping={ping}мс — добре")
            elif ping < 200:
                bits.append(f"• 🟡 Ping={ping}мс — помірно повільно")
            else:
                bits.append(f"• 🔴 Ping={ping}мс — повільно")

        jitter = snap.get("jitter_ms")
        if jitter is not None and jitter > 0:
            if jitter < 5:
                pass  # норм, не пишемо
            elif jitter < 30:
                bits.append(f"• 🟡 Jitter={jitter}мс — мережа нестабільна")
            else:
                bits.append(f"• 🔴 Jitter={jitter}мс — сильні стрибки")

        loss = snap.get("loss_pct")
        if loss is not None and loss > 0:
            bits.append(f"• 🔴 Втрата пакетів={loss}% — серйозна проблема")

        wifi_pct = snap.get("wifi_signal_pct")
        if wifi_pct is not None:
            if wifi_pct < 40:
                bits.append(f"• 🔴 Wi-Fi сигнал={wifi_pct}% — слабкий")
            elif wifi_pct < 60:
                bits.append(f"• 🟡 Wi-Fi сигнал={wifi_pct}% — посередній")

        # PR #27: ВИДАЛЕНО хибний висновок про "інтернет недоступний"
        # коли public_ip не зібрано — це часто означає просто що
        # snapshot dashboard ще не завершився, а не реальну відсутність
        # інтернету. Не плодимо misinformation.

        return "\n".join(bits) if bits else ""

    # ──────────────────────────────────────────────────────────────────
    #  ANALYZE DIAGNOSTICS — для Diagnostics Page
    # ──────────────────────────────────────────────────────────────────

    def analyze_diagnostics(self, rule_data: dict) -> dict:
        """Аналізує діагностику.

        1. Якщо інтернет є — Gemini analyze_network()
        2. Інакше — локальний rule-based аналіз з KB
        """
        # ── СПРОБА 1: Gemini ──────────────────────────────────────
        if is_internet_available():
            try:
                from app.core.gemini_client import get_gemini_client
                client = get_gemini_client()
                if client.is_available():
                    result = client.analyze_network(rule_data)
                    if result.get("success"):
                        result["source"] = "gemini"
                        self._last_source = "gemini"
                        return result
            except Exception as e:
                print(f"[HybridAI] Gemini analyze failed: {e}")
                self._last_error = str(e)

        # ── СПРОБА 2: KB fallback ────────────────────────────────
        result = self._kb_analyze_diagnostics(rule_data)
        result["source"] = "knowledge_base"
        self._last_source = "knowledge_base"
        return result

    def _kb_analyze_diagnostics(self, rule_data: dict) -> dict:
        """Аналіз діагностики через KB (без AI)."""
        try:
            from app.core.knowledge_base import search_kb, get_by_symptoms
        except ImportError:
            return {
                "success": False,
                "error": "KB не доступна",
                "source": "knowledge_base",
                "summary": "", "good": [], "warnings": [],
                "critical": [], "tips": [], "fixes": [],
                "overall": "",
            }

        issues = rule_data.get("issues", [])
        raw = rule_data.get("raw", {})

        good, warnings, critical, tips, fixes = [], [], [], [], []

        # 1. Аналізуємо сирі дані
        ping_gw = raw.get("ping_gw", "")
        ping_cf = raw.get("ping_cf", "")

        # Парсимо ping (формат "20.5мс / 0%")
        def parse_ping(s):
            try:
                if isinstance(s, dict): return s.get("avg_ms"), s.get("loss_pct")
                if not s or s == "?": return None, None
                parts = str(s).split("/")
                ms = float(parts[0].replace("мс", "").strip()) if parts else None
                loss = float(parts[1].replace("%", "").strip()) if len(parts) > 1 else 0
                return ms, loss
            except Exception:
                return None, None

        gw_ms, gw_loss = parse_ping(ping_gw)
        cf_ms, cf_loss = parse_ping(ping_cf)

        if gw_ms is not None and gw_ms < 5 and (gw_loss or 0) < 1:
            good.append(f"✅ Локальна мережа працює відмінно (ping шлюзу {gw_ms:.1f}мс)")
        elif gw_ms is not None and gw_ms > 50:
            warnings.append(f"🟡 Високий ping до шлюзу: {gw_ms:.1f}мс — можлива проблема Wi-Fi")

        if cf_ms is not None and cf_ms < 50 and (cf_loss or 0) < 1:
            good.append(f"✅ Інтернет стабільний (ping Cloudflare {cf_ms:.1f}мс)")
        elif cf_ms is None or (cf_loss or 0) > 50:
            critical.append("🔴 Інтернет недоступний або серйозні втрати")
        elif cf_ms is not None and cf_ms > 200:
            warnings.append(f"🟡 Повільний інтернет ({cf_ms:.0f}мс до Cloudflare)")

        wifi = raw.get("wifi_primary", False)
        if wifi:
            good.append("✅ Wi-Fi підключення активне")

        # 2. Для кожного знайденого rule-issue шукаємо у KB
        for issue in issues[:5]:
            code = issue.code if hasattr(issue, "code") else issue.get("code", "")
            title = issue.title if hasattr(issue, "title") else issue.get("title", "")
            sev = issue.sev if hasattr(issue, "sev") else issue.get("sev", "INFO")

            # Шукаємо в KB
            kb_results = search_kb(title or code, limit=2)
            if kb_results:
                entry = kb_results[0]
                if entry.solutions:
                    tips.extend(entry.solutions[:2])
                if entry.auto_fix:
                    fixes.append({
                        "id": entry.auto_fix,
                        "label": entry.title[:50],
                        "command": "",   # буде підставлено з AUTO_FIX_LIBRARY
                        "reason": entry.causes[0] if entry.causes else "",
                        "risk": "low" if sev == "INFO" else "medium",
                    })

            if sev == "CRITICAL":
                critical.append(f"🔴 {title}")
            elif sev == "WARNING":
                warnings.append(f"🟡 {title}")

        # 3. Загальний висновок
        overall = "good"
        if critical:
            overall = "critical"
        elif warnings:
            overall = "warning"
        elif len(good) >= 3:
            overall = "excellent"

        # 4. Summary
        if overall == "excellent":
            summary = "Мережа працює відмінно — всі основні параметри в нормі."
        elif overall == "good":
            summary = "Мережа працює нормально, серйозних проблем немає."
        elif overall == "warning":
            summary = (f"Знайдено {len(warnings)} помірних проблем. "
                       f"Рекомендую виправити для кращого досвіду.")
        else:
            summary = (f"❌ Виявлено {len(critical)} критичних проблем. "
                       f"Рекомендую негайно діяти.")

        # Унікалізуємо tips
        tips = list(dict.fromkeys(tips))[:6]

        return {
            "success": True,
            "summary": summary,
            "good": good,
            "warnings": warnings,
            "critical": critical,
            "tips": tips,
            "fixes": fixes,
            "overall": overall,
            "raw_text": "(Локальна база знань — без AI)",
            "error": "",
        }


# ══════════════════════════════════════════════════════════════════════
#  SINGLETON
# ══════════════════════════════════════════════════════════════════════

_GLOBAL_HYBRID: Optional[HybridAIClient] = None


def get_hybrid_client() -> HybridAIClient:
    """Повертає глобальний HybridAIClient."""
    global _GLOBAL_HYBRID
    if _GLOBAL_HYBRID is None:
        _GLOBAL_HYBRID = HybridAIClient()
    return _GLOBAL_HYBRID