"""
app/core/gemini_client.py
─────────────────────────
Універсальний клієнт для роботи з Google Gemini API.

PR #26 fix: підняв max_output_tokens до 8192 (max для Gemini 2.0 Flash),
бо коли hybrid_ai додає повний контекст утиліти (~3KB markdown),
відповідь обривалася посередині на старому ліміті 800/1500 токенів.

ВИКОРИСТАННЯ:
    from app.core.gemini_client import GeminiClient

    client = GeminiClient()           # читає GEMINI_API_KEY з env
    if client.is_available():
        result = client.analyze_network(diagnostics_json)
        print(result["summary"])

КЛЮЧ:
    Отримати на https://aistudio.google.com/apikey (безкоштовно).
    Зберегти в одному з місць (Claude шукає в порядку):
      1. env-змінна GEMINI_API_KEY
      2. файл ~/.netguardian/ai_config.json: {"gemini_api_key": "..."}
      3. передати в конструктор GeminiClient(api_key="...")

ЛІМІТИ free tier:
    • 15 RPM (запитів на хвилину)
    • 1500 запитів на день
    • 1M токенів на день
Для NetGuardian — більш ніж достатньо.
"""

import json
import os
import time
from pathlib import Path
from typing import Optional


# Шлях до конфігу (нешифрований локальний)
CONFIG_DIR  = Path.home() / ".netguardian"
CONFIG_PATH = CONFIG_DIR / "ai_config.json"

# Дефолтна модель — Gemini 2.0 Flash (швидка + безкоштовна)
DEFAULT_MODEL = "gemini-2.0-flash"

# Скільки секунд кешуємо результат (щоб не палити квоту на однакові запити)
CACHE_TTL_SEC = 60

# PR #28.1: ліміти токенів зменшено щоб економити денну квоту 1M токенів.
# 3000 цілком вистачає для розумної markdown-відповіді з 4-6 пунктами.
# Якщо потрібно більше — підняти знов до 8192.
MAX_TOKENS_ANALYZE = 3000   # було 8192
MAX_TOKENS_CHAT    = 3000   # було 8192

# PR #28.1: коли отримуємо 429/quota — блокуємо Gemini на цей час
# щоб не мучити користувача безглуздими retry та довгими очікуваннями.
QUOTA_LOCKOUT_SEC = 300   # 5 хвилин


class GeminiClient:
    """Клієнт для Google Gemini API.

    Має вбудовані:
      • Кеш (60с) — щоб не дублювати запити
      • Retry з exponential backoff на rate-limit
      • Graceful fallback якщо ключа немає або API недоступне
      • PR #26: детекція finish_reason=MAX_TOKENS для діагностики обривів
    """

    def __init__(self,
                 api_key: Optional[str] = None,
                 model:   str = DEFAULT_MODEL):
        self.model_name = model
        self.api_key    = api_key or self._load_api_key()
        self._model     = None
        self._last_error: str = ""

        # Кеш: prompt_hash → (result_dict, timestamp)
        self._cache: dict = {}

        # PR #28.1: timestamp до якого Gemini "замкнено" через quota
        # exhausted (429). Доки now < цього значення — is_available()
        # повертає False, fallback одразу йде на локальну AI.
        self._quota_locked_until: float = 0.0

        if self.api_key:
            self._init_model()

    # PR #28.1: метод для перевірки чи зараз quota lockout активний
    def is_quota_locked(self) -> tuple:
        """Чи Gemini зараз заблокований через вичерпану квоту.

        Returns: (locked: bool, seconds_until_unlock: int)
        """
        now = time.time()
        if now < self._quota_locked_until:
            return True, int(self._quota_locked_until - now)
        return False, 0

    def _trigger_quota_lockout(self):
        """PR #28.1: блокує Gemini на 5 хв після 429 errror."""
        self._quota_locked_until = time.time() + QUOTA_LOCKOUT_SEC
        self._last_error = "quota_exhausted"
        print(f"[Gemini] ⛔ Quota вичерпано — блокую на "
              f"{QUOTA_LOCKOUT_SEC}с щоб не мучити юзера retry-ами. "
              f"Поки що — fallback на локальну AI.")

    # ── Завантаження ключа з різних джерел ─────────────────────────
    def _load_api_key(self) -> str:
        # 1. env-змінна (найвищий пріоритет)
        key = os.environ.get("GEMINI_API_KEY", "").strip()
        if key:
            return key
        # 2. файл ~/.netguardian/ai_config.json
        try:
            if CONFIG_PATH.exists():
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
                    return config.get("gemini_api_key", "").strip()
        except Exception as e:
            print(f"[Gemini] config read error: {e}")
        return ""

    def save_api_key(self, key: str) -> bool:
        """Зберігає ключ у локальний конфіг (і одразу ініціалізує модель)."""
        try:
            CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            config = {}
            if CONFIG_PATH.exists():
                with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                    config = json.load(f)
            config["gemini_api_key"] = key.strip()
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            self.api_key = key.strip()
            self._init_model()
            return True
        except Exception as e:
            print(f"[Gemini] save_api_key error: {e}")
            self._last_error = str(e)
            return False

    def _init_model(self):
        """Ініціалізує SDK і модель."""
        try:
            import google.generativeai as genai
            genai.configure(api_key=self.api_key)
            self._model = genai.GenerativeModel(self.model_name)
            print(f"[Gemini] ✅ Model {self.model_name} ready "
                  f"(max_tokens analyze={MAX_TOKENS_ANALYZE}, "
                  f"chat={MAX_TOKENS_CHAT})")
        except ImportError:
            self._last_error = ("google-generativeai не встановлено. "
                                "Виконай: pip install google-generativeai")
            print(f"[Gemini] ⚠️ {self._last_error}")
            self._model = None
        except Exception as e:
            self._last_error = str(e)
            print(f"[Gemini] ⚠️ init failed: {e}")
            self._model = None

    # ── Публічний API ─────────────────────────────────────────────
    def is_available(self) -> bool:
        """Чи готовий клієнт робити запити (є ключ + модель + не quota lockout)."""
        if self._model is None or not self.api_key:
            return False
        # PR #28.1: під час quota lockout відмовляємо одразу
        locked, secs = self.is_quota_locked()
        if locked:
            print(f"[Gemini] ⛔ quota lockout активний ще {secs}с — "
                  f"повертаю is_available=False")
            return False
        return True

    def get_last_error(self) -> str:
        return self._last_error

    def test_connection(self) -> tuple:
        """Робить тестовий запит до API.

        Returns: (success, message)
        """
        if not self.api_key:
            return False, "API-ключ не вказано"
        if not self._model:
            return False, f"Модель не ініціалізовано: {self._last_error}"
        try:
            r = self._model.generate_content(
                "Reply with exactly the text: OK",
                generation_config={"max_output_tokens": 10})
            text = (r.text or "").strip()
            if text:
                return True, f"З'єднання працює (модель: {self.model_name})"
            return False, "Пуста відповідь від API"
        except Exception as e:
            err = str(e)
            self._last_error = err
            if "API_KEY_INVALID" in err or "401" in err:
                return False, "Невірний API-ключ"
            if "quota" in err.lower() or "429" in err:
                return False, "Перевищено ліміт запитів (зачекай 1 хв)"
            return False, f"Помилка: {err[:200]}"

    # ── PR #27.1: Threading-based timeout (працює з будь-яким SDK) ──
    @staticmethod
    def _call_with_timeout(func, timeout_sec: float, *args, **kwargs):
        """Викликає func з timeout у секундах.

        PR #27.1: робимо власний timeout через threading.Thread + Queue
        бо параметр request_options у google-generativeai SDK
        підтримується тільки у 0.3+, а у старіших версіях кидає
        TypeError що ламало весь Gemini.

        Якщо func не завершиться за timeout_sec — кидаємо TimeoutError.
        Background thread залишається daemon — якщо API колись повернеться,
        результат просто ігнорується.
        """
        import threading
        import queue as _queue

        result_q = _queue.Queue(maxsize=1)

        def _worker():
            try:
                result_q.put(("ok", func(*args, **kwargs)))
            except Exception as e:
                result_q.put(("err", e))

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        try:
            kind, val = result_q.get(timeout=timeout_sec)
        except _queue.Empty:
            raise TimeoutError(
                f"Gemini API не відповів за {timeout_sec}с — "
                f"скоріше за все нема інтернету"
            )
        if kind == "ok":
            return val
        # exception у worker — пробросимо
        raise val

    # ── PR #26: Helper для детекції truncation ────────────────────
    @staticmethod
    def _check_truncation(response) -> tuple:
        """Перевіряє чи відповідь обрізалась через MAX_TOKENS.

        Returns: (is_truncated: bool, reason: str)

        Gemini SDK повертає finish_reason у candidates[0].finish_reason:
            STOP = 1            ✅ нормальне завершення
            MAX_TOKENS = 2      ❌ обрізалось через ліміт
            SAFETY = 3          ❌ заблоковано фільтром безпеки
            RECITATION = 4      ❌ заблоковано через цитування
            OTHER = 5           ❌ інша причина
        """
        try:
            candidates = getattr(response, "candidates", None) or []
            if not candidates:
                return False, "no_candidates"
            fr = getattr(candidates[0], "finish_reason", None)
            if fr is None:
                return False, "no_finish_reason"
            # Може бути enum або int
            fr_value = getattr(fr, "value", fr)
            fr_name  = getattr(fr, "name", str(fr_value))
            if fr_value == 2 or "MAX_TOKENS" in str(fr_name).upper():
                return True, "MAX_TOKENS"
            return False, str(fr_name)
        except Exception:
            return False, "check_failed"

    # ── ОСНОВНИЙ МЕТОД: аналіз мережевих метрик ───────────────────
    def analyze_network(self, diagnostics_data: dict,
                         language: str = "uk") -> dict:
        """Інтерпретує дані діагностики як AI-експерт.

        PR #26: max_output_tokens піднято до 8192. Раніше при великому
        контексті JSON обривався на середині поля 'summary'.
        """
        if not self.is_available():
            return {
                "success": False,
                "error": "AI недоступне. Перевір API-ключ у Налаштуваннях.",
                "summary": "", "good": [], "warnings": [],
                "critical": [], "tips": [], "overall": "",
            }

        prompt = self._build_prompt(diagnostics_data, language)

        # Кеш — якщо такий же prompt був <60с тому, повертаємо cached
        cache_key = hash(prompt)
        if cache_key in self._cache:
            cached_data, cached_ts = self._cache[cache_key]
            if time.time() - cached_ts < CACHE_TTL_SEC:
                print("[Gemini] 💾 cache hit")
                return cached_data

        # PR #26: лог розміру promt'у для діагностики
        prompt_chars = len(prompt)
        print(f"[Gemini] 📤 analyze_network: prompt {prompt_chars} chars "
              f"(~{prompt_chars // 4} токенів)")

        # Запит з retry
        for attempt in range(3):
            try:
                # PR #27.1: threading-based timeout (не залежить від версії SDK)
                response = self._call_with_timeout(
                    self._model.generate_content, 20,
                    prompt,
                    generation_config={
                        "temperature": 0.3,    # консервативно (не вигадує)
                        "max_output_tokens": MAX_TOKENS_ANALYZE,  # PR #26: 8192
                        "response_mime_type": "application/json",
                    },
                )
                # PR #26: перевіряємо чи не обрізалось
                is_truncated, fr_name = self._check_truncation(response)
                if is_truncated:
                    print(f"[Gemini] ⚠️ Відповідь обрізана через "
                          f"{fr_name}! Спробуй зменшити контекст або "
                          f"підняти MAX_TOKENS_ANALYZE.")
                    self._last_error = f"truncated by {fr_name}"

                text = (response.text or "").strip()
                if not text:
                    raise RuntimeError("Empty response from Gemini")

                # PR #26: лог розміру відповіді
                resp_chars = len(text)
                print(f"[Gemini] 📥 response: {resp_chars} chars "
                      f"finish={fr_name}")

                # Парсимо JSON
                try:
                    parsed = json.loads(text)
                except json.JSONDecodeError as je:
                    # Іноді AI може обернути JSON у ```json ... ```
                    cleaned = text.strip()
                    if cleaned.startswith("```"):
                        # Видаляємо markdown code fences
                        lines = cleaned.split("\n")
                        cleaned = "\n".join(lines[1:-1])
                    try:
                        parsed = json.loads(cleaned)
                    except json.JSONDecodeError:
                        # PR #26: якщо обрізаний JSON — пробуємо
                        # витягнути хоча б summary
                        if is_truncated:
                            partial = self._extract_partial_json(text)
                            if partial:
                                print(f"[Gemini] ✂️ Витягли частковий JSON "
                                      f"з обрізаної відповіді")
                                parsed = partial
                            else:
                                raise je
                        else:
                            raise je

                result = {
                    "success":  True,
                    "summary":  parsed.get("summary",  ""),
                    "good":     parsed.get("good",     []),
                    "warnings": parsed.get("warnings", []),
                    "critical": parsed.get("critical", []),
                    "tips":     parsed.get("tips",     []),
                    "overall":  parsed.get("overall",  "good"),
                    "raw_text": text,
                    "error":    "",
                }
                # PR #26: якщо було truncation — додаємо warning у відповідь
                if is_truncated:
                    result["truncated"] = True
                    result["warnings"] = list(result["warnings"]) + [
                        "⚠️ AI-відповідь могла бути неповною через "
                        "великий обсяг даних"]

                # Кешуємо
                self._cache[cache_key] = (result, time.time())
                return result

            except Exception as e:
                err = str(e)
                err_low = err.lower()
                self._last_error = err
                print(f"[Gemini] attempt {attempt+1} failed: {err[:200]}")

                # PR #28.1: Quota — не retry, одразу lockout та exit
                if ("quota" in err_low or "429" in err or
                        "exceeded" in err_low):
                    self._trigger_quota_lockout()
                    return {
                        "success": False,
                        "error":   "Quota exhausted",
                        "summary": "", "good": [], "warnings": [],
                        "critical": [], "tips": [], "overall": "",
                    }
                # Інші помилки — короткий backoff
                time.sleep(2 ** attempt)        # 1s, 2s, 4s

        # Усі retry провалились
        return {
            "success": False,
            "error":   f"AI недоступне після 3 спроб: {self._last_error[:200]}",
            "summary": "", "good": [], "warnings": [],
            "critical": [], "tips": [], "overall": "",
        }

    @staticmethod
    def _extract_partial_json(text: str) -> dict:
        """PR #26: Пробує витягти summary/good/warnings з обрізаного JSON.

        Коли Gemini обриває JSON посередині — наприклад:
            {"summary": "Все добре", "good": ["✅ Інтернет", "✅ DNS
        Знаходимо завершені поля до точки обриву і повертаємо їх.
        """
        import re
        result = {}

        # Витягуємо summary (звичайний рядок)
        m = re.search(r'"summary"\s*:\s*"((?:[^"\\]|\\.)*)"', text)
        if m:
            try:
                # json.loads щоб правильно обробити escape-послідовності
                result["summary"] = json.loads(f'"{m.group(1)}"')
            except Exception:
                result["summary"] = m.group(1)

        # Витягуємо списки good/warnings/critical/tips
        for field in ("good", "warnings", "critical", "tips"):
            # Шукаємо "field": [ ... ] — навіть якщо незакритий
            pattern = rf'"{field}"\s*:\s*\[(.*?)(?:\]|$)'
            m = re.search(pattern, text, re.DOTALL)
            if m:
                items_text = m.group(1)
                # Витягуємо завершені рядки в лапках
                items = re.findall(r'"((?:[^"\\]|\\.)*)"\s*(?:,|$)', items_text)
                cleaned_items = []
                for it in items:
                    try:
                        cleaned_items.append(json.loads(f'"{it}"'))
                    except Exception:
                        cleaned_items.append(it)
                if cleaned_items:
                    result[field] = cleaned_items

        # Витягуємо overall
        m = re.search(r'"overall"\s*:\s*"(\w+)"', text)
        if m:
            result["overall"] = m.group(1)

        return result if result else {}

    # ── Побудова prompt'у для Gemini ──────────────────────────────
    def _build_prompt(self, data: dict, language: str) -> str:
        """Будує prompt для Gemini з даних діагностики."""
        issues_list = []
        for issue in data.get("issues", []):
            # issue може бути або dataclass Issue, або dict
            if hasattr(issue, "__dict__"):
                i = {
                    "code":  getattr(issue, "code", ""),
                    "sev":   getattr(issue, "sev", ""),
                    "title": getattr(issue, "title", ""),
                    "desc":  getattr(issue, "desc", ""),
                }
            else:
                i = {
                    "code":  issue.get("code", ""),
                    "sev":   issue.get("sev", ""),
                    "title": issue.get("title", ""),
                    "desc":  issue.get("desc", ""),
                }
            issues_list.append(i)

        raw = data.get("raw", {})

        if language == "uk":
            return f"""Ти — терплячий технічний експерт NetGuardian. Допомагаєш людині БЕЗ ІТ-освіти зрозуміти стан мережі.

📥 ДАНІ:
• Локальна IP: {raw.get("local_ip", "?")} | Gateway: {raw.get("gateway_ip", "?")}
• Ping GW: {raw.get("ping_gw", "?")} | Ping Cloudflare: {raw.get("ping_cf", "?")}
• DNS: {raw.get("dns_ms", "?")}мс | Wi-Fi: {raw.get("wifi_primary", False)}

🔍 Знайдені проблеми ({len(issues_list)}):
{json.dumps(issues_list, ensure_ascii=False, indent=1)}

📌 Висновок engine: {data.get("root_cause", "немає")}

🎯 ЗАВДАННЯ: поверни ТІЛЬКИ JSON (без ```markdown):
{{
  "summary": "1-2 речення-висновок без жаргону. Наприклад: 'Мережа працює відмінно' або 'Інтернет нестабільний — буде лагати'",
  "good": ["✅ Що працює — з цифрами. Напр: '✅ Ping 21мс — швидко'"],
  "warnings": ["🟡 Помірні — ЩО це означає. Напр: '🟡 DNS-кеш 780 записів — нові сайти відкриваються на 1-2с повільніше'"],
  "critical": ["🔴 Серйозні + наслідки. Напр: '🔴 Втрата пакетів 30% — лаги в іграх, відео буферить'"],
  "tips": ["Покрокові команди. Напр: 'Очистити DNS: Win+R → cmd → ipconfig /flushdns → Enter. Перевірка: ▶ ДІАГНОСТИКА → ping має впасти'"],
  "overall": "excellent|good|warning|critical"
}}

🗣️ ПРАВИЛА:
- ELI5 + аналогії (ping=доставка листа, jitter=тряска авто, DNS=телефонна книга, MTU=розмір коробки, VPN=підробний паспорт)
- Якщо все ОК (ping<50, loss<1%) — пиши "Мережа в чудовому стані", не вишукуй нонсенс
- НЕ кажи "проконсультуйся з фахівцем" — ти і є фахівець
- НЕ "перевір налаштування" — кажи КОНКРЕТНО (шлях/команду)
- Макс 4 пункти у списках, 5 у tips
- Українською без англіцизмів
"""
        else:  # en
            return f"""You are a network diagnostics expert. Analyze this data and return JSON.

Data: {json.dumps({"issues": issues_list, "raw": raw}, ensure_ascii=False)}

Return ONLY JSON: {{"summary":"...","good":[],"warnings":[],"critical":[],"tips":[],"overall":"good|warning|critical"}}
"""

    # ── Швидкий чат-режим (для бота) ──────────────────────────────
    def quick_answer(self, question: str, context: dict = None) -> str:
        """Простий Q&A: задає питання, повертає текст.

        Використовується для бота /ask та подібних команд.

        PR #26: max_output_tokens піднято до 8192. Раніше при великому
        контексті (через hybrid_ai gather_full_context) відповіді
        обривалися посередині на 800 токенах.

        ВАЖЛИВО: hybrid_ai тепер вбудовує контекст ПРЯМО в текст
        question. Тому context-параметр зазвичай None, але підтримуємо
        для зворотної сумісності.
        """
        if not self.is_available():
            return "❌ AI недоступне. Налаштуй ключ Gemini у Settings."

        try:
            # Якщо question вже містить наш блок контексту (з hybrid_ai) —
            # не дублюємо. Якщо ні і context переданий — додаємо як JSON.
            already_has_context = "ПОТОЧНИЙ СТАН УТИЛІТИ" in question

            ctx_text = ""
            if context and not already_has_context:
                ctx_text = (f"\n\nКонтекст мережі: "
                            f"{json.dumps(context, ensure_ascii=False)}")

            # PR #28.1: компактний промт ~700 символів замість 2000+
            # (економить токени, що критично для free-tier 1M/день).
            # Gemini добре розуміє стислі чіткі інструкції з прикладами.
            SYSTEM_PROMPT = """\
Ти — терплячий технічний експерт NetGuardian. Допомагаєш людині БЕЗ ІТ-освіти.

🎯 ПРИНЦИПИ:
1. ELI5: без жаргону, з аналогіями (ping=час доставки листа, jitter=тряска \
авто, DNS=телефонна книга, MTU=розмір коробки, VPN=підробний паспорт).
2. Спочатку ВИСНОВОК (1 речення з фактом: "Ping 21мс — відмінно"), потім деталі.
3. Кроки з КОМАНДАМИ: замість "очисти DNS" → "Win+R → cmd → ipconfig /flushdns → Enter".
4. ПЕРЕВІРКА після фіксу: "натисни ▶ ДІАГНОСТИКА — ping має впасти <50мс".
5. Українською, дружньо, як старший брат.

🚫 НЕ КАЖИ:
- "проконсультуйся з фахівцем" (ти і є фахівець)
- "перевір налаштування" (кажи КОНКРЕТНО ЯК — шлях/команду)
- "тощо", "і так далі" (давай конкретні приклади або не пиши)
- Не вигадуй проблем яких немає в даних
- Якщо все ОК — кажи: "У тебе все нормально, не хвилюйся"

📊 У блоці 'ПОТОЧНИЙ СТАН УТИЛІТИ' нижче — реальні дані. Звертайся прямо: \
"Я бачу твій ping=21мс — це відмінно". Макс 4-6 пунктів у списках.
"""

            if already_has_context:
                # Контекст уже у тексті — додаємо потужну системну інструкцію
                prompt = (
                    f"{SYSTEM_PROMPT}\n\n"
                    f"{question}"
                )
            else:
                prompt = (
                    f"{SYSTEM_PROMPT}\n\n"
                    f"ПИТАННЯ КОРИСТУВАЧА: {question}{ctx_text}\n\n"
                    f"Відповідай за принципами вище."
                )

            # PR #26: лог розміру для діагностики обривів
            prompt_chars = len(prompt)
            print(f"[Gemini] 📤 quick_answer: prompt {prompt_chars} chars "
                  f"(~{prompt_chars // 4} токенів), "
                  f"max_output={MAX_TOKENS_CHAT}")

            # PR #27.1: threading-based timeout (не залежить від версії SDK)
            response = self._call_with_timeout(
                self._model.generate_content, 12,
                prompt,
                generation_config={
                    "temperature": 0.5,
                    "max_output_tokens": MAX_TOKENS_CHAT,  # PR #26: 8192
                },
            )

            # PR #26: перевіряємо чи не обрізалось
            is_truncated, fr_name = self._check_truncation(response)
            text = (response.text or "").strip()

            if is_truncated:
                print(f"[Gemini] ⚠️ quick_answer обрізано через {fr_name}! "
                      f"Output {len(text)} chars")
                text += (f"\n\n_⚠️ Відповідь могла бути обрізана через "
                         f"ліміт токенів ({fr_name}). Спробуй питання "
                         f"коротше._")
            else:
                print(f"[Gemini] 📥 quick_answer: {len(text)} chars "
                      f"finish={fr_name}")

            return text or "Пуста відповідь"

        except Exception as e:
            err_msg = str(e)
            err_low = err_msg.lower()
            # PR #28.1: розпізнаємо quota errors і тригеримо lockout
            if ("quota" in err_low or "429" in err_msg or
                    "exceeded" in err_low or "rate" in err_low and "limit" in err_low):
                self._trigger_quota_lockout()
                return "❌ Quota exceeded"
            print(f"[Gemini] quick_answer error: {err_msg[:200]}")
            self._last_error = err_msg
            return f"❌ Помилка: {err_msg[:200]}"


# ──────────────────────────────────────────────────────────────────
#  Singleton instance — спільний для всієї утиліти
# ──────────────────────────────────────────────────────────────────
_GLOBAL_CLIENT: Optional[GeminiClient] = None


def get_gemini_client() -> GeminiClient:
    """Повертає глобальний instance клієнта (lazy init)."""
    global _GLOBAL_CLIENT
    if _GLOBAL_CLIENT is None:
        _GLOBAL_CLIENT = GeminiClient()
    return _GLOBAL_CLIENT


def reset_gemini_client():
    """Скидає глобальний instance (наприклад після оновлення ключа)."""
    global _GLOBAL_CLIENT
    _GLOBAL_CLIENT = None


# ──────────────────────────────────────────────────────────────────
#  gather_network_context — викликається з hybrid_ai
#  Залишаємо для зворотної сумісності, але hybrid_ai має власну
#  розумнішу версію gather_full_context()
# ──────────────────────────────────────────────────────────────────

def gather_network_context() -> dict:
    """Швидкий збір базового мережевого контексту.

    Використовується як fallback коли немає доступу до App instance.
    Повертає базовий dict з local_ip / gateway / public_ip.
    """
    ctx = {}
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ctx["local_ip"] = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Gateway через ipconfig (Windows) або ip route (Linux)
    try:
        import subprocess, platform, re
        if platform.system() == "Windows":
            out = subprocess.run(
                ["ipconfig"], capture_output=True, timeout=5).stdout
            text = ""
            for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
                try:
                    text = out.decode(enc, errors="ignore")
                    if text.strip():
                        break
                except Exception:
                    continue
            for line in text.splitlines():
                if re.search(r"Default Gateway|Основн[иі]й шлюз|"
                             r"Основной шлюз", line, re.I):
                    ip = line.split(":")[-1].strip()
                    if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                        ctx["gateway"] = ip
                        break
        else:
            out = subprocess.run(
                ["ip", "route"], capture_output=True, text=True, timeout=5).stdout
            for line in out.splitlines():
                if line.startswith("default"):
                    parts = line.split()
                    if len(parts) >= 3:
                        ctx["gateway"] = parts[2]
                        break
    except Exception:
        pass

    # Спробуємо dashboard snapshot
    try:
        from features.dashboard.ui import get_dashboard_snapshot
        snap = get_dashboard_snapshot()
        if isinstance(snap, dict):
            ctx.update(snap)
    except Exception:
        pass

    return ctx