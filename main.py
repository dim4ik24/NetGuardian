# main.py
import os

try:
    from dotenv import load_dotenv
    load_dotenv()
    print("✅ .env завантажено")
except ImportError:
    print("⚠️  python-dotenv не встановлена — токен з .env не завантажиться.")
    print("     Встанови: pip install python-dotenv")

# ── ВИПРАВЛЕННЯ COPY-PASTE для української/російської розкладок ──
# Patch ставить контекстне меню (правий клік: Копіювати/Вставити)
# на всі CTkEntry та CTkTextbox що будуть створюватись.
# Має бути ПЕРЕД імпортом NetGuardianApp щоб patched __init__ був готовий
# до моменту коли App почне створювати UI-віджети.
try:
    from clipboard_fix import patch_ctk_widgets_globally
    patch_ctk_widgets_globally()
except ImportError:
    print("⚠️  clipboard_fix.py не знайдено — copy-paste працюватиме тільки англ. розкладкою")

from app.ui.app import NetGuardianApp

if __name__ == "__main__":
    app = NetGuardianApp()

    # Підключаємо універсальний clipboard handler (Ctrl+C/V/X/A на будь-якій
    # розкладці — українська, російська, грузинська тощо)
    try:
        from clipboard_fix import enable_universal_clipboard
        enable_universal_clipboard(app)
    except Exception as e:
        print(f"⚠️  clipboard_fix init failed: {e}")

    # ── PR #4: Forecast continuous measurement + Pi sync ──────────
    # ВАЖЛИВО: спочатку стартуємо MQTT-subscriber явно, інакше всі
    # дані з Pi не потрапляють у pi_agent_cache.db !
    try:
        from features.forecast.mqtt_subscriber import start_global as start_mqtt_subscriber
        if start_mqtt_subscriber():
            print("✅ MQTT subscriber запущено (підписаний на дані Pi)")
        else:
            print("⚠️  MQTT subscriber не зміг підключитись")
    except Exception as e:
        print(f"⚠️  MQTT subscriber init error: {e}")

    # Запускаємо фонові процеси Forecast одразу при старті програми:
    #   1. Continuous measurement (виміри кожні 5 хв навіть якщо вкладку Forecast не відкрито)
    #   2. Sync з Pi (доливаємо дані з pi_agent_cache.db у forecast.db)
    #   3. Запитуємо в Pi свіжу історію щоб не було "дір" якщо ПК спав
    def _start_forecast_background():
        try:
            from features.forecast.engine import ForecastEngine
            engine = ForecastEngine()

            # 1) Запустити постійний моніторинг
            try:
                engine.start_continuous_measurement(interval_seconds=300)
                print("✅ Forecast: continuous measurement запущено (інтервал 5 хв)")
            except Exception as e:
                print(f"⚠️  Forecast start_continuous_measurement error: {e}")

            # 2) Запитати свіжу історію в Pi (subscriber вже працює)
            # Це попросить Pi надіслати весь архів за 7 днів
            try:
                from features.forecast.mqtt_subscriber import get_subscriber
                sub = get_subscriber()
                if sub and sub.is_connected:
                    sub.request_history_sync()
                    print("✅ Pi: надіслано запит на синхронізацію історії")
                    print("   (Pi надсилатиме дані шматками — потрібно ~10-30с)")
                else:
                    print("⚠️  Pi MQTT не підключений — sync неможливий")
            except Exception as e:
                print(f"⚠️  Pi history sync error: {e}")

            # 3) Доллити дані з Pi-кешу (виконається повторно у UI Forecast)
            try:
                added = engine.fill_gaps_from_pi()
                if added > 0:
                    print(f"✅ Forecast: додано {added} записів з Pi-кешу")
                else:
                    print("ℹ️  Pi cache порожній або застарілий — повторим через 60с")
            except Exception as e:
                print(f"⚠️  Forecast fill_gaps_from_pi error: {e}")

            # 4) ПОВТОРНИЙ sync через 60 секунд (після того як subscriber
            # встигне отримати свіжі дані від Pi)
            def _retry_sync():
                try:
                    added2 = engine.fill_gaps_from_pi()
                    if added2 > 0:
                        print(f"✅ Forecast (retry+60с): додано {added2} записів з Pi-кешу")
                except Exception as e:
                    print(f"⚠️  retry sync error: {e}")

            threading.Timer(60.0, _retry_sync).start()

            # 5) Повторний sync через 5 хв — для надійності
            def _retry_sync_5min():
                try:
                    added3 = engine.fill_gaps_from_pi()
                    if added3 > 0:
                        print(f"✅ Forecast (retry+5хв): додано {added3} записів з Pi-кешу")
                except Exception as e:
                    pass

            threading.Timer(300.0, _retry_sync_5min).start()

            # PR #5: SmartScheduler тепер запускається з bot.py, тому тут
            # не потрібно. Якщо bot.py не запустився — SmartScheduler не буде,
            # але це окей бо без Telegram звіти не мають сенсу.

        except Exception as e:
            print(f"⚠️  Forecast background init error: {e}")

    # Запускаємо у фоні з затримкою 5с щоб дати UI повністю завантажитись
    # та MQTT-клієнту встигнути підключитися
    import threading
    threading.Timer(5.0, _start_forecast_background).start()

    app.mainloop()