import sys, os
sys.path.insert(0, os.getcwd())
from features.forecast.engine import ForecastEngine

print("Створюю engine...")
e = ForecastEngine()
print(f"net_id: {e.net_id}")
print()
print("Запускаю fill_gaps_from_pi (читає з ОБОХ таблиць тепер)...")
added = e.fill_gaps_from_pi()
print()
print(f"✅ Додано: {added} рядків")
