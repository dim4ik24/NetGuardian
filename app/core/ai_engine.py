# core/ai_engine.py
"""
NetGuardian AI — Мозок системи  v3.0
══════════════════════════════════════════════════════════════════
База знань: 230+ сценаріїв з OSI L1–L7 (з База_Даних.docx)

ЛОГІКА РОБОТИ:
  L1 (Physical):  діагностика → пояснення → інструкції користувачу
                  (AI сама не може виправити фізичну проблему)

  L2–L7 (Soft):  спочатку спроба AUTO-FIX (flush dns, reset tcp,
                  set dns, reboot via tapo, etc.)
                  якщо не вдалось → чіткий опис + рекомендації

ПІДКЛЮЧЕННЯ:
  from app.core.ai_engine import NetGuardianAI
  ai = NetGuardianAI(tapo_plug=plug, bot_alerter=alerter)
  result = ai.analyze(metrics)
"""

from __future__ import annotations
import subprocess
import platform
import logging
import time
from dataclasses import dataclass, field
from typing import List, Optional, Callable, Dict

log = logging.getLogger("ai_engine")

IS_WINDOWS = platform.system() == "Windows"


# ══════════════════════════════════════════════════════════════
#  СТРУКТУРА ЗАПИСУ БАЗИ ЗНАНЬ
# ══════════════════════════════════════════════════════════════

@dataclass
class DiagEntry:
    """Один запис діагностики з бази знань."""
    code:        str          # напр. "L1-001"
    layer:       int          # 1..7
    title:       str          # назва проблеми (en)
    state:       str          # умова детектування (з docx)
    explanation: str          # пояснення для юзера (з docx)
    logic:       str          # логіка AI / умови (з docx)
    confidence:  int          # ймовірність %
    auto_fix:    Optional[str] = None   # ім'я auto-fix дії або None
    severity:    str = "WARNING"        # CRITICAL / WARNING / INFO
    tags:        List[str] = field(default_factory=list)

    @property
    def is_physical(self) -> bool:
        return self.layer == 1

    @property
    def can_auto_fix(self) -> bool:
        return self.auto_fix is not None


# ══════════════════════════════════════════════════════════════
#  БАЗА ЗНАНЬ — ВСІ ЗАПИСИ З DOCX
# ══════════════════════════════════════════════════════════════

KB: List[DiagEntry] = [

# ──────────────────────────────────────────────────────────────
# L1 — PHYSICAL LAYER (Hardware, Cables & Power)
# ──────────────────────────────────────────────────────────────
DiagEntry("L1-001", 1, "Total Power Loss",
    state="Link: Down, Tapo: 0W",
    explanation="Роутер знеструмлений. Перевір розетку.",
    logic="Tapo.online == False + ping(GW) == Fail",
    confidence=99, severity="CRITICAL",
    tags=["power","tapo","blackout"]),

DiagEntry("L1-002", 1, "Boot Loop",
    state="Link: Down, Tapo: 1-2W",
    explanation="Роутер постійно перезавантажується.",
    logic="tapo_watts циклічно (0.5W → 2W) кожні 40с",
    confidence=85, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["boot-loop","tapo","firmware"]),

DiagEntry("L1-003", 1, "Cable Damage",
    state="Link: 10Mbps, Cat6",
    explanation="Твій кабель Cat6 працює як старий телефонний — можливо пошкоджений.",
    logic="NIC_speed == 10 + Cable_Type == 'Cat6'",
    confidence=95, severity="WARNING",
    tags=["cable","speed"]),

DiagEntry("L1-004", 1, "Unplugged Cable",
    state="Link: Down, NIC: Up",
    explanation="Кабель не вставлено до клацання!",
    logic="NIC.isup == False + NIC.admin_status == Enabled",
    confidence=90, severity="CRITICAL",
    tags=["cable","unplugged"]),

DiagEntry("L1-005", 1, "Overheating",
    state="Tapo: > 15W, Ping: High",
    explanation="Роутер перегрівся. Дай йому 'подихати'.",
    logic="tapo_watts > baseline * 1.5 + jitter > 50ms",
    confidence=70, severity="WARNING",
    tags=["temperature","tapo","overheating"]),

DiagEntry("L1-006", 1, "Cable Interference",
    state="Errors: High, Link: Up",
    explanation="Кабель ловить перешкоди. Прибери джерела завад.",
    logic="netstat.errors_delta > 100/sec при стабільному Link",
    confidence=80, severity="WARNING",
    tags=["cable","errors","interference"]),

DiagEntry("L1-007", 1, "Logic Freeze",
    state="Link: Up, Tapo: 5W, No Ping",
    explanation="Роутер 'завис'. Залізо працює, софт — ні.",
    logic="NIC.isup == True + tapo_watts стабільні + ping Fail",
    confidence=90, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["freeze","firmware","tapo"]),

DiagEntry("L1-008", 1, "NIC Disabled",
    state="NIC: Admin Disabled",
    explanation="Ти вимкнув мережеву карту в Windows.",
    logic="Get-NetAdapter статус Disabled",
    confidence=100, auto_fix="enable_nic", severity="CRITICAL",
    tags=["nic","windows","disabled"]),

DiagEntry("L1-009", 1, "Port Collision / Half-Duplex",
    state="Link: Half-Duplex",
    explanation="Контакти в роз'ємі окислилися або забруднилися.",
    logic="NIC.duplex == 'Half' (перевірка через WMI)",
    confidence=75, severity="WARNING",
    tags=["duplex","cable","port"]),

DiagEntry("L1-010", 1, "Sleep Mode",
    state="Tapo: 0.5W",
    explanation="Роутер у глибокому сні. Він не реагує.",
    logic="tapo_watts < 0.8W протягом 10 хвилин",
    confidence=60, auto_fix="tapo_reboot", severity="WARNING",
    tags=["sleep","tapo"]),

DiagEntry("L1-011", 1, "Overvoltage",
    state="Tapo: Volts > 250V",
    explanation="Напруга занадто висока! Вимикаю для захисту.",
    logic="Tapo.voltage > 250V",
    confidence=100, auto_fix="tapo_off", severity="CRITICAL",
    tags=["voltage","tapo","safety"]),

DiagEntry("L1-012", 1, "Loose DC Jack / Fluctuating Power",
    state="Power: Fluctuating",
    explanation="Штекер у роутері бовтається.",
    logic="tapo_watts дельта > 30% при статичному трафіку",
    confidence=65, severity="WARNING",
    tags=["power","psu","hardware"]),

DiagEntry("L1-013", 1, "Negotiation Fail (100Mbps on Cat6)",
    state="Link: 100Mbps, Cat6",
    explanation="Кабель може 1000 Мбіт, але видає 100. Проблема з обжимкою або портом.",
    logic="NIC_speed == 100 + Cat6_flag == True",
    confidence=90, severity="WARNING",
    tags=["speed","negotiation","cable"]),

DiagEntry("L1-014", 1, "Failing PSU",
    state="Tapo: Power Pulse",
    explanation="Блок живлення пульсує. Скоро йому кінець.",
    logic="Частотний аналіз tapo_current (імпульси 1Гц)",
    confidence=55, severity="WARNING",
    tags=["psu","tapo","hardware"]),

DiagEntry("L1-015", 1, "Bad Crimp",
    state="Link: Down, NIC: Up (flapping)",
    explanation="Контакти в конекторі погано обтиснуті.",
    logic="LinkFlapping_count > 5/min",
    confidence=80, severity="WARNING",
    tags=["cable","crimp","flapping"]),

DiagEntry("L1-016", 1, "Short Circuit",
    state="Tapo: Current > 1A",
    explanation="Аномальний струм! Ризик замикання.",
    logic="Tapo.current > 1000mA",
    confidence=95, auto_fix="tapo_off", severity="CRITICAL",
    tags=["current","short-circuit","tapo","safety"]),

DiagEntry("L1-017", 1, "Cable Too Long",
    state="Errors: Alignment",
    explanation="Твій LAN-кабель занадто довгий (> 90м).",
    logic="AlignmentErrors зростають при навантаженні",
    confidence=70, severity="WARNING",
    tags=["cable","length","errors"]),

DiagEntry("L1-018", 1, "Blackout",
    state="Tapo: 0W, Battery: Active",
    explanation="Світло зникло! Працюємо від повербанка.",
    logic="Tapo.online == False + PC.on_battery == True",
    confidence=100, severity="CRITICAL",
    tags=["blackout","power","battery"]),

DiagEntry("L1-019", 1, "Dust / Ventilation",
    state="Link: Up, Temp: High",
    explanation="Роутеру 'задушливо'. Прибери пил!",
    logic="tapo_watts стабільні + деградація bandwidth",
    confidence=50, severity="WARNING",
    tags=["temperature","dust","ventilation"]),

DiagEntry("L1-020", 1, "Firmware Crash",
    state="Tapo: 6W, Link: Down",
    explanation="Енергія є, порт 'мертвий'. Прошивка впала.",
    logic="tapo_watts в межах норми + NIC.isup == False",
    confidence=85, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["firmware","tapo"]),

DiagEntry("L1-021", 1, "Electric Motor Noise",
    state="Tapo: Power Spike, Ping: High",
    explanation="Поруч увімкнувся потужний прилад (холодильник), що дає завади.",
    logic="Різкий стрибок tapo_current + сплеск jitter > 100ms",
    confidence=65, severity="WARNING",
    tags=["interference","power","noise"]),

DiagEntry("L1-022", 1, "Static Electricity on Cable",
    state="Link: Up, CRC Errors: Increasing",
    explanation="На кабелі накопичується статика. Це заважає передачі даних.",
    logic="Поступове зростання помилок у netstat -e при стабільному Link",
    confidence=75, severity="WARNING",
    tags=["static","cable","crc"]),

DiagEntry("L1-023", 1, "Deep Hardware Sleep",
    state="Tapo: 0.1W, Link: Down",
    explanation="Роутер пішов у режим енергозбереження і не прокидається.",
    logic="tapo_watts < 0.2W + відсутність відповіді на ping шлюзу",
    confidence=80, auto_fix="tapo_reboot", severity="WARNING",
    tags=["sleep","tapo","power-save"]),

DiagEntry("L1-024", 1, "Cable Overlength (Gigabit)",
    state="Link: Up (1G), Loss: 2%",
    explanation="Твій кабель занадто довгий. Гігабіт працює нестабільно.",
    logic="NIC_speed == 1000 + packet_loss > 0 при довжині > 90м",
    confidence=70, severity="WARNING",
    tags=["cable","gigabit","length"]),

DiagEntry("L1-025", 1, "Brownout Risk",
    state="Tapo: Volts < 190V",
    explanation="Напруга в розетці критично впала. Можливі глюки роутера.",
    logic="Tapo.voltage < 190V",
    confidence=100, auto_fix="tapo_off", severity="CRITICAL",
    tags=["voltage","tapo","brownout","power"]),

DiagEntry("L1-026", 1, "Internal Component Fail",
    state="Link: Up, Power: High (Static)",
    explanation="Роутер споживає багато енергії навіть без трафіку. Схоже на поломку внутрішніх компонентів.",
    logic="tapo_watts тримається на максимумі без мережевого навантаження",
    confidence=60, severity="WARNING",
    tags=["hardware","tapo","component"]),

DiagEntry("L1-027", 1, "Voltage Mismatch (Adapter)",
    state="USB Boost: 9V, Link: Down",
    explanation="Кабель-конвертер видає 9V, а роутеру треба 12V. Йому бракує сил для роботи.",
    logic="Зафіксовано тип кабелю 9V при цільовій напрузі 12V",
    confidence=95, severity="CRITICAL",
    tags=["voltage","adapter","power","hardware"]),

DiagEntry("L1-028", 1, "Short Circuit in LAN Port",
    state="Link: Down, Tapo: High Pulse",
    explanation="Коротке замикання в LAN-порті. Витягни кабель і перевір контакти.",
    logic="tapo_current б'є в ліміт при підключенні кабелю",
    confidence=85, auto_fix="tapo_off", severity="CRITICAL",
    tags=["short-circuit","port","tapo","hardware"]),

DiagEntry("L1-029", 1, "Weak Power Adapter",
    state="Link: Up, Tapo: 3W (Unstable)",
    explanation="Блок живлення не тримає навантаження. При сплесках трафіку інтернет впаде.",
    logic="Просідання напруги на розетці при старті Speedtest",
    confidence=65, severity="WARNING",
    tags=["psu","adapter","power","instability"]),

DiagEntry("L1-030", 1, "Parasitic Power via LAN",
    state="Link: Up, Tapo: 0W",
    explanation="Розетка вимкнена, але порт світиться. Живлення йде через LAN-кабель від ПК або PoE-комутатора.",
    logic="Tapo.online == False + NIC.isup == True",
    confidence=90, severity="WARNING",
    tags=["poe","lan","power","tapo"]),

# ──────────────────────────────────────────────────────────────
# L2 — DATA LINK (WiFi, Switches, MAC)
# ──────────────────────────────────────────────────────────────
DiagEntry("L2-001", 2, "Low WiFi Signal",
    state="RSSI: < -70dBm",
    explanation="Сигнал WiFi занадто слабкий. Ти далеко від роутера або є перешкоди.",
    logic="RSSI < -70 dBm при стабільному з'єднанні",
    confidence=90, severity="WARNING",
    tags=["wifi","rssi","signal"]),

DiagEntry("L2-002", 2, "WiFi Channel Congestion",
    state="Channel: Congested, Speed: Low",
    explanation="Сусіди забили твій WiFi канал. Потрібно змінити.",
    logic="Кількість AP на тому ж каналі > 3",
    confidence=80, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","channel","congestion"]),

DiagEntry("L2-003", 2, "WPA2/WPA3 Mismatch",
    state="Auth: WPA3, Client: WPA2",
    explanation="Твій старий ноутбук не підтримує захист WPA3. Знизь рівень безпеки роутера.",
    logic="Клієнт намагається підключитися з WPA2 до точки з WPA3-Only",
    confidence=100, severity="WARNING",
    tags=["wifi","wpa3","authentication"]),

DiagEntry("L2-004", 2, "Evil Twin Attack",
    state="SSID: Same Name (2 nets)",
    explanation="Виявлено мережу-двійника з таким же ім'ям. НЕ підключайся — це пастка!",
    logic="Дві мережі з однаковим SSID, але різними MAC-адресами",
    confidence=95, severity="CRITICAL",
    tags=["security","evil-twin","attack"]),

DiagEntry("L2-005", 2, "Deauthentication Attack",
    state="Disconnect: Deauth frames",
    explanation="Хтось примусово викидає твої пристрої з WiFi. Це атака хакера!",
    logic="Фіксація Deauth пакетів у режимі моніторингу",
    confidence=100, severity="CRITICAL",
    tags=["security","deauth","attack"]),

DiagEntry("L2-006", 2, "ARP Poisoning / DNS Hijacking",
    state="DNS: Fail, IP: OK",
    explanation="Твої запити до сайтів перехоплює невідомий сервер.",
    logic="Відповідь на DNS-запит приходить не від вказаного сервера",
    confidence=70, auto_fix="flush_dns", severity="CRITICAL",
    tags=["security","arp","dns","hijack"]),

DiagEntry("L2-007", 2, "MAC Flooding Attack",
    state="Scan: New MAC (High Freq)",
    explanation="Хтось намагається 'зламати' пам'ять роутера, підставляючи тисячі фейкових адрес.",
    logic="Реєстрація > 50 нових MAC-адрес за 10 секунд",
    confidence=95, severity="CRITICAL",
    tags=["security","mac-flooding","attack"]),

DiagEntry("L2-008", 2, "WiFi Pineapple Attack",
    state="Auth: WPA2-PSK, Probe: Open",
    explanation="Виявлено підробну точку доступу, яка намагається виманити твій пароль.",
    logic="Наявність Probe Requests від пристрою, що імітує твою SSID без шифрування",
    confidence=95, severity="CRITICAL",
    tags=["security","pineapple","phishing"]),

DiagEntry("L2-009", 2, "Bluetooth / WiFi Coexistence Issue",
    state="WiFi: 2.4G, Bluetooth: Active",
    explanation="Твої Bluetooth-навушники заважають WiFi. Вони працюють на одній частоті.",
    logic="Деградація швидкості при активації BT-модуля на ноутбуці",
    confidence=75, severity="WARNING",
    tags=["bluetooth","wifi","interference"]),

DiagEntry("L2-010", 2, "Gateway Isolation (AP Isolation)",
    state="Ping Gateway: Fail, Link: Up",
    explanation="Ти підключений до WiFi, але роутер тебе ігнорує (Client Isolation увімкнено).",
    logic="WiFi Connect == Success, але ping(192.168.x.1) == Fail",
    confidence=90, severity="WARNING",
    tags=["wifi","isolation","gateway"]),

DiagEntry("L2-011", 2, "DFS Channel Radar",
    state="Ping: Jitter > 200ms, 5GHz",
    explanation="Роутер помітив радар і змінив канал 5 ГГц. Зв'язок може перерватися на хвилину.",
    logic="Раптова зміна номера каналу в діапазоні DFS (52-144) без команди юзера",
    confidence=90, severity="INFO",
    tags=["wifi","dfs","5ghz","radar"]),

DiagEntry("L2-012", 2, "UPnP Security Risk",
    state="Scan: Device w/ UPnP Active",
    explanation="Твій пристрій відкрив 'дірку' в роутері для доступу ззовні. Це небезпечно.",
    logic="Виявлено активний протокол SSDP",
    confidence=80, severity="WARNING",
    tags=["security","upnp","ssdp"]),

DiagEntry("L2-013", 2, "Bridge/Loopback Freeze (Broadcast Storm)",
    state="Tapo: 5W, Link: Up, Data: 0",
    explanation="Дані зациклилися всередині мережі. Мережа 'лежить' через шторм пакетів.",
    logic="Вибухове зростання Broadcast трафіку",
    confidence=90, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["broadcast-storm","loopback","stp"]),

DiagEntry("L2-014", 2, "Cheap IoT Traffic (Espressif/Tuya)",
    state="Scan: MAC OUI == Espressif",
    explanation="Твоя дешева смарт-лампа або датчик постійно шле дані. Може бути вразливою.",
    logic="Виявлено пристрій на чіпі ESP8266/ESP32 з високою частотою запитів",
    confidence=70, severity="WARNING",
    tags=["iot","espressif","security"]),

DiagEntry("L2-015", 2, "Possible Spy Cam",
    state="Scan: New Hidden Device",
    explanation="У мережі з'явився прихований пристрій, що постійно передає потік даних.",
    logic="Невідомий MAC + постійний трафік (Stream) понад 2 Мбіт/с",
    confidence=60, severity="WARNING",
    tags=["security","iot","camera"]),

DiagEntry("L2-016", 2, "High Noise Floor (BT/Microwave)",
    state="RSSI: -60dBm, SNR: < 10dB",
    explanation="Сигнал добрий, але рівень фонового шуму занадто високий. Можлива завада від Bluetooth.",
    logic="RSSI в нормі, але SNR критично низький",
    confidence=75, severity="WARNING",
    tags=["noise","snr","bluetooth","interference"]),

DiagEntry("L2-017", 2, "VLAN Mismatch",
    state="Tapo: 6W, Link: Up, No IP",
    explanation="Кабель в нормі, але ти потрапив у 'не ту' віртуальну мережу. Доступу не буде.",
    logic="isup == True, але DHCP Discover ігнорується через теги VLAN",
    confidence=80, severity="WARNING",
    tags=["vlan","dhcp"]),

DiagEntry("L2-018", 2, "Duplicate MAC Address",
    state="Scan: Duplicate MAC (Vendor)",
    explanation="У мережі два пристрої з однаковою адресою (заводський брак). Будуть глюки.",
    logic="Два активні порти бачать один і той самий MAC",
    confidence=95, severity="CRITICAL",
    tags=["mac","duplicate","hardware"]),

DiagEntry("L2-019", 2, "WiFi Radio Disabled",
    state="SSID: Not Found, Tapo: 6W",
    explanation="Живлення є, але Wi-Fi модуль у роутері вимкнено в налаштуваннях.",
    logic="tapo_watts в нормі + pywifi не бачить домашню SSID",
    confidence=95, severity="CRITICAL",
    tags=["wifi","radio","disabled","router"]),

DiagEntry("L2-020", 2, "Incorrect WiFi Password",
    state="Auth: Fail, Reason: 4-Way",
    explanation="Wi-Fi відхиляє пароль. Перевір розкладку клавіатури та CapsLock.",
    logic="Статус WLAN_REASON_4WAY_HANDSHAKE_TIMEOUT у логах",
    confidence=100, severity="WARNING",
    tags=["wifi","password","auth","wpa2"]),

DiagEntry("L2-021", 2, "IP Address Conflict (L2)",
    state="ARP: Duplicate IP detected",
    explanation="Два пристрої отримали однакову IP-адресу. Мережа буде 'падати'.",
    logic="Виявлено два різні MAC на один IP через ARP-запит",
    confidence=99, auto_fix="dhcp_renew", severity="CRITICAL",
    tags=["ip","conflict","arp","dhcp"]),

DiagEntry("L2-022", 2, "Intrusion Alert (New Device)",
    state="New MAC: Unknown",
    explanation="У твоїй мережі з'явився невідомий пристрій. Може, хтось підібрав пароль?",
    logic="MAC-адреса відсутня у базі 'Довірених пристроїв'",
    confidence=80, severity="CRITICAL",
    tags=["security","intrusion","mac","unknown"]),

DiagEntry("L2-023", 2, "WiFi Range Limitation (5GHz)",
    state="RSSI: -85dBm, 5GHz",
    explanation="Ти занадто далеко. 5 ГГц не пробиває стільки стін. Підійди ближче або перейди на 2.4 ГГц.",
    logic="RSSI < -80dBm на частоті 5 ГГц",
    confidence=95, severity="WARNING",
    tags=["wifi","range","5ghz","rssi"]),

DiagEntry("L2-024", 2, "WiFi Signal Overload (Too Close)",
    state="Disconnects: High, Dist: 1m",
    explanation="Ти занадто близько до роутера. Потужний сигнал 'забиває' приймач і викликає розриви.",
    logic="RSSI > -20dBm + постійні перепідключення",
    confidence=70, severity="WARNING",
    tags=["wifi","interference","rssi","proximity"]),

DiagEntry("L2-025", 2, "Legacy Protocol Slowdown (802.11b)",
    state="Mode: 802.11b detected",
    explanation="Старий пристрій у мережі змушує всіх працювати на швидкості 90-х (11 Мбіт/с).",
    logic="Виявлено активний клієнт зі стандартом 802.11b",
    confidence=85, severity="WARNING",
    tags=["wifi","legacy","802.11b","slowdown"]),

DiagEntry("L2-026", 2, "MAC Filtering Active",
    state="SSID: Found, Conn: Denied",
    explanation="Твій пристрій у 'чорному списку' роутера. Тебе не впускають за MAC-адресою.",
    logic="Статус підключення Association Denied (ACL filter)",
    confidence=100, severity="WARNING",
    tags=["wifi","mac-filter","acl","access"]),

DiagEntry("L2-027", 2, "Microwave Oven Interference",
    state="Ping: 500ms, Band: 2.4GHz",
    explanation="Хтось гріє їжу, і твій 2.4ГГц Wi-Fi 'закипає'. Мікрохвильовка заважає на тій самій частоті.",
    logic="Різкий ріст jitter тільки на частоті 2.4GHz + Tapo стабільна",
    confidence=75, severity="WARNING",
    tags=["wifi","interference","microwave","2.4ghz"]),

DiagEntry("L2-028", 2, "DHCP Server Down (WiFi)",
    state="DHCP: No Offer",
    explanation="Роутер не видає IP-адресу. DHCP-сервер 'завис'.",
    logic="Запит DHCP Discover не отримує Offer протягом 10с",
    confidence=90, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["dhcp","server","router","ip"]),

DiagEntry("L2-029", 2, "APIPA Address Active",
    state="IP: 169.254.x.x",
    explanation="Windows не отримала адресу і призначила собі випадкову 169.254.x.x. Інтернету не буде.",
    logic="Локальна IP починається на 169.254",
    confidence=100, auto_fix="dhcp_renew", severity="CRITICAL",
    tags=["apipa","dhcp","ip","169.254"]),

DiagEntry("L2-030", 2, "Stealth WiFi Interference",
    state="Hidden SSID on same channel",
    explanation="Сусід приховав назву мережі, але вона все одно заважає твоїй на тому ж каналі.",
    logic="Wi-Fi Analyzer бачить потужний сигнал без імені (Hidden SSID)",
    confidence=80, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","hidden","interference","channel"]),

DiagEntry("L2-031", 2, "Antenna Problem",
    state="Tapo: 4W, WiFi: Low Signal",
    explanation="Споживання в нормі, але сигнал дуже слабкий. Можливо, антени відкрутилися або несправні.",
    logic="tapo_watts OK + RSSI впав на 30% при тій же відстані",
    confidence=60, severity="WARNING",
    tags=["antenna","wifi","rssi","hardware"]),

DiagEntry("L2-032", 2, "Background Broadcast Flood",
    state="Ping: High, No Traffic",
    explanation="Якийсь пристрій 'спить' і забиває ефір пустими broadcast-запитами.",
    logic="Високий Airtime Utilization при нульовому трафіку",
    confidence=50, severity="WARNING",
    tags=["broadcast","wifi","airtime","idle"]),

DiagEntry("L2-033", 2, "Aggressive Roaming",
    state="Re-associations: Frequent",
    explanation="Твій телефон постійно стрибає між 2.4 та 5 ГГц. Це створює мікро-лаги та розриви зв'язку.",
    logic="Швидка зміна BSSID (MAC роутера) у клієнтських логах",
    confidence=65, severity="WARNING",
    tags=["roaming","wifi","band","steering"]),

DiagEntry("L2-034", 2, "Airtime Fairness Issue",
    state="Band: 2.4G, Mode: 802.11b/g",
    explanation="Старий повільний пристрій забирає весь час ефіру. Інші гаджети чекають своєї черги.",
    logic="Виявлено клієнта зі швидкістю < 54 Mbps при високому навантаженні на канал",
    confidence=85, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","airtime","legacy","fairness"]),

DiagEntry("L2-035", 2, "MAC Randomization Active",
    state="MAC: Apple/Android Random",
    explanation="Твій телефон використовує випадкову MAC-адресу для конфіденційності. Це нормальна поведінка.",
    logic="Другий біт першого байта MAC-адреси дорівнює 1 (Private Address)",
    confidence=100, severity="INFO",
    tags=["mac","randomization","privacy","mobile"]),

DiagEntry("L2-036", 2, "Captive Portal Block",
    state="Connect: Success, IP: None",
    explanation="Ти підключився до мережі, але потрібно пройти авторизацію на веб-сторінці (як у кафе або готелі).",
    logic="HTTP-запит перенаправляється (Redirect 302) на сторонню IP-адресу",
    confidence=90, severity="WARNING",
    tags=["captive","portal","auth","redirect"]),

DiagEntry("L2-037", 2, "Cheap IoT Device (Unknown Vendor)",
    state="Scan: MAC OUI == Unknown",
    explanation="Підключено дешевий смарт-пристрій з невідомим виробником. Може бути вразливим до атак.",
    logic="Префікс MAC-адреси (OUI) відсутній у базі IEEE",
    confidence=70, severity="WARNING",
    tags=["iot","mac","oui","security"]),

DiagEntry("L2-038", 2, "Perfect WiFi Handover (Mesh)",
    state="Roaming: < 1 sec, BSSID change",
    explanation="Ти перейшов від одного роутера до іншого без розриву зв'язку. Mesh-мережа працює чудово!",
    logic="Швидка зміна BSSID при збереженні SSID та активної сесії",
    confidence=100, severity="INFO",
    tags=["roaming","mesh","handover","info"]),

DiagEntry("L2-039", 2, "Multicast Flood",
    state="Latency: High, Multicast: High",
    explanation="Якийсь пристрій забиває мережу службовими повідомленнями. Можливо, принтер або Smart TV.",
    logic="Висока частка Broadcast/Multicast пакетів у загальному трафіку",
    confidence=65, severity="WARNING",
    tags=["multicast","broadcast","printer","iot"]),

DiagEntry("L2-040", 2, "Open Port Security Hole",
    state="Scan: Device w/ Open Ports",
    explanation="На пристрої відкриті небезпечні порти (21, 23, 445). Хакер може зайти всередину мережі.",
    logic="nmap або socket скан виявив відкриті порти 21, 23 або 445",
    confidence=85, severity="CRITICAL",
    tags=["security","ports","scan","vulnerability"]),

DiagEntry("L2-041", 2, "Fresnel Zone Obstacle",
    state="Ping: OK, Packet Loss: 10%",
    explanation="Між тобою і роутером з'явилася фізична перешкода (людина, меблі або двері). Це обриває сигнал.",
    logic="Різке падіння RSSI на 10-15 dBm при незмінних координатах пристрою",
    confidence=55, severity="WARNING",
    tags=["wifi","fresnel","obstacle","rssi"]),

DiagEntry("L2-042", 2, "WPA3 Protocol Incompatibility",
    state="WPA3: Required, Client: WPA2",
    explanation="Твій старий ноутбук не підтримує WPA3. Знизь рівень безпеки роутера до WPA2/WPA3-Mixed.",
    logic="Клієнт намагається підключитися з WPA2 до точки з WPA3-Only",
    confidence=100, severity="WARNING",
    tags=["wpa3","wpa2","compatibility","wifi"]),

DiagEntry("L2-043", 2, "Region/Country Code Mismatch",
    state="Tapo: 6W, Band: 2.4G (Ch 13)",
    explanation="Деякі гаджети не бачать Wi-Fi, бо роутер вибрав канал 13 (заборонений у деяких регіонах).",
    logic="Робочий канал == 13 + скарги на неможливість підключення",
    confidence=80, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","channel","region","country-code"]),

DiagEntry("L2-044", 2, "Public Place WiFi Congestion",
    state="Scan: 100+ MACs detected",
    explanation="Навколо занадто багато людей з увімкненим Wi-Fi. Деградація швидкості неминуча.",
    logic="Кількість Probe Requests в ефірі > 100 за хвилину",
    confidence=70, severity="INFO",
    tags=["wifi","congestion","public","probe"]),

DiagEntry("L2-045", 2, "Power Management Bug",
    state="RSSI: -40dBm, Link: 1 Mbps",
    explanation="Роутер і пристрій поряд, але вони 'заснули' на мінімальній швидкості через баг Power Management.",
    logic="Високий рівень сигналу при мінімальному Data Rate (Power Save bug)",
    confidence=60, severity="WARNING",
    tags=["wifi","power-management","rate","bug"]),

DiagEntry("L2-046", 2, "AP Isolation Mode Active",
    state="ARP: No response (Local)",
    explanation="Пристрої в мережі не бачать один одного. Вимкни 'Guest Mode' або 'AP Isolation' у роутері.",
    logic="ping(PC_1 -> PC_2) == Fail при успішному ping(PC_1 -> Gateway)",
    confidence=90, severity="WARNING",
    tags=["isolation","ap","guest","wifi"]),

DiagEntry("L2-047", 2, "Malformed WiFi Packet",
    state="Scan: 0x00... MAC address",
    explanation="Якийсь пристрій надсилає 'биті' пакети з нульовим MAC. Це може призвести до нестабільності Wi-Fi.",
    logic="Виявлено пакети з некоректною структурою MAC (нульові адреси)",
    confidence=95, severity="CRITICAL",
    tags=["wifi","malformed","packet","mac"]),

DiagEntry("L2-048", 2, "WiFi-LAN Bridge Error",
    state="Tapo: 4W, WiFi: On, Ping: Fail",
    explanation="Антени працюють, але місток між Wi-Fi та LAN зламався всередині роутера. Потрібен ребут.",
    logic="WiFi Association == OK, але трафік не проходить до шлюзу",
    confidence=85, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["wifi","bridge","firmware","tapo"]),

DiagEntry("L2-049", 2, "Espressif IoT Flooding",
    state="Scan: MAC OUI == Espressif",
    explanation="Смарт-лампа або датчик на чіпі ESP8266/ESP32 постійно шле дані. Може бути вразливим.",
    logic="Виявлено пристрій на чіпі ESP8266/ESP32 з високою частотою запитів",
    confidence=70, severity="WARNING",
    tags=["iot","espressif","esp8266","security"]),

DiagEntry("L2-050", 2, "IGMP Snooping Error",
    state="Ping: Low, Video: Buffering",
    explanation="Smart TV не може отримати відеопотік через помилку в налаштуваннях IGMP роутера.",
    logic="Високий дроп Multicast-пакетів при спробі запуску стрімінгу",
    confidence=65, severity="WARNING",
    tags=["igmp","multicast","smarttv","streaming"]),

DiagEntry("L2-051", 2, "802.11d Country Code Conflict",
    state="SSID: Found, Sig: Strong, CC: US",
    explanation="Твій роутер думає, що він у США, а телефон у Європі. Вони не бачать канали 12-13.",
    logic="Невідповідність 802.11d Country Code у маяках (Beacons) роутера",
    confidence=85, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","country-code","802.11d","channel"]),

DiagEntry("L2-052", 2, "Channel Hopping (Auto DFS)",
    state="Tapo: Power Cycle, WiFi: Slow",
    explanation="Роутер постійно перемикає канали, намагаючись втекти від завад. Це створює мікро-лаги.",
    logic="Зміна номера каналу частіше ніж 3 рази на годину",
    confidence=75, auto_fix="suggest_channel", severity="WARNING",
    tags=["wifi","channel","hopping","instability"]),

DiagEntry("L2-053", 2, "ARP Proxy Misconfiguration",
    state="ARP: Response from Ext. IP",
    explanation="Твій роутер відповідає за чужі IP-адреси. Це створює хаос у маршрутах мережі.",
    logic="Отримання ARP-відповіді для зовнішньої IP-адреси",
    confidence=60, severity="WARNING",
    tags=["arp","proxy","misconfig","routing"]),

DiagEntry("L2-054", 2, "Hidden Background Sync (Xiaomi/Tuya)",
    state="Scan: Unknown OUI (Xiaomi)",
    explanation="Твій китайський смарт-пристрій таємно передає дані на сервери виробника в Азії.",
    logic="Активність трафіку на нестандартних портах для пристроїв Xiaomi/Tuya",
    confidence=50, severity="WARNING",
    tags=["iot","xiaomi","tuya","privacy","sync"]),

DiagEntry("L2-055", 2, "Switch Fabric Overload",
    state="Ping: > 100ms (LAN)",
    explanation="Внутрішній комутатор роутера перевантажений. Він не встигає перекидати пакети між портами.",
    logic="Високий пінг до шлюзу по кабелю при низькому навантаженні CPU",
    confidence=70, auto_fix="tapo_reboot", severity="WARNING",
    tags=["switch","overload","lan","performance"]),

DiagEntry("L2-056", 2, "Driver Emulation Bug (Zero MAC)",
    state="Scan: MAC 00:00:00...",
    explanation="Якийсь пристрій використовує нульову MAC-адресу. Це ознака вірусу або критичного глюка драйвера.",
    logic="Виявлено фрейми з нульовим Source MAC у мережі",
    confidence=99, severity="CRITICAL",
    tags=["mac","driver","bug","virus"]),

DiagEntry("L2-057", 2, "Tapo P110 RF Interference",
    state="Tapo: Power Spike, WiFi: Drop",
    explanation="Розетка Tapo P110 може створювати радіозавади в момент вимірювання енергії.",
    logic="Кореляція між запитом Tapo.getEnergy() та втратою пакетів WiFi",
    confidence=55, severity="INFO",
    tags=["tapo","rf","interference","wifi"]),

DiagEntry("L2-058", 2, "Power Saving WiFi Throttle",
    state="Tapo: < 4W, WiFi: Slow",
    explanation="Роутер перейшов у режим економії, знизивши потужність Wi-Fi передавачів.",
    logic="tapo_watts нижче номіналу + падіння RSSI на всіх клієнтах одночасно",
    confidence=70, auto_fix="tapo_reboot", severity="WARNING",
    tags=["wifi","power-saving","throttle","tapo"]),

DiagEntry("L2-059", 2, "IPv4 DHCP Pool Exhausted",
    state="Scan: IPv6 Link-Local only",
    explanation="Пристрої бачать один одного по IPv6, але не можуть отримати нормальну IPv4-адресу. Пул DHCP вичерпаний.",
    logic="Наявність тільки fe80:: адрес при відсутності адреси 192.168.x.x",
    confidence=85, auto_fix="dhcp_renew", severity="WARNING",
    tags=["dhcp","ipv6","ipv4","exhaustion"]),

DiagEntry("L2-060", 2, "Signal Saturation",
    state="Ping: Fluctuating, RSSI: -30",
    explanation="Ти занадто близько до роутера! Сигнал настільки потужний, що 'засліплює' приймач.",
    logic="RSSI > -20dBm (надто сильний сигнал для нормальної роботи WiFi-приймача)",
    confidence=60, severity="INFO",
    tags=["wifi","rssi","saturation","proximity"]),

# ──────────────────────────────────────────────────────────────
# L3 — NETWORK (IP, Routing & DNS)
# ──────────────────────────────────────────────────────────────
DiagEntry("L3-001", 3, "DNS Resolution Issue",
    state="Ping: 8.8.8.8 OK, Web: Fail",
    explanation="Інтернет є, але твій комп'ютер не може знайти адреси сайтів.",
    logic="ping(IP) == OK ТА gethostbyname(URL) повертає помилку",
    confidence=95, auto_fix="flush_dns", severity="WARNING",
    tags=["dns","resolution"]),

DiagEntry("L3-002", 3, "DHCP Assignment Fail (APIPA)",
    state="IP: 169.254.x.x",
    explanation="Windows не отримала IP-адресу від роутера. Інету не буде.",
    logic="Локальний IP у діапазоні APIPA (169.254.0.0/16)",
    confidence=100, auto_fix="dhcp_renew", severity="CRITICAL",
    tags=["dhcp","apipa","ip"]),

DiagEntry("L3-003", 3, "Gateway Block",
    state="Trace: Stops at Hop 1",
    explanation="Роутер бачить тебе, але відмовляється випускати в інтернет.",
    logic="traceroute зупиняється на першому кроці (IP роутера)",
    confidence=90, severity="CRITICAL",
    tags=["gateway","routing","firewall"]),

DiagEntry("L3-004", 3, "VPN IP Leak",
    state="VPN: On, Real IP: Visible",
    explanation="Твій VPN працює, але твій справжній IP все одно видно. Це небезпечно!",
    logic="external_ip з VPN збігається з external_ip без VPN",
    confidence=99, severity="CRITICAL",
    tags=["vpn","leak","privacy"]),

DiagEntry("L3-005", 3, "Routing Loop",
    state="Ping: High, Path: Unusual",
    explanation="Твої дані ходять кругами по мережі провайдера. Це створює величезні лаги.",
    logic="traceroute показує повторювані IP-адреси на різних хопах",
    confidence=80, severity="WARNING",
    tags=["routing","loop","isp"]),

DiagEntry("L3-006", 3, "Packet Fragmentation",
    state="MTU: Too High, Loss: 10%",
    explanation="Твої пакети занадто великі для цього каналу. Вони розбиваються і губляться.",
    logic="ping -f -l 1472 повертає 'Packet needs to be fragmented'",
    confidence=75, auto_fix="fix_mtu", severity="WARNING",
    tags=["mtu","fragmentation"]),

DiagEntry("L3-007", 3, "DNS Localhost Hijack",
    state="DNS: 127.0.0.1",
    explanation="Якась програма на твоєму ПК перехоплює всі запити до сайтів.",
    logic="Системний DNS встановлено на локальну адресу 127.0.0.1",
    confidence=90, severity="WARNING",
    tags=["dns","hijack","localhost"]),

DiagEntry("L3-008", 3, "ISP DNS Server Down",
    state="DNS: Timeout, Tapo: 6W",
    explanation="DNS-сервер твого провайдера 'ліг'. Сайти не відкриваються.",
    logic="nslookup через сервер провайдера Fail, через 8.8.8.8 — OK",
    confidence=90, auto_fix="set_google_dns", severity="CRITICAL",
    tags=["dns","isp","server-down"]),

DiagEntry("L3-009", 3, "Double NAT Detected",
    state="IP: Public (Not Router)",
    explanation="У тебе два роутери поспіль. Це може заважати іграм та портам.",
    logic="Перший хоп traceroute — приватний IP, другий — теж приватний",
    confidence=85, severity="WARNING",
    tags=["nat","double-nat","gaming"]),

DiagEntry("L3-010", 3, "DNS Poisoning (Phishing)",
    state="DNS: Wrong IP returned",
    explanation="Тебе намагаються перенаправити на підробний сайт. Це фішинг!",
    logic="IP-адреса відомого сайту не збігається з глобальною базою IP",
    confidence=85, auto_fix="set_google_dns", severity="CRITICAL",
    tags=["dns","poisoning","phishing","security"]),

DiagEntry("L3-011", 3, "WAN Interface Frozen",
    state="Ping 8.8.8.8: Fail, Tapo: 7W",
    explanation="Порт інтернету на роутері 'замерз'. Потрібен програмний ребут.",
    logic="tapo_watts OK, LAN OK, але зовнішнього зв'язку немає зовсім",
    confidence=90, auto_fix="tapo_reboot", severity="CRITICAL",
    tags=["wan","freeze","tapo"]),

DiagEntry("L3-012", 3, "Routing Table Corrupted",
    state="Route: Default missing",
    explanation="Твій комп'ютер забув, куди відправляти дані в інтернет. Шлях втрачено.",
    logic="route print не показує шлюз за замовчуванням (0.0.0.0)",
    confidence=100, auto_fix="fix_routes", severity="CRITICAL",
    tags=["routing","gateway"]),

DiagEntry("L3-013", 3, "ISP DNS Port Filtered",
    state="Port: 53 Blocked",
    explanation="Твій провайдер блокує сторонні DNS. Ти змушений використовувати тільки їхні.",
    logic="Запити до 8.8.8.8:53 не проходять, а до шлюзу — проходять",
    confidence=95, auto_fix="set_doh", severity="WARNING",
    tags=["dns","isp","port53","doh"]),

DiagEntry("L3-014", 3, "Carrier-Grade NAT (CGNAT)",
    state="Trace: Private IP in WAN",
    explanation="Твій провайдер економить IP і ховає тебе за загальною адресою.",
    logic="Твій WAN IP знаходиться в діапазоні 100.64.0.0/10",
    confidence=95, severity="WARNING",
    tags=["cgnat","nat","isp"]),

DiagEntry("L3-015", 3, "Rogue Gateway / MITM",
    state="IP: 192.168.1.1, MAC: New",
    explanation="У мережі з'явився другий роутер, який видає себе за головний. Це пастка!",
    logic="Виявлено новий MAC на IP шлюзу (Gateway) у таблиці ARP",
    confidence=99, severity="CRITICAL",
    tags=["security","mitm","arp","gateway"]),

DiagEntry("L3-016", 3, "Port Forwarding Issue",
    state="Ping: 8.8.8.8 OK, Game: No Conn",
    explanation="Твій роутер блокує вхідні дані від гри. Потрібно відкрити порти.",
    logic="UPnP вимкнено + NAT Type визначено як 'Strict'",
    confidence=85, severity="WARNING",
    tags=["port-forwarding","nat","gaming"]),

DiagEntry("L3-017", 3, "Inbound DoS Attack",
    state="PPS: > 10,000, CPU: 100%",
    explanation="Хтось закидає твій роутер мільйонами запитів, щоб 'покласти' інтернет.",
    logic="Вибухове зростання кількості пакетів за секунду при низькому трафіку",
    confidence=95, severity="CRITICAL",
    tags=["ddos","attack","security"]),

DiagEntry("L3-018", 3, "ISP Backbone Congestion",
    state="Trace: High MS at Hop 4",
    explanation="Проблема на центральному вузлі зв'язку твого міста. Лагатиме у всіх.",
    logic="Різке зростання затримки на конкретному вузлі посеред маршруту",
    confidence=85, severity="WARNING",
    tags=["isp","congestion","backbone"]),

DiagEntry("L3-019", 3, "DNS Leak (VPN)",
    state="VPN: On, DNS: Original",
    explanation="VPN працює, але твої запити до сайтів ідуть через провайдера. Конфіденційність втрачена!",
    logic="IP DNS-сервера належить місцевому провайдеру під час роботи VPN",
    confidence=95, severity="WARNING",
    tags=["vpn","dns","leak","privacy"]),

DiagEntry("L3-020", 3, "DHCP Pool Exhausted",
    state="Tapo: 8W, Link: Up, IP: No",
    explanation="Роутер не може видати тобі IP, бо вільні адреси закінчилися.",
    logic="DHCP Discover відправляється, але пул адрес порожній",
    confidence=85, severity="WARNING",
    tags=["dhcp","pool","ip"]),

DiagEntry("L3-021", 3, "Gateway Hijack (Route)",
    state="Route: 0.0.0.0 → Local",
    explanation="Твій трафік перенаправлено на інший пристрій у домі. Це шпигунство!",
    logic="Шлюз за замовчуванням змінився на IP іншого ПК, а не роутера",
    confidence=90, severity="CRITICAL",
    tags=["security","gateway","hijack","mitm"]),

DiagEntry("L3-022", 3, "ICMP Redirect Attack",
    state="Scan: ICMP Redirect",
    explanation="Хтось у мережі каже твоєму ПК йти іншим маршрутом. Можлива атака перехоплення трафіку.",
    logic="Отримання ICMP-пакетів типу 5 (Redirect Message)",
    confidence=70, severity="CRITICAL",
    tags=["icmp","redirect","attack","routing"]),

DiagEntry("L3-023", 3, "Dynamic IP Update",
    state="External IP: Changed",
    explanation="Твоя зовнішня IP-адреса змінилася. Це нормальна поведінка для динамічного тарифу провайдера.",
    logic="Попередній external_ip != поточному (зберігається в базі)",
    confidence=100, severity="INFO",
    tags=["ip","dynamic","isp","wan"]),

DiagEntry("L3-024", 3, "ISP Gateway Issue",
    state="Trace: Hop 2 Timeout",
    explanation="Проблема на першому вузлі за межами твого дому. Потрібно дзвонити провайдеру.",
    logic="Втрата пакетів починається рівно на другому хопі traceroute",
    confidence=90, severity="CRITICAL",
    tags=["isp","gateway","traceroute","wan"]),

DiagEntry("L3-025", 3, "BGP Flapping (Global Routes)",
    state="Ping: Jitter 500ms, L3",
    explanation="Глобальні маршрути в інтернеті нестабільні. Це проблема великих провайдерів — зачекай.",
    logic="Хаотична зміна маршруту (Hops) при кожному новому traceroute",
    confidence=60, severity="WARNING",
    tags=["bgp","routing","isp","instability"]),

DiagEntry("L3-026", 3, "Netmask Configuration Error",
    state="Subnet Mask: Mismatch",
    explanation="Твоя маска підмережі налаштована неправильно. Ти не бачиш частину пристроїв у мережі.",
    logic="IP в одній мережі, але маска (напр. 255.255.255.255) блокує зв'язок",
    confidence=80, auto_fix="fix_routes", severity="WARNING",
    tags=["subnet","netmask","config","ip"]),

DiagEntry("L3-027", 3, "Foreign Routing (Geo Redirect)",
    state="Trace: IP in 103.x.x.x",
    explanation="Твій трафік чомусь іде через Азію, хоча сервер у Європі. Це через провайдера або CDN.",
    logic="traceroute показує IP-адреси з геопозицією, далекою від цілі",
    confidence=80, severity="WARNING",
    tags=["routing","geo","isp","traceroute"]),

DiagEntry("L3-028", 3, "DNS Parental Control Filter",
    state="DNS: Quad9, Query: Blocked",
    explanation="DNS-система блокує цей сайт через фільтр безпеки або батьківський контроль.",
    logic="DNS-запит повертає 0.0.0.0 або NXDOMAIN для легітимного сайту",
    confidence=90, auto_fix="set_google_dns", severity="WARNING",
    tags=["dns","filter","parental","blocked"]),

DiagEntry("L3-029", 3, "VPN Server Overload",
    state="VPN: Connected, Speed: 1 Mbps",
    explanation="Твій VPN-сервер перевантажений. Спробуй змінити країну або сервер підключення.",
    logic="Швидкість через VPN в 10+ разів нижча за швидкість без нього",
    confidence=75, severity="WARNING",
    tags=["vpn","overload","speed","server"]),

DiagEntry("L3-030", 3, "UDP Packet Loss at ISP",
    state="Ping: Low, Discord: Disconnect",
    explanation="Веб-сайти працюють, але голосовий UDP-зв'язок обривається. Проблема на стороні провайдера.",
    logic="TCP працює стабільно, але UDP втрачає понад 10% пакетів",
    confidence=80, severity="WARNING",
    tags=["udp","packet-loss","isp","discord"]),

DiagEntry("L3-031", 3, "Routing Loop (Infinity)",
    state="Trace: 30+ Hops",
    explanation="Твій запит загубився в нескінченному циклі між серверами. Максимум хопів досягнуто!",
    logic="traceroute досягає ліміту в 30 кроків без фінальної цілі",
    confidence=100, severity="CRITICAL",
    tags=["routing","loop","traceroute","infinity"]),

DiagEntry("L3-032", 3, "Unsecured Router Admin Panel",
    state="IP: Public, Port 80: Open",
    explanation="Адмін-панель твого роутера відкрита для всього інтернету. Тебе можуть зламати!",
    logic="Зовнішній скан порту 80/443 на твоєму Public IP повертає Open",
    confidence=95, severity="CRITICAL",
    tags=["security","admin","port","router"]),

DiagEntry("L3-033", 3, "ICMP Spoofing (Fake Ping)",
    state="Ping: 1ms (to 8.8.8.8)",
    explanation="Хтось імітує відповіді від Google. Твій пінг фейковий, інтернет насправді не працює.",
    logic="Неправдоподібно низький пінг до віддаленого сервера (< 1ms до 8.8.8.8)",
    confidence=90, severity="CRITICAL",
    tags=["icmp","spoofing","ping","security"]),

DiagEntry("L3-034", 3, "VPN Key Mismatch (WireGuard)",
    state="VPN: WireGuard, Handshake: Fail",
    explanation="Твій WireGuard VPN не може підключитися через неправильний ключ доступу. Перегенеруй ключі.",
    logic="Лог WireGuard показує відсутність відповіді після Handshake",
    confidence=100, severity="CRITICAL",
    tags=["vpn","wireguard","key","handshake"]),

DiagEntry("L3-035", 3, "Application Layer ISP Block",
    state="Ping: OK, Steam: Offline",
    explanation="Мережа в нормі, але провайдер або фаєрвол блокує саме Steam (або іншу програму).",
    logic="ping до серверів Steam OK, але TCP-з'єднання скидається (Reset)",
    confidence=80, severity="WARNING",
    tags=["isp","block","steam","tcp-reset"]),

DiagEntry("L3-036", 3, "Internal ISP Network Only",
    state="IP: 10.x.x.x, Link: Up",
    explanation="Ти підключений до внутрішньої мережі провайдера, але виходу в глобальний інтернет немає.",
    logic="Отримано IP від провайдера, але пінг далі першого вузла не йде",
    confidence=90, severity="CRITICAL",
    tags=["isp","wan","routing","internet"]),

DiagEntry("L3-037", 3, "ISP Backbone Congestion",
    state="Trace: High MS at Hop 4",
    explanation="Проблема на центральному вузлі зв'язку твого міста. Лагатиме у всіх одночасно.",
    logic="Різке зростання затримки на конкретному вузлі посеред traceroute маршруту",
    confidence=85, severity="WARNING",
    tags=["isp","backbone","congestion","traceroute"]),

DiagEntry("L3-038", 3, "NIC Driver Logic Error",
    state="Tapo: 5W, No IP, No Link",
    explanation="Програмна помилка драйвера мережевої карти. Комп'ютер 'думає', що IP є, але зв'язку немає.",
    logic="Невідповідність даних ipconfig та реального стану адаптера",
    confidence=70, auto_fix="enable_nic", severity="WARNING",
    tags=["nic","driver","bug","ip"]),

DiagEntry("L3-039", 3, "DNS Rate Limiting",
    state="DNS: Recursive Query Limit",
    explanation="Ти робиш занадто багато DNS-запитів. Сервер тимчасово заблокував тебе.",
    logic="Отримання помилки REFUSED від DNS-сервера",
    confidence=65, auto_fix="set_doh", severity="WARNING",
    tags=["dns","rate-limit","blocked","doh"]),

DiagEntry("L3-040", 3, "VPN Certificate Expired",
    state="VPN: OpenVPN, Log: Cert Exp.",
    explanation="Твій сертифікат безпеки VPN застарів. Потрібно оновити файл конфігурації.",
    logic="Лог OpenVPN містить помилку TLS Error: Certificate expired",
    confidence=100, severity="CRITICAL",
    tags=["vpn","certificate","expired","openvpn"]),

DiagEntry("L3-041", 3, "IPv6 Global Routing Fail",
    state="IPv6: Link-Local only",
    explanation="IPv6 працює тільки всередині дому (fe80::). Виходу в глобальну мережу немає.",
    logic="Наявність адреси fe80:: при відсутності глобальної 2001::",
    confidence=95, severity="WARNING",
    tags=["ipv6","routing","global","isp"]),

DiagEntry("L3-042", 3, "Port Scanning Detection",
    state="Scan: Syn Stealth Scan",
    explanation="Хтось зовні таємно сканує твої порти. Це підготовка до хакерської атаки!",
    logic="Реєстрація великої кількості напіввідкритих TCP-з'єднань (SYN без ACK)",
    confidence=99, severity="CRITICAL",
    tags=["security","port-scan","syn","attack"]),

DiagEntry("L3-043", 3, "Strict NAT Type (Gaming)",
    state="NAT: Symmetric, Game: Lag",
    explanation="Твій NAT занадто суворий. Ти не зможеш бути хостом у грі або в голосовому чаті.",
    logic="STUN-тест показує зміну зовнішнього порту для різних цілей",
    confidence=90, severity="WARNING",
    tags=["nat","gaming","strict","stun"]),

DiagEntry("L3-044", 3, "IPv4 Stack Failure",
    state="Ping: IPv6 OK, IPv4 Fail",
    explanation="Новий протокол IPv6 працює, а старий IPv4 збоїть. Деякі сайти не відкриються.",
    logic="ping6 google.com — OK, ping google.com — Fail",
    confidence=85, auto_fix="fix_routes", severity="CRITICAL",
    tags=["ipv4","ipv6","stack","routing"]),

DiagEntry("L3-045", 3, "DHCP Pool Conflict",
    state="Tapo: 8W, Link: Up, IP: None",
    explanation="Роутер намагається дати IP, який вже зайнятий іншим пристроєм. Конфлікт DHCP-адрес.",
    logic="DHCP NAK повідомлення в системному лозі роутера",
    confidence=80, auto_fix="dhcp_renew", severity="WARNING",
    tags=["dhcp","pool","conflict","ip"]),

DiagEntry("L3-046", 3, "Ping Flood DoS Attack",
    state="Scan: ICMP Echo Storm",
    explanation="Твій канал забитий безглуздими ping-запитами. Мережа гальмує через DoS атаку.",
    logic="Отримання > 500 ICMP пакетів за секунду на WAN інтерфейс",
    confidence=95, severity="CRITICAL",
    tags=["dos","icmp","flood","attack"]),

DiagEntry("L3-047", 3, "Triple NAT Detected",
    state="Trace: Hop 2 Private IP",
    explanation="Занадто багато посередників! Твій трафік проходить через 3 роутери. Видали зайві.",
    logic="Перші три хопи traceroute мають приватні адреси (192.168/10.x)",
    confidence=90, severity="WARNING",
    tags=["nat","triple","routing","latency"]),

DiagEntry("L3-048", 3, "IPv6 Privacy Extensions Active",
    state="IPv6: Temporary Address",
    explanation="Твій ПК часто змінює IPv6-адресу для анонімності. Це нормальна поведінка Windows.",
    logic="Наявність декількох IPv6, один з яких позначений як temporary",
    confidence=100, severity="INFO",
    tags=["ipv6","privacy","temporary","windows"]),

DiagEntry("L3-049", 3, "TCP Firewall Drop (ICMP Passes)",
    state="Ping: 8.8.8.8 OK, No TCP",
    explanation="Пінги проходять, але фаєрвол блокує весь корисний TCP-трафік. Перевір правила фаєрволу.",
    logic="ICMP (Ping) працює, але спроба telnet або curl скидається",
    confidence=85, severity="WARNING",
    tags=["firewall","tcp","icmp","block"]),

DiagEntry("L3-050", 3, "Stealth UDP Service Discovery",
    state="Scan: UDP Port Scan",
    explanation="Хакер шукає відкриті ігрові сервери або VPN-сервіси на твоєму IP-адресі.",
    logic="Масові UDP запити на випадкові порти (1024-65535)",
    confidence=90, severity="CRITICAL",
    tags=["udp","scan","hacker","security"]),

DiagEntry("L3-051", 3, "DHCP Lease Timeout",
    state="Tapo: 4W, IP: Expired",
    explanation="Час оренди IP-адреси вийшов, а роутер не дав нову. Зв'язок розірвано.",
    logic="tapo_watts в нормі, але IP видалено з мережевого інтерфейсу",
    confidence=85, auto_fix="dhcp_renew", severity="CRITICAL",
    tags=["dhcp","lease","timeout","ip"]),

DiagEntry("L3-052", 3, "Legacy IPv6 Tunneling (6to4)",
    state="IPv6: Tunnel 6to4 detected",
    explanation="Ти використовуєш застарілий метод IPv6 (6to4). Це повільно та небезпечно.",
    logic="IPv6 адреса починається з префікса 2002::",
    confidence=100, severity="WARNING",
    tags=["ipv6","6to4","tunnel","legacy"]),

DiagEntry("L3-053", 3, "Static IP Collision",
    state="IP: Static, Conflict detected",
    explanation="Ти вручну поставив IP, який вже зайнятий. Конфлікт — обидва пристрої матимуть збої.",
    logic="Windows видає системне повідомлення про конфлікт IP-адрес",
    confidence=99, auto_fix="dhcp_renew", severity="CRITICAL",
    tags=["ip","static","conflict","dhcp"]),

DiagEntry("L3-054", 3, "Advanced OS Fingerprinting",
    state="Scan: Fin Scan Detected",
    explanation="Хтось намагається визначити твою операційну систему для пошуку вразливостей.",
    logic="Отримання TCP пакетів з прапором FIN без попереднього з'єднання",
    confidence=95, severity="CRITICAL",
    tags=["security","fingerprinting","scan","os"]),

DiagEntry("L3-055", 3, "MTU Black Hole (VPN)",
    state="VPN: On, MTU: 1500",
    explanation="Через VPN пакети стають завеликими і 'зникають' (MTU Black Hole). Зменш MTU до 1400.",
    logic="Повна втрата зв'язку при передачі великих файлів через VPN тунель",
    confidence=80, auto_fix="fix_mtu", severity="WARNING",
    tags=["mtu","vpn","blackhole","fragmentation"]),

DiagEntry("L3-056", 3, "Smart Plug Offline (Relocation)",
    state="Tapo: 0W, App: Online",
    explanation="Розетку Tapo вимкнули фізично, але в додатку вона ще 'світиться'. Зв'язок з плагом втрачено.",
    logic="Помилка тайм-ауту при спробі handshake з P110",
    confidence=70, severity="INFO",
    tags=["tapo","offline","plug","status"]),

DiagEntry("L3-057", 3, "DNS Spoofing Global",
    state="DNS: Reply from Unknown IP",
    explanation="Ти питаєш Google, а відповідає невідомий сервер. Тебе ведуть на фішинговий сайт!",
    logic="IP-адреса відповіді DNS не збігається з IP запитуваного сервера",
    confidence=95, auto_fix="set_doh", severity="CRITICAL",
    tags=["dns","spoofing","phishing","security"]),

DiagEntry("L3-058", 3, "Routing Table Crash (Empty)",
    state="Tapo: 6W, Link: Up, Data: 0",
    explanation="Залізо працює, але таблиця маршрутів у роутері пуста. Він не знає куди надсилати пакети.",
    logic="isup == True, tapo_watts OK, але route print порожній",
    confidence=90, auto_fix="fix_routes", severity="CRITICAL",
    tags=["routing","crash","table","router"]),

DiagEntry("L3-059", 3, "ICMP TTL Filtering by ISP",
    state="Ping: OK, TTL: Low",
    explanation="Провайдер штучно обмежує TTL твоїх пакетів, щоб ти не міг тестувати мережу.",
    logic="Отримання пакетів з дуже малим значенням TTL (напр. < 5)",
    confidence=65, severity="INFO",
    tags=["icmp","ttl","isp","filter"]),

DiagEntry("L3-060", 3, "VPN DNS Leak",
    state="VPN: On, DNS: Original ISP",
    explanation="VPN працює, але твої DNS-запити все одно йдуть через провайдера. Конфіденційність втрачена!",
    logic="IP DNS-сервера належить місцевому провайдеру під час активної роботи VPN",
    confidence=95, auto_fix="set_doh", severity="CRITICAL",
    tags=["vpn","dns","leak","privacy"]),

# ──────────────────────────────────────────────────────────────
# L4 — TRANSPORT (TCP/UDP, Ports & Firewall)
# ──────────────────────────────────────────────────────────────
DiagEntry("L4-001", 4, "Minecraft Port Closed",
    state="Port 25565: Closed",
    explanation="Твій сервер Minecraft закритий для друзів. Потрібно відкрити порт 25565.",
    logic="socket.connect на локальний порт 25565 — OK, на зовнішній — Fail",
    confidence=100, severity="WARNING",
    tags=["gaming","port","minecraft"]),

DiagEntry("L4-002", 4, "Packet Loss L4 (TCP Retransmits)",
    state="TCP_Retransmits > 5%",
    explanation="Дані губляться і пересилаються заново. Це ознака перевантаження каналу.",
    logic="Аналіз Win32_PerfRawData_Tcpip_TCPv4 (Retransmitted Segments)",
    confidence=85, severity="WARNING",
    tags=["tcp","packet-loss","retransmit"]),

DiagEntry("L4-003", 4, "SMB Port 445 Open (WAN)",
    state="Scan: Port 445 Open (WAN)",
    explanation="Твій доступ до файлів відкритий для всього світу! Це критична вразливість.",
    logic="Зовнішній скан порту 445 на твоєму Public IP повертає Open",
    confidence=99, severity="CRITICAL",
    tags=["security","smb","port445","wannacry"]),

DiagEntry("L4-004", 4, "SSH Brute Force",
    state="SSH Port 22: Brute Force",
    explanation="Хтось намагається підібрати пароль до твого сервера/роутера по SSH.",
    logic="Понад 5 невдалих спроб з'єднання на порт 22 за хвилину з одного IP",
    confidence=95, severity="CRITICAL",
    tags=["security","ssh","brute-force"]),

DiagEntry("L4-005", 4, "RDP Port 3389 Exposed",
    state="RDP Port 3389: Exposed",
    explanation="Твій віддалений стіл відкритий для хакерів. Терміново закрий порт 3389!",
    logic="Публічний IP відповідає на запити порту 3389",
    confidence=98, severity="CRITICAL",
    tags=["security","rdp","port3389"]),

DiagEntry("L4-006", 4, "UDP Reflection DDoS",
    state="UDP Flood: Port 80",
    explanation="Хтось маскує атаку під звичайний веб-трафік. Твій ігровий пінг 'летить' вгору.",
    logic="Масові UDP пакети на порт 80, що зазвичай використовує TCP",
    confidence=95, severity="CRITICAL",
    tags=["ddos","udp","attack"]),

DiagEntry("L4-007", 4, "Bufferbloat Detected",
    state="Tapo: 5W, RTT: High",
    explanation="Твій роутер переповнює чергу пакетів. Це створює лаги, хоча швидкість є.",
    logic="Значне зростання Round-Trip Time при повному завантаженні каналу",
    confidence=75, severity="WARNING",
    tags=["bufferbloat","latency","qos"]),

DiagEntry("L4-008", 4, "Connection Limit Hit",
    state="Tapo: 10W, TCP_Conn > 500",
    explanation="Занадто багато відкритих програм. Роутер не встигає обробляти таблицю сесій.",
    logic="tapo_watts зростає паралельно з кількістю активних Established з'єднань",
    confidence=80, severity="WARNING",
    tags=["tcp","connections","torrent"]),

DiagEntry("L4-009", 4, "P2P Overload (Torrent)",
    state="Tapo: 12W, Conn > 2000",
    explanation="Твій Torrent відкрив занадто багато з'єднань. Роутер може зависнути.",
    logic="Established сесії > 2000 паралельно з піковим споживанням tapo_watts",
    confidence=85, auto_fix="suggest_torrent_limit", severity="WARNING",
    tags=["torrent","p2p","connections"]),

DiagEntry("L4-010", 4, "Outdated TLS 1.0/1.1",
    state="TLS: Version 1.0/1.1",
    explanation="Ти використовуєш старий протокол захисту. Хакер може підглянути твої дані.",
    logic="Фіксація TLS 1.0/1.1 у заголовках пакетів замість 1.3",
    confidence=100, severity="WARNING",
    tags=["ssl","tls","security","encryption"]),

DiagEntry("L4-011", 4, "Man-in-the-Middle SSL Strip",
    state="Port 80: Redirected",
    explanation="Хтось намагається перехопити твій пароль, підміняючи захищене з'єднання.",
    logic="Спроба пониження протоколу з HTTPS на HTTP",
    confidence=95, severity="CRITICAL",
    tags=["security","mitm","ssl","https"]),

DiagEntry("L4-012", 4, "DNS Amplification Attack",
    state="UDP: Port 53, Length > 512",
    explanation="Твій ПК використовують для потужної атаки на когось іншого через DNS.",
    logic="Аномально великі UDP-пакети на порту 53",
    confidence=95, severity="CRITICAL",
    tags=["dns","amplification","ddos","security"]),

DiagEntry("L4-013", 4, "Gaming Input Lag (Nagle)",
    state="TCP_Nagle: Active",
    explanation="Алгоритм Нагла збирає дані в купу. Це добре для файлів, але погано для ігор.",
    logic="Перевірка TcpNoDelay у реєстрі Windows (якщо 0 — лаги в іграх)",
    confidence=100, auto_fix="disable_nagle", severity="WARNING",
    tags=["gaming","nagle","latency","tcp"]),

DiagEntry("L4-014", 4, "VoIP Brute Force",
    state="Port 5060: SIP Attack",
    explanation="Хтось намагається зламати твою IP-телефонію або прослухати дзвінки.",
    logic="Масові запити на порт 5060 (UDP/TCP) з невідомих IP-адрес",
    confidence=95, severity="CRITICAL",
    tags=["voip","sip","brute-force","security"]),

DiagEntry("L4-015", 4, "4K Video Load",
    state="Tapo: 9W, UDP: Stream",
    explanation="Ти дивишся відео у надвисокій якості. Роутер працює на межі потужності.",
    logic="Стабільний потік UDP-даних > 25 Мбіт/с + ріст tapo_watts",
    confidence=80, severity="INFO",
    tags=["streaming","4k","bandwidth"]),

DiagEntry("L4-016", 4, "Outbound Port Block",
    state="SYN_Sent: High, No Sync",
    explanation="Твій фаєрвол або провайдер блокує вихідні з'єднання. Навіть Google не відкриється.",
    logic="Велика кількість статусів SYN_SENT без переходу в ESTABLISHED",
    confidence=90, severity="CRITICAL",
    tags=["firewall","syn","port","block"]),

DiagEntry("L4-017", 4, "Console/Gaming Port Issue",
    state="Port 3074: Moderate NAT",
    explanation="Твоя консоль має обмежений доступ. Можливі проблеми з голосовим чатом у іграх (CoD, Xbox).",
    logic="Тест порту 3074 (UDP) повертає статус 'Filtered' або 'Closed'",
    confidence=85, severity="WARNING",
    tags=["gaming","nat","console","port"]),

DiagEntry("L4-018", 4, "Half-Open TCP Connections",
    state="TCP_FIN_Wait: Excessive",
    explanation="Програми некоректно закривають з'єднання. Пам'ять роутера засмічується 'зависшими' сесіями.",
    logic="Понад 20% сесій перебувають у статусі FIN_WAIT_1 або TIME_WAIT",
    confidence=70, severity="WARNING",
    tags=["tcp","fin-wait","sessions","memory"]),

DiagEntry("L4-019", 4, "SMB Port Open on WAN",
    state="Scan: Port 445 Open (WAN)",
    explanation="Твій доступ до файлів відкритий для всього інтернету! Критична вразливість EternalBlue/WannaCry.",
    logic="Зовнішній скан порту 445 на твоєму Public IP повертає Open",
    confidence=99, severity="CRITICAL",
    tags=["smb","security","port445","vulnerability"]),

DiagEntry("L4-020", 4, "Firewall RST Storm",
    state="Tapo: 4W, TCP_Reset: High",
    explanation="Фаєрвол роутера агресивно скидає з'єднання. Можливо, через вірус або некоректні правила.",
    logic="Високий рівень пакетів з прапором RST (Reset) у внутрішній мережі",
    confidence=75, severity="WARNING",
    tags=["firewall","rst","tcp","virus"]),

DiagEntry("L4-021", 4, "DNS Zone Transfer Attempt",
    state="DNS: Port 53, Proto: TCP",
    explanation="Хтось намагається скачати всю базу DNS-записів через TCP. Це розвідка хакера.",
    logic="Запит на порт 53 через TCP (зазвичай DNS використовує UDP)",
    confidence=90, severity="CRITICAL",
    tags=["dns","zone-transfer","tcp","security"]),

DiagEntry("L4-022", 4, "DPI SSL Interception",
    state="Tapo: 6W, SSL_Handshake: Fail",
    explanation="Хтось намагається підглянути у твій зашифрований трафік. Можливо, вірус-проксі або DPI провайдера.",
    logic="Помилки сертифікатів при встановленні HTTPS з'єднань",
    confidence=65, severity="CRITICAL",
    tags=["dpi","ssl","mitm","security"]),

DiagEntry("L4-023", 4, "RDP Port 3389 Exposed",
    state="RDP Port 3389: Exposed",
    explanation="Твій віддалений стіл відкритий для всього інтернету. Терміново закрий порт 3389!",
    logic="Публічний IP відповідає на запити порту 3389",
    confidence=98, severity="CRITICAL",
    tags=["rdp","security","port3389","exposure"]),

DiagEntry("L4-024", 4, "UDP Gaming Fragmentation",
    state="UDP: Packet Size > 1500",
    explanation="Твої ігрові UDP-пакети занадто великі і розбиваються на частини. Це створює мікро-фризи.",
    logic="Отримання фрагментованих UDP-дейтаграм у ігровому сеансі",
    confidence=80, auto_fix="fix_mtu", severity="WARNING",
    tags=["udp","fragmentation","gaming","mtu"]),

DiagEntry("L4-025", 4, "Connection Dropout (KeepAlive Off)",
    state="Tapo: 5W, TCP_KeepAlive: Off",
    explanation="Програми часто втрачають зв'язок, бо роутер занадто швидко розриває тихі сесії.",
    logic="Сесії закриваються роутером раніше, ніж завершується KeepAlive таймер",
    confidence=60, severity="WARNING",
    tags=["tcp","keepalive","session","timeout"]),

DiagEntry("L4-026", 4, "UPnP Auto Port Mapping Risk",
    state="Scan: UPnP Port Mapping",
    explanation="Програма сама відкрила вхід у твою мережу через UPnP. Перевір — це може бути вірус.",
    logic="Виявлено динамічне правило переадресації портів через UPnP",
    confidence=90, severity="WARNING",
    tags=["upnp","port","security","mapping"]),

DiagEntry("L4-027", 4, "TCP Out-of-Order Packets",
    state="TCP: Out-of-Order > 10%",
    explanation="Пакети приходять не по черзі через нестабільний маршрут. Затримки у відео та іграх.",
    logic="Аналіз лічильника TCP Out-of-Order Segments у статистиці",
    confidence=85, severity="WARNING",
    tags=["tcp","out-of-order","routing","flapping"]),

DiagEntry("L4-028", 4, "SSL Strip MITM Attack",
    state="Port 80: Redirected",
    explanation="Хтось намагається перехопити твій пароль, підміняючи HTTPS на HTTP (SSL Stripping).",
    logic="Спроба пониження протоколу з HTTPS на HTTP (SSL Stripping атака)",
    confidence=95, severity="CRITICAL",
    tags=["mitm","ssl-strip","security","https"]),

DiagEntry("L4-029", 4, "SYN Flood (Possible Virus)",
    state="TCP_Conn: Stuck in SYN",
    explanation="ПК намагається відкрити тисячі з'єднань одночасно. Схоже на вірус або SYN Flood атаку.",
    logic="Кількість сесій у статусі SYN_SENT перевищує 100 за секунду",
    confidence=90, severity="CRITICAL",
    tags=["syn-flood","dos","virus","tcp"]),

DiagEntry("L4-030", 4, "DPI HTTPS Filtering",
    state="Port 443: TCP Reset",
    explanation="Провайдер або фаєрвол розриває твої зашифровані HTTPS з'єднання. Блокування сервісу через DPI.",
    logic="Отримання RST пакета одразу після Client Hello у TLS-сесії",
    confidence=85, severity="WARNING",
    tags=["dpi","https","tcp-reset","isp"]),

DiagEntry("L4-031", 4, "QUIC Protocol Blocked",
    state="QUIC: Blocked, Fallback: TCP",
    explanation="Твій провайдер блокує QUIC (UDP 443) для YouTube/Google. Відео вантажиться довше.",
    logic="Відсутність відповідей на UDP порт 443 при роботі сервісів Google",
    confidence=70, severity="WARNING",
    tags=["quic","udp","isp","youtube"]),

DiagEntry("L4-032", 4, "SSL Certificate Expired",
    state="Tapo: 6W, SSL: Expired",
    explanation="Ти заходиш на сайт із простроченим сертифікатом. Браузер правильно попереджає про небезпеку.",
    logic="Валідація дати закінчення SSL Certificate через OpenSSL запит",
    confidence=100, severity="WARNING",
    tags=["ssl","certificate","expired","security"]),

DiagEntry("L4-033", 4, "Remote Node TCP Congestion",
    state="TCP: ZeroWindow",
    explanation="Сервер, з якого ти качаєш, не встигає приймати дані (Window Size = 0). Проблема на тому боці.",
    logic="Отримання пакетів із Window Size = 0 від віддаленого хоста",
    confidence=90, severity="WARNING",
    tags=["tcp","window","congestion","remote"]),

DiagEntry("L4-034", 4, "VoIP Brute Force (SIP)",
    state="Port 5060: SIP Attack",
    explanation="Хтось намагається зламати IP-телефонію або прослухати дзвінки через порт 5060.",
    logic="Масові запити на порт 5060 (UDP/TCP) з невідомих IP-адрес",
    confidence=95, severity="CRITICAL",
    tags=["voip","sip","brute-force","security"]),

DiagEntry("L4-035", 4, "Excessive VPN MSS Fragmentation",
    state="VPN: On, MSS: < 1200",
    explanation="Налаштування MSS VPN занадто малі. Дані ріжуться на дрібні шматки, що гальмує інтернет.",
    logic="Maximum Segment Size занижений без нагальної потреби",
    confidence=80, auto_fix="fix_mtu", severity="WARNING",
    tags=["vpn","mtu","mss","fragmentation"]),

DiagEntry("L4-036", 4, "TCP Congestion Avoidance",
    state="TCP: Fast Retransmit",
    explanation="Мережа помітила втрати і знизила швидкість передачі через алгоритм Fast Retransmit.",
    logic="Активація алгоритму Fast Retransmit у TCP стеку Windows",
    confidence=70, severity="INFO",
    tags=["tcp","congestion","retransmit","bandwidth"]),

DiagEntry("L4-037", 4, "NTP Time Sync Attack",
    state="Port 123: NTP Spoofing",
    explanation="Хтось намагається збити час на твоєму ПК, щоб зламати сертифікати безпеки.",
    logic="Отримання відповідей часу від неавторизованих NTP-серверів",
    confidence=85, severity="CRITICAL",
    tags=["ntp","security","time","spoofing"]),

DiagEntry("L4-038", 4, "Zombie TCP Sessions",
    state="Tapo: 4W, TCP: Ghost Conn",
    explanation="У пам'яті роутера 'висять' мертві з'єднання без жодного пакету. Вони займають ресурси.",
    logic="Наявність сесій без жодного пакету протягом останніх 10 хвилин",
    confidence=65, severity="WARNING",
    tags=["tcp","zombie","session","memory"]),

DiagEntry("L4-039", 4, "Self-Signed SSL Phishing Risk",
    state="SSL: Self-Signed Cert",
    explanation="Сайт використовує самопідписаний сертифікат. Це ознака підробки або вірусу-проксі.",
    logic="Помилка Authority Key Identifier при перевірці ланцюжка довіри",
    confidence=90, severity="CRITICAL",
    tags=["ssl","self-signed","phishing","security"]),

DiagEntry("L4-040", 4, "Socket Leak (Program Bug)",
    state="Tapo: 6W, TCP_Reset: Loop",
    explanation="Якась програма постійно відкриває/закриває порти у циклі. Перезапусти її або перевір антивірусом.",
    logic="Циклічне зростання RST пакетів між локальним ПК та шлюзом",
    confidence=80, severity="WARNING",
    tags=["socket","leak","tcp","program"]),

# ──────────────────────────────────────────────────────────────
# L5-L6 — SESSION / PRESENTATION
# ──────────────────────────────────────────────────────────────
DiagEntry("L5-001", 5, "SSL Handshake Timeout",
    state="SSL: Handshake Timeout",
    explanation="Твій комп'ютер і сайт не можуть домовитися про секретний шифр.",
    logic="SSLError при спробі встановити захищене з'єднання",
    confidence=95, severity="WARNING",
    tags=["ssl","handshake","tls"]),

DiagEntry("L5-002", 5, "Cookie Expiration",
    state="Auth: Session ID Expired",
    explanation="Твій вхід на сайт застарів. Потрібно заново ввести логін і пароль.",
    logic="HTTP статус 401 Unauthorized або видалення сесійної куки",
    confidence=100, severity="INFO",
    tags=["session","cookie","auth"]),

DiagEntry("L5-003", 5, "Ransomware / Spyware Activity",
    state="Data: Encrypted (Unknown)",
    explanation="Якась програма шле зашифровані дані на невідомий сервер. Це підозріло!",
    logic="Аномальний потік зашифрованого трафіку на новий IP",
    confidence=60, severity="CRITICAL",
    tags=["security","ransomware","spyware","malware"]),

DiagEntry("L5-004", 5, "SSH Key Mismatch (MITM Risk)",
    state="SSH: Key Exchange Fail",
    explanation="Хтось підмінив сервер, до якого ти підключаєшся. Це може бути хакер.",
    logic="Зміна Host Key у файлі known_hosts",
    confidence=99, severity="CRITICAL",
    tags=["security","ssh","mitm","host-key"]),

DiagEntry("L5-005", 5, "SMB v1.0 Active (WannaCry Risk)",
    state="SMB: Version 1.0 active",
    explanation="Ти використовуєш дуже старий протокол обміну файлами. Це 'дірка' в захисті.",
    logic="Виявлено сесію протоколу SMBv1 (вразливість WannaCry)",
    confidence=100, severity="CRITICAL",
    tags=["security","smb","wannacry","vulnerability"]),

DiagEntry("L5-006", 5, "Session Hijack Attempt",
    state="Tapo: 4W, Auth: Brute Force",
    explanation="Хтось намагається підібрати твій сесійний токен. Блокую доступ!",
    logic="Масові запити з різними Authorization заголовками з одного IP",
    confidence=95, severity="CRITICAL",
    tags=["security","session","hijack","brute-force"]),

DiagEntry("L5-007", 5, "API Data Corruption (IoT)",
    state="Tapo: 5W, JSON: Malformed",
    explanation="Твій розумний дім прислав 'биті' дані. Я не можу їх прочитати.",
    logic="Помилка парсингу json.loads() при отриманні відповіді від девайса",
    confidence=95, severity="WARNING",
    tags=["iot","api","json","tapo"]),

DiagEntry("L5-008", 5, "Insecure Encryption (Weak Cipher)",
    state="Tapo: 6W, SSL: Weak Cipher",
    explanation="Ця програма використовує слабкий шифр. Твої паролі під загрозою!",
    logic="Використання RC4 або DES замість сучасного AES-256",
    confidence=85, severity="WARNING",
    tags=["security","encryption","cipher"]),

DiagEntry("L5-009", 5, "SSL Untrusted Certificate",
    state="SSL: Untrusted CA",
    explanation="Цій програмі не можна довіряти, бо її сертифікат ніким не підтверджений.",
    logic="Помилка Self-signed certificate in chain",
    confidence=90, severity="WARNING",
    tags=["ssl","certificate","security"]),

DiagEntry("L5-010", 5, "Database Session Leak",
    state="Tapo: 8W, SQL: Long Session",
    explanation="Твій сервер бази даних тримає занадто багато відкритих сесій. Він 'гальмує'.",
    logic="Ріст tapo_watts паралельно з кількістю Sleep сесій у БД",
    confidence=80, severity="WARNING",
    tags=["database","session","performance"]),

DiagEntry("L5-011", 5, "SSH Key Fingerprint Mismatch",
    state="SSH: Key Exchange Fail",
    explanation="Хтось підмінив сервер, до якого ти підключаєшся по SSH. Це може бути хакер або зміна сервера.",
    logic="Зміна Host Key у файлі known_hosts",
    confidence=99, severity="CRITICAL",
    tags=["ssh","mitm","key","security"]),

DiagEntry("L5-012", 5, "Video Codec Missing",
    state="Video: Codec Not Found",
    explanation="Твій плеєр бачить дані, але не знає як їх декодувати. Відсутній кодек H.265/AV1.",
    logic="Помилка декодування медіа-потоку (Missing H.265/AV1 codec)",
    confidence=85, severity="WARNING",
    tags=["codec","video","presentation","media"]),

DiagEntry("L5-013", 5, "Load Balancer Session Issue",
    state="Session: Sticky Session Fail",
    explanation="Сервер постійно перекидає тебе між різними вузлами. Кошик на сайті скидається — це нормально.",
    logic="Швидка зміна сесійних кук Set-Cookie при кожному запиті",
    confidence=70, severity="WARNING",
    tags=["session","load-balancer","cookie","sticky"]),

DiagEntry("L5-014", 5, "Multiple Session Conflict",
    state="Session: Duplicate Login",
    explanation="Ти зайшов у акаунт з іншого пристрою, тому тут з'єднання обірвалося. Це захист від паралельних сесій.",
    logic="Отримання сигналу розриву сесії через API додатка",
    confidence=75, severity="INFO",
    tags=["session","conflict","duplicate","login"]),

DiagEntry("L5-015", 5, "RPC Port Blocked (135/445)",
    state="RPC: Port 135 Blocked",
    explanation="Програма не може віддалено керувати іншим пристроєм у мережі (заблоковано порт RPC).",
    logic="Блокування портів 135/445 всередині локальної мережі",
    confidence=90, severity="WARNING",
    tags=["rpc","port135","blocked","windows"]),

DiagEntry("L5-016", 5, "Data Compression Mismatch",
    state="Data: Gzip/Brotli Error",
    explanation="Сайт прислав стислі дані (gzip/brotli), які браузер не зміг розпакувати. Проблема сервера.",
    logic="Помилка Content-Encoding при отриманні HTTP-відповіді",
    confidence=70, severity="WARNING",
    tags=["compression","gzip","brotli","http"]),

DiagEntry("L5-017", 5, "Encoding Corruption (UTF-8)",
    state="UTF-8: Character Error",
    explanation="Дані прийшли в неправильному кодуванні. Замість тексту — ієрогліфи або символи '?'.",
    logic="Помилка декодування байтового потоку у формат Unicode",
    confidence=90, severity="WARNING",
    tags=["encoding","utf8","corruption","data"]),

DiagEntry("L5-018", 5, "Base64 Data Overhead",
    state="Data: Base64 Overhead",
    explanation="Програма передає картинки текстом (Base64 в JSON). Це споживає на 30% більше трафіку.",
    logic="Виявлено великі об'єми даних у форматі Base64 всередині JSON API",
    confidence=50, severity="INFO",
    tags=["base64","efficiency","bandwidth","api"]),

DiagEntry("L5-019", 5, "SSL SNI Domain Spoofing",
    state="SSL: SNI Mismatch",
    explanation="Сайт намагається видати себе за інший через підміну імені в SSL-пакеті (SNI). Можлива атака.",
    logic="Невідповідність поля Server Name Indication та реального хоста",
    confidence=85, severity="CRITICAL",
    tags=["ssl","sni","spoofing","security"]),

DiagEntry("L5-020", 5, "TCP Stream Reassembly Lag",
    state="Session: TCP Reassembly",
    explanation="Дані приходять шматками і не збираються докупи вчасно. Лаги у відеозв'язку та стрімінгу.",
    logic="Високий рівень TCP segment reassembly у черзі системи",
    confidence=65, severity="WARNING",
    tags=["tcp","reassembly","streaming","lag"]),

# ──────────────────────────────────────────────────────────────
# L7 — APPLICATION
# ──────────────────────────────────────────────────────────────
DiagEntry("L7-001", 7, "ISP Video Throttling",
    state="Netflix: Bitrate Drop",
    explanation="Схоже, провайдер навмисно обмежує швидкість для відеосервісів.",
    logic="Швидкість на fast.com значно нижча за загальний speedtest",
    confidence=70, severity="WARNING",
    tags=["isp","throttling","netflix","youtube"]),

DiagEntry("L7-002", 7, "Crypto Miner Malware",
    state="Crypto-Miner Pools detected",
    explanation="Твій комп'ютер таємно добуває криптовалюту для хакера. Терміново скан!",
    logic="З'єднання з доменами nicehash, nanopool тощо",
    confidence=99, severity="CRITICAL",
    tags=["malware","crypto","miner","security"]),

DiagEntry("L7-003", 7, "Discord Voice Server Block",
    state="Discord: RTC Connecting",
    explanation="Discord не може підключитися до голосового чату. Можливо, блок провайдера.",
    logic="Нескінченний статус підключення при активному UDP-трафіку",
    confidence=90, severity="WARNING",
    tags=["discord","voip","udp","firewall"]),

DiagEntry("L7-004", 7, "Zoom Packet Loss",
    state="Zoom: Packet Loss > 2%",
    explanation="Твій голос може обриватися в Zoom. Спробуй вимкнути свою камеру.",
    logic="Аналіз UDP-потоку Zoom-сесії (порт 8801)",
    confidence=85, severity="WARNING",
    tags=["zoom","voip","packet-loss","udp"]),

DiagEntry("L7-005", 7, "YouTube 4K Stress",
    state="YouTube: BufferBloat",
    explanation="Твій роутер не встигає 'прожовувати' 4K відео. Знизь якість до 1080p.",
    logic="Пікове споживання tapo_watts (10W+) + затримки в черзі пакетів",
    confidence=80, severity="WARNING",
    tags=["youtube","4k","streaming","bufferbloat"]),

DiagEntry("L7-006", 7, "Steam Background Download",
    state="Steam: Update Active",
    explanation="Steam качає оновлення. Це може заважати твоїй поточній грі.",
    logic="Трафік на порти 27015-27030 + ріст tapo_watts",
    confidence=90, severity="WARNING",
    tags=["steam","download","gaming"]),

DiagEntry("L7-007", 7, "Mail Server Auth Fail",
    state="Outlook: Sync Error",
    explanation="Пошта не приходить. Перевір, чи не змінив ти пароль від поштової скриньки.",
    logic="Помилки протоколів IMAP/SMTP (порти 993/465/587)",
    confidence=85, severity="WARNING",
    tags=["email","imap","smtp","auth"]),

DiagEntry("L7-008", 7, "Gaming Priority Active",
    state="Game Mode: Valorant/CS",
    explanation="Я бачу, що ти в грі. Всі ресурси мережі тепер твої!",
    logic="Детекція процесів ігор + активація QoS правил",
    confidence=100, severity="INFO",
    tags=["gaming","qos","priority"]),

DiagEntry("L7-009", 7, "IoT Cloud Latency",
    state="Smart Home: Tuya/Xiaomi",
    explanation="Твоя розумна лампа довго реагує, бо сервери виробника в Китаї лагають.",
    logic="Високий пінг до специфічних хмарних хостів розумного дому",
    confidence=70, severity="INFO",
    tags=["iot","cloud","latency","smart-home"]),

DiagEntry("L7-010", 7, "HTTP 404 Not Found",
    state="HTTP: 404 Not Found",
    explanation="Цієї сторінки більше не існує або ти помилився в адресі.",
    logic="Фіксація HTTP статус-коду 404 у відповіді сервера",
    confidence=100, severity="INFO",
    tags=["http","404","web"]),

DiagEntry("L7-011", 7, "HTTP 403 Region Block",
    state="HTTP: 403 Forbidden",
    explanation="Тобі заборонено доступ. Можливо, сайт заблоковано у твоїй країні.",
    logic="Отримання коду 403. Рекомендація: увімкни VPN",
    confidence=95, severity="INFO",
    tags=["http","403","region","vpn"]),

DiagEntry("L7-012", 7, "Heavy Multitasking",
    state="Tapo: 12W, Game: Lagging",
    explanation="Ти граєш, качаєш торрент і дивишся YouTube одночасно. Роутеру важко.",
    logic="Комбінація високого tapo_watts та конфлікту пріоритетів L7",
    confidence=90, severity="WARNING",
    tags=["multitasking","gaming","qos"]),

DiagEntry("L7-013", 7, "Mail Server Auth Fail",
    state="Outlook: Sync Error",
    explanation="Пошта не синхронізується. Перевір пароль від поштової скриньки або налаштування IMAP/SMTP.",
    logic="Помилки протоколів IMAP/SMTP (порти 993/465/587)",
    confidence=85, severity="WARNING",
    tags=["mail","smtp","imap","auth"]),

DiagEntry("L7-014", 7, "Disk IO Bottleneck",
    state="Torrent: High Disk IO",
    explanation="Твій диск не встигає записувати торрент-дані. Швидкість інтернету штучно обмежена диском.",
    logic="Високе навантаження на диск (IO) при запасі швидкості мережі",
    confidence=65, severity="INFO",
    tags=["disk","io","torrent","bottleneck"]),

DiagEntry("L7-015", 7, "IoT Cloud Latency",
    state="Smart Home: Tuya/Xiaomi",
    explanation="Розумна лампа або датчик довго реагує. Сервери виробника в Китаї лагають або перевантажені.",
    logic="Високий пінг до специфічних хмарних хостів розумного дому (Tuya/Xiaomi)",
    confidence=70, severity="INFO",
    tags=["iot","cloud","latency","tuya"]),

DiagEntry("L7-016", 7, "Browser RAM Exhaustion",
    state="Browser: Too many tabs",
    explanation="Браузер 'з'їв' всю пам'ять комп'ютера. Це може впливати на стабільність мережевих з'єднань.",
    logic="Процес chrome.exe споживає понад 4 ГБ RAM",
    confidence=80, severity="WARNING",
    tags=["browser","ram","memory","chrome"]),

DiagEntry("L7-017", 7, "Zoom Audio CPU Overload",
    state="Zoom: Background Noise",
    explanation="Процесор напружено прибирає шум під час відеодзвінка. Можливе підвищення затримки.",
    logic="Ріст завантаження CPU при активному стрімі мікрофона з шумоподавленням",
    confidence=50, severity="INFO",
    tags=["zoom","cpu","audio","noise"]),

DiagEntry("L7-018", 7, "Privacy Tracking Alert",
    state="Facebook: High Tracking",
    explanation="Facebook збирає забагато даних через Pixel-трекери на сторінках. Встанови uBlock Origin.",
    logic="Велика кількість фонових запитів до facebook.com/tr/ (Facebook Pixel)",
    confidence=60, severity="INFO",
    tags=["privacy","facebook","tracking","pixel"]),

DiagEntry("L7-019", 7, "Excessive Ad Loading",
    state="Ad-Server Domains detected",
    explanation="На сторінці забагато реклами, яка гальмує завантаження. Встанови блокувальник реклами.",
    logic="DNS-запити до відомих рекламних мереж (Doubleclick, AdSense тощо)",
    confidence=75, severity="INFO",
    tags=["ads","dns","performance","browser"]),

DiagEntry("L7-020", 7, "Upload Bandwidth Saturation",
    state="Telegram: File Upload",
    explanation="Ти відправляєш важкий файл. Вихідний канал насичений — інші пристрої будуть лагати.",
    logic="Високий Upload-трафік на сервери Telegram (IP-діапазони TG)",
    confidence=100, severity="INFO",
    tags=["upload","bandwidth","telegram","qos"]),

]

# ── Індекс для швидкого пошуку ──────────────────────────────
_CODE_INDEX: Dict[str, DiagEntry] = {e.code: e for e in KB}
_TAG_INDEX:  Dict[str, List[DiagEntry]] = {}
for _e in KB:
    for _t in _e.tags:
        _TAG_INDEX.setdefault(_t, []).append(_e)


# ══════════════════════════════════════════════════════════════
#  AUTO-FIX ACTIONS
# ══════════════════════════════════════════════════════════════

class AutoFixer:
    """Набір дій, які AI може виконати автоматично."""

    def __init__(self, tapo=None, bot_alert: Optional[Callable] = None):
        self._tapo = tapo
        self._alert = bot_alert

    def run(self, action: str) -> tuple[bool, str]:
        """Виконати auto-fix. Повертає (success, message)."""
        fn = getattr(self, f"_fix_{action}", None)
        if fn is None:
            return False, f"Auto-fix '{action}' не визначено"
        try:
            return fn()
        except Exception as e:
            log.error(f"AutoFix '{action}' error: {e}")
            return False, f"Помилка виконання auto-fix: {e}"

    # ── DNS fixes ──────────────────────────────────────────
    def _fix_flush_dns(self) -> tuple:
        if IS_WINDOWS:
            r = subprocess.run(["ipconfig", "/flushdns"],
                               capture_output=True, text=True, timeout=10)
            if r.returncode == 0:
                return True, "✅ DNS кеш очищено (ipconfig /flushdns)"
        else:
            subprocess.run(["sudo", "systemd-resolve", "--flush-caches"],
                           capture_output=True, timeout=10)
            return True, "✅ DNS кеш очищено"
        return False, "❌ Не вдалось очистити DNS кеш"

    def _fix_set_google_dns(self) -> tuple:
        if IS_WINDOWS:
            cmds = [
                ["netsh", "interface", "ipv4", "set", "dnsservers",
                 "Wi-Fi", "static", "8.8.8.8", "primary"],
                ["netsh", "interface", "ipv4", "add", "dnsservers",
                 "Wi-Fi", "8.8.8.4", "index=2"],
            ]
            for cmd in cmds:
                subprocess.run(cmd, capture_output=True, timeout=10)
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
            return True, "✅ DNS змінено на Google (8.8.8.8 / 8.8.8.4) + кеш очищено"
        return False, "❌ Зміна DNS підтримується тільки на Windows"

    def _fix_set_doh(self) -> tuple:
        return False, ("ℹ️ DNS over HTTPS потрібно налаштувати вручну:\n"
                       "Firefox: about:config → network.trr.mode = 2\n"
                       "Windows: Settings → DNS → Encrypted (DoH)")

    # ── DHCP / Network ─────────────────────────────────────
    def _fix_dhcp_renew(self) -> tuple:
        if IS_WINDOWS:
            subprocess.run(["ipconfig", "/release"], capture_output=True, timeout=15)
            time.sleep(2)
            r = subprocess.run(["ipconfig", "/renew"], capture_output=True, timeout=30)
            if r.returncode == 0:
                return True, "✅ DHCP оновлено (release → renew)"
        return False, "❌ Не вдалось оновити DHCP"

    def _fix_fix_mtu(self) -> tuple:
        if IS_WINDOWS:
            r = subprocess.run(
                ["netsh", "interface", "ipv4", "set", "subinterface",
                 "Wi-Fi", "mtu=1400", "store=persistent"],
                capture_output=True, timeout=10)
            if r.returncode == 0:
                return True, "✅ MTU встановлено 1400 (безпечне значення для VPN/PPPoE)"
        return False, "❌ Не вдалось змінити MTU"

    def _fix_fix_routes(self) -> tuple:
        if IS_WINDOWS:
            subprocess.run(["netsh", "int", "ip", "reset"], capture_output=True, timeout=15)
            return True, "✅ Таблиця маршрутів скинута (netsh int ip reset)\n⚠️ Перезавантаж ПК"
        return False, "❌ Виправлення маршрутів підтримується тільки на Windows"

    def _fix_enable_nic(self) -> tuple:
        if IS_WINDOWS:
            r = subprocess.run(
                ["powershell", "-Command",
                 "Get-NetAdapter | Where-Object {$_.Status -eq 'Disabled'} | Enable-NetAdapter -Confirm:$false"],
                capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return True, "✅ Мережевий адаптер увімкнено"
        return False, "❌ Не вдалось увімкнути адаптер"

    def _fix_disable_nagle(self) -> tuple:
        if IS_WINDOWS:
            import winreg
            try:
                key_path = r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as base:
                    for i in range(winreg.QueryInfoKey(base)[0]):
                        sub = winreg.EnumKey(base, i)
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                            f"{key_path}\\{sub}", 0,
                                            winreg.KEY_SET_VALUE) as k:
                            winreg.SetValueEx(k, "TcpNoDelay", 0,
                                              winreg.REG_DWORD, 1)
                return True, "✅ Nagle алгоритм вимкнено (TcpNoDelay=1). Перезавантаж ПК."
            except Exception as e:
                return False, f"❌ Помилка реєстру: {e}"
        return False, "❌ Тільки для Windows"

    # ── Tapo ───────────────────────────────────────────────
    def _fix_tapo_reboot(self) -> tuple:
        if self._tapo is None:
            return False, ("❌ Tapo не підключена.\n"
                           "Налаштуй: /tapo setup <IP> <email> <пароль>")
        return self._tapo.reboot_router(off_seconds=8)

    def _fix_tapo_off(self) -> tuple:
        if self._tapo is None:
            return False, "❌ Tapo не підключена"
        return self._tapo.turn_off()

    # ── Інформаційні ───────────────────────────────────────
    def _fix_suggest_channel(self) -> tuple:
        return False, ("ℹ️ Зміни WiFi канал вручну:\n"
                       "• 2.4GHz: використовуй канал 1, 6 або 11\n"
                       "• 5GHz: канали 36, 40, 44, 48 (non-DFS)\n"
                       "Налаштування роутера: 192.168.1.1 → Wireless → Channel")

    def _fix_suggest_torrent_limit(self) -> tuple:
        return False, ("ℹ️ Обмеж з'єднання в торрент-клієнті:\n"
                       "• qBittorrent: Tools → Options → Connection → Max connections: 200\n"
                       "• uTorrent: Options → Preferences → BitTorrent → Max connections: 200")


# ══════════════════════════════════════════════════════════════
#  ГОЛОВНИЙ AI КЛАС
# ══════════════════════════════════════════════════════════════

@dataclass
class DiagResult:
    """Результат AI аналізу."""
    entry:       DiagEntry
    fix_success: Optional[bool]   = None
    fix_message: Optional[str]    = None
    timestamp:   float            = field(default_factory=time.time)

    @property
    def layer_name(self) -> str:
        names = {1:"L1 Physical",2:"L2 Data Link",3:"L3 Network",
                 4:"L4 Transport",5:"L5-L6 Session/Presentation",7:"L7 Application"}
        return names.get(self.entry.layer, f"L{self.entry.layer}")

    def format_for_user(self) -> str:
        """Форматує результат залежно від рівня та результату auto-fix."""
        e = self.entry
        icons = {"CRITICAL": "🔴", "WARNING": "🟡", "INFO": "🔵"}
        icon = icons.get(e.severity, "⚠️")

        lines = [
            f"{icon} *{e.title}* [{self.layer_name}]",
            f"━━━━━━━━━━━━━━━━━━━━━",
            f"📋 {e.explanation}",
            f"🎯 Впевненість: {e.confidence}%",
            "",
        ]

        if e.is_physical:
            # L1: тільки пояснення + рекомендації що ЗРОБИТИ
            lines.append("🔧 *Що потрібно зробити:*")
            lines.extend(self._get_l1_recommendations(e))
        else:
            # L2-L7: показуємо результат auto-fix або рекомендації
            if self.fix_success is True:
                lines.append(f"✅ *Виправлено автоматично:*")
                lines.append(self.fix_message or "")
            elif self.fix_success is False:
                lines.append(f"⚙️ *Спроба автовиправлення:*")
                lines.append(self.fix_message or "")
                lines.append("")
                lines.append("💡 *Рекомендації для ручного виправлення:*")
                lines.extend(self._get_manual_recommendations(e))
            else:
                lines.append("💡 *Рекомендації:*")
                lines.extend(self._get_manual_recommendations(e))

        return "\n".join(lines)

    def _get_l1_recommendations(self, e: DiagEntry) -> List[str]:
        recs = {
            "L1-001": ["• Перевір чи увімкнена розетка", "• Перевір автомат на щитку", "• Перевір кабель живлення роутера"],
            "L1-002": ["• Утримуй Reset 30с → factory reset", "• Перевір блок живлення мультиметром (12V/9V)", "• Дай роутеру охолонути 10 хвилин"],
            "L1-003": ["• Заміни кабель або RJ-45 конектор", "• Спробуй інший порт на роутері", "• Перевір стан жил (всі 8 мають бути цілі)"],
            "L1-004": ["• Вставь кабель до характерного клацання", "• Перевір обидва кінці кабелю"],
            "L1-005": ["• Постав роутер вертикально", "• Забезпечи 10+ см вільного простору навколо", "• Продуй від пилу стисненим повітрям"],
            "L1-006": ["• Прокладіть кабель далі від електромоторів", "• Використовуй екранований кабель FTP/STP"],
            "L1-007": ["• Tapo reboot виконано автоматично", "• Якщо не помогло — фізично вимкни роутер на 30с"],
            "L1-008": ["• ncpa.cpl → правий клік на адаптері → Увімкнути", "• Або: powershell → Get-NetAdapter | Enable-NetAdapter"],
            "L1-009": ["• Замінити кабель або RJ-45 конектор", "• Спробуй порт на роутері примусово виставити 1Gbps Full Duplex"],
            "L1-010": ["• Натисни кнопку живлення на роутері", "• В налаштуваннях роутера вимкни Energy Saving Mode"],
            "L1-011": ["• НЕБЕЗПЕКА! Підключи роутер через стабілізатор", "• Зателефонуй до Обленерго"],
            "L1-012": ["• Перевір штекер блоку живлення в роутері", "• Якщо бовтається — відправ в сервіс"],
            "L1-013": ["• Перевір обжимку всіх 8 жил в RJ-45", "• Заміни конектор або кабель"],
            "L1-014": ["• Заміни блок живлення роутера (тип за специфікацією)", "• Підключи через UPS з фільтрацією"],
            "L1-015": ["• Перевір стан RJ-45 конектора", "• Переобжати конектор або замінити кабель"],
            "L1-016": ["• НЕБЕЗПЕКА! Вимкни розетку", "• Перевір кабель живлення на перегин/пошкодження", "• Зверніться до електрика"],
            "L1-017": ["• Вкороти кабель до 90м максимум", "• Або встанови Gigabit комутатор посередині"],
            "L1-018": ["• Перевір автомат на щитку", "• Зателефонуй до Обленерго (0-800-...)"],
            "L1-019": ["• Продуй вентиляційні отвори стисненим повітрям", "• Поставь роутер у вентильоване місце"],
            "L1-020": ["• Tapo reboot виконано автоматично", "• Якщо проблема повторюється — оновити прошивку роутера"],
            "L1-021": ["• Підключи роутер через ліній-кондиціонер або UPS", "• Розмісти подалі від холодильника/кондиціонера"],
            "L1-022": ["• Заземли корпус роутера", "• Замінити кабель на FTP/STP (екранований)"],
            "L1-023": ["• Tapo reboot виконано автоматично"],
            "L1-024": ["• Вкороти кабель до 90м", "• Встанови Gigabit комутатор на середині дистанції"],
            "L1-025": ["• ⚡ НЕБЕЗПЕКА! Tapo вимкнено автоматично", "• Перевір стабілізатор напруги або UPS", "• Зателефонуй до Обленерго — проблема в мережі"],
            "L1-026": ["• Перевір температуру роутера (не повинна перевищувати 70°C)", "• Продуй вентиляційні отвори", "• Якщо температура нормальна — можлива несправність компонента"],
            "L1-027": ["• Замінити кабель-конвертер на правильний (12V)", "• Перевір напругу мультиметром на вході роутера"],
            "L1-028": ["• ⚡ Tapo вимкнено для захисту!", "• Витягни кабель з LAN-порту і перевір контакти", "• Спробуй інший порт або інший кабель"],
            "L1-029": ["• Замінити блок живлення на оригінальний або якісний аналог", "• Перевір напругу мультиметром при завантаженні мережі"],
            "L1-030": ["• Підключи роутер до розетки Tapo для нормальної роботи", "• Якщо це PoE — перевір налаштування PoE комутатора"],
        }
        return recs.get(e.code, ["• Перевір фізичне підключення", "• Зверніться до технічного спеціаліста"])

    def _get_manual_recommendations(self, e: DiagEntry) -> List[str]:
        recs = {
            # L2
            "L2-001": ["• Пересунь роутер ближче або встанови репітер", "• Переключись на 5GHz якщо близько", "• Використовуй 2.4GHz якщо далеко"],
            "L2-002": ["• WiFi Analyzer (Android) → знайди вільний канал", "• Встанови канали 1, 6 або 11 для 2.4GHz"],
            "L2-003": ["• Вимкни WPA3-Only у роутері → WPA2/WPA3 Mixed", "• Або оновити драйвери WiFi адаптера"],
            "L2-004": ["• НЕ підключайся!", "• Перевір MAC реального роутера на його наклейці", "• Повідом адміністратора мережі"],
            "L2-005": ["• Увімкни 802.11w (Protected Management Frames) у роутері", "• Переключись на WPA3 — обов'язково захищає PMF"],
            "L2-006": ["• ipconfig /flushdns", "• Зміни DNS на 1.1.1.1", "• arp -d * (очисти ARP кеш)"],
            "L2-007": ["• Вимкни Port Security або увімкни MAC фільтр на роутері", "• Знайди і від'єднай зловмисний пристрій"],
            "L2-008": ["• Не вводь пароль!", "• Підключайся тільки до мережі з відомим MAC адресою роутера"],
            "L2-009": ["• Переключись на WiFi 5GHz", "• Або вимкни Bluetooth поки не потрібен"],
            "L2-010": ["• Роутер → Wireless → Disable Client Isolation", "• Або Disable AP Isolation / Guest Mode"],
            "L2-011": ["• Це нормально — зачекай 60с", "• Або переключись на non-DFS канали (36, 40, 44, 48)"],
            "L2-012": ["• Роутер → Advanced → UPnP → Disable", "• Перевір Port Forwarding на підозрілі записи"],
            "L2-013": ["• Перевір кабельні петлі в комутаторі", "• Увімкни STP на роутері", "• Tapo reboot виконано автоматично"],
            "L2-014": ["• Поставь IoT в окрему Guest мережу (AP Isolation)", "• Заблокуй вихідні з'єднання IoT на файрволі"],
            "L2-015": ["• Перевір всі підключені до мережі пристрої", "• Знайди невідомий MAC і ізолюй його"],
            "L2-016": ["• Вимкни Bluetooth якщо не потрібен", "• Переключись на 5GHz", "• Зміни WiFi канал на 1 або 11"],
            "L2-017": ["• Перевір налаштування VLAN на роутері/комутаторі", "• Переключи порт на правильний VLAN"],
            "L2-018": ["• Замінити один з пристроїв (заводський брак)", "• Перевір у виробника наявність firmware fix"],
            "L2-019": ["• Зайди в роутер (192.168.1.1)", "• Налаштування WiFi → увімкни бездротовий модуль", "• Якщо немає доступу — Tapo reboot"],
            "L2-020": ["• Перевір CapsLock та розкладку клавіатури", "• Забудь мережу та підключись знову з правильним паролем"],
            "L2-021": ["• ipconfig /release + ipconfig /renew", "• Зайди в роутер і перевір DHCP-резервації"],
            "L2-022": ["• Зайди в роутер → список підключених пристроїв", "• Якщо невідомий — зміни пароль WiFi та увімкни MAC-фільтр"],
            "L2-023": ["• Перейди на 2.4 ГГц для кімнат зі стінами", "• Встанови WiFi-репітер або mesh-вузол"],
            "L2-024": ["• Відійди на 1-3 метри від роутера", "• Зменш потужність TX у налаштуваннях роутера"],
            "L2-025": ["• Знайди старий 802.11b пристрій і відключи його", "• Вимкни підтримку 802.11b в роутері (залиш тільки n/ac/ax)"],
            "L2-026": ["• Зайди в роутер → MAC фільтрація → додай свій MAC", "• Або вимкни MAC-фільтр якщо він не потрібен"],
            "L2-027": ["• Зачекай поки їжа нагріється", "• Переключись на 5 ГГц — мікрохвильовка не заважає"],
            "L2-028": ["• Tapo reboot виконано автоматично", "• Якщо не помогло — зайди в роутер і перезапусти DHCP-сервер вручну"],
            "L2-029": ["• ipconfig /release + ipconfig /renew", "• Перевір чи працює роутер (Tapo watts > 0)"],
            "L2-030": ["• Зміни канал WiFi на вільний (1, 6, 11 для 2.4GHz)", "• Використовуй WiFi Analyzer для пошуку вільного каналу"],
            "L2-031": ["• Перевір чи щільно прикручені антени", "• Спробуй замінити антену або встанови підсилювач"],
            "L2-032": ["• Знайди пристрій з надмірним broadcast і вимкни його", "• Перевір принтери та IoT-пристрої"],
            "L2-033": ["• Вимкни Band Steering у роутері", "• Або закріпи пристрій за конкретним BSSID"],
            "L2-034": ["• Відключи старий пристрій від мережі", "• Вимкни підтримку 802.11b/g в роутері"],
            "L2-035": ["• Це нормальна поведінка iPhone/Android — проблеми немає", "• Для стабільного MAC: вимкни MAC Randomization у налаштуваннях WiFi"],
            "L2-036": ["• Відкрий браузер та зайди на 192.168.1.1 або перейди за redirect URL", "• Пройди авторизацію на сторінці провайдера або закладу"],
            "L2-037": ["• Перевір що це твій легітимний пристрій", "• Якщо невідомий — вимкни його з мережі та зміни пароль WiFi"],
            "L2-038": ["• Все в порядку! Mesh-мережа працює ідеально", "• Handover < 1 секунди — відмінний результат"],
            "L2-039": ["• Знайди пристрій з надмірним multicast (принтер, Smart TV)", "• Увімкни IGMP Snooping у роутері для контролю multicast"],
            "L2-040": ["• Закрий порти 21, 23 у фаєрволі Windows", "• Вимкни FTP/Telnet сервер якщо він не потрібен"],
            "L2-041": ["• Прибери перешкоду між пристроєм і роутером", "• Або встанови репітер на потрібному боці стіни"],
            "L2-042": ["• Зайди в роутер → Безпека WiFi → змінити на WPA2/WPA3 Mixed", "• Або оновити драйвер WiFi адаптера"],
            "L2-043": ["• Зміни регіон роутера на відповідний (наприклад 'EU')", "• Або встанови канал 1-11 вручну"],
            "L2-044": ["• Використовуй кабель Ethernet замість WiFi", "• Переключись на 5 ГГц — там менше навантаження в публічних місцях"],
            "L2-045": ["• Вимкни Power Management для WiFi адаптера у Windows", "• Або увімкни High Performance режим живлення"],
            "L2-046": ["• Зайди в роутер → вимкни AP Isolation / Client Isolation", "• Перевір чи не підключений до гостьової мережі"],
            "L2-047": ["• Знайди пристрій з нульовим MAC і вимкни його", "• Можливо вірус — запусти антивірусне сканування"],
            "L2-048": ["• Tapo reboot виконано автоматично", "• Якщо не помогло — скинь роутер до заводських налаштувань"],
            "L2-049": ["• Ізолюй IoT пристрій у гостьовій мережі", "• Оновити прошивку пристрою на ESP8266/ESP32"],
            "L2-050": ["• Зайди в роутер → увімкни IGMP Snooping", "• Або перезавантаж роутер через Tapo"],
            "L2-051": ["• Встанови відповідний Country Code в роутері (наприклад 'UA' або 'EU')", "• Зміни канал на 1-11 для сумісності"],
            "L2-052": ["• Встанови фіксований канал WiFi замість 'Auto'", "• WiFi Analyzer допоможе знайти вільний канал"],
            "L2-053": ["• Вимкни ARP Proxy у налаштуваннях роутера", "• Або скинь налаштування до заводських"],
            "L2-054": ["• Ізолюй пристрій у гостьовій WiFi мережі", "• Перевір які дані він надсилає через Wireshark"],
            "L2-055": ["• Tapo reboot виконано автоматично", "• Якщо повторюється — перевір кількість активних з'єднань"],
            "L2-056": ["• Запусти повне антивірусне сканування", "• Знайди пристрій з нульовим MAC через Wireshark"],
            "L2-057": ["• Це може бути тимчасово — зачекай кілька хвилин", "• Встанови Tapo P110 подалі від роутера (20+ см)"],
            "L2-058": ["• Tapo reboot виконано автоматично", "• Вимкни режим економії в налаштуваннях роутера"],
            "L2-059": ["• Збільш DHCP пул у роутері (наприклад до 254 адрес)", "• Або зменш час оренди DHCP lease"],
            "L2-060": ["• Відійди на 1-2 метри від роутера", "• Або зменш TX Power в налаштуваннях WiFi"],
            # L3
            "L3-001": ["• ipconfig /flushdns → виконано автоматично", "• Якщо не помогло: зміни DNS на 1.1.1.1"],
            "L3-002": ["• ipconfig /release && /renew → виконано автоматично", "• Перезавантаж роутер якщо не помогло"],
            "L3-003": ["• Перевір налаштування PPPoE/WAN у роутері", "• Зателефонуй провайдеру"],
            "L3-004": ["• Увімкни DNS Leak Protection у VPN клієнті", "• Перевір налаштування Kill Switch"],
            "L3-005": ["• traceroute <сайт> — знайди де починається петля", "• Зателефонуй провайдеру з деталями"],
            "L3-006": ["• MTU встановлено 1400 автоматично", "• Для PPPoE оптимально: 1452"],
            "L3-007": ["• Перевір що слухає на 127.0.0.1:53: netstat -ano | findstr :53", "• Просканируй систему антивірусом"],
            "L3-008": ["• DNS змінено на 8.8.8.8 автоматично", "• Повідом провайдеру про несправність їх DNS"],
            "L3-009": ["• Увімкни DMZ на роутері провайдера вказавши IP твого роутера", "• Або переведи роутер провайдера в Bridge Mode"],
            "L3-010": ["• DNS змінено на 8.8.8.8 автоматично", "• Просканируй систему — можливий malware"],
            "L3-011": ["• Tapo reboot виконано автоматично", "• Або: Роутер → WAN → Reconnect"],
            "L3-012": ["• Мережа скинута автоматично (netsh int ip reset)", "• Перезавантаж ПК"],
            "L3-013": ["• Спробуй DoH (DNS over HTTPS)", "• Або використай VPN з власним DNS"],
            "L3-014": ["• Зателефонуй провайдеру — попроси білий IP", "• Або VPS + WireGuard для серверів"],
            "L3-015": ["• НЕБЕЗПЕКА! Від'єднайся від мережі", "• Знайди невідомий пристрій і видали"],
            "L3-016": ["• Роутер → Port Forwarding → додай правило для потрібного порту", "• Або увімкни UPnP тимчасово"],
            "L3-017": ["• Зателефонуй провайдеру — попроси null-route атакуючого IP", "• Активуй Cloudflare DDoS Protection"],
            "L3-018": ["• Зачекай — проблема на боці провайдера", "• Зателефонуй провайдеру з скаргою"],
            "L3-019": ["• VPN Settings → Enable DNS Leak Protection", "• Або вручну встанови DNS в налаштуваннях VPN"],
            "L3-020": ["• Роутер → DHCP → розшир пул адрес до 200", "• Зменш Lease Time до 2 годин"],
            "L3-021": ["• НЕБЕЗПЕКА! Запусти: arp -d * (очисти ARP)", "• Знайди пристрій з підозрілим MAC та ізолюй"],
            "L3-022": ["• НЕ ігноруй ICMP Redirect!", "• Перевір ARP таблицю: arp -a", "• Увімкни фільтрацію ICMP Redirect у фаєрволі"],
            "L3-023": ["• Якщо використовуєш порт-forwarding — оновити IP в налаштуваннях", "• Розглянь DynDNS або No-IP для стабільної адреси"],
            "L3-024": ["• Зателефонуй провайдеру на технічну підтримку", "• Надай traceroute результат оператору"],
            "L3-025": ["• Зачекай 15-30 хвилин — BGP зазвичай стабілізується", "• Якщо проблема 2+ годин — дзвони провайдеру"],
            "L3-026": ["• Перевір налаштування IP: має бути 255.255.255.0 або 255.255.0.0", "• Виконано спробу виправлення через route"],
            "L3-027": ["• Якщо проблема зі швидкістю — зверніться до провайдера", "• Спробуй VPN для оптимізації маршруту"],
            "L3-028": ["• DNS змінено на Google 8.8.8.8 автоматично", "• Або увімкни VPN для обходу фільтрів"],
            "L3-029": ["• Зміни VPN сервер на менш навантажений", "• Спробуй інший регіон підключення"],
            "L3-030": ["• Зателефонуй провайдеру — проблема з UDP на їх стороні", "• Тимчасово: переключи Discord на TCP mode у налаштуваннях"],
            "L3-031": ["• Зачекай — маршрут зазвичай відновлюється автоматично", "• Якщо тривало — зателефонуй провайдеру"],
            "L3-032": ["• ТЕРМІНОВО! Зайди в роутер → вимкни UPnP та remote management", "• Встанови складний пароль для адмін-панелі"],
            "L3-033": ["• НЕБЕЗПЕКА! Хтось в мережі імітує відповіді Google", "• Запусти ARP сканування та знайди підозрілий пристрій"],
            "L3-034": ["• Перегенеруй WireGuard ключі на сервері та клієнті", "• Перевір чи правильно скопійований PublicKey"],
            "L3-035": ["• Спробуй VPN для обходу блокування", "• Перевір чи не блокує Windows Defender Steam"],
            "L3-036": ["• Зателефонуй провайдеру — немає доступу до зовнішньої мережі", "• Перезапусти PPPoE/WAN з'єднання в роутері"],
            "L3-037": ["• Зачекай — congestion зазвичай тимчасовий", "• Зателефонуй провайдеру якщо проблема > 2 годин"],
            "L3-038": ["• Оновити або перевстановити драйвер мережевої карти", "• Виконано спробу реактивації NIC"],
            "L3-039": ["• Встановлено DoH (DNS over HTTPS) автоматично", "• Або зменш кількість DNS-запитів з програм"],
            "L3-040": ["• Оновити сертифікат VPN у провайдера VPN-сервісу", "• Або перевстанови OpenVPN конфіг файл"],
            "L3-041": ["• Перевір налаштування IPv6 у роутері (DHCPv6 або SLAAC)", "• Зверніться до провайдера для отримання IPv6-префіксу"],
            "L3-042": ["• НЕБЕЗПЕКА! Хтось зовні атакує твою мережу", "• Увімкни firewall та заблокуй IP зловмисника"],
            "L3-043": ["• Роутер → UPnP → увімкни", "• Або вручну відкрий потрібні UDP порти гри"],
            "L3-044": ["• Виконано спробу відновлення IPv4 через route fix", "• netsh int ipv4 reset → перезавантаж ПК"],
            "L3-045": ["• ipconfig /release + ipconfig /renew", "• Зайди в роутер → DHCP → розширити пул адрес"],
            "L3-046": ["• НЕБЕЗПЕКА! Хтось атакує твій роутер", "• Увімкни ICMP rate limiting у фаєрволі роутера"],
            "L3-047": ["• Визнач зайві роутери та видали один з ланцюга", "• Перевір чи не підключений модем+роутер+роутер в ряд"],
            "L3-048": ["• Це нормально. Privacy Extensions захищають тебе.", "• Якщо потрібен стабільний IPv6 — вимкни privacy extensions"],
            "L3-049": ["• Перевір правила Windows Firewall та вимкни зайві блокування", "• netsh advfirewall reset — скинь до стандартних правил"],
            "L3-050": ["• НЕБЕЗПЕКА! Хтось сканує твої порти", "• Увімкни firewall та заблокуй зловмисний IP"],
            "L3-051": ["• Виконано ipconfig /renew автоматично", "• Якщо не помогло — перезапусти DHCP через Tapo reboot"],
            "L3-052": ["• Вимкни 6to4 тунелювання: netsh interface 6to4 set state disabled", "• Використовуй нативний IPv6 від провайдера"],
            "L3-053": ["• Виконано spробу dhcp_renew автоматично", "• Вручну: зміни IP або вимкни статичний на DHCP"],
            "L3-054": ["• НЕБЕЗПЕКА! Хтось знімає відбиток твоєї ОС", "• Увімкни stealth-режим у фаєрволі"],
            "L3-055": ["• MTU зменшено до 1400 автоматично", "• Якщо не помогло: netsh interface ipv4 set subinterface mtu=1380"],
            "L3-056": ["• Перевір чи підключена Tapo фізично", "• Оновити Tapo прошивку через додаток"],
            "L3-057": ["• DoH активовано автоматично для захисту", "• Змінено DNS на зашифрований Cloudflare 1.1.1.1"],
            "L3-058": ["• Виконано відновлення таблиці маршрутів через route fix", "• Якщо не помогло — Tapo reboot або netsh int reset"],
            "L3-059": ["• Використовуй ICMP з різними TTL для тестування", "• Зверніться до провайдера якщо це проблема"],
            "L3-060": ["• DoH активовано автоматично для захисту DNS", "• Або використовуй DNS через VPN тунель"],
            # L4
            "L4-001": ["• Роутер → Port Forwarding → додай порт 25565 (TCP/UDP)", "• Переконайся що IP ПК статичний"],
            "L4-002": ["• Переключись на кабель замість WiFi", "• Зменш навантаження (торренти тощо)"],
            "L4-003": ["• ТЕРМІНОВО! Роутер → Firewall → заблокуй 445 зовні", "• Вимкни SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false"],
            "L4-004": ["• Встанови fail2ban на сервер", "• Зміни порт SSH з 22 на нестандартний", "• Увімкни тільки SSH-ключі"],
            "L4-005": ["• ТЕРМІНОВО! Роутер → Firewall → закрий 3389 для WAN", "• Доступ до RDP тільки через VPN"],
            "L4-006": ["• Зателефонуй провайдеру — попроси null-route", "• Увімкни DDoS protection на роутері"],
            "L4-007": ["• Перевір bufferbloat: waveform.com/tools/bufferbloat", "• Увімкни SQM/fq_codel у роутері (якщо OpenWrt)"],
            "L4-008": ["• Закрий зайві програми", "• В торрент-клієнті: обмеж з'єднання до 200"],
            "L4-009": ["• qBittorrent → Options → Connection → Max connections: 200"],
            "L4-010": ["• Оновити браузер та ОС", "• Вимкни TLS 1.0/1.1 у Windows: IIS Crypto"],
            "L4-011": ["• НЕ вводь паролі!", "• Підключись через HTTPS вручну (вбий https:// у браузері)"],
            "L4-012": ["• Заблокуй рекурсивні DNS запити ззовні на файрволі", "• Зателефонуй провайдеру"],
            "L4-013": ["• TcpNoDelay=1 встановлено автоматично. Перезавантаж ПК"],
            "L4-014": ["• Заблокуй порт 5060 для зовнішніх IP на файрволі", "• Встанови fail2ban для SIP"],
            "L4-015": ["• Це нормально. Якщо буфферить — знизь якість до 1080p"],
            "L4-016": ["• Перевір правила Windows Firewall", "• Вимкни антивірус тимчасово і перевір", "• Провайдер міг заблокувати вихідні порти — дзвони"],
            "L4-017": ["• Роутер → Port Forwarding → відкрий порт 3074 (UDP)", "• Або увімкни UPnP для автоматичного відкриття"],
            "L4-018": ["• Tapo reboot для очистки сесій", "• Вимкни програму яка некоректно закриває з'єднання"],
            "L4-019": ["• КРИТИЧНО! Windows Firewall → заблокуй вхідний порт 445", "• Вимкни SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false"],
            "L4-020": ["• Запусти антивірусне сканування", "• Перевір правила фаєрволу роутера — скинь до стандартних"],
            "L4-021": ["• Заблокуй TCP порт 53 ззовні у фаєрволі", "• Дозволь DNS тільки через UDP"],
            "L4-022": ["• Запусти антивірусне сканування терміново", "• Перевір сертифікати в браузері на підроблені"],
            "L4-023": ["• КРИТИЧНО! Вимкни RDP або зміни порт", "• Windows: Пуск → Систем → Параметри → вимкни Remote Desktop"],
            "L4-024": ["• MTU зменшено автоматично", "• Або встанови MTU 1480 у мережевому адаптері"],
            "L4-025": ["• Увімкни TCP KeepAlive у роутері (Idle Timeout > 300s)", "• Або у програмі встанови keepalive опцію"],
            "L4-026": ["• Перевір що це легітимна програма", "• Якщо невідомо — вимкни UPnP в роутері"],
            "L4-027": ["• Перевір стабільність інтернет з'єднання", "• Спробуй змінити DNS на 1.1.1.1 для стабільнішого маршруту"],
            "L4-028": ["• НЕБЕЗПЕКА! Хтось проводить SSL Strip атаку", "• Використовуй тільки HTTPS сайти (HSTS)", "• Увімкни VPN"],
            "L4-029": ["• Запусти антивірусне сканування ТЕРМІНОВО", "• Перевір запущені процеси на підозрілі"],
            "L4-030": ["• Спробуй VPN для обходу DPI фільтру", "• Або використовуй QUIC/HTTP3 якщо провайдер не блокує UDP 443"],
            "L4-031": ["• Спробуй вимкнути QUIC у браузері (chrome://flags)", "• Або використовуй VPN де QUIC не блокується"],
            "L4-032": ["• Сайт або сервіс не оновив сертифікат — проблема їхня", "• Спробуй пізніше або зверніться до адміністратора сайту"],
            "L4-033": ["• Проблема на стороні сервера — нічого не можна зробити", "• Спробуй пізніше або використовуй інший дзеркальний сервер"],
            "L4-034": ["• КРИТИЧНО! Закрий порт 5060 у фаєрволі", "• Заблокуй зловмисний IP у роутері"],
            "L4-035": ["• MTU виправлено автоматично", "• Встанови MSS 1380 у VPN клієнті вручну якщо не допомогло"],
            "L4-036": ["• Це нормальна поведінка TCP — алгоритм захищає від перевантаження", "• Зменш навантаження на канал для вирівнювання швидкості"],
            "L4-037": ["• НЕБЕЗПЕКА! Заблокуй UDP порт 123 ззовні у фаєрволі", "• Встанови авторизований NTP: time.windows.com"],
            "L4-038": ["• Tapo reboot для очистки пам'яті роутера", "• Перезапусти програму що створює ghost сесії"],
            "L4-039": ["• НЕ вводь паролі на цьому сайті!", "• Перевір URL — це підробка або вірус-проксі"],
            "L4-040": ["• Перезапусти підозрілу програму", "• Запусти антивірусне сканування"],
            # L5-L7
            "L5-001": ["• Перевір системний час (має бути точним)", "• Вимкни SSL scanning в антивірусі тимчасово"],
            "L5-002": ["• Увійди на сайт заново", "• Очисти cookies для сайту"],
            "L5-003": ["• ТЕРМІНОВО! Від'єднай ПК від мережі", "• Просканируй: Malwarebytes, HitmanPro", "• НЕ платити викуп — зверніться до кіберполіції"],
            "L5-004": ["• НЕ підключайся!", "• ssh-keygen -R <host> якщо сервер перевстановлено", "• Перевір IP сервера через інший канал"],
            "L5-005": ["• ТЕРМІНОВО! Set-SmbServerConfiguration -EnableSMB1Protocol $false", "• Встанови патч MS17-010"],
            "L5-006": ["• Увімкни 2FA на акаунті", "• Зміни пароль", "• Перевір активні сесії"],
            "L5-007": ["• Перезавантаж смарт-пристрій", "• Оновити прошивку пристрою"],
            "L5-008": ["• Оновити програму до останньої версії", "• Увімкни TLS 1.3 у налаштуваннях"],
            "L5-009": ["• НЕ вводь особисті дані на цьому сайті", "• Перевір URL — можливо це phishing"],
            "L5-010": ["• Перевір slow queries в БД", "• Оптимізуй запити або збільш connection pool"],
            "L5-011": ["• НЕБЕЗПЕКА! Хтось підмінив SSH сервер", "• Видали старий ключ: ssh-keygen -R hostname", "• Перевір IP сервера через інший канал"],
            "L5-012": ["• Встанови кодек: VLC або K-Lite Codec Pack", "• Або конвертуй відео у підтримуваний формат"],
            "L5-013": ["• Очисти cookies та кеш браузера", "• Або використовуй sticky session URL з токеном"],
            "L5-014": ["• Це нормально при вході з нового пристрою", "• Вийди з усіх сесій у налаштуваннях акаунту якщо не ти"],
            "L5-015": ["• Перевір правила Windows Firewall для портів 135/445", "• Увімкни Network Discovery якщо потрібен доступ в LAN"],
            "L5-016": ["• Очисти кеш браузера та перезавантаж сторінку", "• Проблема на стороні сервера — спробуй пізніше"],
            "L5-017": ["• Перезавантаж сторінку або очисти кеш браузера", "• Може бути проблема сервера — спробуй інший браузер"],
            "L5-018": ["• Це неефективно, але нешкідливо", "• Повідом розробника додатку про надмірне використання Base64"],
            "L5-019": ["• НЕБЕЗПЕКА! Можлива MITM атака або підроблений сайт", "• НЕ вводь паролі. Перевір URL уважно."],
            "L5-020": ["• Перевір стабільність мережі — можливі втрати пакетів", "• Або збільш буфер reassembly у налаштуваннях TCP"],
            # L7
            "L7-001": ["• Перевір VPN — часто допомагає", "• fast.com vs speedtest.net для порівняння"],
            "L7-002": ["• ТЕРМІНОВО! Від'єднай від мережі", "• Просканируй Malwarebytes", "• Перевстанови Windows"],
            "L7-003": ["• Discord → Settings → Voice → зміни регіон сервера", "• Відкрий UDP 50000-65535 у Firewall"],
            "L7-004": ["• Підключись кабелем", "• Закрий зайві вкладки і програми"],
            "L7-005": ["• Знизь якість до 1080p", "• Підключись кабелем замість WiFi"],
            "L7-006": ["• Steam → Settings → Downloads → Only update between: (нічний час)"],
            "L7-007": ["• Перевір пароль поштового акаунту", "• Для Gmail/Outlook з 2FA — створи App Password"],
            "L7-008": ["• Відмінно! Ігровий режим активний"],
            "L7-009": ["• Спробуй локальне керування (Tapo local API)", "• Home Assistant з локальними інтеграціями"],
            "L7-010": ["• Перевір правильність URL", "• Пошукай сайт у Google"],
            "L7-011": ["• Увімкни VPN для доступу", "• Або спробуй DNS 1.1.1.1"],
            "L7-012": ["• Зупини торрент або YouTube на час гри", "• Увімкни Gaming Mode в NetGuardian"],
            "L7-013": ["• Перевір пароль поштової скриньки", "• Якщо 2FA — переперевір код автентифікатора"],
            "L7-014": ["• Дефрагментуй HDD або перевір стан SSD (CrystalDiskInfo)", "• Або зменш кількість одночасних з'єднань у торрент-клієнті"],
            "L7-015": ["• Це нормально — хмарні сервіси у Китаї лагають", "• Спробуй локальний режим (Local Control) без хмари якщо підтримується"],
            "L7-016": ["• Закрий зайві вкладки браузера", "• Або додай більше RAM або увімкни Tab Discard"],
            "L7-017": ["• Це нормально при шумоподавленні — нічого не потрібно", "• Вимкни AI шумоподавлення якщо CPU > 90%"],
            "L7-018": ["• Встанови uBlock Origin у браузері", "• Або використовуй режим Інкогніто для конфіденційності"],
            "L7-019": ["• Встанови uBlock Origin — заблокує рекламу та прискорить сторінки", "• Або увімкни DNS-блокування реклами через Pi-hole"],
            "L7-020": ["• Це нормально — дочекайся завершення завантаження", "• Або обмеж швидкість upload у налаштуваннях Telegram"],
        }
        return recs.get(e.code, [
            "• Перевір налаштування мережі",
            "• Зверніться до технічного спеціаліста",
        ])


# ══════════════════════════════════════════════════════════════
#  ГОЛОВНИЙ AI КЛАС
# ══════════════════════════════════════════════════════════════

class NetGuardianAI:
    """
    Головний AI аналізатор NetGuardian.

    Використання:
        ai = NetGuardianAI(tapo_plug=plug, bot_alert=alerter.send)
        results = ai.analyze(metrics_dict)
        for r in results:
            print(r.format_for_user())
    """

    def __init__(self, tapo_plug=None, bot_alert: Optional[Callable] = None):
        self._fixer   = AutoFixer(tapo=tapo_plug, bot_alert=bot_alert)
        self._alert   = bot_alert
        self._history: List[DiagResult] = []

    def analyze(self, metrics: dict, ping_ok: bool = True) -> List[DiagResult]:
        """
        Аналізує метрики та повертає список DiagResult.

        metrics — словник з поточними показниками мережі:
          tapo_watts, tapo_volts, tapo_amps, tapo_online, tapo_is_on
          nic_up, nic_speed, link_duplex, packet_loss, jitter
          dns_ok, ip, gateway_ping_ok, retransmits_pct
          open_ports (list), mac_alerts (list), rssi, snr
          http_status, processes (list), ssl_ok, session_ok
        """
        results: List[DiagResult] = []

        for entry in KB:
            if self._matches(entry, metrics, ping_ok):
                result = self._process(entry)
                results.append(result)
                self._history.append(result)

        # Сортуємо: CRITICAL першими, потім за confidence
        severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
        results.sort(key=lambda r: (
            severity_order.get(r.entry.severity, 9),
            -r.entry.confidence
        ))

        return results[:5]  # максимум 5 діагнозів за раз

    def _matches(self, entry: DiagEntry, m: dict, ping_ok: bool) -> bool:
        """Перевіряє чи відповідає запис поточним метрикам."""
        w   = m.get("tapo_watts", -1)
        v   = m.get("tapo_volts", -1)
        a   = m.get("tapo_amps", -1)
        ton = m.get("tapo_online", False)
        ton_on = m.get("tapo_is_on", False)
        nic = m.get("nic_up", True)
        speed = m.get("nic_speed", 1000)
        loss  = m.get("packet_loss", 0)
        jitter= m.get("jitter", 0)
        dns   = m.get("dns_ok", True)
        ip    = m.get("ip", "")
        gw_ok = m.get("gateway_ping_ok", True)
        retr  = m.get("retransmits_pct", 0)
        ports = m.get("open_ports", [])
        rssi  = m.get("rssi", -50)
        snr   = m.get("snr", 25)
        processes = m.get("processes", [])
        new_macs  = m.get("new_macs_per_10s", 0)
        duplex    = m.get("link_duplex", "Full")
        http_code = m.get("http_status", 200)
        ssl_ok    = m.get("ssl_ok", True)

        code = entry.code

        # L1 checks
        if code == "L1-001": return ton and not ton_on and w < 0.1 and not ping_ok
        if code == "L1-002": return 0.5 <= w <= 2.0 and not nic
        if code == "L1-003": return speed == 10
        if code == "L1-004": return not nic and m.get("nic_admin_enabled", False)
        if code == "L1-005": return w > 15 and jitter > 50
        if code == "L1-006": return m.get("nic_errors_delta", 0) > 100 and nic
        if code == "L1-007": return nic and 4 <= w <= 8 and not ping_ok
        if code == "L1-008": return not m.get("nic_admin_enabled", True)
        if code == "L1-009": return duplex == "Half"
        if code == "L1-010": return 0.1 <= w < 0.8 and ton_on
        if code == "L1-011": return v > 250
        if code == "L1-012": return m.get("tapo_power_fluctuating", False)
        if code == "L1-013": return speed == 100 and m.get("cable_cat6", False)
        if code == "L1-014": return m.get("tapo_power_pulse", False)
        if code == "L1-015": return m.get("link_flapping_per_min", 0) > 5
        if code == "L1-016": return a > 1.0
        if code == "L1-017": return m.get("alignment_errors", 0) > 0
        if code == "L1-018": return not ton and m.get("on_battery", False)
        if code == "L1-019": return m.get("temp_high", False) and nic
        if code == "L1-020": return 4 <= w <= 8 and not nic
        if code == "L1-021": return m.get("tapo_current_spike", False) and jitter > 100
        if code == "L1-022": return m.get("crc_errors_increasing", False) and nic
        if code == "L1-023": return w < 0.2 and not nic
        if code == "L1-024": return speed == 1000 and loss > 0 and m.get("cable_length_m", 0) > 90

        # L2 checks
        if code == "L2-001": return rssi < -70
        if code == "L2-002": return m.get("channel_congestion", False)
        if code == "L2-003": return m.get("wpa3_mismatch", False)
        if code == "L2-004": return m.get("evil_twin_detected", False)
        if code == "L2-005": return m.get("deauth_frames", 0) > 0
        if code == "L2-006": return not dns and nic and m.get("dns_hijacked", False)
        if code == "L2-007": return new_macs > 50
        if code == "L2-008": return m.get("wifi_pineapple_detected", False)
        if code == "L2-009": return m.get("bluetooth_active", False) and m.get("wifi_band", "") == "2.4G"
        if code == "L2-010": return nic and not gw_ok and m.get("wifi_connected", False)
        if code == "L2-011": return m.get("dfs_channel_change", False)
        if code == "L2-012": return m.get("upnp_active", False)
        if code == "L2-013": return m.get("broadcast_storm", False)
        if code == "L2-014": return m.get("espressif_device", False)
        if code == "L2-015": return m.get("hidden_device_stream", False)
        if code == "L2-016": return rssi >= -65 and snr < 10
        if code == "L2-017": return nic and not ip and m.get("vlan_issue", False)
        if code == "L2-018": return m.get("duplicate_mac", False)

        # L3 checks
        if code == "L3-001": return ping_ok and not dns
        if code == "L3-002": return ip.startswith("169.254.")
        if code == "L3-003": return not ping_ok and m.get("traceroute_stops_hop1", False)
        if code == "L3-004": return m.get("vpn_leak", False)
        if code == "L3-005": return m.get("routing_loop", False)
        if code == "L3-006": return m.get("mtu_too_high", False) and loss > 5
        if code == "L3-007": return m.get("dns_server", "") == "127.0.0.1"
        if code == "L3-008": return not dns and not ping_ok and m.get("isp_dns_down", False)
        if code == "L3-009": return m.get("double_nat", False)
        if code == "L3-010": return m.get("dns_poisoning", False)
        if code == "L3-011": return not ping_ok and 5 <= w <= 9 and gw_ok
        if code == "L3-012": return not m.get("default_route", True)
        if code == "L3-013": return m.get("port53_blocked", False)
        if code == "L3-014": return m.get("cgnat_detected", False)
        if code == "L3-015": return m.get("rogue_gateway", False)
        if code == "L3-016": return m.get("nat_strict", False) and not ping_ok
        if code == "L3-017": return m.get("pps", 0) > 10000
        if code == "L3-018": return m.get("backbone_congestion", False)
        if code == "L3-019": return m.get("dns_leak_vpn", False)
        if code == "L3-020": return not ip and m.get("dhcp_pool_empty", False)
        if code == "L3-021": return m.get("gateway_hijack", False)

        # L4 checks
        if code == "L4-001": return 25565 in ports
        if code == "L4-002": return retr > 5
        if code == "L4-003": return 445 in m.get("open_wan_ports", [])
        if code == "L4-004": return m.get("ssh_brute_force", False)
        if code == "L4-005": return 3389 in m.get("open_wan_ports", [])
        if code == "L4-006": return m.get("udp_flood", False)
        if code == "L4-007": return m.get("bufferbloat", False)
        if code == "L4-008": return m.get("tcp_conn", 0) > 500 and w > 8
        if code == "L4-009": return m.get("tcp_conn", 0) > 2000 and w > 10
        if code == "L4-010": return m.get("tls_old", False)
        if code == "L4-011": return m.get("ssl_strip", False)
        if code == "L4-012": return m.get("dns_amplification", False)
        if code == "L4-013": return m.get("nagle_active", False) and "game" in processes
        if code == "L4-014": return m.get("sip_brute_force", False)
        if code == "L4-015": return m.get("udp_stream_4k", False) and w > 8

        # L5-L6 checks
        if code == "L5-001": return not ssl_ok and m.get("ssl_handshake_timeout", False)
        if code == "L5-002": return m.get("session_expired", False)
        if code == "L5-003": return m.get("encrypted_unknown_traffic", False)
        if code == "L5-004": return m.get("ssh_key_mismatch", False)
        if code == "L5-005": return m.get("smb_v1_active", False)
        if code == "L5-006": return m.get("session_brute_force", False)
        if code == "L5-007": return m.get("json_malformed", False)
        if code == "L5-008": return m.get("weak_cipher", False)
        if code == "L5-009": return m.get("untrusted_cert", False)
        if code == "L5-010": return m.get("db_long_sessions", False)

        # L7 checks
        if code == "L7-001": return m.get("isp_throttling", False)
        if code == "L7-002": return m.get("miner_detected", False)
        if code == "L7-003": return m.get("discord_rtc_fail", False)
        if code == "L7-004": return m.get("zoom_packet_loss", 0) > 2
        if code == "L7-005": return m.get("youtube_bufferl", False) and w > 9
        if code == "L7-006": return m.get("steam_update_active", False)
        if code == "L7-007": return m.get("mail_auth_fail", False)
        if code == "L7-008": return m.get("game_process", False)
        if code == "L7-009": return m.get("iot_high_latency", False)
        if code == "L7-010": return http_code == 404
        if code == "L7-011": return http_code == 403
        if code == "L7-012": return w > 10 and m.get("multiple_heavy_apps", False)

        # ── New L1 entries (025-030) ────────────────────────────
        if code == "L1-025": return v < 190
        if code == "L1-026": return w > 12 and m.get("no_traffic", False)
        if code == "L1-027": return m.get("adapter_voltage", 12) < 10 and not nic
        if code == "L1-028": return m.get("tapo_current_spike", False) and not nic
        if code == "L1-029": return m.get("voltage_drop_on_load", False) and 2 <= w <= 4
        if code == "L1-030": return not ton and nic

        # ── New L2 entries (019-060) ────────────────────────────
        if code == "L2-019": return w > 4 and not m.get("ssid_found", True)
        if code == "L2-020": return m.get("auth_4way_fail", False)
        if code == "L2-021": return m.get("arp_duplicate_ip", False)
        if code == "L2-022": return m.get("unknown_mac_detected", False)
        if code == "L2-023": return rssi < -80 and m.get("band", "") == "5ghz"
        if code == "L2-024": return rssi > -20 and m.get("wifi_disconnect_freq", 0) > 3
        if code == "L2-025": return m.get("legacy_80211b", False)
        if code == "L2-026": return m.get("mac_filter_denied", False)
        if code == "L2-027": return jitter > 200 and m.get("band", "") == "2.4ghz" and w > 0
        if code == "L2-028": return m.get("dhcp_no_offer", False)
        if code == "L2-029": return m.get("apipa_ip", False)
        if code == "L2-030": return m.get("hidden_ssid_interference", False)
        if code == "L2-031": return rssi < -70 and w > 4
        if code == "L2-032": return m.get("high_airtime_no_traffic", False)
        if code == "L2-033": return m.get("frequent_roaming", False)
        if code == "L2-034": return m.get("legacy_client_high_load", False)
        if code == "L2-035": return m.get("mac_randomized", False)
        if code == "L2-036": return m.get("captive_portal_redirect", False)
        if code == "L2-037": return m.get("unknown_oui_device", False)
        if code == "L2-038": return m.get("perfect_handover", False)
        if code == "L2-039": return m.get("multicast_flood", False)
        if code == "L2-040": return m.get("dangerous_ports_open", False)
        if code == "L2-041": return m.get("rssi_sudden_drop", False) and m.get("no_location_change", True)
        if code == "L2-042": return m.get("wpa3_incompatible", False)
        if code == "L2-043": return m.get("channel_13_active", False)
        if code == "L2-044": return m.get("probe_requests_count", 0) > 100
        if code == "L2-045": return rssi > -50 and m.get("data_rate_low", False)
        if code == "L2-046": return m.get("ap_isolation_active", False)
        if code == "L2-047": return m.get("zero_mac_detected", False)
        if code == "L2-048": return m.get("wifi_assoc_ok", False) and not ping_ok and w > 3
        if code == "L2-049": return m.get("espressif_device", False)
        if code == "L2-050": return m.get("igmp_multicast_drop", False)
        if code == "L2-051": return m.get("country_code_mismatch", False)
        if code == "L2-052": return m.get("channel_changes_per_hour", 0) > 3
        if code == "L2-053": return m.get("arp_proxy_external", False)
        if code == "L2-054": return m.get("xiaomi_tuya_sync", False)
        if code == "L2-055": return m.get("lan_ping_high", False) and ping_ok
        if code == "L2-056": return m.get("zero_source_mac", False)
        if code == "L2-057": return m.get("tapo_rf_correlation", False)
        if code == "L2-058": return w < 4 and rssi < -60
        if code == "L2-059": return m.get("ipv6_only_fe80", False) and not m.get("ipv4_address", True)
        if code == "L2-060": return rssi > -20 and jitter > 30

        # ── New L3 entries (022-060) ────────────────────────────
        if code == "L3-022": return m.get("icmp_redirect", False)
        if code == "L3-023": return m.get("external_ip_changed", False)
        if code == "L3-024": return m.get("traceroute_hop2_fail", False)
        if code == "L3-025": return m.get("bgp_flapping", False)
        if code == "L3-026": return m.get("subnet_mask_wrong", False)
        if code == "L3-027": return m.get("geo_route_foreign", False)
        if code == "L3-028": return m.get("dns_parental_block", False)
        if code == "L3-029": return m.get("vpn_speed_10x_slower", False)
        if code == "L3-030": return m.get("udp_loss_high", False) and ping_ok
        if code == "L3-031": return m.get("traceroute_loop_30", False)
        if code == "L3-032": return m.get("public_port80_open", False)
        if code == "L3-033": return m.get("fake_ping_1ms", False)
        if code == "L3-034": return m.get("wireguard_handshake_fail", False)
        if code == "L3-035": return m.get("steam_tcp_reset", False) and ping_ok
        if code == "L3-036": return m.get("isp_internal_only", False)
        if code == "L3-037": return m.get("backbone_congestion_hop4", False)
        if code == "L3-038": return m.get("nic_driver_error", False)
        if code == "L3-039": return m.get("dns_rate_limited", False)
        if code == "L3-040": return m.get("vpn_cert_expired", False)
        if code == "L3-041": return m.get("ipv6_link_local_only", False)
        if code == "L3-042": return m.get("syn_stealth_scan", False)
        if code == "L3-043": return m.get("nat_symmetric", False)
        if code == "L3-044": return m.get("ipv4_stack_fail", False)
        if code == "L3-045": return m.get("dhcp_pool_conflict", False)
        if code == "L3-046": return m.get("icmp_flood_pps", 0) > 500
        if code == "L3-047": return m.get("triple_nat", False)
        if code == "L3-048": return m.get("ipv6_temporary_addr", False)
        if code == "L3-049": return ping_ok and m.get("tcp_blocked_firewall", False)
        if code == "L3-050": return m.get("udp_port_scan", False)
        if code == "L3-051": return m.get("dhcp_lease_expired", False)
        if code == "L3-052": return m.get("ipv6_6to4_tunnel", False)
        if code == "L3-053": return m.get("static_ip_conflict", False)
        if code == "L3-054": return m.get("fin_scan_detected", False)
        if code == "L3-055": return m.get("vpn_mtu_blackhole", False)
        if code == "L3-056": return not ton and m.get("tapo_app_online", False)
        if code == "L3-057": return m.get("dns_reply_unknown_ip", False)
        if code == "L3-058": return nic and w > 4 and m.get("routing_table_empty", False)
        if code == "L3-059": return m.get("ttl_very_low", False)
        if code == "L3-060": return m.get("vpn_dns_leak", False)

        # ── New L4 entries (016-040) ────────────────────────────
        if code == "L4-016": return m.get("syn_sent_high", False)
        if code == "L4-017": return m.get("port_3074_closed", False)
        if code == "L4-018": return m.get("fin_wait_excessive", False)
        if code == "L4-019": return m.get("port_445_wan_open", False)
        if code == "L4-020": return m.get("tcp_rst_high", False)
        if code == "L4-021": return m.get("dns_zone_transfer_tcp", False)
        if code == "L4-022": return m.get("ssl_handshake_fail_dpi", False)
        if code == "L4-023": return m.get("rdp_3389_exposed", False)
        if code == "L4-024": return m.get("udp_fragmented_gaming", False)
        if code == "L4-025": return m.get("keepalive_off", False)
        if code == "L4-026": return m.get("upnp_port_mapping", False)
        if code == "L4-027": return m.get("tcp_out_of_order", 0) > 10
        if code == "L4-028": return m.get("ssl_strip_attempt", False)
        if code == "L4-029": return m.get("syn_flood_detected", False)
        if code == "L4-030": return m.get("https_port443_rst", False)
        if code == "L4-031": return m.get("quic_blocked", False)
        if code == "L4-032": return m.get("ssl_cert_expired", False)
        if code == "L4-033": return m.get("tcp_zero_window", False)
        if code == "L4-034": return m.get("sip_port5060_attack", False)
        if code == "L4-035": return m.get("vpn_mss_too_low", False)
        if code == "L4-036": return m.get("tcp_fast_retransmit", False)
        if code == "L4-037": return m.get("ntp_spoofing", False)
        if code == "L4-038": return m.get("zombie_sessions", False)
        if code == "L4-039": return m.get("ssl_self_signed", False)
        if code == "L4-040": return m.get("socket_rst_loop", False)

        # ── New L5 entries (011-020) ────────────────────────────
        if code == "L5-011": return m.get("ssh_key_mismatch", False)
        if code == "L5-012": return m.get("codec_not_found", False)
        if code == "L5-013": return m.get("sticky_session_fail", False)
        if code == "L5-014": return m.get("duplicate_session", False)
        if code == "L5-015": return m.get("rpc_port_blocked", False)
        if code == "L5-016": return m.get("compression_mismatch", False)
        if code == "L5-017": return m.get("utf8_encoding_error", False)
        if code == "L5-018": return m.get("base64_overhead", False)
        if code == "L5-019": return m.get("sni_mismatch", False)
        if code == "L5-020": return m.get("tcp_reassembly_lag", False)

        # ── New L7 entries (013-020) ────────────────────────────
        if code == "L7-013": return m.get("mail_auth_fail", False)
        if code == "L7-014": return m.get("disk_io_bottleneck", False)
        if code == "L7-015": return m.get("iot_cloud_latency", False)
        if code == "L7-016": return m.get("browser_ram_high", False)
        if code == "L7-017": return m.get("zoom_cpu_high", False)
        if code == "L7-018": return m.get("facebook_tracking", False)
        if code == "L7-019": return m.get("ad_servers_detected", False)
        if code == "L7-020": return m.get("telegram_upload_active", False)

        return False

    def _process(self, entry: DiagEntry) -> DiagResult:
        """Виконує auto-fix для L2-L7 або повертає результат без нього для L1."""
        result = DiagResult(entry=entry)

        if not entry.is_physical and entry.can_auto_fix:
            log.info(f"AI: auto-fix '{entry.auto_fix}' for {entry.code}")
            ok, msg = self._fixer.run(entry.auto_fix)
            result.fix_success = ok
            result.fix_message = msg

            # Надіслати сповіщення
            if self._alert and entry.severity == "CRITICAL":
                try:
                    self._alert(f"⚠️ *{entry.title}*\n{entry.explanation}\n\n{msg}")
                except Exception:
                    pass

        return result

    def search(self, query: str, limit: int = 5) -> List[DiagEntry]:
        """Пошук по базі знань за ключовими словами."""
        query = query.lower()
        scored = []
        for e in KB:
            score = 0
            if query in e.title.lower():       score += 3
            if query in e.explanation.lower(): score += 2
            for t in e.tags:
                if query in t: score += 2
            if query in e.state.lower():       score += 1
            if score > 0:
                scored.append((score, e))
        return [e for _, e in sorted(scored, key=lambda x: -x[0])[:limit]]

    def get_entry(self, code: str) -> Optional[DiagEntry]:
        return _CODE_INDEX.get(code)

    @property
    def history(self) -> List[DiagResult]:
        return list(self._history[-50:])

    @property
    def stats(self) -> dict:
        total = len(self._history)
        fixed = sum(1 for r in self._history if r.fix_success)
        return {"total_diagnoses": total, "auto_fixed": fixed,
                "kb_entries": len(KB)}
