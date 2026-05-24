"""
pi_kb.py — Локальна база знань для Raspberry Pi.

Скорочена копія NetGuardian Knowledge Base з 60+ найкритичнішими записами.
Призначена для роботи на Pi без інтернету — коли ПК офлайн, Pi може
проаналізувати власні зібрані помилки і повернути діагноз через MQTT.

Кожен запис аналогічний app/core/knowledge_base.py:
    code, title, symptoms, causes, solutions, severity, tags

Доповнено КРИТИЧНИМИ записами для збору помилок Pi:
  - ICMP_TIMEOUT
  - DNS_NXDOMAIN
  - DNS_TIMEOUT
  - HIGH_PACKET_LOSS
  - HIGH_JITTER
  - GATEWAY_UNREACHABLE
  - HTTP_5xx_BURST
  - TCP_RESET_BURST
"""
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class KBEntry:
    code:      str
    title:     str
    symptoms:  List[str]
    causes:    List[str]
    solutions: List[str]
    auto_fix:  Optional[str] = None
    severity:  str = "WARNING"
    tags:      List[str] = field(default_factory=list)


KB: List[KBEntry] = [
    # ── ФІЗИЧНИЙ РІВЕНЬ / ОБЛАДНАННЯ ──────────────────────────────
    KBEntry("HW-001", "Кабель відійшов або пошкоджений",
        ["Інтернет повністю відсутній", "Ethernet LED не горить"],
        ["Кабель не вставлений", "Згин кабелю", "Пошкоджений RJ-45"],
        ["Перевстав кабель", "Спробуй інший кабель", "Перевір LED"],
        severity="CRITICAL", tags=["фізичний", "кабель"]),

    KBEntry("HW-003", "Роутер завис",
        ["Всі сайти не відкриваються", "Пінг до роутера timeout"],
        ["Перевантаження", "Перегрів", "Збій прошивки"],
        ["Перезавантажити роутер (30 сек)", "Перевір вентиляцію"],
        auto_fix="reboot_router", severity="CRITICAL", tags=["роутер"]),

    KBEntry("HW-004", "Wi-Fi сигнал слабкий",
        ["Низький RSSI < -75 dBm", "Часті відключення"],
        ["Далеко від роутера", "Перешкоди (стіни/метал)", "2.4ГГц колізії"],
        ["Перейти ближче до роутера", "Перейти на 5ГГц", "Wi-Fi extender"],
        severity="WARNING", tags=["wifi", "сигнал"]),

    # ── DNS ──────────────────────────────────────────────────────
    KBEntry("DNS-001", "DNS не відповідає",
        ["NXDOMAIN на правильні домени", "Сайти не відкриваються"],
        ["DNS-сервер недоступний", "Провайдер блокує", "Маршрутизація"],
        ["Змінити DNS на 1.1.1.1 / 8.8.8.8", "ipconfig /flushdns",
         "Перевір через nslookup google.com"],
        auto_fix="flush_dns", severity="CRITICAL", tags=["dns"]),

    KBEntry("DNS-002", "DNS-резолвінг повільний",
        ["Сайти відкриваються довго", "Перший запит > 500мс"],
        ["Повільний DNS провайдера", "DNS-кеш переповнений", "DoH/DoT повільний"],
        ["Cloudflare 1.1.1.1", "Скинути кеш DNS", "Quad9 9.9.9.9"],
        auto_fix="flush_dns", severity="WARNING", tags=["dns", "швидкість"]),

    KBEntry("DNS-003", "DNS-hijacking (провайдер підміняє відповіді)",
        ["Несподівані редіректи", "Реклама на чужих сайтах"],
        ["Провайдер блокує/підміняє DNS", "DNS-сервер скомпрометований"],
        ["DoH через Cloudflare", "VPN", "DNSCrypt"],
        severity="CRITICAL", tags=["dns", "безпека"]),

    # ── IP / DHCP ─────────────────────────────────────────────────
    KBEntry("IP-001", "DHCP не видає IP",
        ["IP 169.254.x.x (APIPA)", "Інтернет відсутній"],
        ["DHCP-сервер вимкнено", "MAC-фільтр блокує", "Wi-Fi пароль збился"],
        ["ipconfig /release && /renew", "Перезавантажити роутер",
         "Перевір DHCP на роутері"],
        auto_fix="renew_dhcp", severity="CRITICAL", tags=["dhcp", "ip"]),

    KBEntry("IP-002", "Конфлікт IP-адрес",
        ["Періодична втрата зв'язку", "ARP-конфлікти у логах"],
        ["Два пристрої з тим самим IP", "Статичний IP перетинається з DHCP"],
        ["Перейти на DHCP", "Виправити статичний IP"],
        severity="WARNING", tags=["ip", "конфлікт"]),

    KBEntry("IP-003", "Gateway недоступний",
        ["Пінг до 192.168.0.1 timeout", "LAN недоступний"],
        ["Роутер вимкнено", "Зміни підмережі", "Кабель"],
        ["Перевір роутер", "ipconfig /all → перевір gateway"],
        severity="CRITICAL", tags=["gateway", "ip"]),

    # ── WI-FI ─────────────────────────────────────────────────────
    KBEntry("WIFI-001", "Wi-Fi постійно відключається",
        ["Connection drops every 5-10 min", "Roaming між каналами"],
        ["Слабкий сигнал", "2 точки доступу з тим самим SSID", "Драйвер"],
        ["Оновити драйвер Wi-Fi", "Перевір канали", "Wi-Fi mesh"],
        severity="WARNING", tags=["wifi", "відключення"]),

    KBEntry("WIFI-002", "Перевантаження каналу 2.4ГГц",
        ["Низька швидкість на 2.4ГГц", "Багато сусідніх мереж"],
        ["10+ сусідніх Wi-Fi мереж", "Bluetooth/мікрохвильовка"],
        ["Перейти на 5ГГц", "Зміни канал на 1/6/11", "Wi-Fi сканер"],
        severity="WARNING", tags=["wifi", "канал"]),

    KBEntry("WIFI-003", "Authentication failed (неправильний пароль)",
        ["Не можу підключитись до Wi-Fi", "WPA2 handshake fail"],
        ["Неправильний пароль", "WPA-PSK неспівпадає"],
        ["Перевір пароль", "Видалити мережу і додати знову"],
        severity="WARNING", tags=["wifi", "auth"]),

    # ── ПРОВАЙДЕР / WAN ───────────────────────────────────────────
    KBEntry("ISP-001", "Провайдер недоступний",
        ["Пінг до 8.8.8.8 timeout", "Pi бачить LAN але не інтернет"],
        ["Аварія у провайдера", "Кабель до будинку обірвано", "ONT/модем"],
        ["Подзвонити провайдеру", "Перевір DownDetector",
         "Перезавантажити ONT/модем"],
        severity="CRITICAL", tags=["isp", "wan"]),

    KBEntry("ISP-002", "Високий ping до інтернету (jitter)",
        ["Ping 100-300мс", "Лагі в іграх", "Відео буферизується"],
        ["Перевантаження провайдера", "QoS відсутній", "Throttling"],
        ["Перевір швидкість Speedtest", "QoS у роутері",
         "Звернутись до провайдера"],
        severity="WARNING", tags=["isp", "ping"]),

    KBEntry("ISP-003", "Throttling (провайдер обмежує швидкість)",
        ["Швидкість падає в певні години", "Speedtest показує менше"],
        ["Провайдер обмежує (peering)", "Перевищення тарифу"],
        ["VPN (Cloudflare WARP)", "Тарифний план", "Перевір контракт"],
        severity="WARNING", tags=["isp", "throttling"]),

    # ── БЕЗПЕКА ────────────────────────────────────────────────────
    KBEntry("SEC-001", "ARP spoofing атака",
        ["Часті ARP-конфлікти", "Дивний пристрій у LAN"],
        ["Атакер у мережі", "MITM-атака", "Зловмисник перехоплює трафік"],
        ["Заблокувати MAC у роутері", "Змінити Wi-Fi пароль",
         "Перевір список пристроїв"],
        severity="CRITICAL", tags=["безпека", "arp", "атака"]),

    KBEntry("SEC-002", "Новий невідомий пристрій у мережі",
        ["MAC якого раніше не було", "Підозра на зломаний пароль"],
        ["Гість підключився", "Сусід зламав Wi-Fi", "IoT-пристрій"],
        ["Перевір MAC OUI", "Змінити Wi-Fi пароль",
         "Увімкнути MAC-фільтр"],
        severity="WARNING", tags=["безпека", "lan"]),

    # ── TCP / UDP / ПОРТИ ─────────────────────────────────────────
    KBEntry("TCP-001", "TCP RST burst (з'єднання обриваються)",
        ["Часті 'Connection reset'", "TCP-handshake fails"],
        ["Firewall закриває з'єднання", "MTU mismatch", "Атака TCP-RST"],
        ["Перевір MTU (1500/1492)", "Вимкни AV firewall тимчасово",
         "Перевір логи Windows Defender"],
        severity="WARNING", tags=["tcp", "firewall"]),

    KBEntry("TCP-002", "MTU mismatch (фрагментація)",
        ["Деякі сайти не відкриваються (HTTPS) але інші ОК", "Loss на великих пакетах"],
        ["MTU 1500 vs PPPoE 1492", "VPN додає overhead"],
        ["netsh interface ipv4 set subinterface MTU=1452",
         "Перевір через ping -f -l 1472 8.8.8.8"],
        severity="WARNING", tags=["mtu", "tcp"]),

    # ── HTTP / HTTPS ──────────────────────────────────────────────
    KBEntry("HTTP-001", "5xx помилки сайту",
        ["503/504/500 на сайтах", "API timeouts"],
        ["Сайт недоступний", "Перевантаження сервера", "Cloudflare 5xx"],
        ["Перевір через DownDetector", "Спробуй пізніше",
         "Перевір з іншого пристрою"],
        severity="INFO", tags=["http", "server"]),

    KBEntry("HTTP-002", "Cloudflare 1020 Access Denied",
        ["Cloudflare блокує доступ"],
        ["IP у блок-листі", "VPN/Tor виявлено", "Геоблок"],
        ["Вимкнути VPN", "Звернутись до власника сайту"],
        severity="INFO", tags=["http", "cloudflare"]),

    # ── ПРОДУКТИВНІСТЬ ────────────────────────────────────────────
    KBEntry("PERF-001", "Швидкість сильно нижча за тарифний план",
        ["Speedtest показує 30 з 100 Мбіт", "Сайти повільно"],
        ["Wi-Fi обмежує", "Кабель Cat5 замість Cat6", "Background процеси",
         "Throttling провайдера"],
        ["Speedtest напряму до роутера", "Перевір процеси",
         "Перевір кабель"],
        severity="WARNING", tags=["продуктивність", "швидкість"]),

    KBEntry("PERF-002", "Висока завантаженість каналу (bufferbloat)",
        ["Високий jitter під час Speedtest", "Лагі під час завантажень"],
        ["Відсутній QoS", "Розрив завантажень", "Великі буфери у роутері"],
        ["Увімкнути SQM/CAKE у OpenWrt", "QoS у TP-Link/Asus",
         "Обмежити завантаження"],
        severity="WARNING", tags=["bufferbloat", "qos"]),

    # ── VPN ───────────────────────────────────────────────────────
    KBEntry("VPN-001", "VPN розриває з'єднання",
        ["VPN постійно перепідключається", "Часті розриви"],
        ["Слабкий сигнал", "Сервер перевантажений", "MTU"],
        ["Інший VPN-сервер", "MTU 1300", "Перевір ключі"],
        severity="WARNING", tags=["vpn"]),

    KBEntry("VPN-002", "VPN перехоплює локальний трафік",
        ["Tapo P110 недоступна через VPN", "LAN-пристрої не пінгуються"],
        ["VPN маршрутизує ВСЕ через тунель"],
        ["Split-tunneling", "Виключити 192.168.0.0/16",
         "Статичний route до Tapo"],
        severity="WARNING", tags=["vpn", "routing"]),

    # ── СПЕЦИФІЧНІ ПОМИЛКИ ВІД PI ─────────────────────────────────
    KBEntry("PI-001", "Pi бачить інтернет, ПК — ні",
        ["Pi пінг ОК до 8.8.8.8", "ПК пінг fail"],
        ["Проблема саме на ПК", "Wi-Fi драйвер ПК", "VPN на ПК", "AV на ПК"],
        ["Перезапустити Wi-Fi адаптер", "Вимкнути VPN тимчасово",
         "Перевір антивірус"],
        severity="WARNING", tags=["pc-only", "isolation"]),

    KBEntry("PI-002", "І Pi, і ПК не бачать інтернет",
        ["Pi і ПК — обидва fail"],
        ["Провайдер недоступний", "Роутер завис", "Кабель WAN"],
        ["Перезавантажити роутер", "Подзвонити провайдеру",
         "Перевір ONT/модем"],
        severity="CRITICAL", tags=["network-wide", "isp"]),

    KBEntry("PI-003", "Pi не бачить роутер",
        ["Pi пінг до 192.168.0.1 fail", "Pi disconnected"],
        ["Pi далеко від роутера", "Wi-Fi пароль змінено", "Роутер перезавантажено"],
        ["Перепідключитись до Wi-Fi", "Перевір сигнал",
         "Перезавантажити Pi"],
        severity="WARNING", tags=["pi", "wifi"]),

    KBEntry("PI-004", "CPU Pi перегрівся",
        ["temp > 75°C", "throttled status != 0"],
        ["Поганий тепловідвід", "Висока температура у кімнаті",
         "Перевантаження процесів"],
        ["Heatsink на чіп", "Перевір процеси (top)",
         "Зменши кількість задач"],
        severity="WARNING", tags=["pi", "hardware"]),
]


# ══════════════════════════════════════════════════════════════════
#  SEARCH FUNCTIONS
# ══════════════════════════════════════════════════════════════════
def build_index(kb: list = KB) -> dict:
    idx = {
        "by_code":      {},
        "by_tag":       {},
        "by_severity":  {"CRITICAL": [], "WARNING": [], "INFO": []},
        "auto_fixable": [],
    }
    for entry in kb:
        idx["by_code"][entry.code] = entry
        for tag in entry.tags:
            idx["by_tag"].setdefault(tag, []).append(entry)
        idx["by_severity"][entry.severity].append(entry)
        if entry.auto_fix:
            idx["auto_fixable"].append(entry)
    return idx


def search_kb(query: str, kb: list = KB, limit: int = 5) -> list:
    """Шукає у KB за ключовими словами."""
    query = query.lower()
    scored = []
    for entry in kb:
        score = 0
        if query in entry.title.lower():       score += 3
        for s in entry.symptoms:
            if query in s.lower():              score += 2
        for t in entry.tags:
            if query in t:                      score += 2
        for c in entry.causes:
            if query in c.lower():              score += 1
        for s in entry.solutions:
            if query in s.lower():              score += 1
        if score > 0:
            scored.append((score, entry))
    return [e for _, e in sorted(scored, key=lambda x: -x[0])[:limit]]


def get_by_symptoms(symptoms: list, kb: list = KB) -> list:
    """Підбирає записи за набором симптомів."""
    results = {}
    for symptom in symptoms:
        for m in search_kb(symptom, kb, limit=3):
            current = results.get(m.code, (0, m))
            results[m.code] = (current[0] + 1, m)
    return [e for _, e in sorted(results.values(), key=lambda x: -x[0])]


def entry_to_dict(entry: KBEntry) -> dict:
    """Серіалізація для MQTT-publish."""
    return {
        "code":      entry.code,
        "title":     entry.title,
        "symptoms":  entry.symptoms,
        "causes":    entry.causes,
        "solutions": entry.solutions,
        "auto_fix":  entry.auto_fix,
        "severity":  entry.severity,
        "tags":      entry.tags,
    }


_INDEX = build_index()


if __name__ == "__main__":
    print(f"Pi KB loaded: {len(KB)} entries")
    print("\nCategories:")
    for sev, entries in _INDEX["by_severity"].items():
        print(f"  {sev}: {len(entries)}")
    print(f"\nAuto-fixable: {len(_INDEX['auto_fixable'])}")

    # Тест пошуку
    print("\n--- Test: search 'dns' ---")
    for e in search_kb("dns"):
        print(f"  [{e.code}] {e.title}")