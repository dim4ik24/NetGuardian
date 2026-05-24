"""
NetGuardian AI — LAN Monitor v5.5
ЗМІНИ v5.5 (над v5.4):
  • get_device_display_name() — phone_brand fallback: "Apple iPhone" / "Android-смартфон"
    якщо бренд відомий але модель ні; фільтрація android-xxxxxx hostnames
  • get_device_icon() — _PC_CHIPSETS розширено
  • get_device_threat_summary() — враховує is_banned
  • format_device_card() — додано поле is_banned
  • LanMonitor._restore_active_bans() — після скану відновлює ARP для забанених
  • LanMonitor.stats() — додано "banned" лічильник
  • _clean_name() — "Смартфон", "Телефон" у BAD-списку
"""

import re
import threading
import time
import concurrent.futures as _cf
from typing import Callable, Optional


# ──────────────────────────────────────────────────────────────────
# HELPER UTILS
# ──────────────────────────────────────────────────────────────────

def _is_random_mac(mac: str) -> bool:
    if not mac or len(mac) < 2:
        return False
    try:
        return bool(int(mac.replace("-", ":").split(":")[0], 16) & 0x02)
    except (ValueError, IndexError):
        return False


def _clean_name(s: str) -> str:
    if not s:
        return ""
    s = s.strip()
    _BAD = {
        "", "—", "-", "N/A", "n/a", "unknown", "Unknown",
        "UNKNOWN", "*", "None", "null", "(null)", "?",
        "localhost", "DHCP_HOST", "Невідомо", "Пристрій",
        "router", "gateway", "Смартфон", "Телефон",
    }
    return "" if s in _BAD else s


def _first_line(s: str, max_len: int = 60) -> str:
    if not s:
        return ""
    return s.strip().split("\n")[0][:max_len].strip()


def _looks_like_ip(s: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", s.strip()))


def _guess_os_from_ttl(ttl) -> str:
    if not ttl:
        return ""
    ttl = int(ttl)
    if ttl <= 64:  return "Linux / iOS / Android"
    if ttl <= 128: return "Windows"
    if ttl >= 200: return "Мережевий пристрій"
    return ""


# ──────────────────────────────────────────────────────────────────
# DISPLAY NAME
# ──────────────────────────────────────────────────────────────────

def get_device_display_name(host: dict) -> str:
    """
    Пріоритети:
      1. user_label  2. phone_name  3. phone_model  4. phone_brand (fallback)
      5. ssh_hostname  6. netbios_name  7. dhcp_hostname  8. mdns_name
      9. upnp_name  10. hostname  11. cert_cn  12. snmp_sysdescr
      13. vendor+devtype  14. random-MAC hint  15. IP
    Спеціальний випадок: SHIP server → Tapo Smart пристрій
    """
    label = _clean_name(host.get("user_label", ""))
    if label:
        return label

    # Tapo Smart Plug/Camera — фірмовий HTTP сервер "SHIP"
    http_server = (host.get("http_server") or "").strip().upper()
    if http_server.startswith("SHIP"):
        mac = host.get("mac", "")
        tail = ""
        try:
            cleaned = mac.replace(":", "").replace("-", "").upper()
            if len(cleaned) >= 6:
                tail = cleaned[-6:]
        except Exception:
            pass
        ports = host.get("open_ports", [])
        if 554 in ports or 2020 in ports:
            base = "Tapo Camera"
        else:
            base = "Tapo Smart Plug"
        return f"{base}-{tail}" if tail else base

    phone_name = _clean_name(host.get("phone_name", ""))
    if phone_name:
        if not re.match(r"^android-[0-9a-f]{6,}$", phone_name, re.IGNORECASE):
            return phone_name

    phone_model = _clean_name(host.get("phone_model", ""))
    if phone_model:
        brand = _clean_name(host.get("phone_brand", ""))
        if brand and brand.lower() not in phone_model.lower():
            return f"{brand} {phone_model}"
        return phone_model

    # v5.5: brand без моделі
    phone_brand = _clean_name(host.get("phone_brand", ""))
    if phone_brand:
        if phone_brand == "Apple":   return "Apple iPhone"
        if phone_brand == "Android": return "Android-смартфон"
        return f"{phone_brand} (смартфон)"

    ssh_hn = _clean_name(host.get("ssh_hostname", ""))
    if ssh_hn and not _looks_like_ip(ssh_hn):
        return ssh_hn

    nb = _clean_name(host.get("netbios_name", ""))
    if nb:
        return nb

    dhcp_hn = _clean_name(host.get("dhcp_hostname", ""))
    if dhcp_hn and not _looks_like_ip(dhcp_hn):
        return dhcp_hn

    mdns = _clean_name(host.get("mdns_name", ""))
    if mdns and not _looks_like_ip(mdns):
        return mdns

    upnp = _clean_name(host.get("upnp_name", "")) or _clean_name(host.get("upnp_model", ""))
    if upnp:
        return upnp

    hostname = _clean_name(host.get("hostname", ""))
    if hostname and not _looks_like_ip(hostname):
        return hostname

    cert = _clean_name(host.get("cert_cn", ""))
    if cert and not _looks_like_ip(cert) and len(cert) > 4:
        return cert

    snmp = _clean_name(host.get("snmp_sysdescr", ""))
    if snmp and len(snmp) > 6:
        first = _first_line(snmp)
        if first:
            return first

    vendor  = _clean_name(host.get("vendor",   ""))
    devtype = _clean_name(host.get("dev_type", ""))
    _BAD_VENDOR = {"Невідомо", "Приватний MAC", "Unknown", "?"}
    _BAD_TYPE   = {"Пристрій", "Невідомий", "Device", "Unknown", "?"}

    if vendor and vendor not in _BAD_VENDOR:
        if devtype and devtype not in _BAD_TYPE and devtype.lower() != vendor.lower():
            return f"{vendor} ({devtype})"
        return vendor
    if devtype and devtype not in _BAD_TYPE:
        return devtype

    mac = host.get("mac", "")
    if _is_random_mac(mac):
        pb   = _clean_name(host.get("phone_brand", ""))
        icon = get_device_icon(host)
        if pb:
            return f"{pb} (Приватний MAC)"
        if icon == "📱":
            vc = (host.get("dhcp_vendor_class") or "").lower()
            if "apple" in vc or "iphone" in vc or "ipad" in vc:
                return "Apple iPhone/iPad (Приватний MAC)"
            if "android" in vc or "google" in vc or "samsung" in vc:
                return "Android-смартфон (Приватний MAC)"
            return "Смартфон (Приватний MAC)"
        if icon == "💻":
            return "Ноутбук (Приватний MAC)"
        return "Пристрій (Приватний MAC)"

    return host.get("ip") or "Невідомий пристрій"


# ──────────────────────────────────────────────────────────────────
# DEVICE ICON
# ──────────────────────────────────────────────────────────────────

_PC_CHIPSETS = frozenset({
    "realtek", "intel corporation", "intel wireless",
    "dell", "hp ", "lenovo", "acer", "msi ", "gigabyte",
    "vmware", "virtualbox", "microsoft surface", "asus laptop",
    "hewlett-packard", "hewlett packard",
})

_PHONE_BRANDS_STRICT = frozenset({
    "iphone", "ipad", "ipod",
    "galaxy", "samsung galaxy", "samsung sm-",
    "pixel", "nexus",
    "xiaomi", "redmi", "poco",
    "huawei", "honor",
    "oppo", "realme", "vivo", "oneplus",
    "motorola moto", "nokia phone",
    "xperia",
})


def _mac_tail(mac: str) -> str:
    """Останні 6 hex-символів MAC для унікальних суфіксів імен."""
    if not mac: return ""
    clean = mac.replace(":", "").replace("-", "").upper()
    return clean[-6:] if len(clean) == 12 else ""


def _vendor_short(vendor: str) -> str:
    """Скорочує назву vendor до короткої форми: 'Samsung Electronics Co., Ltd' → 'Samsung'"""
    if not vendor: return ""
    v = vendor.strip()

    # Найпоширеніші vendor-маппінги
    mappings = {
        "samsung electronics": "Samsung",
        "samsung":             "Samsung",
        "apple, inc":          "Apple",
        "apple inc":           "Apple",
        "apple":               "Apple",
        "xiaomi communications": "Xiaomi",
        "xiaomi":              "Xiaomi",
        "huawei technologies": "Huawei",
        "huawei":              "Huawei",
        "honor device":        "Honor",
        "tp-link technologies": "TP-Link",
        "tp-link":             "TP-Link",
        "intel corporate":     "Intel",
        "intel":               "Intel",
        "realtek":             "Realtek",
        "google, inc":         "Google",
        "google":              "Google",
        "microsoft":           "Microsoft",
        "asus":                "Asus",
        "asustek":             "Asus",
        "d-link":              "D-Link",
        "dell":                "Dell",
        "lenovo":              "Lenovo",
        "sony":                "Sony",
        "lg electronics":      "LG",
        "nokia":               "Nokia",
        "oneplus":             "OnePlus",
        "oppo":                "Oppo",
        "vivo":                "Vivo",
        "realme":              "Realme",
        "motorola":            "Motorola",
        "amazon":              "Amazon",
        "raspberry pi":        "RaspberryPi",
        "espressif":           "ESP32",
    }
    low = v.lower()
    for key, short in mappings.items():
        if key in low:
            return short

    # Fallback: перше слово
    first = v.split()[0] if v.split() else v
    return first[:12] if len(first) > 12 else first


def get_device_display_name(host: dict) -> str:
    """
    Повертає найкраще ім'я пристрою для відображення в UI/боті/повідомленнях.
    Є єдиним джерелом правди для назви пристрою.

    Пріоритет:
      1. user_label (вручну введене)
      2. Tapo Smart пристрої (SHIP сервер)
      3. hostname (якщо не ip/unknown)
      4. phone_model, phone_name
      5. phone_brand (для телефонів без моделі)
      6. SSH/DHCP/mDNS/NetBIOS/UPnP hostname
      7. reverse_dns
      8. SSL cert CN
      9. SNMP sysDescr
     10. Vendor-MACTAIL (напр. "Samsung-AABBCC")
     11. "Смартфон-TAIL (Приватний MAC)"
     12. MAC-tail
    """
    import re

    if host.get("user_label"):
        return host["user_label"]

    # Tapo Smart-пристрої: HTTP Server header починається з "SHIP"
    http_server = (host.get("http_server") or "").strip()
    if http_server.upper().startswith("SHIP"):
        mac    = host.get("mac", "")
        tail   = _mac_tail(mac)
        ports  = host.get("open_ports", [])
        if 443 in ports and 80 in ports:
            base = "Tapo Smart Plug"
        elif 554 in ports or 2020 in ports:
            base = "Tapo Camera"
        else:
            base = "Tapo пристрій"
        return f"{base}-{tail}" if tail else base

    hostname = (host.get("hostname") or "").strip()
    if hostname and hostname not in ("—", "N/A", "unknown", "localhost") \
            and not _looks_like_ip(hostname):
        if not host.get("phone_name") and not host.get("phone_model"):
            return hostname

    if host.get("phone_model"):
        brand = host.get("phone_brand", "")
        model = host["phone_model"]
        return f"{brand} {model}".strip() if brand and brand not in model else model

    if host.get("phone_name"):
        pn = host["phone_name"]
        if not re.match(r"^android-[0-9a-f]{6,}$", pn, re.IGNORECASE):
            return pn

    if host.get("phone_brand"):
        brand  = host["phone_brand"]
        os_ver = (host.get("phone_os") or "").strip()
        if brand == "Apple":
            return "Apple iPhone"
        if brand == "Android":
            if os_ver and os_ver != "Android":
                return f"Android-смартфон [{os_ver}]"
            return "Android-смартфон"
        if brand == "Android TV":
            return "Android TV"
        return f"{brand} (смартфон)"

    ssh_hn = (host.get("ssh_hostname") or "").strip()
    if ssh_hn and ssh_hn not in ("—", "N/A", "unknown", "*"):
        return ssh_hn

    for key in ("dhcp_hostname", "mdns_name", "netbios_name", "upnp_name"):
        val = (host.get(key) or "").strip()
        if val and val not in ("—", "N/A", "unknown", "*"):
            return val

    rdns = (host.get("reverse_dns") or "").strip()
    if rdns and rdns not in ("—", "N/A") and not _looks_like_ip(rdns):
        short = rdns.split(".")[0] if len(rdns) > 30 else rdns
        return short

    if hostname and hostname not in ("—", "N/A", "unknown", "localhost") \
            and not _looks_like_ip(hostname):
        return hostname

    cert = (host.get("cert_cn") or "").strip()
    if cert and cert not in ("—", "N/A") and not _looks_like_ip(cert) and len(cert) > 4:
        return cert

    snmp = (host.get("snmp_sysdescr") or "").strip()
    if snmp and len(snmp) > 6:
        first = snmp.split("\n")[0][:50].strip()
        if first:
            return first

    vendor  = (host.get("vendor")   or "").strip()
    devtype = (host.get("dev_type") or "").strip()
    mac     = host.get("mac", "")
    tail    = _mac_tail(mac)

    # "Приватний MAC" — додаємо MAC-tail для унікальної ідентифікації
    if vendor == "Приватний MAC":
        suffix = f"-{tail}" if tail else ""
        brand = (host.get("phone_brand") or "").strip()
        if brand:
            return f"{brand}{suffix} (Приватний MAC)"
        ports = host.get("open_ports", [])
        if 62078 in ports:
            return f"iPhone/iPad{suffix} (Приватний MAC)"
        if 5555 in ports:
            return f"Android{suffix} (Приватний MAC)"
        if devtype and devtype not in ("—", "N/A", "Пристрій", "Смартфон"):
            return f"{devtype}{suffix} (Приватний MAC)"
        return f"Смартфон{suffix} (Приватний MAC)"

    # Vendor-MACTAIL (напр. "Samsung-AABBCC", "Realtek-90FE05")
    if vendor and vendor not in ("—", "N/A", "Невідомо"):
        short_v = _vendor_short(vendor)
        if tail and short_v:
            if devtype and devtype not in ("—", "N/A", "Пристрій"):
                return f"{short_v}-{tail} ({devtype})"
            return f"{short_v}-{tail}"
        if devtype and devtype not in ("—", "N/A", "Пристрій"):
            return f"{vendor} ({devtype})"
        return vendor

    # Random MAC без vendor
    if _is_random_mac(mac):
        brand = (host.get("phone_brand") or "").strip()
        suffix = f"-{tail}" if tail else ""
        ports = host.get("open_ports", [])
        if 62078 in ports:
            return f"iPhone/iPad{suffix} (Приватний MAC)"
        if 5555 in ports:
            return f"Android{suffix} (Приватний MAC)"
        if brand:
            return f"{brand}{suffix} (Приватний MAC)"
        return f"Смартфон{suffix} (Приватний MAC)"

    # MAC-тейл без vendor
    if tail:
        return f"Пристрій-{tail}"
    return host.get("ip") or "Невідомий пристрій"


def get_device_icon(host: dict) -> str:
    if host.get("is_self"):    return "🖥️"
    if host.get("is_gateway"): return "📡"
    if host.get("icon") and host.get("user_label"):
        return host["icon"]

    devtype = (host.get("dev_type")            or "").lower()
    vendor  = (host.get("vendor")              or "").lower()
    model   = (host.get("model")               or "").lower()
    upnp    = ((host.get("upnp_name")   or "") + " " +
               (host.get("upnp_model")  or "")).lower()
    mdns    = (host.get("mdns_name")           or "").lower()
    mdns_hw = (host.get("mdns_hardware_model") or "").lower()
    snmp    = (host.get("snmp_sysdescr")       or "").lower()
    dhcp_vc = (host.get("dhcp_vendor_class")   or "").lower()
    dhcp_fp = (host.get("dhcp_fp_device")      or "").lower()
    phone_m = (host.get("phone_model")         or "").lower()
    phone_b = (host.get("phone_brand")         or "").lower()
    http_sv = (host.get("http_server")         or "").lower()

    # Tapo Smart пристрої — фірмовий HTTP сервер "SHIP"
    if http_sv.startswith("ship"):
        return "🔌"

    _combo = " ".join([devtype, model, upnp, mdns, mdns_hw, snmp, dhcp_vc, dhcp_fp])
    _vendor_is_pc = any(k in vendor for k in _PC_CHIPSETS)

    if any(k in phone_m for k in _PHONE_BRANDS_STRICT): return "📱"
    if any(k in phone_b for k in _PHONE_BRANDS_STRICT): return "📱"

    _PHONE_KW = (
        "iphone", "ipad", "ipod", "android phone", "android tablet",
        "galaxy", "pixel phone", "redmi", "poco",
        "oppo", "vivo", "realme", "oneplus", "xperia",
        "смартфон", "smartphone", "мобільний",
    )
    if any(k in _combo for k in _PHONE_KW): return "📱"

    if not _vendor_is_pc:
        _PHONE_VENDOR_KW = (
            "apple", "samsung", "huawei", "honor", "xiaomi",
            "motorola", "nokia", "htc", "zte", "alcatel",
            "meizu", "oppo", "vivo", "realme", "oneplus",
        )
        if any(k in vendor for k in _PHONE_VENDOR_KW):
            if "apple" in vendor:
                mac_kw = ("macbook", "imac", "mac mini", "mac pro", "mac studio")
                if not any(k in _combo for k in mac_kw):
                    if not any(k in devtype for k in ("laptop","desktop","pc","ноутбук","комп")):
                        return "📱"
            else:
                return "📱"

    if dhcp_fp in ("iphone/ipad", "android", "android phone",
                   "android tablet", "smartphone", "tablet"):
        return "📱"

    _MAC_KW = ("macbook", "mac mini", "mac pro", "imac", "mac studio")
    if any(k in _combo or k in vendor for k in _MAC_KW): return "💻"

    _LAPTOP_KW = (
        "ноутбук", "laptop", "notebook", "thinkpad", "ideapad",
        "inspiron", "latitude", "xps ", "pavilion", "elitebook",
        "probook", "surface", "chromebook", "vivobook", "zenbook",
        "aspire", "predator", "nitro", "swift", "ux", "rog ",
    )
    if any(k in _combo for k in _LAPTOP_KW): return "💻"
    if _vendor_is_pc and any(k in devtype for k in ("laptop", "ноутбук", "notebook")): return "💻"

    _DESKTOP_KW = ("windows pc", "desktop", "workstation", "комп'ютер", "пк ")
    if any(k in _combo for k in _DESKTOP_KW): return "🖥️"
    if _vendor_is_pc and any(k in devtype for k in ("windows pc", "desktop", "pc", "пк")): return "🖥️"

    _ROUTER_KW = (
        "router", "роутер", "gateway", "access point", " ap ",
        "tp-link archer", "keenetic", "mikrotik", "ubiquiti",
        "unifi", "edgerouter", "zyxel", "netgear", "d-link",
        "tenda ", "xiaomi router", "cudy", "openwrt", "dd-wrt",
    )
    if any(k in _combo for k in _ROUTER_KW): return "📡"
    if "router" in vendor or "роутер" in vendor: return "📡"

    _SWITCH_KW = ("switch", "свіч", "cisco catalyst", "netgear gs", "tp-link sg")
    if any(k in _combo for k in _SWITCH_KW): return "🔌"

    _TV_KW = (
        "smart tv", "телевізор", "television", " tv ",
        "lg tv", "samsung tv", "sony bravia", "philips tv",
        "hisense", "tcl tv", "fire tv", "firetv", "apple tv", "appletv",
        "chromecast", "roku ", "android tv", "webos", "tizen", "vidaa",
    )
    if any(k in _combo for k in _TV_KW): return "📺"

    _GAME_KW = ("playstation", "ps4 ", "ps5 ", "xbox", "nintendo", "steam deck", "nvidia shield")
    if any(k in _combo for k in _GAME_KW): return "🎮"

    _SPEAKER_KW = (
        "sonos", "echo dot", "amazon echo", "google home",
        "nest audio", "homepod", "bose soundbar",
        "speaker", "soundbar", "колонка",
    )
    if any(k in _combo for k in _SPEAKER_KW): return "🔊"

    _PRINT_KW = (
        "printer", "принтер", "mfp", "мфу", "laserjet", "epson",
        "canon", "brother", "kyocera", "xerox", "officejet",
    )
    if any(k in _combo for k in _PRINT_KW): return "🖨️"

    _CAM_KW = (
        "camera", "камера", "hikvision", "dahua", "reolink",
        "onvif", "ipcam", "ip cam", "axis ", "doorbell",
    )
    if any(k in _combo for k in _CAM_KW): return "📷"

    _NAS_KW = (
        "nas", "synology", "qnap", "freenas", "truenas",
        "unraid", "openmediavault", " server", "сервер",
    )
    if any(k in _combo for k in _NAS_KW): return "🗄️"

    _IOT_KW = (
        "tuya", "esp8266", "esp32", "tasmota",
        "shelly", "zigbee", "z-wave", "zwave",
        "smart plug", "smart bulb", "розетка", "лампа",
    )
    if any(k in _combo for k in _IOT_KW): return "🔌"

    if _is_random_mac(host.get("mac", "")) and not _vendor_is_pc:
        return "📱"

    if host.get("icon") and host["icon"] != "❓":
        return host["icon"]

    return "❓"


# ──────────────────────────────────────────────────────────────────
# THREAT SUMMARY
# ──────────────────────────────────────────────────────────────────

_PORT_NAMES = {
    21:   "FTP",     22:   "SSH",    23:  "Telnet",   25:  "SMTP",
    53:   "DNS",     80:   "HTTP",   110: "POP3",     135: "RPC",
    139:  "NetBIOS", 143: "IMAP",   443: "HTTPS",    445: "SMB",
    993:  "IMAPS",   995: "POP3S", 1433: "MSSQL",   1723: "PPTP",
    3306: "MySQL",  3389: "RDP",   5900: "VNC",     6881: "BitTorrent",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "Dev", 9100: "Print",
}


def get_device_threat_summary(host: dict) -> str:
    threat = host.get("threat", "safe")
    ports  = host.get("open_ports", [])

    if host.get("is_banned"):
        return "🚫  Заблоковано (ARP + MAC filter)"

    if host.get("alert_dismissed") or host.get("is_allowed"):
        return "✓  Дозволений пристрій"
    if host.get("is_trusted"):
        if host.get("is_self"):    return "✅  Цей комп'ютер"
        if host.get("is_gateway"): return "✅  Довірений шлюз"
        return "✅  Довірений пристрій"
    if host.get("is_self"):
        p = len(ports)
        return f"🖥️  Цей комп'ютер  [{p} портів]" if p else "🖥️  Цей комп'ютер"

    if host.get("is_gateway"):
        gw_name = _clean_name(host.get("hostname", ""))
        return f"📡  Шлюз · {gw_name}" if gw_name else "📡  Шлюз мережі (роутер)"

    crit_ports = [p for p in ports if p in {21, 23, 3389, 5900, 1433, 3306}]
    if crit_ports:
        names = ", ".join(_PORT_NAMES.get(p, str(p)) for p in crit_ports[:3])
        return f"⛔  Критичний порт: {names}"

    if threat == "critical":
        return "⛔  КРИТИЧНА ЗАГРОЗА — перевірте вручну" \
               if not host.get("is_trusted") else "⚠️  Критичний (довірений)"
    if threat == "danger":
        if ports:
            names = ", ".join(_PORT_NAMES.get(p, str(p)) for p in ports[:3])
            return f"⚠️  Небезпечні порти: {names}"
        return "⚠️  Небезпечний пристрій"
    if threat == "warn":
        if ports:
            names = ", ".join(_PORT_NAMES.get(p, str(p)) for p in ports[:3])
            return f"🟡  Відкриті порти: {names}"
        if host.get("is_new"):             return "🟡  Новий невідомий пристрій"
        if _is_random_mac(host.get("mac","")): return "🟡  Приватний MAC (не ідентифіковано)"
        return "🟡  Підозрілий пристрій"

    if host.get("is_new"): return "🆕  Новий пристрій (безпечний)"
    if ports:
        names = ", ".join(_PORT_NAMES.get(p, str(p)) for p in ports[:2])
        return f"🟢  Безпечний  [{names}]"
    src = _name_source(host)
    return f"🟢  Безпечний  ({src})" if src else "🟢  Безпечний"


def _name_source(host: dict) -> str:
    if host.get("user_label"):  return "назву задано вручну"
    if host.get("phone_model"): return "модель ідентифіковано"
    if host.get("phone_name"):  return f"телефон · {host.get('phone_id_method','')}"
    if host.get("ssh_hostname"):  return "★ SSH DHCP"
    if host.get("netbios_name"):  return "NetBIOS"
    if host.get("dhcp_hostname"):
        return f"{host.get('dhcp_source','DHCP')} lease"
    if host.get("mdns_name"):     return "mDNS"
    if _is_random_mac(host.get("mac","")): return "приватний MAC"
    return ""


# ──────────────────────────────────────────────────────────────────
# FORMAT DEVICE CARD
# ──────────────────────────────────────────────────────────────────

def format_device_card(host: dict) -> str:
    icon   = get_device_icon(host)
    name   = get_device_display_name(host)
    threat = host.get("threat", "safe")
    ports  = host.get("open_ports", [])

    threat_prefix = {"critical":"⛔","danger":"⚠️","warn":"🟡","safe":"🟢"}.get(threat,"🟢")
    if host.get("is_trusted") or host.get("alert_dismissed"): threat_prefix = "✅"
    if host.get("is_banned"):                                  threat_prefix = "🚫"

    lines = [
        f"{icon} {threat_prefix} {name}",
        f"   IP: {host.get('ip','?')}   MAC: {host.get('mac','?')}",
    ]

    ident = []
    ssh_hn  = _clean_name(host.get("ssh_hostname",""))
    nb      = _clean_name(host.get("netbios_name",""))
    dhcp_hn = _clean_name(host.get("dhcp_hostname",""))
    if ssh_hn:  ident.append(f"★SSH: {ssh_hn}")
    if nb:      ident.append(f"NetBIOS: {nb}")
    if dhcp_hn and dhcp_hn not in (ssh_hn, nb):
        ident.append(f"{host.get('dhcp_source','DHCP')}: {dhcp_hn}")

    pm = _clean_name(host.get("phone_model",""))
    pn = _clean_name(host.get("phone_name",""))
    po = _clean_name(host.get("phone_os",""))
    if pm:
        brand = _clean_name(host.get("phone_brand",""))
        ident.append(f"Модель: {brand+' '+pm if brand and brand not in pm else pm}".strip())
    if pn and pn not in (pm, ssh_hn, dhcp_hn):
        if not re.match(r"^android-[0-9a-f]{6,}$", pn, re.IGNORECASE):
            ident.append(f"Назва: {pn}")
    if po: ident.append(f"ОС: {po}")
    mdns = _clean_name(host.get("mdns_name",""))
    if mdns and mdns not in (ssh_hn, dhcp_hn, pn, nb):
        ident.append(f"mDNS: {mdns}")
    if ident:
        lines.append("   " + "   ·   ".join(ident))

    vendor  = _clean_name(host.get("vendor",""))
    devtype = _clean_name(host.get("dev_type",""))
    if vendor:
        vt = vendor + (f"  ·  {devtype}" if devtype and devtype.lower() != vendor.lower() else "")
        lines.append(f"   Виробник: {vt}")

    ct = host.get("connection_type","")
    if ct:
        net = f"   {ct}"
        band = host.get("band",""); sig = host.get("signal_pct"); dbm = host.get("signal_dbm")
        if band: net += f"  {band}"
        if sig is not None: net += f"  {sig}%"
        if dbm: net += f" ({dbm} dBm)"
        lines.append(net)

    if ports:
        lines.append(f"   Порти: {', '.join(f'{p}/{_PORT_NAMES.get(p,chr(63))}' for p in ports[:8])}")

    lines.append(f"   {get_device_threat_summary(host)}")

    if host.get("is_banned"):
        lines.append("   🚫  Пристрій у чорному списку (заблоковано)")

    notes = _clean_name(host.get("user_notes",""))
    if notes: lines.append(f"   📝 {notes}")
    if _is_random_mac(host.get("mac","")): lines.append("   🔒 Приватний MAC — iPhone/Android/Windows")

    return "\n".join(lines)


# ──────────────────────────────────────────────────────────────────
# LAN MONITOR v5.5
# ──────────────────────────────────────────────────────────────────

class LanMonitor:
    """
    Фоновий монітор LAN з автовідновленням ARP-блокування.

    v5.5: після кожного скану перевіряє список забанених пристроїв
    і відновлює ARP-отруєння для тих що знову з'явились у мережі.
    Це гарантує блокування навіть після перезапуску програми.
    """

    def __init__(self, engine,
                 interval: int = 120,
                 scan_timeout: int = 120,
                 on_update: Optional[Callable] = None,
                 on_new_device: Optional[Callable] = None,
                 on_threat: Optional[Callable] = None):
        self._engine       = engine
        self._interval     = interval
        self._scan_timeout = scan_timeout
        self._on_update    = on_update
        self._on_new       = on_new_device
        self._on_threat    = on_threat

        self._thread: Optional[threading.Thread] = None
        self._stop_event    = threading.Event()
        self._trigger_event = threading.Event()
        self._pending_live_cb: Optional[Callable] = None

        self._last_scan   = 0.0
        self._scan_count  = 0
        self._is_scanning = False
        self._known_macs: set  = set()
        self._last_hosts: list = []
        self._lock = threading.Lock()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="LanMonitor")
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._trigger_event.set()
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def trigger_scan(self, live_device_cb: Optional[Callable] = None):
        with self._lock:
            self._pending_live_cb = live_device_cb
        self._trigger_event.set()

    def stats(self) -> dict:
        with self._lock:
            hosts = list(self._last_hosts)

        banned_count = 0
        try:
            banned_count = len(self._engine.get_banned())
        except Exception:
            pass

        return {
            "scan_count":  self._scan_count,
            "last_scan":   self._last_scan,
            "is_scanning": self._is_scanning,
            "total":       len(hosts),
            "trusted":     sum(1 for h in hosts if h.get("is_trusted")),
            "new":         sum(1 for h in hosts if h.get("is_new")),
            "banned":      banned_count,
            "threats":     sum(1 for h in hosts
                               if h["threat"] in ("danger", "critical")
                               and not h.get("is_trusted")
                               and not h.get("alert_dismissed")),
            "wifi":        sum(1 for h in hosts if h.get("connection_type") == "WiFi"),
            "wired":       sum(1 for h in hosts if h.get("connection_type") == "LAN"),
            "phones":      sum(1 for h in hosts
                               if h.get("icon") == "📱"
                               and not h.get("is_self")
                               and not h.get("is_gateway")),
            "phones_identified": sum(
                1 for h in hosts
                if (h.get("phone_model") or h.get("phone_name") or
                    h.get("dhcp_hostname") or h.get("ssh_hostname"))
                and h.get("icon") == "📱"
                and not h.get("is_self")
                and not h.get("is_gateway")),
        }

    def get_last_hosts(self) -> list:
        with self._lock:
            return list(self._last_hosts)

    def _loop(self):
        self._do_scan()
        while not self._stop_event.is_set():
            fired = self._trigger_event.wait(timeout=self._interval)
            if self._stop_event.is_set():
                break
            if fired:
                self._trigger_event.clear()
            self._do_scan()

    def _do_scan(self):
        with self._lock:
            live_cb = self._pending_live_cb
            self._pending_live_cb = None
            self._is_scanning = True

        try:
            executor = _cf.ThreadPoolExecutor(
                max_workers=1, thread_name_prefix="LanMonitor-scan")
            future = executor.submit(
                self._engine.scan_network,
                progress_cb=None,
                live_device_cb=live_cb,
            )
            try:
                hosts = future.result(timeout=self._scan_timeout)
            except _cf.TimeoutError:
                print(f"[LanMonitor] scan timeout {self._scan_timeout}s — skip")
                future.cancel()
                return
            finally:
                executor.shutdown(wait=False)
        except Exception as exc:
            print(f"[LanMonitor] scan error: {exc}")
            return
        finally:
            with self._lock:
                self._is_scanning = False

        self._scan_count += 1
        self._last_scan   = time.time()

        new_macs = {
            h["mac"] for h in hosts if h.get("mac") and h["mac"] != "—"
        } - self._known_macs
        self._known_macs.update(new_macs)

        with self._lock:
            self._last_hosts = list(hosts)

        # v5.5: відновлюємо ARP-блокування для забанених пристроїв
        self._restore_active_bans(hosts)

        if self._on_update:
            try:
                self._on_update(hosts)
            except Exception as e:
                print(f"[LanMonitor] on_update error: {e}")

        for h in hosts:
            mac = h.get("mac", "—")
            if mac in new_macs and self._on_new:
                try:
                    self._on_new(h)
                except Exception as e:
                    print(f"[LanMonitor] on_new_device error: {e}")

            if (h["threat"] in ("danger", "critical")
                    and not h.get("is_trusted")
                    and not h.get("alert_dismissed")
                    and self._on_threat):
                try:
                    self._on_threat(h)
                except Exception as e:
                    print(f"[LanMonitor] on_threat error: {e}")

    def _restore_active_bans(self, hosts: list):
        """
        v5.5: після скану перевіряє список забанених і відновлює
        ARP-отруєння для тих що знову з'явились у мережі.
        Захищає від ситуації коли пристрій перепідключився,
        або NetGuardian перезапустили.
        """
        try:
            from features.security.lan_security import permanent_ban_manager, trust_db

            banned = trust_db.get_banned()
            if not banned:
                return

            gw = self._engine._detect_gateway()
            arp_cache: dict = {}
            try:
                arp_cache = self._engine._get_arp_table()
            except Exception:
                pass
            gw_mac = arp_cache.get(gw, "")

            # Індекс онлайн-пристроїв по MAC і IP
            online_macs = {h.get("mac","").upper() for h in hosts}
            online_ips  = {h.get("ip","") for h in hosts}

            for entry in banned:
                mac = (entry.get("mac") or "").upper()
                ip  = entry.get("ip","")

                if not mac:
                    continue

                # Пристрій онлайн?
                if mac not in online_macs and ip not in online_ips:
                    continue

                # ARP ще не активний → запускаємо
                if not permanent_ban_manager.is_active(mac):
                    if ip and gw_mac:
                        permanent_ban_manager.start_ban(ip, mac, gw, gw_mac)

                    # Паралельно MAC filter на роутері
                    if ip:
                        threading.Thread(
                            target=lambda m=mac, i=ip, g=gw:
                                self._engine.router_mac_filter(m, i, g, block=True),
                            daemon=True
                        ).start()

        except ImportError:
            pass
        except Exception as e:
            print(f"[LanMonitor] _restore_active_bans error: {e}")