# core/wifi_engine.py
"""
NetGuardian AI — Wi-Fi Engine  v6
Виправлення v5:
  1. Власні мережі (is_mine=True) виключені з підрахунку інтерференції —
     роутер не рахує сам себе як "перешкоду"
  2. Перемикання каналу рекомендується тільки якщо покращення > MIN_SWITCH_GAIN (25%)
  3. Абсолютний поріг: якщо інтерференція низька скрізь — "канал оптимальний"
  4. Новий метод get_wifi_report_text() для Telegram-бота
  5. Новий метод ascii_channel_bar() — ASCII-графік завантаженості каналів
"""

from __future__ import annotations
import subprocess
import platform
import re
from dataclasses import dataclass
from typing import Optional

# ══════════════════════════════════════════════════════════
#  OUI → VENDOR
# ══════════════════════════════════════════════════════════

OUI_TABLE: dict[str, str] = {
    # TP-Link
    "F81A67":"TP-Link","A42BB0":"TP-Link","B0BE76":"TP-Link",
    "686FF0":"TP-Link","AC84C6":"TP-Link","74DADA":"TP-Link",
    "E848B8":"TP-Link","5035AF":"TP-Link","C025E9":"TP-Link",
    "D46E5C":"TP-Link","50C7BF":"TP-Link","8CFAB1":"TP-Link",
    "B4B024":"TP-Link","F4F26D":"TP-Link","1027F5":"TP-Link",
    # ASUS
    "107B44":"ASUS","2C4D54":"ASUS","3497F6":"ASUS",
    "38D547":"ASUS","50465D":"ASUS","7085C2":"ASUS",
    "90E6BA":"ASUS","B06EBF":"ASUS","E03F49":"ASUS",
    "048D38":"ASUS","10BF48":"ASUS","30B4A4":"ASUS",
    # Cudy
    "E84DD0":"Cudy","B8F009":"Cudy","105BAD":"Cudy",
    # Xiaomi / Redmi
    "28E31F":"Xiaomi","642737":"Xiaomi","744AA4":"Xiaomi",
    "8C97EA":"Xiaomi","B0E235":"Xiaomi","F48B32":"Xiaomi",
    "5453ED":"Xiaomi","A0864C":"Xiaomi","C40BCE":"Xiaomi",
    # D-Link
    "00179A":"D-Link","1CBDB9":"D-Link","2889C1":"D-Link",
    "34363B":"D-Link","6045CB":"D-Link","B8A386":"D-Link",
    # NETGEAR
    "202BC1":"NETGEAR","28C68E":"NETGEAR","4F7A26":"NETGEAR",
    "6CB0CE":"NETGEAR","9C3DCF":"NETGEAR","C44195":"NETGEAR",
    # Tenda
    "C83A35":"Tenda","D4C6AC":"Tenda","C8CCEF":"Tenda",
    "E8BFCA":"Tenda","988B0A":"Tenda","4CEBD6":"Tenda",
    # Keenetic
    "68FF7B":"Keenetic","50FA84":"Keenetic","DC9B9C":"Keenetic",
    # ZyXEL
    "B4751C":"ZyXEL","001349":"ZyXEL","C8B373":"ZyXEL",
    # MikroTik
    "4C5E0C":"MikroTik","6C3B6B":"MikroTik","B8690E":"MikroTik",
    "CC2DE0":"MikroTik","D4CA6D":"MikroTik","E4CE01":"MikroTik",
    "2CC8D9":"MikroTik","B8590A":"MikroTik",
    # Huawei
    "001E10":"Huawei","28311C":"Huawei","3C47C9":"Huawei",
    "4C1FAA":"Huawei","8C34FD":"Huawei","E8CD2D":"Huawei",
    # Apple
    "000393":"Apple","04F7E4":"Apple","3C0754":"Apple",
    "6C96CF":"Apple","A45E60":"Apple","F0D1A9":"Apple",
    "8C8EF2":"Apple","D0817A":"Apple","A8BE27":"Apple",
    # Samsung
    "002339":"Samsung","284CAF":"Samsung","8C711C":"Samsung",
    "F4428F":"Samsung","B47443":"Samsung",
    # Linksys / Cisco
    "00E06F":"Linksys","14DAE9":"Linksys","20AA4B":"Cisco",
    # Ubiquiti
    "00156D":"Ubiquiti","0418D6":"Ubiquiti","44D9E7":"Ubiquiti",
    "687252":"Ubiquiti","78A351":"Ubiquiti","802AA8":"Ubiquiti",
    "24A43C":"Ubiquiti","70A741":"Ubiquiti",
    # Realtek
    "00E04C":"Realtek",
}

def lookup_vendor(bssid: str) -> str:
    oui = bssid.replace(":", "").replace("-", "").upper()[:6]
    return OUI_TABLE.get(oui, "—")


# ══════════════════════════════════════════════════════════
#  CONSTANTS
# ══════════════════════════════════════════════════════════

CHANNELS_5GHZ = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140,
    149, 153, 157, 161, 165,
]

NONOVERLAP_20MHZ = [1, 6, 11]
NONOVERLAP_40MHZ = [3, 11]

# Мінімальне відносне покращення щоб рекомендувати зміну каналу.
# 0.25 = рекомендувати тільки якщо новий канал на 25% вільніший.
# Без цього порогу на майже порожньому ефірі (приватний будинок)
# алгоритм постійно "знаходить" кращий канал з мінімальною різницею.
MIN_SWITCH_GAIN = 0.25

# Абсолютний поріг інтерференції (0–100).
# Якщо навіть найгірший канал нижче цього значення — ефір вільний,
# не потрібно нікуди переключатись.
LOW_INTERFERENCE_ABS = 15.0

# Профілі роутерів (для відкриття адмін-панелі)
ROUTER_PROFILES = [
    ("cudy",       "Cudy",            "/index.html#/wifi/basic"),
    ("tplink",     "TP-Link",         "/webpages/index.html#wirelessBasic"),
    ("tplink_new", "TP-Link (новий)", "/webpages/settings/wireless/basic.html"),
    ("asus",       "ASUS",            "/Advanced_Wireless_Content.asp"),
    ("dlink",      "D-Link",          "/Advanced/Wireless/adv_wifi.asp"),
    ("mikrotik",   "MikroTik",        "/webfig/#Wireless"),
    ("xiaomi",     "Xiaomi/Redmi",    "/#/wifi"),
    ("keenetic",   "Keenetic",        "/#dashboard"),
    ("netgear",    "NETGEAR",         "/WLG_wireless_dual_band.htm"),
    ("zyxel",      "ZyXEL",           "/wlbsc.html"),
    ("linksys",    "Linksys",         "/Wireless_Basic.asp"),
    ("huawei",     "Huawei",          "/html/index.asp#/wifi"),
    ("generic",    "Інший",           "/"),
]


# ══════════════════════════════════════════════════════════
#  DATA CLASS
# ══════════════════════════════════════════════════════════

@dataclass
class WifiNetwork:
    ssid:          str  = "Hidden Network"
    bssid:         str  = ""
    channel:       int  = 0
    signal:        int  = 0
    auth:          str  = "WPA2"
    radio_type:    str  = ""
    band:          str  = "2.4 GHz"
    channel_width: int  = 20
    max_rate:      str  = ""
    vendor:        str  = "—"
    is_mine:       bool = False


# ══════════════════════════════════════════════════════════
#  ENGINE
# ══════════════════════════════════════════════════════════

class WifiEngine:

    OVERLAP_24 = 4
    OVERLAP_5  = 4

    # ──────────────────────────────────────────────────────
    # ──────────────────────────────────────────────────────
    @staticmethod
    def has_wifi_adapter() -> bool:
        """
        Перевіряє чи є фізичний Wi-Fi адаптер у системі.
        Не потребує прав адміна. Повертає True якщо є хоча б
        один активний Wi-Fi інтерфейс.
        """
        if platform.system() == "Windows":
            try:
                # WlanAPI — найнадійніший спосіб
                import ctypes, ctypes.wintypes as wt
                wlan   = ctypes.windll.wlanapi
                handle = wt.HANDLE()
                ver    = wt.DWORD()
                if wlan.WlanOpenHandle(2, None, ctypes.byref(ver),
                                       ctypes.byref(handle)) != 0:
                    return False  # WlanAPI недоступний = немає адаптера
                # WlanEnumInterfaces
                class _GUID(ctypes.Structure):
                    _fields_ = [("d1",wt.DWORD),("d2",wt.WORD),
                                 ("d3",wt.WORD),("d4",ctypes.c_ubyte*8)]
                class _IFI(ctypes.Structure):
                    _fields_ = [("guid",_GUID),("desc",ctypes.c_wchar*256),
                                 ("state",ctypes.c_uint)]
                class _ILIST(ctypes.Structure):
                    _fields_ = [("n",wt.DWORD),("idx",wt.DWORD),
                                 ("info",_IFI*64)]
                p = ctypes.POINTER(_ILIST)()
                wlan.WlanEnumInterfaces(handle, None, ctypes.byref(p))
                count = p.contents.n if p else 0
                wlan.WlanFreeMemory(p)
                wlan.WlanCloseHandle(handle, None)
                return count > 0
            except Exception:
                pass
            # Fallback: netsh
            try:
                out = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, timeout=4,
                    errors="ignore", encoding="utf-8").stdout
                # "There is no wireless interface" = немає адаптера
                no_adapter_markers = [
                    "there is no wireless interface",
                    "немає бездротового",
                    "нет беспроводного",
                    "no wireless interface",
                ]
                low = out.lower()
                if any(m in low for m in no_adapter_markers):
                    return False
                # Якщо є хоч якийсь вивід — адаптер є
                return bool(out.strip())
            except Exception:
                return False
        else:
            # Linux: перевіряємо iwconfig або /sys/class/net
            try:
                out = subprocess.run(
                    ["iwconfig"], capture_output=True,
                    text=True, timeout=4).stdout
                return "ESSID" in out or "IEEE 802.11" in out
            except Exception:
                pass
            try:
                import os
                for iface in os.listdir("/sys/class/net"):
                    if os.path.exists(f"/sys/class/net/{iface}/wireless"):
                        return True
                return False
            except Exception:
                return False

    # Кількість сканів для усереднення сигналу.
    # 2 скани = баланс між точністю і швидкістю (~2-4 сек).
    # Усереднення прибирає природні флуктуації ±10-15% між сканами.
    SCAN_PASSES = 2

    def scan_networks(self) -> list[WifiNetwork]:
        """
        Виконує SCAN_PASSES сканувань і усереднює сигнал по BSSID.
        Це усуває флуктуації ±10-15% які виникають між одиночними
        сканами і призводять до хибних змін навантаженості каналів.
        """
        all_passes: list[list[WifiNetwork]] = []

        scan_fn = (self._scan_windows
                   if platform.system() == "Windows"
                   else self._scan_linux)

        for i in range(self.SCAN_PASSES):
            try:
                nets = scan_fn()
                if nets:
                    all_passes.append(nets)
            except Exception as e:
                print(f"[WifiEngine] scan pass {i} error: {e}")

        if not all_passes:
            return []

        # Збираємо всі мережі по BSSID → усереднюємо сигнал
        bssid_signals: dict[str, list[int]] = {}
        bssid_net:     dict[str, WifiNetwork] = {}

        for nets in all_passes:
            for n in nets:
                key = n.bssid or n.ssid   # fallback на SSID якщо BSSID відсутній
                if key not in bssid_signals:
                    bssid_signals[key] = []
                    bssid_net[key] = n
                bssid_signals[key].append(n.signal)

        merged: list[WifiNetwork] = []
        for key, signals in bssid_signals.items():
            net = bssid_net[key]
            # Округлення до 5% — прибирає дрібний шум, зберігає значущі зміни
            avg_sig = round(sum(signals) / len(signals) / 5) * 5
            net.signal = max(1, min(100, avg_sig))
            merged.append(net)

        connected_ssid, connected_bssid, connected_radio, connected_width = (
            self._get_connected_info())
        ssid_norm  = connected_ssid.strip().lower()  if connected_ssid  else ""
        bssid_norm = connected_bssid.strip().lower() if connected_bssid else ""

        for n in merged:
            # Матч по BSSID — найнадійніший метод (не залежить від кодування)
            if bssid_norm and n.bssid and n.bssid.lower() == bssid_norm:
                n.is_mine = True
                print(f"[WifiEngine] is_mine by BSSID: '{n.ssid}' {n.bssid}")
            # Матч по SSID — нормалізований
            elif ssid_norm and n.ssid.strip().lower() == ssid_norm:
                n.is_mine = True
                print(f"[WifiEngine] is_mine by SSID: '{n.ssid}'")
            # Якщо це наша мережа і ми знаємо реальну ширину — застосовуємо
            if n.is_mine and connected_width > 0:
                n.channel_width = connected_width
                if connected_radio:
                    n.radio_type = connected_radio
                n.max_rate = _estimate_max_rate(
                    connected_radio or n.radio_type, connected_width)
                print(f"[WifiEngine] real width={connected_width}MHz "
                      f"for '{n.ssid}' (from show interfaces)")

            if n.bssid and n.vendor == "—":
                n.vendor = lookup_vendor(n.bssid)

        # Fallback 1: частковий збіг SSID (перші 4 символи)
        if ssid_norm and not any(n.is_mine for n in merged):
            partial = ssid_norm[:4]
            for n in merged:
                if n.ssid.strip().lower().startswith(partial):
                    n.is_mine = True
                    print(f"[WifiEngine] is_mine partial-SSID: '{n.ssid}' ~ '{connected_ssid}'")
                    break

        # Fallback 2: якщо взагалі нічого не знайдено і є лише одна мережа —
        # вона майже точно наша (приватний будинок з одним роутером)
        if not any(n.is_mine for n in merged) and len(merged) == 1:
            merged[0].is_mine = True
            print(f"[WifiEngine] is_mine single-network fallback: '{merged[0].ssid}'")

        print(f"[WifiEngine] знайдено {len(merged)} мереж "
              f"(усереднено {len(all_passes)} скани)")
        for n in merged:
            print(f"  {'★' if n.is_mine else ' '} {n.ssid:<22} ch{n.channel:<4} "
                  f"{n.signal:>3}%  {n.band}  {n.auth}  {n.vendor}")
        return merged

    # ──────────────────────────────────────────────────────
    def get_channel_rating(self, networks: list[WifiNetwork]) -> dict:
        """
        Розраховує інтерференцію на кожному каналі.

        ВАЖЛИВО: власні мережі (is_mine=True) НЕ рахуються як джерело
        інтерференції — інакше алгоритм завжди бачив би "свій" канал
        перевантаженим і рекомендував перемикання в нескінченному циклі.

        Рекомендація дається тільки якщо:
          • інший канал вільніший більш ніж на MIN_SWITCH_GAIN (25%)
          • АБО на поточному каналі є реальні чужі мережі з сильним сигналом
        """
        interf_24 = {ch: 0.0 for ch in range(1, 14)}
        count_24  = {ch: 0   for ch in range(1, 14)}
        interf_5  = {ch: 0.0 for ch in CHANNELS_5GHZ}
        count_5   = {ch: 0   for ch in CHANNELS_5GHZ}

        # Параметри власної (підключеної) мережі.
        # my_channel = 0 означає "ще не визначено" —
        # уникаємо хибного дефолту на канал 6.
        my_channel = 0
        my_band    = "2.4 GHz"
        my_width   = 20

        for net in networks:
            ch  = net.channel
            sig = max(net.signal, 1)
            if ch < 1:
                continue

            # Оновлюємо параметри власної мережі незалежно від фільтра
            if net.is_mine:
                my_channel = ch
                my_band    = net.band
                my_width   = net.channel_width
                # ↓↓↓ КЛЮЧОВЕ ВИПРАВЛЕННЯ: пропускаємо власну мережу
                #     щоб вона не впливала на рахунок інтерференції ↓↓↓
                continue

            if net.band == "5 GHz":
                nearest = min(CHANNELS_5GHZ, key=lambda c: abs(c - ch))
                if nearest in count_5:
                    count_5[nearest] += 1
                for target in CHANNELS_5GHZ:
                    dist   = abs(target - ch)
                    weight = max(0.0, 1.0 - dist / (self.OVERLAP_5 * 4))
                    interf_5[target] += sig * weight
            else:
                if ch > 13:
                    continue
                count_24[ch] += 1
                for target in range(1, 14):
                    dist   = abs(target - ch)
                    weight = max(0.0, 1.0 - dist / self.OVERLAP_24)
                    interf_24[target] += sig * weight

        # ── Нормалізуємо 0–100 ───────────────────────────
        max_raw_24 = max(interf_24.values(), default=1) or 1
        norm_24 = {ch: v / max_raw_24 * 100 for ch, v in interf_24.items()}

        best_24_20 = min(NONOVERLAP_20MHZ, key=lambda c: interf_24[c])
        best_24_40 = min(NONOVERLAP_40MHZ, key=lambda c: interf_24[c])

        if my_channel == 0:
            # Власна мережа не визначена — не можемо давати рекомендацію
            nonoverlap      = NONOVERLAP_20MHZ
            best_ch         = best_24_20
            worth_switching = False
            rec = (
                "⚠ Не вдалось визначити вашу мережу. "
                "Переконайтесь що Wi-Fi підключений і спробуйте ще раз. "
                f"Вільніший канал у вашому ефірі: {best_24_20}."
            )
        elif my_band == "2.4 GHz":
            nonoverlap = NONOVERLAP_40MHZ if my_width >= 40 else NONOVERLAP_20MHZ
            best_ch    = best_24_40 if my_width >= 40 else best_24_20

            cur_interf  = interf_24.get(my_channel, 0)
            best_interf = interf_24.get(best_ch, 0)

            # Абсолютний поріг: якщо ефір практично порожній — не треба нічого
            max_any = max(interf_24.get(c, 0) for c in nonoverlap)
            ether_empty = max_any < LOW_INTERFERENCE_ABS

            # Відносне покращення
            gain = ((cur_interf - best_interf) / max(cur_interf, 1)
                    if cur_interf > 0 else 0)
            worth_switching = (
                best_ch != my_channel
                and not ether_empty
                and gain >= MIN_SWITCH_GAIN
            )

            if worth_switching:
                rec = (
                    f"Канал {my_channel} перевантажений чужими мережами. "
                    f"Рекомендовано канал {best_ch} — на {gain*100:.0f}% вільніший "
                    f"(незалежні: {', '.join(map(str, nonoverlap))})."
                )
            elif ether_empty:
                rec = (
                    f"Ефір практично порожній — {my_channel} канал оптимальний. "
                    f"Чужих мереж поблизу немає або вони дуже слабкі."
                )
            else:
                rec = (
                    f"Канал {my_channel} — оптимальний. "
                    f"Різниця між каналами незначна ({gain*100:.0f}%). "
                    f"Незалежні канали ({my_width} МГц): "
                    f"{', '.join(map(str, nonoverlap))}."
                )
        else:
            nonoverlap = []
            best_ch    = my_channel
            worth_switching = False
            rec = (
                f"5 GHz канал {my_channel} — відмінний вибір. "
                "Канали 5 GHz практично не перекриваються."
            )

        return {
            "interference":       interf_24,
            "interference_norm":  norm_24,
            "network_count":      count_24,
            "interference_5":     interf_5,
            "network_count_5":    count_5,
            "best_channel":       best_ch,
            "best_channel_24":    best_24_20,
            "best_channel_24_40": best_24_40,
            "my_channel":         my_channel,
            "my_band":            my_band,
            "my_width":           my_width,
            "nonoverlap":         nonoverlap,
            "recommendation":     rec,
            "worth_switching":    worth_switching,
        }

    # ──────────────────────────────────────────────────────
    def get_wifi_report_text(
            self,
            networks: list[WifiNetwork],
            rating: dict) -> str:
        """
        Повертає текстовий звіт для Telegram-бота.
        Включає: статус, ASCII-графік, список мереж, рекомендацію.
        """
        my_ch   = rating["my_channel"]
        best_ch = rating["best_channel"]
        my_band = rating["my_band"]
        my_w    = rating["my_width"]
        rec     = rating["recommendation"]
        switch  = rating.get("worth_switching", False)

        mine = next((n for n in networks if n.is_mine), None)
        n_24 = sum(1 for n in networks if n.band == "2.4 GHz")
        n_5  = sum(1 for n in networks if n.band == "5 GHz")
        neighbors = [n for n in networks if not n.is_mine]

        # ── Заголовок ─────────────────────────────────────
        status_icon = "⚠️" if switch else "✅"
        lines = [
            f"📡 *Wi-Fi АНАЛІЗ*",
            f"━━━━━━━━━━━━━━━━━━━━━",
            f"🏠 Моя мережа: `{mine.ssid if mine else '?'}`",
            f"📻 Канал: `{my_ch}` ({my_band}, {my_w} MHz)",
            f"🌐 Всього мереж: `{len(networks)}`  "
            f"({n_24}×2.4GHz / {n_5}×5GHz)",
            f"",
        ]

        # ── ASCII-гістограма 2.4 GHz ──────────────────────
        lines.append("📊 *Завантаженість 2.4 GHz каналів:*")
        lines.append(self.ascii_channel_bar(rating, my_ch, best_ch))

        # ── Сусідні мережі ────────────────────────────────
        if neighbors:
            lines.append(f"\n👥 *Сусідні мережі ({len(neighbors)}):*")
            for n in sorted(neighbors, key=lambda x: -x.signal)[:8]:
                sig_bar = "▓" * round(n.signal / 20) + "░" * (5 - round(n.signal / 20))
                lock    = "🔓" if "open" in n.auth.lower() else "🔒"
                lines.append(
                    f"{lock} `{n.ssid[:18]:<18}` ch`{n.channel:<3}` "
                    f"{sig_bar} `{n.signal}%`"
                )
        else:
            lines.append("\n✅ *Сусідніх мереж не виявлено*")

        # ── Рекомендація ──────────────────────────────────
        lines.append(f"\n{status_icon} *Рекомендація:*")
        lines.append(rec)

        return "\n".join(lines)

    # ──────────────────────────────────────────────────────
    @staticmethod
    def ascii_channel_bar(rating: dict, my_ch: int, best_ch: int) -> str:
        """
        ASCII bar-chart завантаженості каналів 1–13.
        Приклад виводу:
          ch1  ░░░░░░░░░░  FREE
          ch6  ████████░░  80%  ◄ ТИ
          ch11 ██████░░░░  60%
        """
        interf  = rating.get("interference", {})
        count   = rating.get("network_count", {})
        max_v   = max((interf.get(c, 0) for c in range(1, 14)), default=1) or 1
        BAR_W   = 10

        rows = []
        for ch in range(1, 14):
            val   = interf.get(ch, 0)
            cnt   = count.get(ch, 0)
            ratio = val / max_v
            filled = round(ratio * BAR_W)
            bar   = "█" * filled + "░" * (BAR_W - filled)
            pct   = f"{ratio*100:.0f}%"

            tag = ""
            if ch == my_ch and ch == best_ch:
                tag = " ◄ ТИ ✅"
            elif ch == my_ch:
                tag = " ◄ ТИ"
            elif ch == best_ch:
                tag = " ★ BEST"

            cnt_s = f" [{cnt}мер.]" if cnt > 0 else " FREE" if val < 1 else ""
            rows.append(f"`ch{ch:<3} {bar} {pct:>4}{cnt_s}{tag}`")

        return "\n".join(rows)

    # ──────────────────────────────────────────────────────
    @staticmethod
    def get_gateway_ip() -> str:
        try:
            if platform.system() == "Windows":
                out = subprocess.run(
                    ["ipconfig"], capture_output=True,
                    encoding="cp866", errors="ignore", timeout=5).stdout
                for line in out.splitlines():
                    if re.search(
                            r"Default Gateway|Основний шлюз"
                            r"|Основной шлюз|Шлюз по умолчанию",
                            line, re.I):
                        ip = line.split(":")[-1].strip()
                        if re.match(r"\d+\.\d+\.\d+\.\d+", ip):
                            return ip
            else:
                out = subprocess.run(
                    ["ip", "route"], capture_output=True,
                    text=True, timeout=5).stdout
                for line in out.splitlines():
                    if line.startswith("default"):
                        return line.split()[2]
        except Exception:
            pass
        return "192.168.10.1"

    @staticmethod
    def channel_switch_url(gateway_ip: str, router_key: str = "generic") -> str:
        path = "/"
        for key, _, p in ROUTER_PROFILES:
            if key == router_key:
                path = p
                break
        return f"http://{gateway_ip}{path}"

    # ══════════════════════════════════════════════════════
    # WINDOWS SCANNER  (WlanAPI → netsh fallback)
    # ══════════════════════════════════════════════════════

    def _scan_windows(self) -> list[WifiNetwork]:
        nets = self._scan_wlanapi()
        if nets:
            print(f"[WifiEngine] WlanAPI → {len(nets)} мереж")
            return nets

        print("[WifiEngine] WlanAPI не спрацював — пробую netsh...")
        raw = self._run_netsh_robust()
        if not raw:
            print("[WifiEngine] ❌ netsh нічого не повернув")
            return []
        nets = self._parse_netsh(raw)
        if not nets:
            nets = self._fallback_parser(raw)
        print(f"[WifiEngine] netsh → {len(nets)} мереж")
        return nets

    @staticmethod
    def _scan_wlanapi() -> list[WifiNetwork]:
        try:
            import ctypes
            import ctypes.wintypes as wt
            import time

            wlan = ctypes.windll.wlanapi

            WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES      = 0x00000001
            WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES = 0x00000002
            DOT11_BSS_TYPE_ANY = 3

            class GUID(ctypes.Structure):
                _fields_ = [
                    ("Data1", wt.DWORD),("Data2", wt.WORD),
                    ("Data3", wt.WORD),("Data4", ctypes.c_ubyte * 8),
                ]

            class WLAN_INTERFACE_INFO(ctypes.Structure):
                _fields_ = [
                    ("InterfaceGuid", GUID),
                    ("strInterfaceDescription", ctypes.c_wchar * 256),
                    ("isState", ctypes.c_uint),
                ]

            class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
                _fields_ = [
                    ("dwNumberOfItems", wt.DWORD),("dwIndex", wt.DWORD),
                    ("InterfaceInfo", WLAN_INTERFACE_INFO * 64),
                ]

            class WLAN_AVAILABLE_NETWORK(ctypes.Structure):
                _fields_ = [
                    ("strProfileName",          ctypes.c_wchar * 256),
                    ("dot11Ssid_uSSIDLength",   wt.DWORD),
                    ("dot11Ssid_ucSSID",        ctypes.c_ubyte * 32),
                    ("dot11BssType",            ctypes.c_uint),
                    ("uNumberOfBssids",         wt.DWORD),
                    ("bNetworkConnectable",     wt.BOOL),
                    ("wlanNotConnectableReason",wt.DWORD),
                    ("uNumberOfPhyTypes",       wt.DWORD),
                    ("dot11PhyTypes",           wt.DWORD * 8),
                    ("bMorePhyTypes",           wt.BOOL),
                    ("wlanSignalQuality",       wt.DWORD),
                    ("bSecurityEnabled",        wt.BOOL),
                    ("dot11DefaultAuthAlgorithm", ctypes.c_uint),
                    ("dot11DefaultCipherAlgorithm", ctypes.c_uint),
                    ("dwFlags",                 wt.DWORD),
                    ("dwReserved",              wt.DWORD),
                ]

            class WLAN_AVAILABLE_NETWORK_LIST(ctypes.Structure):
                _fields_ = [
                    ("dwNumberOfItems", wt.DWORD),("dwIndex", wt.DWORD),
                    ("Network", WLAN_AVAILABLE_NETWORK * 512),
                ]

            class WLAN_BSS_ENTRY(ctypes.Structure):
                _fields_ = [
                    ("dot11Ssid_uSSIDLength",   wt.DWORD),
                    ("dot11Ssid_ucSSID",        ctypes.c_ubyte * 32),
                    ("uPhyId",                  wt.DWORD),
                    ("dot11Bssid",              ctypes.c_ubyte * 6),
                    ("dot11BssType",            ctypes.c_uint),
                    ("dot11BssPhyType",         ctypes.c_uint),
                    ("lRssi",                   ctypes.c_long),
                    ("uLinkQuality",            wt.DWORD),
                    ("bInRegDomain",            wt.BOOL),
                    ("usBeaconPeriod",          wt.WORD),
                    ("ullTimestamp",            ctypes.c_ulonglong),
                    ("ullHostTimestamp",        ctypes.c_ulonglong),
                    ("usCapabilityInformation", wt.WORD),
                    ("ulChCenterFrequency",     wt.DWORD),
                    ("wlanRateSet_uRateSetLength", wt.DWORD),
                    ("wlanRateSet_usRateSet",   wt.WORD * 126),
                    ("uIeOffset",               wt.DWORD),
                    ("uIeSize",                 wt.DWORD),
                ]

            class WLAN_BSS_LIST(ctypes.Structure):
                _fields_ = [
                    ("dwTotalSize",     wt.DWORD),
                    ("dwNumberOfItems", wt.DWORD),
                    ("wlanBssEntries",  WLAN_BSS_ENTRY * 512),
                ]

            handle      = wt.HANDLE()
            neg_version = wt.DWORD()
            ret = wlan.WlanOpenHandle(2, None, ctypes.byref(neg_version),
                                      ctypes.byref(handle))
            if ret != 0:
                return []

            iface_list_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            ret = wlan.WlanEnumInterfaces(handle, None,
                                          ctypes.byref(iface_list_ptr))
            if ret != 0 or not iface_list_ptr:
                wlan.WlanCloseHandle(handle, None)
                return []

            iface_list = iface_list_ptr.contents
            if iface_list.dwNumberOfItems == 0:
                wlan.WlanFreeMemory(iface_list_ptr)
                wlan.WlanCloseHandle(handle, None)
                return []

            networks: list[WifiNetwork] = []

            for i in range(iface_list.dwNumberOfItems):
                iface    = iface_list.InterfaceInfo[i]
                guid_ptr = ctypes.byref(iface.InterfaceGuid)

                wlan.WlanScan(handle, guid_ptr, None, None, None)
                time.sleep(2.0)

                bss_list_ptr = ctypes.POINTER(WLAN_BSS_LIST)()
                ret = wlan.WlanGetNetworkBssList(
                    handle, guid_ptr, None,
                    DOT11_BSS_TYPE_ANY, False, None,
                    ctypes.byref(bss_list_ptr))

                if ret == 0 and bss_list_ptr:
                    bss_list = bss_list_ptr.contents
                    for j in range(bss_list.dwNumberOfItems):
                        e = bss_list.wlanBssEntries[j]
                        ssid_len = min(e.dot11Ssid_uSSIDLength, 32)
                        try:
                            ssid = bytes(e.dot11Ssid_ucSSID[:ssid_len]
                                        ).decode("utf-8", errors="replace").strip("\x00")
                        except Exception:
                            ssid = "Hidden Network"
                        if not ssid:
                            ssid = "Hidden Network"

                        mac   = ":".join(f"{b:02x}" for b in e.dot11Bssid)
                        rssi  = e.lRssi
                        sig   = max(0, min(100, 2 * (rssi + 100)))
                        ch    = _freq_to_channel(e.ulChCenterFrequency)
                        band, width = _channel_to_band(ch, "")
                        if e.ulChCenterFrequency > 5000000:
                            width = 80

                        networks.append(WifiNetwork(
                            ssid=ssid, bssid=mac, channel=ch, signal=sig,
                            auth="WPA2", radio_type="", band=band,
                            channel_width=width,
                            max_rate=_estimate_max_rate("", width),
                            vendor=lookup_vendor(mac)))
                    wlan.WlanFreeMemory(bss_list_ptr)

            auth_map: dict[str, str] = {}
            for i in range(iface_list.dwNumberOfItems):
                iface = iface_list.InterfaceInfo[i]
                net_list_ptr = ctypes.POINTER(WLAN_AVAILABLE_NETWORK_LIST)()
                flags = (WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_ADHOC_PROFILES |
                         WLAN_AVAILABLE_NETWORK_INCLUDE_ALL_MANUAL_HIDDEN_PROFILES)
                ret = wlan.WlanGetAvailableNetworkList(
                    handle, ctypes.byref(iface.InterfaceGuid),
                    flags, None, ctypes.byref(net_list_ptr))
                if ret == 0 and net_list_ptr:
                    nl = net_list_ptr.contents
                    AUTH_MAP = {0:"Open",1:"Open",2:"WPA",3:"WPA",
                                4:"WPA2",5:"WPA2",6:"WPA3",7:"WPA3"}
                    for j in range(nl.dwNumberOfItems):
                        an = nl.Network[j]
                        ssid_len = min(an.dot11Ssid_uSSIDLength, 32)
                        try:
                            ssid = bytes(an.dot11Ssid_ucSSID[:ssid_len]
                                        ).decode("utf-8", errors="replace").strip("\x00")
                        except Exception:
                            ssid = ""
                        if ssid:
                            auth_str = AUTH_MAP.get(an.dot11DefaultAuthAlgorithm, "WPA2")
                            if not an.bSecurityEnabled:
                                auth_str = "Open"
                            auth_map[ssid] = auth_str
                    wlan.WlanFreeMemory(net_list_ptr)

            for n in networks:
                if n.ssid in auth_map:
                    n.auth = auth_map[n.ssid]

            wlan.WlanFreeMemory(iface_list_ptr)
            wlan.WlanCloseHandle(handle, None)

            seen: set[str] = set()
            unique = []
            for n in networks:
                if n.bssid not in seen:
                    seen.add(n.bssid)
                    unique.append(n)
            return unique

        except Exception as ex:
            print(f"[WlanAPI] exception: {ex}")
            return []

    @staticmethod
    def _run_netsh_robust() -> str:
        cmd = ["netsh", "wlan", "show", "networks", "mode=bssid"]
        for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
            try:
                result = subprocess.run(
                    cmd, capture_output=True,
                    timeout=15, errors="ignore", encoding=enc)
                out = result.stdout
                if "SSID" in out or "BSSID" in out:
                    return out
            except Exception as e:
                print(f"[WifiEngine] netsh enc={enc} err: {e}")
        return ""

    def _parse_netsh(self, output: str) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []

        RE_SSID   = re.compile(r"^SSID\s+\d+\s*:\s*(.*)$", re.I)
        RE_BSSID  = re.compile(
            r"^\s*BSSID\s+\d+\s*:\s*"
            r"((?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2})")
        RE_SIGNAL = re.compile(r":\s*(\d{1,3})\s*%")

        KW_AUTH   = ("authentication", "аутентифікація", "проверка подлинности",
                     "перевірка справжності", "authentification", "uwierzytelnianie")
        KW_SIGNAL = ("signal", "сигнал", "intensité")
        KW_CHAN   = ("channel", "канал", "kanal")
        KW_RADIO  = ("radio type", "тип радіо", "тип радио",
                     "тип радіомережі", "тип радиосети",
                     "type radio", "funktyp", "tipo de radio")
        KW_WIDTH  = ("channel width", "ширина каналу", "ширина канала",
                     "largeur du canal", "kanalbreite")
        KW_VENDOR = ("manufacturer", "виробник", "производитель", "fabricant")

        cur_ssid  = None
        cur_auth  = "WPA2"
        cur_mac   = ""
        cur_sig   = 0
        cur_ch    = 0
        cur_radio = ""
        cur_width = 0
        cur_manuf = ""
        in_bssid  = False

        def flush_bssid():
            if not cur_ssid or not cur_mac:
                return
            band, inferred_w = _channel_to_band(cur_ch, cur_radio)
            width  = cur_width if cur_width > 0 else inferred_w
            vendor = cur_manuf if cur_manuf else lookup_vendor(cur_mac)
            networks.append(WifiNetwork(
                ssid=cur_ssid, bssid=cur_mac, channel=cur_ch,
                signal=cur_sig, auth=cur_auth, radio_type=cur_radio,
                band=band, channel_width=width,
                max_rate=_estimate_max_rate(cur_radio, width),
                vendor=vendor))

        for raw_line in output.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            m = RE_SSID.match(line)
            if m and "BSSID" not in line.upper():
                if in_bssid:
                    flush_bssid()
                cur_ssid  = m.group(1).strip() or "Hidden Network"
                cur_auth  = "WPA2"
                cur_mac   = ""
                cur_sig   = 0
                cur_ch    = 0
                cur_radio = ""
                cur_width = 0
                cur_manuf = ""
                in_bssid  = False
                continue

            m = RE_BSSID.match(line)
            if m:
                if in_bssid:
                    flush_bssid()
                cur_mac   = m.group(1).strip()
                cur_sig   = 0
                cur_ch    = 0
                cur_radio = ""
                cur_width = 0
                cur_manuf = ""
                in_bssid  = True
                continue

            line_low = line.lower()

            if any(kw in line_low for kw in KW_AUTH):
                val = line.split(":", 1)[-1].strip()
                if val:
                    cur_auth = val
                continue

            if in_bssid and any(kw in line_low for kw in KW_SIGNAL):
                m = RE_SIGNAL.search(line)
                if m:
                    try:
                        cur_sig = min(100, max(0, int(m.group(1))))
                    except ValueError:
                        pass
                continue

            if in_bssid and any(kw in line_low for kw in KW_CHAN):
                val = line.split(":", 1)[-1].strip()
                try:
                    cur_ch = int(re.split(r"[+,\s]", val)[0])
                except (ValueError, IndexError):
                    pass
                continue

            if in_bssid and any(kw in line_low for kw in KW_RADIO):
                cur_radio = line.split(":", 1)[-1].strip()
                continue

            if in_bssid and any(kw in line_low for kw in KW_WIDTH):
                m_w = re.search(r"(\d+)", line.split(":", 1)[-1])
                if m_w:
                    try:
                        w = int(m_w.group(1))
                        if w in (20, 40, 80, 160):
                            cur_width = w
                    except ValueError:
                        pass
                continue

            if in_bssid and any(kw in line_low for kw in KW_VENDOR):
                val = line.split(":", 1)[-1].strip()
                if val and val not in ("—", "-", ""):
                    cur_manuf = val
                continue

        if in_bssid:
            flush_bssid()

        return networks

    def _fallback_parser(self, output: str) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        cur: dict = {}

        def save():
            if cur.get("ssid") and cur.get("bssid"):
                ch    = cur.get("channel", 0)
                radio = cur.get("radio_type", "")
                band, inferred_w = _channel_to_band(ch, radio)
                width  = cur.get("channel_width", 0) or inferred_w
                mac    = cur.get("bssid", "")
                vendor = cur.get("vendor_override", "") or lookup_vendor(mac)
                networks.append(WifiNetwork(
                    ssid=cur["ssid"], bssid=mac, channel=ch,
                    signal=cur.get("signal", 0), auth=cur.get("auth", "WPA2"),
                    radio_type=radio, band=band, channel_width=width,
                    max_rate=_estimate_max_rate(radio, width),
                    vendor=vendor))

        for raw in output.splitlines():
            line = raw.strip()
            if not line or ":" not in line:
                continue

            m = re.match(r"^SSID\s+\d+\s*:\s*(.*)$", line, re.I)
            if m and "BSSID" not in line.upper():
                save()
                cur = {"ssid": m.group(1).strip() or "Hidden Network",
                       "bssid": "", "channel": 0, "signal": 0,
                       "auth": "WPA2", "radio_type": ""}
                continue

            m = re.match(
                r"^BSSID\s+\d+\s*:\s*"
                r"((?:[0-9a-f]{2}[:\-]){5}[0-9a-f]{2})", line, re.I)
            if m:
                save()
                cur["bssid"]     = m.group(1).strip()
                cur["signal"]    = 0
                cur["channel"]   = 0
                cur["radio_type"]= ""
                continue

            key, _, val = line.partition(":")
            key = key.strip().lower()
            val = val.strip()

            if re.search(r"signal|сигнал", key, re.I):
                try:
                    cur["signal"] = int(val.replace("%", "").strip())
                except ValueError:
                    pass
            elif re.search(r"channel|канал", key, re.I):
                try:
                    cur["channel"] = int(re.split(r"[+,\s]", val)[0])
                except ValueError:
                    pass
            elif re.search(r"auth|аутент|провер|перевір", key, re.I):
                cur["auth"] = val
            elif re.search(r"radio|радіо|радио|funktyp", key, re.I):
                cur["radio_type"] = val
            elif re.search(r"channel.?width|ширина.?канал|largeur|kanalbreite", key, re.I):
                m_w = re.search(r"(\d+)", val)
                if m_w:
                    try:
                        w = int(m_w.group(1))
                        if w in (20, 40, 80, 160):
                            cur["channel_width"] = w
                    except ValueError:
                        pass
            elif re.search(r"manufacturer|виробник|производитель|fabricant", key, re.I):
                if val and val not in ("—", "-"):
                    cur["vendor_override"] = val

        save()
        return networks

    # ══════════════════════════════════════════════════════
    # LINUX SCANNER
    # ══════════════════════════════════════════════════════

    def _scan_linux(self) -> list[WifiNetwork]:
        networks: list[WifiNetwork] = []
        try:
            r = subprocess.run(
                ["iwlist", "scan"], capture_output=True,
                text=True, timeout=15)
            cur: dict = {}
            for line in r.stdout.splitlines():
                line = line.strip()
                m = re.search(r"Address:\s*([\w:]+)", line)
                if m:
                    if cur.get("ssid"):
                        networks.append(_dict_to_network(cur))
                    cur = {"bssid": m.group(1), "ssid": "",
                           "channel": 0, "signal": 0,
                           "auth": "WPA2", "radio_type": ""}
                m = re.search(r'ESSID:"(.*?)"', line)
                if m:
                    cur["ssid"] = m.group(1) or "Hidden Network"
                m = re.search(r"Channel:(\d+)", line)
                if m:
                    cur["channel"] = int(m.group(1))
                m = re.search(r"Signal level[=:](-?\d+)", line)
                if m:
                    raw = int(m.group(1))
                    cur["signal"] = (max(0, min(100, (raw + 100) * 2))
                                     if raw < 0 else raw)
                if "WPA2" in line:
                    cur["auth"] = "WPA2"
                elif "WPA" in line:
                    cur["auth"] = "WPA"
                elif "open" in line.lower():
                    cur["auth"] = "Open"
            if cur.get("ssid"):
                networks.append(_dict_to_network(cur))
        except Exception as e:
            print(f"[WifiEngine] linux error: {e}")
        return networks

    # ──────────────────────────────────────────────────────
    def _get_connected_info(self) -> tuple[str, str, str, int]:
        """
        Повертає (ssid, bssid) підключеної Wi-Fi мережі.
        Працює коли Ethernet підключений одночасно з Wi-Fi.

        Порядок пріоритетів:
          1. netsh wlan show interfaces  — основне джерело
          2. WlanAPI через ctypes         — якщо netsh пустий
        Визначає і SSID, і BSSID точки доступу — це дозволяє
        матчити мережу навіть якщо SSID повернувся в іншому форматі.
        """
        if platform.system() == "Windows":
            return self._connected_windows_full()
        return self._connected_linux(), "", "", 0

    def _get_connected_ssid(self) -> str:
        """Зворотна сумісність — повертає тільки SSID."""
        ssid, _, _, _ = self._get_connected_info()
        return ssid

    @staticmethod
    def _connected_windows_full() -> tuple[str, str]:
        """
        Парсить netsh wlan show interfaces і повертає (ssid, bssid).
        Працює коректно навіть коли Ethernet підключений одночасно —
        netsh wlan показує Wi-Fi інтерфейси незалежно від маршруту.
        """
        ssid  = ""
        bssid = ""
        # MAC формат: aa:bb:cc:dd:ee:ff або aa-bb-cc-dd-ee-ff
        RE_MAC = re.compile(
            r"^(?:[0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}$")

        for enc in ("utf-8", "cp1251", "cp866"):
            try:
                out = subprocess.run(
                    ["netsh", "wlan", "show", "interfaces"],
                    capture_output=True, timeout=5,
                    errors="ignore", encoding=enc).stdout

                if not out.strip():
                    continue

                print(f"[WifiEngine] netsh output ({len(out)} chars, enc={enc})")

                rx_rate    = 0.0
                radio_type = ""

                for line in out.splitlines():
                    stripped = line.strip()
                    low      = stripped.lower()

                    # SSID (не BSSID)
                    if re.match(r"^ssid\s*:", low) and "bssid" not in low:
                        val = stripped.split(":", 1)[1].strip().rstrip("\r\n ")
                        if val:
                            ssid = val

                    # BSSID
                    elif re.match(r"^bssid\s*:", low):
                        m = re.search(
                            r":\s*([0-9a-fA-F]{2}(?:[:\-][0-9a-fA-F]{2}){5})",
                            stripped, re.I)
                        raw = m.group(1).replace("-", ":").lower() if m else ""
                        if RE_MAC.match(raw):
                            bssid = raw.lower()

                    # Radio type (стандарт) — для визначення ширини каналу
                    elif re.search(
                            r"radio type|тип радіо|тип радио|"
                            r"тип радіомережі|тип радиосети|funktyp", low):
                        radio_type = stripped.split(":", 1)[-1].strip()

                    # Receive rate — ключ для визначення ширини каналу.
                    # 802.11n 20MHz → ≤144 Mbps, 40MHz → ≤300 Mbps
                    # 802.11ac 80MHz → 433-867 Mbps
                    elif re.search(
                            r"receive rate|швидкість прийому|"
                            r"скорость приема|vitesse de réception", low):
                        m_r = re.search(r"[\d.]+", stripped.split(":", 1)[-1])
                        if m_r:
                            try:
                                rx_rate = float(m_r.group())
                            except ValueError:
                                pass

                if ssid:
                    width = _infer_connected_width(radio_type, rx_rate)
                    print(f"[WifiEngine] connected: SSID='{ssid}' BSSID='{bssid}' "
                          f"radio='{radio_type}' rx={rx_rate}Mbps → {width}MHz")
                    return ssid, bssid, radio_type, width

            except Exception as e:
                print(f"[WifiEngine] _connected_windows_full enc={enc}: {e}")

        # Fallback: WlanAPI
        try:
            ssid, bssid, rt, w = WifiEngine._wlanapi_get_connected()
            if ssid:
                print(f"[WifiEngine] connected via WlanAPI: '{ssid}' / '{bssid}'")
                return ssid, bssid, rt, w
        except Exception:
            pass

        return "", "", "", 0

    @staticmethod
    def _wlanapi_get_connected() -> tuple[str, str, str, int]:
        """Отримує SSID/BSSID підключеної мережі напряму через WlanAPI."""
        try:
            import ctypes
            import ctypes.wintypes as wt
            wlan = ctypes.windll.wlanapi

            class GUID(ctypes.Structure):
                _fields_ = [("Data1", wt.DWORD), ("Data2", wt.WORD),
                             ("Data3", wt.WORD), ("Data4", ctypes.c_ubyte * 8)]

            class WLAN_INTERFACE_INFO(ctypes.Structure):
                _fields_ = [("InterfaceGuid", GUID),
                             ("strInterfaceDescription", ctypes.c_wchar * 256),
                             ("isState", ctypes.c_uint)]

            class WLAN_INTERFACE_INFO_LIST(ctypes.Structure):
                _fields_ = [("dwNumberOfItems", wt.DWORD),
                             ("dwIndex",         wt.DWORD),
                             ("InterfaceInfo",   WLAN_INTERFACE_INFO * 64)]

            handle = wt.HANDLE()
            ver    = wt.DWORD()
            if wlan.WlanOpenHandle(2, None, ctypes.byref(ver),
                                   ctypes.byref(handle)) != 0:
                return "", ""

            ilist_ptr = ctypes.POINTER(WLAN_INTERFACE_INFO_LIST)()
            wlan.WlanEnumInterfaces(handle, None, ctypes.byref(ilist_ptr))
            ilist = ilist_ptr.contents

            for i in range(ilist.dwNumberOfItems):
                iface = ilist.InterfaceInfo[i]
                # isState == 1 → wlan_interface_state_connected
                if iface.isState != 1:
                    continue

                # WlanQueryInterface → wlan_intf_opcode_current_connection
                data_ptr  = ctypes.c_void_p()
                data_size = wt.DWORD()
                op_code   = ctypes.c_uint(7)  # wlan_intf_opcode_current_connection
                ret = wlan.WlanQueryInterface(
                    handle, ctypes.byref(iface.InterfaceGuid),
                    op_code, None,
                    ctypes.byref(data_size),
                    ctypes.byref(data_ptr), None)

                if ret == 0 and data_ptr.value:
                    # Перші 4 байти — uSSIDLength, наступні 32 — ucSSID
                    buf = (ctypes.c_ubyte * data_size.value).from_address(
                        data_ptr.value)
                    # Структура WLAN_CONNECTION_ATTRIBUTES починається з
                    # isState(4) + wlanAssocAttrib де перше поле — dot11Ssid
                    # Offset: isState=4, dot11BssType=4 → ssid_len @ offset 8
                    import struct
                    ssid_len = struct.unpack_from("<I", bytes(buf), 8)[0]
                    ssid_len = min(ssid_len, 32)
                    ssid_bytes = bytes(buf[12:12 + ssid_len])
                    ssid = ssid_bytes.decode("utf-8", errors="replace").strip("")

                    # BSSID @ offset 12+32=44 (після dot11Ssid)
                    bssid_bytes = bytes(buf[44:50])
                    bssid = ":".join(f"{b:02x}" for b in bssid_bytes)

                    wlan.WlanFreeMemory(data_ptr)
                    wlan.WlanFreeMemory(ilist_ptr)
                    wlan.WlanCloseHandle(handle, None)
                    return ssid, bssid, "", 0

            wlan.WlanFreeMemory(ilist_ptr)
            wlan.WlanCloseHandle(handle, None)
        except Exception:
            pass
        return "", ""

    @staticmethod
    def _connected_linux() -> str:
        try:
            out = subprocess.run(
                ["iwgetid", "-r"], capture_output=True,
                text=True, timeout=5).stdout
            return out.strip()
        except Exception:
            return ""

    def get_connected_network(
            self, networks: list[WifiNetwork]) -> Optional[WifiNetwork]:
        return next((n for n in networks if n.is_mine), None)


# ══════════════════════════════════════════════════════════
#  MODULE HELPERS
# ══════════════════════════════════════════════════════════

def _infer_connected_width(radio_type: str, rx_rate_mbps: float) -> int:
    """
    Визначає реальну ширину каналу підключеної мережі за типом радіо
    і швидкістю прийому (Receive rate з netsh wlan show interfaces).

      802.11n  20MHz → ≤144 Mbps   →  20
      802.11n  40MHz → 150–300 Mbps →  40
      802.11ac 80MHz → 433–867 Mbps →  80
      Wi-Fi 6  80MHz → 600–1201 Mbps → 80
    """
    rt = radio_type.lower()

    if "ax" in rt or "wi-fi 6" in rt or "802.11ax" in rt:
        return 160 if rx_rate_mbps > 1200 else 80

    if "ac" in rt or "802.11ac" in rt:
        return 160 if rx_rate_mbps > 900 else 80

    if "802.11n" in rt or ("n" in rt and ("ht" in rt or rx_rate_mbps > 0)):
        return 40 if rx_rate_mbps > 150 else 20

    # Невідомий тип — тільки по rx_rate
    if rx_rate_mbps > 300:
        return 80
    if rx_rate_mbps > 150:
        return 40
    return 20


def _channel_to_band(ch: int, radio_type: str = "") -> tuple[str, int]:
    band = "5 GHz" if ch > 14 else "2.4 GHz"
    rt   = radio_type.lower()
    if "160" in rt:
        width = 160
    elif "80" in rt and "80+80" not in rt:
        width = 80
    elif "40" in rt or "ht40" in rt:
        width = 40
    elif "802.11ax" in rt or "wi-fi 6" in rt:
        width = 80
    elif "802.11ac" in rt:
        width = 80
    else:
        width = 20
    return band, width


def _estimate_max_rate(radio_type: str, width: int) -> str:
    rt = radio_type.lower()
    if "ax" in rt or "wi-fi 6" in rt:
        return {160: "2400 Mbps", 80: "1200 Mbps"}.get(width, "600 Mbps")
    if "ac" in rt:
        return {160: "1733 Mbps", 80: "867 Mbps"}.get(width, "433 Mbps")
    if "802.11n" in rt or "ht" in rt:
        return "300 Mbps" if width >= 40 else "150 Mbps"
    if "802.11g" in rt:
        return "54 Mbps"
    if "802.11b" in rt:
        return "11 Mbps"
    return "—"


def _dict_to_network(d: dict) -> WifiNetwork:
    ch    = d.get("channel", 0)
    radio = d.get("radio_type", "")
    band, width = _channel_to_band(ch, radio)
    mac   = d.get("bssid", "")
    return WifiNetwork(
        ssid=d.get("ssid", "Hidden"),
        bssid=mac, channel=ch,
        signal=d.get("signal", 0),
        auth=d.get("auth", "WPA2"),
        radio_type=radio, band=band,
        channel_width=width,
        max_rate=_estimate_max_rate(radio, width),
        vendor=lookup_vendor(mac))


def _freq_to_channel(freq_khz: int) -> int:
    freq_mhz = freq_khz // 1000
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if freq_mhz == 2484:
        return 14
    if 5000 <= freq_mhz <= 5900:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:
        return (freq_mhz - 5950) // 5
    return 0
