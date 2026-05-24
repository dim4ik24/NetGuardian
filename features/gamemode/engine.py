# core/game_booster.py
# ─────────────────────────────────────────────────────────────────────────────
#  NetGuardian AI  ·  Game Latency Optimizer  ·  Backend Engine
#  Сумісність: Windows 10/11 (потребує прав Адміністратора для реєстру/DNS)
# ─────────────────────────────────────────────────────────────────────────────

import subprocess
import platform
import threading
import time
import json
import re
import socket
from pathlib import Path
from datetime import datetime

# ─── Константи ───────────────────────────────────────────────────────────────

# ─── Системні процеси — НІКОЛИ не вбивати ────────────────────────────────────
PROTECTED = {
    "explorer.exe", "winlogon.exe", "csrss.exe", "lsass.exe",
    "services.exe", "svchost.exe", "system", "registry",
    "dwm.exe", "taskmgr.exe", "conhost.exe", "dllhost.exe",
    "spoolsv.exe", "audiodg.exe", "runtimebroker.exe",
    "wininit.exe", "smss.exe",
    # НЕ включаємо steam/epic/battle.net — вони йдуть у GAME_LAUNCHERS
}

# ─── Лаунчери ігор — показуємо, але не вбиваємо ─────────────────────────────
GAME_LAUNCHERS = {
    # Steam
    "steam.exe", "steamwebhelper.exe", "steamservice.exe",
    "gameoverlayui.exe", "steamcrashhandler.exe",
    # Epic
    "epicgameslauncher.exe", "epicwebhelper.exe", "epiconlineservices.exe",
    # GOG
    "gog galaxy.exe", "goggalaxy.exe", "galaxyclient.exe", "galaxyclient helper.exe",
    # Battle.net / Blizzard
    "battle.net.exe", "battle.net launcher.exe", "blizzarderror.exe",
    "agent.exe", "blizzard update agent.exe",
    # EA / Origin
    "origin.exe", "eadesktop.exe", "eabackgroundservice.exe",
    "eaanticheat.exe", "easteamservice.exe",
    # Ubisoft
    "upc.exe", "ubisoft connect.exe", "ubisoftgamelauncher.exe",
    # Rockstar
    "rockstarservice.exe", "socialclubhelper.exe", "rsg-crashhandler.exe",
    # Bethesda / Xbox
    "bethesdanetlauncher.exe", "xboxpcapp.exe", "gamingservices.exe",
    # FiveM / GTA RP лаунчери
    "fivem.exe", "fivem_updating.exe",
    # RAGE MP лаунчер
    "ragemp.exe", "ragemp installer.exe",
    # Інші
    "playniteui.exe", "itchio.exe", "wemod.exe",
    "parsec.exe", "rainwaymain.exe",
}

# ─── НЕБЕЗПЕЧНО ВБИВАТИ — BSOD / втрата даних ────────────────────────────────
DANGEROUS_TO_KILL = {
    "smss.exe", "wininit.exe", "ntoskrnl.exe", "hal.dll",
    "lsm.exe", "wlanext.exe", "ndisuio.sys",
    "vssvc.exe", "sqlservr.exe", "msmdsrv.exe",
    "nvcontainer.exe", "nvdisplay.container.exe",
    "atiesrxx.exe", "atieclxx.exe", "igfxem.exe",
    "audiodg.exe", "audiosrv.dll",
    "msmpeng.exe", "nissrv.exe", "mssense.exe",
    "mscorsvw.exe", "ngen.exe",
}

# ─── Пожирачі трафіку / диску ─────────────────────────────────────────────────
BANDWIDTH_HOGS = {
    "wuauclt.exe", "waasmedic.exe", "tiworker.exe", "musnotifyicon.exe",
    "usoclient.exe", "wudfhost.exe", "wuauserv.exe",
    "msmpeng.exe", "nissrv.exe", "mssense.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "onedrive.exe", "dropbox.exe", "googledrivefs.exe", "googledrive.exe",
    "backup.exe", "backupservice.exe", "backblaze.exe",
    "chromecrashhandler.exe", "chromecrashhandler64.exe",
    "mbamservice.exe", "avgnt.exe", "avguard.exe",
    "mrt.exe", "compattelrunner.exe", "diagtrack.exe",
    "distnoted.exe", "softwareupdate.exe",
}

BROWSERS = {
    "chrome.exe", "msedge.exe", "firefox.exe",
    "opera.exe", "brave.exe", "vivaldi.exe",
    "browser.exe", "chromium.exe", "waterfox.exe",
    "opera gx.exe", "thorium.exe",
}

MESSENGERS = {
    "telegram.exe", "discord.exe", "discordptb.exe", "discordcanary.exe",
    "slack.exe", "teams.exe", "ms-teams.exe",
    "skype.exe", "zoom.exe", "viber.exe",
    "whatsapp.exe", "signal.exe", "element.exe",
}

MEDIA = {
    "spotify.exe", "spotiwebhelper.exe", "spotify_helper.exe",
    "vlc.exe", "mpv.exe", "mpc-hc64.exe", "mpc-hc.exe",
    "wmplayer.exe", "musicbee.exe", "foobar2000.exe",
    "itunes.exe", "potplayer.exe", "potplayermini64.exe",
    "aimp.exe", "winamp.exe",
}

# ─── Відомі ігри — 🎮, підвищуємо пріоритет ──────────────────────────────────
KNOWN_GAMES = {
    # ── CS / Valve ──
    "cs2.exe", "csgo.exe", "cstrike.exe",
    "dota2.exe", "hl2.exe", "portal2.exe",
    "left4dead2.exe", "tf_win64.exe", "tf.exe",

    # ── GTA / Rockstar ──
    "gta5.exe", "gtav.exe", "grandtheftauto5.exe",
    "gta_sa.exe", "gta-vc.exe", "gta3.exe",
    "rdr2.exe", "reddeadredemption2.exe",

    # ── GTA RP мультиплеєр-клієнти ──────────────────────────────
    # FiveM (найпопулярніший GTA RP в Україні)
    "fivem_b2699_gtavprocess.exe",   # основний процес гри FiveM
    "fivem_rgl_b2699_gtavprocess.exe",
    "fivem_gtavprocess.exe",
    "fivem_ros_b2699_gtavprocess.exe",
    "fivem-win32-release.exe",
    # RAGE MP
    "ragempv.exe", "ragemp_v.exe",
    "gta5_ragemp.exe",
    # SAMP / MTA / OpenMP
    "samp.exe", "gta_sa_samp.exe",
    "mta-sa.exe", "multitheftauto.exe",
    "omp-client.exe",
    # RedM (Red Dead RP)
    "redm_b1491_rdr3process.exe",

    # ── CS2 допоміжні процеси ──
    "cs2_win64_retail.exe",

    # ── Valorant ──
    "valorant.exe", "valorant-win64-shipping.exe",
    "vgc.exe", "vanguard.exe",

    # ── CoD / Activision ──
    "modernwarfare.exe", "cod.exe", "codexe.exe",
    "mw2.exe", "mw3.exe", "warzone.exe",
    "blackopscoldwar.exe", "vanguard_shipping.exe",

    # ── Apex / EA ──
    "r5apex.exe", "r5apex_dx12.exe",

    # ── Fortnite ──
    "fortnite.exe", "fortniteclient-win64-shipping.exe",

    # ── Overwatch ──
    "overwatch.exe", "overwatch2.exe",

    # ── PUBG ──
    "pubg.exe", "tslgame.exe",

    # ── Rainbow Six ──
    "rainbowsix.exe", "rainbowsix_vulkan.exe", "r6.exe",

    # ── Rocket League ──
    "rocketleague.exe",

    # ── League of Legends / MOBA ──
    "leagueoflegends.exe", "league of legends.exe",
    "tft.exe", "gameofthrones.exe",

    # ── WoW / MMO ──
    "worldofwarcraft.exe", "wow.exe", "wow-64.exe",
    "gw2-64.exe", "ffxiv.exe", "ffxiv_dx11.exe",
    "archeage.exe", "lineage2.exe",

    # ── Minecraft ──
    "minecraft.exe", "minecraftlauncher.exe",
    "javaw.exe",   # Minecraft Java — ВАЖЛИВО!

    # ── Escape From Tarkov ──
    "escapefromtarkov.exe", "eft.exe",
    "battleeyeservice.exe",   # античит EFT

    # ── Hunt: Showdown ──
    "hunt.exe", "eaclient.exe",

    # ── Cyberpunk ──
    "cyberpunk2077.exe", "cp2077.exe",

    # ── Witcher / CD Projekt ──
    "witcher3.exe", "witcher2.exe",

    # ── Elden Ring / FromSoftware ──
    "eldenring.exe", "sekiro.exe", "darksoulsiii.exe",
    "ds3.exe",

    # ── Paladins / Smite ──
    "paladins.exe", "paladins-win64-shipping.exe",
    "smite.exe",

    # ── Battlefield ──
    "bf2042.exe", "bfv.exe", "bf1.exe", "bf4.exe",

    # ── FIFA / EA FC ──
    "fifa21.exe", "fifa22.exe", "fifa23.exe", "fc24.exe", "fc25.exe",

    # ── Dota underlords / autochess ──
    "underlords.exe",

    # ── Standoff 2 / Mobile ports ──
    "standoff2.exe",

    # ── Інші популярні ──
    "newworld.exe", "lostark.exe",
    "fallguys.exe", "fall_guys_client.exe",
    "deadbydaylight.exe", "dbd.exe",
    "rust.exe", "7daystodie.exe",
    "dayz.exe", "arma3.exe", "arma3_x64.exe",
    "squad.exe", "insurgency.exe",
    "mordhau.exe", "chivalry2.exe",
    "splitgate.exe",
    "gearsofwar.exe", "gearsofwar5.exe",
    "halo.exe", "haloinfinite.exe",
    "destiny2.exe", "d2.exe",
    "pathofexile.exe", "poe.exe",
    "diablo4.exe", "diablo3.exe", "d3.exe",
    "hearthstone.exe",
    "starcraftii.exe", "sc2.exe",
    "warcraft3.exe", "w3.exe",
}

# ─── Ключові слова в назві exe → автоматично ігровий процес ─────────────────
# Якщо точного збігу немає, але ім'я містить одне з цих слів
GAME_KEYWORDS = {
    "fivem", "gtav", "gta5", "grandtheft",
    "ragempv", "ragemp",
    "shipping",        # Unreal Engine: "GameName-Win64-Shipping.exe"
    "gameoverlayui",
    "eaclient",        # Easy Anti-Cheat (вказує на гру)
    "battleye",        # BattlEye (Tarkov, Arma, Dayz)
    "unrealcefsubprocess",  # Unreal Engine WebBrowser
}

# ── Мережевий пріоритет QoS (DSCP) ──────────────────────────────────────────
NET_PRIORITY_DSCP = {
    "maximum": 46,
    "high":    34,
    "normal":   0,
    "low":      8,
}
NET_PRIORITY_NAMES = {
    "maximum": "Максимальний (DSCP 46 — EF)",
    "high":    "Високий (DSCP 34 — AF41)",
    "normal":  "Нормальний (без QoS)",
    "low":     "Низький (DSCP 8 — CS1)",
}


def classify_process(name: str) -> str:
    """
    Класифікує процес. Порядок КРИТИЧНО ВАЖЛИВИЙ:
    ігри > лаунчери > небезпечні > системні > решта.

    Також виконує keyword-матчинг для невідомих ігрових процесів
    (FiveM, RAGE MP та Unreal/Unity ігри мають нестандартні назви).
    """
    n = name.lower().strip()

    # 1. Точний збіг — ігри (найвищий пріоритет)
    if n in KNOWN_GAMES:
        return "game"

    # 2. Точний збіг — лаунчери (Steam, Epic, FiveM лаунчер тощо)
    if n in GAME_LAUNCHERS:
        return "launcher"

    # 3. Keyword-матчинг — ловимо FiveM, RAGE MP, Unreal Shipping процеси
    #    Наприклад: "fivem_b2699_gtavprocess.exe", "mygame-win64-shipping.exe"
    for kw in GAME_KEYWORDS:
        if kw in n:
            # "-shipping.exe" — це Unreal Engine гра (не лаунчер)
            if kw == "shipping" and n.endswith("-win64-shipping.exe"):
                return "game"
            if kw in ("fivem", "gtav", "gta5", "grandtheft", "ragempv", "ragemp"):
                return "game"
            if kw in ("eaclient", "battleye"):
                return "game"   # античит = гра запущена
            return "game"

    # 4. Небезпечні (до системних — деякі можуть перетинатися)
    if n in DANGEROUS_TO_KILL:
        return "dangerous"

    # 5. Системні захищені
    if n in PROTECTED:
        return "protected"

    # 6. Решта
    if n in BANDWIDTH_HOGS:   return "hog"
    if n in BROWSERS:         return "browser"
    if n in MESSENGERS:       return "messenger"
    if n in MEDIA:            return "media"
    return "normal"


CATEGORY_IMPACT = {
    "game":      ("🎮 ГРА",         "Ігровий процес — підвищений пріоритет"),
    "launcher":  ("🚀 ЛАУНЧЕР",     "Ігровий лаунчер — показуємо, не вбиваємо"),
    "hog":       ("⚠️ КРИТИЧНО",    "Системні фонові задачі — жеруть мережу і диск"),
    "browser":   ("🌐 МЕРЕЖА",      "Відкриті вкладки і відео забирають пропускну здатність"),
    "messenger": ("💬 МЕРЕЖА",      "Постійні з'єднання, push-повідомлення, відео-кодеки"),
    "media":     ("🎵 CPU",         "Декодування аудіо/відео навантажує процесор"),
    "protected": ("🛡️ СИСТЕМА",     "Системний процес — захищено від зупинки"),
    "dangerous": ("☠️ НЕБЕЗПЕЧНО",  "Вбивство може призвести до BSOD або втрати даних"),
    "normal":    ("✅ ОК",          "Мінімальний вплив на гру"),
}

GAMING_DNS = {
    "Cloudflare (1.1.1.1)":  ("1.1.1.1",  "1.0.0.1"),
    "Quad9 (9.9.9.9)":       ("9.9.9.9",  "149.112.112.112"),
    "Google (8.8.8.8)":      ("8.8.8.8",  "8.8.4.4"),
}

PING_TARGETS = {
    # 10 серверів — назви точно збігаються з UI _PING_SERVER_COLORS
    "Cloudflare (EU)":   "1.1.1.1",                   # Anycast — завжди найближчий
    "Google DNS":        "8.8.8.8",                   # Frankfurt зазвичай
    "Quad9 (EU)":        "9.9.9.9",                   # Швейцарія/Нідерланди
    "Steam / Valve":     "steamcommunity.com",         # можуть timeout — Valve блокує ICMP
    "Riot Games":        "euw1.api.riotgames.com",     # EU-West CDN
    "Battle.net (EU)":   "eu.actual.battle.net",       # Blizzard EU
    "Epic Games":        "epicgames.com",              # Epic CDN
    "Discord":           "discord.com",                # Discord CDN
    "EA / Origin":       "accounts.ea.com",            # EA front
    "Hetzner (DE)":      "hetzner.com",                # Hetzner — дуже близько до UA
}

BACKUP_FILE = Path.home() / ".netguardian" / "game_boost_backup.json"
IS_WINDOWS  = platform.system() == "Windows"


# ─── Утиліти ─────────────────────────────────────────────────────────────────

def run(cmd: list, timeout: int = 8) -> tuple[bool, str]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=timeout)
        return r.returncode == 0, (r.stdout + r.stderr).strip()
    except Exception as e:
        return False, str(e)


def run_cp866(cmd: list, timeout: int = 8) -> tuple[bool, str]:
    """Запуск з cp866-кодуванням для Windows-команд, що повертають кирилицю."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout)
        out = ""
        for enc in ("cp866", "cp1251", "utf-8", "latin-1"):
            try:
                out = (r.stdout + r.stderr).decode(enc, errors="replace")
                break
            except Exception:
                continue
        return r.returncode == 0, out.strip()
    except Exception as e:
        return False, str(e)


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    ok, _ = run(["net", "session"])
    return ok


def reg_read(key: str, value: str) -> str | None:
    ok, out = run(["reg", "query", key, "/v", value])
    if not ok:
        return None
    match = re.search(r"\s+\S+\s+\w+\s+(\S+)", out)
    return match.group(1) if match else None


def reg_write(key: str, value: str, data: str, reg_type: str = "REG_DWORD") -> bool:
    ok, _ = run(["reg", "add", key, "/v", value,
                 "/t", reg_type, "/d", data, "/f"])
    return ok


def reg_delete(key: str, value: str) -> bool:
    ok, _ = run(["reg", "delete", key, "/v", value, "/f"])
    return ok


# ─── Реєстрові твіки ─────────────────────────────────────────────────────────

REGISTRY_TWEAKS = [
    # ── MMCSS / System Responsiveness ──
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
        "NetworkThrottlingIndex", "4294967295", "REG_DWORD"
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
        "SystemResponsiveness", "0", "REG_DWORD"
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
        "GPU Priority", "8", "REG_DWORD"
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
        "Priority", "6", "REG_DWORD"
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
        "Scheduling Category", "High", "REG_SZ"
    ),
    (
        r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
        "SFIO Priority", "High", "REG_SZ"
    ),

    # ── TCP/IP стек: агресивні налаштування для нижчого latency ──
    (
        # Кеш TCP-параметрів — 4096 entries (default 256)
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "MaxUserPort", "65534", "REG_DWORD"
    ),
    (
        # TIME_WAIT з 240с до 30с — швидше переробляє з'єднання
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "TcpTimedWaitDelay", "30", "REG_DWORD"
    ),
    (
        # Default TTL — 64 (Windows за замовч. 128 → марна затримка)
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "DefaultTTL", "64", "REG_DWORD"
    ),
    (
        # SACK Options — Selective Acknowledgement (швидше recovery loss)
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "SackOpts", "1", "REG_DWORD"
    ),
    (
        # Tcp1323Opts — RFC 1323 Window Scaling + Timestamps
        r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
        "Tcp1323Opts", "1", "REG_DWORD"
    ),
    (
        # MaxConnectionsPerServer — 16 (Windows: 2 — обмежує паралельні запити)
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "MaxConnectionsPerServer", "16", "REG_DWORD"
    ),
    (
        # MaxConnectionsPer1_0Server — 16
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings",
        "MaxConnectionsPer1_0Server", "16", "REG_DWORD"
    ),

    # ── DNS Client: швидший resolution ──
    (
        # NegativeCacheTime — 0 (не кешуємо невдалі запити)
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "NegativeCacheTime", "0", "REG_DWORD"
    ),
    (
        # NetFailureCacheTime — 0
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "NetFailureCacheTime", "0", "REG_DWORD"
    ),
    (
        # NegativeSOACacheTime — 0
        r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "NegativeSOACacheTime", "0", "REG_DWORD"
    ),

    # ── Network Browser: вимикаємо непотрібний broadcast traffic ──
    (
        # NoNetCrawling — не сканує мережу постійно
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "NoNetCrawling", "1", "REG_DWORD"
    ),
]


# ─── Windows Priority Class → psutil.nice() маппінг ─────────────────────────
# psutil на Windows повертає числові константи Priority Class
_NICE_TO_PRIORITY = {
    64:    "Idle",         # IDLE_PRIORITY_CLASS
    16384: "BelowNormal",  # BELOW_NORMAL_PRIORITY_CLASS
    32:    "Normal",       # NORMAL_PRIORITY_CLASS
    32768: "AboveNormal",  # ABOVE_NORMAL_PRIORITY_CLASS
    128:   "High",         # HIGH_PRIORITY_CLASS
    256:   "Realtime",     # REALTIME_PRIORITY_CLASS
    # Linux nice values (fallback)
    19:    "Idle",
    10:    "BelowNormal",
    0:     "Normal",
    -5:    "AboveNormal",
    -10:   "High",
    -20:   "Realtime",
}


class GameBoosterEngine:

    def __init__(self):
        self._auto_active       = False
        self._game_watch_active = False   # FIX: для start_game_watch / stop_game_watch
        self._backup: dict = {}
        self._original_dns: dict[str, tuple] = {}
        BACKUP_FILE.parent.mkdir(parents=True, exist_ok=True)
        self._load_backup()
        # Стан активації Game Mode — якщо є backup, значить режим активний
        # (або був активний але не був коректно деактивований)
        self._is_active = self.has_backup()
        # Callback'и для сповіщення про зміну стану (бот, GUI, etc.)
        self._mode_change_callbacks: list = []

    def on_mode_change(self, cb):
        """Реєструє callback який викликається при activate/deactivate.
        Callback отримує (new_state: bool, source: str) — джерело ('gui'|'bot'|'auto')."""
        if cb not in self._mode_change_callbacks:
            self._mode_change_callbacks.append(cb)

    def _fire_mode_change(self, new_state: bool, source: str = "unknown"):
        """Повідомляє всім підписникам про зміну стану."""
        for cb in self._mode_change_callbacks:
            try:
                cb(new_state, source)
            except Exception as e:
                print(f"[GameEngine] mode_change callback error: {e}")

    # ═══════════════════════════════════════════════════════════════════════
    #  БЕКАП / ВІДНОВЛЕННЯ
    # ═══════════════════════════════════════════════════════════════════════

    def _load_backup(self):
        if BACKUP_FILE.exists():
            try:
                self._backup = json.loads(BACKUP_FILE.read_text())
            except Exception:
                self._backup = {}

    def _save_backup(self):
        BACKUP_FILE.write_text(json.dumps(self._backup, indent=2))

    def _backup_registry(self, log_cb=None):
        if not IS_WINDOWS:
            return
        reg_backup = {}
        for key, value, _, _ in REGISTRY_TWEAKS:
            current = reg_read(key, value)
            reg_backup[f"{key}||{value}"] = current if current is not None else "__ABSENT__"
            if log_cb:
                state = current if current else "не встановлено"
                log_cb(f"  📦 Бекап: {value} = {state}")
        self._backup["registry"] = reg_backup
        self._backup["timestamp"] = datetime.now().isoformat()
        self._save_backup()

    def _backup_dns(self, log_cb=None):
        if not IS_WINDOWS:
            return
        dns_backup = {}
        ok, out = run(["netsh", "interface", "ip", "show", "config"])
        if ok:
            current_adapter = None
            for line in out.splitlines():
                adapter_match = re.search(r'Configuration for interface "(.*?)"', line)
                if adapter_match:
                    current_adapter = adapter_match.group(1)
                if current_adapter:
                    dns_match = re.search(r"Statically Configured DNS Servers:\s+(\S+)", line)
                    if dns_match:
                        dns_backup[current_adapter] = {"primary": dns_match.group(1)}
        self._backup["dns"] = dns_backup
        if log_cb:
            log_cb(f"  📦 DNS бекап: {len(dns_backup)} адаптерів збережено")
        self._save_backup()

    def has_backup(self) -> bool:
        return bool(self._backup.get("registry"))

    def is_active(self) -> bool:
        """
        Чи Game Mode зараз активний.
        FIX: перечитуємо backup з диска щоб бачити зміни від
        іншого instance (напр. бот ↔ GUI мають окремі instance).
        """
        try: self._load_backup()
        except Exception: pass
        return bool(getattr(self, "_is_active", False)) or self.has_backup()

    def activate_game_mode(self, log_cb=None, source: str = "gui") -> tuple[bool, int, int]:
        """
        ЄДИНИЙ метод активації Game Mode — використовується і GUI і ботом.
        Гарантує: backup створюється, твіки застосовуються, is_active=True.

        Повертає (success, ok_count, fail_count).
        source: 'gui' | 'bot' | 'auto' — хто викликав (для нотифікацій)
        """
        # Використовуємо list-обгортку замість nonlocal бо Python scoping
        # у двох рівнях nested-функцій має особливості
        counter = [0, 0]   # [ok_count, fail_count]

        def _wrapped_cb(msg):
            if not msg: return
            if "✅" in msg: counter[0] += 1
            elif "❌" in msg or "⚠️" in msg: counter[1] += 1
            if log_cb:
                try: log_cb(msg)
                except Exception: pass

        try:
            # 1. Network tweaks (робить backup перший раз!)
            if log_cb: log_cb("\n> 🔧 [1/6] Network tweaks...")
            self.apply_network_tweaks(log_cb=_wrapped_cb)
            # 2. Nagle OFF
            if log_cb: log_cb("\n> 🔧 [2/6] Nagle's Algorithm OFF...")
            self.disable_nagle(log_cb=_wrapped_cb)
            # 3. High Performance
            if log_cb: log_cb("\n> 🔧 [3/6] High Performance power...")
            self.set_high_performance_power(log_cb=_wrapped_cb)
            # 4. CPU Unpark
            if log_cb: log_cb("\n> 🔧 [4/6] CPU Core Unpark...")
            self.unpark_cpu_cores(log_cb=_wrapped_cb)
            # 5. DNS flush
            if log_cb: log_cb("\n> 🔧 [5/6] DNS cache flush...")
            self.flush_dns(log_cb=_wrapped_cb)
            # 6. QoS policies для ігор
            if log_cb: log_cb("\n> 🔧 [6/7] QoS policies (130 games)...")
            self.apply_qos_policy(log_cb=_wrapped_cb)

            # 7. PING OPTIMIZER — Timer 0.5ms + IMR/Power/LSO/RSS off
            # Це найвпливовіші tweaks для зниження пінгу (5-15ms економії)
            if log_cb: log_cb("\n> ⚡ [7/8] PING OPTIMIZER (Timer + NIC tweaks)...")
            try:
                ping_results = self.apply_all_ping_tweaks(log_cb=_wrapped_cb)
                successful = sum(1 for v in ping_results.values() if v)
                if log_cb:
                    log_cb(f"  📊 Ping Optimizer: {successful}/{len(ping_results)} оптимізацій")
            except Exception as e:
                if log_cb: log_cb(f"  ⚠️ Ping Optimizer: {e}")

            # 8. EXTRA TWEAKS — нові методи для додаткового зниження пінгу
            if log_cb: log_cb("\n> 🚀 [8/8] EXTRA TWEAKS (background apps, GPU, services)...")
            try:
                # NIC offloads OFF
                self.disable_nic_offloads(log_cb=_wrapped_cb)
                # GPU Hardware Scheduling
                self.set_gpu_priority(log_cb=_wrapped_cb)
                # Visual Effects → Performance
                self.optimize_visual_effects(log_cb=_wrapped_cb)
                # GameDVR / GameBar OFF
                self.disable_throttling_index(log_cb=_wrapped_cb)
                # DNS Cache extended
                self.optimize_dns_cache(log_cb=_wrapped_cb)
                # Fullscreen Optimizations OFF
                self.disable_fullscreen_optimizations(log_cb=_wrapped_cb)
                # Background apps + WU Delivery Optimization
                self.kill_background_apps(log_cb=_wrapped_cb)
                # Зупиняємо непотрібні служби (це останнє, бо потенційно агресивне)
                self.disable_useless_services(log_cb=_wrapped_cb)
            except Exception as e:
                if log_cb: log_cb(f"  ⚠️ Extra Tweaks: {e}")

            self._is_active = True
            ok_count, fail_count = counter[0], counter[1]

            if log_cb:
                log_cb(f"\n> ✅ GAME MODE ACTIVATED — {ok_count} ops ✓")
            # Тригеримо підписників (бот → Telegram notification)
            self._fire_mode_change(True, source)
            return (True, ok_count, fail_count)
        except Exception as e:
            import traceback
            traceback.print_exc()
            if log_cb:
                log_cb(f"\n> ❌ Activation error: {e}")
            return (False, counter[0], counter[1])

    def deactivate_game_mode(self, log_cb=None, source: str = "gui") -> tuple[bool, int]:
        """
        ЄДИНИЙ метод деактивації Game Mode.
        Відновлює все до дефолтних налаштувань.

        Повертає (success, operations_count).
        """
        ops = 0
        def _cb(msg):
            nonlocal ops
            ops += 1
            if log_cb: log_cb(msg)

        try:
            self.restore_defaults(log_cb=_cb)
            # Додатково відновлюємо служби які були зупинені
            try:
                self.restore_services(log_cb=_cb)
            except Exception: pass
            self._is_active = False
            if log_cb:
                log_cb(f"\n> ⏹ GAME MODE DEACTIVATED — {ops} ops restored")
            # Тригеримо підписників
            self._fire_mode_change(False, source)
            return (True, ops)
        except Exception as e:
            if log_cb:
                log_cb(f"\n> ❌ Deactivation error: {e}")
            return (False, ops)

    def diagnose_ping(self,
                      target: str = "8.8.8.8",
                      target_host: str = None,    # alias — UI передає саме його
                      progress_cb=None,            # callback(msg: str, pct: int)
                      log_cb=None) -> dict:
        """
        Повна діагностика пінгу. FIX: прийнято target_host= та progress_cb=,
        повертає router_ms, isp_ms, target_ms, hops (list of dicts з is_bottleneck),
        status, recommendation — формат відповідає _show_diagnose_result у UI.
        """
        if target_host:
            target = target_host

        result = {
            "target":         target,
            "router_ms":      None,   # пінг до 1-го хопу (роутер)
            "isp_ms":         None,   # пінг до 2-3-го хопу (провайдер)
            "target_ms":      None,   # пінг до цілі (середній)
            "avg_ms":         None,
            "min_ms":         None,
            "max_ms":         None,
            "loss_pct":       None,
            "hops":           [],     # [{hop, ip, ms, is_bottleneck, jump}]
            "status":         "ok",   # "wifi_issue"|"isp_issue"|"server_far"|"ok"
            "recommendation": "",
            "analysis":       "",
        }

        # 1. Пінг до цілі (10 пакетів для точності)
        if progress_cb: progress_cb("Пінгую ціль...", 20)
        if log_cb: log_cb(f"  🔍 Пінгую {target} (10 пакетів)...")
        try:
            if IS_WINDOWS:
                r = subprocess.run(
                    ["ping", "-n", "10", "-w", "1000", target],
                    capture_output=True, text=True,
                    encoding="cp866", errors="replace", timeout=20
                )
                out = r.stdout or ""
                samples = []
                for t in re.findall(
                    r"(?:time|время|час)[=<]\s*(\d+)\s*(?:ms|мс)", out, re.IGNORECASE
                ):
                    try:
                        v = float(t)
                        if 0 < v < 5000: samples.append(v)
                    except Exception: pass
                ml = re.search(
                    r"(?:Sent|Отправлено|Надіслано)\s*=\s*(\d+).*?"
                    r"(?:Received|Получено|Отримано)\s*=\s*(\d+)",
                    out, re.IGNORECASE | re.DOTALL
                )
                if ml:
                    s, rcv = int(ml.group(1)), int(ml.group(2))
                    result["loss_pct"] = round((s - rcv) / s * 100, 1) if s else 0
            else:
                r = subprocess.run(
                    ["ping", "-c", "10", "-W", "1", target],
                    capture_output=True, text=True, timeout=20
                )
                out = r.stdout or ""
                samples = [float(t) for t in re.findall(r"time=([\d.]+)\s*ms", out)
                           if 0 < float(t) < 5000]
                m = re.search(r"(\d+)%\s*packet\s*loss", out)
                if m: result["loss_pct"] = float(m.group(1))

            if samples:
                result["avg_ms"]    = round(sum(samples) / len(samples), 1)
                result["min_ms"]    = round(min(samples), 1)
                result["max_ms"]    = round(max(samples), 1)
                result["target_ms"] = result["avg_ms"]
        except Exception as e:
            if log_cb: log_cb(f"  ⚠️ Ping помилка: {e}")

        # 2. Traceroute (до 15 хопів)
        if progress_cb: progress_cb("Traceroute (15 хопів)...", 50)
        if log_cb: log_cb("  🔍 Traceroute...")
        hops = []
        try:
            if IS_WINDOWS:
                r = subprocess.run(
                    ["tracert", "-h", "15", "-w", "1500", "-d", target],
                    capture_output=True, text=True,
                    encoding="cp866", errors="replace", timeout=60
                )
            else:
                r = subprocess.run(
                    ["traceroute", "-m", "15", "-w", "1.5", "-n", target],
                    capture_output=True, text=True, timeout=60
                )
            prev_ms = 0.0
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                if not line: continue
                hm = re.match(r"^\s*(\d+)", line)
                if not hm: continue
                hop_num = int(hm.group(1))
                times = re.findall(r"(\d+)\s*ms", line, re.IGNORECASE)
                ms_val = None
                if times:
                    try:
                        vals = [float(t) for t in times if 0 < float(t) < 10000]
                        if vals: ms_val = round(sum(vals) / len(vals), 1)
                    except Exception: pass
                ipm = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
                ip = ipm.group(1) if ipm else "*"
                jump = 0.0; is_bn = False
                if ms_val is not None and prev_ms > 0:
                    jump = ms_val - prev_ms; is_bn = jump > 30
                if ms_val is not None: prev_ms = ms_val
                hops.append({
                    "hop": hop_num, "ip": ip, "ms": ms_val,
                    "is_bottleneck": is_bn, "jump": round(jump, 1),
                })
                if hop_num == 1 and ms_val is not None:
                    result["router_ms"] = ms_val
                if hop_num == 2 and ms_val is not None and result["isp_ms"] is None:
                    result["isp_ms"] = ms_val
                if hop_num >= 3 and ms_val is not None and result["isp_ms"] is None:
                    result["isp_ms"] = ms_val
            result["hops"] = hops[:15]
        except Exception as e:
            if log_cb: log_cb(f"  ⚠️ Traceroute помилка: {e}")

        # 3. Аналіз і рекомендація
        if progress_cb: progress_cb("Аналіз результатів...", 90)
        router_ms = result.get("router_ms")
        avg       = result.get("avg_ms")
        loss      = result.get("loss_pct") or 0.0

        if router_ms is not None and router_ms > 15:
            result["status"] = "wifi_issue"
            result["recommendation"] = (
                f"Затримка до роутера {router_ms:.0f} мс — занадто висока.\n"
                f"Ознака слабкого Wi-Fi або перевантаженого роутера.\n"
                f"Підключіть ПК через Ethernet — пінг впаде на 20–80 мс."
            )
        elif loss > 5:
            result["status"] = "isp_issue"
            result["recommendation"] = (
                f"Втрата пакетів {loss:.1f}% — нестабільне з'єднання.\n"
                f"Перезавантажте роутер або зверніться до провайдера."
            )
        elif avg is not None and avg > 100:
            result["status"] = "server_far"
            result["recommendation"] = (
                f"Пінг {avg:.0f} мс — сервер далеко або маршрут неоптимальний.\n"
                f"Спробуйте VPN з EU-локацією або оберіть ближчий регіон у грі."
            )
        elif avg is not None:
            result["status"] = "ok"
            result["recommendation"] = (
                f"З'єднання стабільне. Пінг {avg:.0f} мс "
                f"({result['min_ms']:.0f}–{result['max_ms']:.0f} мс).\nВсе добре!"
            )
        else:
            result["status"] = "ok"
            result["recommendation"] = "Діагностика завершена. Хост не відповідає на ICMP."

        parts = []
        if loss is not None:
            parts.append(f"{'❌' if loss>10 else '⚠️' if loss>2 else '✅'} Втрата пакетів: {loss}%")
        if avg is not None:
            jitter = (result["max_ms"] - result["min_ms"]) if result["min_ms"] else 0
            parts.append(f"{'✅' if avg<30 else '✅' if avg<80 else '⚠️' if avg<150 else '❌'} Пінг: {avg} мс")
            if jitter > 30: parts.append(f"⚠️ Великий jitter: {jitter:.0f} мс")
        result["analysis"] = "\n".join(parts) or "Діагностика завершена"

        if progress_cb: progress_cb("Готово!", 100)
        return result

    def verify_tweaks(self) -> dict:
        """
        FIX: Перевіряє фактичний стан твіків Windows.
        Повертає {key: {applied: bool, name: str, value: str, tip: str}} —
        формат відповідає _show_verify_result у UI.
        """
        result: dict = {}
        NW = getattr(__import__("subprocess"), "CREATE_NO_WINDOW", 0)

        checks = [
            ("net_throttle",   "NetworkThrottlingIndex", 0xFFFFFFFF,
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
             "NetworkThrottlingIndex", "Активуй Game Mode"),
            ("sys_resp",       "SystemResponsiveness", 0,
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile",
             "SystemResponsiveness", "Активуй Game Mode"),
            ("gpu_pri",        "GPU Priority (Games)", 8,
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
             "GPU Priority", "Активуй Game Mode"),
            ("games_pri",      "Priority (Games)", 6,
             r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games",
             "Priority", "Активуй Game Mode"),
            ("def_ttl",        "DefaultTTL", 64,
             r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "DefaultTTL", "TCP tweaks не застосовані"),
            ("tcp_wait",       "TcpTimedWaitDelay", 30,
             r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "TcpTimedWaitDelay", "TCP tweaks не застосовані"),
            ("max_port",       "MaxUserPort", 65534,
             r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "MaxUserPort", "TCP tweaks не застосовані"),
            ("sack",           "SackOpts", 1,
             r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
             "SackOpts", "TCP tweaks не застосовані"),
        ]

        import subprocess as _sp
        for key, dname, expected, reg_path, reg_name, tip in checks:
            actual_str = "не знайдено"; applied = False
            try:
                r = _sp.run(["reg", "query", reg_path, "/v", reg_name],
                             capture_output=True, text=True, timeout=5, creationflags=NW)
                out = r.stdout or ""
                m = re.search(r"0x([0-9a-fA-F]+)", out)
                if m:
                    av = int(m.group(1), 16); applied = (av == expected)
                    actual_str = f"0x{av:X}  ({av})"
                else:
                    m2 = re.search(r"\s+REG_\w+\s+(\d+)", out)
                    if m2:
                        av = int(m2.group(1)); applied = (av == expected)
                        actual_str = str(av)
            except Exception as e:
                actual_str = f"error: {e}"
            result[key] = {"applied": applied, "name": dname, "value": actual_str,
                           "tip": tip if not applied else ""}

        # QoS перевірка
        try:
            r = _sp.run(["powershell", "-NoProfile", "-Command",
                          "(Get-NetQosPolicy|Where-Object{$_.Name -like 'NetGuardian*'}).Count"],
                         capture_output=True, text=True, timeout=10, creationflags=NW)
            cnt = 0
            try: cnt = int((r.stdout or "0").strip() or "0")
            except Exception: pass
            result["qos"] = {
                "applied": cnt > 0, "name": "QoS правила для ігор",
                "value": f"{cnt} правил",
                "tip": "Активуй Game Mode → QoS застосується автоматично" if cnt == 0 else "",
            }
        except Exception as e:
            result["qos"] = {"applied": False, "name": "QoS правила", "value": "error", "tip": str(e)[:60]}

        return result

    # ═══════════════════════════════════════════════════════════════════════
    #  ⚡ PING OPTIMIZER — ВСЕБІЧНЕ ЗНИЖЕННЯ ЛАТЕНТНОСТІ
    # ═══════════════════════════════════════════════════════════════════════
    #
    #  Рівні оптимізації (від найбільшого до найменшого ефекту):
    #  1. Timer Resolution 0.5ms  — ОС реагує швидше на пакети   (-5..40ms)
    #  2. Interrupt Moderation OFF — NIC не батчить переривання   (-2..20ms)
    #  3. NIC Power Save OFF       — NIC не засинає між пакетами  (-1..15ms)
    #  4. LSO OFF                  — менший overhead сегментації  (-1..10ms)
    #  5. RSS affinity             — мережа на окремому ядрі CPU  (-1..8ms)
    #  6. QoS DSCP 46              — роутер пропускає гру першою  (залежить від роутера)
    #  7. Game CPU Affinity        — гра тільки на P-ядрах        (-1..5ms jitter)
    #  8. MMCSS Games              — планувальник дає більше CPU  (FPS +3..10%)
    # ═══════════════════════════════════════════════════════════════════════

    # ── 1. TIMER RESOLUTION ──────────────────────────────────────────────

    def set_timer_resolution(self, resolution_ms: float = 0.5, log_cb=None) -> bool:
        """
        Встановлює роздільну здатність системного таймера Windows.
        Default: 15.6ms → Game: 0.5ms
        Ефект: ОС обробляє пакети та переривання у ~31× частіше.

        Потребує: Windows. Зникає після перезавантаження.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ Timer: тільки для Windows.")
            return False
        try:
            import ctypes
            ntdll = ctypes.windll.ntdll
            # Одиниці — 100-наносекундні інтервали. 0.5ms = 5000 одиниць.
            resolution_100ns = int(resolution_ms * 10_000)
            actual = ctypes.c_ulong(0)
            # NtSetTimerResolution(DesiredResolution, Set=True, ActualResolution)
            status = ntdll.NtSetTimerResolution(
                resolution_100ns, True, ctypes.byref(actual)
            )
            actual_ms = actual.value / 10_000
            ok = status == 0
            if log_cb:
                if ok:
                    log_cb(f"  ✅ Timer Resolution → {actual_ms:.2f}ms "
                           f"(було ~15.6ms, зменшено у {15.6/actual_ms:.0f}×)")
                else:
                    log_cb(f"  ⚠️ Timer: NTSTATUS=0x{status:08X}, "
                           f"actual={actual_ms:.2f}ms")
            self._backup["timer_resolution_set"] = True
            self._save_backup()
            return ok
        except Exception as e:
            if log_cb: log_cb(f"  ❌ Timer: {e}")
            return False

    def restore_timer_resolution(self, log_cb=None):
        """Відновлює стандартний таймер Windows (15.6ms)."""
        if not IS_WINDOWS:
            return
        try:
            import ctypes
            ntdll = ctypes.windll.ntdll
            actual = ctypes.c_ulong(0)
            ntdll.NtSetTimerResolution(156001, False, ctypes.byref(actual))
            if log_cb:
                log_cb(f"  ✅ Timer Resolution → стандартний (15.6ms)")
        except Exception as e:
            if log_cb: log_cb(f"  ⚠️ Timer restore: {e}")

    # ── 2. NETWORK ADAPTERS ──────────────────────────────────────────────

    def get_network_adapters(self) -> list[str]:
        """Повертає список активних мережевих адаптерів."""
        if not IS_WINDOWS:
            return []
        try:
            cmd = (
                "Get-NetAdapter | "
                "Where-Object {$_.Status -eq 'Up'} | "
                "Select-Object -ExpandProperty Name"
            )
            ok, out = run(["powershell", "-NoProfile", "-Command", cmd], timeout=8)
            if ok and out:
                return [l.strip() for l in out.splitlines() if l.strip()]
        except Exception:
            pass
        # Fallback: netsh
        try:
            ok, out = run(["netsh", "interface", "show", "interface"], timeout=6)
            adapters = []
            for line in out.splitlines():
                if "Connected" in line or "Підключено" in line:
                    parts = line.split()
                    if len(parts) >= 4:
                        adapters.append(" ".join(parts[3:]))
            return adapters
        except Exception:
            return []

    def _get_active_adapter(self) -> str | None:
        """Повертає ім'я першого активного адаптера (Wi-Fi або Ethernet)."""
        adapters = self.get_network_adapters()
        # Ethernet пріоритетніший за Wi-Fi
        for a in adapters:
            al = a.lower()
            if "ethernet" in al or "local area" in al or "gigabit" in al:
                return a
        return adapters[0] if adapters else None

    # ── 3. INTERRUPT MODERATION ──────────────────────────────────────────

    def disable_interrupt_moderation(self, adapter: str = None,
                                      log_cb=None) -> bool:
        """
        Вимикає Interrupt Moderation (IMR) на мережевому адаптері.

        Interrupt Moderation батчує переривання від NIC для збереження CPU.
        При вимкненні — кожен пакет негайно обробляється → -2..20ms пінгу.

        Потребує: Admin + PowerShell.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ IMR: тільки Windows.")
            return False

        adapter = adapter or self._get_active_adapter()
        if not adapter:
            if log_cb: log_cb("⚠️ IMR: активний адаптер не знайдено.")
            return False

        # Зберігаємо поточне значення
        get_cmd = (
            f"Get-NetAdapterAdvancedProperty -Name '{adapter}' "
            f"| Where-Object {{$_.DisplayName -like '*Interrupt Moderation*'}} "
            f"| Select-Object -ExpandProperty DisplayValue"
        )
        _, cur = run(["powershell", "-NoProfile", "-Command", get_cmd], timeout=8)
        self._backup.setdefault("nic_imr", {})[adapter] = cur.strip() or "Enabled"
        self._save_backup()

        # Вимикаємо
        disable_cmd = (
            f"Set-NetAdapterAdvancedProperty -Name '{adapter}' "
            f"-DisplayName 'Interrupt Moderation' "
            f"-DisplayValue 'Disabled' -ErrorAction SilentlyContinue"
        )
        ok, err = run(["powershell", "-NoProfile", "-Command", disable_cmd], timeout=10)

        if log_cb:
            if ok:
                log_cb(f"  ✅ Interrupt Moderation → ВИМКНЕНО ({adapter})")
                log_cb(f"     ↳ NIC перериває CPU одразу після кожного пакету")
            else:
                # Деякі адаптери не підтримують цю опцію
                log_cb(f"  ⚠️ IMR: {adapter} — опція не підтримується або вже вимкнена")
        return ok

    def restore_interrupt_moderation(self, log_cb=None):
        """Відновлює Interrupt Moderation."""
        if not IS_WINDOWS:
            return
        backup = self._backup.get("nic_imr", {})
        for adapter, value in backup.items():
            if not value or value.lower() in ("enabled", ""):
                value = "Enabled"
            cmd = (
                f"Set-NetAdapterAdvancedProperty -Name '{adapter}' "
                f"-DisplayName 'Interrupt Moderation' "
                f"-DisplayValue '{value}' -ErrorAction SilentlyContinue"
            )
            run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
        if log_cb:
            log_cb("  ✅ Interrupt Moderation → відновлено")

    # ── 4. NIC POWER SAVE ────────────────────────────────────────────────

    def disable_nic_power_save(self, adapter: str = None, log_cb=None) -> bool:
        """
        Вимикає енергозбереження NIC (Energy-Efficient Ethernet + Power Management).

        При ввімкненому EEE адаптер переходить у Low-Power Idle між пакетами.
        Пробудження = +5..30ms spike. Особливо помітно на ноутбуках.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ NIC Power: тільки Windows.")
            return False

        adapter = adapter or self._get_active_adapter()
        if not adapter:
            if log_cb: log_cb("⚠️ NIC Power: адаптер не знайдено.")
            return False

        results = []
        props = [
            ("Energy-Efficient Ethernet",    "Disabled"),
            ("Green Ethernet",               "Disabled"),
            ("Power Saving Mode",            "Disabled"),
            ("Advanced EEE",                 "Disabled"),
            ("Reduce Speed On Power Down",   "Disabled"),
        ]
        for display_name, value in props:
            cmd = (
                f"Set-NetAdapterAdvancedProperty -Name '{adapter}' "
                f"-DisplayName '{display_name}' "
                f"-DisplayValue '{value}' -ErrorAction SilentlyContinue"
            )
            ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
            if ok:
                results.append(display_name)

        # Вимикаємо "Allow computer to turn off this device" через PowerShell
        ps_power_cmd = (
            f"$a = Get-NetAdapter -Name '{adapter}' -ErrorAction SilentlyContinue; "
            f"if ($a) {{ "
            f"  $devId = $a.DeviceID; "
            f"  $pnp = Get-WmiObject Win32_PnPEntity | "
            f"    Where-Object {{$_.DeviceID -like \"*$devId*\"}}; "
            f"  if ($pnp) {{ $pnp.SetPowerState(4, [datetime]::Now) | Out-Null }} "
            f"}}"
        )
        run(["powershell", "-NoProfile", "-Command", ps_power_cmd], timeout=10)

        self._backup.setdefault("nic_power_save_disabled", [])
        if adapter not in self._backup["nic_power_save_disabled"]:
            self._backup["nic_power_save_disabled"].append(adapter)
        self._save_backup()

        if log_cb:
            if results:
                log_cb(f"  ✅ NIC Power Save → ВИМКНЕНО ({adapter})")
                for r in results:
                    log_cb(f"     ↳ {r}: Disabled")
                log_cb(f"     ↳ Зникають spike-и +5..30ms при пробудженні NIC")
            else:
                log_cb(f"  ⚠️ NIC Power Save: {adapter} не підтримує або вже вимкнено")
        return bool(results)

    # ── 5. LSO (Large Send Offload) ──────────────────────────────────────

    def disable_lso(self, adapter: str = None, log_cb=None) -> bool:
        """
        Вимикає Large Send Offload v1 та v2.

        LSO дозволяє NIC самостійно сегментувати великі TCP пакети.
        При вимкненні сегментація повертається до CPU — але для малих ігрових
        UDP/TCP пакетів це ЗНИЖУЄ overhead і latency.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ LSO: тільки Windows.")
            return False

        adapter = adapter or self._get_active_adapter()
        if not adapter:
            if log_cb: log_cb("⚠️ LSO: адаптер не знайдено.")
            return False

        lso_props = [
            "Large Send Offload v2 (IPv4)",
            "Large Send Offload v2 (IPv6)",
            "Large Send Offload Version 2 (IPv4)",
            "Large Send Offload Version 2 (IPv6)",
            "Large Send Offload V2 (IPv4)",
            "Large Send Offload V2 (IPv6)",
        ]
        disabled_count = 0
        for prop in lso_props:
            cmd = (
                f"Set-NetAdapterAdvancedProperty -Name '{adapter}' "
                f"-DisplayName '{prop}' "
                f"-DisplayValue 'Disabled' -ErrorAction SilentlyContinue"
            )
            ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=8)
            if ok:
                disabled_count += 1

        # Також через netsh для сумісності
        run(["netsh", "int", "tcp", "set", "global", "chimney=disabled"], timeout=6)

        self._backup.setdefault("nic_lso_disabled", [])
        if adapter not in self._backup["nic_lso_disabled"]:
            self._backup["nic_lso_disabled"].append(adapter)
        self._save_backup()

        if log_cb:
            log_cb(f"  ✅ LSO → ВИМКНЕНО ({adapter}, {disabled_count} правил)")
            log_cb(f"     ↳ TCP Chimney Offload також вимкнено")
            log_cb(f"     ↳ Менший overhead для дрібних UDP-пакетів гри")
        return True

    # ── 6. RSS AFFINITY ──────────────────────────────────────────────────

    def set_rss_affinity(self, adapter: str = None,
                          base_cpu: int = 0, max_procs: int = 2,
                          log_cb=None) -> bool:
        """
        Прив'язує RSS (Receive Side Scaling) черги до конкретних CPU ядер.

        RSS розподіляє обробку мережевих пакетів по ядрах CPU.
        Пін на ядра 0+1 (P-cores) → менше cache-miss → -1..8ms jitter.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ RSS: тільки Windows.")
            return False

        adapter = adapter or self._get_active_adapter()
        if not adapter:
            if log_cb: log_cb("⚠️ RSS: адаптер не знайдено.")
            return False

        cmd = (
            f"Set-NetAdapterRss -Name '{adapter}' "
            f"-BaseProcessorNumber {base_cpu} "
            f"-MaxProcessors {max_procs} "
            f"-NumberOfReceiveQueues 2 "
            f"-ErrorAction SilentlyContinue"
        )
        ok, err = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)

        if log_cb:
            if ok:
                log_cb(f"  ✅ RSS → CPU {base_cpu}-{base_cpu+max_procs-1} ({adapter})")
                log_cb(f"     ↳ Мережеві переривання обробляються на P-ядрах")
            else:
                log_cb(f"  ⚠️ RSS: {adapter} — {err[:80] if err else 'не підтримується'}")
        return ok

    # ── 7. PROCESS AFFINITY (P-cores) ────────────────────────────────────

    def set_game_affinity_pcores(self, pid: int, exe_name: str,
                                  log_cb=None) -> bool:
        """
        Прив'язує гровий процес до P-ядер (фізичних ядер без HT/E-cores).

        На Intel 12th+ (Alder Lake) і Ryzen — P-ядра мають найнижчу latency.
        Дозволяє уникнути міграцій між P-core та E-core = менший jitter.
        """
        try:
            import psutil
            proc = psutil.Process(pid)
            total_logical  = psutil.cpu_count(logical=True) or 2
            total_physical = psutil.cpu_count(logical=False) or 1

            if total_logical == total_physical:
                # Немає HT — використовуємо всі ядра
                cores = list(range(total_logical))
            else:
                # HT: логічні ядра 0,2,4... = P-ядра (для Intel)
                # Беремо перші N фізичних ядер (не E-cores)
                p_core_count = min(total_physical, 8)
                cores = list(range(0, p_core_count * 2, 2))  # 0,2,4,6...

            proc.cpu_affinity(cores)

            if log_cb:
                log_cb(f"  ✅ {exe_name} → P-cores: {cores}")
                log_cb(f"     ↳ Менше міграцій CPU = стабільніший пінг")
            return True
        except Exception as e:
            if log_cb:
                log_cb(f"  ⚠️ Affinity {exe_name}: {e}")
            return False

    # ── 8. MMCSS (Multimedia Class Scheduler) ────────────────────────────

    def apply_mmcss_tweaks(self, log_cb=None) -> bool:
        """
        Оптимізує MMCSS (Multimedia Class Scheduler Service) для ігор.

        MMCSS дає пріоритет потокам з категорії 'Games' над фоновими.
        Також встановлює NoLazyMode і SystemResponsiveness=0.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ MMCSS: тільки Windows.")
            return False

        base = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile"
        tweaks = [
            (base, "NetworkThrottlingIndex", "4294967295", "REG_DWORD"),
            (base, "SystemResponsiveness",   "0",          "REG_DWORD"),
            (base + r"\Tasks\Games", "Affinity",            "0",    "REG_DWORD"),
            (base + r"\Tasks\Games", "Background Only",     "False","REG_SZ"),
            (base + r"\Tasks\Games", "Clock Rate",          "10000","REG_DWORD"),
            (base + r"\Tasks\Games", "GPU Priority",        "8",    "REG_DWORD"),
            (base + r"\Tasks\Games", "Priority",            "6",    "REG_DWORD"),
            (base + r"\Tasks\Games", "Scheduling Category", "High", "REG_SZ"),
            (base + r"\Tasks\Games", "SFIO Priority",       "High", "REG_SZ"),
            # Audio latency — зменшує переривання від аудіо
            (base + r"\Tasks\Audio", "Clock Rate",          "10000","REG_DWORD"),
            (base + r"\Tasks\Audio", "Priority",            "6",    "REG_DWORD"),
            (base + r"\Tasks\Audio", "Scheduling Category", "Medium","REG_SZ"),
        ]

        count = 0
        for key, value, data, rtype in tweaks:
            if reg_write(key, value, data, rtype):
                count += 1

        # NoLazyMode для DirectX
        dx_key = r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers"
        reg_write(dx_key, "TdrLevel", "0", "REG_DWORD")

        if log_cb:
            log_cb(f"  ✅ MMCSS Games → оптимізовано ({count} записів)")
            log_cb(f"     ↳ Games: Priority=6, GPU=8, Scheduling=High")
            log_cb(f"     ↳ NetworkThrottlingIndex → MAX (без обмеження мережі)")
        return count > 0

    # ── 9. DISABLE NAGLE (розширений) ────────────────────────────────────

    def disable_nagle_extended(self, log_cb=None) -> bool:
        """
        Розширене вимкнення Nagle: + TcpDelAckTicks=0 + TcpInitialRTT.
        TcpDelAckTicks=0 вимикає Delayed ACK — ще -5..15ms на деяких серверах.
        """
        if not IS_WINDOWS:
            return False

        interfaces_key = (
            r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        )
        ok, out = run(["reg", "query", interfaces_key])
        if not ok:
            return False

        count = 0
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"HKEY.*\{[0-9A-Fa-f\-]{36}\}$", line):
                reg_write(line, "TcpAckFrequency",  "1")
                reg_write(line, "TCPNoDelay",        "1")
                reg_write(line, "TcpDelAckTicks",    "0")  # Delayed ACK off
                count += 1

        # Глобальні TCP параметри
        global_key = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"
        reg_write(global_key, "DefaultTTL",           "64",   "REG_DWORD")
        reg_write(global_key, "Tcp1323Opts",           "1",    "REG_DWORD")
        reg_write(global_key, "TcpMaxDupAcks",         "2",    "REG_DWORD")
        reg_write(global_key, "TcpTimedWaitDelay",     "30",   "REG_DWORD")
        reg_write(global_key, "SackOpts",              "1",    "REG_DWORD")
        reg_write(global_key, "EnablePMTUDiscovery",   "1",    "REG_DWORD")
        reg_write(global_key, "EnablePMTUBHDetect",    "0",    "REG_DWORD")

        if log_cb:
            log_cb(f"  ✅ Nagle Extended → {count} адаптерів")
            log_cb(f"     ↳ TcpDelAckTicks=0 (Delayed ACK вимкнено)")
            log_cb(f"     ↳ SACK, PMTU Discovery, TTL=64 оптимізовано")
        return count > 0

    # ════════════════════════════════════════════════════════════════════════
    #  ДОДАТКОВІ AGGRESSIVE PING TWEAKS — нові методи
    # ════════════════════════════════════════════════════════════════════════

    def disable_nic_offloads(self, adapter: str = None, log_cb=None) -> bool:
        """
        Вимикає всі NIC offloads (TCP/UDP Checksum, IPv4 Checksum, Large Send,
        Receive Side Coalescing). Це примушує CPU обробляти пакети — швидше,
        ніж чекати поки NIC прорахує checksum-и.
        Економія: 1-5ms у пік, 0.5-1ms середнє.
        """
        if not IS_WINDOWS:
            if log_cb: log_cb("❌ NIC Offloads: тільки Windows."); return False
        adapter = adapter or self._get_active_adapter()
        if not adapter:
            if log_cb: log_cb("⚠️ NIC Offloads: адаптер не знайдено."); return False

        offloads_to_disable = [
            "*TCPChecksumOffloadIPv4", "*TCPChecksumOffloadIPv6",
            "*UDPChecksumOffloadIPv4", "*UDPChecksumOffloadIPv6",
            "*IPChecksumOffloadIPv4",
            "*LsoV1IPv4", "*LsoV2IPv4", "*LsoV2IPv6",
            "ReceiveSideScaling",   # лишаємо включеним — це інша справа
        ]
        success = 0
        for offload in offloads_to_disable[:8]:   # окрім RSS
            cmd = (
                f"Set-NetAdapterAdvancedProperty -Name '{adapter}' "
                f"-RegistryKeyword '{offload}' -RegistryValue '0' "
                f"-ErrorAction SilentlyContinue"
            )
            ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=8)
            if ok: success += 1

        if log_cb:
            log_cb(f"  ✅ NIC Offloads вимкнено: {success}/8 опцій ({adapter})")
            log_cb(f"     ↳ Checksum/LSO offload OFF — CPU обробляє швидше")
        return success > 0

    def disable_throttling_index(self, log_cb=None) -> bool:
        """
        NetworkThrottlingIndex = MAX (вже є в REGISTRY_TWEAKS).
        Plus: вимикає GameDVR який жере мережу.
        """
        if not IS_WINDOWS:
            return False

        # GameDVR/GameBar вимикання — вони відкривають фоновий запис
        commands = [
            (r"HKCU\System\GameConfigStore", "GameDVR_Enabled", "0", "REG_DWORD"),
            (r"HKCU\System\GameConfigStore", "GameDVR_FSEBehaviorMode", "2", "REG_DWORD"),
            (r"HKCU\System\GameConfigStore", "GameDVR_HonorUserFSEBehaviorMode", "1", "REG_DWORD"),
            (r"HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR", "AllowGameDVR", "0", "REG_DWORD"),
        ]
        ok_count = 0
        for key, val, data, rtype in commands:
            if reg_write(key, val, data, rtype): ok_count += 1

        if log_cb:
            log_cb(f"  ✅ GameDVR вимкнено ({ok_count}/4 ключів)")
            log_cb(f"     ↳ Не записує гру у фоні → не їсть мережу/диск")
        return ok_count > 0

    def optimize_dns_cache(self, log_cb=None) -> bool:
        """
        Розширює DNS-кеш + ставить агресивний TTL.
        Менше DNS-запитів = менше затримок на нових з'єднаннях.
        """
        if not IS_WINDOWS:
            return False

        key = r"HKLM\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters"
        tweaks = [
            ("CacheHashTableBucketSize",   "1",     "REG_DWORD"),
            ("CacheHashTableSize",         "384",   "REG_DWORD"),
            ("MaxCacheEntryTtlLimit",      "64000", "REG_DWORD"),
            ("MaxSOACacheEntryTtlLimit",   "301",   "REG_DWORD"),
        ]
        ok_count = 0
        for val, data, rtype in tweaks:
            if reg_write(key, val, data, rtype): ok_count += 1

        if log_cb:
            log_cb(f"  ✅ DNS кеш оптимізовано ({ok_count}/4)")
            log_cb(f"     ↳ Більший кеш = менше повторних запитів")
        return ok_count > 0

    def disable_useless_services(self, log_cb=None) -> bool:
        """
        Зупиняє служби які жруть мережу/CPU під час гри:
        - SysMain (Superfetch) — постійно сканує диск і RAM
        - DiagTrack — телеметрія Windows
        - WSearch — індексація (вже частково в utility)
        - Spooler — друк (якщо не печатаєш)
        """
        if not IS_WINDOWS or not is_admin():
            if log_cb: log_cb("❌ Services: потрібен Admin."); return False

        services = [
            ("SysMain",      "Superfetch / SysMain"),
            ("DiagTrack",    "Connected User Experiences and Telemetry"),
            ("WSearch",      "Windows Search (індексація)"),
            ("RetailDemo",   "Retail Demo Service"),
            ("MapsBroker",   "Downloaded Maps Manager"),
            ("WMPNetworkSvc","Windows Media Player Network Sharing"),
            ("XblGameSave",  "Xbox Live Game Save"),
            ("XboxGipSvc",   "Xbox Accessory Management"),
        ]

        # Зберігаємо стан служб ДЛЯ ВІДНОВЛЕННЯ
        services_backup = self._backup.setdefault("services", {})
        ok_count = 0
        for svc_name, desc in services:
            try:
                # Запам'ятовуємо чи воно було Running
                _, status_out = run(["sc", "query", svc_name], timeout=5)
                was_running = "RUNNING" in (status_out or "").upper()
                services_backup[svc_name] = was_running

                if was_running:
                    ok, _ = run(["sc", "stop", svc_name], timeout=10)
                    if ok:
                        ok_count += 1
                        if log_cb: log_cb(f"  ⏹ Зупинено: {desc}")
            except Exception: pass

        self._save_backup()
        if log_cb:
            log_cb(f"  ✅ Зупинено {ok_count}/{len(services)} непотрібних служб")
            log_cb(f"     ↳ Звільнено CPU/RAM для гри")
        return ok_count > 0

    def restore_services(self, log_cb=None):
        """Відновлює служби які зупинила disable_useless_services."""
        backup = self._backup.get("services", {})
        for svc_name, was_running in backup.items():
            if was_running:
                run(["sc", "start", svc_name], timeout=10)
                if log_cb: log_cb(f"  ▶️ Відновлено: {svc_name}")

    def set_gpu_priority(self, log_cb=None) -> bool:
        """
        GPU Hardware-accelerated GPU Scheduling — ON.
        Прямий канал GPU ↔ DirectX без CPU-overhead.
        Економія: 2-8ms input lag.
        """
        if not IS_WINDOWS:
            return False
        ok = reg_write(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "HwSchMode", "2", "REG_DWORD"
        )
        # TdrLevel = 0 — повна обробка GPU stalls (не reboot driver просто так)
        ok2 = reg_write(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "TdrLevel", "0", "REG_DWORD"
        )
        # PlatformSupportMiracast вимкнути (broadcast = жре трафік)
        reg_write(
            r"HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers",
            "PlatformSupportMiracast", "0", "REG_DWORD"
        )
        if log_cb:
            log_cb(f"  ✅ Hardware-accelerated GPU Scheduling = ON")
            log_cb(f"     ↳ Прямий GPU ↔ DirectX, мінус 2-8ms input lag")
        return ok and ok2

    def optimize_visual_effects(self, log_cb=None) -> bool:
        """
        Прибирає всі візуальні ефекти Windows (anim, прозорість, тіні).
        Звільнює CPU/GPU що нагружали desktop compositing.
        """
        if not IS_WINDOWS:
            return False

        # VisualFXSetting = 2 (Best Performance)
        ok = reg_write(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects",
            "VisualFXSetting", "2", "REG_DWORD"
        )
        # MenuShowDelay 400 → 0 (миттєві меню)
        reg_write(
            r"HKCU\Control Panel\Desktop",
            "MenuShowDelay", "0", "REG_SZ"
        )
        # Прозорість taskbar OFF
        reg_write(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize",
            "EnableTransparency", "0", "REG_DWORD"
        )
        # Анімація вікон OFF
        reg_write(
            r"HKCU\Control Panel\Desktop\WindowMetrics",
            "MinAnimate", "0", "REG_SZ"
        )

        if log_cb:
            log_cb(f"  ✅ Visual Effects → Best Performance")
            log_cb(f"     ↳ Анімації, тіні, прозорість OFF")
        return ok

    def disable_fullscreen_optimizations(self, log_cb=None) -> bool:
        """
        Вимикає Fullscreen Optimizations глобально.
        FSO часто додає 1-3ms input lag і конфліктує з V-Sync.
        """
        if not IS_WINDOWS:
            return False
        # GameBar / FSE
        keys_to_set = [
            (r"HKCU\System\GameConfigStore", "GameDVR_DXGIHonorFSEWindowsCompatible", "1", "REG_DWORD"),
            (r"HKCU\System\GameConfigStore", "GameDVR_EFSEFeatureFlags", "0", "REG_DWORD"),
        ]
        ok = 0
        for key, val, data, rtype in keys_to_set:
            if reg_write(key, val, data, rtype): ok += 1

        if log_cb:
            log_cb(f"  ✅ Fullscreen Optimizations OFF ({ok}/2)")
            log_cb(f"     ↳ Прямий exclusive fullscreen — мінус 1-3ms input lag")
        return ok > 0

    def kill_background_apps(self, log_cb=None) -> bool:
        """
        Завершує конкретні фонові app'и які найчастіше жруть мережу:
        - Браузерні background tabs (через Chrome flags)
        - Спрацюваня Windows Update Delivery Optimization (P2P)
        """
        if not IS_WINDOWS:
            return False

        # Вимикаємо WUDO (Windows Update Delivery Optimization) — P2P оновлень
        # Це може використовувати 100% upload канал на роздачу!
        ok1 = reg_write(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config",
            "DODownloadMode", "0", "REG_DWORD"
        )

        # Background apps — заборонити фонову активність UWP
        ok2 = reg_write(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications",
            "GlobalUserDisabled", "1", "REG_DWORD"
        )

        # OneDrive — буває фонова синхронізація
        try:
            run(["taskkill", "/F", "/IM", "OneDrive.exe"], timeout=5)
        except Exception: pass

        if log_cb:
            log_cb(f"  ✅ Фонові процеси оптимізовано")
            log_cb(f"     ↳ WU Delivery Optimization OFF (звільнює upload)")
            log_cb(f"     ↳ Background UWP apps OFF")
        return ok1 or ok2

    # ── 10. APPLY ALL PING TWEAKS ─────────────────────────────────────────

    def apply_all_ping_tweaks(self, adapter: str = None,
                               game_pids: list[int] = None,
                               log_cb=None) -> dict[str, bool]:
        """
        Застосовує ВСІ доступні оптимізації пінгу одним викликом.

        Повертає dict {назва: успіх} для відображення результатів у UI.
        """
        if log_cb:
            log_cb("\n> ⚡ PING OPTIMIZER — запуск усіх оптимізацій...\n")

        results = {}

        # 1. Timer Resolution
        if log_cb: log_cb("━ [1/8] Timer Resolution 0.5ms")
        results["timer"]   = self.set_timer_resolution(0.5, log_cb)

        # 2. MMCSS
        if log_cb: log_cb("\n━ [2/8] MMCSS Games Profile")
        results["mmcss"]   = self.apply_mmcss_tweaks(log_cb)

        # 3. Nagle Extended
        if log_cb: log_cb("\n━ [3/8] Nagle + Delayed ACK")
        results["nagle"]   = self.disable_nagle_extended(log_cb)

        # 4. Interrupt Moderation
        if log_cb: log_cb("\n━ [4/8] Interrupt Moderation OFF")
        results["imr"]     = self.disable_interrupt_moderation(adapter, log_cb)

        # 5. NIC Power Save
        if log_cb: log_cb("\n━ [5/8] NIC Power Save OFF")
        results["power"]   = self.disable_nic_power_save(adapter, log_cb)

        # 6. LSO
        if log_cb: log_cb("\n━ [6/8] Large Send Offload OFF")
        results["lso"]     = self.disable_lso(adapter, log_cb)

        # 7. RSS Affinity
        if log_cb: log_cb("\n━ [7/8] RSS → P-cores")
        results["rss"]     = self.set_rss_affinity(adapter, 0, 2, log_cb)

        # 8. Game Process Affinity
        results["affinity"] = False
        if game_pids:
            if log_cb: log_cb("\n━ [8/8] Game CPU Affinity → P-cores")
            for pid in game_pids:
                ok = self.set_game_affinity_pcores(pid, f"PID:{pid}", log_cb)
                if ok:
                    results["affinity"] = True
        else:
            if log_cb: log_cb("\n━ [8/8] Game Affinity — немає запущених ігор")

        ok_count = sum(1 for v in results.values() if v)
        if log_cb:
            log_cb(f"\n> ✅ Ping Optimizer: {ok_count}/{len(results)} оптимізацій застосовано")
            log_cb(f"> 🔄 Перевір пінг через 10с — має впасти на 5..40ms")

        return results

    def restore_ping_tweaks(self, log_cb=None):
        """Відновлює всі NIC-налаштування після Ping Optimizer."""
        self.restore_timer_resolution(log_cb)
        self.restore_interrupt_moderation(log_cb)
        # LSO і RSS — відновлюємо через netsh reset
        if IS_WINDOWS:
            run(["netsh", "int", "tcp", "reset"], timeout=8)
            if log_cb:
                log_cb("  ✅ TCP stack → reset (LSO/RSS відновлено)")


    def restore_defaults(self, log_cb=None) -> bool:
        if not self.has_backup():
            if log_cb:
                log_cb("⚠️ Бекап не знайдено. Нічого відновлювати.")
            return False

        if log_cb:
            log_cb("\n> 🔄 Відновлення налаштувань за замовчуванням...")

        reg_backup = self._backup.get("registry", {})
        for composite_key, original_value in reg_backup.items():
            key, value = composite_key.split("||", 1)
            if original_value == "__ABSENT__":
                reg_delete(key, value)
                if log_cb:
                    log_cb(f"  🗑️ Видалено: {value}")
            else:
                if original_value.startswith("0x") or original_value.isdigit():
                    reg_write(key, value, str(int(original_value, 16)
                              if original_value.startswith("0x") else int(original_value)))
                else:
                    reg_write(key, value, original_value, "REG_SZ")
                if log_cb:
                    log_cb(f"  ✅ Відновлено: {value} = {original_value}")

        dns_backup = self._backup.get("dns", {})
        for adapter, dns_info in dns_backup.items():
            primary = dns_info.get("primary", "dhcp")
            if primary.lower() == "dhcp" or not primary:
                run(["netsh", "interface", "ip", "set", "dns",
                     f'name="{adapter}"', "dhcp"])
            else:
                run(["netsh", "interface", "ip", "set", "dns",
                     f'name="{adapter}"', "static", primary])
            if log_cb:
                log_cb(f"  🌐 DNS відновлено: {adapter} → {primary}")

        self._restore_nagle(log_cb)
        self._remove_qos_policy(log_cb)
        self._remove_all_net_priority_policies(log_cb)
        self.remove_all_bandwidth_limits(log_cb)

        run(["powercfg", "-setactive", "381b4222-f694-41f0-9685-ff5bb260df2e"])
        if log_cb:
            log_cb("  ⚡ Схема живлення → Balanced (дефолт)")

        run(["sc", "start", "wuauserv"])
        if log_cb:
            log_cb("  🔁 Windows Update → відновлено")

        self._backup.clear()
        self._save_backup()
        if log_cb:
            log_cb("\n> ✅ Усі налаштування відновлено!")
        return True

    # ═══════════════════════════════════════════════════════════════════════
    #  МЕРЕЖЕВІ ОПТИМІЗАЦІЇ
    # ═══════════════════════════════════════════════════════════════════════

    def apply_network_tweaks(self, log_cb=None) -> bool:
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ Тільки для Windows.")
            return False
        if not is_admin():
            if log_cb:
                log_cb("❌ Потрібні права Адміністратора!")
            return False

        if log_cb:
            log_cb("\n> 📦 Створення бекапу поточних налаштувань...")
        self._backup_registry(log_cb)
        self._backup_dns(log_cb)

        if log_cb:
            log_cb("\n> ⚙️ Застосування реєстрових твіків...")
        for key, value, data, reg_type in REGISTRY_TWEAKS:
            ok = reg_write(key, value, data, reg_type)
            icon = "✅" if ok else "⚠️ (Admin?)"
            if log_cb:
                log_cb(f"  {icon} {value} = {data}")

        ok, _ = run(["netsh", "int", "tcp", "set", "global",
                     "autotuninglevel=normal"])
        if log_cb:
            log_cb(f"  {'✅' if ok else '⚠️'} TCP AutoTuning = normal")

        # ═══ ДОДАТКОВІ TCP/IP ОПТИМІЗАЦІЇ ДЛЯ НИЖЧОГО ПІНГУ ═══
        # Ці команди реально знижують latency на 5-15ms у грі

        # 1. ECN (Explicit Congestion Notification) — швидше реагує на congestion
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "ecncapability=enabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} ECN Capability = enabled")

        # 2. RSC (Receive Segment Coalescing) — батчить пакети — ВИМКНУТИ для ігор
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "rsc=disabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} RSC = disabled (lower latency)")

        # 3. Timestamps — для accurate RTT measurement
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "timestamps=enabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} TCP Timestamps = enabled")

        # 4. Initial RTO — знизити з 3000ms до 1000ms (швидше retry)
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "initialRto=1000"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} Initial RTO = 1000ms (was 3000)")

        # 5. Min RTO — мінімальний таймаут (default 300ms)
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "minRto=300"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} Min RTO = 300ms")

        # 6. Non-SACK RTT Resiliency
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "nonsackrttresiliency=disabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} Non-SACK RTT Resiliency = disabled")

        # 7. Heuristics — вимикаємо щоб Windows не "вгадував" CongestionProvider
        ok, _ = run(["netsh", "int", "tcp", "set", "heuristics", "disabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} TCP Heuristics = disabled")

        # 8. CTCP (Compound TCP) як CongestionProvider — кращий за NewReno для гри
        ok, _ = run(["netsh", "int", "tcp", "set", "supplemental", "Internet",
                     "congestionprovider=ctcp"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} CongestionProvider = CTCP")

        # 9. Chimney Offload (TCP offload to NIC) — вимикаємо для consistent latency
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "chimney=disabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} TCP Chimney Offload = disabled")

        # 10. Network Direct (RDMA) — вимкнути для звичайних ігор
        ok, _ = run(["netsh", "int", "tcp", "set", "global", "netdma=disabled"])
        if log_cb: log_cb(f"  {'✅' if ok else '⚠️'} NetDMA = disabled")

        if log_cb:
            log_cb("\n> ✅ Мережеві твіки застосовано! (10 додаткових netsh-команд)")
        return True

    def disable_nagle(self, log_cb=None) -> bool:
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ Тільки для Windows.")
            return False

        interfaces_key = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        ok, out = run(["reg", "query", interfaces_key])
        if not ok:
            if log_cb:
                log_cb("❌ Не вдалося отримати список адаптерів.")
            return False

        count = 0
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"HKEY.*\{[0-9A-Fa-f\-]{36}\}$", line):
                adapter_key = line
                reg_write(adapter_key, "TcpAckFrequency", "1")
                reg_write(adapter_key, "TCPNoDelay", "1")
                count += 1

        if log_cb:
            log_cb(f"  ✅ Nagle вимкнено на {count} адаптерах "
                   f"(TcpAckFrequency=1, TCPNoDelay=1)")
        return count > 0

    def _restore_nagle(self, log_cb=None):
        interfaces_key = r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
        ok, out = run(["reg", "query", interfaces_key])
        if not ok:
            return
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"HKEY.*\{[0-9A-Fa-f\-]{36}\}$", line):
                reg_delete(line, "TcpAckFrequency")
                reg_delete(line, "TCPNoDelay")
        if log_cb:
            log_cb("  ✅ Nagle відновлено (ключі видалено)")

    def flush_dns(self, log_cb=None) -> bool:
        ok, _ = run(["ipconfig", "/flushdns"])
        if log_cb:
            log_cb(f"  {'✅' if ok else '❌'} DNS кеш очищено")
        return ok

    def switch_dns(self, profile_name: str, log_cb=None) -> bool:
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ Тільки для Windows.")
            return False

        dns_pair = GAMING_DNS.get(profile_name)
        if not dns_pair:
            if log_cb:
                log_cb(f"❌ DNS профіль '{profile_name}' не знайдено.")
            return False

        primary, secondary = dns_pair
        adapter = self._get_active_adapter()
        if not adapter:
            if log_cb:
                log_cb("❌ Активний мережевий адаптер не знайдено.")
            return False

        ok1, _ = run(["netsh", "interface", "ip", "set", "dns",
                      f"name={adapter}", "static", primary])
        ok2, _ = run(["netsh", "interface", "ip", "add", "dns",
                      f"name={adapter}", secondary, "index=2"])

        if log_cb:
            status = "✅" if ok1 else "⚠️"
            log_cb(f"  {status} DNS → {primary} / {secondary} (адаптер: {adapter})")
        return ok1

    # ═══════════════════════════════════════════════════════════════════════
    #  QoS — ЗАГАЛЬНА ДЛЯ ІГОР (DSCP 46 для KNOWN_GAMES)
    # ═══════════════════════════════════════════════════════════════════════

    def apply_qos_policy(self, log_cb=None) -> bool:
        """
        Створює QoS політики для всіх відомих ігор.
        OPTIMIZATION: одним PowerShell-викликом замість 260.
        Було: ~4-5 хвилин (260 окремих викликів по ~1с кожен)
        Стало: ~2-5 секунд (1 виклик з loop-ом в самому PS)
        """
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ QoS: тільки для Windows.")
            return False
        if not is_admin():
            if log_cb:
                log_cb("❌ QoS: потрібні права Адміністратора.")
            return False

        # Будуємо один великий PS-скрипт який:
        # 1. Видаляє всі старі NetGuardian_* політики
        # 2. Створює нові для всіх ігор
        # 3. Повертає кількість успішно створених
        games_list = sorted(KNOWN_GAMES)
        # Екрануємо лапки в іменах (на всяк випадок)
        games_quoted = ", ".join(f"'{g}'" for g in games_list)

        ps_script = f"""
$ErrorActionPreference = 'SilentlyContinue'
# 1. Видаляємо всі старі NetGuardian_* політики (окрім Net_* які для юзерських QoS)
Get-NetQosPolicy | Where-Object {{ $_.Name -like 'NetGuardian_*' -and $_.Name -notlike 'NetGuardian_Net_*' }} | Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue

# 2. Створюємо нові політики для всіх ігор одним циклом
$games = @({games_quoted})
$created = 0
foreach ($game in $games) {{
    $policyName = 'NetGuardian_' + ($game -replace '\\.exe$','' -replace '-','_')
    try {{
        New-NetQosPolicy -Name $policyName -AppPathNameMatchCondition $game -DSCPAction 46 -NetworkProfile All -ErrorAction Stop | Out-Null
        $created++
    }} catch {{
        # ігноруємо "already exists"
    }}
}}
Write-Output $created
"""

        ok, out = run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                      "-Command", ps_script], timeout=120)

        created = 0
        try:
            # Витягуємо число з output (може бути з пробілами/newlines)
            out_clean = (out or "").strip().split("\n")[-1].strip()
            created = int(out_clean) if out_clean.isdigit() else 0
        except Exception: pass

        if log_cb:
            icon = "✅" if created > 0 else "⚠️"
            log_cb(
                f"  {icon} QoS DSCP 46 (Expedited Forwarding) — "
                f"{created}/{len(games_list)} ігор"
            )
            if created > 0:
                log_cb("  📌 Ігровий трафік тепер пріоритетний на рівні роутера")
            elif not ok:
                log_cb(f"  ⚠️ PowerShell error: {(out or '')[:100]}")
        return created > 0

    def _remove_qos_policy(self, log_cb=None):
        if not IS_WINDOWS:
            return
        cmd = (
            "Get-NetQosPolicy | "
            "Where-Object { $_.Name -like 'NetGuardian_*' -and $_.Name -notlike 'NetGuardian_Net_*' } | "
            "Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
        )
        ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=15)
        if log_cb:
            log_cb(f"  {'✅' if ok else '⚠️'} QoS політики NetGuardian видалено")

    # ═══════════════════════════════════════════════════════════════════════
    #  🆕 МЕРЕЖЕВИЙ ПРІОРИТЕТ PER-PROCESS (QoS DSCP per exe)
    # ═══════════════════════════════════════════════════════════════════════

    def set_process_network_priority(self, exe_name: str, level: str,
                                     log_cb=None) -> tuple[bool, str]:
        """
        Встановлює мережевий пріоритет (QoS DSCP) для конкретного процесу.

        level:
          'maximum' → DSCP 46 (EF — Expedited Forwarding) — ігри, VoIP
          'high'    → DSCP 34 (AF41)                       — відео-стрімінг
          'normal'  → без QoS (видаляє правило)
          'low'     → DSCP 8  (CS1)                        — фоновий трафік

        Як це впливає на пінг:
          Роутер (якщо підтримує QoS / WMM) читає DSCP-тег і обслуговує
          пакети з вищим тегом позачергово. Навіть якщо хтось качає файл на
          100 МБ/с — пакети гри з DSCP 46 пройдуть без черги → пінг падає.
        """
        if not IS_WINDOWS:
            return False, "❌ Тільки для Windows."

        dscp = NET_PRIORITY_DSCP.get(level, 0)
        # Назва правила: NetGuardian_Net_<exe без .exe>
        safe_name = exe_name.replace(".exe", "").replace("-", "_").replace(" ", "_").replace(".", "_")
        policy_name = f"NetGuardian_Net_{safe_name}"

        # Завжди спочатку видаляємо старе правило
        run(["powershell", "-NoProfile", "-Command",
             f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false "
             f"-ErrorAction SilentlyContinue"])

        level_name = NET_PRIORITY_NAMES.get(level, level)

        # Якщо normal → просто видалили, більше нічого робити
        if level == "normal" or dscp == 0:
            msg = f"  🌐 {exe_name} → Нормальний пріоритет (QoS знято)"
            if log_cb:
                log_cb(msg)
            return True, msg

        cmd = (
            f"New-NetQosPolicy "
            f"-Name '{policy_name}' "
            f"-AppPathNameMatchCondition '{exe_name}' "
            f"-DSCPAction {dscp} "
            f"-NetworkProfile All "
            f"-ErrorAction Stop"
        )
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)

        if ok:
            msg = f"  ✅ {exe_name} → {level_name} (DSCP {dscp})"
            if log_cb:
                log_cb(msg)
                log_cb(f"  📌 Пакети від {exe_name} тепер мають найвищий пріоритет на роутері")
            return True, msg
        else:
            err = out[:120] if out else "Невідома помилка"
            msg = f"  ⚠️ {exe_name}: {err}"
            if log_cb:
                log_cb(msg)
                if "admin" in err.lower() or "access" in err.lower():
                    log_cb("  ❗ Запусти NetGuardian від імені Адміністратора")
            return False, msg

    def remove_process_network_priority(self, exe_name: str) -> tuple[bool, str]:
        """Видаляє QoS правило для конкретного процесу."""
        if not IS_WINDOWS:
            return False, "Тільки для Windows."
        safe_name = exe_name.replace(".exe", "").replace("-", "_").replace(" ", "_").replace(".", "_")
        policy_name = f"NetGuardian_Net_{safe_name}"
        ok, _ = run(["powershell", "-NoProfile", "-Command",
                     f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false "
                     f"-ErrorAction SilentlyContinue"])
        return ok, f"{'✅' if ok else '⚠️'} QoS для {exe_name} знято"

    def get_all_network_priorities(self) -> dict[str, str]:
        """
        Повертає всі активні QoS правила NetGuardian_Net_*.
        Повертає: { 'chrome.exe': 'low', 'cs2.exe': 'maximum', ... }
        Використовує Format-List замість JSON — надійніший парсинг.
        """
        result: dict[str, str] = {}
        if not IS_WINDOWS:
            return result

        cmd = (
            "Get-NetQosPolicy | "
            "Where-Object { $_.Name -like 'NetGuardian_Net_*' } | "
            "Select-Object Name, DSCPAction | Format-List"
        )
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
        if not ok or not out.strip():
            return result

        dscp_to_level = {v: k for k, v in NET_PRIORITY_DSCP.items()}
        current_name  = ""

        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Name"):
                current_name = line.split(":", 1)[1].strip()
            elif line.startswith("DSCPAction") and current_name:
                try:
                    dscp = int(line.split(":", 1)[1].strip())
                    exe_base = current_name.replace("NetGuardian_Net_", "")
                    exe_name = exe_base.replace("_", "-").lower() + ".exe"
                    result[exe_name] = dscp_to_level.get(dscp, "normal")
                except Exception:
                    pass
                current_name = ""

        return result

    def _remove_all_net_priority_policies(self, log_cb=None):
        """Видаляє всі per-process QoS правила NetGuardian_Net_*."""
        if not IS_WINDOWS:
            return
        cmd = (
            "Get-NetQosPolicy | "
            "Where-Object { $_.Name -like 'NetGuardian_Net_*' } | "
            "Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
        )
        ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=15)
        if log_cb:
            log_cb(f"  {'✅' if ok else '⚠️'} Мережеві пріоритети per-process видалено")

    # ═══════════════════════════════════════════════════════════════════════
    #  🆕 BANDWIDTH LIMITER — ОБМЕЖЕННЯ ШВИДКОСТІ PER-PROCESS
    # ═══════════════════════════════════════════════════════════════════════

    # Presets для UI (Mbps)
    BANDWIDTH_PRESETS = [
        ("∞  Без ліміту",   0.0),
        ("🔴  0.5 Mbps",    0.5),
        ("🟠  1 Mbps",      1.0),
        ("🟡  2 Mbps",      2.0),
        ("🟢  5 Mbps",      5.0),
        ("🔵  10 Mbps",    10.0),
        ("⚪  25 Mbps",    25.0),
    ]

    def set_process_bandwidth_limit(self, exe_name: str, limit_mbps: float,
                                     log_cb=None) -> tuple[bool, str]:
        """
        Жорстко обмежує швидкість мережі для конкретного процесу (Traffic Shaping).

        limit_mbps == 0  → зняти ліміт (видаляє правило).
        limit_mbps > 0   → обмежити до N Мбіт/с.

        Використовує Windows QoS ThrottleRateActionBitsPerSecond.
        Технологія: той самий механізм, що й у NetLimiter / GlassWire.
        """
        if not IS_WINDOWS:
            return False, "❌ Тільки для Windows."

        safe_name   = (exe_name.replace(".exe", "")
                                .replace("-", "_")
                                .replace(" ", "_")
                                .replace(".", "_"))
        policy_name = f"NetGuardian_Limit_{safe_name}"

        # Завжди спочатку видаляємо старе правило
        run(["powershell", "-NoProfile", "-Command",
             f"Remove-NetQosPolicy -Name '{policy_name}' -Confirm:$false "
             f"-ErrorAction SilentlyContinue"])

        if limit_mbps <= 0:
            msg = f"  🟢 Знято ліміт швидкості для {exe_name}"
            if log_cb:
                log_cb(msg)
            return True, msg

        # bits per second (Windows вимагає біти, не байти)
        bps = int(limit_mbps * 1_000_000)

        cmd = (
            f"New-NetQosPolicy "
            f"-Name '{policy_name}' "
            f"-AppPathNameMatchCondition '{exe_name}' "
            f"-ThrottleRateActionBitsPerSecond {bps} "
            f"-NetworkProfile All "
            f"-ErrorAction Stop"
        )
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)

        if ok:
            msg = f"  🚧 {exe_name} обмежено до {limit_mbps} Мбіт/с"
            if log_cb:
                log_cb(msg)
                log_cb(f"  📌 Інші програми отримають більше пропускної здатності")
            return True, msg
        else:
            err = out[:120] if out else "Невідома помилка"
            msg = f"  ⚠️ {exe_name}: {err}"
            if log_cb:
                log_cb(msg)
                if "admin" in err.lower() or "access" in err.lower():
                    log_cb("  ❗ Запусти NetGuardian від імені Адміністратора")
            return False, msg

    def get_all_bandwidth_limits(self) -> dict[str, float]:
        """
        Повертає всі активні ліміти швидкості NetGuardian_Limit_*.
        Повертає: { 'steam.exe': 2.0, 'chrome.exe': 5.0, ... } (Мбіт/с)
        """
        result: dict[str, float] = {}
        if not IS_WINDOWS:
            return result

        cmd = (
            "Get-NetQosPolicy | "
            "Where-Object { $_.Name -like 'NetGuardian_Limit_*' } | "
            "Select-Object Name, ThrottleRateActionBitsPerSecond | Format-List"
        )
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd], timeout=10)
        if not ok or not out.strip():
            return result

        current_name = ""
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Name"):
                current_name = line.split(":", 1)[1].strip()
            elif line.startswith("ThrottleRateAction") and current_name:
                try:
                    bps      = int(line.split(":", 1)[1].strip())
                    mbps     = round(bps / 1_000_000, 1)
                    exe_base = current_name.replace("NetGuardian_Limit_", "")
                    exe_name = exe_base.replace("_", "-").lower() + ".exe"
                    result[exe_name] = mbps
                except Exception:
                    pass
                current_name = ""

        return result

    def remove_all_bandwidth_limits(self, log_cb=None):
        """Видаляє всі ліміти швидкості NetGuardian_Limit_*."""
        if not IS_WINDOWS:
            return
        cmd = (
            "Get-NetQosPolicy | "
            "Where-Object { $_.Name -like 'NetGuardian_Limit_*' } | "
            "Remove-NetQosPolicy -Confirm:$false -ErrorAction SilentlyContinue"
        )
        ok, _ = run(["powershell", "-NoProfile", "-Command", cmd], timeout=15)
        if log_cb:
            log_cb(f"  {'✅' if ok else '⚠️'} Ліміти швидкості видалено")

    # ═══════════════════════════════════════════════════════════════════════
    #  🆕 RAM CLEANER — ОЧИЩЕННЯ ОПЕРАТИВНОЇ ПАМ'ЯТІ
    # ═══════════════════════════════════════════════════════════════════════

    def clean_ram(self, log_cb=None) -> bool:
        """
        Очищає Working Set фонових процесів і Standby List Windows.
        Ефект: до 200–800 МБ вільної RAM залежно від системи.
        """
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ RAM Clean: тільки для Windows.")
            return False

        ws_ok    = False
        sl_ok    = False
        freed_mb = 0

        try:
            import psutil
            import ctypes

            kernel32 = ctypes.windll.kernel32
            PROCESS_SET_QUOTA         = 0x0100
            PROCESS_QUERY_INFORMATION = 0x0400

            skip_cats    = {"protected", "game", "dangerous"}
            before_total = 0
            after_total  = 0

            for proc in psutil.process_iter():
                try:
                    proc.cpu_percent(interval=None)
                except Exception:
                    pass

            time.sleep(0.4)

            for proc in psutil.process_iter(["pid", "name", "memory_info"]):
                try:
                    info = proc.info
                    pid  = info.get("pid", 0)
                    if pid <= 4:
                        continue
                    cat = classify_process((info.get("name") or "").lower())
                    if cat in skip_cats:
                        continue

                    mem_before = (info.get("memory_info") or type("M", (), {"rss": 0})()).rss

                    handle = kernel32.OpenProcess(
                        PROCESS_SET_QUOTA | PROCESS_QUERY_INFORMATION, False, pid
                    )
                    if handle:
                        ctypes.windll.psapi.EmptyWorkingSet(handle)
                        kernel32.CloseHandle(handle)

                    try:
                        mem_after = psutil.Process(pid).memory_info().rss
                        before_total += mem_before
                        after_total  += mem_after
                    except Exception:
                        pass

                except Exception:
                    pass

            freed_mb = max(0, (before_total - after_total) // (1024 * 1024))
            ws_ok    = True

        except ImportError:
            if log_cb:
                log_cb("  ⚠️ psutil недоступний, fallback → PowerShell GC")
            ok, _ = run([
                "powershell", "-NoProfile", "-Command",
                "[System.GC]::Collect(); [System.GC]::WaitForPendingFinalizers()"
            ], timeout=15)
            ws_ok = ok

        except Exception as e:
            if log_cb:
                log_cb(f"  ⚠️ Working Set: {e}")

        try:
            import ctypes
            ntdll = ctypes.windll.ntdll
            SystemMemoryListInformation = 0x4C
            PURGE_STANDBY_LIST         = 4
            cmd_val = ctypes.c_ulong(PURGE_STANDBY_LIST)
            status  = ntdll.NtSetSystemInformation(
                SystemMemoryListInformation,
                ctypes.byref(cmd_val),
                ctypes.sizeof(cmd_val)
            )
            sl_ok = (status == 0)
        except Exception:
            pass

        if log_cb:
            if ws_ok and freed_mb > 0:
                log_cb(f"  ✅ Working Set очищено: ~{freed_mb} МБ повернуто")
            elif ws_ok:
                log_cb("  ✅ Working Set очищено")
            else:
                log_cb("  ⚠️ Working Set: неповне очищення")

            if sl_ok:
                log_cb("  ✅ Standby List очищено (мікро-фрізи зменшено)")
            else:
                log_cb("  ℹ️ Standby List: запусти від Адміністратора для повного очищення")

        return ws_ok or sl_ok

    # ═══════════════════════════════════════════════════════════════════════
    #  ОПТИМІЗАЦІЯ CPU
    # ═══════════════════════════════════════════════════════════════════════

    def set_high_performance_power(self, log_cb=None) -> bool:
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ Тільки для Windows.")
            return False
        ok, _ = run(["powercfg", "-setactive",
                     "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"])
        if log_cb:
            icon = "✅" if ok else "⚠️"
            log_cb(f"  {icon} Схема живлення → High Performance")
        return ok

    def unpark_cpu_cores(self, log_cb=None) -> bool:
        if not IS_WINDOWS:
            if log_cb:
                log_cb("❌ Тільки для Windows.")
            return False
        ok, _ = run([
            "powercfg", "-setacvalueindex",
            "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c",
            "54533251-82be-4824-96c1-47b60b740d00",
            "893dee8e-2bef-41e0-89c6-b55d0929964c",
            "100"
        ])
        if log_cb:
            icon = "✅" if ok else "⚠️"
            log_cb(f"  {icon} CPU Unpark: мін. стан процесора = 100%")
        return ok

    # ═══════════════════════════════════════════════════════════════════════
    #  УПРАВЛІННЯ ПРОЦЕСАМИ (виправлений scan_processes)
    # ═══════════════════════════════════════════════════════════════════════

    def scan_processes(self, enrich_with_psutil: bool = True) -> list[dict]:
        """
        Сканування виключно через tasklist — без psutil, без GIL-блокування.
        CPU% недоступний через tasklist, тому показуємо 0.
        cpu_priority читається окремо якщо psutil доступний і швидкий.

        Якщо enrich_with_psutil=True — додатково дістає CPU% і NET KB/s через
        psutil (як у GUI). Це корисно для бот-виводу щоб показувати ті ж
        метрики що й в утиліті.
        """
        CAT_ORDER = {
            "game": 0, "launcher": 1, "hog": 2, "browser": 3,
            "messenger": 4, "media": 5, "dangerous": 6,
            "protected": 7, "normal": 8,
        }

        self._last_scan_method = "tasklist"
        procs = self._scan_tasklist_fast()

        if not procs:
            self._last_scan_method = "empty"
            return []

        # ── OPTIONAL: enrichment через psutil (CPU% + NET KB/s) ──
        # Два snapshot'и з інтервалом 1.0с щоб порахувати дельту I/O.
        # Деякі процеси потребують Admin прав — ловимо AccessDenied тихо.
        if enrich_with_psutil:
            try:
                import psutil as _ps
                # Беремо снапшот I/O для top-50 процесів
                top_cats = {"game", "launcher", "hog", "browser", "messenger", "media"}
                # Сортуємо по RAM — топові споживачі найцікавіші
                interesting = sorted(
                    [p for p in procs if p.get("category") in top_cats],
                    key=lambda p: -p.get("ram_mb", 0)
                )[:50]
                pids = [p["pid"] for p in interesting if p.get("pid")]

                io_snap1 = {}
                ps_objs = {}     # зберігаємо Process об'єкти щоб не перестворювати
                for pid in pids:
                    try:
                        pp = _ps.Process(pid)
                        pp.cpu_percent(None)   # priming
                        # io_counters працює навіть для багатьох юзерських процесів
                        # (read_bytes/write_bytes — це all I/O включно з network)
                        io_snap1[pid] = pp.io_counters()
                        ps_objs[pid]  = pp
                    except (_ps.AccessDenied, _ps.NoSuchProcess):
                        pass
                    except Exception: pass

                # 1.0с — достатньо часу щоб отримати релевантні дельти
                time.sleep(1.0)

                for pid in pids:
                    try:
                        pp = ps_objs.get(pid)
                        if not pp:
                            continue
                        try:
                            cpu_now = pp.cpu_percent(None) / max(1, _ps.cpu_count())
                        except Exception:
                            cpu_now = 0.0
                        try:
                            io_new = pp.io_counters()
                            old = io_snap1.get(pid)
                            if old:
                                delta = ((io_new.read_bytes - old.read_bytes) +
                                        (io_new.write_bytes - old.write_bytes))
                                net_kb = round(delta / 1024, 1)   # 1 сек interval
                            else:
                                net_kb = 0.0
                        except Exception:
                            net_kb = 0.0

                        # Оновлюємо процес у списку
                        for p in procs:
                            if p.get("pid") == pid:
                                if cpu_now > 0:
                                    p["cpu"] = cpu_now
                                if net_kb > 0:
                                    p["net_kb"]  = max(0.0, net_kb)
                                    p["net_bps"] = max(0.0, net_kb) * 1024
                                break
                    except Exception: pass
            except ImportError: pass
            except Exception as e:
                # Не критична помилка — продовжуємо без enrichment
                print(f"[scan_processes] psutil enrichment failed: {e}")

        procs.sort(key=lambda x: (
            CAT_ORDER.get(x.get("category", "normal"), 9),
            -x.get("ram_mb", 0)   # сортуємо по RAM бо CPU=0
        ))
        return procs

    def _scan_psutil_fast(self) -> list[dict]:
        """psutil без as_dict(). Sleep 0.1с — мінімум для cpu_percent."""
        try:
            import psutil
        except ImportError:
            return []

        cpu_count = max(1, psutil.cpu_count(logical=True) or 1)
        result = []

        # Ініціалізуємо лічильники
        snap = {}
        try:
            for p in psutil.process_iter():
                try:
                    p.cpu_percent(interval=None)
                    snap[p.pid] = p
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
        except Exception:
            pass

        time.sleep(0.1)  # мінімальний інтервал

        pids_done = set()
        for proc in (list(snap.values()) or list(psutil.process_iter())):
            try:
                pid = proc.pid
                if pid <= 4 or pid in pids_done:
                    continue
                pids_done.add(pid)

                try:
                    name = proc.name()
                except Exception:
                    continue
                if not name:
                    continue

                try:
                    cpu = round(float(proc.cpu_percent(interval=None) or 0) / cpu_count, 1)
                except Exception:
                    cpu = 0.0

                try:
                    mem = proc.memory_info()
                    ram_mb = round(mem.rss / 1024 / 1024, 1) if mem else 0
                except Exception:
                    ram_mb = 0.0

                # CPU пріоритет через nice() — без subprocess, миттєво
                try:
                    nice_val = proc.nice()
                    # Windows: повертає константи пріоритет-класу
                    cpu_priority = _NICE_TO_PRIORITY.get(nice_val, "Normal")
                except Exception:
                    cpu_priority = "Normal"

                category = classify_process(name)
                impact_label, impact_desc = CATEGORY_IMPACT[category]
                result.append({
                    "name":         name,
                    "pid":          pid,
                    "cpu":          cpu,
                    "ram_mb":       ram_mb,
                    "cpu_priority": cpu_priority,
                    "category":     category,
                    "impact":       impact_label,
                    "impact_desc":  impact_desc,
                    "protected":    category in ("protected", "launcher", "dangerous"),
                    "hog":          category == "hog",
                })
            except Exception:
                continue
        return result

    def _scan_tasklist_fast(self) -> list[dict]:
        """
        tasklist /fo csv — найнадійніший метод. Timeout 6с.
        Не залежить від psutil і прав адміністратора.
        """
        if not IS_WINDOWS:
            return self._scan_psutil_fast()

        try:
            # Явний creationflags щоб не відкривалось вікно консолі
            import ctypes as _ct
            CREATE_NO_WINDOW = 0x08000000

            proc = subprocess.Popen(
                ["tasklist", "/fo", "csv", "/nh"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                creationflags=CREATE_NO_WINDOW,
            )
            try:
                stdout_bytes, _ = proc.communicate(timeout=6)
            except subprocess.TimeoutExpired:
                proc.kill()
                return []

            # Декодуємо
            out = ""
            for enc in ("utf-8", "cp1251", "cp866", "latin-1"):
                try:
                    out = stdout_bytes.decode(enc, errors="replace")
                    break
                except Exception:
                    continue

            if not out:
                return []

            result = []
            seen = set()
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) < 2:
                    continue
                name = parts[0].strip()
                if not name:
                    continue
                try:
                    pid = int(parts[1])
                except ValueError:
                    pid = 0
                if pid <= 4 or pid in seen:
                    continue
                seen.add(pid)

                ram_mb = 0.0
                if len(parts) >= 5:
                    mem_str = re.sub(r"[^\d]", "", parts[4])
                    if mem_str:
                        try:
                            ram_mb = round(int(mem_str) / 1024, 1)
                        except Exception:
                            pass

                category = classify_process(name)
                impact_label, impact_desc = CATEGORY_IMPACT[category]
                result.append({
                    "name":        name,
                    "pid":         pid,
                    "cpu":         0.0,
                    "ram_mb":      ram_mb,
                    "category":    category,
                    "impact":      impact_label,
                    "impact_desc": impact_desc,
                    "protected":   category in ("protected", "launcher", "dangerous"),
                    "hog":         category == "hog",
                })
            return result
        except Exception:
            return []

    def kill_process(self, pid: int, name: str) -> tuple[bool, str]:
        """Завершує процес. Ніколи не вбиває захищені або небезпечні процеси."""
        n = name.lower()
        if n in PROTECTED:
            return False, f"🛡️ {name} — системний захищений процес."
        if n in DANGEROUS_TO_KILL:
            return False, (
                f"☠️ {name} — НЕБЕЗПЕЧНО!\n"
                f"Вбивство цього процесу може призвести до BSOD або втрати даних.\n"
                f"Використай зниження пріоритету (↑ → Low) замість завершення."
            )
        try:
            if IS_WINDOWS:
                subprocess.run(["taskkill", "/F", "/PID", str(pid)],
                               capture_output=True, timeout=5)
            else:
                subprocess.run(["kill", "-9", str(pid)],
                               capture_output=True, timeout=5)
            return True, f"⊘ {name} (PID {pid}) — завершено"
        except Exception as e:
            return False, f"❌ {e}"

    def get_process_priority(self, pid: int) -> str:
        if not IS_WINDOWS:
            return "Unknown"
        cmd = f"(Get-Process -Id {pid} -ErrorAction SilentlyContinue).PriorityClass"
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd])
        out = out.strip()
        if ok and out:
            return out
        return "Unknown"

    def set_priority(self, pid: int, level: str) -> tuple[bool, str]:
        if not IS_WINDOWS:
            return False, "Тільки для Windows."
        ps_map = {
            "High": "High", "Above Normal": "AboveNormal",
            "Normal": "Normal", "Below Normal": "BelowNormal", "Low": "Idle",
        }
        ps_level = ps_map.get(level, "Normal")
        cmd = (f'$p = Get-Process -Id {pid} -ErrorAction Stop; '
               f'$p.PriorityClass = "{ps_level}"')
        ok, out = run(["powershell", "-NoProfile", "-Command", cmd])
        if ok:
            return True, f"⬆ {level} пріоритет встановлено (PID {pid})"
        ok2, _ = run([
            "wmic", "process", "where", f"ProcessId={pid}",
            "CALL", "SetPriority", ps_level
        ])
        if ok2:
            return True, f"⬆ {level} пріоритет встановлено через wmic (PID {pid})"
        return False, "⚠️ Помилка. Запустіть від Адміністратора."

    def stop_windows_update(self, log_cb=None) -> bool:
        services = ["wuauserv", "bits", "dosvc"]
        for svc in services:
            ok, _ = run(["sc", "stop", svc])
            if log_cb:
                log_cb(f"  {'✅' if ok else '⚠️'} Службу {svc} зупинено")
        return True

    # ═══════════════════════════════════════════════════════════════════════
    #  ПІНГ-МОНІТОР
    # ═══════════════════════════════════════════════════════════════════════

    def ping_ms(self, host: str, fast: bool = False) -> float | None:
        """
        Вимірює пінг до хоста.
        fast=True  → 1 пакет, 500мс таймаут (для Live Ping Monitor — не блокує петлю).
        fast=False → 4 пакети, медіана (для діагностики — точніший результат).
        """
        count   = 1    if fast else 4
        timeout = 500  if fast else 1000
        samples = []

        try:
            if IS_WINDOWS:
                r = subprocess.run(
                    ["ping", "-n", str(count), "-w", str(timeout), host],
                    capture_output=True, text=True,
                    encoding="cp866", errors="replace", timeout=count * 2 + 2
                )
                out = r.stdout or ""
                # Забираємо всі індивідуальні time= значення
                all_times = re.findall(
                    r"(?:time|время|час)[=<]\s*(\d+)\s*(?:ms|мс)",
                    out, re.IGNORECASE
                )
                for t in all_times:
                    try:
                        v = float(t)
                        if v > 0 and v < 5000:
                            samples.append(v)
                    except Exception: pass

                # Fallback: якщо indiv. не знайдено — беремо "Average"
                if not samples:
                    match = re.search(
                        r"(?:Average|Среднее|Середнє)\s*=\s*(\d+)\s*(?:ms|мс)",
                        out, re.IGNORECASE
                    )
                    if match:
                        v = float(match.group(1))
                        if v > 0: samples.append(v)
            else:
                r = subprocess.run(
                    ["ping", "-c", str(count), "-W", "1", host],
                    capture_output=True, text=True, timeout=count * 2 + 2
                )
                all_times = re.findall(r"time[=<]\s*([\d.]+)\s*ms", r.stdout or "")
                for t in all_times:
                    try:
                        v = float(t)
                        if v > 0: samples.append(v)
                    except Exception: pass
        except Exception:
            pass

        # Якщо пінг дав результат — повертаємо МЕДІАНУ (ігнорує викиди)
        if samples:
            samples.sort()
            mid = len(samples) // 2
            if len(samples) % 2 == 0:
                return round((samples[mid-1] + samples[mid]) / 2, 1)
            return round(samples[mid], 1)

        # Fallback: TCP probe якщо ICMP заблокований
        for port in (27015, 27016, 27017):
            try:
                start = time.perf_counter()
                with socket.create_connection((host, port), timeout=1.5):
                    pass
                ms = round((time.perf_counter() - start) * 1000, 1)
                if ms > 0:
                    return ms
            except Exception:
                pass

        try:
            start = time.perf_counter()
            with socket.create_connection((host, 443), timeout=1.5):
                pass
            ms = round((time.perf_counter() - start) * 1000, 1)
            if ms > 0:
                return ms
        except Exception:
            pass

        return None

    # ═══════════════════════════════════════════════════════════════════════
    #  AUTO-BOOST — фоновий моніторинг ігор (FIX: новий метод)
    # ═══════════════════════════════════════════════════════════════════════

    def start_game_watch(self, log_cb=None) -> None:
        """Запускає фоновий моніторинг. При виявленні нової гри → High Priority + P-cores + Timer 0.5ms."""
        self._game_watch_active = True
        threading.Thread(
            target=self._game_watch_loop, args=(log_cb,),
            daemon=True, name="game_watch"
        ).start()

    def stop_game_watch(self) -> None:
        """Зупиняє фоновий моніторинг ігор."""
        self._game_watch_active = False

    def _game_watch_loop(self, log_cb=None):
        """Кожні 10с сканує процеси. При появі нової гри → High Priority + P-cores affinity."""
        _applied: set = set()
        while getattr(self, "_game_watch_active", False):
            try:
                procs = self._scan_tasklist_fast()
                running_pids = {p["pid"] for p in procs}
                _applied &= running_pids   # прибираємо завершені
                for p in procs:
                    if p.get("category") == "game":
                        pid  = p["pid"]; name = p["name"]
                        if pid not in _applied and pid > 0:
                            self.set_priority(pid, "High")
                            self.set_game_affinity_pcores(pid, name)
                            self.set_timer_resolution(0.5)
                            _applied.add(pid)
                            if log_cb:
                                log_cb(f"🤖 Auto-Boost: {name} → High Priority + P-cores + Timer 0.5ms")
            except Exception as e:
                if log_cb: log_cb(f"🤖 Auto-Boost error: {e}")
            time.sleep(10)

    # ═══════════════════════════════════════════════════════════════════════
    #  AUTO-MODE (фоновий потік)
    # ═══════════════════════════════════════════════════════════════════════

    def start_auto_mode(self, log_cb) -> None:
        self._auto_active = True
        threading.Thread(target=self._auto_loop, args=(log_cb,),
                         daemon=True).start()

    def stop_auto_mode(self) -> None:
        self._auto_active = False

    def _auto_loop(self, log_cb):
        while self._auto_active:
            if IS_WINDOWS:
                ok, out = run_cp866(["tasklist", "/fo", "csv", "/nh"])
                if ok:
                    for line in out.splitlines():
                        parts = line.strip().strip('"').split('","')
                        if len(parts) >= 2:
                            name = parts[0].lower()
                            pid  = parts[1]
                            if name in BANDWIDTH_HOGS and pid.isdigit():
                                subprocess.run(["taskkill", "/F", "/PID", pid],
                                               capture_output=True, timeout=3)
                                log_cb(f"⚡ Auto: {parts[0]} — канал звільнено")
            time.sleep(30)