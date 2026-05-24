"""
NetGuardian AI — LAN Security Audit Engine v5.4.0
FIXES v5.4.0:
  FIX-1: block_device  — fallback до ARP-кешу ОС якщо Scapy не знаходить MAC
  FIX-2: diagnose      — всі блокуючі виклики обгорнуті в потоки з timeout
  FIX-3: Android/phone — Samsung SM-xxxx розпізнається з DHCP hostname
  FIX-4: Router name   — більше ендпоінтів + fallback на router_manager label
  FIX-5: PC hostname   — NetBIOS пріоритет, reverse_dns з timeout
  FIX-6: is_scanning   — прапорець + лічильник для UI scan-widget
"""

import subprocess, platform, socket, threading, time, re
import sqlite3, os, struct, json, urllib.request, urllib.parse
import base64, hashlib, http.cookiejar
from concurrent.futures import ThreadPoolExecutor, as_completed
import concurrent.futures as _cf
from typing import Optional

_OUI_DB: dict[str, tuple[str, str, str]] = {
    # ── Apple ──────────────────────────────────────────────────────
    "00:03:93":("Apple","Mac","💻"),         "00:0A:95":("Apple","Mac/MacBook","💻"),
    "00:17:F2":("Apple","AirPort","📡"),     "00:1D:4F":("Apple","iPhone/iPod","📱"),
    "00:1F:F3":("Apple","iPhone","📱"),      "00:26:BB":("Apple","AirPort/AppleTV","📺"),
    "04:0C:CE":("Apple","iPhone","📱"),      "04:26:65":("Apple","iPhone","📱"),
    "04:52:F3":("Apple","iPhone","📱"),      "04:DB:56":("Apple","iPhone","📱"),
    "08:66:98":("Apple","iPhone","📱"),      "08:70:45":("Apple","MacBook","💻"),
    "08:F4:AB":("Apple","iPhone","📱"),      "0C:3E:9F":("Apple","iPhone","📱"),
    "0C:74:C2":("Apple","iPhone","📱"),      "0C:D7:46":("Apple","iPad","📱"),
    "10:1C:0C":("Apple","iPhone","📱"),      "10:40:F3":("Apple","iPhone","📱"),
    "10:94:BB":("Apple","iPhone","📱"),      "10:9A:DD":("Apple","iPhone","📱"),
    "14:10:9F":("Apple","iPhone","📱"),      "14:5A:05":("Apple","iPhone","📱"),
    "14:8F:C6":("Apple","MacBook","💻"),     "18:65:90":("Apple","iPhone","📱"),
    "18:9E:FC":("Apple","iPhone","📱"),      "18:AF:61":("Apple","iPhone","📱"),
    "18:E7:F4":("Apple","iPhone","📱"),      "1C:36:BB":("Apple","iPhone","📱"),
    "1C:9E:46":("Apple","iPhone","📱"),      "1C:91:48":("Apple","iPhone","📱"),
    "20:76:93":("Apple","iPhone","📱"),      "20:78:F0":("Apple","iPhone","📱"),
    "20:AB:37":("Apple","iPhone","📱"),      "20:C9:D0":("Apple","iPhone","📱"),
    "24:18:1D":("Apple","iPhone/iPad","📱"), "24:1E:EB":("Apple","MacBook","💻"),
    "24:A0:74":("Apple","iPhone","📱"),      "28:37:37":("Apple","iPhone","📱"),
    "28:6A:BA":("Apple","iPhone","📱"),      "28:CF:DA":("Apple","iPhone","📱"),
    "28:CF:E9":("Apple","iPhone/iPad","📱"), "2C:1F:23":("Apple","iPhone","📱"),
    "2C:B4:3A":("Apple","iPhone","📱"),      "2C:F0:EE":("Apple","iPhone","📱"),
    "30:10:E4":("Apple","iPhone","📱"),      "30:35:AD":("Apple","iPhone","📱"),
    "30:90:AB":("Apple","MacBook","💻"),     "30:F7:C5":("Apple","iPhone","📱"),
    "34:08:BC":("Apple","iPhone","📱"),      "34:36:3B":("Apple","iPhone","📱"),
    "34:AB:37":("Apple","iPhone","📱"),      "34:C0:59":("Apple","iPhone","📱"),
    "38:0F:4A":("Apple","iPhone","📱"),      "38:53:9C":("Apple","iPhone","📱"),
    "38:66:F0":("Apple","iPhone","📱"),      "38:B5:4D":("Apple","MacBook","💻"),
    "3C:07:71":("Apple","iPhone","📱"),      "3C:15:C2":("Apple","iPhone","📱"),
    "3C:22:FB":("Apple","MacBook Pro","💻"), "3C:2E:F9":("Apple","MacBook","💻"),
    "3C:D0:F8":("Apple","iPhone","📱"),      "40:33:1A":("Apple","iPhone","📱"),
    "40:3C:FC":("Apple","iPhone","📱"),      "40:4D:7F":("Apple","iPhone","📱"),
    "40:6C:8F":("Apple","iPhone","📱"),      "40:A6:D9":("Apple","MacBook","💻"),
    "40:CB:C0":("Apple","iPhone","📱"),      "44:2A:60":("Apple","iPhone","📱"),
    "44:4C:0C":("Apple","iPhone","📱"),      "44:D8:84":("Apple","iPhone","📱"),
    "48:3B:38":("Apple","iPhone","📱"),      "48:43:7C":("Apple","iPhone","📱"),
    "48:60:BC":("Apple","MacBook","💻"),     "48:A9:1C":("Apple","iPhone","📱"),
    "4C:57:CA":("Apple","iPhone","📱"),      "4C:74:BF":("Apple","iPhone","📱"),
    "4C:8D:79":("Apple","iPhone","📱"),      "50:EA:D6":("Apple","iPhone","📱"),
    "54:72:4F":("Apple","iPhone","📱"),      "54:AE:27":("Apple","iPhone","📱"),
    "54:E4:3A":("Apple","MacBook","💻"),     "58:1F:AA":("Apple","iPhone","📱"),
    "58:40:4E":("Apple","iPhone","📱"),      "58:55:CA":("Apple","iPhone","📱"),
    "58:B0:35":("Apple","iPhone/iPad","📱"), "5C:1D:D9":("Apple","iPhone","📱"),
    "5C:59:48":("Apple","iPhone","📱"),      "5C:95:AE":("Apple","MacBook","💻"),
    "60:03:08":("Apple","iPhone","📱"),      "60:33:4B":("Apple","iPhone","📱"),
    "60:D9:C7":("Apple","iPhone","📱"),      "60:F4:45":("Apple","iPhone","📱"),
    "60:F8:1D":("Apple","iPhone","📱"),      "64:20:0C":("Apple","iPhone","📱"),
    "64:76:BA":("Apple","iPhone","📱"),      "64:9A:BE":("Apple","iPhone","📱"),
    "64:B9:E8":("Apple","MacBook","💻"),     "68:D9:3C":("Apple","iPhone","📱"),
    "6C:40:08":("Apple","iPhone/iPad","📱"), "6C:4A:85":("Apple","iPhone","📱"),
    "6C:70:9F":("Apple","iPhone","📱"),      "6C:96:CF":("Apple","iPhone","📱"),
    "70:3E:AC":("Apple","iPhone","📱"),      "70:56:81":("Apple","iPhone","📱"),
    "70:DE:E2":("Apple","iPhone/iPad","📱"), "70:EC:E4":("Apple","MacBook","💻"),
    "74:1B:B2":("Apple","iPhone","📱"),      "74:E1:B6":("Apple","iPhone","📱"),
    "78:31:C1":("Apple","iPhone","📱"),      "78:4F:43":("Apple","iPhone","📱"),
    "78:6C:1C":("Apple","iPhone","📱"),      "78:7E:61":("Apple","iPhone","📱"),
    "78:A3:E4":("Apple","iPhone","📱"),      "78:D7:5F":("Apple","iPhone","📱"),
    "7C:01:91":("Apple","iPhone","📱"),      "7C:11:BE":("Apple","iPhone","📱"),
    "7C:6D:62":("Apple","iPhone","📱"),      "7C:C3:A1":("Apple","MacBook","💻"),
    "80:82:23":("Apple","iPhone","📱"),      "80:B0:3D":("Apple","iPhone","📱"),
    "80:E6:50":("Apple","iPhone","📱"),      "84:38:35":("Apple","iPhone","📱"),
    "84:78:8B":("Apple","iPhone","📱"),      "84:FC:FE":("Apple","MacBook","💻"),
    "88:1F:A1":("Apple","iPad","📱"),        "88:63:DF":("Apple","iPhone","📱"),
    "88:66:A5":("Apple","iPhone","📱"),      "8C:7B:9D":("Apple","iPhone","📱"),
    "8C:85:90":("Apple","iPhone","📱"),      "90:27:E4":("Apple","iPhone","📱"),
    "90:3C:92":("Apple","iPhone","📱"),      "90:72:40":("Apple","iPhone","📱"),
    "90:8D:6C":("Apple","MacBook","💻"),     "94:E9:6A":("Apple","iPhone","📱"),
    "98:01:A7":("Apple","iPhone","📱"),      "98:FE:94":("Apple","iPhone","📱"),
    "98:D6:BB":("Apple","iPhone","📱"),      "9C:04:EB":("Apple","iPhone","📱"),
    "9C:35:EB":("Apple","iPhone","📱"),      "A0:99:9B":("Apple","iPhone","📱"),
    "A0:D7:95":("Apple","iPhone","📱"),      "A4:5E:60":("Apple","MacBook","💻"),
    "A4:B1:97":("Apple","iPhone","📱"),      "A4:C3:F0":("Apple","iPhone","📱"),
    "A4:D1:8C":("Apple","iPhone","📱"),      "A8:5C:2C":("Apple","iPhone","📱"),
    "A8:66:7F":("Apple","iPhone/iPad","📱"), "A8:96:75":("Apple","iPhone","📱"),
    "A8:BB:CF":("Apple","iPhone","📱"),      "AC:29:3A":("Apple","iPhone","📱"),
    "AC:3C:0B":("Apple","iPhone","📱"),      "AC:7F:3E":("Apple","iPhone","📱"),
    "AC:BC:32":("Apple","MacBook","💻"),     "B0:34:95":("Apple","iPhone","📱"),
    "B0:65:BD":("Apple","iPhone","📱"),      "B0:9F:BA":("Apple","iPhone","📱"),
    "B4:18:D1":("Apple","iPhone/Mac","📱"),  "B4:F0:AB":("Apple","iPhone","📱"),
    "B8:17:C2":("Apple","iPhone","📱"),      "B8:41:A4":("Apple","iPhone","📱"),
    "B8:8D:12":("Apple","iPhone","📱"),      "B8:C1:11":("Apple","iPhone","📱"),
    "BC:3B:AF":("Apple","iPhone","📱"),      "BC:52:B7":("Apple","iPhone","📱"),
    "C0:63:94":("Apple","iPhone","📱"),      "C0:9F:42":("Apple","iPhone","📱"),
    "C4:B3:01":("Apple","iPhone","📱"),      "C8:2A:14":("Apple","iPhone/iPad","📱"),
    "C8:6F:1D":("Apple","iPhone","📱"),      "C8:B5:B7":("Apple","MacBook","💻"),
    "C8:D0:83":("Apple","iPhone","📱"),      "CC:08:8D":("Apple","iPhone","📱"),
    "CC:25:EF":("Apple","MacBook","💻"),     "D0:03:4B":("Apple","iPhone","📱"),
    "D0:23:DB":("Apple","iPhone","📱"),      "D4:20:B0":("Apple","iPhone","📱"),
    "D4:61:9D":("Apple","iPhone","📱"),      "D4:9A:20":("Apple","MacBook","💻"),
    "D4:F4:6F":("Apple","iPhone","📱"),      "D8:1D:72":("Apple","MacBook","💻"),
    "D8:30:62":("Apple","iPhone","📱"),      "DC:2B:2A":("Apple","iPad","📱"),
    "DC:9B:9C":("Apple","iPhone","📱"),      "E0:AC:CB":("Apple","iPhone","📱"),
    "E0:B9:BA":("Apple","iPhone","📱"),      "E0:F5:C6":("Apple","MacBook","💻"),
    "E4:25:E7":("Apple","iPhone","📱"),      "E4:98:BB":("Apple","iPhone","📱"),
    "E8:04:0B":("Apple","iPhone","📱"),      "E8:8D:28":("Apple","MacBook","💻"),
    "EC:35:86":("Apple","iPhone","📱"),      "EC:85:2F":("Apple","iPhone","📱"),
    "F0:18:98":("Apple","iPhone","📱"),      "F0:79:60":("Apple","iPhone","📱"),
    "F0:99:BF":("Apple","iPhone","📱"),      "F0:D1:A9":("Apple","MacBook","💻"),
    "F4:F1:5A":("Apple","iPhone","📱"),      "F8:1E:DF":("Apple","iPhone","📱"),
    "F8:27:93":("Apple","iPhone","📱"),      "F8:62:AA":("Apple","iPhone","📱"),
    "FC:25:3F":("Apple","iPhone","📱"),      "FC:D8:48":("Apple","iPhone","📱"),
    "20:AB:37":("Apple","iPhone","📱"),      "34:AB:37":("Apple","iPhone","📱"),
    "78:D7:5F":("Apple","iPhone","📱"),      "AC:29:3A":("Apple","iPhone","📱"),
    "24:18:1D":("Apple","iPhone/iPad","📱"), "5C:1D:D9":("Apple","iPhone","📱"),
    "4C:57:CA":("Apple","iPhone","📱"),      "BC:52:B7":("Apple","iPhone","📱"),
    "54:72:4F":("Apple","iPhone","📱"),      "CC:08:8D":("Apple","iPhone","📱"),
    "1C:91:48":("Apple","iPhone","📱"),      "88:1F:A1":("Apple","iPad","📱"),
    # ── Samsung ────────────────────────────────────────────────────
    "00:12:47":("Samsung","Galaxy","📱"),     "00:15:B9":("Samsung","Galaxy","📱"),
    "00:1A:8A":("Samsung","Galaxy","📱"),     "00:1D:25":("Samsung","Galaxy","📱"),
    "00:21:19":("Samsung","Galaxy","📱"),     "00:23:39":("Samsung","Galaxy","📱"),
    "00:26:37":("Samsung","Galaxy","📱"),     "04:18:D6":("Samsung","Galaxy S","📱"),
    "08:08:C2":("Samsung","Galaxy","📱"),     "08:37:3D":("Samsung","Galaxy","📱"),
    "08:D4:2B":("Samsung","Galaxy","📱"),     "0C:14:20":("Samsung","Galaxy","📱"),
    "0C:89:10":("Samsung","Galaxy S","📱"),   "10:1D:C0":("Samsung","Galaxy","📱"),
    "10:30:47":("Samsung","Galaxy S","📱"),   "10:D5:42":("Samsung","Galaxy","📱"),
    "14:49:E0":("Samsung","Galaxy","📱"),     "14:89:FD":("Samsung","Galaxy","📱"),
    "14:A3:64":("Samsung","Galaxy A","📱"),   "18:3A:2D":("Samsung","Galaxy","📱"),
    "18:67:B0":("Samsung","Galaxy","📱"),     "1C:62:B8":("Samsung","Galaxy S","📱"),
    "20:13:E0":("Samsung","Galaxy","📱"),     "20:6D:31":("Samsung","Galaxy","📱"),
    "20:A5:93":("Samsung","Galaxy","📱"),     "24:4B:03":("Samsung","Galaxy A","📱"),
    "24:92:0E":("Samsung","Galaxy Note","📱"),"28:27:BF":("Samsung","Galaxy","📱"),
    "28:39:5E":("Samsung","Galaxy","📱"),     "2C:AE:2B":("Samsung","Galaxy","📱"),
    "30:19:66":("Samsung","Galaxy","📱"),     "30:CD:A7":("Samsung","Galaxy A","📱"),
    "34:14:5F":("Samsung","Galaxy","📱"),     "34:23:BA":("Samsung","Galaxy S","📱"),
    "34:6A:C2":("Samsung","Galaxy","📱"),     "34:C3:AC":("Samsung","Galaxy","📱"),
    "34:F3:9A":("Samsung","Galaxy S","📱"),   "38:AA:3C":("Samsung","Galaxy","📱"),
    "3C:62:00":("Samsung","Galaxy Note","📱"),"3C:8B:FE":("Samsung","Galaxy","📱"),
    "40:0E:85":("Samsung","Galaxy","📱"),     "44:65:0D":("Samsung","Galaxy","📱"),
    "44:A7:42":("Samsung","Galaxy","📱"),     "48:13:7E":("Samsung","Galaxy A","📱"),
    "4C:BC:A5":("Samsung","Galaxy S","📱"),   "50:32:75":("Samsung","Smart TV","📺"),
    "50:A4:C8":("Samsung","Galaxy","📱"),     "50:CC:F8":("Samsung","Galaxy S","📱"),
    "54:BD:79":("Samsung","Galaxy","📱"),     "54:FA:3E":("Samsung","Galaxy","📱"),
    "58:C8:76":("Samsung","Galaxy","📱"),     "5C:2E:59":("Samsung","Galaxy Tab","📱"),
    "5C:3C:27":("Samsung","Galaxy","📱"),     "60:01:94":("Samsung","Galaxy","📱"),
    "60:6B:BD":("Samsung","Galaxy","📱"),     "60:A1:0A":("Samsung","Galaxy S","📱"),
    "60:D0:A9":("Samsung","Galaxy","📱"),     "64:B3:10":("Samsung","Galaxy","📱"),
    "68:27:37":("Samsung","Galaxy","📱"),     "68:EB:AE":("Samsung","Galaxy","📱"),
    "70:F9:27":("Samsung","Galaxy","📱"),     "78:47:1D":("Samsung","Galaxy","📱"),
    "78:BD:BC":("Samsung","Smart TV","📺"),   "78:E4:00":("Samsung","Galaxy S","📱"),
    "7C:1C:4E":("Samsung","Galaxy Tab","📱"), "7C:61:66":("Samsung","Galaxy","📱"),
    "80:57:19":("Samsung","Galaxy","📱"),     "84:25:3F":("Samsung","Galaxy A/S","📱"),
    "88:32:9B":("Samsung","Galaxy","📱"),     "88:83:22":("Samsung","Galaxy","📱"),
    "8C:71:F8":("Samsung","Galaxy","📱"),     "8C:77:12":("Samsung","Galaxy Note","📱"),
    "90:18:7C":("Samsung","Galaxy","📱"),     "94:35:0A":("Samsung","Galaxy S","📱"),
    "94:63:D1":("Samsung","Galaxy","📱"),     "98:52:B1":("Samsung","Galaxy","📱"),
    "9C:02:98":("Samsung","Galaxy S","📱"),   "9C:3A:AF":("Samsung","Galaxy","📱"),
    "A0:07:98":("Samsung","Galaxy S","📱"),   "A0:8C:FD":("Samsung","Galaxy","📱"),
    "A4:39:B3":("Samsung","Galaxy","📱"),     "A8:F2:74":("Samsung","Galaxy S","📱"),
    "AC:5A:14":("Samsung","Galaxy A","📱"),   "B0:72:BF":("Samsung","Galaxy S","📱"),
    "B0:EC:71":("Samsung","Galaxy","📱"),     "B4:3A:28":("Samsung","Galaxy","📱"),
    "B4:EF:FA":("Samsung","Galaxy S","📱"),   "BC:20:A4":("Samsung","Galaxy S","📱"),
    "BC:85:56":("Samsung","Galaxy","📱"),     "C0:BD:D1":("Samsung","Galaxy","📱"),
    "C4:42:02":("Samsung","Galaxy S","📱"),   "C4:57:6E":("Samsung","Galaxy","📱"),
    "C4:88:E5":("Samsung","Galaxy S","📱"),   "C8:14:79":("Samsung","Galaxy","📱"),
    "CC:05:1B":("Samsung","Galaxy S","📱"),   "CC:6E:A4":("Samsung","Galaxy","📱"),
    "D0:17:6A":("Samsung","Galaxy","📱"),     "D0:22:BE":("Samsung","Galaxy S","📱"),
    "D0:66:9A":("Samsung","Galaxy A","📱"),   "D8:57:EF":("Samsung","Galaxy","📱"),
    "DC:71:96":("Samsung","Galaxy","📱"),     "EC:9B:F3":("Samsung","Galaxy A","📱"),
    "F0:08:F1":("Samsung","Galaxy","📱"),     "F0:25:B7":("Samsung","Galaxy","📱"),
    "F4:42:8F":("Samsung","Galaxy S","📱"),   "F4:7B:5E":("Samsung","Galaxy A","📱"),
    "F4:9F:54":("Samsung","Galaxy","📱"),     "F8:04:2E":("Samsung","Galaxy","📱"),
    "FC:A1:3E":("Samsung","Galaxy","📱"),     "FC:DB:B3":("Samsung","Galaxy S","📱"),
    "6C:B7:F4":("Samsung","Galaxy","📱"),     "0C:89:10":("Samsung","Galaxy S","📱"),
    "88:83:22":("Samsung","Galaxy","📱"),
    # ── Xiaomi ─────────────────────────────────────────────────────
    "00:9E:C8":("Xiaomi","Mi","📱"),          "04:CF:8C":("Xiaomi","Redmi","📱"),
    "08:21:EF":("Xiaomi","Redmi","📱"),       "0C:1D:AF":("Xiaomi","Mi","📱"),
    "10:2A:B3":("Xiaomi","Mi Note","📱"),     "14:F6:5A":("Xiaomi","Redmi","📱"),
    "18:59:36":("Xiaomi","Mi Router","📡"),   "1C:74:0D":("Xiaomi","Redmi","📱"),
    "20:34:FB":("Xiaomi","Redmi Note","📱"),  "24:CF:24":("Realme","Смартфон","📱"),
    "28:6C:07":("Xiaomi","Mi Router","📡"),   "2C:DB:07":("Xiaomi","Redmi","📱"),
    "34:80:B3":("Xiaomi","Mi 11","📱"),       "38:A4:ED":("Xiaomi","Redmi","📱"),
    "3C:BD:D8":("Xiaomi","POCO","📱"),        "40:31:3C":("Xiaomi","Redmi Note","📱"),
    "44:DB:C0":("Xiaomi","Redmi","📱"),       "44:F4:36":("Xiaomi","Mi","📱"),
    "48:13:7E":("Samsung","Galaxy A","📱"),   "4C:49:E3":("Xiaomi","Redmi","📱"),
    "50:64:2B":("Xiaomi","Redmi","📱"),       "54:48:10":("Xiaomi","Redmi Note","📱"),
    "58:44:98":("Xiaomi","Mi","📱"),          "5C:02:14":("Xiaomi","Redmi Note","📱"),
    "5C:E8:EB":("Xiaomi","Redmi Note","📱"),  "60:AB:D2":("Xiaomi","Redmi","📱"),
    "64:09:80":("Xiaomi","Mi","📱"),          "64:CC:2E":("Xiaomi","Mi Router","📡"),
    "68:DF:DD":("Xiaomi","Redmi","📱"),       "6C:B3:11":("Xiaomi","Redmi","📱"),
    "78:02:F8":("Xiaomi","Redmi","📱"),       "7C:1B:D9":("Xiaomi","Redmi","📱"),
    "80:35:C1":("Xiaomi","Mi Router","📡"),   "88:C3:97":("Xiaomi","Redmi","📱"),
    "8C:BE:BE":("Xiaomi","Mi","📱"),          "98:FA:E3":("Xiaomi","Redmi Note","📱"),
    "9C:99:A0":("Xiaomi","Mi","📱"),          "A0:86:C6":("Xiaomi","Redmi","📱"),
    "A4:50:46":("Xiaomi","Redmi Note","📱"),  "A8:9A:93":("Xiaomi","Redmi","📱"),
    "AC:C1:EE":("Xiaomi","Mi Router","📡"),   "B0:E2:35":("Xiaomi","Redmi","📱"),
    "C4:0B:CB":("Nokia","G-Series","📱"),     "C4:6A:B7":("Xiaomi","Redmi","📱"),
    "C8:47:8C":("Xiaomi","Redmi Note","📱"),  "D8:EB:97":("Xiaomi","Mi Router","📡"),
    "DC:44:27":("Xiaomi","Redmi","📱"),       "E0:CC:F8":("Xiaomi","Redmi","📱"),
    "F4:8B:32":("Xiaomi","Mi/Redmi","📱"),    "F8:A4:5F":("Xiaomi","Redmi","📱"),
    "FC:64:BA":("Xiaomi","Mi Router","📡"),   "10:2A:B3":("Xiaomi","Mi Note","📱"),
    "3C:BD:D8":("Xiaomi","POCO","📱"),
    # ── Huawei / Honor ─────────────────────────────────────────────
    "00:18:82":("Huawei","Смартфон","📱"),    "00:25:9E":("Huawei","Router","📡"),
    "00:9A:CD":("OnePlus","Смартфон","📱"),   "00:E0:FC":("Huawei","Смартфон","📱"),
    "04:02:1F":("Huawei","Honor","📱"),       "04:B0:E7":("Huawei","Honor","📱"),
    "04:BD:70":("Huawei","Honor","📱"),       "08:19:A6":("Huawei","Router","📡"),
    "0C:37:F6":("Huawei","Смартфон","📱"),    "0C:96:BF":("Huawei","Mate","📱"),
    "14:98:77":("Huawei","Router","📡"),      "1C:1D:67":("Huawei","Honor","📱"),
    "20:2B:C1":("Huawei","Смартфон","📱"),    "24:09:95":("Huawei","Router","📡"),
    "28:31:52":("Huawei","Honor","📱"),       "28:6E:D4":("Huawei","Honor","📱"),
    "2C:AB:00":("Huawei","Router","📡"),      "30:74:96":("Huawei","Mate","📱"),
    "30:D1:7E":("Huawei","Router","📡"),      "34:6B:D3":("Huawei","Honor","📱"),
    "38:37:8B":("Huawei","Смартфон","📱"),    "3C:F8:08":("Huawei","Honor","📱"),
    "40:4D:8E":("Huawei","Router","📡"),      "40:CB:A8":("Huawei","Mate","📱"),
    "48:FD:8E":("Huawei","Router","📡"),      "4C:1B:86":("Huawei","Honor","📱"),
    "50:9F:27":("Huawei","Router","📡"),      "54:25:EA":("Huawei","Mate","📱"),
    "54:51:1B":("Huawei","Honor","📱"),       "58:60:5F":("Huawei","Router","📡"),
    "5C:C3:07":("Huawei","Router","📡"),      "60:DE:44":("Huawei","Смартфон","📱"),
    "64:3E:8C":("Huawei","Router","📡"),      "6C:B7:49":("Huawei","Router","📡"),
    "70:7B:E8":("Huawei","Honor","📱"),       "70:72:3C":("Huawei","Mate","📱"),
    "74:88:2A":("Huawei","Router","📡"),      "78:1D:BA":("Huawei","Router","📡"),
    "7C:76:35":("Huawei","Mate","📱"),        "7C:C2:C6":("Huawei","Honor","📱"),
    "80:65:6D":("Huawei","Смартфон","📱"),    "80:FB:06":("Huawei","Router","📡"),
    "84:DB:AC":("Huawei","Honor","📱"),       "88:E3:AB":("Huawei","Router","📡"),
    "8C:34:FD":("Huawei","Honor","📱"),       "90:17:3F":("Huawei","Router","📡"),
    "90:67:1C":("Huawei","Mate","📱"),        "98:E7:F4":("Huawei","Router","📡"),
    "9C:B2:B2":("Huawei","Router","📡"),      "A0:08:6F":("Huawei","Honor","📱"),
    "A4:C6:4F":("Huawei","Honor","📱"),       "A8:CA:89":("Huawei","Mate","📱"),
    "AC:6F:BB":("Huawei","Router","📡"),      "B4:86:55":("Huawei","Mate","📱"),
    "B4:CD:27":("Huawei","Honor","📱"),       "BC:76:70":("Huawei","Router","📡"),
    "C4:07:2F":("Huawei","Router","📡"),      "C4:FF:BC":("Huawei","Honor","📱"),
    "C8:D1:0B":("Huawei","Honor","📱"),       "CC:A2:23":("Huawei","Router","📡"),
    "D4:6A:35":("Huawei","Honor","📱"),       "D4:7A:E2":("Huawei","Mate","📱"),
    "D8:49:0B":("Huawei","Router","📡"),      "DC:D2:FC":("Huawei","Honor","📱"),
    "E0:19:54":("Huawei","Router","📡"),      "E4:0E:EE":("Huawei","Mate","📱"),
    "E8:CD:2D":("Huawei","Router","📡"),      "EC:23:3D":("Huawei","Honor","📱"),
    "F0:79:59":("Huawei","Router","📡"),      "F4:CB:52":("Huawei","Honor","📱"),
    "F8:01:13":("Huawei","Router","📡"),      "FC:48:EF":("Huawei","Mate","📱"),
    # ── Realme / OPPO / Vivo / OnePlus ─────────────────────────────
    "04:D4:C4":("Realme","Смартфон","📱"),    "10:3B:59":("Oppo","Find X","📱"),
    "14:6B:9A":("Realme","Смартфон","📱"),    "18:D4:66":("Oppo","Reno","📱"),
    "1C:77:F6":("Realme","GT","📱"),          "24:CF:24":("Realme","Смартфон","📱"),
    "2C:F0:A2":("Oppo","Смартфон","📱"),      "2C:F0:A2":("Oppo","Смартфон","📱"),
    "34:E8:94":("Realme","Narzo","📱"),       "3C:ED:64":("Oppo","Reno","📱"),
    "40:40:A7":("Vivo","Смартфон","📱"),      "48:7C:2F":("Oppo","Смартфон","📱"),
    "50:11:41":("Vivo","Смартфон","📱"),      "5C:BC:96":("Realme","Смартфон","📱"),
    "60:64:05":("Realme","Смартфон","📱"),    "64:0D:86":("Oppo","Reno","📱"),
    "68:13:C2":("Vivo","Смартфон","📱"),      "6C:5A:B0":("TP-Link","Router","📡"),
    "70:2F:D9":("Oppo","Смартфон","📱"),      "78:1C:23":("Realme","Смартфон","📱"),
    "7C:ED:8D":("Vivo","Смартфон","📱"),      "80:EA:CA":("Realme","Narzo","📱"),
    "84:7B:EB":("Oppo","Смартфон","📱"),      "88:13:BF":("Vivo","Смартфон","📱"),
    "8C:79:F0":("Oppo","Смартфон","📱"),      "94:65:2D":("OnePlus","Nord","📱"),
    "9C:52:F8":("Realme","Смартфон","📱"),    "A4:E4:C9":("Oppo","Find X","📱"),
    "A8:9C:ED":("Oppo","Смартфон","📱"),      "AC:37:43":("OnePlus","Смартфон","📱"),
    "B4:4B:D2":("Realme","GT","📱"),          "B8:AD:28":("Oppo","Смартфон","📱"),
    "BC:14:01":("Vivo","Смартфон","📱"),      "C4:C7:BF":("Oppo","Reno","📱"),
    "C8:F6:50":("OnePlus","Смартфон","📱"),   "D4:50:53":("Realme","Смартфон","📱"),
    "D8:6C:63":("Vivo","Смартфон","📱"),      "E0:D4:E8":("Oppo","Смартфон","📱"),
    "E4:3C:1A":("Oppo","Find X","📱"),        "EC:F0:FE":("Vivo","Смартфон","📱"),
    "F4:D9:FB":("Realme","GT","📱"),          "F8:38:80":("Oppo","Смартфон","📱"),
    "3C:8D:20":("Vivo","Смартфон","📱"),      "9C:28:EF":("Vivo","Смартфон","📱"),
    "28:BE:D7":("Vivo","Смартфон","📱"),      "E0:46:A7":("Vivo","Смартфон","📱"),
    "B8:3E:59":("Vivo","Смартфон","📱"),      "80:EA:CA":("Realme","Narzo","📱"),
    # ── Motorola ───────────────────────────────────────────────────
    "00:08:E2":("Motorola","Смартфон","📱"),  "00:22:A4":("Motorola","Смартфон","📱"),
    "14:F6:D8":("Motorola","Moto G","📱"),    "24:DA:9B":("Motorola","Moto","📱"),
    "2C:C5:4B":("Motorola","Moto G","📱"),    "34:BB:26":("Motorola","Moto G","📱"),
    "3C:43:8E":("Motorola","Moto E","📱"),    "40:6A:BF":("Motorola","Moto","📱"),
    "44:80:EB":("Motorola","Moto G","📱"),    "4C:E1:73":("Motorola","Moto","📱"),
    "54:E7:4C":("Motorola","Moto","📱"),      "5C:51:81":("Motorola","Moto G","📱"),
    "60:BF:ED":("Motorola","Moto G Power","📱"),"68:0A:35":("Motorola","Moto","📱"),
    "A4:70:D6":("Motorola","Moto E","📱"),    "B0:AA:77":("Motorola","Moto G","📱"),
    "BC:F5:AC":("Motorola","Moto","📱"),      "D8:EC:E5":("Motorola","Moto","📱"),
    "E8:D0:FC":("Motorola","Moto G","📱"),    "FC:B0:DE":("Motorola","Moto","📱"),
    # ── Nokia ──────────────────────────────────────────────────────
    "00:21:FE":("Nokia","Смартфон","📱"),     "00:E7:48":("Nokia","G20","📱"),
    "14:AB:C5":("Nokia","G-Series","📱"),     "40:4A:03":("Nokia","Смартфон","📱"),
    "60:57:18":("Nokia","X-Series","📱"),     "6C:3A:B8":("Nokia","XR20","📱"),
    "80:4B:50":("Nokia","Смартфон","📱"),     "C4:0B:CB":("Nokia","G-Series","📱"),
    "D4:CA:6D":("Nokia","Смартфон","📱"),     "F4:9F:F3":("Nokia","Смартфон","📱"),
    # ── Sony Xperia ────────────────────────────────────────────────
    "00:EB:2D":("Sony","Bravia TV","📺"),     "04:BA:D6":("Sony","Xperia","📱"),
    "10:4F:A8":("Sony","Bravia TV","📺"),     "30:17:C8":("Sony","Bravia","📺"),
    "40:B8:37":("LG","V-Series","📱"),        "44:6D:57":("Sony","Xperia","📱"),
    "4C:E9:E4":("Sony","Xperia","📱"),        "54:F2:01":("Sony","Xperia","📱"),
    "58:48:22":("Sony","Xperia","📱"),        "70:3A:CB":("Sony","Xperia","📱"),
    "78:84:3C":("Sony","Xperia","📱"),        "84:C7:EA":("Sony","Xperia","📱"),
    "9C:5C:F9":("Sony","Xperia","📱"),        "AC:9B:0A":("Sony","PlayStation 4","🎮"),
    "CC:1B:E0":("Sony","Xperia","📱"),        "E0:19:1D":("Sony","Xperia","📱"),
    "F0:BF:97":("Sony","PlayStation 5","🎮"), "FC:0F:E6":("Sony","Xperia","📱"),
    # ── LG ─────────────────────────────────────────────────────────
    "30:8C:FB":("LG","Smart TV","📺"),        "34:4D:F7":("LG","OLED TV","📺"),
    "38:8B:59":("LG","Смартфон","📱"),        "40:B8:37":("LG","V-Series","📱"),
    "44:4E:1A":("LG","Smart TV","📺"),        "4C:CA:21":("LG","Смартфон","📱"),
    "60:A1:0A":("Samsung","Galaxy S","📱"),   "88:36:6C":("LG","Смартфон","📱"),
    "8C:8D:28":("Intel","Wireless","💻"),     "A0:39:F7":("LG","G-Series","📱"),
    "A8:23:FE":("LG","Smart TV","📺"),        "CC:2D:83":("LG","Smart TV","📺"),
    # ── Google Pixel / Chromecast / Nest ───────────────────────────
    "00:1A:11":("Google","Chromecast","📺"),  "00:3E:E1":("Google","Pixel","📱"),
    "08:9E:08":("Google","Pixel","📱"),       "1A:2B:3C":("Google","Pixel","📱"),
    "20:DF:B9":("Google","Pixel","📱"),       "3C:5A:B4":("Google","Chromecast","📺"),
    "3C:82:C0":("Google","Pixel","📱"),       "40:4E:36":("Google","Pixel","📱"),
    "48:D6:D5":("Google","Pixel","📱"),       "54:60:09":("Google","Nest Hub","🔊"),
    "6C:AD:F8":("Google","Pixel","📱"),       "80:7A:BF":("Google","Pixel","📱"),
    "A4:77:33":("Google","Pixel","📱"),       "C4:73:1E":("Google","Pixel","📱"),
    "D4:F5:47":("Google","Chromecast","📺"),  "E4:F0:42":("Google","Pixel","📱"),
    "F4:F5:D8":("Google","Chromecast","📺"),  "F8:0F:41":("Google","Pixel","📱"),
    "FA:01:B6":("Google","Pixel","📱"),
    # ── Amazon ─────────────────────────────────────────────────────
    "0C:47:C9":("Amazon","Echo Dot","🔊"),    "34:D2:70":("Amazon","Fire TV","📺"),
    "38:8B:59":("LG","Смартфон","📱"),        "40:B4:CD":("Amazon","Echo","🔊"),
    "44:65:0D":("Samsung","Galaxy","📱"),     "4C:EF:C0":("Amazon","Fire TV","📺"),
    "50:DC:E7":("Amazon","Echo Show","🔊"),   "68:37:E9":("Amazon","Fire TV","📺"),
    "74:C2:46":("Amazon","Fire TV","📺"),     "7C:BB:8A":("Amazon","Echo","🔊"),
    "84:D6:D0":("Amazon","Fire Tablet","📱"), "A0:02:DC":("Amazon","Echo","🔊"),
    "F0:81:73":("Amazon","Echo/Fire TV","🔊"),
    # ── Microsoft ──────────────────────────────────────────────────
    "00:0D:3A":("Microsoft","Xbox One","🎮"), "28:18:78":("Microsoft","Xbox Series","🎮"),
    "30:59:B7":("Microsoft","Surface","💻"),  "60:45:BD":("Microsoft","Xbox One","🎮"),
    "98:5F:D3":("Microsoft","Surface Pro","💻"),"C8:3D:D4":("Microsoft","Xbox One","🎮"),
    "00:13:E8":("Microsoft","Xbox","🎮"),     "7C:1E:52":("Microsoft","Xbox","🎮"),
    "B8:27:EB":("Raspberry Pi","Pi","🖥️"),
    # ── Dell / HP / Lenovo / ASUS ──────────────────────────────────
    "00:21:9B":("Dell","Latitude","💻"),      "14:B3:1F":("Dell","XPS","💻"),
    "18:03:73":("Dell","XPS/Inspiron","💻"),  "1C:40:24":("Dell","Inspiron","💻"),
    "24:B6:FD":("Dell","Inspiron","💻"),      "44:A8:42":("Dell","XPS","💻"),
    "54:BF:64":("Dell","Latitude","💻"),      "B8:CA:3A":("Dell","XPS/Precision","💻"),
    "10:60:4B":("HP","EliteBook","💻"),       "20:16:B9":("HP","ProBook","💻"),
    "3C:D9:2B":("HP","EliteBook","💻"),       "40:B0:34":("HP","EliteBook","💻"),
    "60:EB:69":("HP","Laptop","💻"),          "78:0C:B8":("HP","EliteBook","💻"),
    "80:C1:6E":("HP","ProBook","💻"),         "B4:99:BA":("HP","Laptop","💻"),
    "BC:AE:C5":("HP","Принтер","🖨️"),        "C4:34:6B":("HP","Принтер","🖨️"),
    "30:10:B3":("Lenovo","ThinkPad","💻"),    "3C:97:0E":("Lenovo","ThinkPad","💻"),
    "4C:1D:96":("Lenovo","ThinkPad","💻"),    "54:EE:75":("Lenovo","ThinkPad","💻"),
    "84:2B:2B":("Lenovo","IdeaPad","💻"),     "88:70:8C":("Lenovo","ThinkPad","💻"),
    "D4:81:D7":("Lenovo","ThinkPad","💻"),    "F8:A9:63":("Lenovo","ThinkPad","💻"),
    "2C:56:DC":("ASUS","RT Router","📡"),     "2C:FD:A1":("ASUS","Ноутбук","💻"),
    "50:46:5D":("ASUS","RT Router","📡"),     "6C:F3:7F":("ASUS","Ноутбук","💻"),
    "AC:9E:17":("ASUS","RT-AX Router","📡"),  "E4:BF:FA":("ASUS","ZenBook","💻"),
    "90:E8:68":("ASUS","RT-AX Router","📡"),  "4C:ED:DE":("ASUS","VivoBook","💻"),
    # ── Routers ────────────────────────────────────────────────────
    "10:FE:ED":("TP-Link","Router","📡"),     "14:CC:20":("TP-Link","Router","📡"),
    "18:A6:F7":("TP-Link","Router","📡"),     "30:B5:C2":("TP-Link","Archer Router","📡"),
    "50:C7:BF":("TP-Link","Router","📡"),     "7C:8B:CA":("TP-Link","Archer","📡"),
    "84:16:F9":("TP-Link","Router","📡"),     "A0:F3:C1":("TP-Link","Router","📡"),
    "AC:84:C6":("TP-Link","Archer","📡"),     "B0:48:7A":("TP-Link","Archer","📡"),
    "EC:08:6B":("TP-Link","Archer","📡"),     "F4:F2:6D":("TP-Link","Router","📡"),
    "98:DA:C4":("TP-Link","Tapo","🔌"),       "50:91:E3":("TP-Link","Tapo","🔌"),
    "1C:61:B4":("TP-Link","Tapo","🔌"),       "48:8D:36":("TP-Link","Router","📡"),
    "6C:4C:BC":("TP-Link","Tapo Smart Plug","🔌"),   # Tapo P100/P110/P115/P125
    "54:AF:97":("TP-Link","Tapo","🔌"),       "A8:42:A1":("TP-Link","Tapo","🔌"),
    "00:31:92":("TP-Link","Tapo","🔌"),       "3C:52:A1":("TP-Link","Tapo","🔌"),
    "AC:84:C9":("TP-Link","Tapo Camera","🔌"), "30:DE:4B":("TP-Link","Tapo","🔌"),
    "6C:5A:B0":("TP-Link","Router","📡"),     "C4:E9:84":("TP-Link","Archer AX","📡"),
    "84:C9:B2":("D-Link","DIR Router","📡"),  "C8:BE:19":("D-Link","DIR Router","📡"),
    "1C:7E:E5":("D-Link","Router","📡"),      "00:26:5A":("D-Link","Router","📡"),
    "28:C6:8E":("Netgear","Nighthawk","📡"),  "44:94:FC":("Netgear","Nighthawk","📡"),
    "84:1B:5E":("Netgear","Orbi","📡"),       "C4:3D:C7":("Netgear","Nighthawk","📡"),
    "A0:63:91":("Netgear","Router","📡"),     "30:46:9A":("Netgear","Router","📡"),
    "2C:C8:1B":("MikroTik","hAP/RB","📡"),   "4C:5E:0C":("MikroTik","RouterBoard","📡"),
    "6C:3B:6B":("MikroTik","hAP","📡"),      "B8:69:F4":("MikroTik","RB/CCR","📡"),
    "DC:2C:6E":("MikroTik","hEX Router","📡"),"74:4D:28":("MikroTik","hAP","📡"),
    "E4:8D:8C":("MikroTik","hEX","📡"),      "D4:CA:6D":("MikroTik","wAP","📡"),
    "A0:E4:CB":("Keenetic","Router","📡"),   "50:FF:20":("Keenetic","Router","📡"),
    "14:D6:4D":("Keenetic","Router","📡"),   "20:4E:7F":("Keenetic","Router","📡"),
    "E4:A7:C5":("Keenetic","Router","📡"),   "DC:15:C8":("Keenetic","Router","📡"),
    "5C:E9:31":("TP-Link","Archer Router","📡"),  # TP-Link Archer C64/C6/AX серія
    "00:19:CB":("ZyXEL","Router","📡"),      "A8:6E:84":("Cudy","Router","📡"),
    "B0:BE:76":("Cudy","Router","📡"),       "C8:D7:19":("Tenda","Router","📡"),
    "84:A5:C8":("Tenda","Router","📡"),      "C8:3A:35":("Tenda","Router","📡"),
    # ── Realtek / Intel / MediaTek / Qualcomm ──────────────────────
    "5C:3A:45":("Realtek","Ноутбук/ПК","💻"), "64:E0:03":("Realtek","Ноутбук/ПК","💻"),
    "00:E0:4C":("Realtek","Ноутбук/ПК","💻"), "B0:7D:64":("Intel","Ноутбук","💻"),
    "8C:EC:4B":("Intel","Ноутбук","💻"),      "F8:63:3F":("Intel","Ноутбук","💻"),
    "94:E9:79":("Intel","Ноутбук","💻"),      "48:51:B7":("Intel","Wireless","💻"),
    "8C:8D:28":("Intel","Wireless","💻"),     "10:02:B5":("Intel","Wireless","💻"),
    "5C:E5:0C":("MediaTek","Android","📱"),   "AC:D1:B8":("MediaTek","Android","📱"),
    "E8:50:8B":("Qualcomm","Android","📱"),   "28:3F:69":("Qualcomm","Android/IoT","📱"),
    "A4:2B:B0":("Qualcomm","Android","📱"),   "FC:8F:90":("Qualcomm","Смартфон","📱"),
    # ── VMware / VirtualBox / Raspberry Pi ─────────────────────────
    "00:0C:29":("VMware","Вірт. машина","🖥️"), "00:50:56":("VMware","Вірт. машина","🖥️"),
    "08:00:27":("VirtualBox","Вірт. машина","🖥️"),
    "28:CD:C1":("Raspberry Pi","Pi 4","🖥️"),  "B8:27:EB":("Raspberry Pi","Pi","🖥️"),
    "DC:A6:32":("Raspberry Pi","Pi 4/400","🖥️"),"E4:5F:01":("Raspberry Pi","Pi","🖥️"),
    "D8:3A:DD":("Raspberry Pi","Pi 5","🖥️"),
    # ── Cameras / Printers / NAS ───────────────────────────────────
    "00:60:B0":("Hikvision","IP-камера","📷"), "28:57:BE":("Hikvision","DVR/NVR","📷"),
    "44:19:B6":("Dahua","IP-камера","📷"),     "70:85:C6":("Hikvision","IP-камера","📷"),
    "A0:C5:62":("Reolink","IP-камера","📷"),   "00:4A:58":("Reolink","IP-камера","📷"),
    "40:B8:9A":("Epson","EcoTank","🖨️"),      "78:5B:8B":("Canon","PIXMA","🖨️"),
    "00:1B:A9":("Brother","Принтер","🖨️"),    "00:80:77":("Brother","Принтер","🖨️"),
    "00:1E:8F":("HP","LaserJet","🖨️"),        "00:17:A4":("Synology","NAS","🗄️"),
    "00:11:32":("Synology","NAS","🗄️"),       "00:08:9B":("QNAP","NAS","🗄️"),
}

CRITICAL_PORTS: dict[int, tuple[str, str, str]] = {
    21:("FTP","Небезпечний","🔴"), 22:("SSH","Помірний","🟡"),
    23:("Telnet","КРИТИЧНИЙ","🔴"), 25:("SMTP","Підозрілий","🟠"),
    53:("DNS","Нормальний","🟢"), 80:("HTTP","Нормальний","🟢"),
    110:("POP3","Підозрілий","🟠"), 135:("RPC","Небезпечний","🔴"),
    139:("NetBIOS","Небезпечний","🔴"), 443:("HTTPS","Нормальний","🟢"),
    445:("SMB","Небезпечний","🔴"), 3389:("RDP","Небезпечний","🔴"),
    5353:("mDNS","Нормальний","🟢"), 8080:("HTTP-Alt","Підозрілий","🟠"),
    8443:("HTTPS-Alt","Нормальний","🟢"), 9100:("Printer","Підозрілий","🟠"),
}
DANGEROUS_PORTS  = {21,23,135,139,445,3389}
SUSPICIOUS_PORTS = {25,110,8080,9100}

DEVICE_SIGNATURES: list[dict] = [
    {"ports":[62078],       "name":"iPhone / iPad",     "vendor":"Apple",    "icon":"📱","os":"iOS"},
    {"ports":[8008,8009],   "name":"Chromecast",         "vendor":"Google",   "icon":"📺","os":""},
    {"ports":[8008],        "name":"Android TV",         "vendor":"Android",  "icon":"📺","os":"Android TV"},
    {"ports":[7000],        "name":"AirPlay Device",     "vendor":"Apple",    "icon":"📺","os":""},
    {"ports":[7100],        "name":"AirPlay (Receiver)", "vendor":"Apple",    "icon":"📺","os":""},
    {"ports":[554,80],      "name":"IP Camera",          "vendor":"",         "icon":"📷","os":""},
    {"ports":[554],         "name":"IP Camera / DVR",    "vendor":"",         "icon":"📷","os":""},
    {"ports":[9100],        "name":"Printer",            "vendor":"",         "icon":"🖨️","os":""},
    {"ports":[5000,5001],   "name":"NAS (Synology)",     "vendor":"Synology", "icon":"🗄️","os":"DiskStation"},
    {"ports":[5000],        "name":"NAS",                "vendor":"",         "icon":"🗄️","os":""},
    {"ports":[3306],        "name":"Database Server",    "vendor":"",         "icon":"🗄️","os":""},
    {"ports":[1883],        "name":"IoT Hub (MQTT)",     "vendor":"",         "icon":"🔌","os":""},
    {"ports":[8883],        "name":"IoT Hub (MQTT TLS)", "vendor":"",         "icon":"🔌","os":""},
    {"ports":[49152,55000], "name":"Smart TV (Samsung)", "vendor":"Samsung",  "icon":"📺","os":"Tizen"},
    {"ports":[1400],        "name":"Sonos Speaker",      "vendor":"Sonos",    "icon":"🔊","os":""},
    {"ports":[3689],        "name":"iTunes / AirPlay",   "vendor":"Apple",    "icon":"🔊","os":""},
    {"ports":[135,139,445], "name":"Windows PC",         "vendor":"",         "icon":"💻","os":"Windows"},
    {"ports":[22,80],       "name":"Linux Server",       "vendor":"",         "icon":"🖥️","os":"Linux"},
    {"ports":[22],          "name":"SSH Device",         "vendor":"",         "icon":"🖥️","os":""},
]

HTTP_SERVER_FINGERPRINTS: dict[str,tuple[str,str]] = {
    "netis":("Netis",    "Router"), "netcore":("Netis",    "Router"),
    "netcore wifi":("Netis",    "Router"),
    "wf2419":("Netis",    "Router"), "wf2780":("Netis",    "Router"),
    "wf2880":("Netis",    "Router"), "e1+":("Netis",    "Router"),
     "cudy":("Cudy",     "Router"), "wavlink":("Wavlink",  "Router"),
    "mercusys":("Mercusys", "Router"), "fast router":("FAST",     "Router"),
    "comfast":("COMFAST",  "Router"), "ip-com":("IP-COM",   "Router"),
    "tplink":("TP-Link","Router"),"tp-link":("TP-Link","Router"),
    "tapo":("TP-Link","Smart Plug"),"kasa":("TP-Link","Smart Plug"),
    "mikrotik":("MikroTik","Router"),"routeros":("MikroTik","Router"),
    "keenetic":("Keenetic","Router"),"asus":("ASUS","Router"),
    "ubiquiti":("Ubiquiti","Access Point"),"unifi":("Ubiquiti","UniFi AP"),
    "hikvision":("Hikvision","IP Camera"),"dahua":("Dahua","IP Camera"),
    "reolink":("Reolink","IP Camera"),"axis":("Axis","IP Camera"),
    "synology":("Synology","NAS"),"qnap":("QNAP","NAS"),
    "samsung":("Samsung","Smart TV"),"lg webos":("LG","Smart TV"),
    "sony bravia":("Sony","Smart TV"),"roku":("Roku","Streaming Device"),
    "chromecast":("Google","Chromecast"),"epson":("Epson","Printer"),
    "canon":("Canon","Printer"),"hp-ipp":("HP","Printer"),
    "brother":("Brother","Printer"),"raspberry":("Raspberry Pi","Linux SBC"),
    "openwrt":("OpenWrt","Router"),"dd-wrt":("DD-WRT","Router"),
    "tomato":("Tomato","Router"),"fortinet":("Fortinet","Firewall"),
    "cisco":("Cisco","Network Device"),"pfsense":("pfSense","Firewall"),
    "proxmox":("Proxmox","Hypervisor"),"esxi":("VMware","ESXi Host"),
    "shelly":("Shelly","Smart Plug"),"sonoff":("Sonoff","Smart Switch"),
    "tuya":("Tuya","Smart Device"),"ewelink":("eWeLink","Smart Switch"),
    "wemo":("Belkin","Smart Plug"),"meross":("Meross","Smart Plug"),
    "smartplug":("","Smart Plug"),"smart plug":("","Smart Plug"),
    "smart switch":("","Smart Switch"),"homekit":("","Smart Home"),
    "homeassist":("","Home Assistant"),
}

# ══════════════════════════════════════════════════════════════════
# PERMANENT BAN MANAGER — вічне ARP-отруєння забанених пристроїв
# ══════════════════════════════════════════════════════════════════
class PermanentBanManager:
    """
    Блокування пристроїв через ARP-спуфінг.

    Логіка (як NetCut / bettercap):
      1. Вимикаємо IP-forwarding — щоб наш ПК ДРОПАВ пакети цілі,
         а не пересилав їх. Без цього блокування не працює!
      2. Надсилаємо ARP-відповіді обом сторонам:
         - Цілі кажемо: "MAC шлюзу = наш MAC"  → ціль шле нам
         - Шлюзу кажемо: "MAC цілі = наш MAC"  → шлюз шле нам
         Оскільки forwarding вимкнено — ми дропаємо всі ці пакети.
      3. При розбані — відновлюємо правильні ARP і вмикаємо forwarding.

    Джерела: NetCut, bettercap arp.spoof, github.com/davidlares/arp-spoofing
    """

    def __init__(self):
        self._threads:    dict = {}   # {mac_upper: Thread}
        self._stop_flags: dict = {}   # {mac_upper: Event}
        self._info:       dict = {}   # {mac_upper: (ip, gw_ip, gw_mac, our_mac)}
        self._fwd_disabled     = False
        self.running           = True

    # ── IP Forwarding управління ──────────────────────────────────────

    @staticmethod
    def _set_ip_forward(enable: bool):
        """
        Вмикає (enable=True) або вимикає (enable=False) IP forwarding.
        Вимкнення = пакети не пересилаються = BLOCK.
        """
        import platform as _pl
        try:
            if _pl.system() == "Windows":
                # Windows: через netsh або реєстр
                val = "1" if enable else "0"
                subprocess.run(
                    ["netsh", "int", "ipv4", "set", "global",
                     f"forwarding={'enabled' if enable else 'disabled'}"],
                    capture_output=True, timeout=5)
                # Також через реєстр для надійності
                try:
                    import winreg
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                        0, winreg.KEY_SET_VALUE)
                    winreg.SetValueEx(key, "IPEnableRouter", 0,
                                      winreg.REG_DWORD, 1 if enable else 0)
                    winreg.CloseKey(key)
                except Exception:
                    pass
            else:
                # Linux / macOS
                val = "1" if enable else "0"
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write(val)
        except Exception:
            pass

    def _ensure_forward_disabled(self):
        """Вимикаємо forwarding один раз (коли перший бан стартує)."""
        if not self._fwd_disabled:
            self._set_ip_forward(False)
            self._fwd_disabled = True

    def _maybe_restore_forward(self):
        """Відновлюємо forwarding коли всі бани знято."""
        if self._fwd_disabled and not self._threads:
            self._set_ip_forward(True)
            self._fwd_disabled = False

    # ── Основні методи ────────────────────────────────────────────────

    def start_ban(self, target_ip: str, target_mac: str,
                  gateway_ip: str, gw_mac: str) -> bool:
        """
        Запускає ARP-блокування пристрою.
        Повертає True якщо Scapy доступний і потік запущено.
        """
        mac_key = target_mac.upper().replace("-",":")

        if mac_key in self._threads and self._threads[mac_key].is_alive():
            return True  # вже активний

        # ── Крок 1: перевіряємо Scapy і отримуємо наш MAC ───────────
        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf
            conf.verb = 0
            try:
                our_mac = get_if_hwaddr(conf.iface)
            except Exception:
                # fallback: визначаємо через uuid
                import uuid
                raw = hex(uuid.getnode())[2:].zfill(12)
                our_mac = ":".join(raw[i:i+2] for i in range(0,12,2)).upper()

        except ImportError:
            return False  # Scapy не встановлений

        # ── Крок 2: вимикаємо IP forwarding ──────────────────────────
        self._ensure_forward_disabled()

        self._info[mac_key]      = (target_ip, gateway_ip, gw_mac, our_mac)
        stop_evt                  = threading.Event()
        self._stop_flags[mac_key] = stop_evt

        def _loop(tip=target_ip, tmac=mac_key,
                  gip=gateway_ip,  gmac=gw_mac, our=our_mac):
            try:
                from scapy.all import ARP, Ether, sendp

                # ── Правильні ARP пакети (як у NetCut/bettercap) ─────
                # Цілі: "MAC шлюзу = наш MAC" → ціль шле нам
                pkt_to_victim = (
                    Ether(src=our, dst=tmac) /
                    ARP(op=2,
                        hwsrc=our,   # наш MAC — реальний відправник
                        psrc=gip,    # прикидаємось шлюзом
                        hwdst=tmac,
                        pdst=tip)
                )
                # Шлюзу: "MAC цілі = наш MAC" → шлюз шле нам
                pkt_to_gateway = (
                    Ether(src=our, dst=gmac) /
                    ARP(op=2,
                        hwsrc=our,   # наш MAC
                        psrc=tip,    # прикидаємось ціллю
                        hwdst=gmac,
                        pdst=gip)
                )

                while not stop_evt.is_set() and self.running:
                    sendp([pkt_to_victim, pkt_to_gateway],
                          count=7, inter=0.01, verbose=False)
                    stop_evt.wait(timeout=0.5)  # 2 рази/с

                # ── Відновлення після розбану ─────────────────────────
                # Надсилаємо правильні ARP щоб відновити зв'язок
                try:
                    restore = [
                        # Цілі: "MAC шлюзу = справжній MAC шлюзу"
                        Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=2,
                            hwsrc=gmac, psrc=gip,
                            hwdst="ff:ff:ff:ff:ff:ff", pdst=tip),
                        # Шлюзу: "MAC цілі = справжній MAC цілі"
                        Ether(dst="ff:ff:ff:ff:ff:ff") /
                        ARP(op=2,
                            hwsrc=tmac, psrc=tip,
                            hwdst="ff:ff:ff:ff:ff:ff", pdst=gip),
                    ]
                    sendp(restore, count=8, inter=0.05, verbose=False)
                except Exception:
                    pass

            except Exception:
                pass

        t = threading.Thread(target=_loop, daemon=True,
                             name=f"NetGuardian-Block-{mac_key[:8]}")
        self._threads[mac_key] = t
        t.start()
        return True

    def stop_ban(self, target_mac: str):
        """Зупиняє блокування і відновлює з'єднання пристрою."""
        mac_key = target_mac.upper().replace("-",":")
        evt = self._stop_flags.pop(mac_key, None)
        if evt:
            evt.set()
        self._threads.pop(mac_key, None)
        self._info.pop(mac_key, None)
        # Якщо це останній бан — відновлюємо IP forwarding
        self._maybe_restore_forward()

    def stop_all(self):
        """Зупиняє всі активні блокування."""
        self.running = False
        for evt in self._stop_flags.values():
            evt.set()
        self._threads.clear()
        self._stop_flags.clear()
        self._info.clear()
        # Відновлюємо IP forwarding
        self._maybe_restore_forward()

    def is_active(self, target_mac: str) -> bool:
        mac_key = target_mac.upper().replace("-",":")
        t = self._threads.get(mac_key)
        return t is not None and t.is_alive()

    @property
    def active_count(self) -> int:
        return sum(1 for t in self._threads.values() if t.is_alive())




# Глобальний менеджер — живе весь час роботи програми
permanent_ban_manager = PermanentBanManager()


# ══════════════════════════════════════════════════════════════════
# TRUST DATABASE
# ══════════════════════════════════════════════════════════════════
# __file__ = <ROOT>/features/security/lan_security.py → 3 рівні до ROOT
_LAN_SEC_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEFAULT_TRUST_DB = os.path.join(_LAN_SEC_PROJECT_ROOT, "data", "lan_trust.db")

class TrustDatabase:
    def __init__(self, path: str = _DEFAULT_TRUST_DB):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self._path = path; self._lock = threading.Lock(); self._init_schema()

    def _connect(self): return sqlite3.connect(self._path, check_same_thread=False)

    def _init_schema(self):
        with self._lock:
            con = self._connect()
            con.execute("""CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY, ip TEXT, vendor TEXT,
                model TEXT DEFAULT '', hostname TEXT DEFAULT '',
                first_seen REAL, last_seen REAL, trusted INTEGER DEFAULT 0,
                label TEXT DEFAULT '', notes TEXT DEFAULT '')""")
            for sql in [
                "ALTER TABLE devices ADD COLUMN allowed         INTEGER DEFAULT 0",
                "ALTER TABLE devices ADD COLUMN alert_dismissed INTEGER DEFAULT 0",
                "ALTER TABLE devices ADD COLUMN gateway         TEXT DEFAULT ''",
            ]:
                try: con.execute(sql)
                except Exception: pass
            con.execute("""CREATE TABLE IF NOT EXISTS router_settings (
                gateway TEXT PRIMARY KEY, suppress_warnings INTEGER DEFAULT 0,
                label TEXT DEFAULT '')""")
            con.execute("""CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL,
                event_type TEXT, mac TEXT, ip TEXT, description TEXT)""")
            # ── Таблиця забанених пристроїв ──────────────────────
            con.execute("""CREATE TABLE IF NOT EXISTS banned (
                mac         TEXT PRIMARY KEY,
                ip          TEXT DEFAULT '',
                vendor      TEXT DEFAULT '',
                label       TEXT DEFAULT '',
                reason      TEXT DEFAULT '',
                banned_at   REAL,
                expires_at  REAL DEFAULT 0)""")
            con.commit(); con.close()

    # ── BAN API ───────────────────────────────────────────────────

    def ban_device(self, mac: str, ip: str = "", vendor: str = "",
                   label: str = "", reason: str = "",
                   duration: float = 0.0):
        """
        Додає пристрій до списку забанених.
        duration=0 → назавжди; duration>0 → секунди (expires_at = now+duration).

        ВАЖЛИВО: Автоматично знімає прапорці allowed / alert_dismissed,
        бо забанений пристрій НЕ МОЖЕ бути одночасно "дозволений".
        """
        now       = time.time()
        expires   = (now + duration) if duration > 0 else 0.0
        with self._lock:
            con = self._connect()
            con.execute("""INSERT OR REPLACE INTO banned
                           (mac, ip, vendor, label, reason, banned_at, expires_at)
                           VALUES (?,?,?,?,?,?,?)""",
                        (mac, ip, vendor, label, reason, now, expires))
            # Знімаємо allowed і alert_dismissed щоб уникнути конфлікту станів
            con.execute(
                "UPDATE devices SET allowed=0, alert_dismissed=0, trusted=0 WHERE mac=?",
                (mac,))
            con.commit(); con.close()

    def unban_device(self, mac: str):
        """Знімає бан з пристрою."""
        with self._lock:
            con = self._connect()
            con.execute("DELETE FROM banned WHERE mac=?", (mac,))
            con.commit(); con.close()

    def is_banned(self, mac: str) -> bool:
        """True якщо пристрій забанений і бан ще активний."""
        with self._lock:
            con = self._connect()
            row = con.execute(
                "SELECT expires_at FROM banned WHERE mac=?", (mac,)).fetchone()
            con.close()
        if not row: return False
        expires = row[0]
        if expires > 0 and time.time() > expires:
            # Бан закінчився — прибираємо
            self.unban_device(mac)
            return False
        return True

    def get_banned(self) -> list:
        """Список всіх активних банів."""
        now = time.time()
        with self._lock:
            con = self._connect()
            rows = con.execute(
                "SELECT mac,ip,vendor,label,reason,banned_at,expires_at "
                "FROM banned ORDER BY banned_at DESC").fetchall()
            con.close()
        result = []
        for r in rows:
            mac, ip, vendor, label, reason, banned_at, expires_at = r
            if expires_at > 0 and now > expires_at:
                self.unban_device(mac)
                continue
            result.append({
                "mac": mac, "ip": ip, "vendor": vendor,
                "label": label, "reason": reason,
                "banned_at": banned_at, "expires_at": expires_at,
                "is_permanent": expires_at == 0,
                "remaining": max(0, int(expires_at - now)) if expires_at > 0 else None,
            })
        return result

    def upsert(self, mac, ip, vendor, model="", hostname="", gateway="") -> bool:
        with self._lock:
            con = self._connect(); now = time.time()
            existing = con.execute("SELECT mac FROM devices WHERE mac=?", (mac,)).fetchone()
            is_new = existing is None
            if is_new:
                con.execute("INSERT INTO devices(mac,ip,vendor,model,hostname,first_seen,last_seen,trusted,allowed,gateway) VALUES(?,?,?,?,?,?,?,0,0,?)",
                            (mac,ip,vendor,model,hostname,now,now,gateway))
            else:
                con.execute("UPDATE devices SET ip=?,last_seen=?,model=?,hostname=?,gateway=? WHERE mac=?",
                            (ip,now,model,hostname,gateway,mac))
            con.commit(); con.close(); return is_new

    def log_event(self, event_type, mac, ip, description):
        with self._lock:
            con = self._connect()
            con.execute("INSERT INTO events(ts,event_type,mac,ip,description) VALUES(?,?,?,?,?)",
                        (time.time(),event_type,mac,ip,description))
            con.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY ts DESC LIMIT 1000)")
            con.commit(); con.close()

    def get_recent_events(self, limit=50) -> list:
        with self._lock:
            con = self._connect()
            rows = con.execute("SELECT ts,event_type,mac,ip,description FROM events ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()
            con.close()
        return [{"ts":r[0],"type":r[1],"mac":r[2],"ip":r[3],"desc":r[4]} for r in rows]

    def set_trusted(self, mac, trusted):
        with self._lock:
            con = self._connect()
            con.execute("UPDATE devices SET trusted=?,allowed=? WHERE mac=?", (int(trusted),int(trusted),mac))
            # Якщо робимо довіреним — знімаємо з banned
            if trusted:
                con.execute("DELETE FROM banned WHERE mac=?", (mac,))
            con.commit(); con.close()

    def set_allowed(self, mac, allowed):
        with self._lock:
            con = self._connect()
            con.execute("UPDATE devices SET allowed=?,alert_dismissed=1 WHERE mac=?", (int(allowed),mac))
            # Якщо робимо дозволеним — знімаємо з banned (щоб уникнути конфлікту)
            if allowed:
                con.execute("DELETE FROM banned WHERE mac=?", (mac,))
            con.commit(); con.close()

    def dismiss_alert(self, mac):
        with self._lock:
            con = self._connect()
            con.execute("UPDATE devices SET alert_dismissed=1 WHERE mac=?", (mac,))
            # Dismiss = пропустити попередження → знімаємо з banned
            con.execute("DELETE FROM banned WHERE mac=?", (mac,))
            con.commit(); con.close()

    def restore_alert(self, mac):
        with self._lock:
            con = self._connect()
            con.execute("UPDATE devices SET alert_dismissed=0, allowed=0 WHERE mac=?", (mac,))
            con.commit(); con.close()

    def set_label(self, mac, label, notes=""):
        with self._lock:
            con = self._connect()
            con.execute("UPDATE devices SET label=?, notes=? WHERE mac=?", (label,notes,mac))
            con.commit(); con.close()

    def is_trusted(self, mac) -> bool:
        with self._lock:
            con = self._connect()
            row = con.execute("SELECT trusted FROM devices WHERE mac=?", (mac,)).fetchone()
            con.close(); return bool(row and row[0])

    def is_alert_dismissed(self, mac) -> bool:
        with self._lock:
            con = self._connect()
            row = con.execute("SELECT alert_dismissed FROM devices WHERE mac=?", (mac,)).fetchone()
            con.close(); return bool(row and row[0])

    def set_router_suppress(self, gateway, suppress, label=""):
        with self._lock:
            con = self._connect()
            con.execute("INSERT OR REPLACE INTO router_settings(gateway,suppress_warnings,label) VALUES(?,?,?)",
                        (gateway,int(suppress),label))
            con.commit(); con.close()

    def get_router_suppress(self, gateway) -> bool:
        with self._lock:
            con = self._connect()
            row = con.execute("SELECT suppress_warnings FROM router_settings WHERE gateway=?", (gateway,)).fetchone()
            con.close(); return bool(row and row[0])

    def get_device(self, mac) -> Optional[dict]:
        with self._lock:
            con = self._connect()
            row = con.execute("SELECT mac,ip,vendor,model,hostname,first_seen,last_seen,trusted,allowed,label,notes,alert_dismissed,gateway FROM devices WHERE mac=?", (mac,)).fetchone()
            con.close()
        if not row: return None
        return {"mac":row[0],"ip":row[1],"vendor":row[2],"model":row[3],"hostname":row[4],
                "first_seen":row[5],"last_seen":row[6],"trusted":bool(row[7]),"allowed":bool(row[8]),
                "label":row[9],"notes":row[10],"alert_dismissed":bool(row[11]),"gateway":row[12] or ""}

    def get_all(self) -> list:
        with self._lock:
            con = self._connect()
            rows = con.execute("SELECT mac,ip,vendor,model,hostname,first_seen,last_seen,trusted,allowed,label,notes,alert_dismissed,gateway FROM devices ORDER BY last_seen DESC").fetchall()
            con.close()
        return [{"mac":r[0],"ip":r[1],"vendor":r[2],"model":r[3],"hostname":r[4],
                 "first_seen":r[5],"last_seen":r[6],"trusted":bool(r[7]),"allowed":bool(r[8]),
                 "label":r[9],"notes":r[10],"alert_dismissed":bool(r[11]),"gateway":r[12] or ""} for r in rows]

    def get_devices_by_gateway(self, gateway) -> list:
        with self._lock:
            con = self._connect()
            rows = con.execute("SELECT mac,ip,vendor,model,hostname,first_seen,last_seen,trusted,allowed,label,notes,alert_dismissed,gateway FROM devices WHERE gateway=? ORDER BY last_seen DESC", (gateway,)).fetchall()
            con.close()
        return [{"mac":r[0],"ip":r[1],"vendor":r[2],"model":r[3],"hostname":r[4],
                 "first_seen":r[5],"last_seen":r[6],"trusted":bool(r[7]),"allowed":bool(r[8]),
                 "label":r[9],"notes":r[10],"alert_dismissed":bool(r[11]),"gateway":r[12] or ""} for r in rows]

trust_db = TrustDatabase()

# ══════════════════════════════════════════════════════════════════
# ROUTER MANAGER
# ══════════════════════════════════════════════════════════════════
class RouterManager:
    # Використовуємо той самий _LAN_SEC_PROJECT_ROOT що вище в файлі
    CONFIG_FILE = os.path.join(_LAN_SEC_PROJECT_ROOT, "data", "routers.json")
    def __init__(self):
        self._routers: dict = {}; self._lock = threading.Lock(); self._load()

    def _load(self):
        try:
            if os.path.exists(self.CONFIG_FILE):
                with open(self.CONFIG_FILE,"r",encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data,dict):
                        with self._lock: self._routers = data
        except Exception: pass

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.CONFIG_FILE),exist_ok=True)
            with self._lock: routers_copy = dict(self._routers)
            with open(self.CONFIG_FILE,"w",encoding="utf-8") as f:
                json.dump(routers_copy,f,ensure_ascii=False,indent=2)
        except Exception as e: print(f"[RouterManager] Save error: {e}")

    def add_router(self, name, ip, http_user="admin", http_pwd="admin",
                   ssh_user="", ssh_pwd="", ssh_port=22, ssh_key="", label="", notes="") -> dict:
        config = {"name":name,"ip":ip,"http_user":http_user,"http_pwd":http_pwd,
                  "ssh_user":ssh_user,"ssh_pwd":ssh_pwd,"ssh_port":ssh_port,
                  "ssh_key":ssh_key,"label":label or name,"notes":notes,"added_at":time.time()}
        with self._lock: self._routers[name] = config
        if ssh_user and ssh_pwd:
            RouterSSHScanner.ssh_config[ip] = {"user":ssh_user,"pwd":ssh_pwd,"port":ssh_port,"key_path":ssh_key}
        self.save(); return config

    def remove_router(self, name) -> bool:
        with self._lock:
            if name in self._routers:
                del self._routers[name]; self.save(); return True
        return False

    def get_router(self, name) -> Optional[dict]:
        with self._lock: return dict(self._routers.get(name,{})) or None

    def get_router_by_ip(self, ip) -> Optional[dict]:
        with self._lock:
            for r in self._routers.values():
                if r.get("ip") == ip: return dict(r)
        return None

    def list_routers(self) -> list:
        with self._lock: return [dict(v) for v in self._routers.values()]

    def count(self) -> int:
        with self._lock: return len(self._routers)

    def apply_credentials(self, reader, name):
        cfg = self.get_router(name)
        if cfg:
            reader._username = cfg.get("http_user","admin")
            reader._password = cfg.get("http_pwd","admin")

    def get_all_ips(self) -> list:
        with self._lock: return [r.get("ip","") for r in self._routers.values() if r.get("ip")]

router_manager = RouterManager()

# ══════════════════════════════════════════════════════════════════
# ROUTER SSH SCANNER
# ══════════════════════════════════════════════════════════════════
class RouterSSHScanner:
    ssh_config: dict = {}
    DEFAULT_CREDS = [("admin","admin"),("admin",""),("admin","password"),
                     ("admin","1234"),("root",""),("root","root"),
                     ("root","admin"),("ubnt","ubnt"),("ec2-user","")]
    DNSMASQ_LEASE_PATHS = ["/var/lib/misc/dnsmasq.leases","/tmp/dhcp.leases",
                           "/var/lib/dhcp/dhcpd.leases","/tmp/dnsmasq.leases",
                           "/data/userdata/dhcp.leases"]

    def __init__(self, gateway, timeout=3.0):
        self.gateway = gateway; self.timeout = timeout; self._ssh_ok = False

    def _check_paramiko(self) -> bool:
        try: import paramiko; return True
        except ImportError: return False

    def _connect(self, user, pwd, port=22, key_path=""):
        try:
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            kw = {"hostname":self.gateway,"port":port,"username":user,
                  "timeout":self.timeout,"banner_timeout":self.timeout,"auth_timeout":self.timeout}
            if key_path and os.path.exists(key_path):
                kw["key_filename"] = key_path; kw["look_for_keys"] = False
            else:
                kw["password"] = pwd; kw["look_for_keys"] = False; kw["allow_agent"] = False
            ssh.connect(**kw); return ssh
        except Exception: return None

    def _exec(self, ssh, command) -> str:
        try:
            _, stdout, _ = ssh.exec_command(command, timeout=self.timeout)
            return stdout.read().decode("utf-8",errors="ignore").strip()
        except Exception: return ""

    def _parse_dnsmasq_leases(self, text) -> list:
        clients = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 4: continue
            mac = parts[1].upper(); ip = parts[2]
            hostname = parts[3] if parts[3] != "*" else ""
            if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$",mac): continue
            if not re.match(r"^\d+\.\d+\.\d+\.\d+$",ip): continue
            clients.append({"mac":mac,"ip":ip,"hostname":hostname,"connection_type":"","source":"SSH dnsmasq"})
        return clients

    def _parse_isc_dhcpd_leases(self, text) -> list:
        clients = []
        for block in re.split(r"lease\s+",text):
            ip_m = re.match(r"(\d+\.\d+\.\d+\.\d+)",block)
            if not ip_m: continue
            ip = ip_m.group(1)
            mac_m = re.search(r"hardware ethernet\s+([0-9a-f:]{17})",block,re.IGNORECASE)
            if not mac_m: continue
            mac = mac_m.group(1).upper()
            hn_m = re.search(r'client-hostname\s+"([^"]+)"',block)
            hostname = hn_m.group(1) if hn_m else ""
            if "binding state active" not in block.lower(): continue
            clients.append({"mac":mac,"ip":ip,"hostname":hostname,"connection_type":"","source":"SSH ISC DHCP"})
        return clients

    def _parse_mikrotik_leases(self, text) -> list:
        clients = []
        merged = re.sub(r"\n\s+"," ",text)
        for line in merged.splitlines():
            mac_m = re.search(r"mac-address=([0-9A-Fa-f:]{17})",line)
            ip_m  = re.search(r"address=(\d+\.\d+\.\d+\.\d+)",line)
            if not mac_m or not ip_m: continue
            mac = mac_m.group(1).upper(); ip = ip_m.group(1)
            status = re.search(r"status=(\w+)",line)
            if status and status.group(1) not in ("bound","waiting"): continue
            hn_m    = re.search(r'host-name="([^"]+)"',line)
            comment = re.search(r'comment="([^"]+)"',line)
            hostname = (hn_m.group(1) if hn_m else "") or (comment.group(1) if comment else "")
            clients.append({"mac":mac,"ip":ip,"hostname":hostname,"connection_type":"","source":"SSH MikroTik"})
        return clients

    def _parse_keenetic_ndm(self, text) -> list:
        clients = []
        try:
            data = json.loads(text)
            items = data if isinstance(data,list) else data.get("host",[])
            for item in items:
                mac = item.get("mac","").upper(); ip = item.get("ip","") or item.get("address","")
                hn  = item.get("name","") or item.get("hostname","")
                if mac and ip:
                    clients.append({"mac":mac,"ip":ip,"hostname":hn,"connection_type":"","source":"SSH Keenetic"})
            if clients: return clients
        except Exception: pass
        for line in text.splitlines():
            mac_m = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",line,re.IGNORECASE)
            ip_m  = re.search(r"(\d+\.\d+\.\d+\.\d+)",line)
            if mac_m and ip_m:
                clients.append({"mac":mac_m.group(1).upper(),"ip":ip_m.group(1),"hostname":"","connection_type":"","source":"SSH Keenetic"})
        return clients

    def _parse_ubiquiti_leases(self, text) -> list:
        clients = []
        for line in text.splitlines():
            parts = line.split()
            if len(parts) < 2: continue
            ip_m  = re.match(r"(\d+\.\d+\.\d+\.\d+)$",parts[0])
            mac_m = re.match(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})$",parts[1],re.IGNORECASE)
            if ip_m and mac_m:
                hostname = parts[4] if len(parts) >= 5 else ""
                clients.append({"mac":mac_m.group(1).upper(),"ip":ip_m.group(1),"hostname":hostname,"connection_type":"","source":"SSH Ubiquiti"})
        return clients

    def _parse_arp_output(self, text) -> list:
        clients = []
        for line in text.splitlines():
            mac_m = re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",line,re.IGNORECASE)
            ip_m  = re.search(r"(\d+\.\d+\.\d+\.\d+)",line)
            if mac_m and ip_m:
                mac = mac_m.group(1).upper(); ip = ip_m.group(1)
                if mac != "FF:FF:FF:FF:FF:FF" and not ip.endswith(".255"):
                    clients.append({"mac":mac,"ip":ip,"hostname":"","connection_type":"","source":"SSH ARP"})
        return clients

    def fetch_dhcp_leases(self, user="", pwd="", port=22, key_path="") -> list:
        if not self._check_paramiko(): return []
        saved = RouterSSHScanner.ssh_config.get(self.gateway,{})
        if user and pwd: cred_list = [(user,pwd,port,key_path)]
        elif saved: cred_list = [(saved.get("user","admin"),saved.get("pwd",""),saved.get("port",22),saved.get("key_path",""))]
        else: cred_list = [(u,p,22,"") for u,p in self.DEFAULT_CREDS]
        for _user,_pwd,_port,_key in cred_list:
            ssh = self._connect(_user,_pwd,_port,_key)
            if ssh is None: continue
            self._ssh_ok = True
            RouterSSHScanner.ssh_config[self.gateway] = {"user":_user,"pwd":_pwd,"port":_port,"key_path":_key}
            clients = []
            for path in self.DNSMASQ_LEASE_PATHS:
                output = self._exec(ssh,f"cat {path} 2>/dev/null")
                if output and re.search(r"\d+\.\d+\.\d+\.\d+",output):
                    clients = self._parse_dnsmasq_leases(output)
                    if clients: break
            if not clients:
                output = self._exec(ssh,"cat /var/lib/dhcp/dhcpd.leases 2>/dev/null")
                if output and "lease" in output: clients = self._parse_isc_dhcpd_leases(output)
            if not clients:
                output = self._exec(ssh,"/ip dhcp-server lease print terse 2>/dev/null")
                if output and "address=" in output: clients = self._parse_mikrotik_leases(output)
            if not clients:
                for cmd in ["ndm lease list 2>/dev/null","show ip dhcp 2>/dev/null"]:
                    output = self._exec(ssh,cmd)
                    if output and re.search(r"\d+\.\d+\.\d+\.\d+",output):
                        clients = self._parse_keenetic_ndm(output)
                        if clients: break
            if not clients:
                output = self._exec(ssh,"show dhcp leases 2>/dev/null")
                if output and re.search(r"\d+\.\d+\.\d+\.\d+",output):
                    clients = self._parse_ubiquiti_leases(output)
            if not clients:
                output = self._exec(ssh,"arp -a 2>/dev/null || ip neigh show 2>/dev/null")
                if output: clients = self._parse_arp_output(output)
            ssh.close(); return clients
        return []

    def is_available(self) -> bool:
        try:
            s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            s.settimeout(self.timeout); result = s.connect_ex((self.gateway,22)); s.close()
            return result == 0
        except Exception: return False

# ══════════════════════════════════════════════════════════════════
# ROUTER CLIENT READER  (незмінено від v5.3.2)
# ══════════════════════════════════════════════════════════════════
class RouterClientReader:
    DEFAULT_CREDS=[("admin","admin"),("admin",""),("admin","password"),
                   ("admin","1234"),("admin","admin1234"),("admin","12345678"),
                   ("user","user"),("root","root"),("admin","admin123")]

    def __init__(self,gateway,timeout=5.0,username="",password=""):
        self.gateway=gateway;self.timeout=timeout
        self._username=username or "admin";self._password=password or "admin"
        self._stok=""
        self._router_brand="";self._session_cookies="";self._auth_token=""
        self._cookiejar=http.cookiejar.CookieJar()
        self._opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self._cookiejar))
        try:
            req=urllib.request.Request(f"http://{self.gateway}/",headers={"User-Agent":"Mozilla/5.0"})
            self._opener.open(req,timeout=3)
        except Exception: pass

    def _fetch(self,path,method="GET",data=None,extra_headers=None,base64_auth=False)->Optional[str]:
        url=f"http://{self.gateway}{path}"
        headers={"User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
                 "Accept":"application/json, text/html, */*",
                 "Referer":f"http://{self.gateway}/","Origin":f"http://{self.gateway}","Connection":"keep-alive"}
        if self._session_cookies: headers["Cookie"]=self._session_cookies
        if self._auth_token: headers["Authorization"]=f"Bearer {self._auth_token}"
        if base64_auth:
            cred=base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
            headers["Authorization"]=f"Basic {cred}"
        if extra_headers: headers.update(extra_headers)
        post_data=None
        if data is not None:
            if isinstance(data,dict):
                post_data=json.dumps(data).encode();headers["Content-Type"]="application/json"
            elif isinstance(data,(bytes,str)):
                post_data=data if isinstance(data,bytes) else data.encode()
                headers.setdefault("Content-Type","application/json")
        try:
            req=urllib.request.Request(url,data=post_data,headers=headers,method=method)
            with self._opener.open(req,timeout=self.timeout) as r:
                hdr=r.headers.get("Set-Cookie","")
                if hdr:
                    self._session_cookies="; ".join(c.split(";")[0] for c in hdr.split(",") if "=" in c.split(";")[0])
                return r.read().decode("utf-8",errors="ignore")
        except Exception: return None

    def _fetch_json(self,path,data=None,method="GET")->Optional[dict]:
        raw=self._fetch(path,method=method,data=data)
        if not raw: return None
        try: return json.loads(raw)
        except Exception: return None

    def _post_json(self, path: str, body) -> Optional[str]:
        """POST з JSON body, повертає сирий текст відповіді."""
        if isinstance(body, dict):
            body = json.dumps(body)
        return self._fetch(path, method="POST", data=body,
                           extra_headers={"Content-Type": "application/json"})

    def get_all_clients(self)->list:
        methods=[("TP-Link",self._try_tplink),("ASUS",self._try_asus),
                 ("Keenetic",self._try_keenetic),("MikroTik",self._try_mikrotik),
                 ("Xiaomi",self._try_xiaomi),("Huawei",self._try_huawei),
                 ("D-Link",self._try_dlink),("Netis",self._try_netis),
                 ("Tenda",self._try_tenda),("Netgear",self._try_netgear),
                 ("ZyXEL",self._try_zyxel),("Ubiquiti",self._try_ubiquiti),
                 ("Generic",self._try_generic)]
        for brand,method in methods:
            try:
                result=method()
                if result and len(result)>=1:
                    self._router_brand=brand;merged:dict={}
                    for c in result:
                        mac=c.get("mac","").upper().replace("-",":")
                        if not mac or len(mac)<17: continue
                        if mac not in merged: merged[mac]=c
                        else:
                            ex=merged[mac]
                            if c.get("signal_dbm") and not ex.get("signal_dbm"): ex.update(c)
                            elif c.get("hostname") and not ex.get("hostname"): ex["hostname"]=c["hostname"]
                            if c.get("connection_type")=="WiFi":
                                ex["connection_type"]="WiFi"
                                if c.get("band") and not ex.get("band"): ex["band"]=c["band"]
                    return list(merged.values())
            except Exception: continue
        return []

    def get_dhcp_clients(self)->list:
        return [c for c in self.get_all_clients() if c.get("ip")]

    def _tplink_login(self)->str:
        pwd_md5=hashlib.md5(self._password.encode()).hexdigest().upper()
        for ep in ["/cgi-bin/luci/;stok=/rpc/v1","/cgi-bin/luci/;stok=/rc/v1","/cgi-bin/luci/;stok=/rpc"]:
            resp=self._fetch_json(ep,data={"method":"do","login":{"password":pwd_md5}})
            if resp:
                stok=(resp.get("stok") or resp.get("data",{}).get("stok",""))
                if not stok and resp.get("error_code")==0: stok=resp.get("result",{}).get("stok","")
                if stok: self._stok=stok; return stok
        form=urllib.parse.urlencode({"username":self._username,"password":pwd_md5}).encode()
        raw=self._fetch("/cgi-bin/luci/",data=form,extra_headers={"Content-Type":"application/x-www-form-urlencoded"})
        if raw:
            m=re.search(r"stok=([a-f0-9]+)",raw)
            if m: self._stok=m.group(1); return m.group(1)
        return ""

    def _tplink_parse_client(self,c)->dict:
        mac=(c.get("macaddr") or c.get("mac") or c.get("MAC") or c.get("macAddress") or "").upper().replace("-",":")
        ip=(c.get("ipaddr") or c.get("ip") or c.get("IP") or c.get("ipAddress") or "")
        name=(c.get("custom_name") or c.get("alias") or c.get("name") or
              c.get("hostname") or c.get("deviceName") or c.get("host_name") or "")
        wire=str(c.get("type") or c.get("connect_type") or c.get("connType") or c.get("connection_type") or "")
        is_wifi=(c.get("is_wireless") or c.get("wifi") or c.get("isWireless") or
                 any(k in wire.lower() for k in ("wifi","wlan","2.4","5g","6g")) or
                 wire in ("2","5","6","2.4G","5G","6G"))
        ctype="WiFi" if is_wifi else "LAN";band=""
        if "2.4" in wire or wire in ("2.4G","2G","2"): band="2.4 GHz"
        elif wire in ("5G","5") or ("5" in wire and "2.4" not in wire): band="5 GHz"
        elif "6" in wire or wire in ("6G","6"): band="6 GHz"
        signal=c.get("rssi") or c.get("signal") or c.get("signalStrength")
        return {"mac":mac,"ip":ip,"hostname":name,"connection_type":ctype,"band":band,
                "signal_dbm":int(signal) if signal else None,"signal_pct":self._dbm_to_pct(signal),
                "tx_rate":str(c.get("tx_rate") or c.get("txrate") or c.get("txRate") or ""),
                "bytes_sent":c.get("bytes_sent") or c.get("traffic_up") or c.get("bytesSent"),
                "bytes_recv":c.get("bytes_recv") or c.get("traffic_down") or c.get("bytesRecv"),
                "connected_time":c.get("active_time") or c.get("online_time") or c.get("uptime"),
                "source":"TP-Link API"}

    def _try_tplink(self)->list:
        stok=self._tplink_login()
        def _try_eps(st)->list:
            eps=[f"/cgi-bin/luci/;stok={st}/rc/v1/hosts/list",f"/cgi-bin/luci/;stok={st}/rc/v1/hosts?form=all",
                 f"/cgi-bin/luci/;stok={st}/rc/v1/hosts",f"/cgi-bin/luci/;stok={st}/api/v2/network/hostList",
                 f"/cgi-bin/luci/;stok={st}/api/v2/network/wlanHostList",f"/cgi-bin/luci/;stok={st}/api/v2/wireless/clients",
                 f"/cgi-bin/luci/;stok={st}/rc/v1/dhcp/client",f"/cgi-bin/luci/;stok={st}/rc/v1/network/dhcp",
                 "/data/dhcpClient.json","/api/v2/network/hostList"]
            for ep in eps:
                resp=self._fetch_json(ep)
                if not resp: continue
                items=(resp.get("data") or resp.get("result",{}).get("hosts",[]) or
                       resp.get("host_info",{}).get("host_entry",[]) or resp.get("wlanHostList",[]) or
                       resp.get("dhcp_list",[]) or (resp if isinstance(resp,list) else []))
                if items and isinstance(items,list):
                    parsed=[self._tplink_parse_client(c) for c in items if c.get("mac") or c.get("macaddr")]
                    if parsed: return parsed
            return []
        result=_try_eps("")
        if result: return result
        if stok:
            result=_try_eps(stok)
            if result: return result
        return self._try_tplink_html()

    def _try_tplink_html(self)->list:
        clients=[]
        for page in ["/userRpm/AssignedIpAddrListRpm.htm","/userRpm/AssignedIpAddrListRpm.aspx"]:
            raw=self._fetch(page)
            if raw and "DHCPDynList" in raw:
                m=re.search(r"DHCPDynList\s*=\s*new Array\((.*?)\)",raw,re.DOTALL)
                if m:
                    entries=re.findall(r"'([^']*)'",m.group(1))
                    for i in range(0,len(entries)-3,5):
                        name=entries[i].strip();mac=entries[i+1].strip().upper().replace("-",":");ip=entries[i+2].strip()
                        if mac and len(mac)>=17:
                            clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":"LAN","band":"",
                                            "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                            "bytes_recv":None,"connected_time":None,"source":"TP-Link HTML DHCP"})
        raw=self._fetch("/userRpm/WlanStationRpm.htm")
        if raw and "wlanStaInfo" in raw:
            m=re.search(r"wlanStaInfo\s*=\s*new Array\((.*?)\)",raw,re.DOTALL)
            if m:
                entries=re.findall(r"'([^']*)'",m.group(1))
                for i in range(0,len(entries)-2,5):
                    mac=entries[i].strip().upper().replace("-",":");ip=entries[i+1].strip() if i+1<len(entries) else ""
                    rssi=entries[i+3].strip() if i+3<len(entries) else ""
                    if mac and len(mac)>=17:
                        clients.append({"mac":mac,"ip":ip,"hostname":"","connection_type":"WiFi","band":"",
                                        "signal_dbm":int(rssi) if rssi and rssi.lstrip("-").isdigit() else None,
                                        "signal_pct":self._dbm_to_pct(rssi),"tx_rate":"","bytes_sent":None,
                                        "bytes_recv":None,"connected_time":None,"source":"TP-Link HTML WiFi"})
        return clients

    def _try_asus(self)->list:
        clients=[]
        auth_b64=base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        raw=self._fetch("/appGet.cgi?hook=get_clientlist()",
                        extra_headers={"Authorization":f"Basic {auth_b64}","Referer":f"http://{self.gateway}/"})
        if not raw:
            form=urllib.parse.urlencode({"login_authorization":auth_b64}).encode()
            self._fetch("/login.cgi",data=form,extra_headers={"Content-Type":"application/x-www-form-urlencoded"})
            raw=self._fetch("/appGet.cgi?hook=get_clientlist()")
        if raw:
            try:
                data=json.loads(raw);cl=data.get("get_clientlist",{})
                for mac,info in cl.items():
                    if not isinstance(info,dict) or len(mac)<17: continue
                    is_wifi=info.get("isWL") in ("1",1,True);band=""
                    if is_wifi:
                        freq=str(info.get("wlFreq","") or info.get("band",""))
                        if "5" in freq: band="5 GHz"
                        elif "2" in freq: band="2.4 GHz"
                    clients.append({"mac":mac.upper(),"ip":info.get("ip",""),
                                    "hostname":info.get("name","") or info.get("nickName",""),
                                    "connection_type":"WiFi" if is_wifi else "LAN","band":band,
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":info.get("curTx",""),
                                    "bytes_sent":info.get("totalTx"),"bytes_recv":info.get("totalRx"),
                                    "connected_time":info.get("wlConnectTime",""),"source":"ASUS API"})
            except Exception: pass
        return clients

    def _keenetic_login(self)->bool:
        try:
            req=urllib.request.Request(f"http://{self.gateway}/auth",headers={"User-Agent":"Mozilla/5.0"})
            try:
                with self._opener.open(req,timeout=3): pass
                return True
            except urllib.error.HTTPError as e:
                if e.code==401:
                    realm=e.headers.get("X-NDM-Realm","");challenge=e.headers.get("X-NDM-Challenge","")
                    if realm and challenge:
                        ha1=hashlib.md5(f"{self._username}:{realm}:{self._password}".encode()).hexdigest()
                        resp_hash=hashlib.md5(f"{challenge}{ha1}".encode()).hexdigest()
                        auth_resp=self._fetch("/auth",method="POST",data={"login":self._username,"password":resp_hash},
                                             extra_headers={"Content-Type":"application/json"})
                        return bool(auth_resp)
        except Exception: pass
        return False

    def _try_keenetic(self)->list:
        if not self._session_cookies and not self._auth_token: self._keenetic_login()
        clients=[]
        for ep,payload in [("/rci/",{"show":{"ip":{"hotspot":{}}}}),("/rci/show/ip/hotspot",None)]:
            resp=self._fetch_json(ep,data=payload)
            if not resp: continue
            hosts=(resp.get("show",{}).get("ip",{}).get("hotspot",{}).get("host",[]) or resp.get("host",[]))
            for h in hosts:
                mac=h.get("mac","").upper();ip=h.get("ip","")
                if not mac: continue
                name=(h.get("registered") or h.get("desc") or h.get("name") or h.get("hostname","") or "")
                link=h.get("link","");ctype="WiFi" if link in ("wifi","wireless","wlan") else "LAN"
                rssi=h.get("rssi") or h.get("signal");ap=h.get("ap","");band=""
                if "1" in ap or "5g" in ap.lower(): band="5 GHz"
                elif ap: band="2.4 GHz"
                clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":ctype,"band":band,
                                 "signal_dbm":int(rssi) if rssi else None,"signal_pct":self._dbm_to_pct(rssi),
                                 "tx_rate":h.get("txrate") or h.get("tx-rate",""),
                                 "bytes_sent":h.get("tx-bytes"),"bytes_recv":h.get("rx-bytes"),
                                 "connected_time":h.get("active"),"keenetic_vendor":h.get("vendor",""),
                                 "source":"Keenetic RCI"})
            if clients: return clients
        resp=self._fetch_json("/api/v1/user/network")
        if resp:
            for h in resp.get("data",[]):
                mac=h.get("mac","").upper()
                if mac:
                    clients.append({"mac":mac,"ip":h.get("ip",""),"hostname":h.get("hostname","") or h.get("name",""),
                                    "connection_type":"WiFi" if h.get("wireless") else "LAN","band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":"Keenetic API v1"})
        return clients

    def _try_mikrotik(self)->list:
        clients=[]
        for user,pwd in [(self._username,self._password),("admin",""),("admin","admin")]:
            cred=base64.b64encode(f"{user}:{pwd}".encode()).decode()
            auth_hdr={"Authorization":f"Basic {cred}"}
            for ep in ["/rest/ip/dhcp-server/lease","/rest/ip/arp"]:
                resp=self._fetch_json(ep,extra_headers=auth_hdr)
                if resp and isinstance(resp,list):
                    for lease in resp:
                        mac=(lease.get("mac-address") or lease.get("hw-address") or "").upper()
                        ip=lease.get("address") or ""
                        name=(lease.get("host-name") or lease.get("comment") or lease.get("dynamic",""))
                        status=lease.get("status","bound")
                        if mac and status in ("bound","waiting",""):
                            clients.append({"mac":mac,"ip":ip,"hostname":name if isinstance(name,str) else "",
                                            "connection_type":"LAN","band":"","signal_dbm":None,"signal_pct":None,
                                            "tx_rate":"","bytes_sent":None,"bytes_recv":None,"connected_time":None,
                                            "source":"MikroTik REST"})
                    if clients: return clients
        return clients

    def _try_xiaomi(self)->list:
        clients=[]
        login_resp=self._fetch_json("/cgi-bin/luci/api/xqsystem/login",
            data={"username":self._username,"password":self._password,"logtype":"2"})
        if not login_resp:
            login_resp=self._fetch_json("/api/v1/auth",data={"username":self._username,"password":self._password})
        if not login_resp: return []
        stok=login_resp.get("token") or login_resp.get("data",{}).get("token","")
        if not stok: return []
        for ep in [f"/cgi-bin/luci/;stok={stok}/api/misystem/devicelist",
                   f"/cgi-bin/luci/;stok={stok}/api/xqdatacenter/client_list"]:
            resp=self._fetch_json(ep)
            if not resp: continue
            for dev in resp.get("list",[]):
                mac=dev.get("mac","").upper();ips=dev.get("ip",[{}])
                ip=ips[0].get("ip","") if ips else ""
                name=dev.get("hostname","") or dev.get("name","")
                conn=dev.get("wireless",{}) or dev.get("wifi",{})
                ctype="WiFi" if conn or dev.get("type")==1 else "LAN";band=""
                if conn.get("frequency") in ("2","2.4"): band="2.4 GHz"
                elif conn.get("frequency") in ("5",): band="5 GHz"
                signal=conn.get("signal") or conn.get("rssi")
                if mac:
                    clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":ctype,"band":band,
                                    "signal_dbm":int(signal) if signal else None,"signal_pct":self._dbm_to_pct(signal),
                                    "tx_rate":str(conn.get("txrate","")),"bytes_sent":dev.get("upload"),
                                    "bytes_recv":dev.get("download"),"connected_time":dev.get("online_time"),
                                    "source":"Xiaomi API"})
            if clients: return clients
        return clients

    def _try_huawei(self)->list:
        clients=[]
        for ep in ["/api/system/HostInfo","/html/ssmp/dhcp/dhcpHostInfo.lua","/api/dhcp/settings"]:
            resp=self._fetch_json(ep)
            if not resp: continue
            hosts=(resp.get("Hosts",{}).get("Host",[]) or resp.get("DHCPHosts",[]) or resp.get("hosts",[]))
            for h in hosts:
                mac=(h.get("MACAddress") or h.get("mac") or "").upper()
                ip=h.get("IPAddress") or h.get("ip") or ""
                name=h.get("HostName") or h.get("hostname") or ""
                iface=h.get("InterfaceType","")
                ctype="WiFi" if "WLAN" in iface.upper() else "LAN"
                if mac:
                    clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":ctype,"band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":"Huawei API"})
            if clients: return clients
        return clients

    def _dlink_login(self) -> bool:
        """
        Логін у D-Link роутер. Підтримує 3 механізми:
         1. Basic Auth (Bearer-токен встановлюється глобально)
         2. Legacy D-Link POST-форма на /login.cgi
         3. Modern D-Link POST на /api/auth (новіші DIR-X серії)
        Повертає True якщо авторизовано.
        """
        if not self._username or not self._password:
            return False

        # Механізм 1: Basic Auth — просто запам'ятовуємо для _fetch
        try:
            auth_header = base64.b64encode(
                f"{self._username}:{self._password}".encode()).decode()
            # Тестуємо чи приймається (пробуємо info-сторінку з Basic Auth)
            test = self._fetch("/info.xml", extra_headers={
                "Authorization": f"Basic {auth_header}"
            })
            if test and "<" in test and "error" not in test.lower()[:200]:
                # Basic Auth працює — встановлюємо як default header
                # через base64_auth=True у наступних запитах
                self._use_basic_auth = True
                return True
        except Exception: pass

        # Механізм 2: Legacy login form
        try:
            post_data = urllib.parse.urlencode({
                "ACTION_POST": "LOGIN",
                "LOGIN_USER": self._username,
                "LOGIN_PASSWD": self._password,
            }).encode()
            resp = self._fetch("/login.cgi", method="POST", data=post_data,
                extra_headers={"Content-Type":"application/x-www-form-urlencoded"})
            if resp and self._session_cookies:
                return True
        except Exception: pass

        # Механізм 3: Modern JSON API login
        try:
            import json as _json
            post_data = _json.dumps({
                "username": self._username,
                "password": self._password,
            }).encode()
            resp = self._fetch("/api/auth", method="POST", data=post_data,
                extra_headers={"Content-Type":"application/json"})
            if resp:
                try:
                    j = _json.loads(resp)
                    token = j.get("token") or j.get("session") or j.get("auth")
                    if token:
                        self._auth_token = token
                        return True
                except Exception: pass
        except Exception: pass

        return False

    def _try_dlink(self)->list:
        clients=[]
        # FIX: спершу логінимось якщо є credentials
        self._use_basic_auth = False
        if self._username and self._password:
            self._dlink_login()

        # Modern D-Link DIR endpoints (DIR-825/DIR-853/DIR-X1560 etc — Web-panel Ukraine)
        modern_endpoints = [
            "/rpc/clients", "/rpc/dhcp_clients", "/rpc/wifi_clients",
            "/rpc/get_clients", "/api/clients", "/cgi-bin/rpc.cgi?method=getClients",
            "/advanced/wifi_client_list.php", "/advanced/dhcp_server.php",
            "/web_cgi/getClientsInfo.php", "/getclientinfo", "/clientinfo",
            "/cgi/dhcp_lease", "/cgi-bin/dhcp_lease.cgi",
        ]
        for ep in modern_endpoints:
            # Використовуємо Basic Auth якщо _dlink_login() його підтвердив
            if getattr(self, "_use_basic_auth", False):
                raw = self._fetch(ep, base64_auth=True)
                try: resp = json.loads(raw) if raw else None
                except Exception: resp = None
            else:
                resp = self._fetch_json(ep)
            if not resp: continue
            # Розбираємо різні формати відповідей
            items = None
            if isinstance(resp, list):
                items = resp
            elif isinstance(resp, dict):
                for key in ("clients","dhcpClients","wifiClients","lanClients",
                            "client_list","list","data","result","devices","hosts"):
                    val = resp.get(key)
                    if isinstance(val, list):
                        items = val
                        break
            if not isinstance(items,list): continue
            for item in items:
                if not isinstance(item,dict): continue
                state=str(item.get("state",item.get("status","active"))).lower()
                if state in ("inactive","expired","0","false"): continue
                mac = (item.get("mac") or item.get("macAddr") or item.get("MAC")
                       or item.get("hw_addr") or item.get("hardware_address") or "")
                mac = mac.upper().replace("-",":")
                if not mac or len(mac)<17: continue
                hostname = (item.get("hostname") or item.get("name")
                           or item.get("host") or item.get("device_name") or "")
                ip_val   = (item.get("ip") or item.get("ip_addr")
                           or item.get("ip_address") or item.get("ipv4") or "")
                # Визначаємо Wi-Fi або LAN
                conn_type = "LAN"
                if str(item.get("interface","")).lower() in ("wlan","wifi","wireless"):
                    conn_type = "WiFi"
                elif item.get("signal") or item.get("rssi"):
                    conn_type = "WiFi"
                clients.append({"mac":mac,"ip":ip_val,"hostname":hostname,
                                 "connection_type":conn_type,"band":"",
                                 "signal_dbm":item.get("rssi") or item.get("signal"),
                                 "signal_pct":None,
                                 "tx_rate":"","bytes_sent":None,"bytes_recv":None,
                                 "connected_time":None,"source":"D-Link Modern JSON"})
            if clients: return clients

        for ep in ["/DHCPS.xml","/st_dhcp.xml","/runtime/hosts/hosts"]:
            raw=self._fetch(ep)
            if not raw or "<" not in raw: continue
            for entry in re.finditer(r"<Entry[^>]*/?>|<Entry[^>]*>.*?</Entry>",raw,re.DOTALL|re.IGNORECASE):
                block=entry.group(0);mac=ip=name=expire=""
                for tag,val in re.findall(r'(\w+)="([^"]*)"',block):
                    t=tag.upper()
                    if t in ("MAC","MACADDRESS"): mac=val.upper().replace("-",":")
                    elif t in ("IP","IPADDRESS"): ip=val
                    elif t in ("HOSTNAME","HOST","NAME"): name=val
                    elif t in ("EXPIRE","EXPIRY","TTL"): expire=val
                try:
                    if expire and 0<int(expire)<time.time()-60: continue
                except Exception: pass
                if mac and len(mac)>=17 and mac!="FF:FF:FF:FF:FF:FF" and not mac.startswith("00:00:00"):
                    clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":"LAN","band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":"D-Link XML"})
            if clients: return clients
        for page in ["/DHCP_CLIENT.htm","/Status_dhcptable.asp","/dhcpinfo.htm",
                     "/cgi-bin/dhcpstatus.cgi","/wlan_wireless_advanced.htm"]:
            raw=self._fetch(page)
            if not raw: continue
            rows=re.findall(r"<tr[^>]*>(.*?)</tr>",raw,re.DOTALL|re.IGNORECASE)
            for row in rows:
                cells=re.findall(r"<td[^>]*>(.*?)</td>",row,re.DOTALL|re.IGNORECASE)
                cells=[re.sub(r"<[^>]+>","",c).strip() for c in cells]
                cells=[c for c in cells if c and c not in ("—","-","N/A")]
                mac=ip=name=""
                for cell in cells:
                    c_clean=cell.upper().replace("-",":")
                    if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$",c_clean) and not mac: mac=c_clean
                    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",cell) and not ip: ip=cell
                    elif len(cell)>2 and not name and not cell.isdigit():
                        if not re.match(r"^\d{4}-\d{2}-\d{2}",cell): name=cell
                if mac and mac!="FF:FF:FF:FF:FF:FF":
                    clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":"LAN","band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":f"D-Link HTML {page}"})
            if clients: return clients
        return clients

    def _try_netis(self)->list:
        clients=[]
        for ep in ["/goform/getSysStatusInfo","/goform/getWifiClientInfo","/goform/getDeviceList"]:
            resp=self._fetch_json(ep)
            if not resp: continue
            for key in ("clients","wifiClients","deviceList","dhcpList","client_list","data"):
                items=resp.get(key) if isinstance(resp,dict) else (resp if isinstance(resp,list) else None)
                if not items or not isinstance(items,list): continue
                for item in items:
                    if not isinstance(item,dict): continue
                    mac=(item.get("mac") or item.get("macAddr") or item.get("MAC") or "").upper().replace("-",":")
                    if not mac or len(mac)<17: continue
                    ip=item.get("ip") or item.get("ipAddr") or ""
                    name=item.get("hostname") or item.get("devName") or item.get("name") or ""
                    is_wifi=item.get("wireless",False) or str(item.get("type","")) in ("2","5","wifi")
                    band="";freq=str(item.get("freq","") or item.get("band",""))
                    if "5" in freq: band="5 GHz"
                    elif "2" in freq: band="2.4 GHz"
                    signal=item.get("rssi") or item.get("signal")
                    clients.append({"mac":mac,"ip":ip,"hostname":name,
                                    "connection_type":"WiFi" if is_wifi else "LAN","band":band,
                                    "signal_dbm":int(signal) if signal else None,"signal_pct":self._dbm_to_pct(signal),
                                    "tx_rate":"","bytes_sent":None,"bytes_recv":None,"connected_time":None,"source":"Netis API"})
                if clients: return clients
        for page in ["/cgi-bin/stat.asp","/cgi-bin/status.asp","/NETCORE/dhcpd_client.asp"]:
            raw=self._fetch(page)
            if not raw: continue
            rows=re.findall(r"<tr[^>]*>(.*?)</tr>",raw,re.DOTALL|re.IGNORECASE)
            for row in rows:
                cells=re.findall(r"<td[^>]*>(.*?)</td>",row,re.DOTALL|re.IGNORECASE)
                cells=[re.sub(r"<[^>]+>","",c).strip() for c in cells];cells=[c for c in cells if c]
                mac=ip=name=""
                for c in cells:
                    c_clean=c.upper().replace("-",":")
                    if re.match(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$",c_clean) and not mac: mac=c_clean
                    elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",c) and not ip: ip=c
                    elif len(c)>2 and not name and not c.isdigit(): name=c
                if mac:
                    clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":"LAN","band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":f"Netis HTML {page}"})
            if clients: return clients
        return clients

    def _try_tenda(self)->list:
        clients=[]
        for ep in ["/goform/getWifiClientInfo","/goform/getSysStatusInfo","/goform/getAT"]:
            resp=self._fetch_json(ep)
            if not resp: continue
            hosts=(resp.get("hostList") or resp.get("client_info_list") or resp.get("clientList") or [])
            for h in hosts:
                mac=h.get("mac","").upper();signal=h.get("rssi") or h.get("signal")
                if mac:
                    clients.append({"mac":mac,"ip":h.get("ip",""),
                                    "hostname":h.get("hostname","") or h.get("devname",""),
                                    "connection_type":"WiFi" if h.get("conn_type","").lower()=="wireless" else "LAN",
                                    "band":"","signal_dbm":int(signal) if signal else None,
                                    "signal_pct":self._dbm_to_pct(signal),"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":"Tenda API"})
            if clients: return clients
        return clients

    def _try_netgear(self)->list:
        raw=self._fetch("/attached-devices.htm",base64_auth=True)
        if not raw:
            soap='<?xml version="1.0"?><SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><M1:GetAttachDevice xmlns:M1="urn:NETGEAR-ROUTER:service:DeviceInfo:1"/></SOAP-ENV:Body></SOAP-ENV:Envelope>'
            raw=self._fetch("/setup.cgi?next_file=DeviceInfo.htm",data=soap.encode(),
                            extra_headers={"SOAPAction":'"urn:NETGEAR-ROUTER:service:DeviceInfo:1#GetAttachDevice"',"Content-Type":"text/xml"})
        if not raw: return []
        clients=[]
        for mac,ip in re.compile(r"([0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",re.DOTALL).findall(raw):
            clients.append({"mac":mac.upper(),"ip":ip,"hostname":"","connection_type":"LAN","band":"",
                            "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                            "bytes_recv":None,"connected_time":None,"source":"Netgear"})
        return clients

    def _try_zyxel(self)->list:
        clients=[]
        auth_b64=base64.b64encode(f"{self._username}:{self._password}".encode()).decode()
        auth_hdr={"Authorization":f"Basic {auth_b64}"}
        for ep in ["/cgi-bin/luci/rpc/uci","/UserInterface/index.html","/api/v1/devices"]:
            resp=self._fetch_json(ep,extra_headers=auth_hdr)
            if not resp: continue
            for key in ["devices","clients","hosts","data"]:
                items=resp.get(key,[])
                if isinstance(items,list) and items:
                    for h in items:
                        mac=(h.get("mac") or h.get("MACAddress") or "").upper()
                        if mac and len(mac)>=17:
                            clients.append({"mac":mac,"ip":h.get("ip","") or h.get("IPAddress",""),
                                            "hostname":h.get("hostname","") or h.get("HostName",""),
                                            "connection_type":"LAN","band":"","signal_dbm":None,"signal_pct":None,
                                            "tx_rate":"","bytes_sent":None,"bytes_recv":None,"connected_time":None,"source":"ZyXEL"})
                    if clients: return clients
        return clients

    def _try_ubiquiti(self)->list:
        clients=[]
        login_resp=self._fetch_json("/api/login",data={"username":self._username,"password":self._password})
        if login_resp and login_resp.get("meta",{}).get("rc")=="ok":
            resp=self._fetch_json("/api/s/default/stat/sta")
            if resp:
                for sta in resp.get("data",[]):
                    mac=sta.get("mac","").upper();signal=sta.get("rssi") or sta.get("signal")
                    if mac:
                        clients.append({"mac":mac,"ip":sta.get("ip",""),
                                        "hostname":sta.get("hostname","") or sta.get("name",""),
                                        "connection_type":"WiFi" if sta.get("essid") else "LAN","band":"",
                                        "signal_dbm":int(signal) if signal else None,"signal_pct":self._dbm_to_pct(signal),
                                        "tx_rate":str(sta.get("tx_rate","")),"bytes_sent":sta.get("tx_bytes"),
                                        "bytes_recv":sta.get("rx_bytes"),"connected_time":sta.get("uptime"),"source":"UniFi API"})
                if clients: return clients
        self._fetch("/",data=urllib.parse.urlencode({"username":self._username,"password":self._password}).encode(),
                    extra_headers={"Content-Type":"application/x-www-form-urlencoded"})
        resp=self._fetch_json("/api/edge/data.json?data=dhcp_leases")
        if resp:
            for subnet in resp.get("output",{}).get("dhcp-server-leases",{}).values():
                for ip,info in subnet.items():
                    mac=info.get("mac","").upper();name=info.get("client-hostname","")
                    if mac:
                        clients.append({"mac":mac,"ip":ip,"hostname":name,"connection_type":"LAN","band":"",
                                        "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                        "bytes_recv":None,"connected_time":None,"source":"EdgeOS DHCP"})
        return clients

    def _try_generic(self)->list:
        clients=[]
        mac_ip_re=re.compile(r"([0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}[:\-][0-9A-Fa-f]{2}).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",re.DOTALL)
        for ep in ["/api/v1/devices","/api/devices","/api/clients","/api/hosts","/devices.json","/clients.json",
                   "/cgi-bin/devices.cgi","/cgi-bin/clients.cgi","/data/devices.json","/data/clients.json",
                   "/luci-rpc/ipv4-neigh","/rpc/hosts"]:
            resp=self._fetch_json(ep)
            if not resp: continue
            items=[]
            if isinstance(resp,list): items=resp
            else:
                for key in ["devices","clients","hosts","data","stations","leases","result"]:
                    if isinstance(resp.get(key),list): items=resp[key];break
            for item in items:
                if not isinstance(item,dict): continue
                mac=""
                for k in ["mac","MAC","macaddr","macAddress","hw_addr","hardware","ether"]:
                    v=item.get(k,"")
                    if v and re.match(r"^[0-9a-fA-F:]{17}$",v): mac=v.upper();break
                ip=item.get("ip") or item.get("IP") or item.get("ipaddr") or ""
                hostname=item.get("hostname") or item.get("name") or item.get("alias") or ""
                if mac:
                    clients.append({"mac":mac.replace("-",":"),"ip":ip,"hostname":hostname,
                                    "connection_type":"LAN","band":"","signal_dbm":None,"signal_pct":None,
                                    "tx_rate":"","bytes_sent":None,"bytes_recv":None,"connected_time":None,
                                    "source":f"Generic JSON {ep}"})
            if clients: return clients
        for page in ["/dhcpinfo.htm","/DHCP_CLIENT.htm","/dhcp_clients.htm","/connected_devices.html",
                     "/network_map.asp","/Status_Lan.asp","/lan_dhcp.htm","/cgi-bin/status","/status.html"]:
            raw=self._fetch(page)
            if not raw: continue
            for mac,ip in mac_ip_re.findall(raw):
                mac=mac.replace("-",":").upper()
                if not mac.startswith("FF:FF"):
                    clients.append({"mac":mac,"ip":ip,"hostname":"","connection_type":"LAN","band":"",
                                    "signal_dbm":None,"signal_pct":None,"tx_rate":"","bytes_sent":None,
                                    "bytes_recv":None,"connected_time":None,"source":f"HTML {page}"})
            if clients: return clients
        return clients

    @staticmethod
    def _dbm_to_pct(dbm)->Optional[int]:
        if dbm is None: return None
        try:
            dbm=int(dbm)
            if dbm>=-50: return 100
            if dbm<=-100: return 0
            return int((dbm+100)*2)
        except Exception: return None

    @staticmethod
    def _bytes_human(b)->str:
        if b is None: return ""
        try:
            b=int(b)
            if b<1024: return f"{b} B"
            if b<1048576: return f"{b/1024:.1f} KB"
            if b<1073741824: return f"{b/1048576:.1f} MB"
            return f"{b/1073741824:.1f} GB"
        except Exception: return ""

    @staticmethod
    def _seconds_human(s)->str:
        if not s: return ""
        try:
            s=int(s)
            if s<60: return f"{s}с"
            if s<3600: return f"{s//60}хв"
            return f"{s//3600}г {(s%3600)//60}хв"
        except Exception: return str(s)

RouterDHCPReader=RouterClientReader

# ══════════════════════════════════════════════════════════════════
# PHONE PROBER  (FIX-3: Samsung SM-xxxx з hostname, Android name)
# ══════════════════════════════════════════════════════════════════
class PhoneProber:
    APPLE_MODELS: dict = {
        "iPhone1,1":("iPhone (1st gen)","iOS"),"iPhone2,1":("iPhone 3GS","iOS"),
        "iPhone3,1":("iPhone 4","iOS"),"iPhone4,1":("iPhone 4S","iOS"),
        "iPhone5,1":("iPhone 5","iOS"),"iPhone5,3":("iPhone 5c","iOS"),
        "iPhone6,1":("iPhone 5s","iOS"),"iPhone7,1":("iPhone 6 Plus","iOS"),
        "iPhone7,2":("iPhone 6","iOS"),"iPhone8,1":("iPhone 6s","iOS"),
        "iPhone8,2":("iPhone 6s Plus","iOS"),"iPhone8,4":("iPhone SE (1st gen)","iOS"),
        "iPhone9,1":("iPhone 7","iOS"),"iPhone9,2":("iPhone 7 Plus","iOS"),
        "iPhone10,1":("iPhone 8","iOS"),"iPhone10,2":("iPhone 8 Plus","iOS"),
        "iPhone10,3":("iPhone X (CDMA)","iOS"),"iPhone10,6":("iPhone X (GSM)","iOS"),
        "iPhone11,2":("iPhone XS","iOS"),"iPhone11,4":("iPhone XS Max","iOS"),
        "iPhone11,8":("iPhone XR","iOS"),"iPhone12,1":("iPhone 11","iOS"),
        "iPhone12,3":("iPhone 11 Pro","iOS"),"iPhone12,5":("iPhone 11 Pro Max","iOS"),
        "iPhone12,8":("iPhone SE (2nd gen)","iOS"),"iPhone13,1":("iPhone 12 mini","iOS"),
        "iPhone13,2":("iPhone 12","iOS"),"iPhone13,3":("iPhone 12 Pro","iOS"),
        "iPhone13,4":("iPhone 12 Pro Max","iOS"),"iPhone14,2":("iPhone 13 Pro","iOS"),
        "iPhone14,3":("iPhone 13 Pro Max","iOS"),"iPhone14,4":("iPhone 13 mini","iOS"),
        "iPhone14,5":("iPhone 13","iOS"),"iPhone14,6":("iPhone SE (3rd gen)","iOS"),
        "iPhone14,7":("iPhone 14","iOS"),"iPhone14,8":("iPhone 14 Plus","iOS"),
        "iPhone15,2":("iPhone 14 Pro","iOS"),"iPhone15,3":("iPhone 14 Pro Max","iOS"),
        "iPhone15,4":("iPhone 15","iOS"),"iPhone15,5":("iPhone 15 Plus","iOS"),
        "iPhone16,1":("iPhone 15 Pro","iOS"),"iPhone16,2":("iPhone 15 Pro Max","iOS"),
        "iPhone17,1":("iPhone 16 Pro","iOS"),"iPhone17,2":("iPhone 16 Pro Max","iOS"),
        "iPhone17,3":("iPhone 16","iOS"),"iPhone17,4":("iPhone 16 Plus","iOS"),
        "iPad1,1":("iPad (1st gen)","iPadOS"),"iPad4,1":("iPad Air","iPadOS"),
        "iPad5,3":("iPad Air 2","iPadOS"),"iPad6,11":("iPad (5th gen)","iPadOS"),
        "iPad7,5":("iPad (6th gen)","iPadOS"),"iPad7,11":("iPad (7th gen)","iPadOS"),
        'iPad8,1':('iPad Pro 11" (1st gen)',"iPadOS"),'iPad8,5':('iPad Pro 12.9" (3rd gen)',"iPadOS"),
        'iPad8,9':('iPad Pro 11" (2nd gen)',"iPadOS"),'iPad8,11':('iPad Pro 12.9" (4th gen)',"iPadOS"),
        "iPad11,1":("iPad mini (5th gen)","iPadOS"),"iPad11,3":("iPad Air (3rd gen)","iPadOS"),
        "iPad11,6":("iPad (8th gen)","iPadOS"),"iPad12,1":("iPad (9th gen)","iPadOS"),
        "iPad13,1":("iPad Air (4th gen)","iPadOS"),'iPad13,4':('iPad Pro 11" (3rd gen)',"iPadOS"),
        "iPad13,18":("iPad (10th gen)","iPadOS"),"iPad14,1":("iPad mini (6th gen)","iPadOS"),
        'iPad14,3':('iPad Pro 11" (4th gen)',"iPadOS"),'iPad14,5':('iPad Pro 12.9" (6th gen)',"iPadOS"),
        'iPad14,8':('iPad Air 11" (M2)',"iPadOS"),'iPad14,9':('iPad Air 13" (M2)',"iPadOS"),
        'iPad16,3':('iPad Pro 11" (M4)',"iPadOS"),'iPad16,5':('iPad Pro 13" (M4)',"iPadOS"),
        "MacBookPro18,1":('MacBook Pro 16" (2021)',"macOS"),"MacBookPro19,1":('MacBook Pro 16" (2023)',"macOS"),
        "MacBookPro20,1":("MacBook Pro 14\" M3","macOS"),"MacBookAir10,1":("MacBook Air M1","macOS"),
        "MacBookAir14,2":("MacBook Air M2 (2022)","macOS"),"MacBookAir14,15":("MacBook Air M3","macOS"),
        "Mac14,2":("Mac mini M2","macOS"),"Mac15,3":("Mac mini M4","macOS"),
    }
    SAMSUNG_MODELS: dict = {
        "SM-S928":"Galaxy S24 Ultra","SM-S926":"Galaxy S24+","SM-S921":"Galaxy S24",
        "SM-S918":"Galaxy S23 Ultra","SM-S916":"Galaxy S23+","SM-S911":"Galaxy S23",
        "SM-S908":"Galaxy S22 Ultra","SM-S906":"Galaxy S22+","SM-S901":"Galaxy S22",
        "SM-S898":"Galaxy S24 FE","SM-A546":"Galaxy A54","SM-A536":"Galaxy A53",
        "SM-A526":"Galaxy A52s","SM-A525":"Galaxy A52","SM-A515":"Galaxy A51",
        "SM-A336":"Galaxy A33","SM-A326":"Galaxy A32","SM-A256":"Galaxy A25",
        "SM-A225":"Galaxy A22","SM-A155":"Galaxy A15","SM-A135":"Galaxy A13",
        "SM-A045":"Galaxy A04s","SM-F946":"Galaxy Z Fold5","SM-F936":"Galaxy Z Fold4",
        "SM-F731":"Galaxy Z Flip5","SM-F721":"Galaxy Z Flip4","SM-X810":"Galaxy Tab S9+",
        "SM-X710":"Galaxy Tab S9","SM-X610":"Galaxy Tab S9 FE","SM-T870":"Galaxy Tab S7",
        "SM-T975":"Galaxy Tab S7+","SM-N986":"Galaxy Note20 Ultra","SM-N981":"Galaxy Note20",
        "SM-G991":"Galaxy S21","SM-G996":"Galaxy S21+","SM-G998":"Galaxy S21 Ultra",
        "SM-G781":"Galaxy S20 FE","SM-G985":"Galaxy S20+","SM-G980":"Galaxy S20",
        "SM-G975":"Galaxy S10+","SM-G973":"Galaxy S10","SM-G970":"Galaxy S10e",
        "SM-A715":"Galaxy A71","SM-A217":"Galaxy A21s","SM-A107":"Galaxy A10s",
    }

    @classmethod
    def _samsung_model_from_hostname(cls, hostname: str) -> str:
        """FIX-3: розпізнає модель Samsung з hostname виду 'SM-G998B'"""
        hn_up = hostname.upper().strip()
        m = re.search(r"\b(SM-[A-Z0-9]{3,8})\b", hn_up)
        if not m: return ""
        prefix = m.group(1)
        if prefix in cls.SAMSUNG_MODELS: return cls.SAMSUNG_MODELS[prefix]
        prefix6 = prefix[:6]
        for key, val in cls.SAMSUNG_MODELS.items():
            if key.startswith(prefix6): return val
        return prefix

    @classmethod
    def probe(cls, ip, mac, oui_vendor, open_ports, dhcp_hostname="", timeout=4.0, mdns_cache=None) -> dict:
        result = {"phone_model":"","phone_name":"","phone_brand":"","phone_os":"",
                  "phone_icon":"📱","phone_summary":"","identification_method":[]}
        ports_set = set(open_ports); cache = mdns_cache or {}
        if cache: cls._enrich_from_mdns_cache(result, cache)

        hn = (dhcp_hostname or "").strip()
        if hn and hn not in ("","—","unknown","localhost"):
            _device_brands = {
                "iphone":"Apple","ipad":"Apple","ipod":"Apple","macbook":"Apple","imac":"Apple","apple":"Apple",
                "samsung":"Samsung","galaxy":"Samsung","sm-":"Samsung",
                "android":"Android","android-":"Android",
                "pixel":"Google","nexus":"Google",
                "xiaomi":"Xiaomi","redmi":"Xiaomi","poco":"Xiaomi","mi-":"Xiaomi","mi_":"Xiaomi",
                "huawei":"Huawei","honor":"Honor",
                "oppo":"OPPO","realme":"realme","vivo":"vivo","oneplus":"OnePlus",
                "motorola":"Motorola","moto":"Motorola",
                "nokia":"Nokia","lg-":"LG","sony":"Sony","xperia":"Sony",
                "asus":"ASUS","zenfone":"ASUS","lenovo":"Lenovo","lenovotab":"Lenovo",
                "htc":"HTC","zte":"ZTE","alcatel":"Alcatel",
            }
            hn_lower = hn.lower().replace("_","-")
            for kw, brand in _device_brands.items():
                if kw in hn_lower:
                    model_str = ""
                    if brand == "Samsung" and "sm-" in hn_lower:
                        model_str = cls._samsung_model_from_hostname(hn)
                    elif brand == "Android" and re.match(r"android-[0-9a-f]{6,}", hn_lower):
                        model_str = ""
                    else:
                        model_raw = hn.replace("-"," ").replace("_"," "); parts = model_raw.split()
                        if parts and parts[0].lower() == brand.lower(): model_parts = parts[1:]
                        else: model_parts = parts
                        model_str = " ".join(p.upper() if len(p)<=6 and any(c.isdigit() for c in p) else p.title() for p in model_parts).strip()
                    if not result["phone_brand"]:
                        _os = "iOS" if brand == "Apple" else "Android"
                        result.update({"phone_brand":brand,"phone_model":model_str,
                                       "phone_name":hn,"phone_os":_os,
                                       "phone_summary":f"{brand} {model_str}".strip() if model_str else (hn if brand != "Android" else brand),
                                       "identification_method":["DHCP hostname"]})
                    elif not result["phone_name"]: result["phone_name"] = hn
                    break

        if not result["phone_name"] and hn: result["phone_name"] = hn

        # ── КРОК 1: Unicast mDNS напряму на IP пристрою ─────────────
        if not result["phone_model"]:
            mdns_direct = cls._probe_mdns_unicast(ip, timeout=min(timeout, 2.5))
            if mdns_direct:
                cls._merge(result, mdns_direct, "mDNS-unicast")
                if result["phone_model"]:
                    cls._build_summary(result); return result

        # ── КРОК 1b: HTTP на порт 62078 (iTunes sync, тільки iPhone/iPad) ─
        # Цей порт відкритий на більшості iPhone і інколи повертає модель
        if not result["phone_model"] and (62078 in ports_set or not ports_set):
            ios_info = cls._probe_ios_port(ip, timeout=min(timeout, 1.5))
            if ios_info:
                cls._merge(result, ios_info, "iOS-port")
                if result["phone_model"]:
                    cls._build_summary(result); return result

        # ── КРОК 1c: Android-детектор ────────────────────────────────
        # Android 10+ використовує рандомний MAC і не відповідає на mDNS.
        # Перевіряємо SSDP, DLNA, порт 5555 (ADB), HTTP на різних портах.
        if not result["phone_model"] and not result.get("phone_brand"):
            android_info = cls._probe_android_device(ip, ports_set, timeout=min(timeout, 2.5))
            if android_info:
                cls._merge(result, android_info, "Android")
                if result.get("phone_brand") not in ("", None):
                    cls._build_summary(result); return result

        # ── КРОК 2: AirPlay (Apple TV, HomePod, деякі iPhone) ───────
        if not result["phone_model"] and (7000 in ports_set or 7001 in ports_set or 7100 in ports_set or not ports_set):
            airplay = cls._probe_airplay(ip, timeout=min(timeout,1.5))
            if airplay:
                cls._merge(result, airplay, "AirPlay")
                if result["phone_brand"] == "Apple" and result["phone_model"]:
                    cls._build_summary(result); return result

        # ── КРОК 3: DIAL (Chromecast, Android TV) ───────────────────
        if not result["phone_model"] and (8008 in ports_set or 8009 in ports_set or not ports_set):
            dial = cls._probe_dial(ip, timeout=min(timeout,2.0))
            if dial:
                cls._merge(result, dial, "DIAL")
                if result["phone_model"]: cls._build_summary(result); return result

        # ── КРОК 4: UPnP ─────────────────────────────────────────────
        if not result["phone_model"]:
            upnp = cls._probe_upnp_phone(ip, ports_set, timeout=min(timeout,2.0))
            if upnp: cls._merge(result, upnp, "UPnP")

        # ── КРОК 5: HTTP banner ──────────────────────────────────────
        if 80 in ports_set and not result["phone_model"]:
            banner = cls._probe_http_banner(ip, timeout=min(timeout,1.5))
            if banner: cls._merge(result, banner, "HTTP")

        if not result["phone_brand"]: cls._enrich_from_oui(result, oui_vendor, mac, ports_set)
        cls._build_summary(result); return result

    @classmethod
    def _probe_mdns_unicast(cls, ip: str, timeout: float = 2.0) -> dict:
        """
        Надсилає mDNS-запити напряму (unicast) на IP:5353 пристрою.
        Для iPhone/iPad це повертає TXT-запис _device-info._tcp.local
        з полями md=iPhone14,2, fn=Ім'я власника, osvers=18.1 тощо.
        Працює навіть при рандомному MAC — не потрібен OUI.
        """
        result = {}

        def _build_mdns_query(service: str, qtype: int = 0x10) -> bytes:
            """Будує raw mDNS-запит для заданого service і qtype (0x10=TXT, 0x0c=PTR, 0x01=A)."""
            labels = service.rstrip(".").split(".")
            qname = b""
            for label in labels:
                enc = label.encode("utf-8")
                qname += bytes([len(enc)]) + enc
            qname += b"\x00"
            # Header: ID=0x0000, FLAGS=0x0000, QDCOUNT=1, rest=0
            header = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            # Question: QTYPE, QCLASS=0x8001 (unicast response requested)
            question = qname + bytes([qtype >> 8, qtype & 0xFF]) + b"\x80\x01"
            return header + question

        def _parse_mdns_response(data: bytes) -> dict:
            """Парсить mDNS-відповідь і повертає поля з TXT-записів."""
            parsed = {}
            if len(data) < 12: return parsed
            try:
                ancount = (data[6] << 8) | data[7]
                arcount = (data[10] << 8) | data[11]
                off = 12
                # Skip questions
                qdcount = (data[4] << 8) | data[5]
                for _ in range(qdcount):
                    while off < len(data) and data[off] != 0:
                        if (data[off] & 0xC0) == 0xC0: off += 2; break
                        off += 1 + data[off]
                    else:
                        off += 1
                    off += 4  # QTYPE + QCLASS
                # Parse answers
                for _ in range(ancount + arcount):
                    if off >= len(data): break
                    # Skip name
                    while off < len(data) and data[off] != 0:
                        if (data[off] & 0xC0) == 0xC0: off += 2; break
                        off += 1 + data[off]
                    else:
                        if off < len(data): off += 1
                    if off + 10 > len(data): break
                    rtype = (data[off] << 8) | data[off+1]
                    rdlen = (data[off+8] << 8) | data[off+9]
                    off += 10
                    rdata = data[off:off+rdlen]; off += rdlen
                    if rtype == 0x10:  # TXT
                        pos = 0
                        while pos < len(rdata):
                            slen = rdata[pos]; pos += 1
                            if pos + slen > len(rdata): break
                            txt = rdata[pos:pos+slen].decode("utf-8","ignore"); pos += slen
                            kv = txt.split("=", 1)
                            if len(kv) == 2:
                                k, v = kv[0].lower().strip(), kv[1].strip()
                                if k in ("md", "model"):   parsed["model"] = v
                                if k in ("fn", "an", "name"): parsed["name"] = v
                                if k == "osvers":          parsed["osvers"] = v
                                if k == "deviceid":        parsed["deviceid"] = v
                    elif rtype == 0x0c:  # PTR
                        # PTR запис містить ім'я екземпляра
                        try:
                            ptr_labels = []
                            p = 0
                            while p < len(rdata) and rdata[p] != 0:
                                if (rdata[p] & 0xC0) == 0xC0: break
                                ll = rdata[p]; p += 1
                                ptr_labels.append(rdata[p:p+ll].decode("utf-8","ignore")); p += ll
                            if ptr_labels and len(ptr_labels[0]) > 2:
                                parsed.setdefault("name", ptr_labels[0])
                        except Exception: pass
            except Exception:
                pass
            return parsed

        # Список сервісів для запиту (пріоритет: device-info → companion-link → mobdev2)
        # Список сервісів для запиту (пріоритет: device-info → companion-link → mobdev2)
        queries = [
            ("_device-info._tcp.local",    0x10),  # TXT → md=iPhone14,2, fn=Ім'я
            ("_companion-link._tcp.local", 0x0c),  # PTR → ім'я пристрою
            ("_apple-mobdev2._tcp.local",  0x0c),  # PTR → ім'я
            ("_services._dns-sd._udp.local", 0x0c), # Загальний service discovery
        ]

        # FIX: 3 спроби з паузою (iOS може бути в режимі сну)
        for attempt in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(timeout)
                for service, qtype in queries:
                    pkt = _build_mdns_query(service, qtype)
                    try:
                        sock.sendto(pkt, (ip, 5353))
                        try:
                            data, _ = sock.recvfrom(4096)
                            parsed = _parse_mdns_response(data)
                            if parsed.get("model"):
                                model_id = parsed["model"]
                                apple = cls.APPLE_MODELS.get(model_id)
                                if apple:
                                    result["phone_model"] = apple[0]
                                    result["phone_brand"] = "Apple"
                                    result["phone_os"]    = apple[1]
                                    result["phone_icon"]  = "📱"
                                else:
                                    result["phone_model"] = model_id
                                    if model_id.startswith("iPhone"): result["phone_brand"] = "Apple"; result["phone_os"] = "iOS"
                                    elif model_id.startswith("iPad"): result["phone_brand"] = "Apple"; result["phone_os"] = "iPadOS"
                                    elif model_id.startswith("Mac"):  result["phone_brand"] = "Apple"; result["phone_os"] = "macOS"
                                if parsed.get("name") and not result.get("phone_name"):
                                    result["phone_name"] = parsed["name"]
                                if parsed.get("osvers"):
                                    result["phone_os"] = f"{result.get('phone_os','iOS')} {parsed['osvers']}"
                                sock.close(); return result
                            if parsed.get("name") and not result.get("phone_name"):
                                result["phone_name"] = parsed["name"]
                                result.setdefault("phone_brand", "Apple")
                        except socket.timeout:
                            pass
                    except Exception:
                        pass
                sock.close()
            except Exception:
                pass
            # Пауза між спробами — iOS може "прокинутись"
            if attempt < 2:
                time.sleep(0.3)

        return result

    @classmethod
    def _probe_ios_port(cls, ip: str, timeout: float = 1.5) -> dict:
        """
        Пробує підключитись до порту 62078 (iTunes/iOS pairing).
        Цей порт відкритий майже на всіх iPhone/iPad.
        При підключенні інколи повертає HTTP-відповідь з моделлю пристрою.
        Навіть якщо модель не повертається — факт відкритого порту = Apple iPhone/iPad.
        """
        result = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, 62078)) != 0:
                s.close(); return result
            # Порт відкритий — це Apple пристрій
            result["phone_brand"] = "Apple"
            result["phone_os"]    = "iOS"
            result["phone_icon"]  = "📱"
            # Надсилаємо HTTP GET і дивимось на відповідь
            try:
                s.settimeout(timeout)
                s.send(b"GET /info HTTP/1.0\r\nHost: " + ip.encode() + b"\r\nUser-Agent: iTunes/12.0\r\n\r\n")
                resp = b""
                while len(resp) < 2048:
                    chunk = s.recv(512)
                    if not chunk: break
                    resp += chunk
                text = resp.decode("utf-8", "ignore")
                # Шукаємо model identifier
                for pat in [
                    r"model[^\w]*:?\s*(iPhone\d+,\d+|iPad\d+,\d+|iPod\d+,\d+)",
                    r'"model"\s*:\s*"(iPhone[^"]+)"',
                    r"deviceID[^\w]+(iPhone[^\s<]+)",
                ]:
                    m = re.search(pat, text, re.IGNORECASE)
                    if m:
                        model_id = m.group(1).strip()
                        apple = cls.APPLE_MODELS.get(model_id)
                        if apple:
                            result["phone_model"] = apple[0]
                            result["phone_os"]    = apple[1]
                        else:
                            result["phone_model"] = model_id
                        break
            except Exception:
                pass
            s.close()
        except Exception:
            pass
        return result

    @classmethod
    def _probe_android_device(cls, ip: str, ports_set: set, timeout: float = 2.5) -> dict:
        """
        Детектує Android-смартфони та планшети.

        Методи (від надійного до менш надійного):
          1. SSDP unicast — Android відповідає на M-SEARCH з UPnP описом
          2. DLNA/UPnP на портах 1900, 8200, 8080 — містить модель
          3. ADB порт 5555 — відкритий якщо ввімкнено режим розробника
          4. mDNS _androidtvremote2 — Android TV/Google TV
          5. HTTP на 8080 — деякі Share-apps та Cast
          6. TTL-аналіз (Android = TTL 64)
        """
        result = {}

        # ── 1. SSDP unicast M-SEARCH ─────────────────────────────────
        # Android DLNA стек відповідає на unicast SSDP запит
        try:
            SSDP_MSG = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\n"
                "ST: ssdp:all\r\n\r\n"
            ).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout * 0.4)
            s.sendto(SSDP_MSG, (ip, 1900))
            try:
                resp_bytes, _ = s.recvfrom(4096)
                resp_text = resp_bytes.decode("utf-8", "ignore")
                # Перевіряємо заголовки SSDP відповіді
                is_android = any(k in resp_text.lower() for k in
                    ("android", "samsung", "xiaomi", "huawei", "oppo",
                     "vivo", "realme", "oneplus", "miui", "emui",
                     "mediatek", "qualcomm"))
                if is_android:
                    result["phone_brand"] = "Android"
                    result["phone_os"]    = "Android"
                    result["phone_icon"]  = "📱"
                    # Шукаємо Location для подальшого парсингу
                    for line in resp_text.splitlines():
                        if line.lower().startswith("location:"):
                            loc = line.split(":", 1)[1].strip()
                            try:
                                desc = urllib.request.urlopen(
                                    urllib.request.Request(
                                        loc, headers={"User-Agent":"Android"}),
                                    timeout=1.5).read().decode("utf-8","ignore")
                                # Парсимо модель з UPnP опису
                                m = re.search(r"<modelName>([^<]{2,60})</modelName>", desc, re.IGNORECASE)
                                if m:
                                    model_raw = m.group(1).strip()
                                    # Samsung SM-xxxx
                                    sm = re.search(r"\b(SM-[A-Z0-9]{4,8})\b", model_raw.upper())
                                    if sm:
                                        for prefix, name in cls.SAMSUNG_MODELS.items():
                                            if sm.group(1).startswith(prefix[:5]):
                                                result["phone_model"]  = name
                                                result["phone_brand"]  = "Samsung"
                                                break
                                        if not result.get("phone_model"):
                                            result["phone_model"] = sm.group(1)
                                            result["phone_brand"] = "Samsung"
                                    else:
                                        result["phone_model"] = model_raw
                                m = re.search(r"<friendlyName>([^<]{2,60})</friendlyName>", desc, re.IGNORECASE)
                                if m and not result.get("phone_name"):
                                    result["phone_name"] = m.group(1).strip()
                                m = re.search(r"<manufacturer>([^<]{2,40})</manufacturer>", desc, re.IGNORECASE)
                                if m:
                                    mfr = m.group(1).strip().lower()
                                    if "samsung" in mfr:
                                        result["phone_brand"] = "Samsung"
                                    elif "xiaomi" in mfr or "miui" in mfr:
                                        result["phone_brand"] = "Xiaomi"
                                    elif "huawei" in mfr or "honor" in mfr:
                                        result["phone_brand"] = "Huawei"
                                    elif "oppo" in mfr or "realme" in mfr:
                                        result["phone_brand"] = "OPPO"
                                    elif "google" in mfr or "pixel" in mfr:
                                        result["phone_brand"] = "Google"
                            except Exception:
                                pass
                            break
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass

        if result.get("phone_model"):
            return result

        # ── 2. UPnP/DLNA на відомих портах ───────────────────────────
        # Android Beam, DLNA клієнти, Samsung AllShare відкривають ці порти
        android_ports = [port for port in (8200, 8080, 49152, 49153, 55000, 1400, 8888)
                         if port in ports_set or not ports_set]
        for port in android_ports[:4]:
            for path in ["/description.xml", "/DeviceDescription.xml",
                         "/upnp/desc/smgt/rootDesc.xml", "/rootDesc.xml"]:
                try:
                    req = urllib.request.Request(
                        f"http://{ip}:{port}{path}",
                        headers={"User-Agent": "Android/10.0"})
                    resp_text = urllib.request.urlopen(req, timeout=min(timeout*0.4, 1.0)).read().decode("utf-8","ignore")
                    # Samsung SM-xxxx в modelName
                    m = re.search(r"<modelName>([^<]{2,60})</modelName>", resp_text, re.IGNORECASE)
                    if m:
                        raw = m.group(1).strip()
                        sm = re.search(r"\b(SM-[A-Z0-9]{4,8})\b", raw.upper())
                        if sm:
                            for prefix, name in cls.SAMSUNG_MODELS.items():
                                if sm.group(1).startswith(prefix[:5]):
                                    result["phone_model"] = name
                                    result["phone_brand"] = "Samsung"
                                    break
                            if not result.get("phone_model"):
                                result["phone_model"] = sm.group(1)
                                result["phone_brand"] = "Samsung"
                        else:
                            result["phone_model"] = raw
                    m = re.search(r"<manufacturer>([^<]{2,40})</manufacturer>", resp_text, re.IGNORECASE)
                    if m and not result.get("phone_brand"):
                        mfr = m.group(1).strip().lower()
                        if "samsung" in mfr:   result["phone_brand"] = "Samsung"
                        elif "xiaomi" in mfr:  result["phone_brand"] = "Xiaomi"
                        elif "huawei" in mfr:  result["phone_brand"] = "Huawei"
                        elif "google" in mfr:  result["phone_brand"] = "Google"
                        else: result["phone_brand"] = "Android"
                    m = re.search(r"<friendlyName>([^<]{2,60})</friendlyName>", resp_text, re.IGNORECASE)
                    if m and not result.get("phone_name"):
                        result["phone_name"] = m.group(1).strip()
                    if result:
                        result.setdefault("phone_os", "Android")
                        result.setdefault("phone_icon", "📱")
                        return result
                except Exception:
                    continue

        # ── 3. ADB порт 5555 (режим розробника) ──────────────────────
        adb_open = 5555 in ports_set
        if not adb_open and not ports_set:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.4)
                adb_open = (s.connect_ex((ip, 5555)) == 0)
                s.close()
            except Exception:
                pass
        if adb_open:
            result["phone_brand"] = result.get("phone_brand") or "Android"
            result["phone_os"]    = "Android (ADB enabled)"
            result["phone_icon"]  = "📱"
            return result

        # ── 4. mDNS _androidtvremote2 (Android TV / Google TV) ───────
        if not result:
            try:
                def _build_q(svc):
                    labels = svc.rstrip(".").split(".")
                    qname  = b""
                    for l in labels:
                        e = l.encode(); qname += bytes([len(e)]) + e
                    qname += b"\x00"
                    return b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x0c\x80\x01"

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(0.5)
                for svc in ("_androidtvremote2._tcp.local",
                             "_androiddebugbridge._tcp.local"):
                    sock.sendto(_build_q(svc), (ip, 5353))
                    try:
                        data, _ = sock.recvfrom(2048)
                        if data and len(data) > 12:
                            result["phone_brand"] = "Android TV"
                            result["phone_icon"]  = "📺"
                            break
                    except socket.timeout:
                        pass
                sock.close()
            except Exception:
                pass

        # ── Якщо нічого не знайшли але є рандомний MAC ───────────────
        # Залишаємо результат порожнім — _enrich_from_oui зробить решту
        if result:
            result.setdefault("phone_brand", "Android")
            result.setdefault("phone_os",    "Android")
            result.setdefault("phone_icon",  "📱")

        return result

    @classmethod
    def _probe_airplay(cls, ip, timeout=1.5) -> dict:
        result = {}
        for port in (7000,7001,7100):
            try:
                req = urllib.request.Request(f"http://{ip}:{port}/info",
                    headers={"User-Agent":"AirPlay/550.10","Content-Type":"application/x-apple-binary-plist","X-Apple-Device-ID":"ff:ff:ff:ff:ff:ff"})
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    text = resp.read().decode("utf-8","ignore")
                    for pat in [r"deviceID.*?([A-Za-z0-9 '._-]{4,60})",r"name[^\w]([A-Za-z0-9 '\u0400-\u04ff._-]{4,60})",r"model[^\w](iPhone\w+|iPad\w+|AppleTV\w+)"]:
                        m = re.search(pat, text, re.IGNORECASE)
                        if m and len(m.group(1)) > 3:
                            val = m.group(1).strip()
                            if re.match(r"(iPhone|iPad|AppleTV)", val):
                                mn = cls.APPLE_MODELS.get(val,("","iOS"))
                                if mn[0]: result["phone_model"]=mn[0]; result["phone_os"]=mn[1]
                            elif not result.get("phone_name"): result["phone_name"]=val
                    m = re.search(r"\bmodel\b[^A-Za-z]*(iPhone[\w,]+|iPad[\w,]+|AppleTV[\w,]+)",text,re.IGNORECASE)
                    if m:
                        model_id=m.group(1).strip(); mn=cls.APPLE_MODELS.get(model_id,("","iOS"))
                        if mn[0]: result["phone_model"]=mn[0]; result["phone_os"]=mn[1]
                        elif not result.get("phone_model"): result["phone_model"]=model_id
                    sv_m = re.search(r"srcvers[^\d]*(\d+)\.(\d+)",text)
                    if sv_m and not result.get("phone_os"):
                        major=int(sv_m.group(1))
                        if major>=600: ios_ver=17
                        elif major>=550: ios_ver=16
                        elif major>=500: ios_ver=15
                        elif major>=450: ios_ver=14
                        else: ios_ver=max(13,major//30)
                        result["phone_os"]=f"iOS {ios_ver}"
                    if result: result["phone_brand"]="Apple"; result["phone_icon"]="📱"; return result
            except Exception: continue
        return result

    @classmethod
    def _probe_dial(cls, ip, timeout=2.0) -> dict:
        result={}
        for port,path in [(8008,"/ssdp/device-desc.xml"),(8009,"/ssdp/device-desc.xml"),(8008,"/description.xml")]:
            try:
                req=urllib.request.Request(f"http://{ip}:{port}{path}",headers={"User-Agent":"Mozilla/5.0"})
                with urllib.request.urlopen(req,timeout=timeout) as resp:
                    text=resp.read().decode("utf-8","ignore")
                m=re.search(r"<friendlyName>([^<]{3,60})</friendlyName>",text,re.IGNORECASE)
                if m: result["phone_name"]=m.group(1).strip()
                m=re.search(r"<modelName>([^<]{3,60})</modelName>",text,re.IGNORECASE)
                if m:
                    raw_model=m.group(1).strip()
                    if "Chromecast" in raw_model: result["phone_model"]=raw_model; result["phone_brand"]="Google"; result["phone_icon"]="📺"
                    elif "Fire TV" in raw_model or "FireTV" in raw_model: result["phone_model"]=raw_model; result["phone_brand"]="Amazon"; result["phone_icon"]="📺"
                    elif "Android" in raw_model or "TV" in raw_model: result["phone_model"]=raw_model; result["phone_brand"]="Android"; result["phone_icon"]="📺"
                    else: result["phone_model"]=raw_model
                m=re.search(r"<manufacturer>([^<]{2,40})</manufacturer>",text,re.IGNORECASE)
                if m and not result.get("phone_brand"): result["phone_brand"]=m.group(1).strip()
                if result: return result
            except Exception: continue
        return result

    @classmethod
    def _probe_upnp_phone(cls, ip, ports_set, timeout=2.0) -> dict:
        result={}; probe_urls=[]
        if 80 in ports_set: probe_urls+=[(80,"/description.xml"),(80,"/ssdp/device-desc.xml"),(80,"/rootDesc.xml")]
        if 8080 in ports_set: probe_urls+=[(8080,"/description.xml")]
        for port_n,path in [(55000,"/upnp/desc/smgt/rootDesc.xml"),(1400,"/xml/device_description.xml"),(49152,"/description.xml")]:
            if port_n in ports_set: probe_urls.append((port_n,path))
        for port,path in probe_urls:
            try:
                req=urllib.request.Request(f"http://{ip}:{port}{path}",headers={"User-Agent":"UPnP/1.0 NetGuardian/5.4"})
                with urllib.request.urlopen(req,timeout=timeout) as resp:
                    text=resp.read().decode("utf-8","ignore")
                m=re.search(r"<friendlyName>([^<]{2,80})</friendlyName>",text,re.IGNORECASE)
                if m: result["phone_name"]=m.group(1).strip()
                m=re.search(r"<modelName>([^<]{2,60})</modelName>",text,re.IGNORECASE)
                if m:
                    raw_model=m.group(1).strip()
                    for prefix,name in cls.SAMSUNG_MODELS.items():
                        if raw_model.startswith(prefix): result["phone_model"]=name; result["phone_brand"]="Samsung"; break
                    if not result.get("phone_model"): result["phone_model"]=raw_model
                m=re.search(r"<manufacturer>([^<]{2,40})</manufacturer>",text,re.IGNORECASE)
                if m and not result.get("phone_brand"):
                    mfr=m.group(1).strip(); result["phone_brand"]=mfr
                    if "samsung" in mfr.lower(): result["phone_icon"]="📱"
                    elif any(tv in mfr.lower() for tv in ("sony","lg","philips","hisense","tcl","panasonic","toshiba","sharp")): result["phone_icon"]="📺"
                if result: return result
            except Exception: continue
        return result

    @classmethod
    def _probe_http_banner(cls, ip, timeout=1.5) -> dict:
        result={}
        try:
            req=urllib.request.Request(f"http://{ip}/",headers={"User-Agent":"Mozilla/5.0"})
            with urllib.request.urlopen(req,timeout=timeout) as resp:
                text=resp.read(4096).decode("utf-8","ignore")
                server=resp.headers.get("Server","")
                if server:
                    result["http_server"]=server
                    if "Android" in server: result["phone_brand"]="Android"; result["phone_os"]="Android"
                    elif "iPhone" in server or "iOS" in server: result["phone_brand"]="Apple"; result["phone_os"]="iOS"
                m=re.search(r"<title[^>]*>([^<]{3,60})</title>",text,re.IGNORECASE)
                if m and not result.get("phone_name"):
                    title=m.group(1).strip()
                    if not any(k in title.lower() for k in ("router","gateway","admin")): result["phone_name"]=title
        except Exception: pass
        return result

    @classmethod
    def _enrich_from_mdns_cache(cls, result, cache):
        if cache.get("model"):
            model_raw=cache["model"]; mn=cls.APPLE_MODELS.get(model_raw,("",""))
            if mn[0]:
                if not result["phone_model"]: result["phone_model"]=mn[0]
                if not result["phone_brand"]: result["phone_brand"]="Apple"
                if mn[1] and not result["phone_os"]: result["phone_os"]=mn[1]
            else:
                for prefix,name in cls.SAMSUNG_MODELS.items():
                    if model_raw.startswith(prefix):
                        if not result["phone_model"]: result["phone_model"]=name
                        if not result["phone_brand"]: result["phone_brand"]="Samsung"
                        break
            if not result["phone_model"] and model_raw: result["phone_model"]=model_raw
        if cache.get("hostname") and not result["phone_name"]: result["phone_name"]=cache["hostname"]
        if cache.get("os") and not result["phone_os"]: result["phone_os"]=cache["os"]
        if cache.get("samsung") and not result["phone_brand"]:
            result["phone_brand"]="Samsung"; sm=cache["samsung"]
            for prefix,name in cls.SAMSUNG_MODELS.items():
                if sm.startswith(prefix):
                    if not result["phone_model"]: result["phone_model"]=name; break
        if result.get("phone_model") or result.get("phone_name"):
            if "mDNS" not in result["identification_method"]: result["identification_method"].insert(0,"mDNS")

    @classmethod
    def _enrich_from_oui(cls, result, oui_vendor, mac, ports_set):
        vendor_l=oui_vendor.lower()
        brand_map={"apple":"Apple","samsung":"Samsung","xiaomi":"Xiaomi","huawei":"Huawei",
                   "google":"Google","oppo":"Oppo","realme":"Realme","vivo":"Vivo","oneplus":"OnePlus",
                   "motorola":"Motorola","nokia":"Nokia","sony":"Sony","lg":"LG"}
        for key,brand in brand_map.items():
            if key in vendor_l:
                if not result["phone_brand"]: result["phone_brand"]=brand
                if not result["identification_method"]: result["identification_method"].append("OUI")
                break
        if 62078 in ports_set and not result["phone_brand"]:
            result["phone_brand"]="Apple"
            if "iPhone Sync Port" not in result["identification_method"]: result["identification_method"].append("iPhone Sync Port")
        try:
            if int(mac.split(":")[0],16) & 0x02 and not result["phone_brand"]: result["identification_method"].append("Random MAC")
        except Exception: pass

    @classmethod
    def _merge(cls, result, data, method):
        for key in ("phone_model","phone_name","phone_brand","phone_os","phone_icon"):
            if data.get(key) and not result[key]: result[key]=data[key]
        if method not in result["identification_method"]: result["identification_method"].insert(0,method)

    @classmethod
    def _build_summary(cls, result):
        parts=[]
        if result["phone_brand"]: parts.append(result["phone_brand"])
        if result["phone_model"] and result["phone_model"]!=result["phone_brand"]: parts.append(result["phone_model"])
        if result["phone_os"]: parts.append(f"[{result['phone_os']}]")
        if parts: result["phone_summary"]="  ".join(parts)
        elif result["phone_name"]: result["phone_summary"]=result["phone_name"]
        else: result["phone_summary"]=""
        if result.get("phone_icon")!="📱": return
        brand_l=result["phone_brand"].lower() if result["phone_brand"] else ""
        for tb in ("chromecast","fire tv","firetv","appletv","sony bravia","lg tv","samsung tv"):
            if tb in brand_l or tb in result["phone_summary"].lower(): result["phone_icon"]="📺"; return


# ══════════════════════════════════════════════════════════════════
# DEVICE IDENTIFIER  (FIX-5: NetBIOS priority, reverse_dns timeout)
# ══════════════════════════════════════════════════════════════════
class DeviceIdentifier:
    _SKIP_NETBIOS={"WORKGROUP","MSHOME","HOME","HOMEGROUP","MSBROWSE","__MSBROWSE__","LOCALDOMAIN"}

    @staticmethod
    def query_netbios(ip, timeout=2.0) -> dict:
        result={}
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.settimeout(timeout)
            tid=0xABCD; flags=0x0000
            packet=struct.pack(">HHHHHH",tid,flags,1,0,0,0)
            encoded=b"\x20"+b"CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+b"\x00"
            qtype=struct.pack(">HH",33,1); packet+=encoded+qtype
            sock.sendto(packet,(ip,137))
            try:
                data,_=sock.recvfrom(1024)
                if len(data)>57:
                    num_names=data[56]; offset=57; names=[]
                    _SKIP_NB=DeviceIdentifier._SKIP_NETBIOS
                    for _ in range(min(num_names,10)):
                        if offset+18>len(data): break
                        raw_name=data[offset:offset+15].decode("ascii",errors="ignore").strip()
                        name_type=data[offset+15]
                        if raw_name and name_type in (0x00,0x03,0x20) and raw_name.upper() not in _SKIP_NB:
                            names.append(raw_name)
                        offset+=18
                    if names: result["netbios_name"]=names[0]; result["netbios_names"]=names
            except socket.timeout: pass
            sock.close()
        except Exception: pass
        return result

    @staticmethod
    def query_http_banner(ip, port=80, timeout=2.0) -> dict:
        result={}
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM); sock.settimeout(timeout)
            if sock.connect_ex((ip,port))!=0: sock.close(); return result
            request=f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            sock.send(request.encode()); response=b""
            while True:
                chunk=sock.recv(2048)
                if not chunk: break
                response+=chunk
                if len(response)>8192 or b"\r\n\r\n" in response: break
            sock.close(); text=response.decode("utf-8",errors="ignore")
            m=re.search(r"Server:\s*(.+)",text,re.IGNORECASE)
            if m: result["http_server"]=m.group(1).strip()[:80]
            m=re.search(r"<title[^>]*>([^<]{3,60})</title>",text,re.IGNORECASE)
            if m: result["http_title"]=m.group(1).strip()
        except Exception: pass
        return result

    @staticmethod
    def query_https_cert(ip, timeout=2.0) -> dict:
        result={}
        try:
            import ssl
            ctx=ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
            conn=ctx.wrap_socket(socket.create_connection((ip,443),timeout=timeout),server_hostname=ip)
            cert=conn.getpeercert(); conn.close()
            if cert:
                subject=dict(x[0] for x in cert.get("subject",[]))
                cn=subject.get("commonName","")
                if cn and len(cn)>2: result["cert_cn"]=cn
        except Exception: pass
        return result

    @staticmethod
    def reverse_dns(ip, timeout=2.0) -> str:
        """FIX-5: власний timeout щоб не зависати"""
        result_box=[None]
        def _do():
            try:
                name=socket.gethostbyaddr(ip)[0]
                if name and name!=ip: result_box[0]=name
            except Exception: pass
        t=threading.Thread(target=_do,daemon=True); t.start(); t.join(timeout=timeout)
        return result_box[0] or "—"

    @staticmethod
    def query_snmp_sysdescr(ip, timeout=1.5) -> dict:
        result={}
        try:
            def _tlv(tag,val):
                if len(val)<128: return bytes([tag,len(val)])+val
                elif len(val)<256: return bytes([tag,0x81,len(val)])+val
                else:
                    l=len(val); return bytes([tag,0x82,(l>>8)&0xFF,l&0xFF])+val
            def _encode_oid(oid_str):
                parts=[int(x) for x in oid_str.split(".")]
                enc=bytes([40*parts[0]+parts[1]])
                for v in parts[2:]:
                    if v<128: enc+=bytes([v])
                    else:
                        octets=[]
                        while v: octets.append(v&0x7F); v>>=7
                        octets.reverse()
                        enc+=bytes([o|0x80 for o in octets[:-1]]+[octets[-1]])
                return enc
            community=b"public"; oid_bytes=_encode_oid("1.3.6.1.2.1.1.1.0")
            varbind=_tlv(0x30,_tlv(0x06,oid_bytes)+bytes([0x05,0x00]))
            pdu=_tlv(0xA0,bytes([0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00])+_tlv(0x30,varbind))
            packet=_tlv(0x30,bytes([0x02,0x01,0x01])+_tlv(0x04,community)+pdu)
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); sock.settimeout(timeout)
            sock.sendto(packet,(ip,161))
            try:
                data,_=sock.recvfrom(4096); idx=0
                while idx<len(data)-2:
                    if data[idx]==0x04:
                        length=data[idx+1]
                        if length&0x80:
                            n=length&0x7F; length=int.from_bytes(data[idx+2:idx+2+n],"big"); idx+=n
                        val=data[idx+2:idx+2+length].decode("utf-8",errors="ignore").strip()
                        if len(val)>8: result["snmp_sysdescr"]=val[:200]; break
                    idx+=1
            except socket.timeout: pass
            sock.close()
        except Exception: pass
        return result

    _DHCP_FINGERPRINTS: dict = {
        "1,121,3,6,15,119,252,95,44,46":("Apple iOS","iPhone/iPad","📱"),
        "1,121,3,6,15,119,252,95,44":("Apple iOS","iPhone/iPad","📱"),
        "1,3,6,15,119,252,95,44,46":("Apple iOS (old)","iPhone/iPad","📱"),
        "1,121,3,6,15,119,252,95":("Apple iOS","iPhone/iPad","📱"),
        "1,121,3,6,15,119,252,95,44,46,47,113":("Apple iOS 16+","iPhone/iPad","📱"),
        "1,121,3,6,15,119,252,95,44,46,47":("Apple macOS","Mac","💻"),
        "1,121,3,6,15,119,252":("Apple macOS","Mac","💻"),
        "1,3,6,15,26,28,51,58,59,43":("Android (AOSP)","Android","📱"),
        "1,3,6,15,26,28,51,58,59":("Android","Android","📱"),
        "1,3,6,15,26,28,51,58,59,43,119":("Android (Google)","Pixel","📱"),
        "1,3,6,12,15,17,26,28,51,58,59":("Android (Samsung)","Samsung","📱"),
        "1,33,3,6,15,28,51,58,59,119,43":("Android (Samsung OneUI)","Samsung","📱"),
        "1,3,6,12,15,28,42,51,54,58,59":("Android (Xiaomi)","Xiaomi","📱"),
        "1,3,6,15,28,51,58,59,43,77":("Android (MIUI)","Xiaomi","📱"),
        "1,3,6,15,26,28,43,51,58,59,121":("Android (Huawei)","Huawei","📱"),
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252":("Windows 10/11","PC","💻"),
        "1,3,6,15,31,33,43,44,46,47,119,121,249":("Windows 10","PC","💻"),
        "1,3,6,15,31,33,43,44,46,47,119,121":("Windows","PC","💻"),
        "1,28,2,3,15,6,119,12,44,47,26,121,42":("Linux (DHCP5)","Linux PC","🖥️"),
        "1,2,3,6,12,15,26,28,40,41,42":("Linux (Debian)","Linux PC","🖥️"),
        "1,3,6,12,15,28,42":("Linux (BusyBox)","IoT/Linux","🖥️"),
        "1,3,6,15,26,28,51,58,59,43,77,119":("Android (OnePlus)","OnePlus","📱"),
        "1,3,6,15,28,43,51,58,59,119":("Android (ColorOS)","Oppo/Realme","📱"),
    }

    @staticmethod
    def _probe_upnp_device(ip, timeout=2.0) -> dict:
        result = {}

        # ── FIX-1a: спочатку SSDP unicast M-SEARCH для роутерів ─────
        try:
            SSDP_MSG = (
                "M-SEARCH * HTTP/1.1\r\n"
                f"HOST: {ip}:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 1\r\nST: upnp:rootdevice\r\n\r\n"
            ).encode()
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(SSDP_MSG, (ip, 1900))
            try:
                resp = s.recv(2048).decode("utf-8", "ignore")
                # Витягуємо Location з відповіді
                for line in resp.splitlines():
                    if line.lower().startswith("location:"):
                        loc = line.split(":", 1)[1].strip()
                        try:
                            desc = urllib.request.urlopen(
                                urllib.request.Request(loc, headers={"User-Agent":"UPnP/1.0 NetGuardian"}),
                                timeout=timeout).read().decode("utf-8", "ignore")
                            m = re.search(r"<friendlyName>([^<]{2,80})</friendlyName>", desc, re.IGNORECASE)
                            if m: result["upnp_name"] = m.group(1).strip()
                            m = re.search(r"<modelName>([^<]{2,60})</modelName>", desc, re.IGNORECASE)
                            if m: result["upnp_model"] = m.group(1).strip()
                            m = re.search(r"<manufacturer>([^<]{2,40})</manufacturer>", desc, re.IGNORECASE)
                            if m: result["upnp_vendor"] = m.group(1).strip()
                        except Exception:
                            pass
                        break
            except socket.timeout:
                pass
            s.close()
        except Exception:
            pass

        if result:
            if not result.get("upnp_name") and result.get("upnp_vendor") and result.get("upnp_model"):
                vs = result["upnp_vendor"]; ms = result["upnp_model"]
                result["upnp_name"] = f"{vs} {ms}" if vs.lower() not in ms.lower() else ms
            return result

        # ── Fallback: HTTP XML description ────────────────────────────
        for port, path in [
            (80, "/description.xml"), (80, "/ssdp/device-desc.xml"), (80, "/rootDesc.xml"),
            (8080, "/description.xml"), (8008, "/ssdp/device-desc.xml"),
            (55000, "/upnp/desc/smgt/rootDesc.xml"), (1400, "/xml/device_description.xml"),
            (49152, "/description.xml"),
        ]:
            try:
                resp = urllib.request.urlopen(
                    urllib.request.Request(f"http://{ip}:{port}{path}",
                        headers={"User-Agent":"UPnP/1.0 NetGuardian/5.4"}),
                    timeout=timeout).read().decode("utf-8","ignore")
            except Exception:
                continue
            m = re.search(r"<friendlyName>([^<]{2,80})</friendlyName>", resp, re.IGNORECASE)
            if m: result["upnp_name"] = m.group(1).strip()
            m = re.search(r"<modelName>([^<]{2,60})</modelName>", resp, re.IGNORECASE)
            if m: result["upnp_model"] = m.group(1).strip()
            m = re.search(r"<manufacturer>([^<]{2,40})</manufacturer>", resp, re.IGNORECASE)
            if m: result["upnp_vendor"] = m.group(1).strip()
            if result:
                if not result.get("upnp_name") and result.get("upnp_vendor") and result.get("upnp_model"):
                    vs = result["upnp_vendor"]; ms = result["upnp_model"]
                    result["upnp_name"] = f"{vs} {ms}" if vs.lower() not in ms.lower() else ms
                return result
        return result

    @classmethod
    def dhcp_option55_fingerprint(cls, option55_bytes) -> tuple:
        if not option55_bytes: return ("","","")
        key=",".join(str(b) for b in option55_bytes)
        if key in cls._DHCP_FINGERPRINTS: return cls._DHCP_FINGERPRINTS[key]
        key_prefix=",".join(str(b) for b in option55_bytes[:6])
        for fp_key,fp_val in cls._DHCP_FINGERPRINTS.items():
            if fp_key.startswith(key_prefix): return fp_val
        return ("","","")

    @classmethod
    def identify(cls, ip, mac, oui_vendor, oui_devtype, open_ports, dhcp_hostname="", ttl=None, dhcp_vendor_class="") -> dict:
        info={"hostname":dhcp_hostname or "—","model":"","mdns_name":"","netbios_name":"",
              "http_server":"","http_title":"","cert_cn":"","upnp_name":"","upnp_model":"",
              "snmp_sysdescr":"","icon_override":"","mdns_hardware_model":"","mdns_os_version":"",
              "ttl":ttl,"dhcp_vendor_class":dhcp_vendor_class}
        results={}; lock=threading.Lock(); ports_set=set(open_ports)
        tasks={
            "rdns":    lambda: {"hostname": cls.reverse_dns(ip, timeout=2.0)},
            "netbios": lambda: cls.query_netbios(ip, timeout=2.0),
            "http":    lambda: cls.query_http_banner(ip) if ports_set&{80,8080} else {},
            "https":   lambda: cls.query_https_cert(ip) if ports_set&{443,8443} else {},
            "snmp":    lambda: cls.query_snmp_sysdescr(ip),
            "upnp":    lambda: cls._probe_upnp_device(ip) if ports_set&{80,8080,8008,8009,55000,1400,49152} else {},
        }
        def run(key,fn):
            try:
                r=fn()
                with lock: results[key]=r
            except Exception: pass
        threads=[threading.Thread(target=run,args=(k,v),daemon=True) for k,v in tasks.items()]
        for t in threads: t.start()
        for t in threads: t.join(timeout=5)
        for r in results.values(): info.update({k:v for k,v in r.items() if v})

        # FIX-5: NetBIOS > DHCP > mDNS > UPnP > rDNS
        for name in [info.get("netbios_name",""), dhcp_hostname, info.get("mdns_name",""), info.get("upnp_name","")]:
            if name and name not in ("—",""): info["hostname"]=name; break

        if not info.get("model") and info.get("upnp_model"): info["model"]=info["upnp_model"]
        vendor_l=oui_vendor.lower(); vc_l=dhcp_vendor_class.lower()
        mac_random=bool(mac!="—" and len(mac)>=2 and (int(mac.split(":")[0],16)&0x02))
        icon=""; ttl_os=""
        if ttl:
            if ttl<=64: ttl_os="linux_or_mobile"
            elif ttl<=128: ttl_os="windows"
            elif ttl>=200: ttl_os="network_device"
        hn_l=info["hostname"].lower()
        is_apple=("apple" in vendor_l or "iphone" in hn_l or "ipad" in hn_l or "ios" in vc_l or "apple" in vc_l)
        if is_apple: icon="📱"; info["icon_override"]="Apple iPhone/iPad"
        elif ("android" in vc_l or "android" in hn_l or "samsung" in hn_l or "galaxy" in hn_l or "pixel" in hn_l):
            icon="📱"; info["icon_override"]="Android"
        elif ("windows" in vc_l or "msft" in vc_l or ports_set&{135,139,445}):
            icon="💻"; info["icon_override"]="Windows PC"
        elif 8008 in ports_set or 8009 in ports_set: icon="📺"; info["icon_override"]="Chromecast/Android TV"
        if not icon and info.get("upnp_vendor"):
            uv=info["upnp_vendor"].lower()
            if any(v in uv for v in ("samsung","sony","lg","philips","hisense","tcl","panasonic","toshiba","sharp","bravia","vestel","chromecast","apple tv","roku","fire tv","nvidia")):
                icon="📺"; info["icon_override"]=info["upnp_vendor"]
        if not icon and mac_random:
            if ttl_os=="windows": icon="💻"; info["icon_override"]="Windows PC"
            elif 62078 in ports_set: icon="📱"; info["icon_override"]="iPhone"
            else: icon="📱"; info["icon_override"]="Смартфон"
        if icon: info["icon_override_emoji"]=icon
        if not info.get("model") and ttl_os:
            if ttl_os=="windows": info["os_hint"]="Windows (TTL≈128)"
            elif ttl_os=="linux_or_mobile": info["os_hint"]="Linux / Android"
        return info

# ══════════════════════════════════════════════════════════════════
# MAIN ENGINE  (FIX-2: diagnose no-hang; FIX-4: router name;
#               FIX-6: is_scanning flag for UI-widget)
# ══════════════════════════════════════════════════════════════════
class LanSecurityEngine:
    _mdns_device_cache:    dict = {}
    _new_device_callbacks: list = []
    _suspicious_callbacks: list = []

    # Sticky-cache: пристрої що були online в останніх скан(ах).
    # Формат: {mac: {"last_seen_ts": float, "data": full_device_dict}}
    # Це рятує ситуацію коли Android в doze-режимі ігнорує один-два ARP-broadcast:
    # пристрій показується "online" ще 3 хвилини після останнього виявлення.
    _recently_seen: dict = {}
    STICKY_TTL_SEC = 300   # 5 хвилин — скільки "пам'ятати" пристрій після останнього scan-hit

    # FIX-6: прапорці для UI scan-widget
    is_scanning: bool = False
    scan_progress_text: str = ""
    scan_devices_found: int = 0

    def __init__(self):
        self._my_ip: str = ""; self._last_ttl_map: dict = {}
        self._identifier = DeviceIdentifier()

    def on_new_device(self, cb):
        if cb not in LanSecurityEngine._new_device_callbacks: LanSecurityEngine._new_device_callbacks.append(cb)
    def on_suspicious(self, cb):
        if cb not in LanSecurityEngine._suspicious_callbacks: LanSecurityEngine._suspicious_callbacks.append(cb)
    def _fire_new_device(self, device):
        # Логуємо виклик — допомагає зрозуміти чому telegram-callback не виконується
        cbs = LanSecurityEngine._new_device_callbacks
        print(f"[LanSec] _fire_new_device: {len(cbs)} callbacks, device={device.get('mac','?')}")
        for cb in cbs:
            try:
                cb(device)
            except Exception as e:
                import traceback
                print(f"[LanSec] Callback error: {e}")
                traceback.print_exc()

    def _fire_suspicious(self, device):
        cbs = LanSecurityEngine._suspicious_callbacks
        print(f"[LanSec] _fire_suspicious: {len(cbs)} callbacks, device={device.get('mac','?')}")
        for cb in cbs:
            try:
                cb(device)
            except Exception as e:
                import traceback
                print(f"[LanSec] Suspicious callback error: {e}")
                traceback.print_exc()

    def _sticky_remember(self, devices: list):
        """Зберігає всі online-пристрої у sticky-cache з timestamp."""
        now = time.time()
        for d in devices:
            mac = d.get("mac","")
            if mac and mac != "—" and d.get("is_online"):
                LanSecurityEngine._recently_seen[mac] = {
                    "last_seen_ts": now,
                    "ip":           d.get("ip",""),
                    "data":         dict(d),
                }
        # Чистимо застарілі записи (старші за 2x TTL)
        cutoff = now - (LanSecurityEngine.STICKY_TTL_SEC * 2)
        for mac in list(LanSecurityEngine._recently_seen.keys()):
            if LanSecurityEngine._recently_seen[mac]["last_seen_ts"] < cutoff:
                del LanSecurityEngine._recently_seen[mac]

    def _sticky_get_missing_macs(self, current_macs: set) -> list:
        """Повертає список пристроїв з кешу які НЕ знайшли в поточному скані
        (але бачили <3хв тому). Це Android/iOS що заснули на секунду."""
        now = time.time()
        cutoff = now - LanSecurityEngine.STICKY_TTL_SEC
        missing = []
        for mac, entry in LanSecurityEngine._recently_seen.items():
            if mac in current_macs: continue
            if entry["last_seen_ts"] < cutoff: continue
            # Цей пристрій був online <3хв тому але зараз не виявився → додаємо
            age = int(now - entry["last_seen_ts"])
            stale_data = dict(entry["data"])
            stale_data["is_online"] = True     # вважаємо online (sticky)
            stale_data["_sticky"]   = True      # помітка для UI/бота
            stale_data["_sticky_age_sec"] = age
            missing.append(stale_data)
        return missing

    @staticmethod
    def _is_private_lan_ip(ip: str) -> bool:
        """Перевіряє чи IP належить приватній LAN мережі (RFC 1918 + link-local).
        Публічні IP типу 26.x.x.x (VPN/tunnel адаптери) — не LAN шлюзи."""
        if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
            return False
        try:
            parts = [int(p) for p in ip.split(".")]
            if parts[0] == 10:                              return True   # 10.0.0.0/8
            if parts[0] == 172 and 16 <= parts[1] <= 31:    return True   # 172.16.0.0/12
            if parts[0] == 192 and parts[1] == 168:         return True   # 192.168.0.0/16
            if parts[0] == 169 and parts[1] == 254:         return True   # link-local
            if parts[0] == 100 and 64 <= parts[1] <= 127:   return True   # CGNAT 100.64/10
        except Exception:
            pass
        return False

    def _detect_gateway(self) -> str:
        """Знаходить IP роутера (шлюз) тільки серед приватних LAN адрес.
        Ігнорує VPN/tunnel/публічні шлюзи (26.x.x.x, 10.8.x.x VPN тощо — якщо
        в системі є кілька маршрутів, беремо той, що на LAN)."""
        candidates = []   # збираємо ВСІ виявлені шлюзи, потім фільтруємо

        if platform.system()=="Windows":
            # 1. ipconfig — парсимо БЛОКАМИ адаптерів, беремо тільки фізичні LAN/Wi-Fi
            try:
                r=subprocess.run(["ipconfig"],capture_output=True,text=True,
                                 timeout=5, encoding="cp866", errors="replace")
                current_adapter = ""
                skip_adapter = False
                for raw in r.stdout.splitlines():
                    line = raw.strip()
                    # Новий адаптер — перевіряємо чи це VPN/tunnel
                    if raw and not raw.startswith(" "):
                        current_adapter = line
                        low = line.lower()
                        # Пропускаємо віртуальні адаптери
                        skip_adapter = any(k in low for k in (
                            "vpn", "tunnel", "tap-", "tunneling", "isatap",
                            "teredo", "6to4", "hyper-v", "vmware", "virtualbox",
                            "vethernet", "bluetooth", "loopback"))
                        continue
                    if skip_adapter:
                        continue
                    # Шукаємо Default Gateway в полі
                    if ("Default Gateway" in line or "Основной шлюз" in line
                        or "Шлюз по умолчанию" in line or "Основний шлюз" in line):
                        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
                        if m and not m.group(1).startswith("0."):
                            candidates.append(m.group(1))
            except Exception: pass

            # 2. route print — бачимо metric, можна вибрати найменшу
            try:
                r=subprocess.run(["route","print","0.0.0.0"],capture_output=True,
                                 text=True,timeout=5)
                route_entries = []   # [(metric, gateway)]
                for line in r.stdout.splitlines():
                    cols=line.split()
                    if len(cols) >= 5 and cols[0]=="0.0.0.0" and cols[1]=="0.0.0.0":
                        gw = cols[2]
                        try: metric = int(cols[4])
                        except Exception: metric = 9999
                        if re.match(r"^\d+\.\d+\.\d+\.\d+$",gw) and gw!="0.0.0.0":
                            route_entries.append((metric, gw))
                # Сортуємо за metric — найменша = основний маршрут
                route_entries.sort(key=lambda x: x[0])
                for _, gw in route_entries:
                    candidates.append(gw)
            except Exception: pass

            # 3. PowerShell — бекап
            try:
                r=subprocess.run(["powershell","-Command",
                    "(Get-NetRoute -DestinationPrefix '0.0.0.0/0').NextHop"],
                    capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    m=re.search(r"(\d+\.\d+\.\d+\.\d+)",line)
                    if m: candidates.append(m.group(1))
            except Exception: pass
        else:
            try:
                r=subprocess.run(["ip","route","show","default"],
                                 capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    m=re.search(r"default via (\d+\.\d+\.\d+\.\d+)",line)
                    if m: candidates.append(m.group(1))
            except Exception: pass
            try:
                r=subprocess.run(["route","-n"],capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    if line.startswith("0.0.0.0"):
                        parts=line.split()
                        if len(parts)>=2 and re.match(r"^\d+\.\d+\.\d+\.\d+$",parts[1]):
                            candidates.append(parts[1])
            except Exception: pass

        # Фільтруємо ТІЛЬКИ приватні LAN IP
        lan_candidates = [c for c in candidates if self._is_private_lan_ip(c)]
        if lan_candidates:
            return lan_candidates[0]   # перший виявлений приватний

        # Якщо жоден приватний не знайшовся — повертаємо перший будь-який
        # (рідкісний випадок, коли мережа справді публічна)
        if candidates:
            return candidates[0]

        return "192.168.1.1"

    def _detect_my_ip(self) -> str:
        try:
            gw=self._detect_gateway(); s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(2)
            s.connect((gw,80)); ip=s.getsockname()[0]; s.close()
            if not ip.startswith("127."): return ip
        except Exception: pass
        try:
            hostname=socket.gethostname()
            for info in socket.getaddrinfo(hostname,None,socket.AF_INET):
                addr=info[4][0]
                if not addr.startswith(("127.","169.254.")): return addr
        except Exception: pass
        return ""

    def lookup_oui(self, mac) -> tuple:
        if not mac or mac in ("—","") or len(mac)<8: return ("Невідомо","Пристрій","❓")
        mac_norm=mac.upper().replace("-",":").replace(".",":")
        parts=mac_norm.split(":")
        if len(parts)!=6: return ("Невідомо","Пристрій","❓")
        try:
            if int(parts[0],16)&0x02: return ("Приватний MAC","Смартфон","📱")
        except Exception: pass
        oui=":".join(parts[:3])
        entry=_OUI_DB.get(oui)
        if entry: return entry
        return ("Невідомо","Пристрій","❓")

    def _get_arp_table(self) -> dict:
        result: dict={}
        try:
            if platform.system()=="Windows": r=subprocess.run(["arp","-a"],capture_output=True,text=True,timeout=5)
            else: r=subprocess.run(["arp","-n"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                ip_m=re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",line)
                mac_m=re.search(r"([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})",line)
                if ip_m and mac_m:
                    ip=ip_m.group(1); mac=mac_m.group(1).upper().replace("-",":")
                    if mac not in ("FF:FF:FF:FF:FF:FF","00:00:00:00:00:00"): result[ip]=mac
        except Exception: pass
        if platform.system()!="Windows":
            try:
                r=subprocess.run(["ip","neigh","show"],capture_output=True,text=True,timeout=5)
                for line in r.stdout.splitlines():
                    if "FAILED" in line or "INCOMPLETE" in line: continue
                    ip_m=re.match(r"(\d+\.\d+\.\d+\.\d+)",line)
                    mac_m=re.search(r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})",line,re.IGNORECASE)
                    if ip_m and mac_m: result.setdefault(ip_m.group(1),mac_m.group(1).upper())
            except Exception: pass
        return result

    def _check_scapy(self) -> tuple:
        try:
            import scapy.all
            if platform.system()=="Windows":
                try:
                    from scapy.arch.windows import get_windows_if_list
                    if not get_windows_if_list(): return False,"Npcap не знайдено — встановіть npcap.com"
                except Exception: return False,"Npcap не встановлено (потрібен Scapy на Windows)"
            return True,"Scapy доступний"
        except ImportError: return False,"Scapy не встановлено (pip install scapy)"

    def _scapy_arp_scan(self, subnet_cidr) -> dict:
        """
        Мульти-пасовий ARP-скан. Андроїд/iOS у doze-режимі часто ігнорують
        перший broadcast ARP. Робимо 3 проходи з затримкою 1.5с між ними —
        це значно підвищує виявлення сплячих пристроїв.
        """
        result: dict={}
        try:
            from scapy.all import ARP,Ether,srp,conf; conf.verb=0

            # 3 проходи з наростаючим timeout — sleep-пристрої часто відповідають на 2-й/3-й
            passes = [(2, 0), (2.5, 1.5), (3, 2.0)]   # (timeout, pre-delay)
            for idx, (tmo, pre_delay) in enumerate(passes):
                if pre_delay > 0:
                    time.sleep(pre_delay)
                try:
                    ans,_ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=subnet_cidr),
                        timeout=tmo, verbose=False, retry=1 if idx > 0 else 0)
                    for _,rcv in ans:
                        # Нові хости накопичуються — якщо вже знайшли на pass 1, не перезаписуємо
                        ip = rcv.psrc
                        mac = rcv.hwsrc.upper()
                        if ip not in result:
                            result[ip] = mac
                except Exception: pass

                # Якщо на першому проході знайшли достатньо — можемо не чекати всі 3
                # Але для надійності все одно робимо всі (зайві 3-4с того варто)
        except Exception: pass
        return result

    def _arp_flood_fill(self, subnet_prefix):
        try:
            ok,_=self._check_scapy()
            if ok:
                from scapy.all import ARP,Ether,sendp,conf; conf.verb=0
                targets=[f"{subnet_prefix}{i}" for i in range(1,255)]
                pkts=[Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip) for ip in targets]
                sendp(pkts,verbose=False,inter=0.001); return
        except Exception: pass
        def _do_ping(ip):
            try:
                if platform.system()=="Windows": subprocess.run(["ping","-n","1","-w","200",ip],capture_output=True,timeout=1)
                else: subprocess.run(["ping","-c","1","-W","1",ip],capture_output=True,timeout=1)
            except Exception: pass
        with ThreadPoolExecutor(max_workers=50) as pool:
            pool.map(_do_ping,[f"{subnet_prefix}{i}" for i in range(1,255)])

    def _targeted_send_arp(self, ips) -> dict:
        result: dict={}
        ok,_=self._check_scapy()
        if ok:
            try:
                from scapy.all import ARP,Ether,srp,conf; conf.verb=0
                ans,_=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips),timeout=2,verbose=False)
                for _,rcv in ans: result[rcv.psrc]=rcv.hwsrc.upper()
                return result
            except Exception: pass
        for ip in ips:
            try:
                if platform.system()=="Windows": subprocess.run(["ping","-n","1","-w","300",ip],capture_output=True,timeout=1.5)
                else: subprocess.run(["ping","-c","1","-W","1",ip],capture_output=True,timeout=1.5)
            except Exception: pass
        time.sleep(0.5); arp=self._get_arp_table()
        for ip in ips:
            if ip in arp: result[ip]=arp[ip]
        return result

    def _mdns_listener(self, duration=8.0) -> set:
        found: set=set(); MDNS_ADDR="224.0.0.251"; MDNS_PORT=5353
        SERVICE_TYPES=["_airplay._tcp.local.","_raop._tcp.local.","_companion-link._tcp.local.",
            "_apple-mobdev2._tcp.local.","_appletv._tcp.local.","_homekit._tcp.local.",
            "_sleep-proxy._udp.local.","_dacp._tcp.local.","_googlecast._tcp.local.",
            "_androidtvremote2._tcp.local.","_privet._tcp.local.","_ipp._tcp.local.",
            "_printer._tcp.local.","_http._tcp.local.","_smb._tcp.local.","_ssh._tcp.local.",
            "_workstation._tcp.local.","_device-info._tcp.local.","_services._dns-sd._udp.local."]
        def _build_query(svc):
            parts=svc.rstrip(".").split("."); qname=b""
            for p in parts: enc=p.encode(); qname+=bytes([len(enc)])+enc
            qname+=b"\x00"
            return b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"+qname+b"\x00\x0c\x00\x01"
        def _parse_name(data,off):
            labels,visited=[],set()
            while off<len(data):
                if off in visited: break
                visited.add(off); ln=data[off]
                if ln==0: off+=1; break
                if (ln&0xC0)==0xC0:
                    if off+1>=len(data): break
                    ptr=((ln&0x3F)<<8)|data[off+1]; off+=2
                    sub,_=_parse_name(data,ptr); labels.append(sub); break
                else:
                    off+=1; labels.append(data[off:off+ln].decode("utf-8","ignore")); off+=ln
            return ".".join(labels),off
        def _parse(data,src):
            if len(data)<12: return
            try:
                qdcnt=(data[4]<<8)|data[5]; ancnt=(data[6]<<8)|data[7]
                nscnt=(data[8]<<8)|data[9]; arcnt=(data[10]<<8)|data[11]
                off=12
                for _ in range(qdcnt): _,off=_parse_name(data,off); off+=4
                entry=LanSecurityEngine._mdns_device_cache.get(src,{})
                for _ in range(ancnt+nscnt+arcnt):
                    if off>=len(data): break
                    _,off=_parse_name(data,off)
                    if off+10>len(data): break
                    rtype=(data[off]<<8)|data[off+1]; rdlen=(data[off+8]<<8)|data[off+9]; off+=10
                    rdata=data[off:off+rdlen]; off+=rdlen
                    if rtype==1 and len(rdata)==4: found.add(".".join(str(b) for b in rdata))
                    elif rtype==16:
                        pos=0
                        while pos<len(rdata):
                            slen=rdata[pos]; pos+=1; txt=rdata[pos:pos+slen].decode("utf-8","ignore"); pos+=slen
                            kv=txt.split("=",1)
                            if len(kv)==2:
                                k,v=kv[0].lower(),kv[1]
                                if k in ("md","model","am"): entry["model"]=v
                                elif k in ("fn","an","name","mn"): entry.setdefault("hostname",v)
                                elif k=="osvers": entry["os"]=f"iOS/macOS {v}"
                    elif rtype==12:
                        ptr_name,_=_parse_name(rdata,0); hn=ptr_name.split(".")[0]
                        if hn and len(hn)>2 and "._" not in hn: entry.setdefault("hostname",hn)
                if entry: LanSecurityEngine._mdns_device_cache[src]=entry; found.add(src)
            except Exception: pass
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try: sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEPORT,1)
            except AttributeError: pass
            sock.settimeout(0.5); sock.bind(("",MDNS_PORT))
            mreq=struct.pack("4sL",socket.inet_aton(MDNS_ADDR),socket.INADDR_ANY)
            sock.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,mreq)
            tx=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
            tx.setsockopt(socket.IPPROTO_IP,socket.IP_MULTICAST_TTL,1)
            for svc in SERVICE_TYPES:
                try: tx.sendto(_build_query(svc),(MDNS_ADDR,MDNS_PORT))
                except Exception: pass
            tx.close()
            # ── FIX-1b: агресивні unicast запити для Apple iPhone/iPad ─
            # Шлемо напряму на кожен відомий IP (не в multicast) — змушуємо відповісти
            apple_queries = [
                # TXT запит _device-info._tcp
                b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x0b_device-info\x04_tcp\x05local\x00\x00\x10\x00\x01",
                # PTR запит _apple-mobdev2._tcp
                b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x0e_apple-mobdev2\x04_tcp\x05local\x00\x00\x0c\x00\x01",
                # PTR запит _companion-link._tcp
                b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
                b"\x0f_companion-link\x04_tcp\x05local\x00\x00\x0c\x00\x01",
            ]
            for target_ip in list(found):
                for q in apple_queries:
                    try:
                        sock.sendto(q, (target_ip, 5353))
                    except Exception:
                        pass
            while time.time()<deadline:
                try:
                    data,addr=sock.recvfrom(4096); src=addr[0]
                    if src and not src.startswith(("224.","239.","127.")): found.add(src); _parse(data,src)
                except socket.timeout: pass
                except Exception: break
            sock.close()
        except Exception: pass
        return found

    @staticmethod
    def _guess_os_by_ttl(ttl) -> str:
        if ttl is None: return ""
        if 120<=ttl<=130: return "Windows"
        elif 60<=ttl<=70: return "Linux / Android"
        elif 100<=ttl<=120: return "FreeBSD / macOS"
        elif ttl>=200: return "Router / Network device"
        return ""

    @staticmethod
    def _classify_device(open_ports,ttl,http_server,http_title,vendor,devtype,icon,is_gateway,is_self) -> tuple:
        if is_gateway or is_self: return vendor,devtype,icon,""
        ports=set(open_ports or []); os_hint=""
        for sig in DEVICE_SIGNATURES:
            if all(p in ports for p in sig["ports"]):
                new_vendor=sig.get("vendor") or vendor; new_devtype=sig["name"]
                new_icon=sig["icon"]; new_os=sig.get("os","")
                if vendor not in ("Невідомо","Приватний MAC","","Unknown"): new_vendor=vendor
                return new_vendor,new_devtype,new_icon,new_os
        server_l=(http_server or "").lower(); title_l=(http_title or "").lower(); combined=server_l+" "+title_l
        for kw,(fp_vendor,fp_devtype) in HTTP_SERVER_FINGERPRINTS.items():
            if kw in combined:
                fp_icon=icon
                if fp_devtype in ("Router","Access Point","Firewall","Network Device"): fp_icon="📡"
                elif fp_devtype in ("IP Camera",): fp_icon="📷"
                elif fp_devtype in ("NAS","Database Server","Hypervisor","ESXi Host"): fp_icon="🗄️"
                elif fp_devtype in ("Printer",): fp_icon="🖨️"
                elif fp_devtype in ("Smart TV","Streaming Device","Chromecast"): fp_icon="📺"
                elif fp_devtype in ("Smart Plug","Smart Switch","Smart Device","Smart Home","Home Assistant"): fp_icon="🔌"
                new_vendor=fp_vendor if vendor in ("Невідомо","","Unknown") else vendor
                return new_vendor,fp_devtype,fp_icon,""
        ttl_os=LanSecurityEngine._guess_os_by_ttl(ttl)
        if ttl_os:
            os_hint=ttl_os
            if ttl_os=="Windows" and devtype in ("Невідомо","Пристрій",""): return vendor,"Windows PC","💻",ttl_os
            elif ttl_os=="Linux / Android" and devtype in ("Невідомо","Пристрій",""): return vendor,"Linux / Android","📱",ttl_os
            elif ttl_os=="Router / Network device" and devtype in ("Невідомо","Пристрій",""): return vendor,"Мережевий пристрій","📡",ttl_os
        return vendor,devtype,icon,os_hint

    def _ping_sweep(self, subnet_prefix, progress_cb=None) -> set:
        found: set=set(); lock=threading.Lock()
        ips=[f"{subnet_prefix}{i}" for i in range(1,255)]
        PHONE_PORTS=(80,443,22,8080,5353,62078,7000,7001,7100,49152,49153,55000,1900,5000,8008,8009,9080,554,3689,137,139,445,8443,4443)
        ttl_map: dict={}
        def probe(ip):
            alive=False; ttl=None
            try:
                if platform.system()=="Windows": r=subprocess.run(["ping","-n","1","-w","500",ip],capture_output=True,text=True,timeout=2.0)
                else: r=subprocess.run(["ping","-c","1","-W","1",ip],capture_output=True,text=True,timeout=2.0)
                alive=r.returncode==0
                if alive:
                    m=re.search(r"[Tt][Tt][Ll]=(\d+)",r.stdout)
                    if m: ttl=int(m.group(1))
            except Exception: pass
            if not alive:
                for port in PHONE_PORTS:
                    try:
                        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(0.25)
                        if s.connect_ex((ip,port))==0: alive=True
                        s.close()
                        if alive: break
                    except Exception: pass
            if alive:
                with lock:
                    found.add(ip)
                    if ttl: ttl_map[ip]=ttl
        with ThreadPoolExecutor(max_workers=200) as pool:
            futures={pool.submit(probe,ip): ip for ip in ips}; done=0
            for f in as_completed(futures):
                done+=1
                if progress_cb and done%30==0:
                    pct=int(done/len(ips)*100)
                    progress_cb(f"⏳  Ping sweep: {pct}%  ({len(found)} відповіли)")
                try: f.result()
                except Exception: pass
        self._last_ttl_map=ttl_map; return found

    def _ssdp_discovery(self, duration=3.0) -> set:
        found: set=set(); SSDP_ADDR,SSDP_PORT="239.255.255.250",1900
        msg=(f"M-SEARCH * HTTP/1.1\r\nHOST: {SSDP_ADDR}:{SSDP_PORT}\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n").encode()
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); sock.settimeout(0.5)
            sock.sendto(msg,(SSDP_ADDR,SSDP_PORT)); deadline=time.time()+duration
            while time.time()<deadline:
                try:
                    _,addr=sock.recvfrom(4096)
                    if addr[0]: found.add(addr[0])
                except socket.timeout: pass
                except Exception: break
            sock.close()
        except Exception: pass
        return found

    def _dhcp_hostname_listener(self, duration=5.0) -> dict:
        result: dict={}
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); sock.settimeout(0.5)
            try: sock.bind(("",68))
            except OSError:
                try: sock.bind(("",67))
                except OSError: sock.close(); return result
            deadline=time.time()+duration
            while time.time()<deadline:
                try:
                    data,_=sock.recvfrom(1500)
                    if len(data)<240: continue
                    if data[236:240]!=b"\x63\x82\x53\x63": continue
                    mac_bytes=data[28:34]; mac=":".join(f"{b:02X}" for b in mac_bytes)
                    if mac=="00:00:00:00:00:00": continue
                    hostname=""; vendor_class=""; option55=b""; i=240
                    while i<len(data):
                        opt=data[i]
                        if opt==255: break
                        if opt==0: i+=1; continue
                        if i+1>=len(data): break
                        length=data[i+1]; val=data[i+2:i+2+length]
                        if opt==12: hostname=val.decode("utf-8",errors="ignore").strip()
                        elif opt==55: option55=val
                        elif opt==60: vendor_class=val.decode("utf-8",errors="ignore").strip()
                        i+=2+length
                    if hostname or vendor_class or option55:
                        fp_os,fp_dev,fp_icon=DeviceIdentifier.dhcp_option55_fingerprint(option55)
                        result[mac]={"hostname":hostname,"vendor_class":vendor_class,
                                     "dhcp_option55":",".join(str(b) for b in option55) if option55 else "",
                                     "dhcp_fp_os":fp_os,"dhcp_fp_device":fp_dev,"dhcp_fp_icon":fp_icon}
                except socket.timeout: pass
                except Exception: break
            sock.close()
        except Exception: pass
        return result

    def _nbns_broadcast(self, broadcast_ip, duration=2.0) -> set:
        found: set=set()
        try:
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1); sock.settimeout(0.4)
            packet=b"\xab\xcd\x01\x10\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01"
            sock.sendto(packet,(broadcast_ip,137)); deadline=time.time()+duration
            while time.time()<deadline:
                try:
                    _,addr=sock.recvfrom(1024)
                    if addr[0]: found.add(addr[0])
                except socket.timeout: pass
                except Exception: break
            sock.close()
        except Exception: pass
        return found

    def scan_ports(self, ip, timeout=0.3) -> list:
        ports=list(CRITICAL_PORTS.keys())
        phone_ports=[62078,7000,7001,7100,8008,8009,5000,5001,49152,49153,55000,554,1400,3689,1883,8883,3306]
        all_ports=list(set(ports+phone_ports)); open_ports: list=[]; lock=threading.Lock()
        def _check(port):
            try:
                s=socket.socket(socket.AF_INET,socket.SOCK_STREAM); s.settimeout(timeout)
                if s.connect_ex((ip,port))==0:
                    with lock: open_ports.append(port)
                s.close()
            except Exception: pass
        threads=[threading.Thread(target=_check,args=(p,),daemon=True) for p in all_ports]
        for t in threads: t.start()
        for t in threads: t.join(timeout=timeout+0.15)
        return sorted(open_ports)

    @staticmethod
    def assess_threat(open_ports, is_gateway, is_self) -> str:
        if is_gateway or is_self: return "safe"
        danger=set(open_ports)&DANGEROUS_PORTS; suspicious=set(open_ports)&SUSPICIOUS_PORTS
        if 23 in open_ports or len(danger)>=2: return "critical"
        if danger: return "danger"
        if suspicious or len(open_ports)>=4: return "warn"
        return "safe"

    # ── FIX-2: diagnose не зависає ──────────────────────────────
    def diagnose_async(self, callback: Callable[[list], None]) -> None:
        """FIX-4: запускає diagnose() у фоновому потоці, викликає callback(lines) після завершення.
        Використовуйте цей метод з UI, щоб не заморозити інтерфейс."""
        def _run():
            try:
                lines = self.diagnose()
            except Exception as e:
                lines = [f"❌  Помилка діагностики: {e}"]
            try:
                callback(lines)
            except Exception:
                pass
        threading.Thread(target=_run, daemon=True).start()

    def diagnose(self) -> list:
        lines=[]
        gw=self._detect_gateway(); my=self._detect_my_ip()
        parts=gw.rsplit(".",1); subnet_prefix=parts[0]+"." if len(parts)==2 else "192.168.1."
        lines.append(f"🔍  Шлюз:    {gw}"); lines.append(f"🔍  Мій IP:  {my}")
        lines.append(f"🔍  Підмережа: {subnet_prefix}0/24")
        arp={}
        try:
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                arp=ex.submit(self._get_arp_table).result(timeout=5)
        except Exception: pass
        subnet_arp={ip:mac for ip,mac in arp.items() if ip.startswith(subnet_prefix)}
        lines.append(f"📋  ARP кеш: {len(arp)} записів ({len(subnet_arp)} в підмережі)")
        ok,msg=self._check_scapy(); lines.append(f"{'✅' if ok else '⚠️'}  Scapy/Npcap: {msg}")
        ssh_available=False
        try:
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                ssh_available=ex.submit(RouterSSHScanner(gw,timeout=2.0).is_available).result(timeout=4)
        except Exception: pass
        if ssh_available:
            lines.append(f"✅  SSH порт 22 відкритий на {gw} — SSH scanner доступний")
            saved=RouterSSHScanner.ssh_config.get(gw,{})
            if saved: lines.append(f"🔑  Збережені SSH-дані: user={saved.get('user','?')}")
            else: lines.append("⚠️  SSH: облікові дані не збережені")
        else:
            lines.append(f"ℹ️  SSH порт 22 закритий на {gw} — використовуємо HTTP API")
        routers=router_manager.list_routers()
        if routers:
            lines.append(f"📡  Налаштовані роутери: {len(routers)}")
            for r in routers: lines.append(f"    • {r['label']} ({r['ip']})")
        else:
            lines.append("ℹ️  Роутери не налаштовані")
        def _router_api_check():
            reader=RouterClientReader(gw,timeout=3.0); clients=reader.get_all_clients()
            return reader._router_brand,clients
        try:
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                brand,clients=ex.submit(_router_api_check).result(timeout=8)
            if clients:
                wifi=sum(1 for c in clients if c.get("connection_type")=="WiFi")
                lan=sum(1 for c in clients if c.get("connection_type")=="LAN")
                lines.append(f"✅  Router API ({brand or '?'}): {len(clients)} клієнтів (WiFi: {wifi}, LAN: {lan})")
            else:
                lines.append("⚠️  Router API: не вдалося отримати список клієнтів")
        except _cf.TimeoutError:
            lines.append("⚠️  Router API: timeout (>8с)")
        except Exception as e:
            lines.append(f"⚠️  Router API: {e}")
        try:
            with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                if platform.system()=="Windows":
                    fut=ex.submit(subprocess.run,["ping","-n","1","-w","500",gw],capture_output=True,timeout=3)
                else:
                    fut=ex.submit(subprocess.run,["ping","-c","1","-W","1",gw],capture_output=True,timeout=3)
                r=fut.result(timeout=4)
            lines.append(f"{'✅' if r.returncode==0 else '⚠️'}  Ping до шлюзу {gw}")
        except Exception as e:
            lines.append(f"⚠️  Ping до шлюзу: помилка — {e}")
        return lines

    # ── FIX-4: краще визначення імені роутера ───────────────────
    def _fetch_gateway_fullname(self, ip, oui_vendor, reader=None) -> str:
        router_cfg=router_manager.get_router_by_ip(ip)
        if router_cfg and router_cfg.get("label") and router_cfg["label"]!=router_cfg.get("name",""):
            return router_cfg["label"]
        def _rdr(path,payload=None):
            if reader:
                if payload: return reader._fetch(path,method="POST",data=payload,extra_headers={"Content-Type":"application/json"})
                return reader._fetch(path)
            try:
                req=urllib.request.Request(f"http://{ip}{path}",data=payload,headers={"Content-Type":"application/json","User-Agent":"Mozilla/5.0"})
                return urllib.request.urlopen(req,timeout=2).read().decode("utf-8","ignore")
            except Exception: return None
        for endpoint,payload in [("/rci/",json.dumps({"show":{"system":{}}}).encode()),("/rci/show/system",None)]:
            try:
                raw=_rdr(endpoint,payload)
                if not raw: continue
                data=json.loads(raw)
                sys_info=(data.get("show",{}).get("system",{}) or data.get("system",{}) or data)
                name=(sys_info.get("description") or sys_info.get("modelName") or sys_info.get("model_name") or sys_info.get("type"))
                custom_name=sys_info.get("name") or sys_info.get("hostname")
                if name and len(name)>3:
                    if custom_name and custom_name.lower() not in name.lower(): return f"{name}  «{custom_name}»"
                    return name.strip()
            except Exception: continue
        stok=(reader._stok if reader and reader._stok else "")
        tp_paths=[]
        if stok: tp_paths.append(f"/cgi-bin/luci/;stok={stok}/rc/v1/system/info")
        tp_paths+=["/cgi-bin/luci/;stok=/rc/v1/system/info","/data/product.json","/api/v2/system/info"]
        for tp_path in tp_paths:
            try:
                raw=_rdr(tp_path)
                if not raw: continue
                data_tp=json.loads(raw); result_tp=data_tp.get("result") or data_tp.get("data") or data_tp
                model_tp=result_tp.get("model") or result_tp.get("productName") or ""
                if model_tp and len(model_tp)>2: return f"TP-Link {model_tp.strip()}"
            except Exception: continue
        for port in (80,8080):
            for path in ("/description.xml","/ssdp/device-desc.xml","/rootDesc.xml"):
                try:
                    resp=None
                    if port==80: resp=_rdr(path)
                    if not resp:
                        req=urllib.request.Request(f"http://{ip}:{port}{path}",headers={"User-Agent":"UPnP/1.0"})
                        resp=urllib.request.urlopen(req,timeout=2).read().decode("utf-8","ignore")
                    if not resp: continue
                    m=re.search(r"<friendlyName>([^<]{3,60})</friendlyName>",resp)
                    if m: return m.group(1).strip()
                    m=re.search(r"<modelName>([^<]{3,60})</modelName>",resp)
                    if m:
                        mm=re.search(r"<manufacturer>([^<]{2,40})</manufacturer>",resp)
                        prefix=(mm.group(1).strip()+" ") if mm else ""
                        return prefix+m.group(1).strip()
                except Exception: continue
        try:
            raw=_rdr("/appGet.cgi?hook=get_cfg_clientlist()")
            if raw and "productid" in raw.lower():
                m=re.search(r'"productid"\s*:\s*"([^"]+)"',raw)
                if m: return f"ASUS {m.group(1).strip()}"
        except Exception: pass
        try:
            rdns_box=[None]
            def _rdns():
                try:
                    name=socket.gethostbyaddr(ip)[0]
                    if name and name!=ip: rdns_box[0]=name
                except Exception: pass
            t=threading.Thread(target=_rdns,daemon=True); t.start(); t.join(timeout=2)
            if rdns_box[0]:
                clean_dns=rdns_box[0].split(".")[0]
                if clean_dns and len(clean_dns)>2: return clean_dns
        except Exception: pass
        if reader and reader._router_brand and reader._router_brand not in ("Generic",""):
            if oui_vendor and oui_vendor not in ("Невідомо","Приватний MAC",""):
                return f"{oui_vendor} ({reader._router_brand})"
            return f"{reader._router_brand} Router"
        if oui_vendor and oui_vendor not in ("Невідомо","Приватний MAC",""): return f"{oui_vendor} (шлюз)"
        if router_cfg and router_cfg.get("name"): return router_cfg["name"]
        return ""

    # ── FIX-6: scan_network встановлює is_scanning ───────────────
    def scan_network(self, gateway_ip=None, progress_cb=None, live_device_cb=None) -> list:
        LanSecurityEngine.is_scanning=True
        LanSecurityEngine.scan_progress_text="Починаємо сканування…"
        LanSecurityEngine.scan_devices_found=0
        def _pcb(text):
            LanSecurityEngine.scan_progress_text=text
            if progress_cb: progress_cb(text)
        try:
            return self._scan_network_impl(gateway_ip=gateway_ip,progress_cb=_pcb,live_device_cb=live_device_cb)
        finally:
            LanSecurityEngine.is_scanning=False
            LanSecurityEngine.scan_progress_text=""

    def _scan_network_impl(self, gateway_ip=None, progress_cb=None, live_device_cb=None) -> list:
        gw=gateway_ip or self._detect_gateway(); self._my_ip=self._detect_my_ip()
        _router_cfg=router_manager.get_router_by_ip(gw)
        gw_prefix=gw.rsplit(".",1)[0]+"."; my_prefix=self._my_ip.rsplit(".",1)[0]+"." if self._my_ip else gw_prefix

        # Запускаємо passive listening 60 сек у фоні — захоплює broadcast трафік
        # що допоможе ідентифікувати пристрої в наступних сканах
        try:
            from features.security.deep_identify import get_identifier
            get_identifier().start_passive_listening(duration=60.0)
        except Exception: pass

        # FIX-4: збираємо ВСІ локальні IP (включаючи VPN, VMware, WSL адаптери)
        # is_self = True якщо IP належить БУДЬ-ЯКОМУ адаптеру цього ПК
        _all_my_ips: set = set()
        if self._my_ip: _all_my_ips.add(self._my_ip)
        try:
            hostname=socket.gethostname()
            for info in socket.getaddrinfo(hostname,None,socket.AF_INET):
                addr=info[4][0]
                if not addr.startswith(("127.","169.254.")):
                    _all_my_ips.add(addr)
                    all_local_prefixes=getattr(self,"_all_local_prefixes",set())
                    all_local_prefixes.add(addr.rsplit(".",1)[0]+".")
                    self._all_local_prefixes=all_local_prefixes
        except Exception: pass
        all_local_prefixes = getattr(self, "_all_local_prefixes", set())
        all_local_prefixes.add(my_prefix)
        subnet_prefix=my_prefix; local_gw=my_prefix+"1"
        for prefix in all_local_prefixes:
            for gw_cand in (prefix+"1",prefix+"254"):
                try:
                    r=subprocess.run(["ping","-n","1","-w","500",gw_cand],capture_output=True,timeout=1.5)
                    if r.returncode==0: subnet_prefix=prefix; local_gw=gw_cand; break
                except Exception: pass
            else: continue
            break
        if gateway_ip: subnet_prefix=gw.rsplit(".",1)[0]+"."; local_gw=gw
        subnet_cidr=subnet_prefix+"0/24"; broadcast_ip=subnet_prefix+"255"
        devices: list=[]; lock=threading.Lock(); _mac_only_clients: dict={}

        ssh_dhcp_map: dict={}
        if progress_cb: progress_cb("🔒  Крок -1: SSH пряме читання DHCP роутера…")
        ssh_scanner=RouterSSHScanner(local_gw,timeout=3.0)
        if _router_cfg and _router_cfg.get("ssh_user"):
            RouterSSHScanner.ssh_config[local_gw]={"user":_router_cfg["ssh_user"],"pwd":_router_cfg["ssh_pwd"],
                                                    "port":_router_cfg.get("ssh_port",22),"key_path":_router_cfg.get("ssh_key","")}
        if ssh_scanner.is_available():
            try:
                ssh_clients=ssh_scanner.fetch_dhcp_leases()
                if ssh_clients:
                    for c in ssh_clients:
                        mac=c.get("mac","").upper()
                        if mac and len(mac)>=17: ssh_dhcp_map[mac]=c
                    if progress_cb: progress_cb(f"✅  SSH DHCP ({ssh_scanner.gateway}): {len(ssh_clients)} пристроїв")
                else:
                    if progress_cb: progress_cb("⚠️  SSH: підключено, але лізинги не знайдені → HTTP API")
            except Exception as e:
                if progress_cb: progress_cb(f"⚠️  SSH DHCP помилка: {e} → HTTP API")
        else:
            if progress_cb: progress_cb("ℹ️  SSH порт закритий → HTTP API")

        if progress_cb: progress_cb("🔍  Крок 0: Запит всіх клієнтів з роутера (HTTP API)…")
        router_clients: dict={}; dhcp_map: dict={}; reader=None
        try:
            http_user=_router_cfg.get("http_user","admin") if _router_cfg else "admin"
            http_pwd=_router_cfg.get("http_pwd","admin") if _router_cfg else "admin"
            reader=RouterClientReader(local_gw,username=http_user,password=http_pwd)
            clients=reader.get_all_clients()
            for c in clients:
                mac=c.get("mac","").upper(); ip=c.get("ip","")
                if mac and len(mac)>=17:
                    if mac in ssh_dhcp_map:
                        ssh_entry=ssh_dhcp_map[mac]; merged={**c}
                        if ssh_entry.get("hostname"): merged["hostname"]=ssh_entry["hostname"]
                        merged["dhcp_source_ssh"]=ssh_entry.get("source","SSH"); router_clients[mac]=merged
                    else: router_clients[mac]=c
                if ip: dhcp_map[ip]=router_clients.get(mac,c)
            if progress_cb:
                wifi_cnt=sum(1 for c in clients if c.get("connection_type")=="WiFi")
                lan_cnt=sum(1 for c in clients if c.get("connection_type")=="LAN")
                progress_cb(f"✅  Router HTTP ({reader._router_brand or '?'}): {len(clients)} клієнтів (📡 WiFi: {wifi_cnt}  🔌 LAN: {lan_cnt})")
        except Exception as e:
            if progress_cb: progress_cb(f"⚠️  Router HTTP API: {e}")

        for mac,ssh_entry in ssh_dhcp_map.items():
            if mac not in router_clients:
                router_clients[mac]=ssh_entry; ip=ssh_entry.get("ip","")
                if ip: dhcp_map[ip]=ssh_entry

        if progress_cb: progress_cb("🔍  Крок 1/6: Scapy ARP broadcast scan…")
        scapy_ok,_=self._check_scapy(); arp_scapy: dict={}
        if scapy_ok:
            # Spoiler: перед основним скануванням — targeted wake-up відомих пристроїв
            # (Android/iOS у doze часто потребують unicast-пробудження)
            known_ips = [entry.get("ip","") for entry in LanSecurityEngine._recently_seen.values()
                         if entry.get("ip","").startswith(subnet_prefix)]
            known_ips = [ip for ip in known_ips if ip][:30]   # обмежуємо
            if known_ips:
                if progress_cb: progress_cb(f"⚡  Wake-up {len(known_ips)} відомих пристроїв…")
                try:
                    # Паралельні пінги — будять sleep-пристрої
                    with ThreadPoolExecutor(max_workers=min(30, len(known_ips))) as pool:
                        def _wake(ip):
                            try:
                                if platform.system()=="Windows":
                                    subprocess.run(["ping","-n","1","-w","400",ip],
                                        capture_output=True, timeout=2,
                                        creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
                                else:
                                    subprocess.run(["ping","-c","1","-W","1",ip],
                                        capture_output=True, timeout=2)
                            except Exception: pass
                        list(pool.map(_wake, known_ips))
                    time.sleep(0.8)   # даємо час пристроям відповісти
                except Exception: pass

            arp_scapy=self._scapy_arp_scan(subnet_cidr)
            if progress_cb: progress_cb(f"✅  Scapy знайшов {len(arp_scapy)} хостів")
        else:
            if progress_cb: progress_cb("⚠️  Scapy/Npcap недоступний — інші методи")

        ping_found: set=set(); mdns_found: set=set()
        self._last_ttl_map={}; ssdp_found: set=set()
        nbns_found: set=set(); dhcp_hostnames: dict={}

        def _run_arp_flood(): self._arp_flood_fill(subnet_prefix)
        def _run_mdns():
            nonlocal mdns_found; mdns_found=self._mdns_listener(duration=8.0)
        def _run_ssdp():
            nonlocal ssdp_found; ssdp_found=self._ssdp_discovery(duration=4.0)
        def _run_nbns():
            nonlocal nbns_found; nbns_found=self._nbns_broadcast(broadcast_ip)
        def _run_ping():
            nonlocal ping_found; ping_found=self._ping_sweep(subnet_prefix,progress_cb=progress_cb)
        def _run_dhcp():
            nonlocal dhcp_hostnames; dhcp_hostnames=self._dhcp_hostname_listener(duration=6.0)

        threads=[threading.Thread(target=f,daemon=True) for f in (_run_arp_flood,_run_mdns,_run_ssdp,_run_nbns,_run_ping,_run_dhcp)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=25)

        if progress_cb: progress_cb("🔍  Зчитую ARP кеш після flood…")
        time.sleep(1.5); arp_os=self._get_arp_table()
        known_ips=set(arp_os.keys())|set(arp_scapy.keys())
        missing=[ip for ip in ping_found if ip not in known_ips and ip.startswith(subnet_prefix)]
        if missing:
            if progress_cb: progress_cb(f"🔍  Targeted SendARP для {len(missing)} IP без MAC…")
            targeted=self._targeted_send_arp(missing); arp_os.update(targeted)

        all_macs: dict={**arp_os,**arp_scapy}
        for ip,info in dhcp_map.items():
            if info.get("mac") and ip not in all_macs: all_macs[ip]=info["mac"]
        for mac,info in router_clients.items():
            ip=info.get("ip","")
            if ip and ip not in all_macs: all_macs[ip]=mac
        for mac,ssh_entry in ssh_dhcp_map.items():
            ip=ssh_entry.get("ip","")
            if ip and ip not in all_macs: all_macs[ip]=mac

        extra_ips=({ip for ip in ping_found if ip.startswith(subnet_prefix)}
                   |{ip for ip in mdns_found if ip.startswith(subnet_prefix)}
                   |{ip for ip in ssdp_found if ip.startswith(subnet_prefix)}
                   |{ip for ip in nbns_found if ip.startswith(subnet_prefix)}
                   |set(dhcp_map.keys())
                   |{e.get("ip","") for e in ssh_dhcp_map.values() if e.get("ip")})
        all_ips: set=({ip for ip in all_macs if ip.startswith(subnet_prefix) and not ip.endswith(".255") and not ip.endswith(".0")}|extra_ips)
        all_ips.add(gw)
        if self._my_ip: all_ips.add(self._my_ip)
        # FIX-4: фільтруємо broadcast, multicast та віртуальні підмережі
        _VIRTUAL_SUBNETS = ("172.17.", "172.18.", "172.19.", "172.20.",
                            "192.168.56.", "192.168.137.", "10.0.2.")
        all_ips = {
            ip for ip in all_ips
            if ((not ip.endswith(".255")
                 and not ip.startswith("224.")
                 and not ip.startswith("239.")
                 and ip != "0.0.0.0"
                 and not ip.startswith(_VIRTUAL_SUBNETS))
                or ip.startswith("router_mac_"))
        }

        _mac_to_ip_arp={v.upper():k for k,v in arp_os.items()}
        _mac_to_ip_arp.update({v.upper():k for k,v in arp_scapy.items()})
        for mac,info in router_clients.items():
            ip=info.get("ip","")
            if ip: all_ips.add(ip)
            else:
                found_ip=_mac_to_ip_arp.get(mac.upper(),"")
                if found_ip: info["ip"]=found_ip; all_ips.add(found_ip); dhcp_map[found_ip]=info
                else:
                    if mac.upper() not in {v.upper() for v in all_macs.values()}: _mac_only_clients[mac.upper()]=info
        for mac_key,info in _mac_only_clients.items():
            marker_ip=f"router_mac_{mac_key}"
            all_ips.add(marker_ip); all_macs[marker_ip]=mac_key
            if marker_ip not in dhcp_map: dhcp_map[marker_ip]=info

        total=len(all_ips)
        if progress_cb:
            progress_cb(f"✅  Знайдено {total} IP-адрес (підмережа: {subnet_prefix}0/24)")
            progress_cb(f"🔍  Сканую порти та ідентифікую {total} пристроїв…")

        def _analyze(ip) -> dict:
            is_mac_only=ip.startswith("router_mac_")
            mac=all_macs.get(ip,"—")
            if mac=="—":
                router_info=dhcp_map.get(ip,{})
                if router_info.get("mac"): mac=router_info["mac"]
            router_info=(router_clients.get(mac.upper()) or dhcp_map.get(ip) or {})
            if mac=="—":
                for rmac,rc in router_clients.items():
                    if rc.get("ip")==ip: mac=rmac; router_info=rc; break
            _ssh_entry=ssh_dhcp_map.get(mac.upper() if mac!="—" else "",{})
            _ssh_hostname=_ssh_entry.get("hostname","") if _ssh_entry else ""
            _ssh_source=_ssh_entry.get("source","") if _ssh_entry else ""
            vendor,devtype,icon=self.lookup_oui(mac)
            if is_mac_only:
                real_ip=router_info.get("ip","—") or "—"; open_ports=[]; is_gw=is_self=False
            else:
                real_ip=ip; open_ports=self.scan_ports(ip)
                is_gw=(ip==gw); is_self=(ip in _all_my_ips)
            dhcp_hostname=(_ssh_hostname or router_info.get("hostname",""))
            if not dhcp_hostname and mac!="—":
                _dhcp_info=dhcp_hostnames.get(mac.upper(),{})
                if _dhcp_info.get("hostname"): dhcp_hostname=_dhcp_info["hostname"]
            dhcp_source=_ssh_source or router_info.get("source","")
            _keenetic_vendor=router_info.get("keenetic_vendor","")
            if _keenetic_vendor and vendor in ("Невідомо","Приватний MAC",""): vendor=_keenetic_vendor
            _dhcp_entry=dhcp_hostnames.get(mac.upper() if mac!="—" else "",{})
            _dhcp_vc=_dhcp_entry.get("vendor_class","")
            _dhcp_fp_os=_dhcp_entry.get("dhcp_fp_os","")
            _dhcp_fp_dev=_dhcp_entry.get("dhcp_fp_device","")
            _dhcp_fp_ico=_dhcp_entry.get("dhcp_fp_icon","")
            connection_type=router_info.get("connection_type",""); band=router_info.get("band","")
            signal_dbm=router_info.get("signal_dbm"); signal_pct=router_info.get("signal_pct")
            tx_rate=router_info.get("tx_rate",""); bytes_sent=router_info.get("bytes_sent")
            bytes_recv=router_info.get("bytes_recv"); connected_time_s=router_info.get("connected_time")
            if router_info.get("mac") and mac=="—": mac=router_info["mac"]; vendor,devtype,icon=self.lookup_oui(mac)
            ttl=self._last_ttl_map.get(ip)
            ident=self._identifier.identify(ip,mac,vendor,devtype,open_ports,dhcp_hostname,ttl=ttl,dhcp_vendor_class=_dhcp_vc)

            # FIX-5: NetBIOS > DHCP > mDNS > UPnP
            hostname=ident.get("hostname","—")
            if ident.get("netbios_name") and ident["netbios_name"] not in ("","—"):
                hostname=ident["netbios_name"]
            elif hostname in ("—","",None) and dhcp_hostname: hostname=dhcp_hostname
            elif hostname in ("—","",None) and ident.get("upnp_name"): hostname=ident["upnp_name"]
            elif hostname in ("—","",None) and ident.get("mdns_name"): hostname=ident["mdns_name"]

            model=ident.get("model") or ident.get("upnp_model") or devtype
            vendor,devtype,icon,_fp_os_hint=self._classify_device(
                open_ports=open_ports,ttl=ttl,http_server=ident.get("http_server",""),
                http_title=ident.get("http_title",""),vendor=vendor,devtype=devtype,icon=icon,
                is_gateway=is_gw,is_self=is_self)
            if _fp_os_hint and not ident.get("os_hint"): ident["os_hint"]=_fp_os_hint
            if ident.get("icon_override_emoji") and not is_gw and not is_self:
                icon=ident["icon_override_emoji"]; devtype=ident.get("icon_override",devtype)
            if _dhcp_fp_ico and icon in ("❓","") and not is_gw and not is_self:
                icon=_dhcp_fp_ico
                if _dhcp_fp_dev and devtype in ("Невідомо","—",""): devtype=_dhcp_fp_dev
            if _dhcp_fp_os and not ident.get("os_hint"): ident["os_hint"]=_dhcp_fp_os

            _mdns_cache_entry=LanSecurityEngine._mdns_device_cache.get(ip,{})
            if _mdns_cache_entry:
                if not dhcp_hostname and _mdns_cache_entry.get("hostname"):
                    dhcp_hostname=_mdns_cache_entry["hostname"]
                    if hostname in ("—","",None): hostname=dhcp_hostname
                if not ident.get("mdns_name") and _mdns_cache_entry.get("hostname"):
                    ident["mdns_name"]=_mdns_cache_entry["hostname"]
                    if hostname in ("—","",None): hostname=ident["mdns_name"]
                if _mdns_cache_entry.get("model") and not ident.get("model"):
                    ident["model"]=_mdns_cache_entry["model"]; model=ident["model"]
                if _mdns_cache_entry.get("os"): ident["os_hint"]=_mdns_cache_entry["os"]

            phone_info: dict={}
            # Визначаємо чи це random MAC (iOS 14+ / Android 10+ / Windows 10+)
            _is_rand_mac = False
            try: _is_rand_mac = bool(int(mac.split(":")[0],16) & 0x02)
            except Exception: pass

            is_likely_phone=(
                icon=="📱"
                or devtype in ("Смартфон","iPhone","Android","Телефон","Smartphone")
                or vendor in ("Apple","Samsung","Xiaomi","Huawei","Google","Oppo","Realme","Vivo","OnePlus","Motorola","Nokia","Sony","LG","Приватний MAC")
                or _is_rand_mac   # Random MAC = майже завжди телефон
                or bool(_mdns_cache_entry)
                or (dhcp_hostname and re.search(r"android|SM-|Galaxy|iPhone|iPad",dhcp_hostname,re.IGNORECASE))
            )

            # Для рандомних MAC — пробуємо порт 62078 (iPhone sync) окремо
            if _is_rand_mac and not open_ports:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    if s.connect_ex((ip, 62078)) == 0:
                        open_ports = list(open_ports) + [62078]
                        ports_set.add(62078)
                        icon = "📱"; is_likely_phone = True
                    s.close()
                except Exception: pass
            if is_likely_phone and not is_gw and not is_self and not is_mac_only:
                _phone_dhcp_hn=_ssh_hostname or dhcp_hostname
                phone_info=PhoneProber.probe(ip=ip,mac=mac,oui_vendor=vendor,open_ports=open_ports,
                                             dhcp_hostname=_phone_dhcp_hn,timeout=5.0,mdns_cache=_mdns_cache_entry)
                if phone_info.get("phone_model"): model=phone_info["phone_model"]
                if phone_info.get("phone_name") and hostname in ("—","",None): hostname=phone_info["phone_name"]
                if phone_info.get("phone_icon"): icon=phone_info["phone_icon"]
                if phone_info.get("phone_brand") and phone_info.get("phone_model"):
                    devtype=f"{phone_info['phone_brand']} · {phone_info['phone_model']}"
                elif phone_info.get("phone_brand"): devtype=phone_info["phone_brand"]
                if not phone_info.get("phone_name") and _ssh_hostname:
                    phone_info["phone_name"]=_ssh_hostname
                    phone_info.setdefault("identification_method",[]).insert(0,"SSH DHCP")
                if not phone_info.get("phone_brand") and _keenetic_vendor:
                    phone_info["phone_brand"]=_keenetic_vendor; devtype=_keenetic_vendor

            if is_gw:
                icon,devtype="📡","Шлюз / Роутер"
                if vendor=="Невідомо": vendor="Роутер"
                connection_type="LAN"
                # FIX-1: пріоритет: router_cfg label > _fetch_gateway_fullname > mDNS > vendor-fallback
                if _router_cfg and _router_cfg.get("label"):
                    hostname = _router_cfg["label"]
                elif not hostname or hostname in ("—",""):
                    if _mdns_cache_entry and _mdns_cache_entry.get("hostname"):
                        hostname = _mdns_cache_entry["hostname"]
                    else:
                        hostname = self._fetch_gateway_fullname(ip, vendor, reader=reader)
                # Якщо після всіх спроб ім'я порожнє — показуємо vendor або просто "Роутер"
                if not hostname or hostname in ("—",""):
                    hostname = (vendor if vendor not in ("Невідомо","Роутер","") else f"Роутер ({ip})")
            elif is_self:
                icon,devtype="🖥️","Цей комп'ютер"

            if not connection_type and signal_dbm is not None: connection_type="WiFi"
            # FIX: розширюємо is_online — будь-яка ознака присутності пристрою
            # робить його online. Навіть якщо він не відповідає на ping
            # (iPhone, IoT з firewall), наявність у ARP-кеші чи відкриті порти —
            # це 100% доказ що пристрій в мережі.
            is_online=(
                ip in ping_found
                or ip in mdns_found
                or ip in ssdp_found
                or ip in nbns_found
                or bool(open_ports)
                or ip in arp_scapy
                or ip in arp_os                      # FIX: системний ARP
                or bool(dhcp_hostname)               # FIX: DHCP lease == активний
                or (mac != "—" and mac != "")        # FIX: якщо є MAC з будь-якого джерела
            ) if not is_mac_only else False
            threat=self.assess_threat(open_ports,is_gw,is_self); is_new=False
            if mac!="—": is_new=trust_db.upsert(mac,ip,vendor,model,hostname,gateway=local_gw)
            db_entry=trust_db.get_device(mac) if mac!="—" else None
            is_trusted=db_entry["trusted"] if db_entry else True
            is_allowed=db_entry["allowed"] if db_entry else False
            alert_dismissed=db_entry["alert_dismissed"] if db_entry else False
            user_label=db_entry["label"] if db_entry else ""
            user_notes=db_entry["notes"] if db_entry else ""

            # FIX: перевіряємо чи пристрій у банлисті і знімаємо allowed якщо так
            # Це гарантує що неможливо бути одночасно "Дозволено" і "Заблоковано"
            is_banned = trust_db.is_banned(mac) if mac!="—" else False
            if is_banned:
                is_allowed      = False
                alert_dismissed = False
                is_trusted      = False
                threat          = "critical"   # заблоковані завжди червоні

            if (is_trusted or alert_dismissed) and threat=="warn": threat="safe"
            if trust_db.get_router_suppress(local_gw) and threat=="warn": threat="safe"

            device={"ip":real_ip if is_mac_only else ip,"mac":mac,"is_mac_only":is_mac_only,
                    "hostname":hostname,"vendor":vendor,"dev_type":devtype,"model":model,"icon":icon,
                    "open_ports":open_ports,"is_gateway":is_gw,"is_self":is_self,"threat":threat,
                    "original_threat":threat,"is_trusted":is_trusted,"is_allowed":is_allowed,
                    "alert_dismissed":alert_dismissed,"is_banned":is_banned,"is_new":is_new,"user_label":user_label,
                    "user_notes":user_notes,"gateway":local_gw,"dhcp_hostname":dhcp_hostname,
                    "dhcp_source":dhcp_source,"ssh_hostname":_ssh_hostname,"ssh_dhcp_source":_ssh_source,
                    "connection_type":connection_type,"band":band,"signal_dbm":signal_dbm,"signal_pct":signal_pct,
                    "tx_rate":tx_rate,"bytes_sent":bytes_sent,"bytes_recv":bytes_recv,"connected_time":connected_time_s,
                    "netbios_name":ident.get("netbios_name",""),"mdns_name":ident.get("mdns_name",""),
                    "http_server":ident.get("http_server",""),"http_title":ident.get("http_title",""),
                    "cert_cn":ident.get("cert_cn",""),"upnp_name":ident.get("upnp_name","") or phone_info.get("phone_name",""),
                    "upnp_model":ident.get("upnp_model","") or phone_info.get("phone_model",""),
                    "upnp_vendor":ident.get("upnp_vendor",""),"snmp_sysdescr":ident.get("snmp_sysdescr",""),
                    "dhcp_vendor_class":_dhcp_vc,"dhcp_fp_os":_dhcp_fp_os,"dhcp_fp_device":_dhcp_fp_dev,
                    "mdns_hardware_model":ident.get("mdns_hardware_model","") or phone_info.get("phone_model",""),
                    "mdns_os_version":ident.get("mdns_os_version","") or phone_info.get("phone_os",""),
                    "os_hint":ident.get("os_hint","") or _dhcp_fp_os or phone_info.get("phone_os",""),
                    "ttl":ttl,"is_online":is_online,"phone_info":phone_info,
                    "phone_model":phone_info.get("phone_model",""),"phone_name":phone_info.get("phone_name","") or _ssh_hostname,
                    "phone_os":phone_info.get("phone_os",""),"phone_brand":phone_info.get("phone_brand",""),
                    "phone_summary":phone_info.get("phone_summary",""),
                    "phone_id_method":", ".join(phone_info.get("identification_method",[])),
                    "deep_identify": {}}   # буде заповнено нижче якщо треба

            LanSecurityEngine.scan_devices_found+=1  # FIX-6

            # ── Deep Identify: використовуємо 5 додаткових методів для пристроїв з Private MAC ──
            # Запускаємо тільки якщо базовий probe нічого не знайшов
            needs_deep = (
                not device.get("phone_model") and not device.get("phone_name")
                and not device.get("hostname","").strip("—")
                and not is_gw and not is_self and not is_mac_only
                and device.get("is_online")
            )
            if needs_deep:
                try:
                    from features.security.deep_identify import get_identifier
                    di = get_identifier()
                    di_result = di.identify(ip, mac, device)
                    if di_result["confidence"] >= 0.5 and di_result["name"]:
                        device["deep_identify"] = di_result
                        device["deep_identify_name"] = di_result["name"]
                        # Якщо confidence високий — використовуємо як phone_name
                        if di_result["confidence"] >= 0.7 and not device.get("phone_name"):
                            device["phone_name"] = di_result["name"]
                            device["phone_id_method"] = (
                                device.get("phone_id_method","") + f", {di_result['method']}"
                            ).strip(", ")
                except Exception as e:
                    device["deep_identify_error"] = str(e)[:100]

            if is_new and not is_gw and not is_self:
                # Перевіряємо чи пристрій був у sticky-cache недавно —
                # якщо так, це не справжній "новий пристрій", а просто
                # повернення з doze-режиму. Не спамимо сповіщеннями.
                was_seen_recently = mac in LanSecurityEngine._recently_seen
                if not was_seen_recently:
                    trust_db.log_event("NEW_DEVICE",mac,ip,f"Новий пристрій: {user_label or hostname or vendor}")
                    self._fire_new_device(device)
                else:
                    # Був у кеші → не новий, тихо оновлюємо
                    device["is_new"] = False
            if threat in ("danger","critical") and not alert_dismissed:
                trust_db.log_event("SUSPICIOUS",mac,ip,f"Підозрілий пристрій: порти {open_ports[:5]}")
                self._fire_suspicious(device)
            if progress_cb:
                display_ip=real_ip if is_mac_only else ip
                conn_badge=f" [{connection_type}]" if connection_type else ""
                online_tag="" if is_online else " 💤"; ssh_mark=" ★" if _ssh_hostname else ""
                label=(phone_info.get("phone_summary") or user_label or hostname or model or vendor)
                progress_cb(f"✅  {display_ip}{conn_badge}{online_tag}{ssh_mark}  {label}  — {len(open_ports)} портів")
            return device

        with ThreadPoolExecutor(max_workers=min(total,24)) as pool:
            futures={pool.submit(_analyze,ip): ip for ip in all_ips}
            for f in as_completed(futures):
                dev=f.result()
                with lock: devices.append(dev)
                if live_device_cb: live_device_cb(dev)

        _order={"critical":0,"danger":1,"warn":2,"safe":9}
        devices.sort(key=lambda d:(_order.get(d["threat"],9),0 if d["is_gateway"] else (1 if d["is_self"] else 2),
                                   [int(x) for x in d["ip"].split(".") if x.isdigit()]))

        # FIX-4: Дедуплікація власного ПК (кілька мережевих адаптерів / VMware / WSL)
        # Плюс: дедуплікація запису без MAC якщо є інший запис з тим самим IP І MAC.
        unique_devices: dict = {}
        ip_to_mac_key: dict = {}    # для швидкого пошуку: ip → ключ_у_unique_devices

        # ПЕРШИЙ ПРОХІД: записи з валідним MAC
        for d in devices:
            mac = d.get("mac","")
            ip_ = d.get("ip","")
            if d.get("is_self"):
                if "self_pc" not in unique_devices:
                    unique_devices["self_pc"] = d
                else:
                    # Мерджимо інформацію (порти, hostname)
                    existing = unique_devices["self_pc"]
                    for port in d.get("open_ports", []):
                        if port not in existing.get("open_ports", []):
                            existing.setdefault("open_ports", []).append(port)
                    if not existing.get("hostname") and d.get("hostname"):
                        existing["hostname"] = d["hostname"]
                if ip_:
                    ip_to_mac_key[ip_] = "self_pc"
            elif mac and mac != "—":
                if mac not in unique_devices:
                    unique_devices[mac] = d
                else:
                    existing = unique_devices[mac]
                    if len(d.get("hostname","") or "") > len(existing.get("hostname","") or ""):
                        unique_devices[mac] = d
                if ip_:
                    ip_to_mac_key[ip_] = mac

        # ДРУГИЙ ПРОХІД: записи без MAC ("—") — мерджимо у MAC-запис якщо
        # IP вже є; інакше додаємо як окремий "ip-only" запис
        for d in devices:
            mac = d.get("mac","")
            ip_ = d.get("ip","")
            if d.get("is_self") or (mac and mac != "—"):
                continue   # вже оброблено

            if ip_ and ip_ in ip_to_mac_key:
                # Той самий IP вже є з MAC → мерджимо порти/hostname/host data
                target_key = ip_to_mac_key[ip_]
                target = unique_devices[target_key]
                # Об'єднуємо open_ports
                for port in d.get("open_ports", []):
                    if port not in target.get("open_ports", []):
                        target.setdefault("open_ports", []).append(port)
                # Hostname — використовуємо який довший/більш інформативний
                if not target.get("hostname") and d.get("hostname"):
                    target["hostname"] = d["hostname"]
                # Vendor — якщо у MAC-запису порожньо
                if not target.get("vendor") and d.get("vendor"):
                    target["vendor"] = d["vendor"]
            else:
                # IP без жодного MAC-двійника — лишаємо як є
                unique_devices[ip_] = d

        # ТРЕТІЙ ПРОХІД (захисний): шукаємо ЛІШЕ ЗАЛИШКИ дублікатів по IP.
        # Якщо два записи мають однаковий IP (наприклад через різні джерела
        # router-API/scapy-ARP) — зливаємо найповнішим у один.
        ip_groups: dict = {}    # ip → list of (key, dev)
        for key, dev in list(unique_devices.items()):
            ip_v = dev.get("ip", "")
            if not ip_v: continue
            ip_groups.setdefault(ip_v, []).append((key, dev))

        for ip_v, entries in ip_groups.items():
            if len(entries) <= 1: continue
            print(f"[lan_security] DEDUP: знайдено {len(entries)} записів "
                  f"для IP={ip_v}, зливаю у один")
            # Сортуємо за "якістю" — той у якого є MAC і more info виграє
            def _score(item):
                _, d_ = item
                s = 0
                if d_.get("mac") and d_.get("mac") != "—": s += 100
                if d_.get("vendor"): s += 20
                if d_.get("hostname"): s += 10
                s += len(d_.get("open_ports", []))
                return s
            entries.sort(key=_score, reverse=True)
            keep_key, keep_dev = entries[0]
            # Мерджимо все з інших у keep_dev
            for other_key, other_dev in entries[1:]:
                # Об'єднуємо порти
                for port in other_dev.get("open_ports", []):
                    if port not in keep_dev.get("open_ports", []):
                        keep_dev.setdefault("open_ports", []).append(port)
                # Hostname/Vendor — якщо у keep пусто
                if not keep_dev.get("hostname") and other_dev.get("hostname"):
                    keep_dev["hostname"] = other_dev["hostname"]
                if not keep_dev.get("vendor") and other_dev.get("vendor"):
                    keep_dev["vendor"] = other_dev["vendor"]
                # Видаляємо дубль
                unique_devices.pop(other_key, None)
                print(f"[lan_security]   → видалено дубль: key={other_key}, "
                      f"mac={other_dev.get('mac')}")

        devices = list(unique_devices.values())

        online_devices=[d for d in devices if d.get("is_online") or d.get("is_gateway") or d.get("is_self")]
        offline_count=len(devices)-len(online_devices)

        # ── ULTIMATE DISCOVERY: 10 методів виявлення завжди ──
        # Запускається ЗАВЖДИ (раніше умовно, тепер безумовно) щоб
        # гарантовано знайти всі пристрої. Робить додаткове сканування
        # через ICMP/TCP/UDP/mDNS/SSDP/NetBIOS/LLMNR/IPv6/rDNS.
        try:
            from features.security.ultimate_discovery import discover_all
            if progress_cb:
                progress_cb(f"🔎  Запускаю ULTIMATE DISCOVERY (10 методів)…")
            ult_result = discover_all(
                subnet_prefix=subnet_prefix,
                subnet_cidr=subnet_cidr,
                progress_cb=progress_cb)

            # Мерджимо ultimate-знахідки з основними
            found_macs = {d.get("mac","").upper() for d in online_devices if d.get("mac")}
            found_ips  = {d.get("ip","") for d in online_devices}
            added = 0

            for ip, udev in ult_result.get("devices", {}).items():
                if not ip.startswith(subnet_prefix): continue
                mac = udev.get("mac","").upper()
                # Якщо пристрій вже відомий — оновлюємо дані (додаткові порти, hostname)
                if ip in found_ips or (mac and mac in found_macs):
                    # Оновлюємо існуючий
                    for existing in online_devices:
                        if existing.get("ip") == ip or existing.get("mac","").upper() == mac:
                            if udev.get("identified_as") and not existing.get("user_label"):
                                if not existing.get("phone_name"):
                                    existing["phone_name"] = udev["identified_as"]
                                    existing["phone_id_method"] = (
                                        existing.get("phone_id_method","") +
                                        f", ultimate({udev.get('id_method','?')})"
                                    ).strip(", ")
                            # Додаємо нові відкриті порти
                            for port in udev.get("ports", []):
                                if port not in existing.get("open_ports", []):
                                    existing.setdefault("open_ports", []).append(port)
                            break
                    continue

                # Новий пристрій виявлений ultimate-методами!
                new_dev = {
                    "ip":       ip,
                    "mac":      mac or "—",
                    "hostname": udev.get("hostname","") or udev.get("identified_as","") or "",
                    "vendor":   "",
                    "dev_type": udev.get("identified_as","Невідомо"),
                    "model":    "",
                    "icon":     "❓",
                    "open_ports":     udev.get("ports", []),
                    "is_gateway":     False,
                    "is_self":        False,
                    "is_online":      True,
                    "is_new":         True,
                    "threat":         "warn" if udev.get("ports") else "safe",
                    "is_trusted":     False,
                    "is_allowed":     False,
                    "alert_dismissed": False,
                    "is_banned":      False,
                    "user_label":     "",
                    "user_notes":     "",
                    "gateway":        local_gw,
                    "connection_type": "",
                    "phone_name":     udev.get("identified_as",""),
                    "phone_id_method":f"ultimate:{udev.get('id_method','?')}",
                    "phone_brand":    "",
                    "phone_model":    "",
                    "phone_os":       "",
                    "phone_summary":  "",
                    "ssdp_server":    udev.get("ssdp_server",""),
                    "mdns_name":      ",".join(udev.get("mdns_names",[])[:3]),
                    "netbios_name":   udev.get("netbios",{}).get("name",""),
                    "ipv6":           udev.get("ipv6",""),
                    "_discovered_by": udev.get("discovered_by",[]),
                    "_ultimate":      True,   # мітка
                }

                # Якщо NetBIOS знайшов MAC — записуємо
                if not mac and udev.get("netbios",{}).get("mac"):
                    new_dev["mac"] = udev["netbios"]["mac"]

                # OUI lookup для vendor
                if new_dev["mac"] and new_dev["mac"] != "—":
                    try:
                        v, _, _ = self.lookup_oui(new_dev["mac"])
                        new_dev["vendor"] = v or ""
                    except Exception: pass

                online_devices.append(new_dev)
                added += 1

                # FIX: записуємо в БД і тригеримо сповіщення — щоб popup
                # і Telegram-бот отримали повідомлення ПРО ВСІ знайдені пристрої
                # (включно з тими що ultimate discovery витягнув)
                if new_dev["mac"] and new_dev["mac"] != "—":
                    try:
                        was_seen = new_dev["mac"] in LanSecurityEngine._recently_seen
                        is_new_to_db = trust_db.upsert(
                            new_dev["mac"], new_dev["ip"],
                            new_dev["vendor"], new_dev.get("model",""),
                            new_dev.get("hostname",""), gateway=local_gw)
                        new_dev["is_new"] = is_new_to_db and not was_seen
                        if new_dev["is_new"]:
                            trust_db.log_event("NEW_DEVICE", new_dev["mac"], new_dev["ip"],
                                f"Знайдено через Ultimate Discovery: {new_dev.get('phone_name') or new_dev.get('vendor','?')}")
                            # НЕ fire_new_device тут — це робить UI при виявленні
                            # (інакше був би дубль popup)
                    except Exception: pass

            if progress_cb:
                progress_cb(f"✅  Ultimate Discovery додав {added} нових пристроїв "
                            f"(всього тепер: {len(online_devices)})")
        except Exception as e:
            if progress_cb:
                progress_cb(f"⚠️  Ultimate Discovery помилка: {str(e)[:80]}")

        # ── STICKY-CACHE: додаємо пристрої що були online <3хв тому ──
        # Це рятує Android/iOS що зараз у doze-режимі: вони не відповідають
        # на ARP прямо зараз, але були активні хвилину тому.
        current_macs = {d.get("mac","") for d in online_devices if d.get("mac")}
        sticky_devices = self._sticky_get_missing_macs(current_macs)
        if sticky_devices:
            # Для sticky-пристроїв оновлюємо threat-статус з актуальної БД
            for sd in sticky_devices:
                mac = sd.get("mac","")
                if mac != "—":
                    # Перевіряємо поточний стан у БД (banned/trusted міг змінитись)
                    try:
                        db_entry = trust_db.get_device(mac)
                        if db_entry:
                            sd["is_trusted"]      = db_entry["trusted"]
                            sd["is_allowed"]      = db_entry["allowed"]
                            sd["alert_dismissed"] = db_entry["alert_dismissed"]
                        sd["is_banned"] = trust_db.is_banned(mac)
                        if sd["is_banned"]:
                            sd["threat"] = "critical"
                            sd["is_allowed"] = False
                    except Exception: pass
            online_devices.extend(sticky_devices)
            if progress_cb:
                progress_cb(f"🔄  +{len(sticky_devices)} з sticky-cache (Android/iOS у doze)")

        # Зберігаємо знайдених у cache для наступного разу
        self._sticky_remember(online_devices)

        if progress_cb:
            ssh_cnt=sum(1 for d in online_devices if d.get("ssh_hostname"))
            sticky_cnt=sum(1 for d in online_devices if d.get("_sticky"))
            msg=f"✅  Завершено. Онлайн: {len(online_devices)} пристроїв."
            if ssh_cnt:    msg+=f"  ★ {ssh_cnt} з точним SSH hostname"
            if sticky_cnt: msg+=f"  💾 {sticky_cnt} зі sticky-cache"
            if offline_count: msg+=f"  ({offline_count} офлайн — приховано)"
            progress_cb(msg)
        return online_devices

    def scan_all_routers(self, progress_cb=None, live_device_cb=None) -> dict:
        routers=router_manager.list_routers()
        if not routers:
            if progress_cb: progress_cb("ℹ️  Роутери не налаштовані — скануємо поточну мережу")
            gw=self._detect_gateway()
            devices=self.scan_network(gateway_ip=gw,progress_cb=progress_cb,live_device_cb=live_device_cb)
            return {"Поточна мережа":devices}
        results: dict={}; all_results_lock=threading.Lock()
        def _scan_one(router_cfg):
            name=router_cfg.get("label") or router_cfg.get("name","Router"); ip=router_cfg.get("ip","")
            if not ip: return
            def _pcb(text):
                if progress_cb: progress_cb(f"[{name}] {text}")
            def _lcb(device):
                device["router_name"]=name
                if live_device_cb: live_device_cb(device)
            try:
                _pcb("🔍 Починаю сканування…")
                devices=self.scan_network(gateway_ip=ip,progress_cb=_pcb,live_device_cb=_lcb)
                for d in devices: d["router_name"]=name
                with all_results_lock: results[name]=devices
                _pcb(f"✅ Завершено: {len(devices)} пристроїв")
            except Exception as e:
                _pcb(f"❌ Помилка: {e}")
                with all_results_lock: results[name]=[]
        threads=[threading.Thread(target=_scan_one,args=(r,),daemon=True) for r in routers]
        for t in threads: t.start()
        for t in threads: t.join()
        return results

    def get_all_network_devices(self, progress_cb=None) -> list:
        results=self.scan_all_routers(progress_cb=progress_cb); all_devices=[]
        for devices in results.values(): all_devices.extend(devices)
        seen_macs: set=set(); unique: list=[]
        for d in all_devices:
            mac=d.get("mac","—")
            if mac=="—" or mac not in seen_macs:
                if mac!="—": seen_macs.add(mac)
                unique.append(d)
        return unique

    def set_trusted(self,mac,trusted): trust_db.set_trusted(mac,trusted)
    def set_allowed(self,mac,allowed): trust_db.set_allowed(mac,allowed)
    def dismiss_alert(self,mac): trust_db.dismiss_alert(mac)
    def restore_alert(self,mac): trust_db.restore_alert(mac)
    def set_router_suppress(self,gateway,suppress): trust_db.set_router_suppress(gateway,suppress)
    def get_router_suppress(self,gateway)->bool: return trust_db.get_router_suppress(gateway)
    def set_device_label(self,mac,label,notes=""): trust_db.set_label(mac,label,notes)

    def get_network_info(self)->dict:
        gw=self._detect_gateway(); my=self._my_ip or self._detect_my_ip()
        ok,msg=self._check_scapy()
        gw_prefix=".".join(gw.split(".")[:3]); my_prefix=".".join(my.split(".")[:3]) if my else gw_prefix
        subnet=(my_prefix if my_prefix!=gw_prefix else gw_prefix)+".0/24"
        ssh_ok=RouterSSHScanner(gw,timeout=1.5).is_available(); routers=router_manager.list_routers()
        return {"gateway":gw,"my_ip":my,"scapy_available":ok,"scapy_msg":msg,"subnet":subnet,
                "local_subnet":my_prefix+".0/24","ssh_available":ssh_ok,
                "configured_routers":[{"name":r["label"],"ip":r["ip"]} for r in routers],"routers_count":len(routers)}
    # ══════════════════════════════════════════════════════════════
    # disconnect_device — ГОЛОВНИЙ метод блокування
    #
    # Стратегія (всі методи запускаються ПАРАЛЕЛЬНО для максимального ефекту):
    #   A) ARP-отруєння — блокує трафік поки програма запущена (надійно)
    #   B) Router kick API — відключає зараз від WiFi
    #   C) Router MAC filter — забороняє повторне підключення
    #
    # Повертає (ok, message, method) де ok=True якщо хоча б ARP запущено.
    # ══════════════════════════════════════════════════════════════
    def disconnect_device(self, target_ip: str, target_mac: str,
                          gateway_ip: str = "", duration: int = 0,
                          status_cb=None) -> tuple:
        gw      = gateway_ip or self._detect_gateway()
        mac_up  = target_mac.upper().replace("-", ":")

        if status_cb: status_cb(f"⚔️  Починаю блокування {target_ip}…")

        results   = []   # що вдалось
        arp_ok    = False
        router_ok = False

        # ══════════════════════════════════════════════════════════
        # ФАЗА 1: Router MAC Filter (PRIMARY method — працює надійно)
        # ══════════════════════════════════════════════════════════
        # Це найкращий спосіб: роутер сам блокує пристрій. Постійно.
        # Якщо роутер підтримує MAC filter і є credentials — тут і закінчуємо.
        if status_cb: status_cb(f"📡  Спроба блокування через роутер {gw}…")

        try:
            ok_filter, msg_filter = self.router_mac_filter(
                mac_up, target_ip, gw, block=True)
            if ok_filter:
                router_ok = True
                results.append("Router MAC Filter")
                if status_cb: status_cb(f"✅  Роутер заблокував {mac_up} назавжди")

                # Додатково — kick (щоб негайно розірвати з'єднання)
                try:
                    self._router_api_kick(target_ip, mac_up, gw)
                    results.append("Router Kick")
                except Exception: pass

                # Успіх — ARP не потрібний, все постійно
                return True, (
                    f"✅  {target_ip} ЗАБЛОКОВАНО НАЗАВЖДИ через роутер\n\n"
                    f"🛡️  MAC-фільтр роутера: активний\n"
                    f"📡  Пристрій відключено з Wi-Fi\n"
                    f"🔒  Повторне підключення неможливе\n\n"
                    f"Щоб розблокувати — використовуй '🔓 Розблокувати' у списку."
                ), "Router MAC Filter"
        except Exception as e:
            if status_cb: status_cb(f"⚠️  Router filter помилка: {e}")

        # ══════════════════════════════════════════════════════════
        # ФАЗА 2: ARP-spoofing fallback
        # ══════════════════════════════════════════════════════════
        # Router не підтримує / немає credentials → fallback на ARP.
        # УВАГА: це ТИМЧАСОВЕ блокування поки NetGuardian запущений.
        if status_cb: status_cb(f"⚠️  Router недоступний, fallback на ARP…")

        scapy_ok, scapy_msg = self._check_scapy()

        # Перевіряємо права адміністратора Windows
        if platform.system() == "Windows":
            try:
                import ctypes as _ct
                if not _ct.windll.shell32.IsUserAnAdmin():
                    # FIX: повертаємо метод "Manual" — UI покаже діалог з покроковою
                    # інструкцією ручного блокування через admin-панель роутера
                    return False, (
                        "❌  Автоматичне блокування недоступне\n\n"
                        "Причини:\n"
                        "• Router API: провал (credentials або роутер не підтримується)\n"
                        "• ARP fallback: немає прав адміністратора\n\n"
                        "💡  Можеш заблокувати ВРУЧНУ через admin-панель роутера —\n"
                        "    покажу інструкцію у наступному вікні."
                    ), "Manual"
            except Exception:
                pass

        if not scapy_ok:
            return False, (
                f"❌  Автоматичне блокування недоступне\n\n"
                f"• Router API: провал (credentials або роутер не підтримується)\n"
                f"• ARP fallback: {scapy_msg}\n\n"
                "💡  Можеш заблокувати ВРУЧНУ через admin-панель роутера —\n"
                "    покажу інструкцію у наступному вікні."
            ), "Manual"

        try:
            arp_cache = self._get_arp_table()
            gw_mac    = arp_cache.get(gw, "")

            # Отримуємо MAC шлюзу через Scapy якщо нема в кеші
            if not gw_mac:
                try:
                    from scapy.all import ARP, Ether, srp, conf
                    conf.verb = 0
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gw),
                                 timeout=2, verbose=False)
                    if ans:
                        gw_mac = ans[0][1].hwsrc
                except Exception:
                    pass

            if not gw_mac:
                return False, (
                    f"❌  Не вдалось знайти MAC шлюзу {gw}.\n"
                    "Перевірте підключення до мережі."
                ), "—"

            # Отримуємо MAC цілі якщо не переданий або порожній
            if not mac_up or mac_up in ("—", ""):
                try:
                    from scapy.all import ARP, Ether, srp, conf
                    conf.verb = 0
                    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
                                 timeout=2, verbose=False)
                    if ans:
                        mac_up = ans[0][1].hwsrc.upper()
                except Exception:
                    pass
                if not mac_up or mac_up in ("—", ""):
                    mac_up = arp_cache.get(target_ip, "")

            if not mac_up or mac_up in ("—", ""):
                return False, (
                    f"❌  Не вдалось знайти MAC пристрою {target_ip}.\n"
                    "Переконайтесь що пристрій онлайн."
                ), "—"

            # Запускаємо ARP — start_ban повертає True якщо Scapy спрацював
            if duration == 0:
                arp_started = permanent_ban_manager.start_ban(
                    target_ip, mac_up, gw, gw_mac)
                if arp_started:
                    arp_ok = True
                    results.append("♾️ ARP постійне")
            else:
                ok_arp, _ = self.block_device(
                    target_ip, gw, duration=duration,
                    target_mac=mac_up, status_cb=status_cb)
                if ok_arp:
                    arp_ok = True
                    results.append(f"⏱️ ARP {duration}с")

        except PermissionError:
            return False, (
                "❌  Відмовлено в доступі.\n"
                "Запустіть NetGuardian як Адміністратор."
            ), "—"
        except Exception as e:
            return False, f"❌  ARP помилка: {e}", "—"

        # ── B) Router kick — відключаємо ВІД МЕРЕЖІ ЗАРАЗ ────────────
        def _do_router():
            nonlocal router_ok
            try:
                ok_kick, msg_kick = self._router_api_kick(target_ip, mac_up, gw)
                if ok_kick:
                    router_ok = True
                    results.append("Router kick")
                    if status_cb: status_cb(f"✅  Router API: пристрій відключено")
            except Exception:
                pass

            # ── C) Router MAC filter — забороняємо ПОВТОРНЕ підключення ─
            try:
                ok_filter, _ = self.router_mac_filter(
                    mac_up, target_ip, gw, block=True)
                if ok_filter:
                    results.append("MAC filter")
                    if status_cb: status_cb(f"🔒  MAC filter: повторне підключення заблоковано")
            except Exception:
                pass

        # Запускаємо router у фоні (не чекаємо — він може бути повільним)
        threading.Thread(target=_do_router, daemon=True).start()

        # ── Готуємо відповідь ─────────────────────────────────────────
        if arp_ok:
            dur_str = "назавжди" if duration == 0 else f"{duration}с"
            return True, (
                f"⚔️  {target_ip} ЗАБЛОКОВАНО ({dur_str})\n\n"
                f"✂️  Трафік перехоплюється (ARP)\n"
                f"📡  Router kick + MAC filter запущені у фоні\n\n"
                f"⚠️  Блокування активне поки NetGuardian запущений.\n"
                f"     Пристрій залишається в WiFi-мережі,\n"
                f"     але весь його трафік дропається."
            ), "ARP + Router"

        return False, (
            "❌  Блокування не вдалось.\n\n"
            "Причини:\n"
            "• Потрібні права Адміністратора\n"
            "• Scapy + Npcap не встановлені (npcap.com)\n"
            "• Запустіть NetGuardian: ПКМ → 'Як адміністратор'"
        ), "—"

    def _router_api_kick(self, target_ip: str, target_mac: str, gw: str) -> tuple:
        """
        Блокування через веб-інтерфейс роутера.
        TP-Link Archer C6/C64: Access Control blacklist (Advanced > Security > Access Control).
        """
        _router_cfg = router_manager.get_router_by_ip(gw)
        http_user = _router_cfg.get("http_user","admin") if _router_cfg else "admin"
        http_pwd  = _router_cfg.get("http_pwd","admin")  if _router_cfg else "admin"
        reader = RouterClientReader(gw, timeout=6.0, username=http_user, password=http_pwd)
        mac = target_mac.upper().replace("-",":")

        # ══════════════════════════════════════════════════════════════
        # TP-LINK ARCHER — Access Control через stok JSON API
        # (Archer C6, C64, A6, AX серія — всі використовують /cgi-bin/luci)
        # ══════════════════════════════════════════════════════════════
        stok = reader._tplink_login()
        if stok:
            # ── Крок 1: Вмикаємо Access Control в режимі Blacklist ──
            for ep in [
                f"/cgi-bin/luci/;stok={stok}/admin/access_control?form=config",
                f"/cgi-bin/luci/;stok={stok}/rc/v1/security/access_control",
            ]:
                for pl in [
                    {"method":"do",  "access_control":{"config":{"enable":1,"mode":0}}},
                    {"method":"set", "access_control":{"config":{"enable":1,"mode":0}}},
                ]:
                    try: reader._post_json(ep, pl)
                    except Exception: pass

            # ── Крок 2: Додаємо MAC до blacklist ────────────────────
            # Формат для Archer C6/C64/A6 V2+ (прошивки 2019+)
            blacklist_payloads = [
                # Archer C6/C64 — основний endpoint
                {"method":"do","access_control":{"black_list_add":[{
                    "mac":      mac,
                    "name":     target_ip,
                    "blocked":  1
                }]}},
                # Archer A6 V2 формат
                {"method":"do","access_control":{"add":{
                    "mac":  mac,
                    "name": target_ip or "blocked"
                }}},
                # Новіший API (AX серія)
                {"method":"add","access_control":{"black_list":[{
                    "mac":        mac,
                    "deviceName": target_ip or "blocked",
                    "type":       "block"
                }]}},
            ]
            endpoints = [
                f"/cgi-bin/luci/;stok={stok}/admin/access_control?form=black_list",
                f"/cgi-bin/luci/;stok={stok}/admin/security?form=access_control",
                f"/cgi-bin/luci/;stok={stok}/rc/v1/security/access_control",
                f"/cgi-bin/luci/;stok={stok}/rc/v1/access_control/black",
            ]
            for ep in endpoints:
                for pl in blacklist_payloads:
                    try:
                        resp = reader._post_json(ep, pl)
                        if resp:
                            s = str(resp)
                            if any(k in s for k in
                                   ('"error_code":0', '"success"',
                                    '"errorcode":0', 'success":true')):
                                return True, (
                                    f"✅  {mac} заблоковано через "
                                    f"Access Control Blacklist (TP-Link Archer)")
                    except Exception:
                        pass

            # ── Крок 3: WiFi kick (відключає зараз) ─────────────────
            # Навіть якщо Access Control спрацює після реконнекту —
            # kick відключає пристрій негайно
            kick_payloads = [
                {"method":"do","wireless":{"kick_sta":{"mac":mac}}},
                {"method":"do","wireless":{"kick":{"mac":mac}}},
                {"method":"do","wireless":{"disassociate_sta":{"mac":mac}}},
            ]
            kick_eps = [
                f"/cgi-bin/luci/;stok={stok}/admin/wireless?form=station",
                f"/cgi-bin/luci/;stok={stok}/rc/v1/wireless/kick",
                f"/cgi-bin/luci/;stok={stok}/admin/wireless?form=kick",
            ]
            for ep in kick_eps:
                for pl in kick_payloads:
                    try:
                        resp = reader._post_json(ep, pl)
                        if resp and '"error_code":0' in str(resp):
                            return True, f"✅  {mac} відключено (WiFi kick + Access Control)"
                    except Exception:
                        pass

        # ── Keenetic ──────────────────────────────────────────────────
        for pl in [
            {"ip":{"hotspot":{"host":[{"mac":mac,"blocked":True}]}}},
            {"ip":{"hotspot":{"host":[{"mac":mac,"disconnect":True}]}}},
        ]:
            try:
                resp = reader._fetch("/rci/", method="POST",
                    data=json.dumps({"set":pl}),
                    extra_headers={"Content-Type":"application/json"})
                if resp and "error" not in (resp or "").lower():
                    return True, f"✅  {mac} заблоковано (Keenetic)"
            except Exception:
                pass

        # ── ASUS ──────────────────────────────────────────────────────
        try:
            import base64 as _b64
            auth = _b64.b64encode(f"{http_user}:{http_pwd}".encode()).decode()
            resp = reader._fetch(f"/remove_sta.cgi?remove_mac={mac}",
                extra_headers={"Authorization":f"Basic {auth}"})
            if resp and len(resp) < 200:
                return True, f"✅  {mac} заблоковано (ASUS)"
        except Exception:
            pass

        return False, f"Router API: не вдалось заблокувати {mac}"

    def router_mac_filter(self, target_mac: str, target_ip: str = "",
                          gateway_ip: str = "", block: bool = True,
                          device_name: str = "") -> tuple:
        """
        Додає/видаляє MAC-адресу з чорного списку роутера.
        block=True → заблокувати (пристрій НЕ ЗМОЖЕ підключитись до WiFi).
        block=False → розблокувати.
        Підтримує: TP-Link Archer, Keenetic, ASUS, MikroTik.
        """
        gw = gateway_ip or self._detect_gateway()
        _router_cfg = router_manager.get_router_by_ip(gw)
        http_user = _router_cfg.get("http_user","admin") if _router_cfg else "admin"
        http_pwd  = _router_cfg.get("http_pwd","admin")  if _router_cfg else "admin"
        reader = RouterClientReader(gw, timeout=6.0,
                                    username=http_user, password=http_pwd)
        mac = target_mac.upper().replace("-",":")
        action = "BLOCK" if block else "UNBLOCK"

        # ── TP-Link Archer (MAC filter / Access Control) ─────────────
        try:
            stok = reader._tplink_login()
            if stok:
                # Метод 1: hosts_info blocked (новіші Archer AX)
                payload_block = {
                    "method": "do",
                    "hosts_info": {
                        "table": "blocked_host",
                        "para": {"mac": mac, "type": "1" if block else "0"}
                    }
                }
                # Метод 2: access_control black_list
                payload_acl = {
                    "method": "do" if block else "delete",
                    "access_control": {
                        "black_list" if block else "remove_black": [
                            {"mac": mac, "deviceName": device_name or "Device"}
                        ]
                    }
                }
                # Метод 3: wireless blacklist_add / blacklist_del
                payload_wl = {
                    "method": "do",
                    "wireless": {
                        ("blacklist_add" if block else "blacklist_del"): {"mac": mac}
                    }
                }
                for payload in [payload_block, payload_acl, payload_wl]:
                    for ep in [
                        f"/cgi-bin/luci/;stok={stok}/rc/v1/hosts/block",
                        f"/cgi-bin/luci/;stok={stok}/admin/access_control?form=black_list",
                        f"/cgi-bin/luci/;stok={stok}/admin/wireless?form=blacklist",
                        f"/cgi-bin/luci/;stok={stok}/rc/v1/hosts",
                    ]:
                        try:
                            resp = reader._post_json(ep, payload)
                            if resp and any(k in str(resp).lower() for k in
                                           ('"error_code":0', '"success"', 'ok', 'errorcode":0')):
                                verb = "заблоковано" if block else "розблоковано"
                                return True, f"✅  {mac} {verb} (TP-Link MAC filter)"
                        except Exception:
                            pass
        except Exception:
            pass

        # ── Keenetic (hotspot blocked=true/false) ────────────────────
        try:
            payload_ke = {
                "ip": {"hotspot": {"host": [{"mac": mac, "blocked": block}]}}
            }
            resp = reader._fetch("/rci/", method="POST",
                data=json.dumps({"set": payload_ke}),
                extra_headers={"Content-Type": "application/json"})
            if resp and "error" not in (resp or "").lower():
                verb = "заблоковано" if block else "розблоковано"
                return True, f"✅  {mac} {verb} (Keenetic MAC filter)"
        except Exception:
            pass

        # ── ASUS (networkmap + block_maclist) ────────────────────────
        try:
            import base64 as _b64
            auth = _b64.b64encode(f"{http_user}:{http_pwd}".encode()).decode()
            if block:
                data = f"action_mode=apply&blocking=1&mac={mac}"
            else:
                data = f"action_mode=apply&blocking=0&mac={mac}"
            resp = reader._fetch("/apply.cgi",
                method="POST", data=data,
                extra_headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/x-www-form-urlencoded"
                })
            if resp:
                verb = "заблоковано" if block else "розблоковано"
                return True, f"✅  {mac} {verb} (ASUS MAC filter)"
        except Exception:
            pass

        # ── MikroTik (address-list) ──────────────────────────────────
        try:
            import base64 as _b64
            cred = _b64.b64encode(f"{http_user}:{http_pwd}".encode()).decode()
            if block:
                resp = reader._fetch(
                    "/rest/ip/firewall/address-list",
                    method="PUT",
                    data=json.dumps({"list": "blacklist", "address": target_ip or mac}),
                    extra_headers={
                        "Authorization": f"Basic {cred}",
                        "Content-Type": "application/json"
                    })
            else:
                # Знаходимо запис і видаляємо
                items = reader._fetch_json(
                    "/rest/ip/firewall/address-list",
                    extra_headers={"Authorization": f"Basic {cred}"})
                if items and isinstance(items, list):
                    for item in items:
                        if item.get("address") in (target_ip, mac):
                            reader._fetch(
                                f"/rest/ip/firewall/address-list/{item['.id']}",
                                method="DELETE",
                                extra_headers={"Authorization": f"Basic {cred}"})
            verb = "заблоковано" if block else "розблоковано"
            return True, f"✅  {mac} {verb} (MikroTik firewall)"
        except Exception:
            pass

        return False, (
            "❌  Роутер не підтримує MAC-фільтр через API.\n\n"
            "Підтримувані роутери: TP-Link Archer, Keenetic, ASUS, MikroTik.\n"
            "Перевірте логін/пароль у налаштуваннях NetGuardian.\n\n"
            "Альтернатива: ARP-спуфінг (блокує трафік поки програма запущена)."
        )

    def speed_limit_device(self, target_ip: str, target_mac: str,
                           gateway_ip: str = "",
                           upload_kbps: int = 0,
                           download_kbps: int = 0) -> tuple:
        """
        FIX-1: Обмеження швидкості для пристрою через Router API.
        upload_kbps=0 / download_kbps=0 = без обмежень (скасувати).
        Підтримує: TP-Link Archer, Keenetic, ASUS, MikroTik.
        Повертає (ok, message).
        """
        gw = gateway_ip or self._detect_gateway()
        _router_cfg = router_manager.get_router_by_ip(gw)
        http_user = _router_cfg.get("http_user","admin") if _router_cfg else "admin"
        http_pwd  = _router_cfg.get("http_pwd","admin")  if _router_cfg else "admin"
        reader = RouterClientReader(gw, timeout=5.0, username=http_user, password=http_pwd)
        mac_colon = target_mac.upper().replace("-",":")

        up_mbps   = round(upload_kbps / 1024, 2) if upload_kbps else 0
        down_mbps = round(download_kbps / 1024, 2) if download_kbps else 0
        up_str    = f"{upload_kbps} Кбіт/с" if upload_kbps else "без обмежень"
        down_str  = f"{download_kbps} Кбіт/с" if download_kbps else "без обмежень"

        # ── TP-Link Archer QoS ───────────────────────────────────────
        try:
            stok = reader._tplink_login()
            if stok:
                # QoS bandwidth rule
                payload = {
                    "method": "do",
                    "qos": {
                        "set_bandwidth": {
                            "mac": mac_colon,
                            "up_speed":   upload_kbps,
                            "down_speed": download_kbps,
                            "enable": 1 if (upload_kbps or download_kbps) else 0,
                        }
                    }
                }
                for ep in [
                    f"/cgi-bin/luci/;stok={stok}/admin/qos?form=rule_list",
                    f"/cgi-bin/luci/;stok={stok}/rc/v1/qos/bandwidth",
                ]:
                    try:
                        resp = reader._post_json(ep, str(payload).replace("'",'"'))
                        if resp and ('"error_code":0' in str(resp) or "success" in str(resp).lower()):
                            return True, (
                                f"✅  Обмеження встановлено (TP-Link QoS)\n"
                                f"↑ Upload: {up_str}\n↓ Download: {down_str}")
                    except Exception:
                        pass
        except Exception:
            pass

        # ── Keenetic — bandwidth policy ──────────────────────────────
        try:
            policy = {}
            if upload_kbps:   policy["up"] = upload_kbps * 1000
            if download_kbps: policy["down"] = download_kbps * 1000
            payload = {"ip": {"hotspot": {"host": [{"mac": mac_colon, "policy": policy}]}}}
            resp = reader._fetch("/rci/", method="POST",
                data={"set": payload},
                extra_headers={"Content-Type": "application/json"})
            if resp and "error" not in (resp or "").lower():
                return True, (
                    f"✅  Обмеження встановлено (Keenetic)\n"
                    f"↑ Upload: {up_str}\n↓ Download: {down_str}")
        except Exception:
            pass

        # ── ASUS — bandwidth limiter ─────────────────────────────────
        try:
            import base64
            auth = base64.b64encode(f"{http_user}:{http_pwd}".encode()).decode()
            data = (f"action_mode=apply&bw_enabled=1"
                    f"&bw_rulelist={mac_colon}>{download_kbps}>{upload_kbps}>1>1")
            resp = reader._fetch("/apply.cgi",
                method="POST", data=data,
                extra_headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/x-www-form-urlencoded"
                })
            if resp:
                return True, (
                    f"✅  Обмеження встановлено (ASUS)\n"
                    f"↑ Upload: {up_str}\n↓ Download: {down_str}")
        except Exception:
            pass

        return False, (
            "❌  Обмеження швидкості через API недоступне.\n\n"
            "Підтримувані роутери: TP-Link Archer, Keenetic, ASUS.\n"
            "Переконайтесь що логін/пароль роутера правильний\n"
            "у налаштуваннях NetGuardian."
        )

    def _ssh_kick(self, target_ip: str, target_mac: str, gw: str) -> tuple:
        """Відключення через SSH до роутера."""
        ssh = RouterSSHScanner(gw, timeout=4.0)
        if not ssh.is_available():
            return False, "SSH недоступний"
        saved = RouterSSHScanner.ssh_config.get(gw, {})
        if not saved:
            return False, "SSH credentials не збережені"

        import paramiko
        client = ssh._connect(
            saved.get("user","admin"), saved.get("pwd",""),
            saved.get("port",22), saved.get("key_path",""))
        if not client:
            return False, "SSH підключення не вдалось"

        mac_colon = target_mac.upper()
        mac_lower = target_mac.lower()
        commands = [
            # MikroTik
            f"/interface wireless deauth mac-address={mac_colon}",
            f"/ip dhcp-server lease remove [find mac-address={mac_colon}]",
            # OpenWrt / LEDE
            f"hostapd_cli deauthenticate {mac_lower}",
            f"iwpriv ra0 set DisConnectSta={mac_colon}",
            # dnsmasq: видалення DHCP lease
            f"sed -i '/{mac_lower}/d' /var/lib/misc/dnsmasq.leases 2>/dev/null; "
            f"kill -HUP $(cat /var/run/dnsmasq.pid 2>/dev/null) 2>/dev/null",
        ]
        success = False
        for cmd in commands:
            try:
                out = ssh._exec(client, cmd)
                if out is not None:
                    success = True
            except Exception:
                pass
        client.close()

        if success:
            return True, f"✅  {target_ip} відключено (SSH)"
        return False, "SSH kick команди не дали результату"

    def _deauth_device(self, target_ip: str, target_mac: str, gw: str,
                       duration: int = 10, status_cb=None) -> tuple:
        """
        802.11 Deauthentication frames через Scapy.
        УВАГА: потребує WiFi-адаптер у режимі монітору!
        Якщо монітор-режиму немає — повернемо False.
        """
        ok, _ = self._check_scapy()
        if not ok:
            return False, "Scapy недоступний"
        try:
            from scapy.all import (RadioTap, Dot11, Dot11Deauth,
                                   sendp, conf, get_if_list)
            conf.verb = 0

            # Шукаємо WiFi інтерфейс у режимі монітору
            monitor_iface = None
            try:
                import subprocess
                result = subprocess.run(
                    ["iwconfig"], capture_output=True, text=True, timeout=3)
                for line in result.stdout.splitlines():
                    if "Monitor" in line:
                        iface = line.split()[0]
                        monitor_iface = iface
                        break
            except Exception:
                pass

            if not monitor_iface:
                return False, "Немає WiFi-інтерфейсу в режимі монітора"

            # Пакет деавторизації від імені AP (gateway) до клієнта
            # та від клієнта до AP (двостороннє відключення)
            gw_mac = self._get_arp_table().get(gw, "ff:ff:ff:ff:ff:ff")
            pkt_to_client = (
                RadioTap() /
                Dot11(addr1=target_mac, addr2=gw_mac, addr3=gw_mac) /
                Dot11Deauth(reason=7)   # reason 7 = Class 3 frame received from nonassociated STA
            )
            pkt_to_ap = (
                RadioTap() /
                Dot11(addr1=gw_mac, addr2=target_mac, addr3=gw_mac) /
                Dot11Deauth(reason=7)
            )

            def _send_loop():
                deadline = time.time() + duration
                while time.time() < deadline:
                    sendp([pkt_to_client, pkt_to_ap],
                          iface=monitor_iface, count=5, inter=0.1, verbose=False)
                    if status_cb:
                        rem = int(deadline - time.time())
                        status_cb(f"📡  Deauth {target_ip}… {rem}с")
                    time.sleep(0.5)
                if status_cb:
                    status_cb(f"✅  Deauth {target_ip} завершено")

            threading.Thread(target=_send_loop, daemon=True).start()
            return True, (
                f"📡  {target_ip} відключається (802.11 Deauth)\n"
                f"Тривалість: {duration}с"
            )
        except ImportError:
            return False, "Scapy не має Dot11 (потрібен повний пакет)"
        except Exception as e:
            return False, f"Deauth помилка: {e}"

    def block_device(self, target_ip: str, gateway_ip: str,
                     duration: int = 30,
                     status_cb=None, target_mac: str = "") -> tuple:
        """
        ARP-спуфінг блокування (метод NetCut/bettercap).

        Алгоритм:
          1. Вимикаємо IP-forwarding на нашому ПК (щоб дропати пакети)
          2. Цілі надсилаємо: "MAC шлюзу = наш MAC"
          3. Шлюзу надсилаємо: "MAC цілі = наш MAC"
          → Весь трафік цілі йде до нас і дропається
          4. По закінченню — відновлюємо ARP і forwarding
        """
        # ── Admin check ───────────────────────────────────────────
        if platform.system() == "Windows":
            try:
                import ctypes as _ct
                if not _ct.windll.shell32.IsUserAnAdmin():
                    return False, (
                        "❌  Потрібні права Адміністратора!\n"
                        "ПКМ → 'Запустити як адміністратор'"
                    )
            except Exception:
                pass

        # ── Scapy check ───────────────────────────────────────────
        scapy_ok, scapy_msg = self._check_scapy()
        if not scapy_ok:
            return False, (
                f"❌  Scapy/Npcap недоступний: {scapy_msg}\n\n"
                "Встановіть: npcap.com  +  pip install scapy\n"
                "Потім перезапустіть як Адміністратор"
            )

        try:
            from scapy.all import ARP, Ether, srp, sendp, get_if_hwaddr, conf
            conf.verb = 0

            # ── Отримуємо наш MAC ─────────────────────────────────
            try:
                our_mac = get_if_hwaddr(conf.iface)
            except Exception:
                import uuid
                raw = hex(uuid.getnode())[2:].zfill(12)
                our_mac = ":".join(raw[i:i+2] for i in range(0,12,2)).upper()

            # ── MAC цілі ──────────────────────────────────────────
            victim_mac = (target_mac.strip().upper().replace("-",":") or "")
            if not victim_mac or victim_mac == "—":
                arp_table = self._get_arp_table()
                victim_mac = arp_table.get(target_ip, "")
            if not victim_mac:
                try:
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
                        timeout=2, verbose=False, iface=conf.iface)
                    if ans: victim_mac = ans[0][1].hwsrc.upper()
                except Exception: pass
            if not victim_mac:
                return False, f"❌  Не знайдено MAC для {target_ip}"

            # ── MAC шлюзу ─────────────────────────────────────────
            gw_mac = self._get_arp_table().get(gateway_ip, "")
            if not gw_mac:
                try:
                    ans, _ = srp(
                        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=gateway_ip),
                        timeout=2, verbose=False, iface=conf.iface)
                    if ans: gw_mac = ans[0][1].hwsrc.upper()
                except Exception: pass
            if not gw_mac:
                return False, f"❌  Не знайдено MAC шлюзу {gateway_ip}"

            # ── Вимикаємо IP forwarding (ключовий крок!) ──────────
            permanent_ban_manager._ensure_forward_disabled()

            # ── Правильні ARP пакети (логіка NetCut) ─────────────
            # Жертві: "MAC шлюзу = МІЙ MAC" → жертва шле нам
            pkt_victim = (
                Ether(src=our_mac, dst=victim_mac) /
                ARP(op=2,
                    hwsrc=our_mac,   psrc=gateway_ip,
                    hwdst=victim_mac, pdst=target_ip)
            )
            # Шлюзу: "MAC жертви = МІЙ MAC" → шлюз шле нам
            pkt_gateway = (
                Ether(src=our_mac, dst=gw_mac) /
                ARP(op=2,
                    hwsrc=our_mac,  psrc=target_ip,
                    hwdst=gw_mac,   pdst=gateway_ip)
            )

            def _restore():
                """Відновлюємо правильні ARP після закінчення."""
                try:
                    sendp([
                        # Жертві: справжній MAC шлюзу
                        Ether(src=gw_mac, dst=victim_mac) /
                        ARP(op=2,
                            hwsrc=gw_mac,    psrc=gateway_ip,
                            hwdst=victim_mac, pdst=target_ip),
                        # Шлюзу: справжній MAC жертви
                        Ether(src=victim_mac, dst=gw_mac) /
                        ARP(op=2,
                            hwsrc=victim_mac, psrc=target_ip,
                            hwdst=gw_mac,     pdst=gateway_ip),
                    ], count=8, inter=0.05, verbose=False)
                except Exception:
                    pass
                # Якщо більше немає активних банів — відновлюємо forwarding
                if permanent_ban_manager.active_count == 0:
                    permanent_ban_manager._maybe_restore_forward()

            def _loop():
                deadline = time.time() + duration
                tick = 0
                while time.time() < deadline:
                    try:
                        sendp([pkt_victim, pkt_gateway],
                              count=7, inter=0.01, verbose=False)
                    except Exception:
                        break
                    tick += 1
                    if status_cb and tick % 6 == 0:
                        rem = int(deadline - time.time())
                        status_cb(f"✂️  Блокую {target_ip}… {rem}с")
                    time.sleep(0.5)
                _restore()
                if status_cb:
                    status_cb(f"✅  {target_ip} — доступ відновлено")

            threading.Thread(target=_loop, daemon=True,
                             name=f"Block-{target_ip}").start()

            dur_m = duration // 60
            dur_s = duration % 60
            dur_str = f"{dur_m}хв {dur_s}с" if dur_m else f"{dur_s}с"
            return True, (
                f"✂️  {target_ip} заблоковано на {dur_str}\n"
                f"Наш MAC: {our_mac}\n"
                f"MAC жертви: {victim_mac}\n"
                f"MAC шлюзу: {gw_mac}"
            )

        except PermissionError:
            return False, (
                "❌  PermissionError — потрібен Адміністратор + Npcap"
            )
        except Exception as e:
            return False, f"❌  Помилка: {e}"

    # ── BAN API ───────────────────────────────────────────────────

    def _trust_db_ban_only(self, mac: str, ip: str, vendor: str,
                           label: str, reason: str, duration: float):
        """Записує бан у БД без запуску ARP."""
        trust_db.ban_device(mac, ip, vendor, label, reason, duration)
        trust_db.log_event("ban", mac, ip,
            f"Banned: {label or vendor or mac}  reason={reason or '—'}")

    def ban_device(self, mac: str, ip: str = "", vendor: str = "",
                   label: str = "", reason: str = "", duration: float = 0.0):
        """
        Назавжди або тимчасово банить пристрій.
        duration=0 → назавжди:
          1) Додає до MAC-фільтру роутера (пристрій не зможе підключитись)
          2) Запускає вічне ARP-отруєння як додатковий захист
        duration>0 → тимчасовий ARP spoof
        """
        trust_db.ban_device(mac, ip, vendor, label, reason, duration)
        trust_db.log_event("ban", mac, ip,
            f"Banned: {label or vendor or mac}  reason={reason or '—'}")

        if duration == 0.0:
            # ── Крок 1: MAC filter на роутері (найнадійніший) ────────
            gw = self._detect_gateway()
            threading.Thread(
                target=lambda: self.router_mac_filter(
                    mac, ip, gw, block=True, device_name=label or ip),
                daemon=True).start()

            # ── Крок 2: вічний ARP-спуфінг як резерв ─────────────────
            if ip:
                arp_cache = self._get_arp_table()
                gw_mac = arp_cache.get(gw, "")
                if gw_mac:
                    permanent_ban_manager.start_ban(ip, mac, gw, gw_mac)

    def unban_device(self, mac: str, ip: str = ""):
        """Знімає бан, зупиняє ARP-отруєння і видаляє з MAC-фільтру роутера."""
        permanent_ban_manager.stop_ban(mac)
        trust_db.unban_device(mac)
        trust_db.log_event("unban", mac, "", f"Unbanned: {mac}")
        # Видаляємо з MAC-фільтру роутера у фоні
        if ip:
            gw = self._detect_gateway()
            threading.Thread(
                target=lambda: self.router_mac_filter(mac, ip, gw, block=False),
                daemon=True).start()

    def is_banned(self, mac: str) -> bool:
        return trust_db.is_banned(mac)

    def get_banned(self) -> list:
        return trust_db.get_banned()

    @staticmethod
    def configure_ssh(gateway, user, pwd, port=22, key_path=""):
        RouterSSHScanner.ssh_config[gateway] = {
            "user": user, "pwd": pwd, "port": port, "key_path": key_path
        }

    @staticmethod
    def get_ssh_config(gateway) -> dict:
        return RouterSSHScanner.ssh_config.get(gateway, {})

    @staticmethod
    def clear_ssh_config(gateway=""):
        if gateway:
            RouterSSHScanner.ssh_config.pop(gateway, None)
        else:
            RouterSSHScanner.ssh_config.clear()

    @staticmethod
    def configure_router(name, ip, http_user="admin", http_pwd="admin",
                         ssh_user="", ssh_pwd="", ssh_port=22, ssh_key="",
                         label="", notes="") -> dict:
        return router_manager.add_router(
            name=name, ip=ip, http_user=http_user, http_pwd=http_pwd,
            ssh_user=ssh_user, ssh_pwd=ssh_pwd, ssh_port=ssh_port,
            ssh_key=ssh_key, label=label, notes=notes
        )

    @staticmethod
    def remove_router(name) -> bool:
        return router_manager.remove_router(name)

    @staticmethod
    def list_configured_routers() -> list:
        return router_manager.list_routers()

    @staticmethod
    def get_router_manager() -> RouterManager:
        return router_manager