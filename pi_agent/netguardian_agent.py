#!/usr/bin/env python3
"""NetGuardian Pi Agent — фоновий збирач мережевих даних + локальний AI."""
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import threading
import time
from datetime import datetime
from pathlib import Path

# ─── PR #4: Локальний AI на Pi (KB + збирач помилок) ──────────────────────────
# Працює як 3-й fallback для hybrid_ai на ПК (Gemini → KB-ПК → Pi-AI)
try:
    from pi_kb import search_kb, get_by_symptoms, entry_to_dict, KB
    from pi_error_collector import (
        ErrorCollector,
        analyze_situation,
        get_errors_since,
        count_errors_by_type,
    )
    HAS_LOCAL_AI = True
    print("[AI] ✅ Локальний AI завантажено (pi_kb + pi_error_collector)")
except ImportError as e:
    HAS_LOCAL_AI = False
    print(f"[AI] ⚠️ Локальний AI вимкнено: {e}")
    ErrorCollector = None
    KB = []
    def search_kb(*a, **kw): return []
    def get_by_symptoms(*a, **kw): return []
    def entry_to_dict(e): return {}
    def analyze_situation(*a, **kw):
        return {"source": "raspberry_pi", "summary": "AI not available", "errors_count": 0}
    def get_errors_since(*a, **kw): return []
    def count_errors_by_type(*a, **kw): return {}

HOME = Path.home() / ".netguardian-agent"
HOME.mkdir(parents=True, exist_ok=True)
DB_PATH = HOME / "ping_log.db"
PING_HOSTS         = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
PING_INTERVAL_SEC  = 60
SPEEDTEST_INTERVAL = 3600
LAN_SCAN_INTERVAL  = 300
WEB_PORT           = 8080
MQTT_BROKER  = "broker.hivemq.com"
MQTT_PORT    = 1883
MQTT_TOPIC_PREFIX = os.environ.get(
    "NETGUARDIAN_MQTT_PREFIX", "netguardian/dim4ik2003")
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS ping_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL, host TEXT NOT NULL,
                ping_ms REAL, loss_pct REAL
            );
            CREATE INDEX IF NOT EXISTS idx_ping_ts ON ping_log(ts);
            CREATE TABLE IF NOT EXISTS speedtest_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                dl_mbps REAL, ul_mbps REAL,
                ping_ms REAL, server TEXT
            );
            CREATE TABLE IF NOT EXISTS lan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT NOT NULL, mac TEXT,
                hostname TEXT, vendor TEXT,
                online INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_lan_ts ON lan_log(ts);
            CREATE INDEX IF NOT EXISTS idx_lan_mac ON lan_log(mac);
        """)
    print(f"[Agent] DB готова: {DB_PATH}")
def icmp_ping(host: str, count: int = 4):
    try:
        r = subprocess.run(
            ["ping", "-c", str(count), "-W", "2", host],
            capture_output=True, text=True, timeout=count * 3 + 2)
        out = r.stdout
        m = re.search(r"min/avg/max[^=]*=\s*[\d.]+/([\d.]+)/", out)
        avg = float(m.group(1)) if m else 0.0
        m2 = re.search(r"(\d+)%\s*packet\s*loss", out)
        loss = float(m2.group(1)) if m2 else 100.0
        return avg, loss
    except Exception as e:
        print(f"[ping] error {host}: {e}")
        return 0.0, 100.0
def ping_collector(mqtt_pub):
    print(f"[ping] Старт колектора (інтервал {PING_INTERVAL_SEC}с)")
    while True:
        try:
            for host in PING_HOSTS:
                avg, loss = icmp_ping(host)
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    with sqlite3.connect(DB_PATH, timeout=5) as conn:
                        conn.execute(
                            "INSERT INTO ping_log (ts, host, ping_ms, loss_pct) "
                            "VALUES (?, ?, ?, ?)",
                            (ts, host, avg, loss))
                except Exception as e:
                    print(f"[ping] DB error: {e}")
                mqtt_pub("ping", {"ts": ts, "host": host, "ms": avg, "loss": loss})
                print(f"[ping] {host}: {avg:.1f}ms loss={loss}%")
        except Exception as e:
            print(f"[ping] loop error: {e}")
        time.sleep(PING_INTERVAL_SEC)
def run_speedtest():
    try:
        r = subprocess.run(
            ["speedtest-cli", "--json", "--secure"],
            capture_output=True, text=True, timeout=120)
        if r.returncode != 0:
            return None
        data = json.loads(r.stdout)
        return {
            "dl_mbps": round(data["download"] / 1_000_000, 2),
            "ul_mbps": round(data["upload"] / 1_000_000, 2),
            "ping_ms": round(data["ping"], 2),
            "server":  data.get("server", {}).get("sponsor", "?"),
        }
    except Exception as e:
        print(f"[speedtest] error: {e}")
        return None
def speedtest_collector(mqtt_pub):
    print("[speedtest] Старт")
    time.sleep(120)
    while True:
        try:
            print("[speedtest] Запускаю...")
            result = run_speedtest()
            if result:
                ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                try:
                    with sqlite3.connect(DB_PATH, timeout=5) as conn:
                        conn.execute(
                            "INSERT INTO speedtest_log "
                            "(ts, dl_mbps, ul_mbps, ping_ms, server) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (ts, result["dl_mbps"], result["ul_mbps"],
                             result["ping_ms"], result["server"]))
                except Exception as e:
                    print(f"[speedtest] DB error: {e}")
                mqtt_pub("speedtest", {"ts": ts, **result})
                print(f"[speedtest] DL={result['dl_mbps']} UL={result['ul_mbps']}")
        except Exception as e:
            print(f"[speedtest] loop: {e}")
        time.sleep(SPEEDTEST_INTERVAL)
def get_local_subnet():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        parts = ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    except Exception:
        return "192.168.0.0/24"
def lan_scan_scapy():
    devices = []
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        subnet = get_local_subnet()
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=3, verbose=0)
        for sent, recv in ans:
            ip = recv.psrc
            mac = recv.hwsrc.lower()
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            devices.append({"ip": ip, "mac": mac,
                           "hostname": hostname, "vendor": ""})
    except PermissionError:
        return lan_scan_proc()
    except Exception as e:
        print(f"[lan] scapy error: {e}")
        return lan_scan_proc()
    return devices
def lan_scan_proc():
    devices = []
    try:
        with open("/proc/net/arp") as f:
            for line in f.readlines()[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    devices.append({"ip": parts[0], "mac": parts[3].lower(),
                                   "hostname": "", "vendor": ""})
    except Exception as e:
        print(f"[lan] /proc/net/arp error: {e}")
    return devices
def lan_scanner(mqtt_pub):
    print(f"[lan] Старт сканера (інтервал {LAN_SCAN_INTERVAL}с)")
    while True:
        try:
            devices = lan_scan_scapy()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                with sqlite3.connect(DB_PATH, timeout=5) as conn:
                    for d in devices:
                        conn.execute(
                            "INSERT INTO lan_log "
                            "(ts, ip, mac, hostname, vendor, online) "
                            "VALUES (?, ?, ?, ?, ?, 1)",
                            (ts, d["ip"], d["mac"],
                             d.get("hostname", ""), d.get("vendor", "")))
            except Exception as e:
                print(f"[lan] DB error: {e}")
            mqtt_pub("lan", {"ts": ts, "count": len(devices), "devices": devices})
            print(f"[lan] Знайдено {len(devices)} пристроїв")
        except Exception as e:
            print(f"[lan] loop: {e}")
        time.sleep(LAN_SCAN_INTERVAL)
class MqttPublisher:
    def __init__(self):
        self.client = None
        self.connected = False
        try:
            import paho.mqtt.client as mqtt
            cid = f"ng-pi-{socket.gethostname()}-{int(time.time())}"
            try:
                self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cid)
            except AttributeError:
                self.client = mqtt.Client(client_id=cid)
            self.client.on_connect = self._on_connect
            self.client.on_disconnect = self._on_disconnect
            # ─── PR #4: AI команди від ПК ─────────────────────────────────
            self.client.on_message = self._on_message
            self.client.connect_async(MQTT_BROKER, MQTT_PORT, keepalive=60)
            self.client.loop_start()
        except ImportError:
            print("[mqtt] ❌ paho-mqtt не встановлено!")
        except Exception as e:
            print(f"[mqtt] init: {e}")
    def _on_connect(self, client, userdata, flags, rc, properties=None):
        self.connected = (rc == 0)
        if rc == 0:
            print(f"[mqtt] ✅ З'єднано: {MQTT_BROKER} prefix={MQTT_TOPIC_PREFIX}")
            # ─── PR #4: Підписуємось на команди від ПК ───────────────────
            try:
                cmd_topic = f"{MQTT_TOPIC_PREFIX}/cmd/+"
                client.subscribe(cmd_topic, qos=1)
                print(f"[mqtt] 📥 Subscribed: {cmd_topic}")
            except Exception as e:
                print(f"[mqtt] subscribe error: {e}")
        else:
            print(f"[mqtt] ❌ rc={rc}")
    def _on_disconnect(self, client, userdata, *args, **kwargs):
        self.connected = False
        rc = args[0] if args else "?"
        print(f"[mqtt] ⚠️ Disconnect rc={rc} — спроба reconnect...")

        # PR #10: автоматичний reconnect у фоні
        # paho-mqtt loop_start() сам спробує перепідключитись, але якщо
        # broker довго недоступний — даємо явну допомогу
        def reconnect_loop():
            attempt = 0
            while not self.connected:
                attempt += 1
                try:
                    time.sleep(min(60, 5 * attempt))  # backoff: 5,10,15...60
                    print(f"[mqtt] 🔄 reconnect attempt #{attempt}")
                    self.client.reconnect()
                    print(f"[mqtt] ✅ reconnect успіх")
                    break
                except Exception as e:
                    print(f"[mqtt] reconnect #{attempt} failed: {e}")
                    if attempt > 50:
                        print("[mqtt] забагато спроб, перезапусти service")
                        break

        threading.Thread(target=reconnect_loop, daemon=True,
                          name="MqttReconnect").start()

    # ─── PR #4: ОБРОБКА КОМАНД ВІД ПК (локальний AI на Pi) ────────────────
    def _on_message(self, client, userdata, msg):
        """Реагує на команди cmd/* від ПК.

        Підтримує:
          • cmd/analyze     — Pi запускає KB-аналіз і повертає висновок
          • cmd/get_errors  — Pi надсилає список зафіксованих помилок
          • cmd/daily_report — Pi формує добовий звіт зараз
          • cmd/send_history — Pi надсилає історію пінгів (для синхронізації)
          • cmd/ping        — простий heartbeat від клієнта (тільки оновлює seen)
        """
        # PR #7: маркуємо що клієнт-ПК на зв'язку
        self._mark_client_seen()

        try:
            cmd = msg.topic.rsplit("/", 1)[-1]
            try:
                payload = json.loads(msg.payload.decode() or "{}")
            except Exception:
                payload = {}
            print(f"[cmd] 📨 {cmd} payload={payload}")

            if cmd == "analyze":
                # ГОЛОВНА AI-КОМАНДА: Pi аналізує помилки і повертає діагноз
                seconds = int(payload.get("period_sec", 3600))
                req_id  = payload.get("req_id", "")
                if HAS_LOCAL_AI:
                    analysis = analyze_situation(seconds)
                    analysis["req_id"]   = req_id
                    analysis["hostname"] = socket.gethostname()
                    self.publish("ai_analysis", analysis)
                    print(f"[cmd] ✅ AI: {analysis.get('errors_count', 0)} помилок, "
                          f"{len(analysis.get('kb_matches', []))} KB-збігів")
                else:
                    self.publish("ai_analysis", {
                        "req_id": req_id,
                        "source": "raspberry_pi",
                        "error":  "Local AI not available",
                    })

            elif cmd == "get_errors":
                seconds = int(payload.get("period_sec", 3600))
                req_id  = payload.get("req_id", "")
                errors  = get_errors_since(seconds, limit=200)
                counts  = count_errors_by_type(seconds)
                self.publish("errors_report", {
                    "req_id": req_id,
                    "period": seconds,
                    "errors": errors,
                    "counts": counts,
                    "total":  len(errors),
                })
                print(f"[cmd] ✅ Errors report: {len(errors)} записів")

            elif cmd == "daily_report":
                # Простий добовий звіт з ping_log
                report = self._build_daily_report()
                self.publish("daily_summary", report)
                print(f"[cmd] ✅ Daily report sent")

            elif cmd == "send_history":
                # Шматки історії пінгу для синхронізації з ПК
                self._send_history_chunks()

            elif cmd == "ping":
                # Простий health-check
                self.publish("pong", {"hostname": socket.gethostname(),
                                       "ts": datetime.now().isoformat()})

            else:
                print(f"[cmd] ⚠️ Unknown command: {cmd}")
        except Exception as e:
            print(f"[cmd] error: {e}")

    def _build_daily_report(self) -> dict:
        """Будує добовий звіт із ping_log (твоя існуюча таблиця)."""
        report = {
            "type": "daily",
            "date": datetime.now().strftime("%Y-%m-%d"),
            "generated": datetime.now().isoformat(),
        }
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT AVG(ping_ms), MIN(ping_ms), MAX(ping_ms),
                           AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE date(ts) = date('now', 'localtime')
                      AND ping_ms > 0
                """)
                row = c.fetchone()
                if row and row[0]:
                    report.update({
                        "avg_ping": round(row[0], 1),
                        "min_ping": round(row[1], 1),
                        "max_ping": round(row[2], 1),
                        "avg_loss": round(row[3] or 0, 2),
                        "samples":  row[4],
                    })
        except Exception as e:
            print(f"[daily] error: {e}")
        return report

    def _send_history_chunks(self):
        """Надсилає всю історію пінгу за 7 днів шматками по 100 записів."""
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                c = conn.cursor()
                c.execute("""
                    SELECT ts, host, ping_ms, loss_pct FROM ping_log
                    WHERE ts >= datetime('now', '-7 days', 'localtime')
                      AND ping_ms > 0
                    ORDER BY ts ASC
                """)
                rows = c.fetchall()
        except Exception as e:
            print(f"[history] error: {e}")
            return

        if not rows:
            return

        CHUNK = 100
        total_chunks = (len(rows) + CHUNK - 1) // CHUNK
        print(f"[history] sending {len(rows)} rows / {total_chunks} chunks")

        for i in range(0, len(rows), CHUNK):
            idx = i // CHUNK
            chunk = rows[i:i + CHUNK]
            payload = {
                "type":         "history_chunk",
                "chunk_idx":    idx,
                "total_chunks": total_chunks,
                "data": [
                    {"ts": r[0], "host": r[1],
                     "ping_ms": r[2], "loss_pct": r[3]}
                    for r in chunk
                ],
            }
            self.publish("history", payload)
            time.sleep(0.3)

    def publish(self, suffix, payload):
        if not self.client:
            return
        try:
            topic = f"{MQTT_TOPIC_PREFIX}/{suffix}"
            self.client.publish(topic, json.dumps(payload, ensure_ascii=False), qos=0)
        except Exception as e:
            print(f"[mqtt] publish: {e}")

    def _mark_client_seen(self):
        """PR #7: фіксує час останнього звернення клієнта (ПК).

        Скрипт pi_client_monitor.py читає цей файл і шле alert у Telegram,
        якщо клієнт не з'являвся > 30 хв.
        """
        try:
            seen_file = Path.home() / ".netguardian-agent" / "client_seen.txt"
            seen_file.parent.mkdir(parents=True, exist_ok=True)
            with open(seen_file, "w") as f:
                f.write(str(int(time.time())))
        except Exception as e:
            print(f"[client_seen] write error: {e}")

def heartbeat(mqtt_pub):
    start = time.time()
    while True:
        try:
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            uptime = int(time.time() - start)
            cpu_temp = 0
            try:
                with open("/sys/class/thermal/thermal_zone0/temp") as f:
                    cpu_temp = round(int(f.read().strip()) / 1000, 1)
            except Exception:
                pass
            mqtt_pub("heartbeat", {"ts": ts, "uptime_sec": uptime,
                                    "cpu_temp_c": cpu_temp,
                                    "hostname": socket.gethostname()})
        except Exception as e:
            print(f"[heartbeat] {e}")
        time.sleep(30)
def start_web_dashboard():
    try:
        from flask import Flask, jsonify
    except ImportError:
        print("[web] ❌ Flask не встановлено!")
        while True:
            time.sleep(60)
    app = Flask(__name__)
    HTML = """<!DOCTYPE html>
<html lang="uk"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetGuardian Pi</title>
<style>
body{font-family:'Segoe UI',monospace;background:#0a0f1a;color:#e0f0ff;padding:20px;max-width:800px;margin:auto}
h1{color:#00d4ff;border-bottom:2px solid #00d4ff}
.card{background:#111c2a;border:1px solid #1e3040;border-radius:8px;padding:16px;margin-bottom:16px}
.label{color:#607080;font-size:.9em}
.value{color:#00ff88;font-size:1.5em;font-weight:bold}
.row{display:flex;gap:16px;flex-wrap:wrap}
.row>div{flex:1;min-width:150px}
table{width:100%;border-collapse:collapse}
td,th{padding:6px;border-bottom:1px solid #1e3040;text-align:left}
th{color:#00d4ff}
.ai-status{padding:8px 12px;background:#1a2540;border-radius:6px;display:inline-block;margin-bottom:10px}
.ai-on{color:#00ff88}.ai-off{color:#ff6060}
</style></head><body>
<h1>🛡️ NetGuardian Pi Agent</h1>
<p style="color:#607080;font-size:.8em">Auto-refresh 10с · <span id="ts"></span></p>
<div class="ai-status">
🧠 Локальний AI: <span id="ai_st" class="ai-on">enabled</span>
· <span id="ai_err">помилок (1 год): -</span>
</div>
<div class="card"><h3>📡 Останній пінг</h3><div class="row">
<div><div class="label">8.8.8.8</div><div class="value" id="p1">-</div></div>
<div><div class="label">1.1.1.1</div><div class="value" id="p2">-</div></div>
<div><div class="label">9.9.9.9</div><div class="value" id="p3">-</div></div>
</div></div>
<div class="card"><h3>⚡ Speedtest</h3><div class="row">
<div><div class="label">DL</div><div class="value" id="dl">-</div></div>
<div><div class="label">UL</div><div class="value" id="ul">-</div></div>
<div><div class="label">Server</div><div class="value" id="srv" style="font-size:1em">-</div></div>
</div></div>
<div class="card"><h3>📶 LAN</h3><table id="lan_t"><thead><tr><th>IP</th><th>MAC</th><th>Host</th></tr></thead><tbody></tbody></table></div>
<div class="card"><h3>📊 24 год</h3><div class="row">
<div><div class="label">avg ping</div><div class="value" id="ap">-</div></div>
<div><div class="label">avg loss</div><div class="value" id="al">-</div></div>
<div><div class="label">вимірів</div><div class="value" id="cnt">-</div></div>
</div></div>
<script>
async function r(){try{const r=await fetch('/api/status');const d=await r.json();
document.getElementById('ts').textContent='Оновлено: '+d.now;
document.getElementById('ai_st').textContent=d.ai_enabled?'enabled ✅':'disabled ❌';
document.getElementById('ai_st').className=d.ai_enabled?'ai-on':'ai-off';
document.getElementById('ai_err').textContent='помилок (1 год): '+(d.ai_errors_count||0);
const p=d.last_pings||{};
document.getElementById('p1').textContent=(p['8.8.8.8']||'-')+' ms';
document.getElementById('p2').textContent=(p['1.1.1.1']||'-')+' ms';
document.getElementById('p3').textContent=(p['9.9.9.9']||'-')+' ms';
if(d.last_speedtest){
document.getElementById('dl').textContent=d.last_speedtest.dl_mbps+' Mbps';
document.getElementById('ul').textContent=d.last_speedtest.ul_mbps+' Mbps';
document.getElementById('srv').textContent=d.last_speedtest.server;}
const tb=document.querySelector('#lan_t tbody');tb.innerHTML='';
(d.lan_devices||[]).forEach(x=>{tb.innerHTML+=`<tr><td>${x.ip}</td><td>${x.mac}</td><td>${x.hostname||''}</td></tr>`});
document.getElementById('ap').textContent=(d.stats.avg_ping||'-')+' ms';
document.getElementById('al').textContent=(d.stats.avg_loss||'-')+' %';
document.getElementById('cnt').textContent=d.stats.count||'-';
}catch(e){console.error(e)}}r();setInterval(r,10000);
</script></body></html>"""
    @app.route("/")
    def index():
        return HTML
    @app.route("/api/status")
    def status():
        result = {"now": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                  "last_pings": {}, "last_speedtest": None,
                  "lan_devices": [], "stats": {},
                  "ai_enabled": HAS_LOCAL_AI,
                  "ai_errors_count": 0}
        try:
            with sqlite3.connect(DB_PATH, timeout=5) as conn:
                for host in PING_HOSTS:
                    c = conn.execute(
                        "SELECT ping_ms FROM ping_log WHERE host=? "
                        "ORDER BY id DESC LIMIT 1", (host,))
                    row = c.fetchone()
                    if row:
                        result["last_pings"][host] = round(row[0], 1)
                c = conn.execute(
                    "SELECT dl_mbps, ul_mbps, ping_ms, server, ts "
                    "FROM speedtest_log ORDER BY id DESC LIMIT 1")
                row = c.fetchone()
                if row:
                    result["last_speedtest"] = {
                        "dl_mbps": row[0], "ul_mbps": row[1],
                        "ping_ms": row[2], "server": row[3], "ts": row[4]}
                c = conn.execute("""
                    SELECT ip, mac, hostname, vendor, MAX(ts)
                    FROM lan_log WHERE ts >= datetime('now','-15 minutes')
                    GROUP BY mac""")
                for row in c.fetchall():
                    result["lan_devices"].append({
                        "ip": row[0], "mac": row[1],
                        "hostname": row[2], "vendor": row[3]})
                c = conn.execute("""
                    SELECT AVG(ping_ms), AVG(loss_pct), COUNT(*)
                    FROM ping_log
                    WHERE ts >= datetime('now','-1 day') AND ping_ms > 0""")
                row = c.fetchone()
                if row:
                    result["stats"] = {
                        "avg_ping": round(row[0] or 0, 1),
                        "avg_loss": round(row[1] or 0, 2),
                        "count": row[2] or 0}

                # ─── PR #4: підраховуємо AI-помилки за 1 год ───
                if HAS_LOCAL_AI:
                    try:
                        c = conn.execute("""
                            SELECT COUNT(*) FROM network_errors
                            WHERE ts >= datetime('now', '-1 hour', 'localtime')
                        """)
                        row = c.fetchone()
                        if row:
                            result["ai_errors_count"] = row[0]
                    except Exception:
                        pass
        except Exception as e:
            print(f"[web] error: {e}")
        return jsonify(result)

    # ─── PR #4: новий endpoint для AI-аналізу через HTTP ──────────────────
    @app.route("/api/analyze")
    def api_analyze():
        """HTTP-альтернатива для cmd/analyze. Можна юзати з браузера/curl."""
        if not HAS_LOCAL_AI:
            return jsonify({"error": "Local AI not available"}), 503
        period = 3600
        try:
            from flask import request
            period = int(request.args.get("period", 3600))
        except Exception:
            pass
        analysis = analyze_situation(period)
        return jsonify(analysis)

    @app.route("/api/errors")
    def api_errors():
        """HTTP endpoint: список помилок мережі за період."""
        if not HAS_LOCAL_AI:
            return jsonify({"error": "Local AI not available"}), 503
        period = 3600
        try:
            from flask import request
            period = int(request.args.get("period", 3600))
        except Exception:
            pass
        return jsonify({
            "period": period,
            "errors": get_errors_since(period, limit=200),
            "counts": count_errors_by_type(period),
        })

    @app.route("/api/logs")
    def api_logs():
        """HTTP endpoint: останні рядки з monitor.log та системних логів.

        Query params:
          ?lines=50    — скільки останніх рядків (за замовч. 30)
          ?type=monitor|agent|all — який лог (за замовч. monitor)
        """
        try:
            from flask import request
            lines_n  = int(request.args.get("lines", 30))
            log_type = request.args.get("type", "monitor")
            lines_n  = max(5, min(200, lines_n))
        except Exception:
            lines_n  = 30
            log_type = "monitor"

        result = {
            "type":  log_type,
            "lines": lines_n,
        }

        # Monitor log
        monitor_log = Path.home() / ".netguardian-agent" / "monitor.log"
        if log_type in ("monitor", "all") and monitor_log.exists():
            try:
                with open(monitor_log, "r", errors="replace") as f:
                    all_lines = f.readlines()
                result["monitor"] = "".join(all_lines[-lines_n:])
                result["monitor_size"] = monitor_log.stat().st_size
            except Exception as e:
                result["monitor_error"] = str(e)
        else:
            result["monitor"] = "(no log yet)"

        # Останній client_seen
        seen_file = Path.home() / ".netguardian-agent" / "client_seen.txt"
        if seen_file.exists():
            try:
                ts = int(seen_file.read_text().strip())
                age = int(time.time() - ts)
                result["client_seen_age_sec"] = age
                result["client_seen_ts"] = ts
            except Exception:
                result["client_seen_age_sec"] = None

        # Стан monitor
        state_file = Path.home() / ".netguardian-agent" / "monitor_state.json"
        if state_file.exists():
            try:
                result["monitor_state"] = json.loads(state_file.read_text())
            except Exception:
                pass

        return jsonify(result)

    print(f"[web] Запуск Flask на :{WEB_PORT}")
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False, use_reloader=False)
def main():
    print("=" * 60)
    print(" NetGuardian Pi Agent — старт")
    print(f" Hostname: {socket.gethostname()}")
    print(f" Python:   {platform.python_version()}")
    print(f" DB:       {DB_PATH}")
    print(f" MQTT:     {MQTT_BROKER} prefix={MQTT_TOPIC_PREFIX}")
    print(f" Web:      http://0.0.0.0:{WEB_PORT}")
    print(f" Local AI: {'✅ enabled' if HAS_LOCAL_AI else '❌ disabled'}")
    print("=" * 60)
    init_db()
    mqtt = MqttPublisher()
    pub = mqtt.publish

    # ─── PR #4: ErrorCollector (24/7 збір мережевих помилок для AI) ───────
    error_collector = None
    if HAS_LOCAL_AI and ErrorCollector:
        try:
            error_collector = ErrorCollector()
            error_collector.start()
            print("[AI] ✅ ErrorCollector запущено (збір помилок 24/7)")
        except Exception as e:
            print(f"[AI] ⚠️ ErrorCollector failed: {e}")

    threads = [
        threading.Thread(target=ping_collector, args=(pub,), daemon=True),
        threading.Thread(target=speedtest_collector, args=(pub,), daemon=True),
        threading.Thread(target=lan_scanner, args=(pub,), daemon=True),
        threading.Thread(target=heartbeat, args=(pub,), daemon=True),
    ]
    for t in threads:
        t.start()
    start_web_dashboard()
if __name__ == "__main__":
    main()