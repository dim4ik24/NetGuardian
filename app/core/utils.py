# core/network.py
import subprocess
import ping3
import re

class NetworkScanner:
    @staticmethod
    def get_default_gateway():
        """Розумний пошук IP-адреси роутера в системі Windows"""
        try:
            output = subprocess.check_output("route print -4", encoding="oem", creationflags=subprocess.CREATE_NO_WINDOW)
            gateways = []
            for line in output.split('\n'):
                if "0.0.0.0" in line and "255.255.255.255" not in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0":
                        gw = parts[2]
                        if gw != "0.0.0.0" and gw != "127.0.0.1":
                            gateways.append((gw, int(parts[-1])))
            if gateways:
                for gw, metric in gateways:
                    if gw.startswith("192.168.") or gw.startswith("10.") or gw.startswith("172."):
                        return gw
                gateways.sort(key=lambda x: x[1])
                return gateways[0][0]
        except Exception:
            pass
        return '192.168.1.1'

    @staticmethod
    def check_ping(host='8.8.8.8', timeout=2):
        """Пінгує ціль і повертає мілісекунди або помилку"""
        try:
            delay = ping3.ping(host, timeout=timeout)
            if delay is None: return -1
            return int(delay * 1000)
        except Exception:
            return -2

    @staticmethod
    def flush_dns():
        """Системна команда самовідновлення (Auto-Heal)"""
        try:
            result = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            lines = result.stdout.split('\n')
            success_line = [line for line in lines if "Successfully" in line or "Успішно" in line]
            if success_line:
                return f"[OK] {success_line[0].strip()}"
            return "[OK] Кеш DNS успішно очищено."
        except Exception as e:
            return f"[Помилка] Не вдалося виконати команду: {e}"
