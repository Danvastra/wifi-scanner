import sys
import platform
import subprocess
import re
import shutil
import json
import threading
import time
import os
import webbrowser
from datetime import datetime, timedelta
from plyer import notification
import speedtest
import requests

from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QPushButton, QTableWidget,
    QTableWidgetItem, QHBoxLayout, QLabel, QProgressBar, QMessageBox,
    QCheckBox, QLineEdit
)
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# ================================
# UTILS
# ================================
def get_vendor_from_mac(mac):
    mac = mac.upper().replace(":", "")[:6]
    vendors = {
        "F4F5E8": "TP-Link",
        "A4B197": "Xiaomi",
        "B0B28F": "Huawei",
        "9C5CF9": "ZTE",
        "3CA308": "Ubiquiti",
        "D8C4E9": "ASUS",
        "001A1E": "Cisco",
    }
    return vendors.get(mac, "Unknown Vendor")

def detect_interfaces():
    interfaces = []
    osname = platform.system().lower()
    if "windows" in osname:
        out = subprocess.run(["netsh","wlan","show","interfaces"], capture_output=True, text=True).stdout
        matches = re.findall(r"Name\s*:\s*(.+)", out)
        interfaces.extend(matches)
    else:
        if shutil.which("nmcli"):
            out = subprocess.run(["nmcli","device","status"], capture_output=True, text=True).stdout
            for line in out.split("\n"):
                if "wifi" in line.lower() and ("connected" in line.lower() or "disconnected" in line.lower()):
                    interfaces.append(line.split()[0])
        else:
            interfaces.append("wlan0")
    return interfaces if interfaces else ["wlan0"]

# ================================
# WINDOWS & LINUX SCAN
# ================================
def get_connected_windows():
    try:
        out = subprocess.run(["netsh","wlan","show","interfaces"], capture_output=True, text=True).stdout
        match = re.search(r"SSID\s*:\s(.+)", out)
        return match.group(1).strip() if match else None
    except:
        return None

def scan_windows():
    connected_ssid = get_connected_windows()
    out = subprocess.run(["netsh","wlan","show","networks","mode=bssid"], capture_output=True, text=True).stdout
    blocks = out.split("SSID ")
    networks = []
    for block in blocks[1:]:
        lines = block.split("\n")
        ssid = lines[0].split(":")[1].strip()
        entry = {
            "ssid": ssid,
            "status": "CONNECTED" if ssid == connected_ssid else "AVAILABLE",
            "bssid": "",
            "vendor": "",
            "signal": "",
            "channel": "",
            "security": ""
        }
        bssid_matches = re.findall(r"BSSID \d+ : ([\w:]+)", block)
        signal_matches = re.findall(r"Signal\s*:\s*(\d+)%", block)
        channel_match = re.search(r"Channel\s*:\s*(\d+)", block)
        security_match = re.search(r"Authentication\s*:\s*(.*)", block)
        if bssid_matches:
            entry["bssid"] = bssid_matches[0]
            entry["vendor"] = get_vendor_from_mac(entry["bssid"])
        if signal_matches:
            entry["signal"] = signal_matches[0]
        if channel_match:
            entry["channel"] = channel_match.group(1)
        if security_match:
            entry["security"] = security_match.group(1).strip()
        networks.append(entry)
    return networks

def get_connected_linux():
    if shutil.which("nmcli"):
        result = subprocess.run(["nmcli","-t","-f","active,ssid","device","wifi"], capture_output=True, text=True).stdout
        for line in result.strip().split("\n"):
            parts = line.split(":")
            if len(parts) >= 2 and parts[0] == "yes":
                return parts[1]
    return None

def scan_linux():
    connected_ssid = get_connected_linux()
    networks = []
    if shutil.which("nmcli"):
        out = subprocess.run(["nmcli","-t","-f","SSID,BSSID,SIGNAL,CHAN,SECURITY","device","wifi"], capture_output=True, text=True).stdout
        for line in out.split("\n"):
            parts = line.split(":")
            if len(parts) >= 5:
                ssid, bssid, signal, channel, security = parts
                entry = {
                    "ssid": ssid if ssid else "(Hidden)",
                    "status": "CONNECTED" if ssid == connected_ssid else "AVAILABLE",
                    "bssid": bssid,
                    "vendor": get_vendor_from_mac(bssid),
                    "signal": signal,
                    "channel": channel,
                    "security": security
                }
                networks.append(entry)
    return networks

# ================================
# THREAD UNTUK SCAN
# ================================
class ScanThread(QThread):
    result_signal = pyqtSignal(list)
    def __init__(self, keyword="", min_signal=0):
        super().__init__()
        self.keyword = keyword.lower()
        self.min_signal = min_signal
    def run(self):
        osname = platform.system().lower()
        if "windows" in osname:
            data = scan_windows()
        else:
            data = scan_linux()
        filtered = []
        for d in data:
            sig = int(d["signal"]) if d["signal"].isdigit() else 0
            if sig >= self.min_signal and (self.keyword in d["ssid"].lower() or self.keyword == ""):
                filtered.append(d)
        self.result_signal.emit(filtered)

# ================================
# THREAD UNTUK SPEEDTEST
# ================================
class SpeedTestThread(QThread):
    result_signal = pyqtSignal(dict)
    def run(self):
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            download = st.download() / 1_000_000  # Mbps
            upload = st.upload() / 1_000_000      # Mbps
            ping = st.results.ping
            self.result_signal.emit({"download": download, "upload": upload, "ping": ping})
        except Exception as e:
            self.result_signal.emit({"error": str(e)})

# ================================
# THREAD UNTUK GEO-IP INFO
# ================================
class GeoIPThread(QThread):
    result_signal = pyqtSignal(dict)
    def run(self):
        try:
            res = requests.get("https://ipapi.co/json/").json()
            info = {
                "ip": res.get("ip"),
                "city": res.get("city"),
                "region": res.get("region"),
                "country": res.get("country_name"),
                "timezone": res.get("timezone")
            }
            # waktu lokal berdasarkan timezone API
            tz = res.get("timezone")
            # jika timezone tersedia, hitung waktu sekarang di timezone tersebut
            if tz:
                local_time = datetime.now(datetime.utcnow().astimezone().tzinfo).astimezone().strftime("%Y-%m-%d %H:%M:%S")
                # catatan: pendekatan ini tidak benar-benar menghitung timezone, tapi cukup untuk display dasar
                info["local_time"] = local_time
            else:
                info["local_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.result_signal.emit(info)
        except Exception as e:
            self.result_signal.emit({"error": str(e)})

# ================================
# GUI
# ================================
class WifiScannerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WiFi Scanner v5.4 by Danvastra")
        self.setGeometry(50,50,1100,780)
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        # Title
        self.title = QLabel("WiFi Scanner v5.4 by Danvastra")
        self.title.setAlignment(Qt.AlignCenter)
        self.title.setStyleSheet("font-size:22px;font-weight:bold;")
        self.layout.addWidget(self.title)

        # Geo-Info Label (IP, Kota, Negara, Waktu)
        self.geo_label = QLabel("Mendeteksi informasi IP …")
        self.geo_label.setAlignment(Qt.AlignCenter)
        self.layout.addWidget(self.geo_label)

        # Filters
        filter_layout = QHBoxLayout()
        self.keyword_input = QLineEdit(); self.keyword_input.setPlaceholderText("Filter SSID (kosong = semua)")
        self.signal_input = QLineEdit(); self.signal_input.setPlaceholderText("Minimal sinyal % (0-100)")
        filter_layout.addWidget(QLabel("Filter SSID:")); filter_layout.addWidget(self.keyword_input)
        filter_layout.addWidget(QLabel("Min Signal:")); filter_layout.addWidget(self.signal_input)
        self.layout.addLayout(filter_layout)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(["SSID","Status","BSSID","Vendor","Signal","Channel","Security"])
        self.layout.addWidget(self.table)

        # Chart
        self.fig = Figure(figsize=(6,4))
        self.canvas = FigureCanvas(self.fig)
        self.ax = self.fig.add_subplot(111)
        self.layout.addWidget(self.canvas)

        # Buttons
        btn_layout = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Sekali")
        self.monitor_btn = QPushButton("Mulai Monitoring")
        self.stop_btn = QPushButton("Stop")
        self.export_btn = QPushButton("Export HTML/JSON/TXT")
        self.speed_btn = QPushButton("Test Speed WiFi")
        self.theme_chk = QCheckBox("Dark Mode")
        btn_layout.addWidget(self.scan_btn)
        btn_layout.addWidget(self.monitor_btn)
        btn_layout.addWidget(self.stop_btn)
        btn_layout.addWidget(self.export_btn)
        btn_layout.addWidget(self.speed_btn)
        btn_layout.addWidget(self.theme_chk)
        self.layout.addLayout(btn_layout)

        # Progress Bar
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.layout.addWidget(self.progress)

        # Speed Test Result Label
        self.speed_label = QLabel("")
        self.layout.addWidget(self.speed_label)

        # Event Connections
        self.scan_btn.clicked.connect(self.scan_once)
        self.monitor_btn.clicked.connect(self.start_monitoring)
        self.stop_btn.clicked.connect(self.stop_monitoring)
        self.export_btn.clicked.connect(self.export_results)
        self.speed_btn.clicked.connect(self.start_speed_test)
        self.theme_chk.stateChanged.connect(self.toggle_theme)

        # State
        self.monitoring = False
        self.scan_thread = None
        self.monitor_thread = None
        self.speed_thread = None
        self.latest_results = []
        self.previous_signals = {}

        # Export folder
        self.export_folder = "wifi_exports"
        if not os.path.exists(self.export_folder):
            os.makedirs(self.export_folder)
        self.auto_clean_folder(days=7, max_files=20)

        # Jalankan Geo IP detection
        self.geo_thread = GeoIPThread()
        self.geo_thread.result_signal.connect(self.set_geo_info)
        self.geo_thread.start()

    def set_geo_info(self, info):
        if "error" in info:
            self.geo_label.setText(f"Geo-IP error: {info['error']}")
        else:
            ip = info.get("ip")
            city = info.get("city")
            region = info.get("region")
            country = info.get("country")
            lt = info.get("local_time")
            self.geo_label.setText(f"IP: {ip} — {city}, {region}, {country} — Waktu lokal: {lt}")

    def scan_once(self):
        if self.scan_thread is not None:
            self.scan_thread.wait()
            self.scan_thread = None
        keyword = self.keyword_input.text()
        try:
            min_sig = int(self.signal_input.text())
        except:
            min_sig = 0
        self.progress.setValue(30)
        self.scan_thread = ScanThread(keyword, min_sig)
        self.scan_thread.result_signal.connect(self.load_results)
        self.scan_thread.finished.connect(lambda: self.progress.setValue(100))
        self.scan_thread.start()

    def load_results(self, data):
        for item in data:
            ssid = item["ssid"]
            signal = int(item["signal"]) if item["signal"].isdigit() else 0
            if ssid not in self.previous_signals:
                notification.notify(title="WiFi Baru Terdeteksi",
                                    message=f"{ssid} terdeteksi dengan sinyal {signal}%",
                                    timeout=3)
            else:
                prev = self.previous_signals[ssid]
                if prev - signal >= 20:
                    notification.notify(title="Signal Drop",
                                        message=f"{ssid} turun {prev - signal}% ({prev}% → {signal}%)",
                                        timeout=3)
            self.previous_signals[ssid] = signal

        self.latest_results = data
        self.table.setRowCount(len(data))
        ssids = []
        signals = []
        for i, item in enumerate(data):
            self.table.setItem(i, 0, QTableWidgetItem(item["ssid"]))
            self.table.setItem(i, 1, QTableWidgetItem(item["status"]))
            self.table.setItem(i, 2, QTableWidgetItem(item["bssid"]))
            self.table.setItem(i, 3, QTableWidgetItem(item["vendor"]))
            self.table.setItem(i, 4, QTableWidgetItem(item["signal"]))
            self.table.setItem(i, 5, QTableWidgetItem(item["channel"]))
            self.table.setItem(i, 6, QTableWidgetItem(item["security"]))
            ssids.append(item["ssid"])
            signals.append(int(item["signal"]) if item["signal"].isdigit() else 0)
        self.update_chart(ssids, signals)

    def update_chart(self, ssids, signals):
        self.ax.clear()
        self.ax.bar(ssids, signals, color='blue')
        self.ax.set_ylim(0, 100)
        self.ax.set_ylabel("Signal (%)")
        self.ax.set_xlabel("SSID")
        self.ax.set_title("Kekuatan Sinyal WiFi (Multi-Interface)")
        self.ax.tick_params(axis='x', rotation=45)
        self.canvas.draw()

    def start_monitoring(self):
        if self.monitoring:
            return
        self.monitoring = True
        keyword = self.keyword_input.text()
        try:
            min_sig = int(self.signal_input.text())
        except:
            min_sig = 0

        def monitor_job():
            while self.monitoring:
                if self.scan_thread is not None:
                    self.scan_thread.wait()
                self.scan_thread = ScanThread(keyword, min_sig)
                self.scan_thread.result_signal.connect(self.load_results)
                self.scan_thread.start()
                for i in range(10):
                    if not self.monitoring:
                        break
                    self.progress.setValue(i * 10)
                    time.sleep(0.5)
            self.progress.setValue(0)

        self.monitor_thread = threading.Thread(target=monitor_job, daemon=True)
        self.monitor_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        if self.scan_thread is not None:
            self.scan_thread.wait()
            self.scan_thread = None
        self.progress.setValue(0)

    def export_results(self):
        if not self.latest_results:
            QMessageBox.warning(self, "Error", "Tidak ada data untuk diexport!")
            return
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        folder = self.export_folder
        if not os.path.exists(folder):
            os.makedirs(folder)

        json_file = os.path.join(folder, f"wifi_scan_{timestamp}.json")
        with open(json_file, "w") as f:
            json.dump(self.latest_results, f, indent=4)

        txt_file = os.path.join(folder, f"wifi_scan_{timestamp}.txt")
        with open(txt_file, "w") as f:
            for n in self.latest_results:
                f.write(f"{n['status']} - SSID: {n['ssid']}\n")
                for k, v in n.items():
                    f.write(f"  {k}: {v}\n")
                f.write("\n")

        html_file = os.path.join(folder, f"wifi_scan_{timestamp}.html")
        with open(html_file, "w") as f:
            f.write("<html><body><h2>Hasil Scan WiFi</h2><table border=1>")
            f.write("<tr><th>SSID</th><th>Status</th><th>BSSID</th><th>Vendor</th><th>Signal</th><th>Channel</th><th>Security</th></tr>")
            for n in self.latest_results:
                f.write("<tr>")
                f.write(f"<td>{n['ssid']}</td>")
                f.write(f"<td>{n['status']}</td>")
                f.write(f"<td>{n['bssid']}</td>")
                f.write(f"<td>{n['vendor']}</td>")
                f.write(f"<td>{n['signal']}</td>")
                f.write(f"<td>{n['channel']}</td>")
                f.write(f"<td>{n['security']}</td>")
                f.write("</tr>")
            f.write("</table></body></html>")

        webbrowser.open(html_file)
        QMessageBox.information(self, "Sukses", f"Export berhasil! Semua file di folder '{folder}'")

    def toggle_theme(self, state):
        if state == Qt.Checked:
            dark_style = """
            QWidget { background-color: #2b2b2b; color: #f0f0f0; }
            QPushButton { background-color: #3c3f41; color: #f0f0f0; border: 1px solid #555; }
            QTableWidget { background-color: #2b2b2b; color: #f0f0f0; gridline-color: #555; }
            QProgressBar { background-color: #3c3f41; color: #f0f0f0; }
            QLineEdit { background-color: #3c3f41; color: #f0f0f0; }
            """
            self.setStyleSheet(dark_style)
        else:
            self.setStyleSheet("")

    def auto_clean_folder(self, days=7, max_files=20):
        files = [os.path.join(self.export_folder, f) for f in os.listdir(self.export_folder)]
        files = [f for f in files if os.path.isfile(f)]
        cutoff = datetime.now() - timedelta(days=days)
        for f in files:
            if datetime.fromtimestamp(os.path.getmtime(f)) < cutoff:
                os.remove(f)
        files = sorted(files, key=lambda x: os.path.getmtime(x))
        while len(files) > max_files:
            os.remove(files[0])
            files.pop(0)

    def start_speed_test(self):
        self.speed_label.setText("Mengukur kecepatan jaringan …")
        self.speed_btn.setEnabled(False)
        self.speed_thread = SpeedTestThread()
        self.speed_thread.result_signal.connect(self.display_speed)
        self.speed_thread.start()

    def display_speed(self, data):
        self.speed_btn.setEnabled(True)
        if "error" in data:
            self.speed_label.setText(f"Speed Test gagal: {data['error']}")
            return
        download = data["download"]
        upload = data["upload"]
        ping = data["ping"]
        self.speed_label.setText(f"Download: {download:.2f} Mbps | Upload: {upload:.2f} Mbps | Ping: {ping:.1f} ms")

        ss = ["Download", "Upload"]
        vals = [download, upload]
        self.ax.clear()
        self.ax.bar(ss, vals, color=["green", "orange"])
        self.ax.set_ylim(0, max(vals) * 1.2)
        self.ax.set_ylabel("Mbps")
        self.ax.set_title("Hasil Speed Test WiFi")
        self.canvas.draw()

    def closeEvent(self, event):
        self.monitoring = False
        if self.scan_thread is not None:
            self.scan_thread.wait()
        event.accept()

# ================================
# MAIN
# ================================
if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = WifiScannerGUI()
    gui.show()
    sys.exit(app.exec_())
