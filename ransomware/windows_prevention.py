import os
import psutil
import time
import logging
import subprocess
import threading
import smtplib
import hashlib
import winreg
import shutil
import sys
import ctypes
from email.message import EmailMessage
from plyer import notification

# Setup logging
logging.basicConfig(
    filename="ransomware_prevention.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    encoding="utf-8"
)

class WindowsRansomwarePrevention:
    def __init__(self):
        self.blocked_processes = set()
        self.whitelist = self.load_whitelist()
        self.config = {
            "cpu_threshold": 50,
            "mem_threshold": 40,
            "scan_interval": 3,
            "email_alerts": True,
            "monitor_network": True
        }
        self.suspicious_extensions = [".encrypted", ".locked", ".crypt", ".ransom"]
        self.ransomware_patterns = ["wannacry", "locky", "petya", "ransom", "cryptolocker"]
        self.suspicious_services = ["TermService", "RemoteRegistry", "wuauserv", "vss"]

    def run_as_admin(self):
        """Ensure script runs with admin privileges"""
        if not ctypes.windll.shell32.IsUserAnAdmin():
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
            sys.exit()

    def load_whitelist(self):
        """Load trusted process hashes"""
        whitelist = set()
        try:
            with open("whitelist.txt", "r") as f:
                for line in f:
                    whitelist.add(line.strip())
        except FileNotFoundError:
            logging.warning("Whitelist file not found, using empty whitelist")
        return whitelist

    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for block in iter(lambda: f.read(4096), b""):
                    sha256.update(block)
            return sha256.hexdigest()
        except Exception as e:
            logging.error(f"Error calculating hash for {filepath}: {e}")
            return None

    def monitor_processes(self):
        """Enhanced process monitoring with whitelist checking"""
        print("🚀 Starting enhanced process monitoring...")
        while True:
            for process in psutil.process_iter(attrs=['pid', 'name', 'exe', 'cpu_percent', 'memory_percent']):
                try:
                    info = process.info
                    process_name = info['name'].lower()
                    exe_path = info['exe']
                    
                    # Skip whitelisted processes
                    if exe_path and self.calculate_file_hash(exe_path) in self.whitelist:
                        continue
                        
                    if self.is_ransomware(process_name, info['cpu_percent'], info['memory_percent']):
                        self.terminate_process(info['pid'], process_name)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
                    logging.debug(f"Process access error: {e}")
                    continue
                    
            time.sleep(self.config['scan_interval'])

    def is_ransomware(self, process_name, cpu_usage, mem_usage):
        """Enhanced ransomware detection with multiple heuristics"""
        # Known ransomware patterns
        if any(pattern in process_name for pattern in self.ransomware_patterns):
            return True
            
        # High resource usage
        if cpu_usage > self.config['cpu_threshold'] or mem_usage > self.config['mem_threshold']:
            logging.warning(f"High resource usage detected: {process_name} (CPU: {cpu_usage}%, MEM: {mem_usage}%)")
            return True
            
        # Suspicious file operations
        try:
            process = psutil.Process(process.info['pid'])
            open_files = process.open_files()
            if len(open_files) > 100:  # Mass file access
                return True
        except:
            pass
            
        return False

    def terminate_process(self, pid, process_name):
        """Enhanced process termination with tree killing"""
        if pid in self.blocked_processes:
            return

        try:
            parent = psutil.Process(pid)
            children = parent.children(recursive=True)
            
            # Kill child processes first
            for child in children:
                try:
                    child.terminate()
                    self.blocked_processes.add(child.pid)
                except:
                    pass
                    
            # Kill parent process
            parent.terminate()
            self.blocked_processes.add(pid)

            logging.warning(f"Terminated suspicious process tree: {process_name} (PID: {pid})")
            print(f"⚠️ ALERT: Terminated {process_name} (PID: {pid})")

            if self.config['email_alerts']:
                self.send_email_alert(f"Ransomware process {process_name} (PID: {pid}) terminated!")

        except Exception as e:
            logging.error(f"Failed to terminate {process_name}: {e}")

    def monitor_file_changes(self):
        """Monitor for suspicious file modifications"""
        print("🔍 Starting file change monitoring...")
        while True:
            for folder in ["C:\\Users", "C:\\Windows\\Temp"]:
                for root, _, files in os.walk(folder):
                    for file in files:
                        if any(file.endswith(ext) for ext in self.suspicious_extensions):
                            filepath = os.path.join(root, file)
                            logging.warning(f"Suspicious file detected: {filepath}")
                            self.quarantine_file(filepath)
            time.sleep(60)  # Check every minute

    def quarantine_file(self, filepath):
        """Move suspicious file to quarantine"""
        quarantine_dir = "C:\\Quarantine"
        os.makedirs(quarantine_dir, exist_ok=True)
        try:
            shutil.move(filepath, os.path.join(quarantine_dir, os.path.basename(filepath)))
            logging.info(f"Quarantined suspicious file: {filepath}")
        except Exception as e:
            logging.error(f"Failed to quarantine {filepath}: {e}")

    def protect_critical_resources(self):
        """Enhanced protection for critical system resources"""
        print("🛡️ Hardening critical system resources...")
        
        # Protect boot configuration
        os.system("bcdedit /set {current} bootstatuspolicy ignoreallfailures")
        os.system("bcdedit /set {current} recoveryenabled no")
        
        # Disable PowerShell script execution
        self.set_registry_value(
            r"HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell",
            "ExecutionPolicy",
            "Restricted"
        )
        
        # Enable Windows Defender real-time protection
        os.system("powershell Set-MpPreference -DisableRealtimeMonitoring $false")
        
        # Enable Controlled Folder Access
        os.system("powershell Set-MpPreference -EnableControlledFolderAccess Enabled")

    def set_registry_value(self, key_path, value_name, value_data):
        """Helper function to set registry values"""
        try:
            key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
            winreg.SetValueEx(key, value_name, 0, winreg.REG_SZ, value_data)
            winreg.CloseKey(key)
            return True
        except Exception as e:
            logging.error(f"Failed to set registry value {key_path}\\{value_name}: {e}")
            return False

    def start_monitoring(self):
        """Start all monitoring threads"""
        print("🚀 Starting enhanced ransomware protection system...")
        self.run_as_admin()
        
        # Initialize protections
        self.disable_suspicious_services()
        self.protect_critical_resources()
        self.secure_file_permissions()
        if self.config['monitor_network']:
            self.block_network_access()
        self.protect_registry_and_scheduler()

        # Start monitoring threads
        threading.Thread(target=self.monitor_processes, daemon=True).start()
        threading.Thread(target=self.monitor_file_changes, daemon=True).start()

        print("✅ System secured. Monitoring started.")

if __name__ == "__main__":
    prevention = WindowsRansomwarePrevention()
    prevention.start_monitoring()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n🛑 Monitoring stopped.")