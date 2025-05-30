import os
import sys
import time
import logging
import shutil
import subprocess
import psutil
import winreg
import math
import ctypes
from plyer import notification
from ai_models import AIModelManager

# Setup logging
logging.basicConfig(filename="ransomware_rollback.log", level=logging.INFO,
                    format="%(asctime)s - %(message)s", encoding="utf-8")

class WindowsRollbackSystem:
    def __init__(self):
        self.backup_folder = "C:\\RansomwareBackups"
        self.monitored_folders = ["C:\\Users\\Public", "C:\\Documents"]
        self.shadow_copy_created = False
        self.rollback_actions = []
        self.SUSPICIOUS_EXTENSIONS = [".locked", ".crypt", ".encrypted", ".ransom"]
        self.ai_model = AIModelManager()

    def run_as_admin(self):
        if ctypes.windll.shell32.IsUserAnAdmin():
            return
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable,
                                            " ".join(sys.argv), None, 1)
        sys.exit()

    def notify_user(self, title, message):
        notification.notify(title=title, message=message,
                            app_name="Windows Rollback System", timeout=5)

    def detect_encrypted_files(self):
        encrypted_files = []
        for folder in self.monitored_folders:
            if not os.path.exists(folder):
                continue
            for root, _, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    if any(file.lower().endswith(ext) for ext in self.SUSPICIOUS_EXTENSIONS):
                        encrypted_files.append(file_path)
                        continue
                    if self.is_high_entropy(file_path):
                        encrypted_files.append(file_path)
        return encrypted_files

    def is_high_entropy(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                data = f.read(8192)
                return self.calculate_entropy(data) > 7.0
        except:
            return False

    def calculate_entropy(self, data):
        if not data:
            return 0
        entropy = 0
        for x in range(256):
            p_x = float(data.count(bytes([x]))) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log(p_x, 2)
        return entropy

    def create_shadow_copy(self):
        if self.shadow_copy_created:
            return
        try:
            subprocess.run("wmic shadowcopy call create Volume=C:\\", shell=True,
                           check=True, capture_output=True, text=True)
            self.shadow_copy_created = True
            logging.info("✅ Shadow copy created.")
        except Exception as e:
            logging.error(f"❌ Shadow copy creation failed: {str(e)}")

    def restore_from_shadow_copy(self, file_path):
        try:
            output = subprocess.check_output("vssadmin list shadows", shell=True,
                                             text=True, encoding='utf-8', errors='ignore')
            if "Shadow Copy ID" in output:
                restore_cmd = f'cmd.exe /c "wbadmin start recovery -items="{file_path}" -version latest -quiet"'
                process = subprocess.run(restore_cmd, shell=True, capture_output=True, text=True)
                if "successfully recovered" in process.stdout:
                    self.rollback_actions.append(f"Restored from shadow copy: {file_path}")
                    return True
        except Exception as e:
            logging.warning(f"⚠️ Failed to restore from shadow copy: {str(e)}")
        return False

    def rollback_registry_changes(self):
        registry_backup_path = os.path.join(self.backup_folder, "registry_backup.reg")
        if os.path.exists(registry_backup_path):
            try:
                subprocess.run(f"reg import \"{registry_backup_path}\"", shell=True,
                               check=True, capture_output=True, text=True)
                self.rollback_actions.append("Restored registry from backup")
                return True
            except Exception as e:
                logging.error(f"❌ Registry rollback failed: {str(e)}")
        return False

    def create_system_backup(self):
        os.makedirs(self.backup_folder, exist_ok=True)
        for folder in self.monitored_folders:
            backup_path = os.path.join(self.backup_folder, os.path.basename(folder))
            shutil.copytree(folder, backup_path, dirs_exist_ok=True)
        subprocess.run(f'reg export HKLM "{self.backup_folder}\\registry_backup.reg" /y',
                       shell=True)

    def rollback_system_settings(self):
        try:
            subprocess.run("gpupdate /force", shell=True)
            subprocess.run("netsh int ip reset", shell=True)
            subprocess.run("netsh winsock reset", shell=True)
            self.rollback_actions.append("Reset system settings")
            return True
        except Exception as e:
            logging.error(f"❌ System reset failed: {str(e)}")
        return False

    def disable_malicious_services(self):
        services = ["wscript", "cscript", "powershell"]
        count = 0
        for service in services:
            try:
                subprocess.run(f"taskkill /f /im {service}.exe", shell=True)
                self.rollback_actions.append(f"Stopped process: {service}.exe")
                count += 1
            except:
                pass
        return count

    def harden_system(self):
        measures = [
            'reg add "HKEY_CURRENT_USER\\Software\\Microsoft\\Office\\16.0\\Excel\\Security" /v "VBAWarnings" /t REG_DWORD /d 2 /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\PowerShell\\1\\ShellIds\\Microsoft.PowerShell" /v "ExecutionPolicy" /t REG_SZ /d "Restricted" /f',
            'reg add "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access" /v "EnableControlledFolderAccess" /t REG_DWORD /d 1 /f'
        ]
        for cmd in measures:
            subprocess.run(cmd, shell=True)

    def restore_files(self, files=None):
        files = files or self.detect_encrypted_files()
        restored = []
        for file_path in files:
            if self.restore_from_shadow_copy(file_path):
                restored.append(file_path)
        return restored

    def generate_rollback_report(self):
        report_file = "rollback_report.txt"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write("🚨 Ransomware Rollback Summary 🚨\n\n")
            f.write("\n".join(self.rollback_actions))
        self.notify_user("Rollback Report Generated", "📄 Check rollback_report.txt for details!")

    def run_rollback(self):
        print("🔄 Running full rollback...")
        self.create_shadow_copy()
        restored_files = self.restore_files()
        self.rollback_registry_changes()
        self.rollback_system_settings()
        self.disable_malicious_services()
        self.harden_system()
        self.generate_rollback_report()
        self.notify_user("Rollback Completed", f"✅ Restored {len(restored_files)} files.")

    def ai_guided_rollback(self, threat_details):
        severity = self.assess_threat_severity(threat_details)
        if severity == "high":
            self.create_shadow_copy()
            self.restore_files(threat_details.get("files_affected", []))
            self.rollback_registry_changes()
            self.rollback_system_settings()
        elif severity == "medium":
            if threat_details.get("files_affected"):
                self.restore_files(threat_details["files_affected"])
            if threat_details.get("registry_affected"):
                self.rollback_registry_changes()
        else:
            if threat_details.get("files_affected"):
                self.restore_files(threat_details["files_affected"])

    def assess_threat_severity(self, threat_details):
        features = [
            len(threat_details.get('files_affected', [])),
            len(threat_details.get('processes', [])),
            threat_details.get('network_activity', 0),
            threat_details.get('system_impact', 0)
        ]
        score = sum(features)
        if score > 10:
            return "high"
        elif score > 5:
            return "medium"
        return "low"

    def auto_monitor_and_rollback(self):
        print("👁️ Monitoring system for ransomware activity...")
        while True:
            threat_info = self.ai_model.scan_system()
            if threat_info["threat_detected"]:
                logging.warning("🚨 AI Model detected ransomware activity!")
                self.notify_user("Ransomware Alert", "🚨 Threat detected! Running AI-guided rollback...")
                self.ai_guided_rollback(threat_info)
            time.sleep(10)

if __name__ == "__main__":
    rollback_system = WindowsRollbackSystem()
    rollback_system.run_as_admin()
    rollback_system.auto_monitor_and_rollback()
