import threading
import time
import logging
import os
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from ttkbootstrap.scrolled import ScrolledText
from ttkbootstrap.style import Style
from ttkbootstrap.tableview import Tableview
from ttkbootstrap.dialogs import Messagebox
import psutil
import socket
import hashlib
import json
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import windows_detection
import windows_prevention
import windows_rollback
from utils import send_email_alert, show_notification, play_alert_sound
from datetime import datetime
from tkinter import filedialog, messagebox

from queue import Queue, Empty
from PIL import Image, ImageTk
Image.CUBIC = Image.BICUBIC
# Enhanced logging configuration
logging.basicConfig(
    filename="ransomware_system.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    filemode='a'  # Append mode
)
logger = logging.getLogger(__name__)

class EnhancedFileMonitor(FileSystemEventHandler):
    """Enhanced file system monitoring with pattern detection"""
    def __init__(self, protection_system):
        super().__init__()
        self.protection_system = protection_system
        self.suspicious_extensions = ['.encrypted', '.locked', '.crypt', '.ransom']
        self.whitelist = self.load_whitelist()
        
    def load_whitelist(self):
        """Load whitelisted processes and files"""
        try:
            with open('whitelist.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {'processes': [], 'files': []}
    
    def on_modified(self, event):
        """Detect suspicious file modifications"""
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if any(filename.endswith(ext) for ext in self.suspicious_extensions):
                self.protection_system.handle_suspicious_file(event.src_path)
    
    def on_created(self, event):
        """Detect suspicious file creations"""
        if not event.is_directory:
            filename = os.path.basename(event.src_path)
            if any(filename.endswith(ext) for ext in self.suspicious_extensions):
                self.protection_system.handle_suspicious_file(event.src_path)

class ThreatIntelligence:
    """Threat intelligence feed integration"""
    def __init__(self):
        self.known_ransomware_hashes = self.load_known_hashes()
        self.known_malicious_ips = self.load_malicious_ips()
    
    def load_known_hashes(self):
        """Load known ransomware file hashes"""
        try:
            with open('known_hashes.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def load_malicious_ips(self):
        """Load known malicious IP addresses"""
        try:
            with open('malicious_ips.json', 'r') as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return []
    
    def check_file_hash(self, filepath):
        """Check if file hash matches known ransomware"""
        try:
            with open(filepath, 'rb') as f:
                file_hash = hashlib.sha256(f.read()).hexdigest()
                return file_hash in self.known_ransomware_hashes
        except Exception:
            return False
    
    def check_ip(self, ip_address):
        """Check if IP is known malicious"""
        return ip_address in self.known_malicious_ips

class RansomwareProtectionSystem:
    def __init__(self, gui):
        self.gui = gui
        self.detector = windows_detection.WindowsRansomwareDetector()
        self.preventer = windows_prevention.WindowsRansomwarePrevention()
        self.rollback_system = windows_rollback.WindowsRollbackSystem()
        self.threat_intel = ThreatIntelligence()
        self.file_monitor = EnhancedFileMonitor(self)
        self.file_observer = Observer()
          # Performance monitoring
        self.performance_stats = {
            'scan_time': 0,
            'process_scan_time': 0,
            'file_scan_time': 0,
            'network_scan_time': 0
        }
        # Thread management
        self.stop_event = threading.Event()
        self.monitoring = False
        self.threads = []
        self.message_queue = Queue()
        
        # Data storage
        self.history_data = []
        self.detected_files_data = []
        self.rollbacked_files_data = []
        self.system_stats = {
            'files_protected': 0,
            'threats_blocked': 0,
            'files_restored': 0,
            'last_threat': None
        }
         # Optimized monitoring
        self.last_process_scan = 0
        self.last_file_scan = 0
        self.last_network_scan = 0
        self.scan_intervals = {
            'process': 5,    # seconds
            'file': 10,      # seconds
            'network': 3     # seconds
        }
        # Status flags
        self.detection_active = False
        self.prevention_active = False
        self.rollback_active = False
        self.file_monitoring_active = False
        
        # Start the message processing thread
        self.start_message_processor()

    def start_message_processor(self):
        """Start a thread to process messages from the queue"""
        processor = threading.Thread(target=self.process_messages, daemon=True)
        processor.start()
        self.threads.append(processor)

    def process_messages(self):
        """Process messages from the queue for GUI updates"""
        while not self.stop_event.is_set():
            try:
                message = self.message_queue.get(timeout=0.5)
                if hasattr(self.gui, 'log_message'):
                    self.gui.log_message(message)
            except Empty:
                continue

    def update_log(self, message, level="info"):
        """Enhanced logging with levels and queue processing"""
        log_method = getattr(logger, level, logger.info)
        log_method(message)
        self.message_queue.put(f"[{level.upper()}] {message}")

    def add_history(self, item, action, details=None):
        """Add history entry with optional details"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        entry = [timestamp, item, action]
        if details:
            entry.append(str(details))
        self.history_data.append(entry)
        self.gui_safe_update('update_history_display')

    def add_detected_item(self, item_type, name, status, threat_level="medium"):
        """Add detected item with threat level"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.detected_files_data.append([timestamp, item_type, name, status, threat_level])
        self.system_stats['threats_blocked'] += 1
        self.system_stats['last_threat'] = timestamp
        self.gui_safe_update('update_detected_display')

    def add_rollbacked_item(self, name, status):
        """Add rollbacked file entry"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.rollbacked_files_data.append([timestamp, name, status])
        self.system_stats['files_restored'] += 1
        self.gui_safe_update('update_rollbacked_display')

    def gui_safe_update(self, method_name, *args):
        """Safely update GUI elements from any thread"""
        if hasattr(self.gui, method_name):
            self.gui.after(0, getattr(self.gui, method_name), *args)

    def handle_suspicious_file(self, filepath):
        """Handle detected suspicious file"""
        filename = os.path.basename(filepath)
        self.update_log(f"⚠️ Suspicious file detected: {filename}", "warning")
        
        # Check against threat intelligence
        is_known_threat = self.threat_intel.check_file_hash(filepath)
        threat_level = "high" if is_known_threat else "medium"
        
        self.add_detected_item("File", filename, "Quarantined", threat_level)
        self.add_history("File Detection", f"Suspicious file: {filename}", 
                        {"path": filepath, "threat_level": threat_level})
        
        # Play alert sound for high threat levels
        if threat_level == "high":
            play_alert_sound()
        
        # Trigger prevention if active
        if self.prevention_active:
            self.preventer.quarantine_file(filepath)
        
        # Trigger rollback if active
        if self.rollback_active:
            restored = self.rollback_system.restore_files([filepath])
            if restored:
                self.add_rollbacked_item(filename, "Restored")

    def start_detection(self):
        """AI-Based Ransomware Detection with enhanced monitoring"""
        if self.detection_active:
            self.update_log("Detection module is already running", "warning")
            return
            
        self.update_log("Starting AI-Based Ransomware Detection...", "info")
        self.detection_active = True
        
        def detection_loop():
            while self.detection_active and not self.stop_event.is_set():
                try:
                    metrics = self.detector.collect_system_metrics()
                    ransomware_detected = self.detector.detect_ransomware(metrics)
                    
                    # Enhanced network monitoring
                    network_anomaly = self.detector.check_network_connections()
                    
                    if ransomware_detected or network_anomaly:
                        threat_type = "Network" if network_anomaly else "System"
                        self.update_log(f"ALERT: {threat_type} ransomware activity detected!", "warning")
                        
                        # Get detailed threat info
                        if network_anomaly:
                            suspicious_conn = self.detector.get_suspicious_connections()
                            details = {"type": "network", "connections": suspicious_conn}
                        else:
                            suspicious_procs = self.detector.get_suspicious_processes()
                            details = {"type": "process", "processes": suspicious_procs}
                        
                        self.add_history("Threat Detection", f"{threat_type} ransomware detected", details)
                        show_notification("Ransomware Alert", f"{threat_type} activity detected!")
                        send_email_alert("🚨 Ransomware Alert!", 
                                       f"{threat_type} activity detected!\nDetails: {json.dumps(details)}")
                        
                        # Trigger response
                        self.respond_to_threat(details)
                        
                except Exception as e:
                    self.update_log(f"Detection Error: {str(e)}", "error")
                
                time.sleep(3)  # Reduced sleep time for more responsive detection
            
            self.detection_active = False
            self.update_log("Detection module stopped", "info")
        
        detection_thread = threading.Thread(target=detection_loop, daemon=True)
        detection_thread.start()
        self.threads.append(detection_thread)

    def respond_to_threat(self, threat_details):
        """Coordinate response to detected threat"""
        # Process termination for process threats
        if threat_details["type"] == "process":
            for proc in threat_details["processes"]:
                self.add_detected_item("Process", proc["name"], "Terminated", proc.get("threat_level", "medium"))
                if self.prevention_active:
                    self.preventer.terminate_process(proc["pid"])
        
        # Network blocking for network threats
        elif threat_details["type"] == "network":
            for conn in threat_details["connections"]:
                self.add_detected_item("Connection", f"{conn['local']}->{conn['remote']}", 
                                      "Blocked", "high")
                if self.prevention_active:
                    self.preventer.block_ip_address(conn["remote_ip"])
        
        # File restoration if files were affected
        if self.rollback_active:
            restored_files = self.rollback_system.restore_affected_files(threat_details)
            if restored_files:
                for file in restored_files:
                    self.add_rollbacked_item(os.path.basename(file), "Restored")

    def start_file_monitoring(self):
        """Start file system monitoring"""
        if self.file_monitoring_active:
            self.update_log("File monitoring is already running", "warning")
            return
            
        self.update_log("Starting file system monitoring...", "info")
        self.file_monitoring_active = True
        
        try:
            # Monitor important directories
            important_dirs = [
                os.path.expanduser("~/Documents"),
                os.path.expanduser("~/Desktop"),
                os.path.expanduser("~/Pictures")
            ]
            
            for directory in important_dirs:
                if os.path.exists(directory):
                    self.file_observer.schedule(self.file_monitor, directory, recursive=True)
            
            self.file_observer.start()
            self.update_log(f"File monitoring active on {len(important_dirs)} directories", "info")
            
        except Exception as e:
            self.update_log(f"File monitoring error: {str(e)}", "error")
            self.file_monitoring_active = False

    def stop_file_monitoring(self):
        """Stop file system monitoring"""
        if not self.file_monitoring_active:
            return
            
        self.file_observer.stop()
        self.file_observer.join()
        self.file_monitoring_active = False
        self.update_log("File monitoring stopped", "info")

    def start_prevention(self):
        """Enhanced ransomware prevention mechanisms"""
        if self.prevention_active:
            self.update_log("Prevention module is already running", "warning")
            return
            
        self.update_log("Activating enhanced ransomware prevention...", "info")
        self.prevention_active = True
        
        try:
            # Enhanced prevention measures
            self.preventer.harden_system()
            self.preventer.secure_critical_files()
            self.preventer.enable_firewall()
            self.preventer.disable_macro_execution()
            
            self.add_history("Prevention", "Enhanced prevention activated")
            self.gui_safe_update('update_history_display')
            
            # Start process monitoring in a separate thread
            proc_monitor_thread = threading.Thread(
                target=self.preventer.monitor_processes,
                args=(self.handle_suspicious_process,),
                daemon=True
            )
            proc_monitor_thread.start()
            self.threads.append(proc_monitor_thread)
            
            self.update_log("Prevention module started with enhanced protection", "info")
            
        except Exception as e:
            self.update_log(f"Prevention Error: {str(e)}", "error")
            self.add_history("Prevention", f"Error activating prevention: {str(e)}")
            self.gui_safe_update('update_history_display')
            self.prevention_active = False

    def handle_suspicious_process(self, process_info):
        """Callback for suspicious process detection"""
        self.add_detected_item("Process", process_info["name"], "Terminated", process_info["threat_level"])
        self.add_history("Process Prevention", f"Terminated suspicious process: {process_info['name']}")
        
        # For critical threats, trigger additional actions
        if process_info["threat_level"] == "critical":
            play_alert_sound()
            send_email_alert("🚨 CRITICAL PROCESS ALERT!", 
                           f"Critical process detected and terminated:\n{json.dumps(process_info)}")

    def start_rollback(self):
        """Enhanced file monitoring and restoration"""
        if self.rollback_active:
            self.update_log("Rollback module is already running", "warning")
            return
            
        self.update_log("Starting enhanced file rollback monitoring...", "info")
        self.rollback_active = True
        
        def rollback_loop():
            while self.rollback_active and not self.stop_event.is_set():
                try:
                    # Check for recently modified files
                    recent_files = self.rollback_system.get_recently_modified_files()
                    suspicious = [f for f in recent_files if self.is_suspicious_file(f)]
                    
                    if suspicious:
                        restored = self.rollback_system.restore_files(suspicious)
                        if restored:
                            self.update_log(f"Restored {len(restored)} suspicious files", "info")
                            for file in restored:
                                self.add_rollbacked_item(os.path.basename(file), "Restored")
                                self.system_stats['files_restored'] += 1
                            
                except Exception as e:
                    self.update_log(f"Rollback Error: {str(e)}", "error")
                
                time.sleep(10)  # Check every 10 seconds
            
            self.rollback_active = False
            self.update_log("Rollback module stopped", "info")
        
        rollback_thread = threading.Thread(target=rollback_loop, daemon=True)
        rollback_thread.start()
        self.threads.append(rollback_thread)

    def is_suspicious_file(self, filepath):
        """Determine if a file shows signs of ransomware encryption"""
        try:
            # Check extension
            filename = filepath.lower()
            if any(filename.endswith(ext) for ext in self.file_monitor.suspicious_extensions):
                return True
                
            # Check entropy (simple version)
            if self.detector.is_high_entropy(filepath):
                return True
                
            # Check against threat intelligence
            if self.threat_intel.check_file_hash(filepath):
                return True
                
        except Exception:
            return False
        
        return False

    def run_all(self):
        """Start all protection modules with enhanced checks"""
        if self.monitoring:
            self.update_log("System is already running", "warning")
            return
            
        self.update_log("Starting comprehensive ransomware protection...", "info")
        self.monitoring = True
        self.stop_event.clear()
        
        # Update system stats
        self.system_stats['start_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.system_stats['status'] = 'active'
        
        self.add_history("System", "Comprehensive protection started")
        self.gui_safe_update('update_dashboard_status', "Active", "green")
        self.gui_safe_update('enable_stop_buttons')
        self.gui_safe_update('disable_start_buttons')
        
        # Start all modules
        self.start_detection()
        self.start_prevention()
        self.start_rollback()
        self.start_file_monitoring()
        
        # Update module statuses
        self.gui_safe_update('update_module_statuses', "Starting...", "orange")

    def stop_all(self):
        """Stop all monitoring processes safely"""
        if not self.monitoring:
            self.update_log("System is not running", "warning")
            return
            
        self.update_log("Stopping protection system...", "info")
        self.stop_event.set()
        self.monitoring = False
        
        # Stop all modules
        self.stop_detection()
        self.stop_prevention()
        self.stop_rollback()
        self.stop_file_monitoring()
        
        # Update system stats
        self.system_stats['status'] = 'inactive'
        self.system_stats['stop_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        self.add_history("System", "Protection system stopped")
        self.gui_safe_update('update_dashboard_status', "Stopped", "red")
        self.gui_safe_update('disable_stop_buttons')
        self.gui_safe_update('enable_start_buttons')
        
        # Clean up threads
        for thread in self.threads:
            if thread.is_alive():
                thread.join(timeout=1)
        self.threads = []

    def stop_detection(self):
        self.detection_active = False

    def stop_prevention(self):
        self.prevention_active = False

    def stop_rollback(self):
        self.rollback_active = False

    def get_system_stats(self):
        """Return current system statistics"""
        return self.system_stats

class EnhancedRansomwareGUI(ttk.Window):
    def __init__(self):
        # Initialize the main window with theme
        super().__init__(themename="darkly")
        self.title("AI Ransomware Protection Pro")
        self.geometry("1000x750")
        self.minsize(800, 600)
        
        # Initialize the protection system
        self.protection_system = RansomwareProtectionSystem(self)
        
        # Create the notebook (tab container)
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Initialize all tabs
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.logs_tab = ttk.Frame(self.notebook)
        self.history_tab = ttk.Frame(self.notebook)
        self.detected_tab = ttk.Frame(self.notebook)
        self.rollback_tab = ttk.Frame(self.notebook)
        self.settings_tab = ttk.Frame(self.notebook)
        
        
        
        self.create_status_bar
        # Create widgets for each tab
        self.create_dashboard_tab()
        self.create_logs_tab()
        self.create_history_tab()
        self.create_detected_tab()
        self.create_rollback_tab()
        self.create_settings_tab()
        
        # Set up periodic updates
        self.after(1000, self.update_system_stats)

    def create_widgets(self):
        """Create all GUI components"""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_dashboard_tab()
        self.create_logs_tab()
        self.create_history_tab()
        self.create_detected_tab()
        self.create_rollback_tab()
        self.create_settings_tab()
        
        # Status bar
        self.create_status_bar()
    def optimized_detection_loop(self):
          """Optimized detection loop with staggered scanning"""
          while self.detection_active and not self.stop_event.is_set():
            start_time = time.time()
            
            # Stagger different types of scans
            current_time = time.time()
            
            # Process scanning
            if current_time - self.last_process_scan > self.scan_intervals['process']:
                process_scan_start = time.time()
                self.scan_processes()
                self.performance_stats['process_scan_time'] = time.time() - process_scan_start
                self.last_process_scan = current_time
                
            # File scanning
            if current_time - self.last_file_scan > self.scan_intervals['file']:
                file_scan_start = time.time()
                self.scan_files()
                self.performance_stats['file_scan_time'] = time.time() - file_scan_start
                self.last_file_scan = current_time
                
            # Network scanning
            if current_time - self.last_network_scan > self.scan_intervals['network']:
                network_scan_start = time.time()
                self.scan_network()
                self.performance_stats['network_scan_time'] = time.time() - network_scan_start
                self.last_network_scan = current_time
                
            # System metrics (always scan)
            metrics = self.detector.collect_system_metrics()
            if self.detector.detect_ransomware(metrics):
                self.handle_threat(metrics)
                
            # Update performance stats
            self.performance_stats['scan_time'] = time.time() - start_time
            time.sleep(0.1)  # Reduced sleep for more responsive scanning
            
    def scan_processes(self):
        """Optimized process scanning"""
        suspicious_procs = self.detector.analyze_suspicious_processes(quick_scan=True)
        if suspicious_procs:
            self.handle_suspicious_processes(suspicious_procs)
            
    def scan_files(self):
        """Optimized file scanning"""
        # Focus on recently modified files
        recent_files = self.get_recently_modified_files()
        suspicious_files = [f for f in recent_files if self.is_suspicious_file(f)]
        if suspicious_files:
            self.handle_suspicious_files(suspicious_files)
            
    def scan_network(self):
        """Optimized network scanning"""
        suspicious_conns = self.detector.analyze_network_connections()
        if suspicious_conns:
            self.handle_suspicious_connections(suspicious_conns)
            
    def get_recently_modified_files(self, hours=1):
        """Get files modified in the last hour"""
        cutoff = time.time() - (hours * 3600)
        recent_files = []
        
        for folder in self.file_monitor.important_dirs:
            for root, _, files in os.walk(folder):
                for file in files:
                    path = os.path.join(root, file)
                    try:
                        if os.path.getmtime(path) > cutoff:
                            recent_files.append(path)
                    except:
                        continue
                        
        return recent_files

    def create_dashboard_tab(self):
        """Create the dashboard tab with system overview"""
        # Create the tab frame
        self.dashboard_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_tab, text="Dashboard")
        
        # System Status Frame
        status_frame = ttk.LabelFrame(self.dashboard_tab, text="System Status", bootstyle="info")
        status_frame.pack(fill=X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Stopped", font=('Helvetica', 12))
        self.status_label.pack(pady=5)
        
        # Stats Frame
        stats_frame = ttk.LabelFrame(self.dashboard_tab, text="Protection Statistics", bootstyle="primary")
        stats_frame.pack(fill=X, padx=10, pady=5)
        
        self.stats_labels = {
            'files_protected': ttk.Label(stats_frame, text="Files Protected: 0"),
            'threats_blocked': ttk.Label(stats_frame, text="Threats Blocked: 0"),
            'files_restored': ttk.Label(stats_frame, text="Files Restored: 0"),
            'last_threat': ttk.Label(stats_frame, text="Last Threat: Never")
        }
        
        for label in self.stats_labels.values():
            label.pack(anchor=W, padx=5, pady=2)
        
        # Control Buttons
        btn_frame = ttk.Frame(self.dashboard_tab)
        btn_frame.pack(fill=X, padx=10, pady=10)
        
        self.start_btn = ttk.Button(
            btn_frame, 
            text="Start Protection", 
            command=self.start_monitoring, 
            bootstyle="success",
            width=15
        )
        self.start_btn.pack(side=LEFT, padx=5)
        
        self.stop_btn = ttk.Button(
            btn_frame, 
            text="Stop Protection", 
            command=self.stop_monitoring, 
            bootstyle="danger",
            state=DISABLED,
            width=15
        )
        self.stop_btn.pack(side=LEFT, padx=5)
        
        self.simulate_btn = ttk.Button(
            btn_frame, 
            text="Simulate Attack", 
            command=self.simulate_attack, 
            bootstyle="warning",
            width=15
        )
        self.simulate_btn.pack(side=RIGHT, padx=5)
        
        # Module Status
        module_frame = ttk.LabelFrame(self.dashboard_tab, text="Module Status", bootstyle="secondary")
        module_frame.pack(fill=X, padx=10, pady=5)
        
        self.module_status = {
            'detection': ttk.Label(module_frame, text="Detection: Stopped", foreground="red"),
            'prevention': ttk.Label(module_frame, text="Prevention: Stopped", foreground="red"),
            'rollback': ttk.Label(module_frame, text="Rollback: Stopped", foreground="red"),
            'file_monitor': ttk.Label(module_frame, text="File Monitor: Stopped", foreground="red")
        }
        
        for label in self.module_status.values():
            label.pack(anchor=W, padx=5, pady=2)
        
        # Threat Level Indicator
        threat_frame = ttk.LabelFrame(self.dashboard_tab, text="Threat Level", bootstyle="danger")
        threat_frame.pack(fill=X, padx=10, pady=5)
        
        self.threat_level = ttk.Label(
            threat_frame, 
            text="NORMAL", 
            font=('Helvetica', 16, 'bold'), 
            foreground="green"
        )
        self.threat_level.pack(pady=5)
        
        # Threat Meter with fallback
        try:
            from PIL import Image
            self.threat_meter = ttk.Meter(
                threat_frame,
                metersize=150,
                amountused=0,
                metertype="semi",
                subtext="Threat Level",
                interactive=False,
                bootstyle="info"
            )
        except (ImportError, AttributeError) as e:
            print(f"Using Progressbar fallback: {e}")
            self.threat_meter = ttk.Progressbar(
                threat_frame,
                length=150,
                mode='determinate',
                bootstyle="info-striped"
            )
        self.threat_meter.pack(pady=5)

    def create_logs_tab(self):
        """Create the logs tab with advanced filtering and display"""
        # Create the tab frame
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")
        
        # Filter controls frame
        filter_frame = ttk.Frame(self.logs_tab)
        filter_frame.pack(fill=X, padx=10, pady=5)
        
        # Filter label
        ttk.Label(filter_frame, text="Filter:").pack(side=LEFT, padx=5)
        
        # Log level filter combobox
        self.log_filter = ttk.Combobox(
            filter_frame, 
            values=["All", "Info", "Warning", "Error", "Critical"],
            state="readonly",
            width=10
        )
        self.log_filter.current(0)
        self.log_filter.pack(side=LEFT, padx=5)
        self.log_filter.bind("<<ComboboxSelected>>", self.filter_logs)
        
        # Search entry
        self.search_entry = ttk.Entry(filter_frame)
        self.search_entry.pack(side=LEFT, padx=5, fill=X, expand=True)
        self.search_entry.bind("<KeyRelease>", self.filter_logs)
        
        # Log display area
        self.log_box = ScrolledText(
            self.logs_tab, 
            height=20, 
            width=100, 
            state=DISABLED,
            autohide=True,
            bootstyle="round"
        )
        self.log_box.pack(fill=BOTH, expand=True, padx=10, pady=5)
        
        # Apply text tags for coloring
        self.log_box.text.tag_config("info", foreground="black")
        self.log_box.text.tag_config("warning", foreground="orange")
        self.log_box.text.tag_config("error", foreground="red")
        self.log_box.text.tag_config("critical", foreground="red", font=('Helvetica', 9, 'bold'))
        
        # Log control buttons
        btn_frame = ttk.Frame(self.logs_tab)
        btn_frame.pack(fill=X, padx=10, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="Clear Logs", 
            command=self.clear_logs,
            bootstyle="outline"
        ).pack(side=LEFT, padx=5)
        
        ttk.Button(
            btn_frame, 
            text="Export Logs", 
            command=self.export_logs,
            bootstyle="outline"
        ).pack(side=RIGHT, padx=5)
        
        # Initial log load
        self.filter_logs()

    def create_history_tab(self):
        """Create the history tab with table"""
        self.history_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.history_tab, text="History")
        
        # Get history data with fallback
        history_data = getattr(self.protection_system, 'history_data', [])
        
        # Create tableview
        self.history_table = Tableview(
            master=self.history_tab,
            coldata=[
                {"text": "Timestamp", "stretch": False, "width": 150},
                {"text": "Item", "stretch": True},
                {"text": "Action", "stretch": True}
            ],
            rowdata=history_data,
            searchable=True,
            bootstyle="primary",
            paginated=True
        )
        self.history_table.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Add right-click menu (use the view attribute instead of table)
        self.history_menu = ttk.Menu(self, tearoff=0)
        self.history_menu.add_command(label="View Details", command=self.show_history_details)
        self.history_table.view.bind("<Button-3>", self.show_history_menu)

    def show_history_menu(self, event):
        """Show context menu for history items"""
        try:
            row = self.history_table.view.identify_row(event.y)
            self.history_table.view.selection_set(row)
            self.history_menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(f"Error showing history menu: {e}")

    def create_detected_tab(self):
        """Create the detected threats tab with proper Tableview implementation"""
        self.detected_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.detected_tab, text="Detected Threats")
        
        # Get detected items with fallback
        detected_data = getattr(self.protection_system, 'detected_files_data', [])
        
        # Create tableview
        self.detected_table = Tableview(
            master=self.detected_tab,
            coldata=[
                {"text": "Timestamp", "stretch": False, "width": 150},
                {"text": "Type", "stretch": False, "width": 100},
                {"text": "Name", "stretch": True},
                {"text": "Status", "stretch": False, "width": 120},
                {"text": "Threat Level", "stretch": False, "width": 100}
            ],
            rowdata=detected_data,
            searchable=True,
            bootstyle="warning",
            paginated=True
        )
        self.detected_table.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Apply row styling - NEW CORRECT WAY
        for i, item in enumerate(detected_data):
            if len(item) > 4:  # Check if threat level exists
                threat_level = item[4].lower()
                if threat_level == "low":
                    self.detected_table.view.tag_configure(f"row{i}", background="#5cb85c", foreground="white")
                elif threat_level == "medium":
                    self.detected_table.view.tag_configure(f"row{i}", background="#f0ad4e")
                elif threat_level == "high":
                    self.detected_table.view.tag_configure(f"row{i}", background="#d9534f", foreground="white")
                elif threat_level == "critical":
                    self.detected_table.view.tag_configure(f"row{i}", background="#d9534f", foreground="white", font=('Helvetica', 9, 'bold'))
                self.detected_table.view.item(self.detected_table.view.get_children()[i], tags=(f"row{i}",))

    def create_rollback_tab(self):
        """Create the rollback tab"""
        self.rollback_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.rollback_tab, text="Rollback")
        
        self.rollback_table = Tableview(
            self.rollback_tab,
            coldata=[
                {"text": "Timestamp", "stretch": False, "width": 150},
                {"text": "Name", "stretch": True},
                {"text": "Status", "stretch": False, "width": 120}
            ],
            rowdata=self.protection_system.rollbacked_files_data,
            searchable=True,
            autofit=True,
            bootstyle="success",
            paginated=True
        )
        self.rollback_table.pack(fill=BOTH, expand=True, padx=10, pady=10)
        
        # Rollback controls
        btn_frame = ttk.Frame(self.rollback_tab)
        btn_frame.pack(fill=X, padx=10, pady=5)
        
        ttk.Button(
            btn_frame, 
            text="Rollback Now", 
            command=self.manual_rollback,
            bootstyle="outline"
        ).pack(side=RIGHT, padx=5)

    def create_settings_tab(self):
        """Create the settings tab"""
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Settings")
        
        # Protection settings
        protection_frame = ttk.LabelFrame(self.settings_tab, text="Protection Settings", padding=10)
        protection_frame.pack(fill=X, padx=10, pady=5)
        
        self.realtime_protection = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            protection_frame,
            text="Enable real-time protection",
            variable=self.realtime_protection,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        self.heuristic_analysis = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            protection_frame,
            text="Enable heuristic analysis",
            variable=self.heuristic_analysis,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        self.auto_rollback = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            protection_frame,
            text="Enable automatic rollback",
            variable=self.auto_rollback,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        # Notification settings
        notify_frame = ttk.LabelFrame(self.settings_tab, text="Notification Settings", padding=10)
        notify_frame.pack(fill=X, padx=10, pady=5)
        
        self.email_alerts = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            notify_frame,
            text="Enable email alerts",
            variable=self.email_alerts,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        self.desktop_alerts = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            notify_frame,
            text="Enable desktop notifications",
            variable=self.desktop_alerts,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        self.sound_alerts = ttk.BooleanVar(value=True)
        ttk.Checkbutton(
            notify_frame,
            text="Enable sound alerts",
            variable=self.sound_alerts,
            bootstyle="round-toggle"
        ).pack(anchor=W, pady=2)
        
        # Save button
        btn_frame = ttk.Frame(self.settings_tab)
        btn_frame.pack(fill=X, padx=10, pady=10)
        
        ttk.Button(
            btn_frame,
            text="Save Settings",
            command=self.save_settings,
            bootstyle="success"
        ).pack(side=RIGHT, padx=5)

    def create_status_bar(self):
        """Create the status bar at bottom of window"""
        self.status_bar = ttk.Frame(self)
        self.status_bar.pack(fill=X, side=BOTTOM, pady=2)
        
        self.status_message = ttk.Label(
            self.status_bar,
            text="Ready",
            relief=SUNKEN,
            anchor=W
        )
        self.status_message.pack(fill=X, padx=5)
        
        self.version_label = ttk.Label(
            self.status_bar,
            text="v1.0.0",
            relief=SUNKEN,
            anchor=E,
            width=10
        )
        self.version_label.pack(side=RIGHT, padx=5)

    def update_system_stats(self):
     """Periodically update system statistics"""
     stats = self.protection_system.get_system_stats()

     self.stats_labels['files_protected'].config(text=f"Files Protected: {stats.get('files_protected', 0)}")
     self.stats_labels['threats_blocked'].config(text=f"Threats Blocked: {stats.get('threats_blocked', 0)}")
     self.stats_labels['files_restored'].config(text=f"Files Restored: {stats.get('files_restored', 0)}")

     last_threat = stats.get('last_threat')

     if last_threat:
        try:
            last_threat_time = datetime.strptime(last_threat, '%Y-%m-%d %H:%M:%S')
            self.stats_labels['last_threat'].config(text=f"Last Threat: {last_threat}")
            
            threat_age = (datetime.now() - last_threat_time).total_seconds()

            if threat_age < 3600:
                self.set_threat_level("high", 75)
            elif threat_age < 86400:
                self.set_threat_level("medium", 50)
            else:
                self.set_threat_level("low", 25)

        except ValueError as e:
            self.stats_labels['last_threat'].config(text="Last Threat: Invalid format")
            print(f"[!] Error parsing last threat timestamp: {e}")
            self.set_threat_level("normal", 0)
     else:
        self.stats_labels['last_threat'].config(text="Last Threat: Never")
        self.set_threat_level("normal", 0)

     self.after(5000, self.update_system_stats)  # Update every 5 seconds

    def set_threat_level(self, level, meter_value):
        """Update the threat level indicator"""
        colors = {
            "normal": "green",
            "low": "green",
            "medium": "orange",
            "high": "red",
            "critical": "darkred"
        }
        
        self.threat_level.config(
            text=level.upper(),
            foreground=colors.get(level, "green")
        )
        
        self.threat_meter.configure(amountused=meter_value)
        
        if level in ["high", "critical"]:
            self.threat_meter.configure(bootstyle="danger")
        elif level == "medium":
            self.threat_meter.configure(bootstyle="warning")
        else:
            self.threat_meter.configure(bootstyle="success")

    def log_message(self, message):
     """Update log box with messages"""
     if hasattr(self, 'log_box') and self.log_box:
        self.log_box.text.config(state=NORMAL)
        
        # Color coding based on log level
        if message.startswith("[ERROR]"):
            self.log_box.text.tag_config("error", foreground="red")
            self.log_box.text.insert(END, message + "\n", "error")
        elif message.startswith("[WARNING]"):
            self.log_box.text.tag_config("warning", foreground="orange")
            self.log_box.text.insert(END, message + "\n", "warning")
        elif message.startswith("[CRITICAL]"):
            self.log_box.text.tag_config("critical", foreground="red", font=('Helvetica', 9, 'bold'))
            self.log_box.text.insert(END, message + "\n", "critical")
        else:
            self.log_box.text.insert(END, message + "\n")
        
        self.log_box.text.config(state=DISABLED)
        self.log_box.text.yview(END)
    
    # Update status bar if it exists
     if hasattr(self, 'status_message') and self.status_message:
        self.status_message.config(text=message.split("]")[-1].strip())

    def filter_logs(self, event=None):
        """Filter logs based on selected level and search text"""
        level_filter = self.log_filter.get()
        search_text = self.search_entry.get().lower()
        
        self.log_box.text.config(state=NORMAL)
        self.log_box.text.delete(1.0, END)
        
        try:
            with open("ransomware_system.log", "r") as f:
                for line in f:
                    if level_filter != "All" and f" - {level_filter.upper()} - " not in line:
                        continue
                    if search_text and search_text not in line.lower():
                        continue
                    
                    # Apply appropriate tag based on log level
                    if " - ERROR - " in line:
                        self.log_box.text.insert(END, line, "error")
                    elif " - WARNING - " in line:
                        self.log_box.text.insert(END, line, "warning")
                    elif " - CRITICAL - " in line:
                        self.log_box.text.insert(END, line, "critical")
                    else:
                        self.log_box.text.insert(END, line, "info")
                        
        except FileNotFoundError:
            self.log_box.text.insert(END, "No log file found\n")
        except Exception as e:
            self.log_box.text.insert(END, f"Error reading logs: {str(e)}\n")
        
        self.log_box.text.config(state=DISABLED)
        self.log_box.text.yview(END)

    def clear_logs(self):
        """Clear the log display"""
        self.log_box.text.config(state=NORMAL)
        self.log_box.text.delete(1.0, END)
        self.log_box.text.config(state=DISABLED)

    def export_logs(self):
        """Export logs to a file"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filepath:
            try:
                with open(filepath, "w") as f:
                    f.write(self.log_box.text.get(1.0, END))
                    messagebox.showinfo("Success", "Logs exported successfully")
            except Exception as e:
                    messagebox.showerror("Error", f"Failed to export logs: {str(e)}")

    def update_history_display(self):
        """Update the history table"""
        self.history_table.load_table_data(self.protection_system.history_data)

    def update_detected_display(self):
        """Update the detected threats table with color coding"""
        self.detected_table.load_table_data(self.protection_system.detected_files_data)
        
        # Apply threat level coloring
        for i, item in enumerate(self.protection_system.detected_files_data):
            threat_level = item[4].lower() if len(item) > 4 else "medium"
            self.detected_table.table.tag_row(i, threat_level)

    def update_rollbacked_display(self):
        """Update the rollback table"""
        self.rollback_table.load_table_data(self.protection_system.rollbacked_files_data)

    def show_history_details(self):
        """Show details for selected history item with enhanced formatting and error handling"""
        try:
            # Get the selected row from the table
            selected_row = self.history_table.get_selected_row()
            
            if not selected_row:
                messagebox.showwarning("No Selection", "Please select an event first")
                return
            
            # Create a formatted details message
            details = [
                f"Timestamp: {selected_row.values[0]}",
                f"Item: {selected_row.values[1]}", 
                f"Action: {selected_row.values[2]}",
            ]
            
            # Add additional details if they exist
            if len(selected_row.values) > 3:
                details.append(f"\nAdditional Details:\n{selected_row.values[3]}")
            
            # Show the details in a scrollable text window for long messages
            detail_window = ttk.Toplevel(self)
            detail_window.title("Event Details")
            detail_window.geometry("500x300")
            
            text_frame = ttk.Frame(detail_window)
            text_frame.pack(fill=BOTH, expand=True, padx=10, pady=10)
            
            text_widget = ScrolledText(text_frame, wrap=WORD)
            text_widget.pack(fill=BOTH, expand=True)
            
            # Insert the details with formatting
            text_widget.insert(END, "\n".join(details))
            text_widget.config(state=DISABLED)  # Make it read-only
            
            # Add a close button
            button_frame = ttk.Frame(detail_window)
            button_frame.pack(fill=X, padx=10, pady=5)
            
            ttk.Button(
                button_frame,
                text="Close",
                command=detail_window.destroy,
                bootstyle="primary"
            ).pack(side=RIGHT)
            
        except Exception as e:
            error_msg = f"Error showing event details: {str(e)}"
            logging.error(error_msg, exc_info=True)
            messagebox.showerror("Error", error_msg)

    def manual_rollback(self):
        """Initiate manual rollback"""
        if not self.protection_system.rollback_active:
            Messagebox.show_warning(
                "Rollback module is not active",
                "Please start protection first",
                parent=self
            )
            return
            
        answer = Messagebox.show_question(
            "This will attempt to restore all recently modified files. Continue?",
            "Confirm Rollback",
            parent=self
        )
        
        if answer == "Yes":
            self.protection_system.rollback_system.manual_rollback()
            self.log_message("[INFO] Manual rollback initiated")

    def update_dashboard_status(self, status, color):
        """Update the status label"""
        self.status_label.config(text=f"Status: {status}", foreground=color)

    def update_module_statuses(self, status, color="orange"):
        """Update module status labels"""
        if status == "Starting...":
            for label in self.module_status.values():
                label.config(text=f"{label.cget('text').split(':')[0]}: {status}", foreground=color)
        else:
            self.module_status['detection'].config(
                text=f"Detection: {'Active' if self.protection_system.detection_active else 'Stopped'}",
                foreground="green" if self.protection_system.detection_active else "red"
            )
            self.module_status['prevention'].config(
                text=f"Prevention: {'Active' if self.protection_system.prevention_active else 'Stopped'}",
                foreground="green" if self.protection_system.prevention_active else "red"
            )
            self.module_status['rollback'].config(
                text=f"Rollback: {'Active' if self.protection_system.rollback_active else 'Stopped'}",
                foreground="green" if self.protection_system.rollback_active else "red"
            )
            self.module_status['file_monitor'].config(
                text=f"File Monitor: {'Active' if self.protection_system.file_monitoring_active else 'Stopped'}",
                foreground="green" if self.protection_system.file_monitoring_active else "red"
            )

    def enable_stop_buttons(self):
        """Enable stop button"""
        self.stop_btn.config(state=NORMAL)

    def disable_stop_buttons(self):
        """Disable stop button"""
        self.stop_btn.config(state=DISABLED)

    def enable_start_buttons(self):
        """Enable start button"""
        self.start_btn.config(state=NORMAL)

    def disable_start_buttons(self):
        """Disable start button"""
        self.start_btn.config(state=DISABLED)

    def start_monitoring(self):
        """Start all protection modules"""
        self.start_btn.config(state=DISABLED)
        self.stop_btn.config(state=NORMAL)
        self.update_dashboard_status("Starting...", "orange")
        self.protection_system.run_all()

    def stop_monitoring(self):
        """Stop all protection modules"""
        self.protection_system.stop_all()
        self.start_btn.config(state=NORMAL)
        self.stop_btn.config(state=DISABLED)

    def simulate_attack(self):
        """Simulate a ransomware attack for testing"""
        if not self.protection_system.monitoring:
            Messagebox.show_warning(
                "System not running",
                "Please start protection first",
                parent=self
            )
            return
            
        answer = Messagebox.show_question(
            "This will simulate a ransomware attack for testing. Continue?",
            "Confirm Simulation",
            parent=self
        )
        
        if answer == "Yes":
            self.log_message("[WARNING] Simulating ransomware attack...")
            self.set_threat_level("critical", 100)
            
            # Simulate detection
            self.protection_system.add_detected_item(
                "Process", 
                "ransomware_simulator.exe", 
                "Terminated", 
                "critical"
            )
            
            # Simulate file encryption
            self.protection_system.add_detected_item(
                "File", 
                "test_document.docx.encrypted", 
                "Quarantined", 
                "high"
            )
            
            # Simulate rollback
            self.protection_system.add_rollbacked_item(
                "test_document.docx", 
                "Restored"
            )
            
            # Play alert sound
            play_alert_sound()
            
            self.log_message("[WARNING] Simulation complete. System responded correctly.")

    def save_settings(self):
        """Save system settings"""
        settings = {
            'realtime_protection': self.realtime_protection.get(),
            'heuristic_analysis': self.heuristic_analysis.get(),
            'auto_rollback': self.auto_rollback.get(),
            'email_alerts': self.email_alerts.get(),
            'desktop_alerts': self.desktop_alerts.get(),
            'sound_alerts': self.sound_alerts.get()
        }
        
        try:
            with open('settings.json', 'w') as f:
                json.dump(settings, f)
            self.log_message("[INFO] Settings saved successfully")
        except Exception as e:
            self.log_message(f"[ERROR] Failed to save settings: {str(e)}")

    def load_settings(self):
        """Load system settings"""
        try:
            with open('settings.json', 'r') as f:
                settings = json.load(f)
                
            self.realtime_protection.set(settings.get('realtime_protection', True))
            self.heuristic_analysis.set(settings.get('heuristic_analysis', True))
            self.auto_rollback.set(settings.get('auto_rollback', True))
            self.email_alerts.set(settings.get('email_alerts', True))
            self.desktop_alerts.set(settings.get('desktop_alerts', True))
            self.sound_alerts.set(settings.get('sound_alerts', True))
            
            self.log_message("[INFO] Settings loaded successfully")
        except FileNotFoundError:
            self.log_message("[INFO] No settings file found, using defaults")
        except Exception as e:
            self.log_message(f"[ERROR] Failed to load settings: {str(e)}")

    def on_close(self):
        """Handle window close event"""
        if self.protection_system.monitoring:
            answer = Messagebox.show_question(
                "Protection system is still running. Close anyway?",
                "Confirm Exit",
                parent=self
            )
            if answer != "Yes":
                return
                
        self.protection_system.stop_all()
        self.destroy()

if __name__ == "__main__":
    app = EnhancedRansomwareGUI()
    app.protocol("WM_DELETE_WINDOW", app.on_close)
    app.load_settings()
    app.mainloop()
   