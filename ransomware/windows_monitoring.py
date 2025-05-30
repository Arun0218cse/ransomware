import threading
import time
import logging
import os
import csv
import psutil
import ttkbootstrap as ttk
import numpy as np
import pandas as pd # type: ignore
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from joblib import dump, load
from ttkbootstrap.constants import *
from tkinter import messagebox, Toplevel, Label, Button, Scrollbar, Text, Frame, filedialog
from tkinter.scrolledtext import ScrolledText
from plyer import notification
from datetime import datetime

# Setup Logging
LOG_FILE = "windows_monitoring.csv"
LOGGING_FORMAT = "%(asctime)s - %(message)s"

if not os.path.exists(LOG_FILE):
    with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
        csv.writer(f).writerow(["Timestamp", "CPU_Usage(%)", "Memory_Usage(%)", "Memory_Used(MB)", "Memory_Available(MB)", "Disk_IO(Bytes)", "Network_IO(Bytes)", "Num_Processes", "Status"])

logging.basicConfig(filename="windows_monitoring.log", level=logging.INFO, encoding="utf-8", format=LOGGING_FORMAT)

class WindowsMonitoring:
    def __init__(self, gui):
        self.gui = gui
        self.running = threading.Event()
        self.thresholds = {"cpu": 85, "memory": 90, "disk_io": 500_000_000, "network_io": 100_000_000}
        self.history_data = []
        self.detected_anomalies = []
        self.ai_model = AIModel()  # Add AI model
        self.ai_analysis_interval = 60  # Run AI analysis every 60 seconds
        self.last_ai_analysis = 0
        
    # ... (keep existing methods)
    
    def monitor_system(self):
        self.running.set()
        start_time = time.time()
        
        while self.running.is_set():
            metrics = self.collect_system_metrics()
            self.gui.update_metrics(metrics)
            
            # Run AI analysis periodically
            current_time = time.time()
            if current_time - self.last_ai_analysis > self.ai_analysis_interval:
                self.last_ai_analysis = current_time
                self.run_ai_analysis()
            
            if metrics["cpu_usage"] > 95 or metrics["memory_usage_percent"] > 95:
                self.gui.trigger_restart()
            time.sleep(5)
    
    def run_ai_analysis(self):
        """Run AI anomaly detection"""
        # First train model if not trained
        if not hasattr(self.ai_model.model, "estimators_"):
            if len(self.history_data) >= 60:  # Only train if we have enough data
                self.ai_model.train_model(self.history_data)
            return
            
        # Predict anomalies
        anomalies = self.ai_model.predict_anomalies(self.history_data)
        
        for anomaly in anomalies:
            message = (f"🤖 AI Warning: Potential anomaly detected (score: {anomaly['score']:.2f}). "
                      f"CPU: {anomaly['metrics']['cpu']}%, "
                      f"Memory: {anomaly['metrics']['memory']}%, "
                      f"Disk IO: {anomaly['metrics']['disk_io']}, "
                      f"Network IO: {anomaly['metrics']['network_io']}")
            
            self.detected_anomalies.append([anomaly["timestamp"], message])
            self.gui.update_detected_display()
            self.send_notification("AI Anomaly Alert", message)
            self.gui.update_log(message)
            

class MonitoringGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🖥 Windows System Monitor with AI")
        self.root.geometry("900x800")  # Slightly taller to accommodate new AI button
        self.root.resizable(False, False)
        self.style = ttk.Style("superhero")
        self.monitoring_system = WindowsMonitoring(self)
        self.create_widgets()
        self.history_window = None
        self.detected_window = None
        self.detection_history_window = None
        self.ai_status_window = None

    def create_widgets(self):
        # Main title
        ttk.Label(self.root, text="🖥 Windows System Monitoring with AI", 
                 font=("Arial", 18, "bold"), bootstyle="inverse-primary").pack(pady=10)
        
        # Metrics frame
        metrics_frame = ttk.Frame(self.root, bootstyle="secondary", padding=10)
        metrics_frame.pack(pady=5, fill="x", padx=10)
        for i in range(4):
            metrics_frame.columnconfigure(i, weight=1)
            
        # Metric labels
        labels_data = [
            ("CPU: 0%", 0, 0, "self.cpu_label"), 
            ("Memory: 0%", 0, 1, "self.memory_percent_label"),
            ("Used: 0 MB", 1, 1, "self.memory_usage_label"), 
            ("Available: 0 MB", 2, 1, "self.memory_available_label"),
            ("Disk IO: 0 Bytes", 0, 2, "self.disk_label"), 
            ("Network IO: 0 Bytes", 0, 3, "self.network_label"),
            ("Processes: 0", 1, 2, "self.process_label"), 
            ("Status: Normal", 1, 3, "self.status_label")
        ]
        
        for text, row, col, attr_name in labels_data:
            label = ttk.Label(metrics_frame, text=text, 
                            font=("Arial", 12 if row == 0 else 10), 
                            bootstyle="info" if row <= 1 else "secondary")
            label.grid(row=row, column=col, padx=5, pady=2, sticky="ew")
            setattr(self, attr_name, label)

        # CPU cores display
        cpu_cores_frame = ttk.LabelFrame(self.root, text="CPU Core Usage", 
                                        bootstyle="primary", padding=10)
        cpu_cores_frame.pack(pady=5, padx=10, fill="x")
        num_cores = psutil.cpu_count()
        self.core_labels = [ttk.Label(cpu_cores_frame, text=f"Core {i+1}: 0%", 
                                     font=("Arial", 10), bootstyle="info") 
                           for i in range(num_cores)]
        
        for i, label in enumerate(self.core_labels):
            label.grid(row=i // 4, column=i % 4, padx=5, pady=2, sticky="ew")
        
        # Fill empty grid spaces if needed
        for i in range((num_cores + 3) // 4 * 4 - num_cores):
            ttk.Label(cpu_cores_frame, text="", font=("Arial", 10)).grid(
                row=num_cores // 4, column=num_cores % 4 + i, padx=5, pady=2, sticky="ew")

        # System log
        ttk.Label(self.root, text="System Log:", font=("Arial", 10, "bold"), 
                 bootstyle="inverse-secondary").pack(pady=(10, 2), padx=10, anchor="w")
        self.log_box = ScrolledText(self.root, height=8, width=95, state="disabled", 
                                  bg="#2D2D2D", fg="white", font=("Arial", 10))
        self.log_box.pack(pady=5, padx=10, fill="x")

        # Main control buttons
        button_frame = ttk.Frame(self.root, padding=10)
        button_frame.pack(pady=10, fill="x")
        for i in range(3):
            button_frame.columnconfigure(i, weight=1)
            
        buttons_data = [
            ("🚀 Start Monitoring", self.start_monitoring, "success-outline", 0),
            ("🛑 Stop Monitoring", self.stop_monitoring, "danger-outline", 1, DISABLED),
            ("📜 View History", self.show_history, "info-outline", 2)
        ]
        
        self.start_btn, self.stop_btn = None, None
        for text, command, style, col, *state in buttons_data:
            btn = ttk.Button(button_frame, text=text, bootstyle=style, 
                            command=command, state=state[0] if state else NORMAL)
            btn.grid(row=0, column=col, padx=5, sticky="ew")
            if "Start" in text:
                self.start_btn = btn
            elif "Stop" in text:
                self.stop_btn = btn

        # AI and detection buttons
        ai_button_frame = ttk.Frame(self.root)
        ai_button_frame.pack(pady=5, fill="x")
        
        ttk.Button(ai_button_frame, text="🤖 Train AI Model", bootstyle="success-outline",
                  command=self.train_ai_model).pack(side=LEFT, padx=5, fill="x", expand=True)
        ttk.Button(ai_button_frame, text="🔍 AI Status", bootstyle="info-outline",
                  command=self.show_ai_status).pack(side=LEFT, padx=5, fill="x", expand=True)
        
        ttk.Button(self.root, text="🔍 Detection History", bootstyle="warning-outline",
                  command=self.show_detection_history).pack(pady=5, padx=10, fill="x")
        ttk.Button(self.root, text="⚠️ Detected Anomalies", bootstyle="danger-outline",
                  command=self.show_detected_anomalies).pack(pady=5, padx=10, fill="x")

    # ... (keep all existing methods like update_metrics, update_log, etc.)

    def train_ai_model(self):
        """Train the AI model with current data"""
        if len(self.monitoring_system.history_data) < 60:
            messagebox.showwarning("Insufficient Data", 
                                 "Need at least 60 data points to train the AI model.")
            return
            
        # Disable button during training
        for child in self.root.winfo_children():
            if isinstance(child, ttk.Button) and "Train AI Model" in child.cget("text"):
                child.config(state=DISABLED)
                
        self.update_log("🤖 Starting AI model training...")
        
        # Train in background thread
        threading.Thread(target=self._train_ai_in_thread, daemon=True).start()
    
    def _train_ai_in_thread(self):
        """Train AI model in background thread"""
        try:
            success = self.monitoring_system.ai_model.train_model(
                self.monitoring_system.history_data)
            
            self.root.after(0, lambda: self._handle_training_result(success))
        except Exception as e:
            self.root.after(0, lambda: self._handle_training_result(False, str(e)))
    
    def _handle_training_result(self, success, error_msg=None):
        """Handle the result of AI model training"""
        # Re-enable button
        for child in self.root.winfo_children():
            if isinstance(child, ttk.Button) and "Train AI Model" in child.cget("text"):
                child.config(state=NORMAL)
                
        if success:
            self.update_log("🤖 AI model trained successfully!")
            messagebox.showinfo("Success", "AI model trained successfully!")
        else:
            error_msg = error_msg or "Unknown error occurred"
            self.update_log(f"❌ Failed to train AI model: {error_msg}")
            messagebox.showerror("Error", f"Failed to train AI model:\n{error_msg}")
    
    def show_ai_status(self):
        """Show information about the AI model status"""
        if self.ai_status_window is None or not self.ai_status_window.winfo_exists():
            self.ai_status_window = Toplevel(self.root)
            self.ai_status_window.title("AI Model Status")
            
            status_frame = ttk.Frame(self.ai_status_window, padding=10)
            status_frame.pack(fill=BOTH, expand=True)
            
            # Model info
            ttk.Label(status_frame, text="AI Model Information", 
                     font=("Arial", 12, "bold")).pack(pady=5)
            
            model = self.monitoring_system.ai_model.model
            is_trained = hasattr(model, "estimators_") if model else False
            
            info_text = Text(status_frame, height=10, width=60, wrap=WORD)
            scrollbar = ttk.Scrollbar(status_frame, command=info_text.yview)
            info_text.config(yscrollcommand=scrollbar.set)
            scrollbar.pack(side=RIGHT, fill=Y)
            info_text.pack(fill=BOTH, expand=True)
            
            info_text.insert(END, f"Model Type: {type(model).__name__}\n")
            info_text.insert(END, f"Status: {'Trained' if is_trained else 'Not Trained'}\n")
            
            if is_trained:
                info_text.insert(END, f"\nTrained on: {len(self.monitoring_system.history_data)} data points\n")
                info_text.insert(END, f"Last Anomaly Detection: {self._get_last_anomaly_time()}\n")
                info_text.insert(END, f"\nModel Parameters:\n")
                for param, value in model.get_params().items():
                    info_text.insert(END, f"  {param}: {value}\n")
            
            info_text.config(state=DISABLED)
            
            # Close button
            ttk.Button(status_frame, text="Close", 
                      command=self.ai_status_window.destroy).pack(pady=10)
        else:
            self.ai_status_window.lift()
    
    def _get_last_anomaly_time(self):
        """Get the timestamp of the last detected anomaly"""
        if not self.monitoring_system.detected_anomalies:
            return "No anomalies detected yet"
            
        last_anomaly = self.monitoring_system.detected_anomalies[-1]
        return last_anomaly[0]  # Return timestamp

    # ... (keep all other existing methods)
class AIModel:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.model_file = "ai_model.joblib"
        self.scaler_file = "scaler.joblib"
        self.load_model()
        
    def load_model(self):
        """Load pre-trained model and scaler if they exist"""
        try:
            self.model = load(self.model_file)
            self.scaler = load(self.scaler_file)
            logging.info("AI Model loaded successfully")
        except:
            logging.warning("No pre-trained AI model found, will train new one")
            self.model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
    
    def save_model(self):
        """Save the trained model and scaler"""
        dump(self.model, self.model_file)
        dump(self.scaler, self.scaler_file)
        logging.info("AI Model saved successfully")
    
    def prepare_data(self, history_data):
        """Prepare monitoring data for the AI model"""
        if not history_data or len(history_data) < 10:
            return None
            
        # Convert to DataFrame
        df = pd.DataFrame(history_data, columns=[
            "timestamp", "cpu_usage", "memory_percent", "memory_used_mb",
            "memory_available_mb", "disk_io", "network_io", "num_processes", "status"
        ])
        
        # Select numerical features
        features = df[["cpu_usage", "memory_percent", "disk_io", "network_io", "num_processes"]]
        
        # Add rolling statistics
        for col in features.columns:
            features[f"{col}_rolling_avg"] = features[col].rolling(window=5).mean()
            features[f"{col}_rolling_std"] = features[col].rolling(window=5).std()
        
        # Drop NA values from rolling calculations
        features = features.dropna()
        
        if len(features) < 5:
            return None
            
        return features
    
    def train_model(self, history_data):
        """Train the anomaly detection model"""
        features = self.prepare_data(history_data)
        if features is None:
            logging.warning("Not enough data to train AI model")
            return False
            
        # Scale the features
        X_scaled = self.scaler.fit_transform(features)
        
        # Train the model
        self.model.fit(X_scaled)
        self.save_model()
        logging.info("AI Model trained successfully")
        return True
    
    def predict_anomalies(self, history_data):
        """Predict potential anomalies"""
        features = self.prepare_data(history_data)
        if features is None:
            return []
            
        # Scale the features
        X_scaled = self.scaler.transform(features)
        
        # Get predictions (-1 for anomalies, 1 for normal)
        predictions = self.model.predict(X_scaled)
        
        # Get anomaly scores (the lower, the more anomalous)
        scores = self.model.decision_function(X_scaled)
        
        # Prepare results
        anomalies = []
        for i, (pred, score) in enumerate(zip(predictions, scores)):
            if pred == -1:  # Anomaly detected
                last_row = history_data[-(len(predictions)-i)]
                anomalies.append({
                    "timestamp": last_row[0],
                    "metrics": {
                        "cpu": last_row[1],
                        "memory": last_row[2],
                        "disk_io": last_row[5],
                        "network_io": last_row[6]
                    },
                    "score": score
                })
        
        return anomalies

if __name__ == "__main__":
    root = ttk.Window(themename="superhero")
    app = MonitoringGUI(root)
    root.mainloop()