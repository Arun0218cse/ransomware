import psutil
import time
import logging
import pickle
import hashlib
import socket
import json
import os
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from collections import deque
from ai_models import AIModelManager
import joblib

# Configure enhanced logging
logging.basicConfig(
    filename='detection_history.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filemode='a'  # Append mode
)
logger = logging.getLogger(__name__)

# Define features with baseline thresholds
FEATURES = {
    'cpu_percent': {'threshold': 80, 'weight': 0.15},
    'memory_percent': {'threshold': 85, 'weight': 0.15},
    'disk_read_count': {'threshold': 1000, 'weight': 0.1},
    'disk_write_count': {'threshold': 1000, 'weight': 0.1},
    'network_bytes_sent': {'threshold': 10000000, 'weight': 0.1},
    'network_bytes_recv': {'threshold': 10000000, 'weight': 0.1},
    'process_count': {'threshold': 200, 'weight': 0.05},
    'thread_count': {'threshold': 1000, 'weight': 0.05},
    'file_rename_count': {'threshold': 50, 'weight': 0.15},
    'suspicious_process_count': {'threshold': 1, 'weight': 0.1}
}

class WindowsRansomwareDetector:
    def __init__(self, model_path='ransomware_model.pkl', config_file='detector_config.json'):
        self.model = self.load_model(model_path)
        self.config = self.load_config(config_file)
        self.metric_history = deque(maxlen=60)  # Track last minute of metrics
        self.suspicious_keywords = self.load_keywords()
        self.known_ransomware_hashes = self.load_known_hashes()
        
        if self.model is None:
            logger.warning("No trained model found. Using heuristic detection only.")

    def load_config(self, config_file):
        """Load detector configuration from JSON file"""
        try:
            with open(config_file) as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Config file {config_file} not found, using defaults")
            return {'scan_interval': 10, 'alert_threshold': 0.85}
        except Exception as e:
            logger.error(f"Error loading config: {e}")
            return {'scan_interval': 10, 'alert_threshold': 0.85}

    def load_keywords(self):
        """Load suspicious keywords for process detection"""
        try:
            with open('suspicious_keywords.json') as f:
                return json.load(f)
        except FileNotFoundError:
            return ["encrypt", "ransom", "locky", "cryptolocker", "wannacry"]
        except Exception as e:
            logger.error(f"Error loading keywords: {e}")
            return ["encrypt", "ransom", "locky", "cryptolocker", "wannacry"]

    def load_known_hashes(self):
        """Load known ransomware file hashes"""
        try:
            with open('known_hashes.json') as f:
                return json.load(f)
        except FileNotFoundError:
            return []
        except Exception as e:
            logger.error(f"Error loading known hashes: {e}")
            return []

    def load_model(self, model_path):
        """Loads a pre-trained ransomware detection model with enhanced error handling"""
        try:
            with open(model_path, 'rb') as f:
                model = pickle.load(f)
            logger.info(f"Successfully loaded model from {model_path}")
            return model
        except FileNotFoundError:
            logger.warning(f"Model file not found at {model_path}")
            return None
        except pickle.UnpicklingError:
            logger.error(f"Model file {model_path} is corrupted")
            return None
        except Exception as e:
            logger.error(f"Unexpected error loading model: {e}")
            return None

    def collect_system_metrics(self):
        """Collects comprehensive system metrics with enhanced monitoring"""
        metrics = {}
        try:
            # CPU and Memory
            metrics['cpu_percent'] = psutil.cpu_percent(interval=1)
            metrics['memory_percent'] = psutil.virtual_memory().percent

            # Disk I/O
            disk_io = psutil.disk_io_counters()
            metrics['disk_read_count'] = disk_io.read_count
            metrics['disk_write_count'] = disk_io.write_count

            # Network
            net_io = psutil.net_io_counters()
            metrics['network_bytes_sent'] = net_io.bytes_sent
            metrics['network_bytes_recv'] = net_io.bytes_recv

            # Processes
            metrics['process_count'] = len(psutil.pids())
            metrics['thread_count'] = sum(p.num_threads() for p in psutil.process_iter())

            # Additional metrics
            metrics['file_rename_count'] = self.check_file_renames()
            metrics['suspicious_process_count'] = len(self.analyze_suspicious_processes(quick_scan=True))

            # Store timestamp
            metrics['timestamp'] = datetime.now().isoformat()

            self.metric_history.append(metrics)
            return metrics

        except Exception as e:
            logger.error(f"Error collecting system metrics: {e}", exc_info=True)
            return None

    def detect_ransomware(self, metrics):
        """Enhanced detection using both model and heuristic analysis"""
        detection_score = 0.0
        
        # Use machine learning model if available
        if self.model:
            try:
                feature_vector = [metrics.get(feature, 0) for feature in FEATURES]
                detection_score = self.model.predict_proba([feature_vector])[0][1]  # Probability of ransomware
                logger.debug(f"Model detection score: {detection_score:.2f}")
            except Exception as e:
                logger.error(f"Model prediction error: {e}")

        # Add heuristic analysis
        heuristic_score = self.heuristic_analysis(metrics)
        combined_score = (detection_score * 0.7) + (heuristic_score * 0.3)
        
        logger.info(f"Combined detection score: {combined_score:.2f}")
        return combined_score > self.config.get('alert_threshold', 0.85)

    def heuristic_analysis(self, metrics):
        """Computes a heuristic score based on threshold violations"""
        score = 0.0
        for feature, params in FEATURES.items():
            value = metrics.get(feature, 0)
            threshold = params['threshold']
            weight = params['weight']
            
            if value > threshold:
                # Scale the contribution based on how much we exceed the threshold
                excess = min((value - threshold) / threshold, 2.0)  # Cap at 2x threshold
                score += weight * (excess / 2.0)  # Normalize to 0-1 range
                
        return min(score, 1.0)  # Cap at 1.0

    def analyze_suspicious_processes(self, quick_scan=False):
        """Enhanced process analysis with hash checking"""
        suspicious_processes = []
        checked_hashes = set()
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
            try:
                proc_info = proc.info
                
                # Skip if quick scan and process is old
                if quick_scan and (time.time() - proc_info['create_time']) > 3600:
                    continue
                    
                # Check process name and cmdline
                name = proc_info['name'].lower()
                cmdline = " ".join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ""
                
                # Check against keywords
                keyword_match = any(
                    keyword in name or keyword in cmdline
                    for keyword in self.suspicious_keywords
                )
                
                # Check executable hash if path exists
                hash_match = False
                if proc_info['exe'] and os.path.exists(proc_info['exe']):
                    file_hash = self.calculate_file_hash(proc_info['exe'])
                    if file_hash in self.known_ransomware_hashes:
                        hash_match = True
                
                if keyword_match or hash_match:
                    proc_info['detection_reason'] = (
                        "keyword_match" if keyword_match else "hash_match"
                    )
                    suspicious_processes.append(proc_info)
                    logger.warning(
                        f"Suspicious process: PID={proc_info['pid']} "
                        f"Name='{proc_info['name']}' "
                        f"Reason={proc_info['detection_reason']}"
                    )
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.error(f"Error analyzing process: {e}")
                
        return suspicious_processes

    def calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of a file"""
        try:
            hasher = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except Exception as e:
            logger.error(f"Error calculating hash for {filepath}: {e}")
            return None

    def check_file_renames(self):
        """Placeholder for file rename monitoring"""
        # In a real implementation, this would use filesystem monitoring
        # For now, we return 0 but this should be implemented properly
        return 0

    def analyze_network_connections(self):
        """Analyze network connections for suspicious activity"""
        suspicious_connections = []
        known_bad_ips = ["1.1.1.1", "2.2.2.2"]  # Example - should be loaded from config
        
        try:
            for conn in psutil.net_connections():
                if conn.status == 'ESTABLISHED' and conn.raddr:
                    ip = conn.raddr.ip
                    if ip in known_bad_ips:
                        suspicious_connections.append({
                            'pid': conn.pid,
                            'local_address': conn.laddr,
                            'remote_address': conn.raddr,
                            'status': conn.status
                        })
        except Exception as e:
            logger.error(f"Error analyzing network connections: {e}")
            
        return suspicious_connections

if __name__ == '__main__':
    try:
        detector = WindowsRansomwareDetector()
        logger.info("Ransomware Detector Initialized")
        
        while True:
            start_time = time.time()
            
            # Collect and analyze metrics
            metrics = detector.collect_system_metrics()
            if metrics:
                if detector.detect_ransomware(metrics):
                    logger.critical("POTENTIAL RANSOMWARE ACTIVITY DETECTED")
                    
                    # Detailed investigation
                    suspicious_processes = detector.analyze_suspicious_processes()
                    suspicious_connections = detector.analyze_network_connections()
                    
                    # Here you would typically trigger alerts and prevention mechanisms
                    
            # Sleep for the remaining interval time
            elapsed = time.time() - start_time
            sleep_time = max(0, detector.config.get('scan_interval', 10) - elapsed)
            time.sleep(sleep_time)
            
    except KeyboardInterrupt:
        logger.info("Detector stopped by user")
    except Exception as e:
        logger.critical(f"Detector crashed: {e}", exc_info=True)
        # Add to imports
from ai_models import AIModelManager

class WindowsRansomwareDetector:
    def __init__(self, model_path='ransomware_model.pkl', config_file='detector_config.json'):
        self.model = self.load_model(model_path)
        self.config = self.load_config(config_file)
        self.metric_history = deque(maxlen=60)
        self.suspicious_keywords = self.load_keywords()
        self.known_ransomware_hashes = self.load_known_hashes()
        self.ai_model = AIModelManager()  # Add AI model manager
        
        if self.model is None:
            logger.warning("No trained model found. Using heuristic and AI detection.")

    def load_model(self, model_path):
        """Load the ML model from disk."""
        if os.path.exists(model_path):
            try:
                model = joblib.load(model_path)
                logger.info(f"Loaded model from: {model_path}")
                return model
            except Exception as e:
                logger.error(f"Error loading model: {e}")
        else:
            logger.warning(f"Model path not found: {model_path}")
        return None
    def load_config(self, path):
        try:
          with open(path, 'r') as f:
            return json.load(f)
        except Exception as e:
         logger.error(f"Failed to load config: {e}")
        return {"alert_threshold": 0.85}

    def load_keywords(self):
      return ["encrypt", "ransom", "decrypt", "locker"]  # Extend as needed

    def load_known_hashes(self):
      return set()  # Load from file if available

    # Add new AI-enhanced detection method
    def ai_enhanced_detect(self, metrics):
        """Enhanced detection combining ML model and AI analysis"""
        # Traditional model detection
        model_score = 0
        if self.model:
            try:
                feature_vector = [metrics.get(feature, 0) for feature in FEATURES]
                model_score = self.model.predict_proba([feature_vector])[0][1]
            except Exception as e:
                logger.error(f"Model prediction error: {e}")
        
        # AI system metrics analysis
        ai_result = self.ai_model.analyze_system_metrics(metrics)
        ai_score = 0.5  # Default neutral score
        
        if ai_result:
            # Convert AI results to a score (0-1)
            ai_score = 0.5 + (0.5 * ai_result['current_anomaly']) + (0.1 * ai_result['trend_anomalies'])
            ai_score = max(0, min(1, ai_score))  # Clamp to 0-1 range
            
        # Combined score with model weighting
        combined_score = (model_score * 0.6) + (ai_score * 0.4)
        
        logger.info(f"AI-enhanced detection - Model: {model_score:.2f}, AI: {ai_score:.2f}, Combined: {combined_score:.2f}")
        return combined_score > self.config.get('alert_threshold', 0.85)
    
    # Update the detect_ransomware method to use AI-enhanced detection
    def detect_ransomware(self, metrics):
        """Detect ransomware using combined approaches"""
        return self.ai_enhanced_detect(metrics)
    
    # Add AI-enhanced process analysis
    def analyze_suspicious_processes(self, quick_scan=False):
        """Enhanced process analysis with AI"""
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                        'cpu_percent', 'memory_percent', 'num_threads']):
            try:
                proc_info = proc.info
                
                if quick_scan and (time.time() - proc_info['create_time']) > 3600:
                    continue
                    
                # AI analysis
                ai_result = self.ai_model.analyze_process(proc_info)
                
                # Combine with traditional detection
                name = proc_info['name'].lower()
                cmdline = " ".join(proc_info['cmdline']).lower() if proc_info['cmdline'] else ""
                
                keyword_match = any(keyword in name or keyword in cmdline 
                                  for keyword in self.suspicious_keywords)
                
                hash_match = False
                if proc_info['exe'] and os.path.exists(proc_info['exe']):
                    file_hash = self.calculate_file_hash(proc_info['exe'])
                    hash_match = file_hash in self.known_ransomware_hashes
                
                # Determine threat level based on all indicators
                threat_level = "low"
                if keyword_match or hash_match:
                    threat_level = "high"
                elif ai_result and ai_result['malicious_prob'] > 0.7:
                    threat_level = "medium"
                
                if threat_level != "low":
                    proc_info['threat_level'] = threat_level
                    proc_info['ai_score'] = ai_result['malicious_prob'] if ai_result else 0
                    suspicious_processes.append(proc_info)
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
                
        return suspicious_processes