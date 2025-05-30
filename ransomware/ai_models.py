import os
import joblib
import math
import logging
import psutil
import numpy as np
import pandas as pd
from collections import deque
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM
from sklearn.cluster import DBSCAN
from sklearn.neighbors import LocalOutlierFactor

class AIModelManager:
    def __init__(self):
        self.models = {
            'file_entropy': self.init_file_entropy_model(),
            'process_behavior': self.init_process_behavior_model(),
            'network_traffic': self.init_network_traffic_model(),
            'system_metrics': self.init_system_metrics_model()
        }
        self.scalers = {}
        self.history = deque(maxlen=1000)  # Store recent metrics for trend analysis
        self.initialize_models()

    def initialize_models(self):
        model_dir = "ai_models"
        os.makedirs(model_dir, exist_ok=True)

        for model_name in self.models:
            model_path = os.path.join(model_dir, f"{model_name}.joblib")
            scaler_path = os.path.join(model_dir, f"{model_name}_scaler.joblib")

            try:
                self.models[model_name] = joblib.load(model_path)
                self.scalers[model_name] = joblib.load(scaler_path)
                logging.info(f"Loaded pre-trained {model_name} model")
            except:
                logging.warning(f"No pre-trained {model_name} model found, initializing new one")
                if model_name == 'file_entropy':
                    self.models[model_name] = IsolationForest(n_estimators=100, contamination=0.05)
                elif model_name == 'process_behavior':
                    self.models[model_name] = RandomForestClassifier(n_estimators=50)
                elif model_name == 'network_traffic':
                    self.models[model_name] = OneClassSVM(nu=0.05, kernel="rbf")
                elif model_name == 'system_metrics':
                    self.models[model_name] = LocalOutlierFactor(n_neighbors=20, contamination=0.05)

                self.scalers[model_name] = StandardScaler()

    # --------- Model Initializers ---------
    def init_file_entropy_model(self):
        return IsolationForest(n_estimators=100, contamination=0.05)

    def init_process_behavior_model(self):
        return RandomForestClassifier(n_estimators=50)

    def init_network_traffic_model(self):
        return OneClassSVM(nu=0.05, kernel="rbf")

    def init_system_metrics_model(self):
        return LocalOutlierFactor(n_neighbors=20, contamination=0.05)

    # --------- File Analysis ---------
    def analyze_file(self, filepath):
        try:
            features = self.extract_file_features(filepath)
            if features is None:
                return None

            scaled = self.scalers['file_entropy'].transform([features])
            prediction = self.models['file_entropy'].predict(scaled)
            score = self.models['file_entropy'].decision_function(scaled)

            return {
                'is_anomaly': prediction[0] == -1,
                'anomaly_score': float(score[0]),
                'features': features
            }
        except Exception as e:
            logging.error(f"File analysis error: {str(e)}")
            return None

    def extract_file_features(self, filepath):
        try:
            stats = os.stat(filepath)
            entropy = self.calculate_entropy(filepath)

            return [
                stats.st_size,
                entropy,
                len(filepath),
                filepath.count('.'),
                int(any(filepath.lower().endswith(ext) for ext in ['.encrypted', '.locked', '.crypt']))
            ]
        except Exception as e:
            logging.error(f"Error extracting file features: {str(e)}")
            return None

    def calculate_entropy(self, filepath, chunk_size=8192):
        entropy = 0
        counts = [0] * 256

        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for byte in chunk:
                        counts[byte] += 1

            total = sum(counts)
            if total == 0:
                return 0

            for count in counts:
                if count > 0:
                    p = count / total
                    entropy -= p * math.log(p, 2)

            return entropy
        except Exception:
            return 0

    # --------- Process Analysis ---------
    def analyze_process(self, process_info):
        try:
            features = self.extract_process_features(process_info)
            scaled = self.scalers['process_behavior'].transform([features])
            proba = self.models['process_behavior'].predict_proba(scaled)

            return {
                'malicious_prob': float(proba[0][1]),
                'features': features
            }
        except Exception as e:
            logging.error(f"Process analysis error: {str(e)}")
            return None

    def extract_process_features(self, process_info):
        return [
            process_info.get('cpu_percent', 0),
            process_info.get('memory_percent', 0),
            process_info.get('num_threads', 1),
            len(process_info.get('exe', '')),
            len(process_info.get('cmdline', [])),
            int('powershell' in process_info.get('name', '').lower())
        ]

    # --------- Network Analysis ---------
    def analyze_network(self, network_info):
        try:
            features = self.extract_network_features(network_info)
            scaled = self.scalers['network_traffic'].transform([features])
            prediction = self.models['network_traffic'].predict(scaled)

            return {
                'is_anomaly': prediction[0] == -1,
                'features': features
            }
        except Exception as e:
            logging.error(f"Network analysis error: {str(e)}")
            return None

    def extract_network_features(self, conn_info):
        return [
            conn_info.get('bytes_sent', 0),
            conn_info.get('bytes_recv', 0),
            conn_info.get('remote_port', 0),
            int(conn_info.get('status') == 'ESTABLISHED'),
            len(conn_info.get('remote_ip', ''))
        ]

    # --------- System Metrics Analysis ---------
    def analyze_system_metrics(self, metrics):
        try:
            features = self.extract_system_features(metrics)
            self.history.append(features)

            if len(self.history) >= 10:
                recent_data = list(self.history)[-10:]
                scaled = self.scalers['system_metrics'].transform(recent_data)
                predictions = self.models['system_metrics'].fit_predict(scaled)
                anomalies = [p == -1 for p in predictions]

                return {
                    'current_anomaly': anomalies[-1],
                    'trend_anomalies': sum(anomalies),
                    'features': features
                }
            return None
        except Exception as e:
            logging.error(f"System metrics analysis error: {str(e)}")
            return None

    def extract_system_features(self, metrics):
        return [
            metrics.get('cpu_percent', 0),
            metrics.get('memory_percent', 0),
            metrics.get('disk_read_count', 0),
            metrics.get('disk_write_count', 0),
            metrics.get('network_bytes_sent', 0),
            metrics.get('network_bytes_recv', 0),
            metrics.get('process_count', 0),
            metrics.get('file_rename_count', 0)
        ]

    # --------- Save Models ---------
    def save_models(self):
        model_dir = "ai_models"
        os.makedirs(model_dir, exist_ok=True)

        for model_name, model in self.models.items():
            model_path = os.path.join(model_dir, f"{model_name}.joblib")
            scaler_path = os.path.join(model_dir, f"{model_name}_scaler.joblib")

            joblib.dump(model, model_path)
            joblib.dump(self.scalers[model_name], scaler_path)

        logging.info("All AI models saved successfully")
