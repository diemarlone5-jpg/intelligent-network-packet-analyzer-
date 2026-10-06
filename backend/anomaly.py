import numpy as np
from sklearn.ensemble import IsolationForest

class AnomalyDetector:
    """Détecte les comportements inhabituels via règles métier et IA."""
    def __init__(self):
        self.port_scan_tracker = {}
        self.model = IsolationForest(contamination=0.05, random_state=42)
        self.data_history = []
        self.is_trained = False

    def inspect(self, packet: dict) -> list:
        alerts = []
        src_ip = packet.get("src_ip")
        dst_port = packet.get("dst_port")
        length = packet.get("length", 0)

        if src_ip and dst_port:
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = set()
            self.port_scan_tracker[src_ip].add(dst_port)

            if len(self.port_scan_tracker[src_ip]) > 12:
                alerts.append({
                    "type": "Scan de Ports Suspect",
                    "severity": "ELEVEE",
                    "message": f"La machine {src_ip} tente de contacter un nombre élevé de ports distincts (>12)."
                })

        if dst_port and length:
            self.data_history.append([length, dst_port])
            if len(self.data_history) >= 20:
                if not self.is_trained:
                    self.model.fit(self.data_history)
                    self.is_trained = True
                else:
                    pred = self.model.predict([[length, dst_port]])
                    if pred[0] == -1:
                        alerts.append({
                            "type": "Anomalie Détectée par IA",
                            "severity": "MOYENNE",
                            "message": f"Combinaison taille ({length} B) / port ({dst_port}) statistiquement anormale."
                        })

        return alerts
