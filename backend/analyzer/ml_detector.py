import numpy as np
from sklearn.ensemble import IsolationForest

class MLAnomalyDetector:
    def __init__(self, contamination=0.10):
        self.model = IsolationForest(contamination=contamination, random_state=42)
        self.is_trained = False
        self.training_buffer = []
        self.min_training_size = 15

    def _extract_features(self, parsed_packet: dict) -> list:
        proto_map = {"TCP": 6, "UDP": 17, "ICMP": 1}
        proto_val = proto_map.get(str(parsed_packet.get("protocol", "")).upper(), 0)

        length = parsed_packet.get("length", 0)
        src_port = parsed_packet.get("src_port", 0) or 0
        dst_port = parsed_packet.get("dst_port", 0) or 0

        return [length, src_port, dst_port, proto_val]

    def process_packet(self, parsed_packet: dict):
        if not parsed_packet:
            return None

        features = self._extract_features(parsed_packet)

        if not self.is_trained:
            self.training_buffer.append(features)
            if len(self.training_buffer) >= self.min_training_size:
                self.model.fit(self.training_buffer)
                self.is_trained = True
            return None

        prediction = self.model.predict([features])[0]
        score = float(self.model.decision_function([features])[0])

        if prediction == -1:
            # Calcul direct des écarts réels pour l'explication
            avg_len = np.mean([f[0] for f in self.training_buffer]) if self.training_buffer else 0
            
            return {
                "type": "ML_ANOMALY",
                "severity": "MEDIUM",
                "message": f"Comportement atypique IA (Score: {score:.2f})",
                "score": score,
                "details": {
                    "length": parsed_packet.get("length", 0),
                    "avg_length": round(avg_len, 1),
                    "protocol": parsed_packet.get("protocol", "Inconnu"),
                    "dst_port": parsed_packet.get("dst_port", 0)
                }
            }

        return None
