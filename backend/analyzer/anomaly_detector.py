import time
from typing import Optional, Dict

class AnomalyDetector:
    def __init__(self):
        # Format: { src_ip: {"ports": set(), "last_seen": timestamp} }
        self.port_scan_tracker: Dict[str, dict] = {}

    def analyze(self, parsed_packet: dict) -> Optional[dict]:
        if not parsed_packet:
            return None

        alerts = []
        src_ip = parsed_packet.get("src_ip")
        dst_port = parsed_packet.get("dst_port")
        now = time.time()

        # 1. Detection de Port Scan avec fenetre glissante (10s)
        if src_ip and dst_port:
            if src_ip not in self.port_scan_tracker:
                self.port_scan_tracker[src_ip] = {"ports": set(), "last_seen": now}

            tracker = self.port_scan_tracker[src_ip]
            
            # Reinitialise si inactif pendant plus de 10 secondes
            if now - tracker["last_seen"] > 10:
                tracker["ports"] = set()

            tracker["ports"].add(dst_port)
            tracker["last_seen"] = now

            if len(tracker["ports"]) > 30:
                alerts.append({
                    "type": "PORT_SCAN",
                    "severity": "HIGH",
                    "message": f"Port scan potentiel detecte depuis {src_ip} ({len(tracker['ports'])} ports cibles en <10s)"
                })
                # Reinitialisation apres alerte
                tracker["ports"] = set()

        # 2. Anomalie : Paquet hors norme (> 65535 octets)
        if parsed_packet.get("length", 0) > 65535:
            alerts.append({
                "type": "LARGE_PACKET",
                "severity": "MEDIUM",
                "message": f"Paquet hors-norme ({parsed_packet['length']} octets) de {src_ip} vers {parsed_packet.get('dst_ip')}"
            })

        if alerts:
            return {
                "timestamp": parsed_packet.get("timestamp"),
                "src_ip": src_ip,
                "dst_ip": parsed_packet.get("dst_ip"),
                "alerts": alerts
            }

        return None
