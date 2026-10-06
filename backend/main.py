import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, Raw
from backend.enricher import IPEnricher
from backend.explainer import HumanExplainer
from backend.tracker import FlowTracker
from backend.anomaly import AnomalyDetector
from backend.database import DatabaseManager

class NetworkAnalyzerCore:
    def __init__(self):
        self.enricher = IPEnricher()
        self.tracker = FlowTracker()
        self.anomaly_detector = AnomalyDetector()
        self.db = DatabaseManager()
        self.recent_packets = []
        self.alerts = []
        self.is_capturing = False
        self.packet_counter = 0
        self.thread = None

    def _packet_callback(self, packet):
        if not packet.haslayer(IP):
            return

        self.packet_counter += 1
        ip_layer = packet[IP]
        proto = "AUTRE"
        src_port, dst_port = None, None

        if packet.haslayer(TCP):
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        elif packet.haslayer(ICMP):
            proto = "ICMP"

        geo = self.enricher.lookup(ip_layer.dst)

        pkt_data = {
            "id": self.packet_counter,
            "src_ip": ip_layer.src,
            "dst_ip": ip_layer.dst,
            "protocol": proto,
            "length": len(packet),
            "src_port": src_port,
            "dst_port": dst_port,
            "country": geo["country"],
            "org": geo["org"],
            "loc": geo["loc"]
        }

        explanation = HumanExplainer.explain_packet(pkt_data)
        pkt_data["explanation"] = explanation["summary"]

        self.tracker.update_flow(pkt_data)
        alerts_found = self.anomaly_detector.inspect(pkt_data)

        if alerts_found:
            self.alerts.append({
                "timestamp": pkt_data["id"],
                "src_ip": pkt_data["src_ip"],
                "dst_ip": pkt_data["dst_ip"],
                "alerts": alerts_found
            })

        self.recent_packets.append(pkt_data)
        if len(self.recent_packets) > 500:
            self.recent_packets.pop(0)

        self.db.save_packet(pkt_data)

    def start_capture(self, filter_str=""):
        if not self.is_capturing:
            self.is_capturing = True
            self.thread = threading.Thread(target=self._sniff_loop, args=(filter_str,), daemon=True)
            self.thread.start()

    def _sniff_loop(self, filter_str):
        sniff(filter=filter_str if filter_str else None, prn=self._packet_callback, store=0, stop_filter=lambda x: not self.is_capturing)

    def stop_capture(self):
        self.is_capturing = False
