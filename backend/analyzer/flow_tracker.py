import time
from typing import Dict, Any

class FlowTracker:
    def __init__(self):
        # Dictionnaire des flux actifs : key = (src_ip, dst_ip, src_port, dst_port, protocol)
        self.flows: Dict[tuple, Dict[str, Any]] = {}

    def _get_flow_key(self, parsed_packet: dict) -> tuple:
        return (
            parsed_packet.get("src_ip"),
            parsed_packet.get("dst_ip"),
            parsed_packet.get("src_port"),
            parsed_packet.get("dst_port"),
            parsed_packet.get("protocol")
        )

    def process_packet(self, parsed_packet: dict) -> dict:
        if not parsed_packet or not parsed_packet.get("src_ip"):
            return None

        key = self._get_flow_key(parsed_packet)
        now = time.time()

        if key not in self.flows:
            self.flows[key] = {
                "src_ip": parsed_packet["src_ip"],
                "dst_ip": parsed_packet["dst_ip"],
                "src_port": parsed_packet["src_port"],
                "dst_port": parsed_packet["dst_port"],
                "protocol": parsed_packet["protocol"],
                "packet_count": 1,
                "total_bytes": parsed_packet["length"],
                "start_time": now,
                "last_seen": now
            }
        else:
            flow = self.flows[key]
            flow["packet_count"] += 1
            flow["total_bytes"] += parsed_packet["length"]
            flow["last_seen"] = now

        return self.flows[key]

    def get_active_flows( me ) -> list:
        return list(self.flows.values())
