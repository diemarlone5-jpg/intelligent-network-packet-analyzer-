from datetime import datetime

class FlowTracker:
    """Regroupe les paquets isolés sous forme de sessions de communication."""
    def __init__(self):
        self.flows = {}

    def update_flow(self, packet: dict) -> dict:
        src = packet.get("src_ip")
        dst = packet.get("dst_ip")
        proto = packet.get("protocol")
        src_port = packet.get("src_port", 0)
        dst_port = packet.get("dst_port", 0)
        length = packet.get("length", 0)

        endpoints = sorted([f"{src}:{src_port}", f"{dst}:{dst_port}"])
        flow_key = f"{proto}_{endpoints[0]}_{endpoints[1]}"

        now = datetime.now()
        if flow_key not in self.flows:
            self.flows[flow_key] = {
                "session_key": flow_key,
                "src_ip": src,
                "dst_ip": dst,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": proto,
                "packet_count": 1,
                "total_bytes": length,
                "start_time": now,
                "last_active": now,
                "status": "ACTIVE"
            }
        else:
            flow = self.flows[flow_key]
            flow["packet_count"] += 1
            flow["total_bytes"] += length
            flow["last_active"] = now

        return self.flows[flow_key]

    def get_all_flows(self) -> list:
        return list(self.flows.values())
