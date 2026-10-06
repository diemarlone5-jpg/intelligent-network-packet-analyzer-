from scapy.all import Packet, IP, IPv6, TCP, UDP, ICMP
from datetime import datetime

def parse_packet(packet: Packet) -> dict | None:
    """Extrait les meta-donnees d'un paquet reseau."""
    if not packet.haslayer(IP) and not packet.haslayer(IPv6):
        return None

    packet_info = {
        "timestamp": datetime.now().isoformat(),
        "length": len(packet),
        "protocol": "OTHER",
        "src_ip": None,
        "dst_ip": None,
        "src_port": None,
        "dst_port": None,
    }

    # Couche IP
    if packet.haslayer(IP):
        packet_info["src_ip"] = packet[IP].src
        packet_info["dst_ip"] = packet[IP].dst
    elif packet.haslayer(IPv6):
        packet_info["src_ip"] = packet[IPv6].src
        packet_info["dst_ip"] = packet[IPv6].dst

    # Couche Transport
    if packet.haslayer(TCP):
        packet_info["protocol"] = "TCP"
        packet_info["src_port"] = packet[TCP].sport
        packet_info["dst_port"] = packet[TCP].dport
    elif packet.haslayer(UDP):
        packet_info["protocol"] = "UDP"
        packet_info["src_port"] = packet[UDP].sport
        packet_info["dst_port"] = packet[UDP].dport
    elif packet.haslayer(ICMP):
        packet_info["protocol"] = "ICMP"

    return packet_info
