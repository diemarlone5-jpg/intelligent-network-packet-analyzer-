import threading
from scapy.all import sniff, conf

class PacketSniffer:
    def __init__(self, callback, interface=None, filter_str=""):
        self.callback = callback
        self.interface = interface if interface else conf.iface
        self.filter_str = filter_str
        self._stop_event = threading.Event()
        self._thread = None

    def _sniff_packets(self):
        sniff(
            iface=self.interface,
            filter=self.filter_str,
            prn=self.callback,
            stop_filter=lambda p: self._stop_event.is_set(),
            store=False
        )

    def start(self):
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._sniff_packets, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
