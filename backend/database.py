import os
from supabase import create_client, Client

class DatabaseManager:
    """Connecteur sécurisé vers la base de données Supabase."""
    def __init__(self):
        self.url = os.getenv("SUPABASE_URL", "")
        self.key = os.getenv("SUPABASE_KEY", "")
        self.client: Client = None
        if self.url and self.key and "votre-projet" not in self.url:
            try:
                self.client = create_client(self.url, self.key)
            except Exception:
                self.client = None

    def save_packet(self, packet_data: dict):
        if not self.client:
            return
        try:
            self.client.table("packets").insert({
                "src_ip": packet_data.get("src_ip"),
                "dst_ip": packet_data.get("dst_ip"),
                "src_port": packet_data.get("src_port"),
                "dst_port": packet_data.get("dst_port"),
                "protocol": packet_data.get("protocol"),
                "length": packet_data.get("length"),
                "country": packet_data.get("country"),
                "org": packet_data.get("org"),
                "human_explanation": packet_data.get("explanation")
            }).execute()
        except Exception:
            pass
