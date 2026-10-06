from supabase import create_client, Client
from backend.config import config

class SupabaseService:
    def __init__(self):
        self.client: Client | None = None
        if config.SUPABASE_URL and config.SUPABASE_KEY:
            try:
                self.client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
                print("[+] Connexion Supabase etablie.")
            except Exception as e:
                print(f"[-] Erreur de connexion Supabase: {e}")
        else:
            print("[!] Supabase non configure (cles manquantes dans .env).")

    def insert_packet(self, packet_data: dict):
        if self.client:
            return self.client.table("packets").insert(packet_data).execute()

    def insert_alert(self, alert_data: dict):
        if self.client:
            return self.client.table("alerts").insert(alert_data).execute()
