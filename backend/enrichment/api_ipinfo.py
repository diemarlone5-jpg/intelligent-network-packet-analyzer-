import requests
from backend.config import config

class IPInfoEnricher:
    def __init__(self):
        self.token = config.IPINFO_TOKEN
        self.cache = {}

    def get_ip_info(self, ip_address: str) -> dict:
        """Recupere la geolocalisation d'une adresse IP."""
        if not ip_address or ip_address.startswith(("127.", "192.168.", "10.")) or ip_address == "localhost":
            return {"ip": ip_address, "type": "PRIVATE/LOCAL"}

        if ip_address in self.cache:
            return self.cache[ip_address]

        url = f"https://ipinfo.io/{ip_address}/json"
        params = {"token": self.token} if self.token else {}

        try:
            response = requests.get(url, params=params, timeout=3)
            if response.status_code == 200:
                data = response.json()
                self.cache[ip_address] = data
                return data
        except Exception as e:
            print(f"[-] Erreur IPInfo pour {ip_address}: {e}")

        return {"ip": ip_address, "error": "Unable to fetch data"}
