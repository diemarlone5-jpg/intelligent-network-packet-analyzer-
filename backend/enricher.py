import requests
import ipaddress

class IPEnricher:
    """Module d'enrichissement d'informations via API externe (IPinfo)."""
    def __init__(self, api_key=None):
        self.api_key = api_key
        self.cache = {}

    def is_private_ip(self, ip: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except ValueError:
            return False

    def lookup(self, ip: str) -> dict:
        if not ip or ip == "N/A":
            return {"country": "N/A", "org": "Inconnu", "loc": "N/A"}
        if self.is_private_ip(ip):
            return {"country": "LOCAL", "org": "Réseau Local / FAI", "loc": "N/A"}
        if ip in self.cache:
            return self.cache[ip]
        try:
            url = f"https://ipinfo.io/{ip}/json"
            params = {"token": self.api_key} if self.api_key else {}
            response = requests.get(url, params=params, timeout=2)
            if response.status_code == 200:
                data = response.json()
                result = {
                    "country": data.get("country", "INCONNU"),
                    "org": data.get("org", "Inconnu"),
                    "loc": data.get("loc", "N/A")
                }
                self.cache[ip] = result
                return result
        except Exception:
            pass
        return {"country": "INCONNU", "org": "Non disponible", "loc": "N/A"}
