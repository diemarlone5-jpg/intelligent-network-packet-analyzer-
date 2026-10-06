import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

class Config:
    # Supabase
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")

    # APIs tierces
    IPINFO_TOKEN: str = os.getenv("IPINFO_TOKEN", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")

    # Configuration reseau / capture
    DEFAULT_INTERFACE: str = os.getenv("NETWORK_INTERFACE", None)  # None = interface par defaut
    PACKET_BUFFER_SIZE: int = int(os.getenv("PACKET_BUFFER_SIZE", "100"))

config = Config()
