import sys
import os

# Ajoute le dossier racine au path Python
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

import streamlit as st
import json
import pandas as pd

try:
    from backend.sniffer import NetworkSniffer
    from backend.explainer import explain_packet, group_communications
except ImportError:
    from backend.main import NetworkAnalyzerCore

# --- Intégration Supabase ---
import streamlit as st
from supabase import create_client, Client

supabase_url = st.secrets.get("SUPABASE_URL")
supabase_key = st.secrets.get("SUPABASE_KEY")

@st.cache_resource
def init_supabase() -> Client:
    if supabase_url and supabase_key:
        try:
            return create_client(supabase_url, supabase_key)
        except Exception as e:
            st.error(f"Erreur de connexion à Supabase: {e}")
    return None

supabase = init_supabase()

def save_packet_to_supabase(packet_data):
    if supabase:
        try:
            data = {
                "protocol": packet_data.get("protocol"),
                "src_ip": packet_data.get("src_ip"),
                "dst_ip": packet_data.get("dst_ip"),
                "dst_port": packet_data.get("dst_port"),
                "length": packet_data.get("length"),
                "country": packet_data.get("country"),
                "org": packet_data.get("org"),
                "explanation": packet_data.get("explanation")
            }
            supabase.table("packets").insert(data).execute()
        except Exception as e:
            print(f"Erreur lors de l'insertion Supabase : {e}")
