import streamlit as st
import pandas as pd

def render_packet_view(packets_data):
    st.subheader("📦 Flux de Paquets en Temps Réel (avec GeoIP)")
    if packets_data:
        df = pd.DataFrame(packets_data)
        # Reorganisation des colonnes pour la lisibilite
        cols_order = ["timestamp", "protocol", "src_ip", "country", "org", "dst_ip", "length"]
        available_cols = [c for c in cols_order if c in df.columns] + [c for c in df.columns if c not in cols_order]
        st.dataframe(df[available_cols], use_container_width=True)
    else:
        st.info("Aucun paquet capturé pour le moment.")
