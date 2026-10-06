import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh
from backend.main import NetworkAnalyzerCore

st.set_page_config(page_title="Intelligent Network Packet Analyzer", layout="wide", page_icon="🛡️")

if "core" not in st.session_state:
    st.session_state.core = NetworkAnalyzerCore()

core = st.session_state.core

# --- BARRE LATÉRALE ---
st.sidebar.title("🛡️ Analyseur Réseau")
bpf_filter = st.sidebar.text_input("Filtre BPF (ex: tcp, udp, icmp)", "")

col1, col2 = st.sidebar.columns(2)
if col1.button("▶ Démarrer"):
    core.start_capture(filter_str=bpf_filter)
    st.sidebar.success("Capture démarrée !")

if col2.button("⏹️ Arrêter"):
    core.stop_capture()
    st.sidebar.info("Capture arrêtée.")

st.sidebar.markdown("---")
auto_refresh = st.sidebar.checkbox("🔄 Actualisation auto (2s)", value=True)
if auto_refresh and core.is_capturing:
    st_autorefresh(interval=2000, key="refresh_loop")

page = st.sidebar.radio("Navigation", ["Tableau de Bord", "Paquets & Explication", "Communications", "Alertes IA", "Carte GeoIP"])

# --- VUE : TABLEAU DE BORD ---
if page == "Tableau de Bord":
    st.title("📊 Tableau de Bord du Trafic")
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Paquets Capturés", len(core.recent_packets))
    c2.metric("Sessions Actives", len(core.tracker.get_all_flows()))
    c3.metric("Alertes Détectées", len(core.alerts))
    c4.metric("État Capture", "🟢 En Cours" if core.is_capturing else "🔴 Arrêtée")

    if core.recent_packets:
        df = pd.DataFrame(core.recent_packets)
        
        col_chart1, col_chart2 = st.columns(2)
        with col_chart1:
            st.write("### Protocoles")
            fig_proto = px.pie(df, names='protocol', hole=0.4)
            st.plotly_chart(fig_proto, use_container_width=True)
            
        with col_chart2:
            st.write("### Principales Destinations (Organisations)")
            fig_org = px.bar(df['org'].value_counts().head(5), orientation='h')
            st.plotly_chart(fig_org, use_container_width=True)

# --- VUE : PAQUETS & EXPLICATION ---
elif page == "Paquets & Explication":
    st.title("📦 Analyse Détaillée & Explications")
    if core.recent_packets:
        df = pd.DataFrame(core.recent_packets)
        st.dataframe(df[["protocol", "src_ip", "dst_ip", "dst_port", "length", "country", "org"]], use_container_width=True)

        st.markdown("---")
        st.subheader("💡 Explication en Langage Humain")
        
        idx = st.number_input("Sélectionnez l'index du paquet (ligne) à analyser :", min_value=0, max_value=len(core.recent_packets)-1, value=0, step=1)
        selected_pkt = core.recent_packets[idx]
        
        st.markdown(f"**Analyse du paquet #{idx} :**")
        st.info(selected_pkt.get("explanation", "Aucune explication disponible."))
        
        with st.expander("🔍 Voir toutes les données brutes du paquet"):
            st.json(selected_pkt)
    else:
        st.info("Aucun paquet capturé pour le moment. Cliquez sur 'Démarrer' dans le menu latéral.")

# --- VUE : COMMUNICATIONS ---
elif page == "Communications":
    st.title("🔗 Communications & Flow Tracker")
    flows = core.tracker.get_all_flows()
    if flows:
        st.dataframe(pd.DataFrame(flows), use_container_width=True)
    else:
        st.info("Aucune communication enregistrée.")

# --- VUE : ALERTES IA ---
elif page == "Alertes IA":
    st.title("🚨 Détection des Comportements Inhabituels")
    if not core.alerts:
        st.success("Aucune anomalie ou comportement suspect détecté pour le moment.")
    else:
        for alert in core.alerts:
            st.error(f"⚠️ Source : {alert.get('src_ip')} ➡️ Destination : {alert.get('dst_ip')}")
            for a in alert.get("alerts", []):
                st.write(f"- **[{a.get('severity')}] {a.get('type')}** : {a.get('message')}")

# --- VUE : CARTE GEOIP ---
elif page == "Carte GeoIP":
    st.title("🗺️ Localisation Géographique des Serveurs Contactés")
    coords = []
    for p in core.recent_packets:
        loc = p.get("loc")
        if loc and loc != "N/A":
            try:
                lat, lon = map(float, loc.split(","))
                coords.append({"latitude": lat, "longitude": lon})
            except Exception:
                pass
                
    if coords:
        df_coords = pd.DataFrame(coords)
        st.map(df_coords)
    else:
        st.info("Aucune coordonnée GPS enregistrée.")
