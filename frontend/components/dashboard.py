import streamlit as st
import pandas as pd
import plotly.express as px

def render_dashboard(packets_data, alerts_data):
    st.subheader("📊 Métriques Générales")

    col1, col2, col3 = st.columns(3)
    col1.metric("Paquets Capturés", len(packets_data))
    col2.metric("Alertes Détectées", len(alerts_data))
    
    protocols_count = pd.DataFrame(packets_data)['protocol'].value_counts() if packets_data else {}
    col3.metric("Protocoles Actifs", len(protocols_count))

    if packets_data:
        df = pd.DataFrame(packets_data)
        st.subheader("Répartition des Protocoles")
        fig = px.pie(df, names='protocol', title="Distribution TCP / UDP / ICMP")
        st.plotly_chart(fig, use_container_width=True)
