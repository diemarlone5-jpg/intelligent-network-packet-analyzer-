import streamlit as st
import pandas as pd
import pydeck as pdk

def render_map_view(packets_data):
    st.subheader("🗺️ Géolocalisation des IP Interceptées")
    
    if not packets_data:
        st.info("Aucune donnée géographique à afficher pour le moment.")
        return

    # Extraction des coordonnées enregistrées dans les paquets
    points = []
    for p in packets_data:
        loc = p.get("loc")
        if loc and loc != "N/A":
            try:
                lat, lon = map(float, loc.split(","))
                points.append({
                    "lat": lat,
                    "lon": lon,
                    "src_ip": p.get("src_ip"),
                    "country": p.get("country"),
                    "org": p.get("org")
                })
            except ValueError:
                continue

    if points:
        df_map = pd.DataFrame(points)
        
        # Configuration de la vue carte 3D / PyDeck
        view_state = pdk.ViewState(
            latitude=df_map["lat"].mean(),
            longitude=df_map["lon"].mean(),
            zoom=2,
            pitch=30
        )

        layer = pdk.Layer(
            "ScatterplotLayer",
            data=df_map,
            get_position=["lon", "lat"],
            get_color="[255, 75, 75, 160]",
            get_radius=200000,
            pickable=True
        )

        r = pdk.Deck(
            layers=[layer],
            initial_view_state=view_state,
            tooltip={"text": "IP: {src_ip}\nPays: {country}\nOrg: {org}"}
        )

        st.pydeck_chart(r)
    else:
        st.info("Les adresses publiques capturées n'ont pas encore fourni de coordonnées GPS.")
