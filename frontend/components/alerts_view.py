import streamlit as st
from backend.explanations.interpreter import interpret_alert

def render_alerts_view(alerts_data):
    st.subheader("🚨 Alertes & Sécurité")
    if not alerts_data:
        st.success("Aucune anomalie détectée.")
        return

    for idx, alert in enumerate(alerts_data):
        timestamp = alert.get('timestamp', 'N/A')
        src_ip = alert.get('src_ip', 'Inconnue')
        dst_ip = alert.get('dst_ip', 'Inconnue')
        
        with st.expander(f"⚠️ [{idx + 1}] {timestamp} — Source: {src_ip}"):
            for item in alert.get("alerts", []):
                st.error(f"**Type :** {item.get('type')} | **Sévérité :** {item.get('severity')}")
                st.write(f"**Message :** {item.get('message')}")
                st.caption(f"Destination : {dst_ip}")

            button_key = f"btn_llm_{idx}_{timestamp}"
            if st.button("💡 Expliquer avec l'IA", key=button_key):
                with st.spinner("Analyse par le LLM..."):
                    explanation = interpret_alert(alert)
                    st.info(explanation)
