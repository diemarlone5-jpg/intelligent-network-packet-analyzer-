from backend.explanations.llm_helper import ask_llm

def interpret_alert(alert_data: dict) -> str:
    """Prepare le prompt pour l'explication de l'alerte."""
    prompt = f"Explique l'alerte réseau suivante et donne 2 recommandations : {alert_data}"
    return ask_llm(prompt)
