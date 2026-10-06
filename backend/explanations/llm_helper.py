import requests
from backend.config import config

def ask_llm(prompt: str) -> str:
    """Genere une explication simple d'une alerte reseau via OpenAI API."""
    if not config.OPENAI_API_KEY:
        return "Clé API OpenAI absente dans la configuration (.env)."

    headers = {
        "Authorization": f"Bearer {config.OPENAI_API_KEY}",
        "Content-Type": "application/json"
    }
    data = {
        "model": "gpt-3.5-turbo",
        "messages": [
            {"role": "system", "content": "Vous êtes un expert en sécurité réseau qui explique les alertes aux administrateurs de façon claire et concise."},
            {"role": "user", "content": prompt}
        ],
        "max_tokens": 150
    }

    try:
        res = requests.post("https://api.openai.com/v1/chat/completions", json=data, headers=headers, timeout=5)
        if res.status_code == 200:
            return res.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"Erreur de communication LLM: {e}"

    return "Impossible de générer une explication."
