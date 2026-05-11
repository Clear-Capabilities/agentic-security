import requests

SYSTEM_PROMPT = (
    "You are a friendly support bot. Be concise, polite, and helpful. "
    "If you don't know the answer, say so."
)

def generate(prompt: str) -> str:
    payload = {
        "model": "mistral",
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "max_tokens": 256,
        "stream": False,
    }
    return requests.post(
        "http://localhost:11434/api/generate",
        json=payload,
        timeout=30,
    ).json().get("response", "")
