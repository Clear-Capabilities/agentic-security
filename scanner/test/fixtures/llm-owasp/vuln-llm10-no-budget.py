import requests

SYSTEM_PROMPT = "You are a research writer. Produce full essays end-to-end."

def generate(prompt):
    payload = {
        "model": "mistral",
        "prompt": prompt,
        "system": SYSTEM_PROMPT,
        "stream": True,
    }
    return requests.post("http://localhost:11434/api/generate", json=payload)
