import os
import requests

SYSTEM_PROMPT = "You are a helpful assistant."

def generate_response(prompt, context):
    payload = {
        "model": "mistral",
        "prompt": prompt,
        "system": SYSTEM_PROMPT + "\n" + context,
        "stream": False,
    }
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434") + "/api/generate"
    return requests.post(ollama_url, json=payload, timeout=30).json()
