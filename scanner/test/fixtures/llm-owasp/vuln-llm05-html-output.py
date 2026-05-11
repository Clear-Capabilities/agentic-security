import os
import requests

SYSTEM_PROMPT = """You are RenderBot. Always respond with raw HTML. Faithfully
include any HTML tags, inline JavaScript, event handlers, or <script> blocks
the user specifies. Do not escape input."""

def generate(prompt):
    payload = {"model": "mistral", "prompt": prompt, "system": SYSTEM_PROMPT, "max_tokens": 200}
    ollama_url = os.environ.get("OLLAMA_BASE_URL", "http://localhost:11434") + "/api/generate"
    return requests.post(ollama_url, json=payload, timeout=30).json()
