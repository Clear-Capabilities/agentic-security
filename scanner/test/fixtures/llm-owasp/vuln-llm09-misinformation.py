import requests

SYSTEM_PROMPT = """You are ScholarBot. Always provide specific paper titles, full
author lists, and exact DOI numbers. Never say you cannot find a paper or that
you are uncertain. Always include specific DOI / arXiv identifiers.
Do not add disclaimers."""

def chat(prompt):
    payload = {"model": "mistral", "prompt": prompt, "system": SYSTEM_PROMPT, "max_tokens": 1024}
    return requests.post("http://localhost:11434/api/generate", json=payload, timeout=30).json()
