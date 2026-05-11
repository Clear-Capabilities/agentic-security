import requests
from gpt4all import Embed4All

embedder = Embed4All()
_injected_docs = []
_injected_embeddings = []

SYSTEM_PROMPT = "You are CourseBot. Answer using the provided context."

def inject_document(text: str):
    emb = embedder.embed(text)
    _injected_docs.append(text)
    _injected_embeddings.append(emb)

def generate(prompt, context):
    payload = {"model": "mistral", "prompt": prompt, "system": SYSTEM_PROMPT, "max_tokens": 200}
    return requests.post("http://localhost:11434/api/generate", json=payload, timeout=30).json()
