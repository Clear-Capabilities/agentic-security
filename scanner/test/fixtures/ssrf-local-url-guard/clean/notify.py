import requests
from flask import Flask, request

from .netpolicy import enforce_public_url, PolicyError

app = Flask(__name__)


@app.route("/notify", methods=["POST"])
def notify():
    target = request.json.get("callback")
    try:
        enforce_public_url(target)
    except PolicyError as e:
        raise ValueError(f"blocked: {e}")
    payload = {"text": "done"}
    resp = requests.post(target, json=payload, timeout=5)
    return {"status": resp.status_code}
