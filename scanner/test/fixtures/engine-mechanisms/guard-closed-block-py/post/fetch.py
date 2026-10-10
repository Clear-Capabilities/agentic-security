import requests
from flask import Flask, request

app = Flask(__name__)
ALLOWED_HOSTS = {"api.example.com"}


@app.route("/proxy")
def proxy():
    target = request.args.get("u")
    if target.split("/")[2] not in ALLOWED_HOSTS:
        raise ValueError("host not allowed")
    resp = requests.get(target)
    return str(resp.status_code)
