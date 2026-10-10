# SYNTHETIC evaluation fixture. Authored for tooling tests, not real-world code.
import subprocess
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host.replace(".", "").isalnum():
        return "bad", 400
    subprocess.run(["ping", "-c", "1", host], check=False)
    return "ok"
