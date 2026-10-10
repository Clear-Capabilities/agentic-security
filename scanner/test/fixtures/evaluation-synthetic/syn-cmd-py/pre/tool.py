# SYNTHETIC evaluation fixture. Authored for tooling tests, not real-world code.
import os
from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    os.system("ping -c 1 " + host)
    return "ok"
