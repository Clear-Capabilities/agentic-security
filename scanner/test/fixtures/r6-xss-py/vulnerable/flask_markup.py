from flask import Flask, request
from markupsafe import Markup

app = Flask(__name__)


@app.route("/badge")
def badge():
    label = request.args.get("label", "")
    return str(Markup("<span class='badge'>" + label + "</span>"))
