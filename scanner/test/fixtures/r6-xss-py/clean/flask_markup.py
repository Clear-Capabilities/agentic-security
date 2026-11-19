from flask import Flask, request
from markupsafe import Markup, escape

app = Flask(__name__)


@app.route("/badge")
def badge():
    label = escape(request.args.get("label", ""))
    return str(Markup("<span class='badge'>") + label + Markup("</span>"))
