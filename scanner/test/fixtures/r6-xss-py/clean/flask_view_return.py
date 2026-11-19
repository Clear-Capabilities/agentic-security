from flask import Flask, request, jsonify
from markupsafe import escape

app = Flask(__name__)


@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    return "<h1>Hello " + escape(name) + "</h1>", 200


@app.route("/hi.json")
def hi_json():
    return jsonify(hello=request.args.get("name", ""))


@app.route("/hi.txt")
def hi_text():
    return "Hello " + request.args.get("name", "")
