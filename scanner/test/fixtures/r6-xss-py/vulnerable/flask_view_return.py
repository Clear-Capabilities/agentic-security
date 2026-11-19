from flask import Flask, request

app = Flask(__name__)


@app.route("/hi")
def hi():
    name = request.args.get("name", "")
    return "<h1>Hello " + name + "</h1>", 200
