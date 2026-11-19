from flask import Flask, request, make_response, jsonify

app = Flask(__name__)


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    resp = make_response(jsonify(msg=msg))
    resp.headers["X-Frame-Options"] = "DENY"
    return resp
