from flask import Flask, request, make_response

app = Flask(__name__)


@app.route("/echo")
def echo():
    msg = request.args.get("msg", "")
    resp = make_response("<div class='msg'>" + msg + "</div>")
    resp.headers["X-Frame-Options"] = "DENY"
    return resp
