# demo-app — deliberately vulnerable. See README.md. Never deploy.
#
# Nightly revenue report. The region comes from a CLI/HTTP parameter and is
# formatted straight into the SQL.
import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.route("/report")
def report():
    region = request.args.get("region")
    conn = sqlite3.connect("shop.db")
    cur = conn.cursor()
    cur.execute(f"SELECT SUM(total) FROM orders WHERE region = '{region}'")
    return {"revenue": cur.fetchone()[0]}
