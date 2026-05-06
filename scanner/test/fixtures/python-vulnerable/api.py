# Vulnerable Python file: user input flows into sinks. Should produce critical/high findings.
from flask import Flask, request
import sqlite3
import subprocess
import os

app = Flask(__name__)
conn = sqlite3.connect("app.db")
cursor = conn.cursor()

@app.route('/users')
def get_user():
    user_id = request.args.get('id')
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # SQL injection
    return "ok"

@app.route('/ping')
def ping():
    host = request.args.get('host')
    os.system("ping -c 1 " + host)  # Command injection
    return "ok"

@app.route('/eval')
def evil():
    expr = request.args.get('expr')
    return eval(expr)  # Code injection
