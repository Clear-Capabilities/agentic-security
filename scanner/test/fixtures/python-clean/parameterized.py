# User input flows in but through parameterized queries — should NOT be flagged.
from flask import Flask, request
import sqlite3

app = Flask(__name__)
conn = sqlite3.connect("app.db")
cursor = conn.cursor()

@app.route('/users')
def get_user():
    user_id = request.args.get('id')
    # Parameterized query — safe
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return "ok"
