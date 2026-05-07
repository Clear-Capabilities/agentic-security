# Python in-file helper flow: source → helper(param) → sink in helper body.
# Feat-1: scanner should attribute the SQL injection in `lookup_user` back to
# the source `request.args.get('id')` even though they're in different functions.
from flask import Flask, request
import sqlite3

app = Flask(__name__)
conn = sqlite3.connect("app.db")


def lookup_user(username):
    cursor = conn.cursor()
    return cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")


@app.route('/users')
def get_user():
    user_id = request.args.get('id')
    return lookup_user(user_id)
