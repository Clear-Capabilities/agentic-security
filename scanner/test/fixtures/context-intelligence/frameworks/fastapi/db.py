import sqlite3


def get_db():
    return sqlite3.connect("app.db")


def require_user():
    raise PermissionError
