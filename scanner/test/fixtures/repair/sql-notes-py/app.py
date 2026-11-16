# A small notes service as a WSGI application. Search builds its SQL with an f-string.
import json
from urllib.parse import parse_qs


def create_app(db):
    def app(environ, start_response):
        user = environ.get("HTTP_X_USER", "")
        if not user:
            return respond(start_response, 401, {"error": "login required"})
        if environ["REQUEST_METHOD"] == "GET" and environ["PATH_INFO"] == "/notes":
            title = parse_qs(environ.get("QUERY_STRING", "")).get("title", [""])[0]
            try:
                rows = db.execute(f"SELECT title, body FROM notes WHERE owner = '{user}' AND title = '{title}'").fetchall()
            except Exception:
                return respond(start_response, 500, {"error": "query failed"})
            return respond(start_response, 200, [{"title": t, "body": b} for t, b in rows])
        return respond(start_response, 404, {"error": "not found"})

    return app


def respond(start_response, status, value):
    body = json.dumps(value).encode()
    start_response(f"{status} X", [("Content-Type", "application/json")])
    return [body]
