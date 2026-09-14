# pyshelf — a tiny Flask book-review app, written purely as scan input for
# the independent external-holdout gate (SARD_80_F1_SCANNER_PRD.md
# adversarial-premortem remediation, P1 item 6). Never installed or run.
#
# Same discipline as bench/holdout-independent/tinymart (see its README):
# every vulnerable/safe route below was written and classified by reading
# this file, BEFORE the scanner was ever run against it once. See
# scanner/test/benchmark/realworld/expected/pyshelf.json for the ground
# truth this file's own comments justify line-by-line.

import os
import sqlite3
import subprocess
from flask import Flask, request, render_template_string

app = Flask(__name__)
DB_PATH = os.environ.get("PYSHELF_DB", "pyshelf.sqlite3")
REVIEWS_DIR = "/var/pyshelf/reviews"

# NOTE: this fixture deliberately does NOT include a hardcoded-secret class
# (tinymart/config.js already covers it). Two earlier attempts here — a
# SendGrid-shaped value, then a Stripe sk_test_-shaped value — were BOTH
# rejected by GitHub's own push-protection secret scanner despite neither
# being a real, working credential: any sufficiently plausible API-key-
# shaped literal is apparently enough to trigger it regardless of a
# test/live distinction, which makes "construct a fake-but-scanner-safe
# secret" a losing, ever-shifting target rather than a one-time design
# choice. Scope narrowed to 4 vulnerability classes for this app instead
# of chasing a fifth. See bench/holdout-independent/README.md for the
# full account.


# --- SQL injection: string-formatted query --------------------------------
@app.route("/search")
def search_books():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Vulnerable: the search term is interpolated directly into the SQL
    # text via an f-string, not bound as a parameter.
    cur.execute(f"SELECT id, title FROM books WHERE title LIKE '%{q}%'")
    return str(cur.fetchall())


@app.route("/search-safe")
def search_books_safe():
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Safe: bound parameter, no string interpolation of untrusted input.
    cur.execute("SELECT id, title FROM books WHERE title LIKE ?", (f"%{q}%",))
    return str(cur.fetchall())


# --- Command injection: shell=True with concatenated input ----------------
@app.route("/thumbnail")
def make_thumbnail():
    isbn = request.args.get("isbn", "")
    # Vulnerable: isbn is attacker-controlled and reaches a shell via
    # subprocess.run(..., shell=True) with string concatenation.
    subprocess.run("convert /covers/" + isbn + ".jpg -resize 100x100 /tmp/thumb.jpg", shell=True)
    return "ok"


@app.route("/thumbnail-safe")
def make_thumbnail_safe():
    isbn = request.args.get("isbn", "")
    # Safe: argv-array form, no shell, no string built from untrusted input.
    subprocess.run(["convert", f"/covers/{isbn}.jpg", "-resize", "100x100", "/tmp/thumb.jpg"], shell=False)
    return "ok"


# --- Path traversal: unchecked join ----------------------------------------
@app.route("/review")
def get_review():
    filename = request.args.get("file", "")
    # Vulnerable: filename joined onto REVIEWS_DIR with no containment
    # check before the file is opened — "../../etc/passwd" reaches os.open.
    path = os.path.join(REVIEWS_DIR, filename)
    with open(path, "r") as f:
        return f.read()


@app.route("/review-safe")
def get_review_safe():
    filename = request.args.get("file", "")
    candidate = os.path.realpath(os.path.join(REVIEWS_DIR, filename))
    # Safe: resolved path is checked to still be inside REVIEWS_DIR before
    # opening it.
    if not candidate.startswith(os.path.realpath(REVIEWS_DIR) + os.sep):
        return "forbidden", 403
    with open(candidate, "r") as f:
        return f.read()


# --- Reflected XSS: unescaped template interpolation -----------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Vulnerable: render_template_string builds the template itself from
    # untrusted input, so Jinja2's autoescaping never applies to `name` —
    # it's part of the template source, not a substituted variable.
    return render_template_string("<h1>Welcome, " + name + "!</h1>")


@app.route("/greet-safe")
def greet_safe():
    name = request.args.get("name", "")
    # Safe: name is passed as a template VARIABLE, so Jinja2's default
    # autoescaping applies to it normally.
    return render_template_string("<h1>Welcome, {{ name }}!</h1>", name=name)
