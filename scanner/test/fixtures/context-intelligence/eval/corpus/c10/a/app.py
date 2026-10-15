from flask import Flask, jsonify
from flask_login import login_required, current_user
from storage import db

app = Flask(__name__)


@app.route("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    row = db.execute("SELECT * FROM notes WHERE id = ?", (note_id,)).fetchone()
    return jsonify(row)
