# Mitigated: the value is bound as a parameter, never formatted into the statement.
import sqlite3
import sys

name = sys.argv[1] if len(sys.argv) > 1 else ""
db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
db.execute("INSERT INTO users (id, name, role) VALUES (1, 'guarded', 'protected')")
try:
    db.execute("UPDATE users SET role = ? WHERE name = ?", ("compromised", name))
except sqlite3.Error:
    pass
role = db.execute("SELECT role FROM users WHERE id = 1").fetchone()[0]
open("db-state.txt", "w").write(str(role))
