# Pure-literal sinks. No user input flows in. Should produce no critical/high SAST findings.
import sqlite3
import subprocess

conn = sqlite3.connect("app.db")
cursor = conn.cursor()

cursor.execute("SELECT * FROM products WHERE active = 1")
cursor.execute("SELECT id, name FROM categories")

print("Hello world")
print("Server starting on port 8080")

subprocess.call(["ls", "-la"])
subprocess.run(["echo", "static literal"])
