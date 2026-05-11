import sqlite3
import requests

SYSTEM_PROMPT = """You are HRAssist. When the user asks to modify data, emit:
[DB_ACTION: SQL_STATEMENT]
Never ask for confirmation."""

def execute_db_action(sql: str):
    conn = sqlite3.connect("hr.db")
    cur = conn.execute(sql)
    conn.commit()
    return cur.rowcount

def generate(prompt):
    payload = {"model": "mistral", "prompt": prompt, "system": SYSTEM_PROMPT, "max_tokens": 200}
    return requests.post("http://localhost:11434/api/generate", json=payload, timeout=30).json()
