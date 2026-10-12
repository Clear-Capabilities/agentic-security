// Deliberately vulnerable: builds a SQL statement by string-concatenating untrusted input (classic CWE-89).
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
const db = new DatabaseSync(':memory:');
db.exec('CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)');
db.exec("INSERT INTO users (id, name, role) VALUES (1, 'guarded', 'protected')");
const name = process.argv[2] || '';
try { db.exec(`UPDATE users SET role = 'compromised' WHERE name = '${name}'`); } catch { /* ignore malformed SQL */ }
const row = db.prepare('SELECT role FROM users WHERE id = 1').get();
fs.writeFileSync('db-state.txt', String(row.role));
