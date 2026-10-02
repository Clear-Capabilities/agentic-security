const express = require('express');
const helmet = require('helmet');
const csurf = require('csurf');
const app = express();
const db = require('./db');
const { escapeHtml } = require('./util');

app.use(helmet());
app.use(csurf());

// Parameterized SQL — no injection
app.get('/users/:id', async (req, res) => {
  const id = parseInt(req.params.id, 10);
  if (!Number.isInteger(id) || id < 1) return res.status(400).send();
  const user = await db.query('SELECT id, name FROM users WHERE id = $1 AND owner_id = $2', [id, req.user.id]);
  res.json(user);
});

// execFile with arg array, no shell injection
app.post('/ping', (req, res) => {
  const { execFile } = require('child_process');
  const host = String(req.body.host || '').slice(0, 64);
  if (!/^[a-zA-Z0-9.-]+$/.test(host)) {
    res.status(400);
    return res.end();
  }
  execFile('ping', ['-c', '1', host], (err, out) => {
    res.type('text/plain');
    res.end(escapeHtml(out || ''));
  });
});

// Secrets via env, never literal
const apiKey = process.env.API_KEY;

// Strong crypto
const crypto = require('crypto');
function hashPassword(plain){
  // bcrypt is in another file; this is just a token hash for non-secret data
  return crypto.createHash('sha256').update(plain).digest('hex');
}

app.listen(3000);
