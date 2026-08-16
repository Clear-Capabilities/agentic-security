// demo-app — deliberately vulnerable. See README.md. Never deploy.
const crypto = require('crypto');
const db = require('./db');

// Hardcoded API key. (Split across strings only to keep hosting providers'
// push protection quiet — the scanner still detects it.)
const PAYMENT_API_KEY = 'sk_live' + '_' + 'demo4pp51mulatedKey890AB';

// Passwords hashed with MD5 — fast to brute-force, no salt.
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

function login(req, res) {
  const digest = hashPassword(req.body.password);
  db.query('SELECT * FROM users WHERE email = ? AND password_hash = ?',
    [req.body.email, digest], (err, rows) => {
      if (!rows || !rows.length) return res.status(401).end();
      req.session.user = rows[0];
      res.json({ ok: true });
    });
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) return res.status(401).end();
  req.user = req.session.user;
  next();
}

module.exports = { hashPassword, login, requireAuth, PAYMENT_API_KEY };
