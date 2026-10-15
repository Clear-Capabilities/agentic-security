const { db } = require('./db');

function requireUser(req, res, next) {
  const token = req.headers.authorization;
  if (!token) { return res.status(401).end(); }
  req.user = lookupSession(token);
  if (!req.user) { return res.status(401).end(); }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') { return res.status(403).end(); }
  next();
}

function lookupSession(token) {
  return db.query('SELECT * FROM sessions WHERE token = $1', [token]);
}

module.exports = { requireUser, requireAdmin };
