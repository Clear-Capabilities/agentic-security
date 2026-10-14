// Shared authorization helpers used by several routes.
const { db } = require('./db');

function requireUser(req, res, next) {
  if (!req.headers.authorization) { return res.status(401).end(); }
  req.user = lookupSession(req.headers.authorization);
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
