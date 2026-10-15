const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();

app.post('/users/:id/role', requireUser, async (req, res) => {
  await db.query('UPDATE users SET role = $1 WHERE id = $2', [req.body.role, req.params.id]);
  res.status(204).end();
});

module.exports = app;
