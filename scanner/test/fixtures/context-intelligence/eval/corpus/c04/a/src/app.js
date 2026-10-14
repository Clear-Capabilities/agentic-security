const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();

app.get('/share/:token', async (req, res) => {
  const link = await db.query('SELECT doc_id FROM share_links WHERE token = $1 AND expires_at > now()', [req.params.token]);
  const doc = await db.query('SELECT * FROM documents WHERE id = $1', [link.doc_id]);
  res.json(doc);
});

module.exports = app;
