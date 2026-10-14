const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();

app.get('/share/:id', async (req, res) => {
  const doc = await db.query('SELECT * FROM documents WHERE id = $1', [req.params.id]);
  res.json(doc);
});

module.exports = app;
