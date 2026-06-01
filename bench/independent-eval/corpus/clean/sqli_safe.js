// SMOKE FIXTURE (not an independent corpus). Ground truth: CLEAN (CWE-89 absent).
const express = require('express');
const app = express();
const db = require('./db');

app.get('/users', (req, res) => {
  const id = req.query.id;
  // Parameterized query — the value is bound, never concatenated.
  db.query('SELECT * FROM users WHERE id = ?', [id], (err, rows) => res.json(rows));
});

module.exports = app;
