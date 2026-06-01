// SMOKE FIXTURE (not an independent corpus). Ground truth: VULNERABLE, CWE-89.
const express = require('express');
const app = express();
const db = require('./db');

app.get('/users', (req, res) => {
  const id = req.query.id;
  // User input concatenated straight into the SQL string.
  db.query('SELECT * FROM users WHERE id = ' + id, (err, rows) => res.json(rows));
});

module.exports = app;
