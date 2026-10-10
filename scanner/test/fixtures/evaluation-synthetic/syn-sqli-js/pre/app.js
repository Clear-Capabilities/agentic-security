// SYNTHETIC evaluation fixture. Authored for tooling tests, not real-world code.
const express = require('express');
const db = require('./db');
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = '" + id + "'", (err, rows) => {
    res.json(rows);
  });
});

app.listen(3000);
