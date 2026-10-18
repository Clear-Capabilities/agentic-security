const express = require('express');
const db = require('./db');
const router = express.Router();

router.get('/user', (req, res) => {
  db.query('SELECT * FROM users WHERE id = ?', [req.query.id], (err, rows) => res.json(rows));
});

module.exports = router;
