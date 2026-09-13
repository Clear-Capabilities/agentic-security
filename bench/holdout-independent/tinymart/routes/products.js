const express = require('express');
const router = express.Router();
const db = require('../lib/db');

// VULNERABLE: SQL injection. `category` comes straight from the query
// string and is concatenated directly into the SQL text — an attacker can
// supply `' OR '1'='1` or a UNION-based payload to read arbitrary rows.
router.get('/search', (req, res) => {
  const category = req.query.category;
  const sql = "SELECT id, name, price FROM products WHERE category = '" + category + "'";
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send('search failed');
    res.json(rows);
  });
});

// FIXED variant of the same query shape: the connector's own placeholder
// binding is used instead of string concatenation, so `category` can never
// change the query's structure regardless of its content.
router.get('/search-safe', (req, res) => {
  const category = req.query.category;
  db.query('SELECT id, name, price FROM products WHERE category = ?', [category], (err, rows) => {
    if (err) return res.status(500).send('search failed');
    res.json(rows);
  });
});

// VULNERABLE: a second, independent SQL injection — this one via a numeric
// path parameter that "looks safe" but is never validated or parameterized.
router.get('/by-vendor/:vendorId', (req, res) => {
  const vendorId = req.params.vendorId;
  db.query('SELECT * FROM products WHERE vendor_id = ' + vendorId, (err, rows) => {
    if (err) return res.status(500).send('lookup failed');
    res.json(rows);
  });
});

module.exports = router;
