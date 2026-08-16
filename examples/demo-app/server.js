// demo-app — deliberately vulnerable. See README.md. Never deploy.
const express = require('express');
const db = require('./db');
const { requireAuth } = require('./auth');

const app = express();
app.use(express.json());

// SQL injection: the order id is concatenated straight into the query.
app.get('/orders/:id', requireAuth, (req, res) => {
  db.query(`SELECT * FROM orders WHERE id = ${req.params.id}`, (err, rows) => {
    res.json(rows);
  });
});

app.get('/orders', requireAuth, (req, res) => {
  db.query('SELECT * FROM orders WHERE user_id = ?', [req.user.id], (err, rows) => {
    res.json(rows);
  });
});

app.post('/orders', requireAuth, (req, res) => {
  db.query('INSERT INTO orders (user_id, total) VALUES (?, ?)', [req.user.id, req.body.total], () => {
    res.status(201).end();
  });
});

// Missing auth: every sibling route checks, this state-changer doesn't —
// anyone who can reach the API can delete any order by id.
app.delete('/orders/:id', (req, res) => {
  db.query('DELETE FROM orders WHERE id = ?', [req.params.id], () => {
    res.status(204).end();
  });
});

// Code injection: a "price rule calculator" that evals user input.
app.post('/admin/price-rule', requireAuth, (req, res) => {
  const discounted = eval(req.body.rule);
  res.json({ discounted });
});

app.listen(3000);
