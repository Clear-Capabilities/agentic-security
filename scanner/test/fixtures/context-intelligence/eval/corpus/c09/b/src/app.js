const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

app.post('/transfers', async (req, res) => {
  await db.transaction(async (tx) => {
    await tx.query('UPDATE accounts SET balance = balance - $1 WHERE id = $2', [req.body.amount, req.user.accountId]);
    await tx.query('UPDATE accounts SET balance = balance + $1 WHERE id = $2', [req.body.amount, req.body.to]);
  });
  res.status(201).end();
});

module.exports = app;
