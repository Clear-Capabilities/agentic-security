const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

app.get('/orgs/:orgId/invoices/:id', async (req, res) => {
  const invoice = await db.query('SELECT * FROM invoices WHERE id = $1 AND org_id = $2', [req.params.id, req.user.orgId]);
  res.json(invoice);
});

module.exports = app;
