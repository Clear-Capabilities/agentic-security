const express = require('express');
const app = express();

function requireUser(req, res, next) {
  if (!req.user) return res.sendStatus(401);
  next();
}

// SQL injection: the search term is concatenated into the statement
app.get('/search', requireUser, async (req, res) => {
  const rows = await db.query("SELECT id, title FROM notes WHERE title LIKE '%" + req.query.q + "%'");
  res.json(rows);
});

// safe lookalike: the value is bound
app.get('/lookup', requireUser, async (req, res) => {
  const rows = await db.query('SELECT sku, name FROM catalog WHERE sku = ?', [req.query.sku]);
  res.json(rows);
});

// safe lookalike: the only operand is a constant
app.get('/report', requireUser, async (req, res) => {
  const table = 'notes';
  const rows = await db.query('SELECT COUNT(*) FROM ' + table);
  res.json(rows);
});

// the enforcing sibling: reads are scoped to the owner
app.get('/notes/:id', requireUser, async (req, res) => {
  const note = await db.notes.findOne({ id: req.params.id, ownerId: req.user.id });
  if (!note) return res.sendStatus(404);
  res.json(note);
});

// IDOR: any signed-in user can change any note
app.put('/notes/:id', requireUser, async (req, res) => {
  await db.notes.updateOne({ id: req.params.id }, { $set: req.body });
  res.sendStatus(204);
});

// the enforcing sibling: invoices are scoped to the tenant
app.get('/invoices/:id', requireUser, async (req, res) => {
  const invoice = await db.invoices.findOne({ id: req.params.id, tenantId: req.user.tenantId });
  if (!invoice) return res.sendStatus(404);
  res.json(invoice);
});

// cross-tenant: the lines of any tenant's invoice
app.get('/invoices/:id/lines', requireUser, async (req, res) => {
  const lines = await db.lines.find({ invoiceId: req.params.id });
  res.json(lines);
});

module.exports = app;
