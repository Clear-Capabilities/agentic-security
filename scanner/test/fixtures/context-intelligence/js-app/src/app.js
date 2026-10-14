const express = require('express');
const { requireUser, requireAdmin } = require('./auth');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

// SAFE: the document is looked up scoped by the authenticated principal.
app.get('/orgs/:orgId/docs/:id', async (req, res) => {
  const doc = await db.query('SELECT * FROM docs WHERE id = $1 AND org_id = $2', [req.params.id, req.user.orgId]);
  logMetric('doc_read', 1);
  res.json(doc);
});

// VULNERABLE: object fetched by a client supplied id, no ownership or tenant scope.
app.get('/docs/:id', async (req, res) => {
  const doc = await db.query('SELECT * FROM docs WHERE id = ' + req.params.id);
  res.json(doc);
});

// GUARD AFTER SENSITIVE OPERATION: the ownership check runs after the write has happened.
app.post('/docs/:id/archive', async (req, res) => {
  const doc = await db.query('UPDATE docs SET archived = true WHERE id = $1', [req.params.id]);
  if (doc.ownerId !== req.user.id) { return res.status(403).end(); }
  res.json(doc);
});

// BFLA: privileged action guarded by an admin middleware on the route.
app.post('/admin/purge', requireAdmin, (req, res) => {
  db.query('DELETE FROM docs');
  res.end();
});

// DYNAMIC DISPATCH: the handler is chosen at runtime.
app.post('/actions/:name', (req, res) => {
  const fn = actions[req.params.name];
  fn(req, res);
});

// RECURSIVE helper reachable from a route.
function walk(node) {
  if (!node.parent) return node;
  return walk(node.parent);
}
app.get('/tree/:id', (req, res) => {
  res.json(walk(req.query.node));
});

// UNRESOLVED first-party call (destructured import is not followed by the IR).
const { getReport } = require('./reports');
app.get('/reports/:id', (req, res) => {
  res.json(getReport(req.params.id));
});
