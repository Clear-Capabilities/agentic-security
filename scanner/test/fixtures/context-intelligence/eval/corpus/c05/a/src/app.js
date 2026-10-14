const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

app.post('/tasks/:id/close', async (req, res) => {
  const task = await db.query('UPDATE tasks SET closed = true WHERE id = $1 RETURNING *', [req.params.id]);
  if (task.ownerId !== req.user.id) { return res.status(403).end(); }
  res.json(task);
});

module.exports = app;
