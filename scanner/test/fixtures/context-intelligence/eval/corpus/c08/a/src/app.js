const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

const actions = {
  list: async (req, res) => res.json(await db.query('SELECT * FROM jobs')),
  purge: async (req, res) => { await db.query('DELETE FROM jobs'); res.status(204).end(); },
};

app.post('/jobs/:action', async (req, res) => {
  const run = actions[req.params.action];
  return run(req, res);
});

module.exports = app;
