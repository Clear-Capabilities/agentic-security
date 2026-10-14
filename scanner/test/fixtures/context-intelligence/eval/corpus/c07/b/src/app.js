const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { findOwned } = require('./repo');

const app = express();
app.use(requireUser);

app.get('/projects/:id', async (req, res) => {
  const project = await findOwned(req.user, req.params.id);
  res.json(project);
});

module.exports = app;
