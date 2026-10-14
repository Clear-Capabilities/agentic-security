const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
app.use(requireUser);

app.get('/notes/:id', async (req, res) => {
  const note = await db.query('SELECT * FROM notes WHERE id = $1 AND owner_id = $2', [req.params.id, req.user.id]);
  logMetric('note_read', 1);
  res.json(note);
});

module.exports = app;
