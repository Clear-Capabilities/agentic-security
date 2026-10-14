const express = require('express');
const { requireUser, requireAdmin } = require('./session');
const { db, logMetric } = require('./db');

const app = express();
const router = express.Router();
router.use(requireUser);

router.post('/purge', async (req, res) => {
  await db.query('DELETE FROM audit_events WHERE created_at < $1', [req.body.before]);
  res.status(204).end();
});

app.use('/admin', router);
module.exports = app;
