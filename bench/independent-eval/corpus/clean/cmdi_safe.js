// SMOKE FIXTURE (not an independent corpus). Ground truth: CLEAN (CWE-78 absent).
const { execFile } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  // Argv-form execFile — no shell, the host is a single argument, not interpolated.
  execFile('ping', ['-c', '1', req.query.host], (err, out) => res.send(out));
});

module.exports = app;
