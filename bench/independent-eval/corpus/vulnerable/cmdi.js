// SMOKE FIXTURE (not an independent corpus). Ground truth: VULNERABLE, CWE-78.
const { exec } = require('child_process');
const express = require('express');
const app = express();

app.get('/ping', (req, res) => {
  // User input concatenated into a shell command string.
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

module.exports = app;
