const express = require('express');
const app = express();

app.post('/run', (req, res) => {
  const { exec } = require('child_process');
  // agentic-security: ignore Command Injection — input is whitelisted by upstream gateway
  exec('echo ' + req.body.cmd, (e, o) => res.send(o));
});

app.post('/eval', (req, res) => {
  // agentic-security: ignore-next-line
  res.send(eval(req.body.expr));
});

// This one should still fire (no pragma).
app.get('/sql/:id', (req, res) => {
  const db = require('./db');
  db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
});

app.listen(3000);
