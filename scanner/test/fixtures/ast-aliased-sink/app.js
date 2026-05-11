const express = require('express');
const cp = require('child_process');
const app = express();

// Aliased exec via destructuring — should taint
const { exec } = cp;
app.post('/run', (req, res) => {
  exec('echo ' + req.body.cmd, (e, o) => res.send(o));
});

// Aliased exec via property reassignment
const runShell = cp.exec;
app.post('/run2', (req, res) => {
  runShell('ls ' + req.query.dir, (e, o) => res.send(o));
});

// Indirect bracket-access
app.post('/run3', (req, res) => {
  cp['exec']('cat ' + req.body.file, (e, o) => res.send(o));
});

app.listen(3000);
