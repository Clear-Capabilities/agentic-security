const express = require('express');
const { exec } = require('child_process');
const app = express();

const ACTIONS = { status: 'systemctl status app', restart: 'systemctl restart app' };

app.post('/api/ctl', (req, res) => {
  const cmd = ACTIONS[req.body.action];
  if (!cmd) return res.status(400).end();
  exec(cmd, (err, out) => res.send(out));
});

app.listen(3000);
