const express = require('express');
const { execFile } = require('child_process');
const app = express();
app.use(express.json());

app.post('/api/ping', (req, res) => {
  const host = String(req.body.host);
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(host)) return res.status(400).end();
  execFile('ping', ['-c', '1', host], (err, out) => res.send(out));
});

app.listen(3000);
