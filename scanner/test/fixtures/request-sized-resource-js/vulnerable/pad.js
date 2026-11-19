const express = require('express');
const app = express();

app.get('/pad', (req, res) => {
  const width = parseInt(req.query.width, 10);
  const line = ''.padEnd(width, '-');
  const buf = new Uint8Array(width);
  const cells = Array.from({ length: width }, (_, i) => i);
  for (const i of cells) {
    buf[i] = 45;
  }
  res.send(line + buf.length);
});

app.post('/dedupe', (req, res) => {
  const tags = req.body.tags;
  const unique = [];
  for (const tag of tags) {
    if (!unique.includes(tag)) unique.push(tag);
  }
  res.json(unique);
});
