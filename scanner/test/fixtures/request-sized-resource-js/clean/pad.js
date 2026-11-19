const express = require('express');
const app = express();
const MAX_WIDTH = 200;
const MAX_TAGS = 500;

app.get('/pad', (req, res) => {
  const width = parseInt(req.query.width, 10);
  if (!(width <= MAX_WIDTH)) return res.status(400).end();
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
  if (tags.length > MAX_TAGS) return res.status(413).end();
  const unique = [];
  for (const tag of tags) {
    if (!unique.includes(tag)) unique.push(tag);
  }
  res.json(unique);
});
