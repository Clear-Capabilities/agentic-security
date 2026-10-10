const express = require('express');
const axios = require('axios');
const app = express();
const ALLOWED_HOSTS = new Set(['api.example.com']);
app.get('/proxy', async (req, res) => {
  const target = req.query.u;
  const r = await axios.get(target);
  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) {
    console.log('unexpected host');
  }
  res.type('text/plain').send(String(r.status));
});
