const express = require('express');
const axios = require('axios');
const app = express();

// Static URL — must NOT fire SSRF (FP suppression target)
app.get('/health', async (req, res) => {
  const r = await fetch('https://api.example.com/status');
  res.json(await r.json());
});

// Static template literal — must NOT fire SSRF
app.get('/version', async (req, res) => {
  const r = await fetch(`https://api.example.com/version`);
  res.json(await r.json());
});

// process.env URL — must NOT fire SSRF
app.get('/upstream', async (req, res) => {
  const r = await fetch(process.env.UPSTREAM_URL);
  res.json(await r.json());
});

// Static URL with options — must NOT fire SSRF
app.post('/notify', async (req, res) => {
  const r = await axios.post('https://hooks.example.com/notify', { event: 'ping' });
  res.json(r.data);
});

// User-controlled URL — MUST fire SSRF (real vuln)
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const r = await fetch(target);
  res.send(await r.text());
});

app.listen(3000);
