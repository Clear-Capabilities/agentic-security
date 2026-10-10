const express = require('express');
const axios = require('axios');
const app = express();
const ALLOWED_HOSTS = new Set(['api.example.com']);
function assertAllowedHost(target) {
  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) {
    throw new Error('host not allowed');
  }
}
app.get('/proxy', async (req, res) => {
  const target = req.query.u;
  assertAllowedHost(target);
  const r = await axios.get(target);
  res.type('text/plain').send(String(r.status));
});
module.exports = { assertAllowedHost };
