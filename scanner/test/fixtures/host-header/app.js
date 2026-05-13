const express = require('express');
const app = express();

// VULNERABLE: reset link uses req.headers.host
app.post('/reset-request', (req, res) => {
  const token = generateToken();
  const link = `https://${req.headers.host}/reset?token=${token}`;
  sendEmail(req.body.email, `Click to reset: ${link}`);
  res.json({ ok: true });
});

// VULNERABLE: redirect target uses host header
app.get('/verify', (req, res) => {
  return res.redirect('https://' + req.headers.host + '/welcome');
});

// SAFE: uses env constant
app.post('/reset-safe', (req, res) => {
  const token = generateToken();
  const link = `${process.env.PUBLIC_HOST}/reset?token=${token}`;
  sendEmail(req.body.email, link);
  res.json({ ok: true });
});

function generateToken() { return require('crypto').randomBytes(32).toString('hex'); }
function sendEmail() {}

app.listen(3000);
