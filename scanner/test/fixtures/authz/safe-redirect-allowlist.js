import express from 'express';
const app = express();
const ALLOWED_REDIRECTS = ['https://app.example/home', 'https://app.example/dashboard'];

app.get('/oauth/callback', (req, res) => {
  const next = req.query.redirect_uri;
  if (!ALLOWED_REDIRECTS.includes(next)) {
    return res.status(400).end();
  }
  res.redirect(next);
});
