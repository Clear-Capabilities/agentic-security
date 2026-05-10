import express from 'express';
const app = express();

app.get('/oauth/callback', (req, res) => {
  const next = req.query.redirect_uri;
  res.redirect(next);
});
