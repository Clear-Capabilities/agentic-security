const express = require('express');
const escapeHtml = require('escape-html');
const app = express();

app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + escapeHtml(String(req.query.name)) + '</h1>');
});

app.listen(3000);
