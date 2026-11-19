const express = require('express');
const he = require('he');
const app = express();

app.get('/hello', (req, res) => {
  res.send('<p>Hello ' + he.encode(req.query.name) + '</p>');
});

app.get('/hello.json', (req, res) => {
  res.json({ hello: req.query.name });
});

module.exports = app;
