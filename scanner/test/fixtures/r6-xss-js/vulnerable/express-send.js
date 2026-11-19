const express = require('express');
const app = express();

app.get('/hello', (req, res) => {
  res.send('<p>Hello ' + req.query.name + '</p>');
});

module.exports = app;
