// Source file: takes user input, passes it to an imported helper.
const { lookupUser } = require('./lib');
const express = require('express');
const app = express();

app.post('/login', (req, res) => {
  const userInput = req.body.username;
  const result = lookupUser(userInput);
  res.json(result);
});
