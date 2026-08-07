// Cross-machine determinism fixture.
//
// Deliberately DEPENDENCY-FREE: an SCA finding would depend on the OSV/KEV
// cache, which differs by machine and network state, and would report an
// environment difference as a determinism failure. Everything here is
// first-party source that the SAST and taint layers can decide from the file
// alone. Do not add dependencies, network calls, timestamps, or randomness.
const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');

const app = express();

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.get('/file', (req, res) => {
  res.send(fs.readFileSync('/var/data/' + req.query.name, 'utf8'));
});

app.get('/search', (req, res) => {
  const q = req.query.q;
  db.query("SELECT * FROM items WHERE name = '" + q + "'", (e, rows) => res.json(rows));
});

app.get('/hello', (req, res) => {
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

function digest(pw) {
  return crypto.createHash('md5').update(pw).digest('hex');
}

module.exports = { app, digest };
