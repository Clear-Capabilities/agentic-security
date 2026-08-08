const { exec } = require('child_process');
const { readTarget, readName } = require('./reader');

function ping(req, res) {
  const host = readTarget(req);
  exec('ping -c 1 ' + host, (e, out) => res.send(out));
}

function lookup(req, res, db) {
  const name = readName(req);
  db.query("SELECT * FROM users WHERE name = '" + name + "'", (e, rows) => res.json(rows));
}

module.exports = { ping, lookup };
