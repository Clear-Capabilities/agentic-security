const express = require('express');
const router = express.Router();
const { exec, execFile } = require('child_process');

// VULNERABLE: command injection. `hostname` is interpolated directly into a
// shell command string — an attacker supplies `; rm -rf / #` or similar to
// run arbitrary commands with the server process's privileges.
router.get('/ping', (req, res) => {
  const hostname = req.query.host;
  exec('ping -c 1 ' + hostname, (err, stdout) => {
    if (err) return res.status(500).send('ping failed');
    res.type('text/plain').send(stdout);
  });
});

// FIXED variant of the same feature: execFile with an argument ARRAY never
// invokes a shell, so no metacharacter in `hostname` can change what
// command actually runs — it can only ever be passed as literal argv[1].
router.get('/ping-safe', (req, res) => {
  const hostname = req.query.host;
  execFile('ping', ['-c', '1', hostname], (err, stdout) => {
    if (err) return res.status(500).send('ping failed');
    res.type('text/plain').send(stdout);
  });
});

module.exports = router;
