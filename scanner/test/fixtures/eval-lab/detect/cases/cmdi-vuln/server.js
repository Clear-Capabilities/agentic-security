const express = require('express');
const { exec } = require('child_process');
const app = express();
app.use(express.json());

// FLAW: unsanitized host reaches a shell (CWE-78)
app.post('/api/ping', (req, res) => {
  exec('ping -c 1 ' + req.body.host, (err, out) => res.send(out));
});

app.listen(3000);
