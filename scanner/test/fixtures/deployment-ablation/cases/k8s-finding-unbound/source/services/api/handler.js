const { exec } = require('child_process');

function listDir(req, res) {
  const dir = req.query.dir;
  exec('ls ' + dir, (err) => {
    res.end();
  });
}

module.exports = { listDir };
