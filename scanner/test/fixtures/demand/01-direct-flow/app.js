const cp = require('child_process');
function handler(req, res) {
  const cmd = req.query.cmd;
  cp.exec(cmd);
  cp.exec('ls -la');
}
function other(req, res) {
  cp.exec('uptime');
}
