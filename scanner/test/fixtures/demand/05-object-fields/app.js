const cp = require('child_process');
function handler(req, res) {
  const opts = { cmd: req.query.cmd, label: 'safe' };
  cp.exec(opts.label);
  cp.exec(opts.cmd);
  res.send(opts.label);
}
