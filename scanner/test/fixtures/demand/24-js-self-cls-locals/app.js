const cp = require('child_process');
function build(req) {
  const self = { cmd: req.query.cmd };
  cp.exec(self.cmd);
}
function safe() {
  const cls = { cmd: 'ls' };
  cp.exec(cls.cmd);
}
module.exports = { build, safe };
