const cp = require('child_process');
const lib = require('unknown-transform-lib');
function handler(req, res) {
  const t = lib.transform(req.query.cmd);
  cp.exec(t);
  const u = lib.transform('fixed');
  cp.exec(u);
}
