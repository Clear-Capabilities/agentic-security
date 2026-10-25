const cp = require('child_process');
let pending = null;
function init(req) {
  pending = req.query.cmd;
}
function runPending() {
  cp.exec(pending);
}
