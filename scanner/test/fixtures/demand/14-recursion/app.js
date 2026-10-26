const cp = require('child_process');
function descend(n, acc) {
  if (n <= 0) { cp.exec(acc); return; }
  descend(n - 1, acc + 'x');
}
function entry(req, res) {
  descend(3, req.query.cmd);
}
function entryClean(req, res) {
  descend(3, 'fixed');
}
