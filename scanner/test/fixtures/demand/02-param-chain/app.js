const cp = require('child_process');
function leaf(c) {
  cp.exec(c);
}
function mid(c) {
  leaf(c);
}
function top(req, res) {
  const v = req.body.cmd;
  mid(v);
}
function clean(req, res) {
  mid('static-command');
}
function island() {
  cp.exec('date');
}
