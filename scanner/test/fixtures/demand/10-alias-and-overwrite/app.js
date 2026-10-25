const cp = require('child_process');
function aliased(req) {
  const a = req.query.x;
  const b = a;
  cp.exec(b);
}
function overwritten(req) {
  let c = req.query.y;
  c = 'static';
  cp.exec(c);
}
function concatenated(req) {
  const d = 'ping ' + req.query.host;
  cp.exec(d);
}
