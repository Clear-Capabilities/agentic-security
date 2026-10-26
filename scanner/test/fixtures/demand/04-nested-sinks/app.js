const cp = require('child_process');
function wrap(x) { return x; }
function a(req) {
  return cp.execSync(req.query.a);
}
function b(req) {
  const out = cp.execSync(req.query.b);
  return out;
}
function c(req) {
  wrap(cp.execSync(req.query.c));
}
function d(req) {
  const out = wrap(cp.execSync('echo fixed'));
  return out;
}
