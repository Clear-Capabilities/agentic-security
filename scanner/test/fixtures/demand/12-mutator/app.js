const cp = require('child_process');
function fill(list, v) { list.push(v); }
function merge(o, v) { Object.assign(o, v); }
function viaPush(req) {
  const l = [];
  fill(l, req.query.x);
  cp.exec(l);
}
function viaAssign(req) {
  const o = {};
  merge(o, req.query);
  cp.exec(o.cmd);
}
function viaPushClean(req) {
  const l = [];
  fill(l, 'fixed');
  cp.exec(l);
}
