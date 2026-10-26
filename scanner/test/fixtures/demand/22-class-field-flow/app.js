const cp = require('child_process');
class Box {
  set(v) { this.v = v; }
  get() { return this.v; }
  other() { return 'x'; }
}
function h(req) {
  const o = new Box();
  o.set(req.query.x);
  cp.exec(o.get());
}
function h2(req) {
  const o = new Box();
  o.v = req.query.y;
  cp.exec(o.get());
}
function h3(req) {
  const o = new Box();
  o.set('lit');
  cp.exec(o.get());
}
class Run {
  constructor(c) { this.c = c; }
  go() { cp.exec(this.c); }
}
function h4(req) {
  const r = new Run(req.query.z);
  r.go();
}
function h5(req) {
  const r = new Run('ls');
  r.go();
}
