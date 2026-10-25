const cp = require('child_process');
class Svc {
  fetchCmd() { return process.env.CMD; }
  fixedCmd() { return 'ls'; }
}
function h(req) {
  const s = new Svc();
  const c = s.fetchCmd();
  cp.exec(c);
  const d = s.fixedCmd();
  cp.exec(d);
}
