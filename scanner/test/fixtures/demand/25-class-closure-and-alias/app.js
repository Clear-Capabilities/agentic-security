const cp = require('child_process');
class Job {
  setCmd(req) { this.cmd = req.query.cmd; }
  start() {
    const self = this;
    setTimeout(() => { cp.exec(self.cmd); }, 0);
  }
  startArrow() {
    [1].forEach(() => { cp.exec(this.cmd); });
  }
}
function go(req) {
  const j = new Job();
  j.setCmd(req);
  j.start();
  j.startArrow();
}
module.exports = { Job, go };
