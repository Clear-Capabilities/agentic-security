const cp = require('child_process');
class Runner {
  constructor() { this.cmd = null; }
  load(req) { this.cmd = req.query.cmd; }
  run() { cp.exec(this.cmd); }
}
module.exports = Runner;
