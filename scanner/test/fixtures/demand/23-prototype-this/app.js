const cp = require('child_process');
function Runner() { this.cmd = null; }
Runner.prototype.load = function (req) { this.cmd = req.query.cmd; };
Runner.prototype.run = function () { cp.exec(this.cmd); };
module.exports = Runner;
