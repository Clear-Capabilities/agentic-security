const cp = require('child_process');
function noSource() {
  const cmd = 'ls -la';
  cp.exec(cmd);
}
function literalArg() {
  cp.exec('uptime');
}
