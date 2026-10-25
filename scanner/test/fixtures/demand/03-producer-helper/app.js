const cp = require('child_process');
const { readInput, constant } = require('./helpers');
function handler(req, res) {
  const taintedCmd = readInput();
  cp.exec(taintedCmd);
  const safeCmd = constant();
  cp.exec(safeCmd);
}
