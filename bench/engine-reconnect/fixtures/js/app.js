function readInput(req) {
  return req.query.cmd;
}

function runIt(req) {
  const cmd = readInput(req);
  require('child_process').exec(cmd);
}

module.exports = { runIt };
