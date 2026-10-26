const cp = require('child_process');
function handler(req, res) {
  const { cmd, label } = req.query;
  cp.exec(cmd);
  cp.exec(label);
}
