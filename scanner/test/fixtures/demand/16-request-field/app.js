const cp = require('child_process');
function authenticate(req, res) {
  req.user = req.query.user;
}
function handler(req, res) {
  cp.exec(req.user);
}
