const cp = require('child_process');
function each(list, cb) {
  cb(list);
}
function named(v) {
  cp.exec(v);
}
function handler(req, res) {
  each(req.query.x, function (v) { cp.exec(v); });
  [req.body.q].forEach((z) => cp.exec(z));
  each(req.query.y, named);
  each('fixed', function (w) { cp.exec(w); });
}
