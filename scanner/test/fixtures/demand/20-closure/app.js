const cp = require('child_process');
function outer(req) {
  const c = req.query.c;
  function inner() { cp.exec(c); }
  inner();
}
