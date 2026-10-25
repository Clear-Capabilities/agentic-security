const cp = require('child_process');
function chargeA(req) { cp.exec(req.query.a); }
function chargeB(x) { return x + '1'; }
function chargeC(y) { cp.exec(chargeB(y)); }
function runC(req) { chargeC(req.body.c); }
