// Controlled call/return fixture: one shared helper called from several sites
// with the same field (so the callee body is shared), a nested helper, and a
// helper called with a clean and a tainted argument.
function id(x) { return x; }
function wrap(v) { return id(v); }
function pick(a, b) { return a; }

function twoCalls(req) {
  const r1 = id(req.body.email);
  const r2 = id(req.body.email);
  console.log(r1);
  console.log(r2);
}

function nested(req) {
  const w1 = wrap(req.body.name);
  const w2 = wrap(req.body.name);
  console.log(w1);
  console.log(w2);
}

function positions(req) {
  const e1 = req.body.first;
  const e2 = req.body.first;
  const r = pick(e1, e2);
  console.log(r);
}

function cleanAndDirty(req) {
  const clean = id('plain');
  const dirty = id(req.body.token);
  console.log(clean);
  console.log(dirty);
}

module.exports = { twoCalls, nested, positions, cleanAndDirty };
