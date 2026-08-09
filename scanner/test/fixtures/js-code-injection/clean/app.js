const { NodeVM } = require('vm2');
const vm = new NodeVM({});
const ALLOWED = { sum: (a, b) => a + b, upper: (s) => String(s).toUpperCase() };
module.exports = async function handler(req, res) {
  // Dispatch table, not an evaluator: the operation is chosen from a fixed set
  // and the request never contributes source text.
  const op = ALLOWED[req.body.op];
  if (!op) return res.status(400).send('unknown op');
  res.send(op(req.body.a, req.body.b));
  await vm.run('module.exports = 1', __dirname); // literal: not a sink
};
