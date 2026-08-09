const { NodeVM } = require('vm2');
const vm = new NodeVM({});
module.exports = async function handler(req, res) {
  // The sandbox is not a control: running attacker-influenced source in vm2 is
  // still code injection. This is the shape from GHSA-3769-jgqc-cxm7.
  const out = await vm.run(`module.exports = async function(){${req.body.code}}()`, __dirname);
  res.send(out);
};
