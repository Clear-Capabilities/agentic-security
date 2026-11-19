const vm = require('vm');
app.post('/calc', (req, res) => {
  res.json({ v: vm.runInNewContext(req.body.expr, {}) });
});