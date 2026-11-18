const vm = require('vm');
app.post('/calc', (req, res) => {
  res.json({ v: vm.runInNewContext('n * 2', { n: req.body.n }) });
});