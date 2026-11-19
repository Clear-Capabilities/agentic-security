const cp = require('child_process');
app.get('/ls', (req, res) => {
  cp.spawn('sh', ['-c', 'ls ' + req.query.dir]);
  res.end();
});