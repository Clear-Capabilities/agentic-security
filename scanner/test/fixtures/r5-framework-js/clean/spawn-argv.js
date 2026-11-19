const cp = require('child_process');
app.get('/ls', (req, res) => {
  cp.spawn('ls', ['-l', req.query.dir]);
  res.end();
});