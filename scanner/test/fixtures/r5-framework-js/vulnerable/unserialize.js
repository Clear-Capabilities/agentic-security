const serialize = require('node-serialize');
app.get('/profile', (req, res) => {
  const profile = serialize.unserialize(req.cookies.profile);
  res.json(profile);
});