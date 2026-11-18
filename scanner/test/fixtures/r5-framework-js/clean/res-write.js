const escapeHtml = require('escape-html');
app.get('/hello', (req, res) => {
  res.write('<h1>' + escapeHtml(req.query.name) + '</h1>');
  res.end();
});