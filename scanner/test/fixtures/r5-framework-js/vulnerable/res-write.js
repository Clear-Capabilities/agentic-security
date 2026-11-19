app.get('/hello', (req, res) => {
  res.write('<h1>' + req.query.name + '</h1>');
  res.end();
});