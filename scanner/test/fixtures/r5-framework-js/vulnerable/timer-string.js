app.get('/later', (req, res) => {
  setTimeout('notify(' + req.query.id + ')', 100);
  res.end();
});