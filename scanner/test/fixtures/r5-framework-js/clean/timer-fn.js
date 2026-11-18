app.get('/later', (req, res) => {
  const id = req.query.id;
  setTimeout(() => notify(id), 100);
  res.end();
});
