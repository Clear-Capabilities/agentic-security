app.get('/go', (req, res) => {
  res.location(req.query.next);
  res.sendStatus(302);
});