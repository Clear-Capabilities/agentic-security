app.get('/go', (req, res) => {
  const next = req.query.next;
  if (!next.startsWith('/') || next.startsWith('//')) return res.sendStatus(400);
  res.location(next);
  res.sendStatus(302);
});