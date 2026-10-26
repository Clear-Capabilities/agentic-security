function handler(req, res) {
  const payload = { a: req.query.a, b: 'safe' };
  res.send(payload);
}
function whole(req, res) {
  const body = req.query;
  res.send(body);
}
