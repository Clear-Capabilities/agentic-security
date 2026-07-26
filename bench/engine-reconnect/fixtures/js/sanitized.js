function handler(req, res) {
  const raw = req.query.name;
  const safe = escapeHtml(raw);
  res.send(safe);
}

module.exports = { handler };
