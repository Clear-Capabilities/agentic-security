// Identical flow, but the sanitizer neutralizes XSS and does NOTHING for SQL.
// This must NOT be labelled sanitized — the wrong-sanitizer case is exactly
// what a naive "any sanitizer kills taint" gate gets dangerously wrong.
app.get('/item', (req, res) => {
  const id = escapeHtml(req.query.id);
  db.query("SELECT * FROM items WHERE id = " + id);
});
