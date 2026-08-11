// Same sanitizer as wrong-family/ (escapeHtml, appliesTo 'xss'), but here it
// guards an XSS sink — so the family MATCHES and the finding must be labelled.
app.get('/item', (req, res) => {
  const name = escapeHtml(req.query.name);
  el.insertAdjacentHTML('beforeend', name);
});
