// Control: no sanitizer at all. Must not be labelled sanitized.
app.get('/item', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM items WHERE id = " + id);
});
