const buildSql = (t, w) => 'SELECT * FROM ' + t + ' WHERE ' + w;

app.get('/items/:id', (req, res) => {
  const itemId = req.params.id;
  db.query(buildSql('items', "id = '" + itemId + "'"));
});
