const buildSql = (t, w) => 'SELECT * FROM ' + t + ' WHERE ' + w;

app.get('/orders/:id', (req, res) => {
  const orderId = req.params.id;
  db.query(buildSql('orders', "id = '" + orderId + "'"));
});
