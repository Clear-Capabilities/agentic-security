// 3 routes each calling db.query through a shared `buildSql` helper invocation.
// The bundling heuristic finds the common var across the 3 sinks.
const buildSql = (t, w) => 'SELECT * FROM ' + t + ' WHERE ' + w;

app.get('/users/:id', (req, res) => {
  const userId = req.params.id;
  db.query(buildSql('users', "id = '" + userId + "'"));
});
