app.get('/users', async (req, res) => {
  const rows = await prisma.$queryRawUnsafe('SELECT * FROM users WHERE name = $1', req.query.name);
  res.json(rows);
});