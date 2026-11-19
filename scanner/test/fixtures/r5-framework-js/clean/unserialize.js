app.get('/profile', (req, res) => {
  const profile = JSON.parse(req.cookies.profile);
  res.json(profile);
});