app.get('/download', (req, res) => {
  res.sendFile(req.query.file, { root: '/srv/files' });
});