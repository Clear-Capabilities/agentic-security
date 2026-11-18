app.get('/download', (req, res) => {
  res.sendFile('/srv/files/' + req.query.file);
});