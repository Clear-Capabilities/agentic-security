const axios = require('axios');
app.post('/hook', async (req, res) => {
  const r = await axios.post('https://hooks.internal.test/notify', { id: req.body.id });
  res.json(r.data);
});