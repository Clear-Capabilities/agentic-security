const axios = require('axios');
app.post('/hook', async (req, res) => {
  const r = await axios.post(req.body.callback, { ok: true });
  res.json(r.data);
});