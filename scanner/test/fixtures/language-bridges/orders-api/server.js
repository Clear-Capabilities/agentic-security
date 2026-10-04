const express = require('express');
const app = express();
app.use(express.json());

// a comment mentioning app.post('/api/ghost') must not declare a route
app.post('/api/orders', (req, res) => {
  const { email, quantity } = req.body;
  const region = process.env.DB_NAME;
  res.json({ ok: true, email, quantity, region });
});

app.get('/health', (req, res) => res.send('ok'));
app.listen(8080);
