import express from 'express';
import session from 'express-session';
const app = express();
app.use(session({ secret: process.env.SESS_SECRET, resave: false, saveUninitialized: false }));

app.post('/login', async (req, res) => {
  const user = await authenticate(req.body.username, req.body.password);
  if (!user) return res.status(401).end();
  req.session.regenerate((err) => {
    if (err) return res.status(500).end();
    req.session.userId = user.id;
    res.json({ ok: true });
  });
});

async function authenticate(u, p) { return null; }
