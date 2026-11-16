// Accounts: POST /register {user, password} and POST /login {user, password}. Passwords are stored as an unsalted MD5 digest.
import crypto from 'node:crypto';

function hashPassword(password) {
  return crypto.createHash('md5').update(String(password)).digest('hex');
}

function readJson(req) {
  return new Promise((resolve) => {
    let t = '';
    req.on('data', (d) => { t += d; });
    req.on('end', () => { try { resolve(JSON.parse(t || '{}')); } catch { resolve({}); } });
  });
}

export function createApp({ db }) {
  const insert = db.prepare('INSERT INTO users (name, pw) VALUES (?, ?)');
  const byName = db.prepare('SELECT name, pw FROM users WHERE name = ?');
  const send = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  return async (req, res) => {
    const b = await readJson(req);
    if (req.method === 'POST' && req.url === '/register') {
      if (typeof b.user !== 'string' || typeof b.password !== 'string' || byName.get(b.user)) return send(res, 400, { error: 'invalid' });
      insert.run(b.user, hashPassword(b.password));
      return send(res, 201, { ok: true });
    }
    if (req.method === 'POST' && req.url === '/login') {
      const row = typeof b.user === 'string' ? byName.get(b.user) : null;
      if (!row || typeof b.password !== 'string' || row.pw !== hashPassword(b.password)) return send(res, 401, { error: 'invalid credentials' });
      return send(res, 200, { ok: true, user: row.name });
    }
    return send(res, 404, { error: 'not found' });
  };
}
