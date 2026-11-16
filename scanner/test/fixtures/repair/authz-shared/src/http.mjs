export function sendJson(res, status, value) {
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(JSON.stringify(value));
}

export function readJson(req) {
  return new Promise((resolve) => {
    let raw = '';
    req.on('data', (d) => { raw += d; });
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { resolve({}); } });
  });
}

// The session lookup: a bearer token names a user row (id, tenant, role).
export function currentUser(db, req) {
  const m = /^Bearer (\w+)$/.exec(String(req.headers.authorization || ''));
  if (!m) return null;
  return db.prepare('SELECT id, tenant, role FROM users WHERE token = ?').get(m[1]) || null;
}
