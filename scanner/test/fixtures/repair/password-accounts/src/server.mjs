// Member accounts: POST /signup {email, secret} and POST /session {email, secret}. Secrets are kept as an unsalted SHA-256 digest.
import { createHash } from 'node:crypto';

const digest = (secret) => createHash('sha256').update(secret, 'utf8').digest('hex');

async function bodyOf(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { return {}; }
}

export function buildServer({ db: database }) {
  const add = database.prepare('INSERT INTO members (email, secret_hash, created) VALUES (?, ?, ?)');
  const find = database.prepare('SELECT email, secret_hash FROM members WHERE email = ?');
  const reply = (res, code, payload) => { res.statusCode = code; res.setHeader('content-type', 'application/json'); res.end(JSON.stringify(payload)); };
  return async (req, res) => {
    const body = await bodyOf(req);
    const ok = typeof body.email === 'string' && typeof body.secret === 'string' && body.secret.length >= 8;
    if (req.method === 'POST' && req.url === '/signup') {
      if (!ok || find.get(body.email)) return reply(res, 422, { error: 'rejected' });
      add.run(body.email, digest(body.secret), Date.now());
      return reply(res, 201, { created: body.email });
    }
    if (req.method === 'POST' && req.url === '/session') {
      const member = ok ? find.get(body.email) : undefined;
      if (member && digest(body.secret) === member.secret_hash) return reply(res, 200, { session: member.email });
      return reply(res, 403, { error: 'denied' });
    }
    return reply(res, 404, { error: 'unknown route' });
  };
}
