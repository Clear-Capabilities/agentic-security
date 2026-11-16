// A small notes service. Search builds its SQL by string concatenation.
import { readJson, sendJson } from './http.mjs';

export function createApp({ db }) {
  return async (req, res) => {
    const url = new URL(req.url, 'http://notes.local');
    const user = String(req.headers['x-user'] || '');
    if (!user) return sendJson(res, 401, { error: 'login required' });
    if (req.method === 'GET' && url.pathname === '/notes') {
      const title = url.searchParams.get('title') || '';
      try {
        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();
        return sendJson(res, 200, rows);
      } catch {
        return sendJson(res, 500, { error: 'query failed' });
      }
    }
    if (req.method === 'POST' && url.pathname === '/notes') {
      const b = await readJson(req);
      db.prepare('INSERT INTO notes (owner, title, body) VALUES (?, ?, ?)').run(user, String(b.title), String(b.body));
      return sendJson(res, 201, { ok: true });
    }
    return sendJson(res, 404, { error: 'not found' });
  };
}
