// A multi-tenant notes service. Reads and updates look a note up by id only.
import { readJson, sendJson, currentUser } from './http.mjs';

export function createApp({ db }) {
  const byId = db.prepare('SELECT id, owner, tenant, body FROM notes WHERE id = ?');
  const update = db.prepare('UPDATE notes SET body = ? WHERE id = ?');
  return async (req, res) => {
    const url = new URL(req.url, 'http://notes.local');
    const user = currentUser(db, req);
    if (!user) return sendJson(res, 401, { error: 'login required' });
    const m = /^\/notes\/(\d+)$/.exec(url.pathname);
    if (!m) return sendJson(res, 404, { error: 'not found' });
    const note = byId.get(Number(m[1]));
    if (!note) return sendJson(res, 404, { error: 'not found' });
    if (req.method === 'GET') return sendJson(res, 200, { id: note.id, body: note.body });
    if (req.method === 'PUT') {
      const b = await readJson(req);
      update.run(String(b.body), note.id);
      return sendJson(res, 200, { ok: true });
    }
    return sendJson(res, 405, { error: 'method not allowed' });
  };
}
