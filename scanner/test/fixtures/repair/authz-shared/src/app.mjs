// A multi-tenant notes service. Reads, updates and the public page all load notes through access.mjs.
import { readJson, sendJson, currentUser } from './http.mjs';
import { loadNote } from './access.mjs';
import { readNote } from './read.mjs';
import { writeNote } from './write.mjs';

export function createApp({ db }) {
  return async (req, res) => {
    const url = new URL(req.url, 'http://notes.local');
    const pub = /^\/public\/(\d+)$/.exec(url.pathname);
    if (pub && req.method === 'GET') {
      const note = loadNote(db, Number(pub[1]));
      if (!note || !note.public) return sendJson(res, 404, { error: 'not found' });
      return sendJson(res, 200, { id: note.id, body: note.body });
    }
    const user = currentUser(db, req);
    if (!user) return sendJson(res, 401, { error: 'login required' });
    const m = /^\/notes\/(\d+)$/.exec(url.pathname);
    if (!m) return sendJson(res, 404, { error: 'not found' });
    if (req.method === 'GET') return readNote(db, user, Number(m[1]), res);
    if (req.method === 'PUT') return writeNote(db, user, Number(m[1]), await readJson(req), res);
    return sendJson(res, 405, { error: 'method not allowed' });
  };
}
