import { sendJson } from './http.mjs';
import { loadNote } from './access.mjs';

export function writeNote(db, user, id, body, res) {
  const note = loadNote(db, id);
  if (!note) return sendJson(res, 404, { error: 'not found' });
  db.prepare('UPDATE notes SET body = ? WHERE id = ?').run(String(body.body), note.id);
  return sendJson(res, 200, { ok: true });
}
