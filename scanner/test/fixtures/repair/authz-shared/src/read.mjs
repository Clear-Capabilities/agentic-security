import { sendJson } from './http.mjs';
import { loadNote } from './access.mjs';

export function readNote(db, user, id, res) {
  const note = loadNote(db, id);
  if (!note) return sendJson(res, 404, { error: 'not found' });
  return sendJson(res, 200, { id: note.id, body: note.body });
}
