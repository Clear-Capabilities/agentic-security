// Loads a note by id. Every route goes through here.
export function loadNote(db, id) {
  return db.prepare('SELECT id, owner, tenant, public, body FROM notes WHERE id = ?').get(id) || null;
}
