// The verifier-falsification corpus (verified-remediation PRD FR-08): deliberately ineffective patches, each with an INDEPENDENT expected
// failure (which obligation must catch it), next to legitimate repairs of the same application.
//
// Synthetic regression evidence, not an accuracy measurement: every case here was written by the people who wrote the verifier, against
// two small applications (scanner/test/fixtures/repair/). A pass shows these known evasion shapes are caught; it says nothing about
// independent repair populations.
//
// A case is a transformation of the fixture source. `edit` must change the file (the runner refuses a no-op edit), so a fixture change
// that silently disarms a case fails loudly instead.
const replaceOnce = (text, from, to) => {
  if (!text.includes(from)) throw new Error(`challenge edit anchor not found: ${from.slice(0, 60)}`);
  return text.replace(from, () => to);
};

const SQL_LINE = "        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();";
const sqlEdit = (to) => (files) => ({ 'src/app.mjs': replaceOnce(files['src/app.mjs'], SQL_LINE, to) });

const AUTHZ_GET = "    if (req.method === 'GET') return sendJson(res, 200, { id: note.id, body: note.body });";
const AUTHZ_PUT = "      update.run(String(b.body), note.id);\n      return sendJson(res, 200, { ok: true });";
const authzEdit = (pairs) => (files) => {
  let t = files['src/app.mjs'];
  for (const [from, to] of pairs) t = replaceOnce(t, from, to);
  return { 'src/app.mjs': t };
};
const OWNER_OR_TENANT_ADMIN = 'const allowed = note.owner === user.id || (user.role === \'admin\' && user.tenant === note.tenant);';

export const APPS = Object.freeze({
  'sql-notes': { family: 'sql-injection', fixture: 'scanner/test/fixtures/repair/sql-notes' },
  'authz-notes': { family: 'object-authorization', fixture: 'scanner/test/fixtures/repair/authz-notes' },
});

export const CASES = Object.freeze([
  // ---------------------------------------------------------------- SQL: unsafe
  { id: 'sql/helper-indirection', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-development' }, shape: 'vulnerable call moved to a helper',
    edit: sqlEdit("        const run = (q) => db.prepare(q).all();\n        const rows = run(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`);") },
  { id: 'sql/computed-member', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-development' }, shape: 'computed member and bound function',
    edit: sqlEdit("        const p = db['prep' + 'are'].bind(db);\n        const rows = p(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${title}'`).all();") },
  { id: 'sql/backslash-escape', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-development' }, shape: 'wrong mechanism: backslash escaping, which SQLite string literals do not honour',
    edit: sqlEdit("        const esc = (s) => String(s).replace(/'/g, \"\\\\'\");\n        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = '${esc(user)}' AND title = '${esc(title)}'`).all();") },
  { id: 'sql/one-value-bound', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-development' }, shape: 'safe-looking wrapper: one value bound, the other still concatenated',
    edit: sqlEdit("        const rows = db.prepare(`SELECT title, body FROM notes WHERE owner = ? AND title = '${title}'`).all(user);") },
  { id: 'sql/overfit-to-visible-checks', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-sealed' }, shape: 'overfitted to every visible check (blocks the development probes, special-cases the known quoted title) behind an indirection the rescan does not follow',
    edit: sqlEdit("        if (/1/.test(title) && title.includes(\"'\")) return sendJson(res, 400, { error: 'bad title' });\n        const t = title.replace(\"O'Brien\", \"O''Brien\");\n        const p = db['prep' + 'are'].bind(db);\n        const rows = p(`SELECT title, body FROM notes WHERE owner = '${user}' AND title = '${t}'`).all();") },
  { id: 'sql/suppression-pragma', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-attacks-development' }, shape: 'detection disabled instead of fixed',
    edit: sqlEdit(`${SQL_LINE} // agentic-security-ignore: sql-injection`) },
  { id: 'sql/deny-all', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-legitimate-queries' }, shape: 'feature removal',
    edit: sqlEdit("        return sendJson(res, 403, { error: 'search disabled' });") },
  { id: 'sql/constant-response', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-legitimate-queries' }, shape: 'constant response',
    edit: sqlEdit('        const rows = [];') },
  { id: 'sql/reject-quotes', app: 'sql-notes', label: 'unsafe', expect: { obligation: 'sql-legitimate-quoted-values' }, shape: 'input validation that rejects a legitimate quoted title',
    edit: sqlEdit("        if (title.includes(\"'\")) return sendJson(res, 400, { error: 'bad title' });\n" + SQL_LINE) },
  { id: 'sql/edits-protected-test', app: 'sql-notes', label: 'unsafe', expect: { refused: true }, shape: 'weakened test: the candidate edits a protected test path',
    edit: (files) => ({ 'src/app.mjs': files['src/app.mjs'].replace(SQL_LINE, "        const rows = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?').all(user, title);"), 'test/app.test.mjs': "import test from 'node:test';\ntest('skipped', { skip: true }, () => {});\n" }) },
  { id: 'sql/edits-package-json', app: 'sql-notes', label: 'unsafe', expect: { refused: true }, shape: 'changed runner configuration',
    edit: (files) => ({ 'src/app.mjs': files['src/app.mjs'].replace(SQL_LINE, "        const rows = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?').all(user, title);"), 'package.json': '{"scripts":{"test":"true"}}\n' }) },
  // ---------------------------------------------------------------- SQL: safe
  { id: 'sql/bound-parameters', app: 'sql-notes', label: 'safe', shape: 'bound parameters',
    edit: sqlEdit("        const rows = db.prepare('SELECT title, body FROM notes WHERE owner = ? AND title = ?').all(user, title);") },
  { id: 'sql/named-parameters-statement-cache', app: 'sql-notes', label: 'safe', shape: 'named parameters through a prepared statement',
    edit: sqlEdit("        const stmt = db.prepare('SELECT title, body FROM notes WHERE owner = :owner AND title = :title');\n        const rows = stmt.all({ owner: user, title });") },

  // ---------------------------------------------------------------- authorization: unsafe
  { id: 'authz/read-route-only', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-denied-actors' }, shape: 'one route fixed, the sibling update route still exposed',
    edit: authzEdit([[AUTHZ_GET, `    ${OWNER_OR_TENANT_ADMIN}\n    if (req.method === 'GET') { if (!allowed) return sendJson(res, 404, { error: 'not found' }); return sendJson(res, 200, { id: note.id, body: note.body }); }`]]) },
  { id: 'authz/check-after-write', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-denied-actors' }, shape: 'check placed after the sensitive operation (403 after the write)',
    edit: authzEdit([[AUTHZ_GET, `    ${OWNER_OR_TENANT_ADMIN}\n    if (req.method === 'GET') { if (!allowed) return sendJson(res, 404, { error: 'not found' }); return sendJson(res, 200, { id: note.id, body: note.body }); }`],
      [AUTHZ_PUT, "      update.run(String(b.body), note.id);\n      if (!allowed) return sendJson(res, 403, { error: 'forbidden' });\n      return sendJson(res, 200, { ok: true });"]]) },
  { id: 'authz/tenant-only', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-denied-actors' }, shape: 'wrong check: tenant compared, owner ignored',
    edit: authzEdit([[AUTHZ_GET, "    if (note.tenant !== user.tenant) return sendJson(res, 404, { error: 'not found' });\n" + AUTHZ_GET]]) },
  { id: 'authz/any-admin', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-denied-actors' }, shape: 'wrong check: an admin of another tenant allowed',
    edit: authzEdit([[AUTHZ_GET, "    if (note.owner !== user.id && user.role !== 'admin') return sendJson(res, 404, { error: 'not found' });\n" + AUTHZ_GET]]) },
  { id: 'authz/actor-from-request', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-denied-actors' }, shape: 'wrong actor: the check trusts a value the caller controls',
    edit: authzEdit([[AUTHZ_GET, "    const claimed = url.searchParams.get('as') || note.owner;\n    if (note.owner !== claimed) return sendJson(res, 404, { error: 'not found' });\n" + AUTHZ_GET]]) },
  { id: 'authz/deny-all', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-allowed-workflows' }, shape: 'deny-all',
    edit: authzEdit([[AUTHZ_GET, "    return sendJson(res, 403, { error: 'forbidden' });\n" + AUTHZ_GET]]) },
  { id: 'authz/owner-only-breaks-admin', app: 'authz-notes', label: 'unsafe', expect: { obligation: 'authz-allowed-workflows' }, shape: 'over-tight: the declared same-tenant admin workflow broken',
    edit: authzEdit([[AUTHZ_GET, "    if (note.owner !== user.id) return sendJson(res, 404, { error: 'not found' });\n" + AUTHZ_GET]]) },
  // ---------------------------------------------------------------- authorization: safe
  { id: 'authz/owner-or-tenant-admin', app: 'authz-notes', label: 'safe', shape: 'policy check before any operation',
    edit: authzEdit([[AUTHZ_GET, `    ${OWNER_OR_TENANT_ADMIN}\n    if (!allowed) return sendJson(res, 404, { error: 'not found' });\n${AUTHZ_GET}`]]) },
  { id: 'authz/scoped-query', app: 'authz-notes', label: 'safe', shape: 'authorization in the query itself',
    edit: authzEdit([["  const byId = db.prepare('SELECT id, owner, tenant, body FROM notes WHERE id = ?');", "  const byId = db.prepare(\"SELECT id, owner, tenant, body FROM notes WHERE id = ? AND (owner = ? OR (tenant = ? AND ? = 'admin'))\");"],
      ['    const note = byId.get(Number(m[1]));', '    const note = byId.get(Number(m[1]), user.id, user.tenant, user.role);']]) },
]);
