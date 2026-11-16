// The verifier-falsification corpus (verified-remediation PRD FR-08): deliberately ineffective patches, each with an INDEPENDENT expected
// failure (which obligation must catch it), next to legitimate repairs of the same application.
//
// Synthetic regression evidence, not an accuracy measurement: every case here was written by the people who wrote the verifier, against
// six small applications (scanner/test/fixtures/repair/). A pass shows these known evasion shapes are caught; it says nothing about
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

const FETCH = '      const r = await fetch(target);\n';
const ssrfEdit = (to) => (files) => ({ 'src/app.mjs': replaceOnce(files['src/app.mjs'], FETCH, to) });
const PARTNERS = "      const ALLOWED = new Set(['api.partner.test', 'cdn.partner.test']);\n";
const REBIND_CHECK = "      if (INTERNAL.test(address)) { res.writeHead(403); res.end('internal destination'); return; }\n";
const REBIND_LOOKUP = '      const address = net.isIP(host) ? host : (await lookup(host)).address;\n';
const REBIND_FETCH = "      const r = await fetch(target, { redirect: 'manual' });\n      res.writeHead(200, { 'content-type': 'text/plain' });\n      res.end((await r.text()).slice(0, 500));\n";
const rebindEdit = (pairs) => (files) => {
  let t = files['src/app.mjs'];
  for (const [from, to] of pairs) t = replaceOnce(t, from, to);
  return { 'src/app.mjs': t };
};
const RESOLVE = '    const file = path.resolve(filesRoot, name);\n';
const fsEdit = (to) => (files) => ({ 'src/app.mjs': replaceOnce(files['src/app.mjs'], RESOLVE, to) });
const NOT_FOUND = "      res.writeHead(404); res.end('no such file'); return;\n";

export const APPS = Object.freeze({
  'sql-notes': { family: 'sql-injection', fixture: 'scanner/test/fixtures/repair/sql-notes' },
  'authz-notes': { family: 'object-authorization', fixture: 'scanner/test/fixtures/repair/authz-notes' },
  'ssrf-preview': { family: 'ssrf', fixture: 'scanner/test/fixtures/repair/ssrf-preview' },
  'ssrf-rebind': { family: 'ssrf', fixture: 'scanner/test/fixtures/repair/ssrf-rebind' },
  'files-download': { family: 'path-traversal', fixture: 'scanner/test/fixtures/repair/files-download' },
  'password-login': { family: 'password-storage', fixture: 'scanner/test/fixtures/repair/password-login', findingCwe: 'CWE-916' },
});

// ---------------------------------------------------------------- password storage edits
const PW_HASH = "function hashPassword(password) {\n  return crypto.createHash('md5').update(String(password)).digest('hex');\n}\n";
const PW_CMP = 'row.pw !== hashPassword(b.password)';
const PW_LOGIN_OK = "      return send(res, 200, { ok: true, user: row.name });\n";
const D = '$';
const pwKdf = (salt, N) => 'function hashPassword(password) {\n'
  + `  const salt = ${salt};\n`
  + `  const key = crypto.scryptSync(String(password), salt, 32, { N: ${N}, r: 8, p: 1 });\n`
  + `  return 'scrypt${D}${N}${D}8${D}1${D}' + salt.toString('hex') + '${D}' + key.toString('hex');\n`
  + '}\n';
const pwVerify = (legacy) => 'function verifyPassword(password, stored) {\n'
  + "  if (stored.startsWith('scrypt$')) {\n"
  + "    const [, n, r, p, saltHex, keyHex] = stored.split('$');\n"
  + "    const key = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), keyHex.length / 2, { N: Number(n), r: Number(r), p: Number(p) });\n"
  + "    return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));\n"
  + '  }\n'
  + (legacy
    ? "  const legacy = crypto.createHash('md5').update(String(password)).digest('hex');\n  return legacy.length === stored.length && crypto.timingSafeEqual(Buffer.from(legacy), Buffer.from(stored));\n"
    : '  return false;\n')
  + '}\n';
const PW_RANDOM = 'crypto.randomBytes(16)';
const pwEdit = ({ salt = PW_RANDOM, N = 16384, legacy = true, rehash = false }) => (files) => {
  let t = replaceOnce(files['src/app.mjs'], PW_HASH, pwKdf(salt, N) + pwVerify(legacy));
  t = replaceOnce(t, PW_CMP, '!verifyPassword(b.password, row.pw)');
  if (rehash) t = replaceOnce(t, PW_LOGIN_OK, "      if (!row.pw.startsWith('scrypt$')) db.prepare('UPDATE users SET pw = ? WHERE name = ?').run(hashPassword(b.password), row.name);\n" + PW_LOGIN_OK);
  return { 'src/app.mjs': t };
};

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

  // ---------------------------------------------------------------- server-side request forgery: unsafe
  { id: 'ssrf/first-hop-allowlist', app: 'ssrf-preview', label: 'unsafe', expect: { obligation: 'ssrf-attacks-development' }, shape: 'allowlist on the first URL only; the client still follows a redirect off the approved host',
    edit: ssrfEdit(`${PARTNERS}      if (!ALLOWED.has(new URL(target).hostname)) { res.writeHead(403); res.end('destination not allowed'); return; }\n${FETCH}`) },
  { id: 'ssrf/address-denylist', app: 'ssrf-preview', label: 'unsafe', expect: { obligation: 'ssrf-attacks-development' }, shape: 'denylist of internal address literals; an internal host name resolves past it',
    edit: ssrfEdit(`      if (/^(?:10|127|169\\.254|192\\.168)\\./.test(new URL(target).hostname)) { res.writeHead(403); res.end('destination not allowed'); return; }\n${FETCH}`) },
  { id: 'ssrf/fitted-to-visible-probes', app: 'ssrf-preview', label: 'unsafe', expect: { obligation: 'ssrf-attacks-sealed' }, shape: 'a pattern fitted to the development probes, re-checked on every hop; a decimal address or an upper-case name gets through',
    edit: ssrfEdit("      let next = target; let r;\n      for (let hop = 0; hop < 4; hop++) {\n        if (/169\\.254|10\\.0\\.0\\.7|internal|localhost|127\\./.test(next)) { res.writeHead(403); res.end('destination not allowed'); return; }\n        r = await fetch(next, { redirect: 'manual' });\n        if (r.status < 300 || r.status > 399) break;\n        next = new URL(r.headers.get('location'), next).href;\n      }\n") },
  { id: 'ssrf/deny-all', app: 'ssrf-preview', label: 'unsafe', expect: { obligation: 'ssrf-legitimate-requests' }, shape: 'feature removal',
    edit: ssrfEdit("      res.writeHead(403); res.end('previews disabled'); return;\n") },
  { id: 'ssrf/no-legitimate-redirects', app: 'ssrf-preview', label: 'unsafe', expect: { obligation: 'ssrf-legitimate-requests' }, shape: 'over-tight: redirects refused, so the approved host\'s legitimate redirect breaks',
    edit: ssrfEdit(`${PARTNERS}      const first = new URL(target);\n      if (!ALLOWED.has(first.hostname)) { res.writeHead(403); res.end('destination not allowed'); return; }\n      const r = await fetch(first, { redirect: 'error' });\n`) },
  { id: 'ssrf/rebind-check-removed', app: 'ssrf-rebind', label: 'unsafe', expect: { obligation: 'ssrf-attacks-development' }, shape: 'the existing address check deleted: caught only by regression guards (attacks the original already blocked)',
    edit: rebindEdit([[REBIND_CHECK, ''], [REBIND_LOOKUP, '']]) },
  // ---------------------------------------------------------------- server-side request forgery: safe
  { id: 'ssrf/allowlist-every-hop', app: 'ssrf-preview', label: 'safe', shape: 'allowlist checked on every hop, redirects followed by hand',
    edit: ssrfEdit(`${PARTNERS}      let next = new URL(target); let r;\n      for (let hop = 0; ; hop++) {\n        if (hop > 3 || next.protocol !== 'http:' || next.username || next.password || !ALLOWED.has(next.hostname)) { res.writeHead(403); res.end('destination not allowed'); return; }\n        r = await fetch(next, { redirect: 'manual' });\n        if (r.status < 300 || r.status > 399) break;\n        next = new URL(r.headers.get('location'), next);\n      }\n`) },
  { id: 'ssrf/rebind-pinned-address', app: 'ssrf-rebind', label: 'safe', shape: 'connect to the address that was checked, with the original Host header',
    edit: rebindEdit([["import net from 'node:net';\n", "import net from 'node:net';\nimport http from 'node:http';\n"], [REBIND_FETCH, "      if (target.protocol !== 'http:' || net.isIPv6(host)) { res.writeHead(403); res.end('unsupported destination'); return; }\n      const body = await new Promise((resolve, reject) => {\n        const rq = http.get({ host: address, port: Number(target.port) || 80, path: target.pathname + target.search, headers: { host: target.host } }, (r) => { let t = ''; r.setEncoding('utf8'); r.on('data', (d) => { t += d; }); r.on('end', () => resolve(t)); });\n        rq.on('error', reject);\n      });\n      res.writeHead(200, { 'content-type': 'text/plain' });\n      res.end(body.slice(0, 500));\n"]]) },

  // ---------------------------------------------------------------- path traversal: unsafe
  { id: 'path/reject-dot-dot', app: 'files-download', label: 'unsafe', expect: { obligation: 'filesystem-attacks-development' }, shape: 'a filter on ".."; an absolute path and a link out of the root get through',
    edit: fsEdit(`    if (name.includes('..')) {\n${NOT_FOUND}    }\n${RESOLVE}`) },
  { id: 'path/prefix-without-separator', app: 'files-download', label: 'unsafe', expect: { obligation: 'filesystem-attacks-development' }, shape: 'startsWith(root) without a separator: a sibling directory sharing the prefix gets through',
    edit: fsEdit(`${RESOLVE}    if (!file.startsWith(filesRoot)) {\n${NOT_FOUND}    }\n`) },
  { id: 'path/lexical-containment', app: 'files-download', label: 'unsafe', expect: { obligation: 'filesystem-attacks-development' }, shape: 'lexical containment only: a symbolic link inside the root leads outside it',
    edit: fsEdit(`${RESOLVE}    if (!file.startsWith(filesRoot + path.sep)) {\n${NOT_FOUND}    }\n`) },
  { id: 'path/basename-only', app: 'files-download', label: 'unsafe', expect: { obligation: 'filesystem-legitimate-requests' }, shape: 'over-tight: basename breaks every nested legitimate path',
    edit: fsEdit('    const file = path.join(filesRoot, path.basename(name));\n') },
  // ---------------------------------------------------------------- path traversal: safe
  { id: 'path/realpath-containment', app: 'files-download', label: 'safe', shape: 'both paths resolved through links, containment checked with a separator',
    edit: fsEdit(`    let file;\n    try {\n      const base = fs.realpathSync(filesRoot);\n      file = fs.realpathSync(path.resolve(base, name));\n      if (!file.startsWith(base + path.sep)) throw new Error('outside');\n    } catch {\n${NOT_FOUND}    }\n`) },

  // ---------------------------------------------------------------- password storage: unsafe
  { id: 'password/fast-digest-swap', app: 'password-login', label: 'unsafe', expect: { obligation: 'password-storage' }, shape: 'a stronger fast digest (sha256 for md5): still unsalted and fast',
    edit: (files) => ({ 'src/app.mjs': files['src/app.mjs'].split("createHash('md5')").join("createHash('sha256')") }) },
  { id: 'password/constant-salt', app: 'password-login', label: 'unsafe', expect: { obligation: 'password-storage' }, shape: 'scrypt with one salt for every user: equal passwords store equal values',
    edit: pwEdit({ salt: "Buffer.from('0123456789abcdef0123456789abcdef', 'hex')", rehash: true }) },
  { id: 'password/low-cost', app: 'password-login', label: 'unsafe', expect: { obligation: 'password-storage' }, shape: 'scrypt below the approved cost (N 1024)',
    edit: pwEdit({ N: 1024, rehash: true }) },
  { id: 'password/legacy-users-locked-out', app: 'password-login', label: 'unsafe', expect: { obligation: 'password-legitimate-logins' }, shape: 'new format only: every existing account can no longer log in',
    edit: pwEdit({ legacy: false, rehash: true }) },
  { id: 'password/no-migration', app: 'password-login', label: 'unsafe', expect: { obligation: 'password-legacy-migrated' }, shape: 'legacy accounts accepted but never upgraded: their stored values stay fast digests',
    edit: pwEdit({}) },
  // ---------------------------------------------------------------- password storage: safe
  { id: 'password/scrypt-with-migration', app: 'password-login', label: 'safe', shape: 'salted scrypt, legacy digests accepted only to log in, upgraded on the next successful login',
    edit: pwEdit({ rehash: true }) },
]);
