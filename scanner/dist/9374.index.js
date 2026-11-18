export const id = 9374;
export const ids = [9374];
export const modules = {

/***/ 69374:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   draftProfile: () => (/* binding */ draftProfile)
/* harmony export */ });
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var _profile_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(61252);
// A DRAFT application profile from the code (verified-remediation usability): the facts the code states are filled in with the basis
// for each, and everything the code cannot state is a placeholder string (see PLACEHOLDER below). `validateProfile` refuses any profile
// that still holds one, so a draft is never planned by accident: it is a starting point the operator completes, not a profile.
//
// What is read, and only from the finding's file and the files it imports by relative path (at most 12, inside the root):
//   application  the entry file, its local imports, an exported function that returns a request listener (or is named createApp/
//                createServer/makeApp/app), and the runtime from the extension
//   database     `CREATE TABLE` statements in string literals of those files or in `.sql` files under the root (SQLite only)
//   actors       the request header the code reads for identity (authorization, x-user, cookie, x-api-key)
//   family       the route around the finding's line (`pathname === '/x'`, `app.get('/x'`, `router.post('/x'`) and the request value
//                read there (`searchParams.get('q')`, `req.query.q`, `req.body.q`, `req.params.id`)
// Nothing is executed, and no value that decides a verdict (an approved host, a policy, a planted secret, a legitimate value, an
// expected response) is ever guessed: those are always TODO.




// the placeholder prefix validateProfile refuses
const PLACEHOLDER = 'TODO: ';
const TODO = (what) => `${PLACEHOLDER}${what}`;
const MAX_FILES = 12;

function readConfined(root, rel) {
  const real = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(root);
  const abs = node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(real, rel);
  if (!abs.startsWith(real + node_path__WEBPACK_IMPORTED_MODULE_1__.sep)) return null;
  try { const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(abs); if (!st.isFile() || st.isSymbolicLink() || st.size > 500_000) return null; return node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(abs, 'utf8'); } catch { return null; }
}

/** The finding's file and the files it imports by relative path, breadth first. */
function localFiles(root, entry) {
  const out = new Map(); const queue = [entry];
  while (queue.length && out.size < MAX_FILES) {
    const rel = queue.shift();
    if (out.has(rel)) continue;
    const text = readConfined(root, rel);
    if (text === null) continue;
    out.set(rel, text);
    for (const m of text.matchAll(/(?:from\s+|require\(\s*|import\(\s*)['"](\.\.?\/[^'"]+)['"]/g)) {
      let target = node_path__WEBPACK_IMPORTED_MODULE_1__.posix.normalize(node_path__WEBPACK_IMPORTED_MODULE_1__.posix.join(node_path__WEBPACK_IMPORTED_MODULE_1__.posix.dirname(rel), m[1]));
      if (!/\.[cm]?[jt]sx?$/.test(target)) for (const ext of ['.mjs', '.js', '.ts', '/index.js']) { if (readConfined(root, target + ext) !== null) { target += ext; break; } }
      if (!target.startsWith('..')) queue.push(target);
    }
  }
  return out;
}

const FACTORY_NAME = /^(?:createApp|createServer|makeApp|buildApp|app|handler)$/;
function exportedFactory(text) {
  const names = [...text.matchAll(/export\s+(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]);
  names.push(...[...text.matchAll(/export\s+const\s+([A-Za-z_$][\w$]*)\s*=/g)].map((m) => m[1]));
  // a function whose body returns a (req, res) listener is the factory
  for (const n of names) {
    const at = text.indexOf(n);
    if (/return\s+(?:async\s+)?(?:function\s*)?\(\s*req\s*,\s*res\b/.test(text.slice(at, at + 4000))) return { name: n, basis: 'returns a (req, res) request listener' };
  }
  const byName = names.find((n) => FACTORY_NAME.test(n));
  return byName ? { name: byName, basis: 'exported under a factory name' } : null;
}

function schemaOf(root, files) {
  const stmts = new Set();
  const take = (text) => { for (const m of text.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[\w"]+\s*\([^;]*?\)\s*;?/gi)) stmts.add(m[0].trim().replace(/;?$/, ';')); };
  for (const t of files.values()) take(t);
  const walk = (dir, depth) => {
    if (depth > 3) return;
    let ents = []; try { ents = node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(node_path__WEBPACK_IMPORTED_MODULE_1__.join(root, dir), { withFileTypes: true }); } catch { return; }
    for (const e of ents) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const rel = dir ? `${dir}/${e.name}` : e.name;
      if (e.isDirectory()) walk(rel, depth + 1);
      else if (e.isFile() && e.name.endsWith('.sql')) { const t = readConfined(root, rel); if (t) take(t); }
    }
  };
  walk('', 0);
  return [...stmts].slice(0, 40);
}

const IDENTITY_HEADERS = [['authorization', /headers\s*(?:\.authorization|\[\s*['"]authorization['"]\s*\])/i], ['x-user', /['"]x-user['"]/i], ['x-api-key', /['"]x-api-key['"]/i], ['cookie', /headers\s*(?:\.cookie|\[\s*['"]cookie['"]\s*\])|req\.cookies/i]];

/** The route and the request value around a line of `text`. */
function routeAround(text, line) {
  const lines = text.split('\n');
  const before = lines.slice(0, line).join('\n');
  const window = lines.slice(Math.max(0, line - 40), line + 5).join('\n');
  let route = null; let method = 'GET';
  const routes = [...before.matchAll(/(?:pathname\s*[!=]==?\s*['"](\/[^'"]*)['"])|(?:\b(?:app|router|server)\.(get|post|put|patch|delete)\(\s*['"](\/[^'"]*)['"])/gi)];
  const last = routes[routes.length - 1];
  if (last) { route = last[1] || last[3]; if (last[2]) method = last[2].toUpperCase(); }
  const methodCheck = [...window.matchAll(/req\.method\s*===?\s*['"]([A-Z]+)['"]/g)].pop();
  if (methodCheck && !last?.[2]) method = methodCheck[1];
  const value = [...window.matchAll(/searchParams\.get\(\s*['"]([\w-]+)['"]|req\.query\.([\w$]+)|req\.query\[\s*['"]([\w-]+)['"]|req\.body\.([\w$]+)|req\.params\.([\w$]+)/g)].pop();
  let where = null; let name = null;
  if (value) { name = value[1] || value[2] || value[3] || value[4] || value[5]; where = value[4] ? 'body' : value[5] ? 'route' : 'query'; }
  return { route, method, name, where };
}

const FAMILY_SECTION = {
  'sql-injection': 'sql', 'object-authorization': 'authorization', ssrf: 'ssrf', 'path-traversal': 'filesystem', 'password-storage': 'passwords', credential: 'credential', workflow: 'workflow',
};

function familySection(family, r, actor) {
  const req = r.route
    ? { actor, method: r.method, path: r.where === 'query' && r.name ? `${r.route}?${r.name}={{value}}` : r.where === 'route' ? r.route.replace(new RegExp(`:${r.name}\\b`), '{{value}}') : r.route, ...(r.where === 'body' && r.name ? { body: { [r.name]: '{{value}}' } } : {}) }
    : { actor, method: TODO('the request method'), path: TODO('the request path, with {{value}} where the untrusted value goes') };
  const input = { id: 'input-1', ...req, benign: [{ value: TODO('a legitimate value'), expectStatus: [200] }] };
  switch (family) {
    case 'sql-injection': return { inputs: [{ ...input, secrets: [TODO('the planted secret another actor\'s rows hold')] }] };
    case 'ssrf': return { policy: TODO('allowlist or public-only'), approved: [TODO('every host the application may contact')], hosts: [TODO('each host: name, addresses and the routes the verifier serves')], inputs: [input] };
    case 'path-traversal': return { root: TODO('the directory the application may serve'), tree: { [TODO('a file inside the root')]: TODO('its content'), [TODO('a file outside the root')]: '{{secret:outside-file}}' }, inputs: [input] };
    default: return { [TODO('this family\'s section: see docs/reference/repair-contract.md')]: true };
  }
}

/**
 * @param {{root:string, finding:{file:string, line?:number, cwe?:string}, family:string}} o
 * @returns {{profile:object, todo:string[], detected:object[]}}
 */
function draftProfile({ root, finding, family }) {
  const detected = [];
  const files = localFiles(root, finding.file);
  const entryText = files.get(finding.file) ?? '';
  const runtime = /\.py$/.test(finding.file) ? 'python' : 'node';
  const factory = exportedFactory(entryText);
  if (factory) detected.push({ field: 'application.export', value: factory.name, basis: factory.basis });
  detected.push({ field: 'application.files', value: [...files.keys()], basis: 'the finding\'s file and its relative imports' });
  const usesSqlite = [...files.values()].some((t) => /node:sqlite|better-sqlite3|['"]sqlite3['"]|import\s+sqlite3/.test(t));
  const schema = usesSqlite ? schemaOf(root, files) : [];
  if (schema.length) detected.push({ field: 'database.schemaSql', value: `${schema.length} CREATE TABLE statement(s)`, basis: 'string literals in the application files and .sql files under the root' });
  const header = IDENTITY_HEADERS.find(([, re]) => [...files.values()].some((t) => re.test(t)))?.[0] || null;
  if (header) detected.push({ field: 'actors[].headers', value: header, basis: 'the request header the code reads' });
  const around = routeAround(entryText, Number(finding.line) || 1);
  if (around.route) detected.push({ field: `${FAMILY_SECTION[family] || family}.inputs[0]`, value: `${around.method} ${around.route}${around.name ? ` (${around.where} ${around.name})` : ''}`, basis: `the route around line ${finding.line}` });
  const profile = {
    schema: _profile_js__WEBPACK_IMPORTED_MODULE_2__/* .PROFILE_SCHEMA */ .Ow, schemaVersion: '1.0.0',
    application: { entry: finding.file, export: factory?.name || TODO('the exported factory that returns the request listener'), files: [...files.keys()], runtime },
    database: usesSqlite ? { engine: 'sqlite', schemaSql: schema.length ? schema.join(' ') : TODO('the CREATE TABLE statements'), seed: [TODO('INSERT statements: two actors\' rows, one holding a planted {{secret:<name>}}')] } : { engine: 'sqlite', schemaSql: TODO('the application does not use SQLite where the draft could see it: only SQLite is executed in this release'), seed: [] },
    actors: [
      { id: 'user', tenant: 't1', role: 'member', headers: header ? { [header]: TODO(`the ${header} value the application accepts for this user`) } : { [TODO('the header that identifies a user')]: TODO('its value') } },
      { id: 'other', tenant: 't2', role: 'member', headers: header ? { [header]: TODO(`the ${header} value for a second user`) } : {} },
    ],
    ...(FAMILY_SECTION[family] ? { [FAMILY_SECTION[family]]: familySection(family, around, 'user') } : {}),
  };
  const todo = [];
  const visit = (v, at) => {
    if (typeof v === 'string' && v.startsWith('TODO:')) todo.push(`${at}: ${v.slice(6)}`);
    else if (Array.isArray(v)) v.forEach((x, i) => visit(x, `${at}[${i}]`));
    else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { if (k.startsWith('TODO:')) todo.push(`${at}: ${k.slice(6)}`); visit(x, at ? `${at}.${k}` : k); }
  };
  visit(profile, '');
  return { profile, todo, detected };
}


/***/ })

};
