export const id = 5535;
export const ids = [5535,5144];
export const modules = {

/***/ 44652:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   IW: () => (/* binding */ safeLabel),
/* harmony export */   Qz: () => (/* binding */ safeRelPath),
/* harmony export */   bt: () => (/* binding */ cleanForTerminal),
/* harmony export */   dj: () => (/* binding */ canonicalJson),
/* harmony export */   fQ: () => (/* binding */ normalizeText),
/* harmony export */   iq: () => (/* binding */ sliceLines),
/* harmony export */   kH: () => (/* binding */ cmpCodeUnit),
/* harmony export */   qQ: () => (/* binding */ hashOf),
/* harmony export */   sc: () => (/* binding */ sha256),
/* harmony export */   v6: () => (/* binding */ readRepoFile),
/* harmony export */   w9: () => (/* binding */ snapshotHashOf)
/* harmony export */ });
/* unused harmony export HASH_ALGORITHM */
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(77598);
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(76760);
//
// Canonical serialization, hashing and path/snapshot safety for Deterministic Context Intelligence.
//
// Everything DCI stores or compares goes through this module so that "same checkout + same config => same bytes" is
// a property of one place. No clock, no randomness, no host path ever enters a hashed value.




/** Bump when the canonical encoding below changes; it is mixed into every hash. */
const HASH_ALGORITHM = 'sha256/canon-1';

function sha256(text) {
  return node_crypto__WEBPACK_IMPORTED_MODULE_0__.createHash('sha256').update(text).digest('hex');
}

/**
 * Code-unit order, independent of the host locale. `localeCompare` orders by the process locale, so the same checkout
 * could be sorted differently on two machines; every ordering that reaches a hashed value goes through this instead.
 */
function cmpCodeUnit(a, b) {
  const x = String(a); const y = String(b);
  return x < y ? -1 : x > y ? 1 : 0;
}

// Control characters (C0, DEL, C1), the bidirectional override/isolate marks and the line/paragraph separators. A
// repository controls the text of its own route strings and file names, so anything printed to a terminal or placed
// in a prompt outside the untrusted fence must not be able to carry an escape sequence or reorder what a reader sees.
const UNSAFE_DISPLAY = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]/g;

/** Make text safe to print: unsafe characters become '?'. Newline and tab are kept; use `safeLabel` for one-line values. */
function cleanForTerminal(text) {
  return String(text).replace(UNSAFE_DISPLAY, '?');
}

/** A one-line, bounded, printable form of a name taken from source (a route path, a file name). */
function safeLabel(text, max = 120) {
  const t = String(text).replace(/[\n\r\t]+/g, ' ').replace(UNSAFE_DISPLAY, '?').replace(/ {2,}/g, ' ').trim();
  return t.length > max ? `${t.slice(0, max - 3)}...` : t;
}

/** CRLF/CR -> LF so a Windows checkout and a Unix one produce the same spans and hashes. */
function normalizeText(text) {
  return String(text).replace(/\r\n?/g, '\n');
}

/**
 * JSON with object keys sorted at every depth. Arrays keep their order (callers sort them where order is not
 * meaningful). `undefined` members are dropped, exactly as JSON.stringify does, so a missing and an undefined field hash alike.
 */
function canonicalJson(value) {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(v) {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (v && typeof v === 'object') {
    const out = {};
    for (const k of Object.keys(v).sort()) {
      if (v[k] !== undefined) out[k] = sortKeys(v[k]);
    }
    return out;
  }
  return v;
}

function hashOf(value) {
  return sha256(`${HASH_ALGORITHM}\n${canonicalJson(value)}`);
}

/**
 * A repository-relative path in canonical form, or null. Rejects absolute paths, drive letters, NUL, backslash
 * tricks and any `..` segment: a manifest can never name a file outside the repository.
 */
function safeRelPath(p) {
  if (typeof p !== 'string' || p === '' || p.includes('\0')) return null;
  const n = p.replace(/\\/g, '/');
  if (n.startsWith('/') || /^[A-Za-z]:/.test(n)) return null;
  const parts = n.split('/');
  const out = [];
  for (const seg of parts) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') return null;
    out.push(seg);
  }
  return out.length ? out.join('/') : null;
}

/**
 * Read one repository file for analysis. Refuses a symlink and anything whose real path leaves the repository root,
 * and refuses non-regular files. Returns { ok, text } or { ok:false, reason }; never throws.
 */
function readRepoFile(rootReal, rel, { maxBytes = 2 * 1024 * 1024 } = {}) {
  const safe = safeRelPath(rel);
  if (!safe) return { ok: false, reason: 'unsafe-path' };
  const abs = node_path__WEBPACK_IMPORTED_MODULE_2__.join(rootReal, safe);
  try {
    const st = node_fs__WEBPACK_IMPORTED_MODULE_1__.lstatSync(abs);
    if (st.isSymbolicLink()) return { ok: false, reason: 'symlink' };
    if (!st.isFile()) return { ok: false, reason: 'not-a-regular-file' };
    if (st.size > maxBytes) return { ok: false, reason: 'too-large' };
    const real = node_fs__WEBPACK_IMPORTED_MODULE_1__.realpathSync(abs);
    if (real !== rootReal && !real.startsWith(rootReal + node_path__WEBPACK_IMPORTED_MODULE_2__.sep)) return { ok: false, reason: 'escapes-root' };
    return { ok: true, text: normalizeText(node_fs__WEBPACK_IMPORTED_MODULE_1__.readFileSync(abs, 'utf8')) };
  } catch (err) {
    return { ok: false, reason: err && err.code ? String(err.code) : 'unreadable' };
  }
}

/** Hash of the analysed file set: sorted [path, content hash] pairs. Order of discovery never matters. */
function snapshotHashOf(fileContents) {
  const rows = Object.keys(fileContents).sort().map(f => [f, sha256(fileContents[f])]);
  return hashOf(rows);
}

/** 1-based inclusive line slice of already-normalised text. */
function sliceLines(text, startLine, endLine) {
  const lines = text.split('\n');
  return lines.slice(Math.max(0, startLine - 1), Math.max(0, endLine)).join('\n');
}


/***/ }),

/***/ 17202:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   $E: () => (/* binding */ blankComments),
/* harmony export */   TM: () => (/* binding */ looksLikeTelemetry),
/* harmony export */   gs: () => (/* binding */ signatureText),
/* harmony export */   kl: () => (/* binding */ analyzeSymbolText),
/* harmony export */   qr: () => (/* binding */ dependencyParams)
/* harmony export */ });
/* unused harmony exports CONTROL_KINDS, ownerBinding, isSecuritySignificant */
//
// Security-relevant facts inside ONE symbol's source: authentication / authorization / ownership / tenant controls,
// and the sensitive operations they have to precede.
//
// EVIDENCE DISCIPLINE. Every fact says how it was established:
//   evidence 'observed'  the text itself shows it (a decorator, a comparison of a resource field with the principal,
//                        a query whose filter mentions the principal)
//   evidence 'inferred'  only a NAME suggests it (`requireAdmin(...)`); the callee's body was not shown to reject
// A name is never promoted to 'observed'. Nothing here decides that code is safe; it decides what must NOT be
// dropped from a context bundle, and what the model is told was seen.
//
// This module is deliberately pattern-based and says so: it exists to be conservative about what it keeps, not
// to prove anything. The packer never removes a symbol that contains any fact reported here.

const CONTROL_KINDS = Object.freeze(['authentication', 'authorization-role', 'ownership', 'tenant-scope']);

const DECORATOR = /^\s*@(?:login_required|permission_required|user_passes_test|PreAuthorize|PostAuthorize|Secured|RolesAllowed|Authorize|Authenticated|authenticated|requires_auth|requires_roles|jwt_required|auth_required|has_role|roles_required|admin_required|staff_member_required|csrf_protect|UseGuards|Roles|Permissions|RequirePermission)\b/;
// A QUALIFIED principal reference names where the identity came from (the session, the authenticated user object).
// A BARE identifier (`userId`, `orgId`) may just as well have been copied out of the URL, so it is only ever INFERRED.
const QUALIFIED_PRINCIPAL = /(?:\breq\.user\b|\brequest\.user\b|\bcurrent_?[Uu]ser\b|\bsession\.user\b|\bsession\[['"]user|\bprincipal\b|\bctx\.user\b|\bauth\.user\b|\bg\.user\b|\bres\.locals\.user\b|\bSecurityContext\w*|\bgetPrincipal\b|\bauthUser\b|\bcurrentUserId\b|\bauthId\b|\breq\.auth\b|\brequest\.auth\b)/;
const BARE_PRINCIPAL = /(?:\buserId\b|\buser_id\b|\btenantId\b|\btenant_id\b|\borgId\b|\borg_id\b|\buid\b|\bme\.id\b)/;
// Request-supplied values are attacker-controlled by definition; blank them before looking for a principal reference.
const UNTRUSTED_ACCESSOR = /\b(?:req|request)\.(?:params|query|body|args|form|json|headers|cookies|values|data)\b(?:\.\w+|\[[^\]]*\])?|\b(?:params|query|body)\[[^\]]*\]|\bparams\.\w+|\brequest\.(?:GET|POST)\b(?:\.get\([^)]*\)|\[[^\]]*\])?|\bparam\s+["'][\w-]+["']/g;
function principalIn(text, extra = null) {
  const noReq = text.replace(UNTRUSTED_ACCESSOR, ' ');
  // a column name inside a SQL string (`org_id`) is not a reference to the principal; look only outside string literals
  const code = noReq.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, '""');
  if (QUALIFIED_PRINCIPAL.test(code) || /\bsession\[['"]user/.test(noReq)) return 'qualified';
  if (extra && extra.test(code)) return 'qualified';
  if (BARE_PRINCIPAL.test(code)) return 'bare';
  return null;
}

// Dependency-injected principals (FastAPI-style): a signature parameter bound to an auth-looking dependency holds the
// authenticated principal, so `user.id` in the body is the principal and not an arbitrary local.
const DEP_PARAM = /(\w+)\s*(?::[^=,)]*?)?=\s*(?:Depends|Security)\(\s*([\w.]+)|(\w+)\s*:\s*Annotated\[[^\]]*?(?:Depends|Security)\(\s*([\w.]+)/g;
const PRINCIPAL_DEP = /(?:user|auth|principal|session|token|account|member|identity|credential)/i;
function dependencyParams(signatureText) {
  const out = [];
  let m;
  DEP_PARAM.lastIndex = 0;
  while ((m = DEP_PARAM.exec(signatureText))) out.push({ param: m[1] || m[3], dependency: m[2] || m[4] });
  return out;
}
function signatureText(lines, declLine, maxLines = 12) {
  let t = '';
  for (let i = declLine - 1; i < Math.min(lines.length, declLine - 1 + maxLines); i++) { t += ' ' + lines[i]; if (/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(lines[i])) break; }
  return t;
}
// An owner/tenant FIELD NAME, not any word that merely contains one: `ownerId`, `owner_id`, `tenant`, `getOwnerId`
// qualify; `owner_name` and `cols` do not (the trailing boundary rejects them).
const OWNER_KEY = '\\w*?(?:[Oo]wner|[Tt]enant|[Oo]rg(?:ani[sz]ation)?|[Aa]ccount|[Cc]reated_?[Bb]y|[Aa]uthor|[Tt]eam|[Ww]orkspace)(?:_?(?:[Ii]d|ID))?\\b|[Uu]ser_?(?:[Ii]d|ID)\\b';
const OWNER_KEY_RE = new RegExp(`(?<![\\w])(?:${OWNER_KEY})`);
const TENANT_WORD = /tenant|org|workspace|team|account/i;
// a SQL string comparing an owner column with a bound parameter: `owner_id = ?`, `owner_id = $1`, `tenant_id = :t`
const SQL_OWNER_PLACEHOLDER = new RegExp(`(?<![\\w])(?:${OWNER_KEY})\\s*(?:=|\\bIN\\b|\\bin\\b)\\s*\\(?\\s*(?:\\?|\\$\\d+|:\\w+|%s|@\\w+)`);
// an owner column compared with the principal written straight into the string: `owner_id = ${req.user.id}`
const SQL_OWNER_INTERPOLATED = new RegExp(`(?<![\\w])(?:${OWNER_KEY})\\s*=\\s*(?:'?\\s*\\+\\s*|\\$\\{\\s*)(?:${QUALIFIED_PRINCIPAL.source}|${BARE_PRINCIPAL.source})`);
const PRINCIPAL_GLOBAL = new RegExp(QUALIFIED_PRINCIPAL.source, 'g');
const STRING_LITERAL = /(["'`])(?:\\.|(?!\1).)*\1/g;

/**
 * Is an owner/tenant FIELD actually tied to the principal in this text? The field and the principal must sit in the
 * same clause (split on , ; && || braces), so `{ audit: req.user.id, cols: 'owner_name' }` is a decoy and
 * `{ ownerId: req.user.id }` is a filter. A SQL string with an owner column against a bound placeholder counts when the
 * principal is passed in the same call. Returns null or { level: 'qualified'|'bare', tenant }.
 */
function ownerBinding(text, extra = null) {
  let best = null;
  const take = (level, tenant) => { if (!best || (level === 'qualified' && best.level !== 'qualified')) best = { level, tenant }; };
  const code = text.replace(STRING_LITERAL, (m) => (SQL_OWNER_PLACEHOLDER.test(m) || SQL_OWNER_INTERPOLATED.test(m) ? m : '""'));
  for (const clause of code.split(/[,;{}]|&&|\|\|/)) {
    // the principal's own name (`req.user`, `current_user`) is not an owner field, so it is removed before looking for one
    const forKey = clause.replace(STRING_LITERAL, ' ').replace(PRINCIPAL_GLOBAL, ' ');
    if (!OWNER_KEY_RE.test(forKey)) continue;
    const pr = principalIn(clause, extra);
    if (pr) take(pr, TENANT_WORD.test(clause));
  }
  for (const m of text.match(STRING_LITERAL) || []) {
    const placeholder = SQL_OWNER_PLACEHOLDER.test(m);
    if (placeholder) {
      const pr = principalIn(text, extra);
      if (pr) take(pr, TENANT_WORD.test(m));
    }
    if (SQL_OWNER_INTERPOLATED.test(m)) take('qualified', TENANT_WORD.test(m));
  }
  return best;
}

const COMPARE = /(?:===|!==|==|!=|\.equals\(|\bis not\b|\bis\b|\bnot in\b|\bin\b|\.includes\(|\.has\()/;
const REJECT = /(?:\breturn\b|\bthrow\b|\braise\b|\babort\b|\bexit\b|\b40[0-9]\b|\bforbidden\b|\bunauthori[sz]ed\b|\bHttpError\b|\breject\b|\bnot_?allowed\b|\bdeny\b|\bdenied\b|throwError|\bfinish\b|\bhalt\b|\bPermissionDenied\b|\bAccessDenied\b|status\()/i;

const AUTH_NAME = /(?:^|[.:])(?:(?:require|ensure|check|assert|verify|validate|enforce|authori[sz]e|authenticate|protect|guard|must|need|has|is|can|cannot|allow)\w*(?:auth|login|session|token|jwt|user|perm|role|admin|owner|access|tenant|scope|member|polic|abilit|credential|principal)\w*|authori[sz]e\w*|authenticate\w*|isAuthenticated|requireAuth\w*|requireUser|requireAdmin|requireAuthId|can|cannot|ability\.\w+|policy\.\w+|hasRole|hasPermission|isAdmin|isOwner|checkOwner\w*|ownedBy|belongsTo)$/i;

const SENSITIVE_NAME = /(?:^|[.:])(?:query|queryOne|queryRow|exec|execute|executeQuery|raw|rawQuery|prepare|find|findAll|findOne|findById|findByPk|findUnique|findFirst|findMany|get|getById|getBy|select|selectList|selectFirst|insert|insertOne|insertMany|insert_|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|remove|destroy|save|create|createMany|aggregate|runDB|writeFile|writeFileSync|appendFile|unlink|rm|rmdir|spawn|spawnSync|execSync|execFile|system|popen|fetch|request|post|put|patch)$/i;
const DB_RECEIVER = /(?:^|\b)(?:db|database|conn|connection|pool|client|cursor|session|repo|repository|dao|model|models|collection|table|prisma|knex|sequelize|orm|store|objects|manager|em|entityManager|mongo|redis|cache|conn|stmt|statement|fs|child_process|cp|axios|http|https|requests|httpx|got|superagent|Database|Persist|Yesod|System)\b/;
// Flask-SQLAlchemy `Model.query...`, SQLAlchemy `session.query/add/delete/merge/execute/get`, and the query-builder methods that end a chain.
const PY_ORM = /(?:\b[A-Z]\w*\.query\b|\b(?:db\.)?session\.(?:query|add|add_all|delete|merge|execute|get|bulk_save_objects)\b|\.(?:filter_by|get_or_404|first_or_404|one_or_404)\()/;
const PY_ORM_WRITE = /\.(?:delete|update|bulk_update_mappings|bulk_insert_mappings)\(|\b(?:db\.)?session\.(?:add|add_all|delete|merge|bulk_save_objects)\b/;
const SQL_TEXT = /\b(?:select\s[\s\S]{1,120}\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i;
const HS_SENSITIVE = /(?:^|\.)(?:runDB|selectList|selectFirst|getBy|getJust|insert_?|insertEntity|update|updateWhere|delete|deleteWhere|replace|upsert|query|query_|execute|execute_|readFile|writeFile|callProcess|readProcess)$|^(?:Database\.|System\.Process\.|System\.Directory\.)/;

// Names that answer a question rather than enforce a rule.
const PREDICATE_NAME = /^(?:is|has|can|cannot|allow|owned|belongs)/i;
function bareCallStatement(trimmedLine, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`^(?:await\\s+)?${esc}\\s*\\(`).test(trimmedLine) && /\)\s*;?\s*(?:\/\/.*|\/\*.*)?$/.test(trimmedLine);
}

const WRITE_VERB = /(?:insert|update|upsert|delete|remove|destroy|save|create|write|append|unlink|rm|exec|spawn|system|popen|post|put|patch|replace)/i;

function kindOfAuthName(name) {
  const n = name.toLowerCase();
  if (/(?:owner|ownedby|belongsto)/.test(n)) return 'ownership';
  if (/(?:tenant|org|scope|member|workspace|team)/.test(n)) return 'tenant-scope';
  if (/(?:role|admin|perm|polic|abilit|^can|\.can|cannot|allow)/.test(n)) return 'authorization-role';
  return 'authentication';
}

/**
 * The text of the statement that starts on line `ln`: from that line until its parentheses balance (capped). A query
 * filter is judged on its OWN statement; looking at neighbouring lines is how a guard written on the next line gets
 * mistaken for a filter on the query above it.
 */
function statementAt(lines, ln, maxLines = 12) {
  let depth = 0;
  let text = '';
  for (let i = ln - 1; i < Math.min(lines.length, ln - 1 + maxLines); i++) {
    const s = lines[i];
    text += ' ' + s;
    for (const c of s) { if (c === '(') depth++; else if (c === ')') depth--; }
    if (depth <= 0) break;
  }
  return text;
}

function clip(s) { return s.trim().slice(0, 160); }

/**
 * Facts for one symbol.
 *   symbol  graph symbol (id, file, startLine, endLine, declLine)
 *   lines   the FILE's lines (0-based array)
 * Returns [{ symbolId, line, category:'control'|'sensitive', kind, subkind, evidence, basis, rejectionSeen, text }]
 */
/**
 * Blank the comments (and Python docstrings) of a source file, keeping every character position and newline, so line numbers do not move.
 * The analysis looks for calls and comparisons in code; a comment that SAYS `ownerId: req.user.id` or `requireUser(req)` is prose, and prose is the
 * easiest thing for a hostile or merely careless author to write. Strings are left alone (the principal and SQL rules already read around them).
 */
function blankComments(text, file = '') {
  const src = String(text || '');
  const hash = /\.(?:py|rb|sh|php|pl|r)$/i.test(file);
  const dashes = /\.l?hs$/i.test(file);
  const cLike = !dashes && !/\.(?:py|rb|sh|pl|r)$/i.test(file);
  const out = src.split('');
  const n = src.length;
  let i = 0;
  const blank = (a, b) => { for (let k = a; k < b && k < n; k++) if (out[k] !== '\n') out[k] = ' '; };
  while (i < n) {
    const c = src[i]; const d = src[i + 1];
    if (c === '"' || c === "'" || c === '`') {
      if (/\.py$/i.test(file) && src.startsWith(c.repeat(3), i)) {
        const end = src.indexOf(c.repeat(3), i + 3); const stop = end < 0 ? n : end + 3;
        blank(i, stop); i = stop; continue;           // a docstring or triple-quoted block is prose
      }
      let j = i + 1;
      while (j < n && src[j] !== c && !(src[j] === '\n' && c !== '`')) { if (src[j] === '\\') j++; j++; }
      i = j + 1; continue;
    }
    if (cLike && c === '/' && d === '*') { const end = src.indexOf('*/', i + 2); const stop = end < 0 ? n : end + 2; blank(i, stop); i = stop; continue; }
    if (cLike && c === '/' && d === '/' && (i === 0 || /[\s;,)}{\]]/.test(src[i - 1]))) { let j = src.indexOf('\n', i); if (j < 0) j = n; blank(i, j); i = j; continue; }
    if (hash && c === '#' && !(file.endsWith('.php') && d === '[')) { let j = src.indexOf('\n', i); if (j < 0) j = n; blank(i, j); i = j; continue; }
    if (dashes && c === '-' && d === '-' && !/[!#$%&*+./<=>?@\\^|~:]/.test(src[i + 2] || ' ')) { let j = src.indexOf('\n', i); if (j < 0) j = n; blank(i, j); i = j; continue; }
    if (dashes && c === '{' && d === '-') { const end = src.indexOf('-}', i + 2); const stop = end < 0 ? n : end + 2; blank(i, stop); i = stop; continue; }
    i++;
  }
  return out.join('');
}

function bodyAfterSignature(raw) {
  const arrow = raw.indexOf('=>');
  let rest = null;
  if (arrow >= 0) rest = raw.slice(arrow + 2);
  else { const m = /\)\s*\{(.*)$/.exec(raw); if (m) rest = m[1]; }
  if (rest === null) return '';
  const brace = /^\s*\{(.*)$/.exec(rest);
  return brace ? brace[1] : rest;
}

function analyzeSymbolText(symbol, lines, { haskell = false } = {}) {
  const out = [];
  const seen = new Set();
  const depParams = symbol.declLine ? dependencyParams(signatureText(lines, symbol.declLine)).filter(d => PRINCIPAL_DEP.test(d.dependency)) : [];
  const extraPrincipal = depParams.length ? new RegExp(`\\b(?:${depParams.map(d => d.param).join('|')})\\b\\s*(?:\\.|\\[)`) : null;
  const push = (f) => {
    const key = `${f.line}|${f.category}|${f.kind}|${f.basis}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ symbolId: symbol.id, ...f });
  };

  for (let ln = symbol.startLine; ln <= symbol.endLine; ln++) {
    const raw = lines[ln - 1];
    if (raw === undefined) break;
    const t = raw.trim();
    if (t === '' || /^(?:\/\/|#(?!\[)|--|\/\*|\*)/.test(t)) continue;

    // decorators / annotations that sit above the declaration are guards in their own right
    if (ln < (symbol.declLine || symbol.startLine) + 1 && DECORATOR.test(raw)) {
      const kind = /role|perm|PreAuthorize|PostAuthorize|Secured|RolesAllowed|admin|staff|Roles|Permissions|RequirePermission/i.test(raw) ? 'authorization-role' : 'authentication';
      push({ line: ln, category: 'control', kind, subkind: null, evidence: 'observed', basis: 'decorator', rejectionSeen: true, text: clip(raw) });
      continue;
    }

    // a declaration line is not a call: `function requireUser(` names a function, it does not invoke one
    const isDeclLine = ln === symbol.declLine && /(?:\bfunction\b|\bdef\b|=>|^\s*(?:async\s+)?[\w$.]+\s*[=:]\s*(?:async\s*)?(?:function|\()|^\s*(?:public|private|protected|static|func|fun)\b)/.test(raw);

    // calls on this line
    const calls = [];
    const re = /([A-Za-z_$][\w$]*(?:(?:\.|::)[A-Za-z_$][\w$]*)*)\s*\(/g;
    let m;
    // A one-line handler (`app.get('/x', guard, async (req, res) => { res.json(await db.docs.findOne({ id })); })`) is its own declaration
    // line, so skipping the whole line also skipped its body. Only the SIGNATURE is skipped: the calls after the arrow or the opening brace count.
    const scanText = isDeclLine ? bodyAfterSignature(raw) : raw;
    while ((m = re.exec(scanText))) calls.push(m[1]);
    if (haskell && !isDeclLine) {
      const hre = /\b([A-Z][\w.]*\.[a-z][\w']*|[a-z][\w']*)\b/g;
      while ((m = hre.exec(raw))) if (AUTH_NAME.test(m[1]) || HS_SENSITIVE.test(m[1])) calls.push(m[1]);
    }
    for (const name of calls) {
      if (AUTH_NAME.test(name) && !/^(?:if|for|while|switch|catch|function)$/.test(name)) {
        const lastSeg = name.split(/[.:]/).pop();
        // A predicate (isOwner, hasRole, can) only returns an answer. Called as a bare statement its answer is thrown away,
        // so it guards nothing, whatever the lines around it say.
        const discarded = !haskell && PREDICATE_NAME.test(lastSeg) && bareCallStatement(t, name);
        const rej = !discarded && (REJECT.test(lines.slice(ln - 1, ln + 3).join(' ')) || /^(?:require|ensure|enforce|assert|authori[sz]e|authenticate|protect)/i.test(lastSeg));
        push({ line: ln, category: 'control', kind: kindOfAuthName(name), subkind: null, evidence: 'inferred', basis: discarded ? 'call-name-result-discarded' : 'call-name', rejectionSeen: rej, text: clip(raw) });
      }
      const last = name.split(/[.:]/).pop();
      const recv = name.includes('.') ? name.slice(0, name.lastIndexOf('.')) : '';
      const isSens = haskell
        ? HS_SENSITIVE.test(name)
        : (SENSITIVE_NAME.test(name) && (DB_RECEIVER.test(recv) || /^(?:query|queryOne|queryRow|execute|executeQuery|rawQuery|findOne|findById|findByPk|findUnique|findFirst|findMany|insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|runDB|writeFile|writeFileSync|appendFile|unlink|spawn|spawnSync|execSync|execFile|upsert)$/.test(last)));
      if (isSens) {
        const verb = WRITE_VERB.test(last) ? 'write' : 'read';
        const sub = /(?:writeFile|appendFile|unlink|rm|rmdir)/i.test(last) ? 'filesystem'
          : /(?:spawn|exec|system|popen|callProcess|readProcess)/i.test(last) && !/execute|query/i.test(last) ? 'process'
          : /(?:fetch|request|axios|http|got|superagent|requests|httpx)/i.test(name) ? 'external-call'
          : `data-${verb}`;
        push({ line: ln, category: 'sensitive', kind: sub, subkind: verb, evidence: 'observed', basis: 'call-name', rejectionSeen: null, text: clip(raw) });
        // a data operation whose own statement mentions the principal and an owner/tenant field is scoped by it
        const stmt = statementAt(lines, ln);
        const pr = sub.startsWith('data-') ? ownerBinding(stmt, extraPrincipal) : null;
        if (pr) {
          push({ line: ln, category: 'control', kind: pr.tenant ? 'tenant-scope' : 'ownership', subkind: null, evidence: pr.level === 'qualified' ? 'observed' : 'inferred', basis: pr.level === 'qualified' ? 'query-filter' : 'query-filter-bare-identifier', rejectionSeen: null, text: clip(raw) });
        }
      }
    }
    // Python ORM calls. `Model.query.filter_by(...).delete()` and `db.session.add(x)` name no database receiver the call-name rule
    // recognises, and the chained `.delete()` is not a call on one, so the data operation was invisible and a route that
    // deletes a row read as touching nothing sensitive. A write is a chained mutation or a session write; anything else is a read.
    if (!haskell && PY_ORM.test(raw)) {
      const orm = PY_ORM_WRITE.test(raw) ? 'write' : 'read';
      push({ line: ln, category: 'sensitive', kind: `data-${orm}`, subkind: orm, evidence: 'observed', basis: 'orm-call', rejectionSeen: null, text: clip(raw) });
      const stmt = statementAt(lines, ln);
      const pr = ownerBinding(stmt, extraPrincipal);
      if (pr) {
        push({ line: ln, category: 'control', kind: pr.tenant ? 'tenant-scope' : 'ownership', subkind: null, evidence: pr.level === 'qualified' ? 'observed' : 'inferred', basis: pr.level === 'qualified' ? 'query-filter' : 'query-filter-unqualified', rejectionSeen: null, text: clip(raw) });
      }
    }
    if (SQL_TEXT.test(raw)) {
      const verb = /\b(?:insert|update|delete)\b/i.test(raw) ? 'write' : 'read';
      push({ line: ln, category: 'sensitive', kind: `data-${verb}`, subkind: verb, evidence: 'observed', basis: 'sql-text', rejectionSeen: null, text: clip(raw) });
      const stmt = statementAt(lines, ln);
      const pr = ownerBinding(stmt, extraPrincipal);
      if (pr) {
        push({ line: ln, category: 'control', kind: pr.tenant ? 'tenant-scope' : 'ownership', subkind: null, evidence: pr.level === 'qualified' ? 'observed' : 'inferred', basis: pr.level === 'qualified' ? 'query-filter' : 'query-filter-bare-identifier', rejectionSeen: null, text: clip(raw) });
      }
    }

    // a resource field compared with the principal: the ownership check itself
    const cmpPr = COMPARE.test(raw) && /\b(?:if|unless|assert|when|guard|require|expect|where|elif|&&|\|\|)\b|\?/.test(raw) ? ownerBinding(raw, extraPrincipal) : null;
    if (cmpPr) {
      const rej = REJECT.test(lines.slice(ln - 1, ln + 3).join(' '));
      push({ line: ln, category: 'control', kind: cmpPr.tenant ? 'tenant-scope' : 'ownership', subkind: null, evidence: cmpPr.level === 'qualified' ? 'observed' : 'inferred', basis: cmpPr.level === 'qualified' ? 'comparison' : 'comparison-bare-identifier', rejectionSeen: rej, text: clip(raw) });
    }
  }
  // A function whose NAME says it is a guard and whose BODY shows a rejection path is a guard function. This is
  // 'inferred' (the name) with the rejection read from the body; a name alone never counts as rejecting.
  if (symbol.kind === undefined || symbol.kind === 'function') {
    const nm = String(symbol.name || '');
    if (nm && !nm.startsWith('<') && AUTH_NAME.test(nm)) {
      const body = lines.slice(symbol.startLine - 1, symbol.endLine).join('\n');
      if (REJECT.test(body)) push({ line: symbol.declLine || symbol.startLine, category: 'control', kind: kindOfAuthName(nm), subkind: null, evidence: 'inferred', basis: 'guard-function', rejectionSeen: true, text: clip(lines[(symbol.declLine || symbol.startLine) - 1] || '') });
    }
  }
  out.sort((a, b) => a.line - b.line || (a.category < b.category ? -1 : a.category > b.category ? 1 : 0) || (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0) || (a.basis < b.basis ? -1 : 1));
  return out;
}

/** True when a fact set contains anything the packer must never drop. */
function isSecuritySignificant(facts) {
  return facts.length > 0;
}

const TELEMETRY_NAME = /(?:^|[.:_])(?:log(?:ger)?|logging|metrics?|telemetry|statsd|trace|tracing|span|instrument|monitor|analytics|track(?:ing)?|debug|audit_?log_?noop|format_?(?:date|time|currency|number)|pretty|humanize)\w*$/i;
function looksLikeTelemetry(name) { return TELEMETRY_NAME.test(String(name || '')); }


/***/ }),

/***/ 50152:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   Nk: () => (/* binding */ buildSymbolGraph),
/* harmony export */   U2: () => (/* binding */ MATERIAL_REASONS),
/* harmony export */   dC: () => (/* binding */ validateGraph)
/* harmony export */ });
/* unused harmony exports GRAPH_SCHEMA_VERSION, CONTINUATIONS, EDGE_KINDS, RESOLVERS, conditionalityOf */
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(44652);
/* harmony import */ var _spans_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(77311);
/* harmony import */ var _imports_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(86588);
//
// Versioned, typed declaration/reference graph (symbol-graph/1).
//
// This is an ADAPTER-FED CONTRACT, not a second analyzer: symbols and calls come from the shared IR (or, additively,
// from imported compiler metadata). What this module adds is the part the context packer needs and the IR does not
// carry: stable ids, hash-verifiable source spans, per-edge provenance and conditionality, and an explicit,
// classified record of every call that could not be resolved. An unresolved call is data, never a leaf that looks
// like fully analysed code.




const GRAPH_SCHEMA_VERSION = 'symbol-graph/1';

const CONTINUATIONS = /^(?:next|done|cb|callback|resolve|reject|reply|fn_next)$/;

/** Unresolved-call reasons that could be hiding first-party code (and so block a `complete` claim). */
const MATERIAL_REASONS = Object.freeze(new Set([
  'name-matches-first-party-declaration', 'dynamic-callee', 'call-through-local-or-parameter',
  'ambiguous-import-target', 'import-target-not-declared-in-module', 'unresolved-relative-import',
]));

const EDGE_KINDS = Object.freeze(['call', 'dynamic_possible', 'external_unknown']);
const RESOLVERS = Object.freeze(['source-static', 'compiler-enriched']);

/** Calls that cannot carry security meaning and are never first-party code. Classified, not dropped. */
const INERT_CALL = /^(?:console\.\w+|Math\.\w+|JSON\.\w+|Object\.(?:keys|values|entries|assign|freeze)|Array\.\w+|Number\.\w+|String\.\w+|Promise\.\w+|parseInt|parseFloat|isNaN|String|Number|Boolean|next|require|print|len|str|int|float|bool|list|dict|tuple|range|isinstance|enumerate|zip|sorted|min|max|sum|abs|round|type|super|pure|fromMaybe|maybe|fmap|show|fst|snd|not|\w+\.(?:json|send|status|sendStatus|end|render|redirect|setHeader|header|then|catch|finally|push|pop|shift|unshift|slice|splice|join|split|map|filter|reduce|forEach|includes|indexOf|toString|trim|replace|toLowerCase|toUpperCase|keys|values|entries|startswith|endswith|lower|upper|items|strip))$/;
const DYNAMIC_CALL = /(?:\[|\bapply\b|\bcall\b|\beval\b|\bFunction\b|__import__|getattr|dynamic|<dynamic>|\bsend\()/;

function lastSegment(name) {
  const s = String(name || '');
  const parts = s.split(/[.:]|::/);
  return parts[parts.length - 1] || s;
}

/** Largest CFG line of a function (0 when it has no CFG). Used only as a lower bound for a span end. */
function cfgMaxLine(fn) {
  let m = 0;
  const nodes = fn && fn.cfg && fn.cfg.nodes;
  if (nodes) for (const n of Object.values(nodes)) if (Number.isInteger(n.line) && n.line > m) m = n.line;
  return m;
}

/** Names a function binds locally: its parameters and every assignment target in its CFG. */
function localNamesOf(fn) {
  const set = new Set((fn && Array.isArray(fn.params) ? fn.params : []).map(String));
  const nodes = fn && fn.cfg && fn.cfg.nodes;
  if (nodes) for (const n of Object.values(nodes)) if (n.kind === 'assign' && typeof n.target === 'string') set.add(n.target);
  return set;
}

/**
 * Is `nodeId` on every modelled path from entry to exit? (CFG dominance, by removal.) Bounded: a CFG larger than
 * the cap reports 'unknown' rather than paying a quadratic cost on a generated file.
 */
function conditionalityOf(fn, nodeId) {
  const cfg = fn && fn.cfg;
  if (!cfg || !cfg.nodes || !nodeId || !cfg.nodes[nodeId]) return 'unknown';
  if (Object.keys(cfg.nodes).length > 600) return 'unknown';
  if (nodeId === cfg.entry || nodeId === cfg.exit) return 'unconditional';
  const seen = new Set([cfg.entry]);
  const stack = [cfg.entry];
  while (stack.length) {
    const cur = stack.pop();
    for (const s of cfg.nodes[cur]?.succ || []) {
      if (s === nodeId || seen.has(s)) continue;
      seen.add(s);
      stack.push(s);
    }
  }
  return seen.has(cfg.exit) ? 'conditional' : 'unconditional';
}

/**
 * Build the graph from IR facts.
 *   fileContents  { path: normalised text }
 *   functions     Map<qid, fn>  (the IR call graph's `functions`)
 *   edges         [{caller, callee|null, calleeName, line, site}]
 *   provenance    'source-static' | 'compiler-enriched'
 */
function buildSymbolGraph({ fileContents, functions, edges }) {
  const linesOf = new Map();
  const lines = (f) => {
    if (!linesOf.has(f)) linesOf.set(f, (fileContents[f] || '').split('\n'));
    return linesOf.get(f);
  };

  // Stable ids: file + declared name + ordinal among same-named declarations in that file, ordered by line. An edit
  // ABOVE a function therefore does not rename it; only adding a same-named sibling above it does.
  const rows = [...functions.values()]
    .filter(fn => fn && fn.file && fileContents[fn.file] !== undefined)
    .sort((a, b) => a.file < b.file ? -1 : a.file > b.file ? 1 : (a.line - b.line) || (a.qid < b.qid ? -1 : 1));
  const ordinal = new Map();
  const idByQid = new Map();
  const symbols = [];
  for (const fn of rows) {
    const anon = /^(?:anon|anonymous|<anonymous>|lambda)\b/.test(fn.name || '') || !fn.name;
    const base = anon ? `${fn.file}::<anon>@${fn.line}` : `${fn.file}::${fn.name}`;
    const k = ordinal.get(base) || 0;
    ordinal.set(base, k + 1);
    // The first declaration keeps the bare id; a same-named sibling, or a SECOND anonymous function on the same line
    // (`xs.map(x => ys.map(y => ...))`), gets an ordinal. Before the ordinal applied to anonymous functions too, two arrows on one
    // line produced two symbols with one id and `validateGraph` refused the whole build as `duplicate-symbol-id`.
    const id = k === 0 ? base : `${base}#${k + 1}`;
    idByQid.set(fn.qid, id);
    const span = (0,_spans_js__WEBPACK_IMPORTED_MODULE_2__/* .spanFor */ .Wc)(fn.file, lines(fn.file), fn.line, cfgMaxLine(fn));
    const text = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sliceLines */ .iq)(fileContents[fn.file], span.startLine, span.endLine);
    symbols.push({
      id,
      name: fn.name || '<anon>',
      kind: fn.name === '<module>' ? 'module-top-level' : 'function',
      file: fn.file,
      startLine: span.startLine,
      endLine: span.endLine,
      declLine: fn.line,
      spanPrecision: span.precision,
      spanHash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)(text),
      params: Array.isArray(fn.params) ? fn.params.map(String) : [],
      resolver: 'source-static',
    });
  }
  symbols.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);

  const byLastName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.name.startsWith('<')) continue;
    const key = lastSegment(s.name);
    if (!byLastName.has(key)) byLastName.set(key, []);
    byLastName.get(key).push(s.id);
  }

  const imports = (0,_imports_js__WEBPACK_IMPORTED_MODULE_1__/* .buildImportMap */ .kB)(fileContents);
  const symbolsByFileName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    for (const key of new Set([s.name, lastSegment(s.name)])) {
      const k = `${s.file}\0${key}`;
      if (!symbolsByFileName.has(k)) symbolsByFileName.set(k, []);
      symbolsByFileName.get(k).push(s.id);
    }
  }

  const byFullName = new Map();
  for (const s of symbols) {
    if (s.kind !== 'function' || s.id.includes('::<anon>@')) continue;
    if (!byFullName.has(s.name)) byFullName.set(s.name, []);
    byFullName.get(s.name).push(s.id);
  }

  const graphEdges = [];
  for (const e of edges || []) {
    const from = idByQid.get(e.caller);
    if (!from) continue;
    const callerFn = functions.get(e.caller);
    const callerFile = callerFn.file;
    const base = {
      from,
      line: Number.isInteger(e.line) ? e.line : 0,
      calleeName: String(e.calleeName || ''),
      resolver: 'source-static',
      conditionality: conditionalityOf(callerFn, e.site),
      resolution: 'ir',
    };
    const to = e.callee ? idByQid.get(e.callee) : null;
    if (to) {
      graphEdges.push({ ...base, to, kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [] });
      continue;
    }
    const name = base.calleeName;
    const push = (kind, confidence, unresolvedReason, candidates = [], extra = {}) => graphEdges.push({ ...base, ...extra, to: null, kind, confidence, unresolvedReason, candidates });

    if (INERT_CALL.test(name) || CONTINUATIONS.test(name)) { push('external_unknown', 'high', 'inert-builtin'); continue; }

    // a fully qualified name (`Auth.requireUser`, `Class.method`) that matches exactly one declaration IS that declaration
    if (/[.:]/.test(name)) {
      const q = (byFullName.get(name) || []).filter(id => id !== from);
      if (q.length === 1) { graphEdges.push({ ...base, to: q[0], kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [], resolution: 'qualified-name' }); continue; }
    }

    const imp = (0,_imports_js__WEBPACK_IMPORTED_MODULE_1__/* .resolveViaImports */ .xU)(imports, callerFile, name);
    if (imp && imp.kind === 'exact-import') {
      const ids = (symbolsByFileName.get(`${imp.targetFile}\0${imp.member}`) || []).filter(id => id !== from);
      if (ids.length === 1) { graphEdges.push({ ...base, to: ids[0], kind: 'call', confidence: 'high', unresolvedReason: null, candidates: [], resolution: 'import' }); continue; }
      push('external_unknown', 'low', ids.length ? 'ambiguous-import-target' : 'import-target-not-declared-in-module', ids.slice(0, 5));
      continue;
    }
    if (imp && imp.kind === 'third-party') { push('external_unknown', 'high', 'third-party-import'); continue; }
    if (imp && imp.kind === 'unresolved-import') { push('external_unknown', 'low', 'unresolved-relative-import'); continue; }

    // a bare identifier that is a parameter or a local assignment is a call through a value: the target is data
    if (/^[A-Za-z_$][\w$]*$/.test(name) && !imp && localNamesOf(callerFn).has(name)) { push('dynamic_possible', 'low', 'call-through-local-or-parameter'); continue; }
    if (DYNAMIC_CALL.test(name) || name === '') { push('dynamic_possible', 'low', 'dynamic-callee'); continue; }

    const cand = (byLastName.get(lastSegment(name)) || []).filter(id => id !== from).slice(0, 5);
    if (cand.length) push('external_unknown', 'low', 'name-matches-first-party-declaration', cand);
    else push('external_unknown', 'high', 'external-boundary');
  }
  graphEdges.sort((a, b) =>
    (a.from < b.from ? -1 : a.from > b.from ? 1 : 0) || (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));

  const snapshotHash = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)(Object.keys(fileContents).sort().map(f => [f, (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)(fileContents[f])]));
  const body = { schemaVersion: GRAPH_SCHEMA_VERSION, snapshotHash, symbols, edges: graphEdges, imports: imports.map(i => ({ file: i.file, local: i.local, source: i.source, member: i.member, kind: i.kind, target: i.target })) };
  return { ...body, hash: (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)(body) };
}

/**
 * Structural validation. Returns a list of problems (empty = valid): dangling ids, spans outside the file, a span
 * hash that no longer matches the text, an edge that names a symbol that is not in the graph.
 */
function validateGraph(graph, fileContents) {
  const problems = [];
  if (!graph || graph.schemaVersion !== GRAPH_SCHEMA_VERSION) return ['unsupported-schema-version'];
  const ids = new Set(graph.symbols.map(s => s.id));
  if (ids.size !== graph.symbols.length) problems.push('duplicate-symbol-id');
  for (const s of graph.symbols) {
    const text = fileContents[s.file];
    if (typeof text !== 'string') { problems.push(`missing-file:${s.file}`); continue; }
    const n = text.split('\n').length;
    if (!(s.startLine >= 1 && s.endLine >= s.startLine && s.endLine <= n)) { problems.push(`span-out-of-range:${s.id}`); continue; }
    if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sliceLines */ .iq)(text, s.startLine, s.endLine)) !== s.spanHash) problems.push(`stale-span-hash:${s.id}`);
  }
  for (const e of graph.edges) {
    if (!ids.has(e.from)) problems.push(`dangling-from:${e.from}`);
    if (e.to && !ids.has(e.to)) problems.push(`dangling-to:${e.to}`);
    for (const c of e.candidates || []) if (!ids.has(c)) problems.push(`dangling-candidate:${c}`);
  }
  const { hash, ...rest } = graph;
  if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)(rest) !== hash) problems.push('graph-hash-mismatch');
  return problems;
}


/***/ }),

/***/ 86588:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   iC: () => (/* binding */ resolveJsModule),
/* harmony export */   kB: () => (/* binding */ buildImportMap),
/* harmony export */   xU: () => (/* binding */ resolveViaImports)
/* harmony export */ });
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(76760);
//
// Import maps (JS/TS and Python): which local name in a file refers to which module, and which declaration in it.
//
// The shared IR resolves a call to a declaration only for the shapes it models; a destructured `require` or a named
// ES import is not one of them, so a call such as `getReport(id)` arrives as an edge to nowhere. Left alone, nearly
// every Express/Node route would be reported as having an unresolved call. This module recovers those edges from the
// import statements themselves and records HOW each was resolved, so the result is still evidence and not a guess:
//
//   exact-import   the local name is bound by an import of a module in the repository, and that module declares a
//                  function of that name (or, for a namespace, of the member name)
//   third-party    the module is a package, not a repository file: a boundary, not first-party code
//   unresolved     a relative import that no repository file satisfies
//
// Scope, stated plainly: this is statement-level pattern matching. Re-export chains, `import()` expressions,
// computed `require` arguments and package-relative aliases (tsconfig paths) are not followed.


const JS_EXTS = ['', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '/index.js', '/index.mjs', '/index.ts', '/index.tsx'];

function resolveJsModule(fromFile, source, files) {
  if (!source.startsWith('.')) return { kind: 'third-party', target: null };
  const base = node_path__WEBPACK_IMPORTED_MODULE_0__.posix.normalize(node_path__WEBPACK_IMPORTED_MODULE_0__.posix.join(node_path__WEBPACK_IMPORTED_MODULE_0__.posix.dirname(fromFile), source));
  for (const ext of JS_EXTS) if (files.has(base + ext)) return { kind: 'repo', target: base + ext };
  return { kind: 'unresolved', target: null };
}

function resolvePyModule(fromFile, dotted, files) {
  let dir = node_path__WEBPACK_IMPORTED_MODULE_0__.posix.dirname(fromFile);
  let mod = dotted;
  const lead = /^\.+/.exec(mod);
  const candidatesBase = [];
  if (lead) {
    for (let i = 1; i < lead[0].length; i++) dir = node_path__WEBPACK_IMPORTED_MODULE_0__.posix.dirname(dir);
    mod = mod.slice(lead[0].length);
    candidatesBase.push(dir === '.' ? '' : dir);
  } else {
    candidatesBase.push('', node_path__WEBPACK_IMPORTED_MODULE_0__.posix.dirname(fromFile) === '.' ? '' : node_path__WEBPACK_IMPORTED_MODULE_0__.posix.dirname(fromFile));
  }
  for (const b of candidatesBase) {
    const rel = mod.replace(/\./g, '/');
    for (const cand of [rel ? `${rel}.py` : '__init__.py', rel ? `${rel}/__init__.py` : '__init__.py']) {
      const full = b ? node_path__WEBPACK_IMPORTED_MODULE_0__.posix.join(b, cand) : cand;
      if (files.has(full)) return { kind: 'repo', target: full };
    }
  }
  return { kind: lead ? 'unresolved' : 'third-party', target: null };
}

function stripComments(text) {
  return text.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' ')).replace(/(^|[^:'"`\\])\/\/[^\n]*/g, (m, p1) => p1 + ' '.repeat(m.length - p1.length));
}

function names(list) {
  return list.split(',').map(s => s.trim()).filter(Boolean).map(s => {
    const m = /^(?:\w+\s+as\s+)?([\w$]+)$/.exec(s.replace(/^type\s+/, '').replace(/^([\w$]+)\s*:\s*([\w$]+)$/, '$1 as $2'));
    const parts = s.replace(/^type\s+/, '').split(/\s+as\s+|\s*:\s*/).map(x => x.trim()).filter(Boolean);
    void m;
    if (parts.length === 2) return { imported: parts[0], local: parts[1] };
    if (parts.length === 1) return { imported: parts[0], local: parts[0] };
    return null;
  }).filter(Boolean).filter(n => /^[\w$]+$/.test(n.imported) && /^[\w$]+$/.test(n.local));
}

/** Import entries for one JS/TS file. */
function jsImports(file, text, files) {
  const t = stripComments(text);
  const out = [];
  const add = (local, source, member) => out.push({ file, local, source, member, ...resolveJsModule(file, source, files) });
  for (const m of t.matchAll(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(?:await\s+)?require\(\s*['"]([^'"]+)['"]\s*\)/g)) for (const n of names(m[1])) add(n.local, m[2], n.imported);
  for (const m of t.matchAll(/\b(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?require\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1], m[2], '*');
  for (const m of t.matchAll(/\bimport\s+(?:type\s+)?([\w$]+)?\s*,?\s*(?:\{([^}]*)\}|\*\s+as\s+([\w$]+))?\s*from\s*['"]([^'"]+)['"]/g)) {
    if (m[1]) add(m[1], m[4], 'default');
    if (m[2]) for (const n of names(m[2])) add(n.local, m[4], n.imported);
    if (m[3]) add(m[3], m[4], '*');
  }
  return out;
}

function pyImports(file, text, files) {
  const out = [];
  const add = (local, source, member) => out.push({ file, local, source, member, ...resolvePyModule(file, source, files) });
  // the unparenthesised form ends at the line end; only the parenthesised form may span lines
  for (const m of text.matchAll(/^[ \t]*from[ \t]+([.\w]+)[ \t]+import[ \t]+(?:\(([\w\s,]+)\)|([\w \t,]+))/gm)) {
    for (const n of (m[2] ?? m[3]).split(',').map(s => s.trim()).filter(Boolean)) {
      const p = n.split(/\s+as\s+/);
      add(p[1] || p[0], m[1], p[0]);
    }
  }
  for (const m of text.matchAll(/^[ \t]*import\s+([.\w]+)(?:\s+as\s+(\w+))?\s*$/gm)) add(m[2] || m[1].split('.')[0], m[1], '*');
  return out;
}

/** All import entries, deterministically ordered. */
function buildImportMap(fileContents) {
  const files = new Set(Object.keys(fileContents));
  const out = [];
  for (const file of [...files].sort()) {
    if (/\.(?:js|jsx|mjs|cjs|ts|tsx)$/i.test(file)) out.push(...jsImports(file, fileContents[file], files));
    else if (/\.py$/i.test(file)) out.push(...pyImports(file, fileContents[file], files));
  }
  return out.sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0) || (a.local < b.local ? -1 : a.local > b.local ? 1 : 0) || (a.source < b.source ? -1 : 1));
}

/**
 * Resolve a callee name used in `file` against the import map.
 * Returns { kind:'exact-import', targetFile, member } | { kind:'third-party' } | { kind:'unresolved-import' } | null.
 */
function resolveViaImports(imports, file, calleeName) {
  const parts = String(calleeName || '').split('.');
  const head = parts[0];
  const imp = imports.filter(i => i.file === file && i.local === head);
  if (!imp.length) return null;
  const i = imp[0];
  if (i.kind === 'third-party') return { kind: 'third-party' };
  if (i.kind === 'unresolved') return { kind: 'unresolved-import' };
  if (parts.length === 1) {
    const member = i.member === '*' || i.member === 'default' ? head : i.member;
    return { kind: 'exact-import', targetFile: i.target, member, namespaceCall: i.member === '*' || i.member === 'default' };
  }
  if (i.member === '*' || i.member === 'default') return { kind: 'exact-import', targetFile: i.target, member: parts[parts.length - 1], namespaceCall: false };
  // `db.query()` where `db` is a NAMED import: a method of an imported object, not a function of that module
  return { kind: 'imported-object-method' };
}


/***/ }),

/***/ 1325:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   u1: () => (/* binding */ buildManifest),
/* harmony export */   yl: () => (/* binding */ validateManifest)
/* harmony export */ });
/* unused harmony exports MANIFEST_SCHEMA_VERSION, INTEGRITY_VALUES, contextHashOf */
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(44652);
/* harmony import */ var _reachability_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(77875);
//
// context-manifest/1: the inspectable record behind every bundle.
//
// A manifest answers, without any model: which entry point, which exact source spans (with hashes), which controls
// were seen and how they were established, what could not be resolved, what was left out and why, and how complete
// the bundle is. `validateManifest` enforces the contract's hard rules, so a manifest that over-claims is an error,
// not a warning.



const MANIFEST_SCHEMA_VERSION = 'context-manifest/1';
const INTEGRITY_VALUES = Object.freeze(['complete', 'partial', 'unavailable']);

/** Content-addressed key of a bundle set. Depends on what the model would see and how it was built, never on the commit. */
function contextHashOf({ entrypoint, pack, graphSchema }) {
  return (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({
    algorithm: 'context-hash/1',
    graphSchema,
    entrypoint: { kind: entrypoint.kind, method: entrypoint.method, path: entrypoint.pathTemplate, handler: entrypoint.handlerSymbol },
    profile: pack.profile, maxTokens: pack.maxTokens, prune: pack.pruneLowValue,
    packages: pack.packages.map(p => p.sha256),
    integrity: pack.integrity,
  });
}

function buildManifest({ entrypoint, reach, pack, graph, fileContents, repository, semanticSource = ['static-ir'] }) {
  const omittedWithControls = pack.omissions.some(o => o.reason === 'omitted_due_to_budget' && o.symbolId && reach.facts.some(f => f.symbolId === o.symbolId));
  const protection = (0,_reachability_js__WEBPACK_IMPORTED_MODULE_1__/* .evaluateProtection */ .lO)({ facts: reach.facts, unknowns: reach.unknowns, omittedWithControls, capped: reach.capped });
  const byId = new Map(graph.symbols.map(s => [s.id, s]));

  const reachableSymbols = reach.visited.map(v => {
    const s = byId.get(v.symbolId);
    return { symbolId: v.symbolId, file: s.file, start: { line: s.startLine, column: 1 }, end: { line: s.endLine, column: 1 }, spanHash: s.spanHash, spanPrecision: s.spanPrecision, reason: v.reason, depth: v.depth, pathFromRoot: v.path, confidence: v.confidence };
  });
  const includedSymbols = new Set(pack.packages.flatMap(p => p.segments.flatMap(s => s.symbolIds)));
  for (const r of reachableSymbols) r.included = includedSymbols.has(r.symbolId) || (reach.root && reach.root.kind === 'inline-block' && r.reason === 'handler');

  const manifest = {
    schemaVersion: MANIFEST_SCHEMA_VERSION,
    entrypointId: entrypoint.id,
    entrypoint: {
      kind: entrypoint.kind, method: entrypoint.method, path: entrypoint.pathTemplate, framework: entrypoint.framework, language: entrypoint.language,
      handlerSymbol: entrypoint.handlerSymbol, handlerKind: entrypoint.handlerKind, handlerConfidence: entrypoint.handlerConfidence,
      registrationSite: entrypoint.registrationSite, authScheme: entrypoint.authScheme, middleware: entrypoint.middleware,
    },
    repository,
    graph: { schemaVersion: graph.schemaVersion, hash: graph.hash, source: semanticSource },
    context: {
      profile: pack.profile, maxTokens: pack.maxTokens, integrity: pack.integrity, integrityReasons: [...pack.integrityReasons].sort(),
      tokenizer: pack.tokenizer, pruneLowValue: pack.pruneLowValue,
      packages: pack.packages.map(p => ({ index: p.index, total: p.total, setId: p.setId, sha256: p.sha256, tokensEstimated: p.tokensEstimated, standalone: p.standalone, integrity: p.integrity, segments: p.segments })),
    },
    reachableSymbols,
    // observed and inferred are kept apart on purpose: a name is not an observation
    controls: reach.facts.filter(f => f.category === 'control').map(f => ({ symbolId: f.symbolId, file: f.file, line: f.line, kind: f.kind, evidence: f.evidence, basis: f.basis, rejectionSeen: f.rejectionSeen, order: f.effLine === -1 ? 'before-handler' : null, status: 'included' })),
    sensitiveOperations: reach.facts.filter(f => f.category === 'sensitive').map(f => ({ symbolId: f.symbolId, file: f.file, line: f.line, kind: f.kind, basis: f.basis })),
    protection,
    unknowns: reach.unknowns.map(u => ({ type: u.type, site: u.site, calleeName: u.calleeName || null, reason: u.reason, material: u.material, candidates: u.candidates || [] })),
    boundaries: reach.boundaries,
    omissions: pack.omissions,
    traversal: { capped: reach.capped, cycles: reach.cycles, limits: reach.limits, unvisited: reach.unvisited },
    status: { entrypoint: entrypoint.disposition, reachability: reach.capped || reach.unknowns.some(u => u.material) ? 'partial' : (reach.root ? 'complete' : 'unavailable'), bundle: pack.integrity },
    resolutionReasons: entrypoint.resolutionReasons,
  };
  manifest.contextHash = contextHashOf({ entrypoint, pack, graphSchema: graph.schemaVersion });
  manifest.manifestHash = (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({ ...manifest, repository: undefined });
  return manifest;
}

/**
 * Contract validation. Returns problems (empty = valid). With `fileContents` it also verifies every span hash against
 * the current source, which is what turns a stale manifest into an error instead of a quiet mismatch.
 */
function validateManifest(m, { fileContents = null } = {}) {
  const p = [];
  if (!m || m.schemaVersion !== MANIFEST_SCHEMA_VERSION) return ['unsupported-schema-version'];
  if (!INTEGRITY_VALUES.includes(m.context?.integrity)) p.push('bad-integrity-value');
  const materialUnknowns = (m.unknowns || []).some(u => u.material);
  const budgetOmissions = (m.omissions || []).some(o => o.reason === 'omitted_due_to_budget');
  if (m.context?.integrity === 'complete' && (materialUnknowns || budgetOmissions || m.traversal?.capped)) p.push('complete-with-material-gaps');
  if (m.context?.integrity === 'complete' && m.status?.entrypoint && m.status.entrypoint !== 'resolved') p.push('complete-with-unresolved-entrypoint');
  for (const pk of m.context?.packages || []) {
    if (pk.total > 1 && pk.integrity === 'complete') p.push(`standalone-complete-in-split-set:${pk.index}`);
    for (const s of pk.segments || []) {
      if (!(0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .safeRelPath */ .Qz)(s.file) || s.file !== (0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .safeRelPath */ .Qz)(s.file)) p.push(`unsafe-path:${s.file}`);
      if (fileContents) {
        const t = fileContents[s.file];
        if (typeof t !== 'string') { p.push(`missing-file:${s.file}`); continue; }
        if (s.startLine < 1 || s.endLine > t.split('\n').length || s.endLine < s.startLine) { p.push(`span-out-of-range:${s.file}:${s.startLine}`); continue; }
        if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sha256 */ .sc)((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .sliceLines */ .iq)(t, s.startLine, s.endLine)) !== s.spanHash) p.push(`stale-span:${s.file}:${s.startLine}-${s.endLine}`);
      }
    }
  }
  const probe = { ...m };
  delete probe.manifestHash;
  if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_0__/* .hashOf */ .qQ)({ ...probe, repository: undefined }) !== m.manifestHash) p.push('manifest-hash-mismatch');
  if (JSON.stringify(m).match(/"(?:file|site)":"(?:\/|[A-Za-z]:)/)) p.push('absolute-host-path');
  return p;
}


/***/ }),

/***/ 77875:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   lO: () => (/* binding */ evaluateProtection),
/* harmony export */   sX: () => (/* binding */ reachFrom)
/* harmony export */ });
/* unused harmony exports DEFAULT_LIMITS, PROTECTION_DIMENSIONS */
/* harmony import */ var _controls_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(17202);
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(44652);
/* harmony import */ var _graph_schema_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(50152);
//
// Deterministic, bounded reachability from an entry point's handler.
//
// Breadth-first, with a stable tie-break (call line, then callee name, then target id), so the same graph always
// yields the same visit order and therefore the same bundle bytes. Three things this module refuses to do:
//
//   * claim exhaustiveness. A call that could not be resolved to a declaration is recorded as an explicit unknown.
//     Only the ones that COULD hide first-party code (the callee's name matches a first-party declaration, or the
//     callee is dynamic) are `material`; a call into a library or a response helper is a boundary, listed but not
//     blocking, because nothing first-party can be hiding behind it.
//   * hide a limit. Hitting the symbol or depth cap marks the walk `capped` and lists what was left unvisited.
//   * lose a control. Middleware and every callee are walked, and each visited symbol's controls are collected by the
//     same classifier the packer uses to refuse pruning.




const DEFAULT_LIMITS = Object.freeze({ maxSymbols: 60, maxDepth: 12 });

function indexGraph(graph) {
  const byId = new Map();
  const edgesFrom = new Map();
  for (const s of graph.symbols) byId.set(s.id, s);
  for (const e of graph.edges) {
    if (!edgesFrom.has(e.from)) edgesFrom.set(e.from, []);
    edgesFrom.get(e.from).push(e);
  }
  return { byId, edgesFrom };
}

/**
 * Walk the graph from an entry point.
 * Returns { root, visited, facts, unknowns, boundaries, capped, unvisited, cycles, limits }.
 */
function reachFrom({ graph, fileContents, entrypoint, limits = {} }) {
  const lim = { ...DEFAULT_LIMITS, ...limits };
  const { byId, edgesFrom } = indexGraph(graph);
  const linesCache = new Map();
  const linesOf = (f) => { if (!linesCache.has(f)) linesCache.set(f, (0,_controls_js__WEBPACK_IMPORTED_MODULE_0__/* .blankComments */ .$E)(fileContents[f] || '', f).split('\n')); return linesCache.get(f); };

  const visited = [];
  const seen = new Set();
  const unknowns = [];
  const boundaryMap = new Map();
  let cycles = 0;
  let capped = false;
  const queue = [];

  const inlineRoot = entrypoint.handlerKind === 'inline' && entrypoint.rootSpan && entrypoint.language === 'haskell';
  const rootSymbol = entrypoint.handlerSymbol ? byId.get(entrypoint.handlerSymbol) : null;

  // the "root view": either the handler declaration or, for an inline handler inside a larger declaration, only the
  // registration block's lines
  let root = null;
  if (inlineRoot && rootSymbol) {
    root = { kind: 'inline-block', symbolId: rootSymbol.id, file: entrypoint.rootSpan.file, startLine: entrypoint.rootSpan.startLine, endLine: entrypoint.rootSpan.endLine, declLine: entrypoint.rootSpan.startLine, spanPrecision: entrypoint.rootSpan.precision };
  } else if (rootSymbol) {
    root = { kind: 'declaration', symbolId: rootSymbol.id, file: rootSymbol.file, startLine: rootSymbol.startLine, endLine: rootSymbol.endLine, declLine: rootSymbol.declLine, spanPrecision: rootSymbol.spanPrecision };
  } else if (entrypoint.rootSpan) {
    root = { kind: 'registration-only', symbolId: null, file: entrypoint.rootSpan.file, startLine: entrypoint.rootSpan.startLine, endLine: entrypoint.rootSpan.endLine, declLine: entrypoint.rootSpan.startLine, spanPrecision: entrypoint.rootSpan.precision };
  }

  const enqueue = (symbolId, depth, reason, viaLine, path, confidence) => {
    if (seen.has(symbolId)) { cycles++; return; }
    seen.add(symbolId);
    queue.push({ symbolId, depth, reason, viaLine, path, confidence });
  };

  if (!root) {
    return { root: null, visited: [], facts: [], unknowns: [{ type: 'no-handler', site: `${entrypoint.registrationSite.file}:${entrypoint.registrationSite.line}`, reason: 'entry point has no resolvable handler or registration block', material: true }], boundaries: [], capped: false, unvisited: [], cycles: 0, limits: lim };
  }

  // middleware runs before the handler: it is enqueued first and ordered at line -1
  for (const mw of [...entrypoint.middleware].sort((a, b) => (a.line - b.line) || (0,_canonical_js__WEBPACK_IMPORTED_MODULE_1__/* .cmpCodeUnit */ .kH)(a.name, b.name))) {
    if (mw.symbolId && byId.has(mw.symbolId)) enqueue(mw.symbolId, 0, mw.inherited ? 'inherited-middleware' : 'middleware', -1, [mw.symbolId], mw.resolution === 'resolved' ? 'exact' : 'name-match');
  }
  if (root.symbolId) {
    if (!seen.has(root.symbolId)) { seen.add(root.symbolId); }
    queue.unshift({ symbolId: root.symbolId, depth: 0, reason: 'handler', viaLine: null, path: [root.symbolId], confidence: entrypoint.handlerConfidence, isRoot: true });
  }

  const emitted = [];
  while (queue.length) {
    const cur = queue.shift();
    const sym = byId.get(cur.symbolId);
    if (!sym) continue;
    if (emitted.length >= lim.maxSymbols) { capped = true; queue.unshift(cur); break; }
    emitted.push(cur);
    visited.push({ symbolId: cur.symbolId, depth: cur.depth, reason: cur.reason, viaLine: cur.viaLine, path: cur.path, confidence: cur.confidence });

    const restrictTo = cur.isRoot && root.kind === 'inline-block' ? [root.startLine, root.endLine] : null;
    const out = (edgesFrom.get(cur.symbolId) || [])
      .filter(e => !e.superseded)
      .filter(e => !restrictTo || (e.line >= restrictTo[0] && e.line <= restrictTo[1]))
      .sort((a, b) => (a.line - b.line) || (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0) || ((a.to || '') < (b.to || '') ? -1 : 1));
    for (const e of out) {
      // The root-level line a chain started on: callees of the handler are ordered by the line of the call that led to them.
      const via = cur.isRoot ? e.line : cur.viaLine;
      if (e.conflict) {
        // the compiler and the static pass disagree about this call: follow both, and say the bundle is not settled
        unknowns.push({ type: 'compiler-static-conflict', site: `${sym.file}:${e.line}`, from: cur.symbolId, calleeName: e.calleeName, reason: 'compiler-and-static-analysis-disagree', material: true, candidates: [] });
      }
      if (e.to) {
        if (cur.depth + 1 > lim.maxDepth) { capped = true; continue; }
        enqueue(e.to, cur.depth + 1, 'callee', via, [...cur.path, e.to], 'exact');
      } else if (_graph_schema_js__WEBPACK_IMPORTED_MODULE_2__/* .MATERIAL_REASONS */ .U2.has(e.unresolvedReason)) {
        unknowns.push({ type: e.kind, site: `${sym.file}:${e.line}`, from: cur.symbolId, calleeName: e.calleeName, reason: e.unresolvedReason, material: true, candidates: e.candidates });
        // Candidates are shown to the model as CANDIDATES (low confidence); the unknown stays material regardless.
        if (e.candidates.length && e.candidates.length <= 3 && cur.depth + 1 <= lim.maxDepth) {
          for (const c of e.candidates) enqueue(c, cur.depth + 1, 'name-match-candidate', via, [...cur.path, c], 'name-match');
        }
      } else {
        const key = `${e.calleeName}|${e.unresolvedReason}`;
        const b = boundaryMap.get(key) || { calleeName: e.calleeName, reason: e.unresolvedReason, count: 0, firstSite: `${sym.file}:${e.line}` };
        b.count++;
        boundaryMap.set(key, b);
      }
    }
  }
  const unvisited = queue.map(q => q.symbolId).sort();

  // facts: classified once per visited symbol, with the effective ordering line attached
  const facts = [];
  for (const v of visited) {
    const sym = byId.get(v.symbolId);
    const isInlineRoot = v.reason === 'handler' && root.kind === 'inline-block';
    const view = isInlineRoot ? { ...sym, startLine: root.startLine, endLine: root.endLine, declLine: root.startLine } : sym;
    const hs = /\.l?hs$/i.test(sym.file);
    for (const f of (0,_controls_js__WEBPACK_IMPORTED_MODULE_0__/* .analyzeSymbolText */ .kl)(view, linesOf(sym.file), { haskell: hs })) {
      let effLine;
      if (v.reason === 'handler') effLine = f.line;
      else if (v.reason === 'middleware' || v.reason === 'inherited-middleware') effLine = -1;
      else effLine = v.viaLine === null || v.viaLine === undefined ? f.line : v.viaLine;
      facts.push({ ...f, file: sym.file, effLine, via: v.reason });
    }
  }
  // registration-only roots have no symbol: still classify the registration block itself
  if (!root.symbolId) {
    const view = { id: `${root.file}::<registration>@${root.startLine}`, file: root.file, startLine: root.startLine, endLine: root.endLine, declLine: root.startLine };
    for (const f of (0,_controls_js__WEBPACK_IMPORTED_MODULE_0__/* .analyzeSymbolText */ .kl)(view, linesOf(root.file), { haskell: /\.l?hs$/i.test(root.file) })) facts.push({ ...f, file: root.file, effLine: f.line, via: 'handler' });
  }

  unknowns.sort((a, b) => (a.site < b.site ? -1 : a.site > b.site ? 1 : 0) || (a.calleeName < b.calleeName ? -1 : 1));
  const boundaries = [...boundaryMap.values()].sort((a, b) => (a.calleeName < b.calleeName ? -1 : a.calleeName > b.calleeName ? 1 : 0));
  return { root, visited, facts, unknowns, boundaries, capped, unvisited, cycles, limits: lim };
}

/**
 * Protection state per dimension. The five non-present states are deliberately distinct, because collapsing them is
 * how "I did not see a check" turns into "there is no check":
 *   present                     an observed or named control precedes the first sensitive operation
 *   evaluated_and_ineffective   a control exists but runs AFTER the first sensitive operation (a late guard)
 *   not_present                 the context is complete and no control of this kind is in it
 *   not_resolved                a material unknown edge could hide one
 *   omitted_due_to_budget       a symbol that holds a control was left out for size
 *   not_seen                    no sensitive operation was seen, so there was nothing for a control to protect
 */
const PROTECTION_DIMENSIONS = Object.freeze(['authentication', 'authorization-role', 'ownership']);

function evaluateProtection({ facts, unknowns, omittedWithControls = false, capped = false }) {
  // An operation inside the middleware chain (a session lookup the authentication guard performs, reached through it) is the
  // control's own work, not an operation the control must precede: it carries the chain's position (-1) and does not gate.
  const sens = facts.filter(f => f.category === 'sensitive' && f.effLine >= 0);
  const firstSens = sens.length ? Math.min(...sens.map(f => f.effLine)) : null;
  const dims = {};
  for (const dim of PROTECTION_DIMENSIONS) {
    const kinds = dim === 'ownership' ? ['ownership', 'tenant-scope'] : [dim];
    const ctl = facts.filter(f => f.category === 'control' && kinds.includes(f.kind));
    // A control whose answer is visibly thrown away (a predicate called as a bare statement) guards nothing.
    const effective = (f) => f.rejectionSeen !== false;
    // Ownership is the one dimension where reading before checking is the ordinary safe shape: load the record by id, refuse unless the
    // principal owns it, and only then act on it. What an unchecked read can do is bounded by the check that follows before anything is
    // written, so for ownership and tenant scope the line that must be preceded is the first WRITE. With no write in view the first
    // sensitive operation of any kind still applies, so a read returned without a check is not excused.
    const writes = sens.filter(f => f.subkind === 'write' || f.kind === 'filesystem' || f.kind === 'process');
    const gate = dim === 'ownership' && writes.length ? Math.min(...writes.map(f => f.effLine)) : firstSens;
    const before = ctl.filter(f => effective(f) && (gate === null || f.effLine < gate || (f.basis === 'query-filter' && f.effLine <= gate)));
    const after = ctl.filter(f => gate !== null && f.effLine > gate);
    let state; let why;
    if (before.length) { state = 'present'; why = 'a control precedes the first sensitive operation'; }
    else if (after.length) { state = 'evaluated_and_ineffective'; why = 'every control of this kind runs after the first sensitive operation'; }
    else if (ctl.length && ctl.every(f => !effective(f))) { state = 'evaluated_and_ineffective'; why = 'a check is called but nothing in view acts on its answer'; }
    else if (ctl.length) { state = 'evaluated_and_ineffective'; why = 'a control is present but is not ordered before the sensitive operation'; }
    else if (omittedWithControls) { state = 'omitted_due_to_budget'; why = 'a symbol holding a control was left out for size'; }
    else if (unknowns.some(u => u.material) || capped) { state = 'not_resolved'; why = 'an unresolved call or a traversal limit could hide a control'; }
    else if (firstSens === null) { state = 'not_seen'; why = 'no sensitive operation was seen in the resolved context'; }
    else { state = 'not_present'; why = 'the resolved context is complete and contains no control of this kind'; }
    dims[dim] = {
      state, why, firstSensitiveLine: firstSens,
      // How the control was established: 'observed' = the text shows it, 'inferred' = only a name suggests it. Only meaningful for `present`.
      strength: state === 'present' ? (before.some(f => f.evidence === 'observed') ? 'observed' : 'inferred') : null,
      evidence: ctl.slice(0, 6).map(f => ({ file: f.file, line: f.line, kind: f.kind, evidence: f.evidence, basis: f.basis, order: firstSens === null ? 'no-sensitive-op' : f.effLine < firstSens ? 'before-sensitive' : f.effLine > firstSens ? 'after-sensitive' : 'same-step', rejectionSeen: f.rejectionSeen })),
    };
  }
  return dims;
}


/***/ }),

/***/ 77311:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   $X: () => (/* binding */ inlineBlockSpan),
/* harmony export */   Wc: () => (/* binding */ spanFor),
/* harmony export */   sG: () => (/* binding */ splitArgs),
/* harmony export */   yP: () => (/* binding */ callStatement)
/* harmony export */ });
//
// Source-span computation. The shared IR records where a function STARTS and the lines of its CFG nodes, but not where
// it ends, and a context bundle must quote whole declarations. Ends are therefore derived from the source text here,
// and every derived end says how it was derived (`precision`), because a bundle that quietly cut a function short
// would drop a guard without anyone being told.
//
//   brace        a balanced `{ ... }` body was found after the declaration start
//   indent       the body is the run of lines indented deeper than the declaration (Python, Haskell, Nix, Ruby-ish)
//   cfg-lower-bound  neither worked; the last CFG line is a LOWER bound and the span is flagged as uncertain

const BRACE_LANG = /\.(?:js|jsx|mjs|cjs|ts|tsx|java|cs|kt|go|php|phtml|rs|c|cc|cpp|cxx|h|hpp)$/i;
const INDENT_LANG = /\.(?:py|l?hs|nix|rb)$/i;

function indentOf(line) {
  const m = /^[ \t]*/.exec(line)[0];
  return m.replace(/\t/g, '    ').length;
}

/** Find the line of the `}` that closes the first `{` at or after startLine. Skips strings and comments. */
function braceEnd(lines, startLine) {
  let depth = 0;
  let opened = false;
  let inBlock = false;
  for (let i = startLine - 1; i < lines.length; i++) {
    const s = lines[i];
    let quote = null;
    for (let j = 0; j < s.length; j++) {
      const c = s[j];
      const n = s[j + 1];
      if (inBlock) { if (c === '*' && n === '/') { inBlock = false; j++; } continue; }
      if (quote) {
        if (c === '\\') { j++; continue; }
        if (c === quote) quote = null;
        continue;
      }
      if (c === '/' && n === '/') break;
      if (c === '/' && n === '*') { inBlock = true; j++; continue; }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '{') { depth++; opened = true; }
      else if (c === '}') {
        depth--;
        if (opened && depth === 0) return i + 1;
      }
    }
    // A declaration with no brace on its first lines is not a braced body (an arrow expression, an abstract method).
    if (!opened && i - (startLine - 1) > 6) return null;
    // A statement that ended before any brace opened (`foo();`) has no body to close.
    if (!opened && /;\s*$/.test(s) && i >= startLine - 1) return null;
  }
  return null;
}

function indentEnd(lines, startLine) {
  const base = indentOf(lines[startLine - 1] || '');
  let end = startLine;
  for (let i = startLine; i < lines.length; i++) {
    const s = lines[i];
    if (s.trim() === '') continue;
    if (indentOf(s) > base) end = i + 1;
    else break;
  }
  return end;
}

/**
 * { startLine, endLine, precision } for a declaration that begins at `line`. `cfgMax` is the largest CFG line seen
 * for that function (or 0). Decorators / annotations / attributes immediately above the declaration are included in
 * the span: they ARE the guard on many frameworks (`@login_required`, `@PreAuthorize`).
 */
function spanFor(file, lines, line, cfgMax = 0) {
  let start = Math.max(1, line);
  // pull in contiguous decorator/annotation lines directly above
  while (start > 1 && /^\s*(?:@[A-Za-z_]|\[[A-Z]\w*[\](,])/.test(lines[start - 2] || '')) start--;
  let end = null;
  let precision = 'cfg-lower-bound';
  if (BRACE_LANG.test(file)) {
    end = braceEnd(lines, line);
    if (end) precision = 'brace';
  }
  if (!end && INDENT_LANG.test(file)) {
    end = indentEnd(lines, line);
    precision = 'indent';
  }
  if (!end) end = Math.max(line, cfgMax || line);
  end = Math.min(end, lines.length);
  return { startLine: start, endLine: Math.max(end, start), precision };
}

/** Indentation block starting at a registration line: the line plus every following line indented deeper. */
function inlineBlockSpan(lines, line) {
  return { startLine: line, endLine: indentEnd(lines, line), precision: 'indent' };
}

/** Balanced `( ... )` statement text starting at the first `(` on or after `line`. { text, endLine } or null. */
function callStatement(lines, line, maxLines = 40) {
  let depth = 0;
  let opened = false;
  let quote = null;
  let text = '';
  for (let i = line - 1; i < Math.min(lines.length, line - 1 + maxLines); i++) {
    const s = lines[i];
    for (let j = 0; j < s.length; j++) {
      const c = s[j];
      text += c;
      if (quote) {
        if (c === '\\') { text += s[j + 1] || ''; j++; continue; }
        if (c === quote) quote = null;
        continue;
      }
      if (c === '"' || c === "'" || c === '`') { quote = c; continue; }
      if (c === '(') { depth++; opened = true; }
      else if (c === ')') {
        depth--;
        if (opened && depth === 0) return { text, endLine: i + 1 };
      }
    }
    text += '\n';
  }
  return null;
}

/** Split the arguments of a call text at top-level commas. Returns trimmed argument strings. */
function splitArgs(callText) {
  const open = callText.indexOf('(');
  if (open < 0) return [];
  const body = callText.slice(open + 1, callText.lastIndexOf(')') >= 0 ? callText.lastIndexOf(')') : undefined);
  const args = [];
  let depth = 0;
  let quote = null;
  let cur = '';
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      cur += c;
      if (c === '\\') { cur += body[i + 1] || ''; i++; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'" || c === '`') { quote = c; cur += c; continue; }
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    if (c === ',' && depth === 0) { args.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) args.push(cur.trim());
  return args;
}


/***/ }),

/***/ 65535:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   DU: () => (/* binding */ writeStoreJson),
/* harmony export */   Mf: () => (/* binding */ writeBundle),
/* harmony export */   Nl: () => (/* binding */ exportBundle),
/* harmony export */   Oq: () => (/* binding */ readStoreFile),
/* harmony export */   V3: () => (/* binding */ verifyStoredBundle),
/* harmony export */   WI: () => (/* binding */ readManifest),
/* harmony export */   WS: () => (/* binding */ readStoreJson),
/* harmony export */   Yt: () => (/* binding */ readPackageText),
/* harmony export */   ZP: () => (/* binding */ listStoredBundles),
/* harmony export */   kF: () => (/* binding */ cleanupStore),
/* harmony export */   q1: () => (/* binding */ storeRoot),
/* harmony export */   writeStoreFile: () => (/* binding */ writeStoreFile)
/* harmony export */ });
/* unused harmony exports STORE_DIR, ARTIFACT_NAME */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var node_path__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(76760);
/* harmony import */ var node_crypto__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(77598);
/* harmony import */ var _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(31174);
/* harmony import */ var _posture_legal_hold_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(45144);
/* harmony import */ var _manifest_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(1325);
/* harmony import */ var _canonical_js__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(44652);
//
// Governed persistence for DCI artifacts, under `<project>/.agentic-security/context-intelligence/`.
//
// Layout (all content-addressed where it can be):
//   bundles/<contextHash>/manifest.json, context-<n>.txt   one directory per bundle set
//   index.json                                             entry point -> current bundle, plus the build identity
//   reviews/<jobKey>.json                                  one verified review result per job
//   queues/<runId>.json                                    durable job-queue state (resume / cancel)
//   batches/<batchId>/                                     offline batch request and result files
//
// Every write is a temp file + rename, opened O_EXCL | O_NOFOLLOW, so a symlink or hard link planted at the target is
// REPLACED, never written through. Directories are created 0700 and files 0600. The state root must resolve inside
// the project root. Reads re-verify: a stored text file whose hash no longer matches its manifest is an ERROR.








const STORE_DIR = 'context-intelligence';
const ARTIFACT_NAME = STORE_DIR;
const SAFE_SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const MAX_JSON_BYTES = 32 * 1024 * 1024;

function storeRoot(root) { return (0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.statePath)(root, STORE_DIR); }

function refuse(code, reason) { return { ok: false, code, reason }; }

function segments(rel) {
  const segs = String(rel).split('/');
  if (!segs.length || segs.some(s => !SAFE_SEGMENT.test(s) || s === '.' || s === '..')) return null;
  return segs;
}

/** Create the directory chain below the store root, refusing links and anything resolving outside the project. */
function ensureDirs(root, segs) {
  const base = storeRoot(root);
  const projectReal = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(node_path__WEBPACK_IMPORTED_MODULE_1__.resolve(root));
  const stateRoot = node_path__WEBPACK_IMPORTED_MODULE_1__.join(projectReal, _posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__/* .STATE_DIR_NAME */ .Ky);
  if (!(0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.isSafeStateDir)(stateRoot)) return refuse('unsafe-state-dir', 'no project marker beside the state directory');
  node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(stateRoot, { recursive: true, mode: 0o700 });
  let cur = node_path__WEBPACK_IMPORTED_MODULE_1__.join(stateRoot, STORE_DIR);
  void base;
  for (const seg of [null, ...segs]) {
    if (seg !== null) cur = node_path__WEBPACK_IMPORTED_MODULE_1__.join(cur, seg);
    try {
      const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(cur);
      if (st.isSymbolicLink()) return refuse('symlink', `${node_path__WEBPACK_IMPORTED_MODULE_1__.relative(projectReal, cur)} is a symbolic link`);
      if (!st.isDirectory()) return refuse('not-a-directory', node_path__WEBPACK_IMPORTED_MODULE_1__.relative(projectReal, cur));
    } catch (e) {
      if (e && e.code !== 'ENOENT') return refuse('stat-failed', String(e.code || e));
      node_fs__WEBPACK_IMPORTED_MODULE_0__.mkdirSync(cur, { mode: 0o700 });
    }
  }
  const real = node_fs__WEBPACK_IMPORTED_MODULE_0__.realpathSync(cur);
  if (real !== stateRoot && !real.startsWith(stateRoot + node_path__WEBPACK_IMPORTED_MODULE_1__.sep)) return refuse('escapes-state-root', 'the store resolves outside the project');
  return { ok: true, dir: real };
}

/** Atomic, link-safe write of one file below the store root. `rel` is like `bundles/<hash>/manifest.json`. */
function writeStoreFile(root, rel, body) {
  try {
    if (!(0,_posture_state_dir_js__WEBPACK_IMPORTED_MODULE_3__.stateWritesEnabled)()) return refuse('state-writes-disabled', 'state writes are switched off for this process');
    if (typeof body !== 'string' && !Buffer.isBuffer(body)) return refuse('bad-body', 'body must be a string or Buffer');
    if (Buffer.byteLength(body) > MAX_JSON_BYTES) return refuse('too-large', 'artifact exceeds the size ceiling');
    const segs = segments(rel);
    if (!segs) return refuse('bad-path', 'store paths are safe relative names');
    const name = segs.pop();
    const d = ensureDirs(root, segs);
    if (!d.ok) return d;
    const target = node_path__WEBPACK_IMPORTED_MODULE_1__.join(d.dir, name);
    try { if (node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(target).isSymbolicLink()) { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(target, { force: true }); } } catch { /* absent */ }
    const tmp = node_path__WEBPACK_IMPORTED_MODULE_1__.join(d.dir, `.${name}.${process.pid}.${node_crypto__WEBPACK_IMPORTED_MODULE_2__.randomBytes(6).toString('hex')}.tmp`);
    let fd = null;
    try {
      fd = node_fs__WEBPACK_IMPORTED_MODULE_0__.openSync(tmp, node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.O_WRONLY | node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.O_CREAT | node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.O_EXCL | (node_fs__WEBPACK_IMPORTED_MODULE_0__.constants.O_NOFOLLOW || 0), 0o600);
      node_fs__WEBPACK_IMPORTED_MODULE_0__.writeSync(fd, body);
      node_fs__WEBPACK_IMPORTED_MODULE_0__.fsyncSync(fd);
      node_fs__WEBPACK_IMPORTED_MODULE_0__.closeSync(fd); fd = null;
      node_fs__WEBPACK_IMPORTED_MODULE_0__.renameSync(tmp, target);
    } catch (e) {
      if (fd !== null) { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.closeSync(fd); } catch { /* best effort */ } }
      try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(tmp, { force: true }); } catch { /* best effort */ }
      return refuse('write-failed', String((e && e.message) || e).slice(0, 160));
    }
    return { ok: true, path: target };
  } catch (e) {
    return refuse('write-failed', String((e && e.message) || e).slice(0, 160));
  }
}

function writeStoreJson(root, rel, value) { return writeStoreFile(root, rel, JSON.stringify(value, null, 2) + '\n'); }

/** Read one store file. Never follows a link. Returns { ok, text } or { ok:false, code }. */
function readStoreFile(root, rel) {
  const segs = segments(rel);
  if (!segs) return refuse('bad-path', 'store paths are safe relative names');
  const file = node_path__WEBPACK_IMPORTED_MODULE_1__.join(storeRoot(root), ...segs);
  try {
    const st = node_fs__WEBPACK_IMPORTED_MODULE_0__.lstatSync(file);
    if (st.isSymbolicLink() || !st.isFile()) return refuse('not-a-regular-file', rel);
    if (st.size > MAX_JSON_BYTES) return refuse('too-large', rel);
    return { ok: true, text: node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(file, 'utf8') };
  } catch (e) {
    return refuse(e && e.code === 'ENOENT' ? 'missing' : 'unreadable', rel);
  }
}

function readStoreJson(root, rel) {
  const r = readStoreFile(root, rel);
  if (!r.ok) return r;
  try { return { ok: true, value: JSON.parse(r.text) }; } catch { return refuse('corrupt-json', rel); }
}

/** Persist one built bundle set: manifest + every package text. */
function writeBundle(root, bundle) {
  const { manifest, pack } = bundle;
  const dir = `bundles/${manifest.contextHash}`;
  const written = [];
  for (const p of pack.packages) {
    const r = writeStoreFile(root, `${dir}/context-${p.index}.txt`, p.text);
    if (!r.ok) return r;
    written.push(r.path);
  }
  const m = writeStoreJson(root, `${dir}/manifest.json`, manifest);
  if (!m.ok) return m;
  written.push(m.path);
  return { ok: true, paths: written, contextHash: manifest.contextHash };
}

function readManifest(root, contextHash) {
  if (!/^[0-9a-f]{64}$/.test(String(contextHash))) return refuse('bad-hash', 'a context hash is 64 hex characters');
  return readStoreJson(root, `bundles/${contextHash}/manifest.json`);
}

/** Read a package's stored text and prove it still matches the hash in its manifest. */
function readPackageText(root, manifest, index = 1) {
  const pk = manifest.context.packages.find(p => p.index === index);
  if (!pk) return refuse('no-such-package', String(index));
  const r = readStoreFile(root, `bundles/${manifest.contextHash}/context-${index}.txt`);
  if (!r.ok) return r;
  if ((0,_canonical_js__WEBPACK_IMPORTED_MODULE_6__/* .sha256 */ .sc)(r.text) !== pk.sha256) return refuse('hash-mismatch', `context-${index}.txt does not match the manifest`);
  return { ok: true, text: r.text, package: pk };
}

/**
 * Verify a stored bundle: manifest contract, every package text against its hash, and (with fileContents) every span
 * against the current source. Any mismatch is an error; nothing is skipped quietly.
 */
function verifyStoredBundle(root, contextHash, { fileContents = null } = {}) {
  const m = readManifest(root, contextHash);
  if (!m.ok) return { ok: false, problems: [`manifest-${m.code}`] };
  const problems = [...(0,_manifest_js__WEBPACK_IMPORTED_MODULE_5__/* .validateManifest */ .yl)(m.value, { fileContents })];
  if (m.value.contextHash !== contextHash) problems.push('context-hash-differs-from-directory');
  for (const pk of m.value.context.packages) {
    const t = readPackageText(root, m.value, pk.index);
    if (!t.ok) problems.push(`package-${pk.index}-${t.code}`);
  }
  return { ok: problems.length === 0, problems, manifest: m.value };
}

function listStoredBundles(root) {
  const dir = node_path__WEBPACK_IMPORTED_MODULE_1__.join(storeRoot(root), 'bundles');
  try {
    return node_fs__WEBPACK_IMPORTED_MODULE_0__.readdirSync(dir, { withFileTypes: true }).filter(e => e.isDirectory() && /^[0-9a-f]{64}$/.test(e.name)).map(e => e.name).sort();
  } catch { return []; }
}

/**
 * Remove stored bundles that the current index does not reference and that are older than `olderThanDays`.
 * A legal hold on the `context-intelligence` artifact blocks every deletion. `dryRun` reports without removing.
 */
function cleanupStore(root, { olderThanDays = 30, now = Date.now(), dryRun = false } = {}) {
  const holds = (0,_posture_legal_hold_js__WEBPACK_IMPORTED_MODULE_4__.loadLegalHolds)(root);
  const hold = (0,_posture_legal_hold_js__WEBPACK_IMPORTED_MODULE_4__.isUnderHold)(ARTIFACT_NAME, holds, now);
  if (hold) return { ok: true, removed: [], kept: listStoredBundles(root), blockedByLegalHold: { owner: hold.owner, reason: hold.reason } };
  const idx = readStoreJson(root, 'index.json');
  const referenced = new Set(idx.ok ? (idx.value.entrypoints || []).map(e => e.contextHash).filter(Boolean) : []);
  const removed = [];
  const kept = [];
  for (const h of listStoredBundles(root)) {
    const dir = node_path__WEBPACK_IMPORTED_MODULE_1__.join(storeRoot(root), 'bundles', h);
    let age;
    try { age = (now - node_fs__WEBPACK_IMPORTED_MODULE_0__.statSync(dir).mtimeMs) / 86400000; } catch { kept.push(h); continue; }
    if (referenced.has(h) || age <= olderThanDays) { kept.push(h); continue; }
    if (!dryRun) { try { node_fs__WEBPACK_IMPORTED_MODULE_0__.rmSync(dir, { recursive: true, force: true }); } catch { kept.push(h); continue; } }
    removed.push(h);
  }
  return { ok: true, removed, kept, blockedByLegalHold: null, dryRun };
}

/**
 * Secure export: a single self-describing JSON document with the manifest and the package texts (never the source
 * tree), refused for a bundle that fails verification. Honours legal hold trivially (it only reads).
 */
function exportBundle(root, contextHash) {
  const v = verifyStoredBundle(root, contextHash);
  if (!v.ok) return { ok: false, problems: v.problems };
  const texts = v.manifest.context.packages.map(p => readPackageText(root, v.manifest, p.index).text);
  return { ok: true, export: { schemaVersion: 'context-export/1', manifest: v.manifest, packages: texts } };
}


/***/ }),

/***/ 45144:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   addLegalHold: () => (/* binding */ addLegalHold),
/* harmony export */   isUnderHold: () => (/* binding */ isUnderHold),
/* harmony export */   listLegalHolds: () => (/* binding */ listLegalHolds),
/* harmony export */   loadLegalHolds: () => (/* binding */ loadLegalHolds),
/* harmony export */   removeLegalHold: () => (/* binding */ removeLegalHold)
/* harmony export */ });
/* unused harmony export LEGAL_HOLD_FILE */
/* harmony import */ var node_fs__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(73024);
/* harmony import */ var _state_dir_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(31174);
/* harmony import */ var _artifact_registry_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(70471);
// FR-707 (assurance-hardening PRD): "Support legal hold and policy-
// authorized retention exceptions | Legal hold is identity-bound, reasoned,
// time-bounded where applicable, and auditable."
//
// A third instance of the recurring {owner, reason, expires_at} exception
// shape this codebase already uses twice — `posture/suppressions.js`'s
// pro-tier exception (scoped to a FINDING) and `posture/compliance-policy.js`'s
// structured `not-applicable` (scoped to a COMPLIANCE CONTROL). Per D-0025,
// these are deliberately distinct mechanisms serving different subjects, not
// one shared module — this file is the third subject: a STATE ARTIFACT.
//
// Field naming matches the existing two schemas' snake_case convention
// (`owner`, `reason`, `expires_at`) rather than inventing a fourth style.
//
//   identity-bound   -> `owner` (required, who placed the hold and is
//                        accountable for lifting it)
//   reasoned         -> `reason` (required — "we might need this later" is
//                        not a reason; same discipline suppressions.js
//                        already enforces for its own exceptions)
//   time-bounded
//     where applicable -> `expires_at` is OPTIONAL: a null/absent value is
//                        an INDEFINITE hold, which the acceptance
//                        criterion's own "where applicable" phrase
//                        explicitly allows (a genuine legal matter may have
//                        no known end date) — an ISO date value behaves
//                        exactly like FR-506/FR-1004's own expiring
//                        exceptions: once past, the hold is no longer
//                        active and the artifact is exposed to its normal
//                        retention TTL again.
//   auditable        -> persisted as a single JSON array under
//                        `.agentic-security/legal-holds.json` (itself
//                        registered as operator-config — an operator/legal
//                        team's own input, never scanner-written from scan
//                        results), readable via `listLegalHolds`.
//
// Consulted from TWO places, not one: `retention-policy.js#findExpiredArtifacts`
// (defense in depth for any caller reaching it directly) AND `cmdReset`
// itself for its PLAIN (non-`--expired`) path, which deletes every
// registered 'generated' artifact unconditionally and would otherwise blow
// through a hold that only gated TTL expiry.





const LEGAL_HOLD_FILE = 'legal-holds.json';

function _loadRaw(scanRoot) {
  let fp;
  try { fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE); } catch { return []; }
  let raw;
  try { raw = node_fs__WEBPACK_IMPORTED_MODULE_0__.readFileSync(fp, 'utf8'); } catch { return []; }
  try {
    const doc = JSON.parse(raw);
    return Array.isArray(doc) ? doc : [];
  } catch { return []; }
}

/**
 * All legal holds ever recorded for this project, malformed entries
 * dropped rather than throwing. Never filters by expiry — see
 * `isUnderHold`/`listLegalHolds` for that.
 */
function loadLegalHolds(scanRoot) {
  return _loadRaw(scanRoot).filter(h => h && typeof h === 'object' && typeof h.artifact === 'string' && typeof h.owner === 'string' && typeof h.reason === 'string');
}

/**
 * Is `artifactName` currently protected by an active (non-expired) hold?
 * Returns the matching hold record, or null. Multiple holds on the same
 * artifact are permitted (e.g. two independent legal matters); the first
 * still-active one found is returned.
 */
function isUnderHold(artifactName, holds, now = Date.now()) {
  for (const h of holds) {
    if (h.artifact !== artifactName) continue;
    if (!h.expires_at) return h; // indefinite hold — always active
    const t = Date.parse(h.expires_at);
    if (!Number.isFinite(t) || t >= now) return h;
  }
  return null;
}

/**
 * Active (non-expired) holds only, unless `includeExpired`. For
 * `legal-hold list` / auditing.
 */
function listLegalHolds(scanRoot, { includeExpired = false, now = Date.now() } = {}) {
  const holds = loadLegalHolds(scanRoot);
  if (includeExpired) return holds;
  return holds.filter(h => {
    if (!h.expires_at) return true;
    const t = Date.parse(h.expires_at);
    return !Number.isFinite(t) || t >= now;
  });
}

/**
 * Add a legal hold. Validates identity-bound + reasoned up front (both
 * required, non-empty) and that `expires_at`, if given, is a parseable
 * date in the future — an already-expired hold would be a hold that
 * protects nothing, which is never a legitimate request. `artifact` must
 * name a real registered artifact (artifact-registry.js) — a hold on an
 * unrecognised name can never protect anything and almost always means a
 * typo. Returns `{ok:true, hold}` or `{ok:false, reason}`; never throws.
 */
function addLegalHold(scanRoot, { artifact, owner, reason, expires_at } = {}) {
  if (!artifact || typeof artifact !== 'string') return { ok: false, reason: '--artifact is required' };
  if (!(0,_artifact_registry_js__WEBPACK_IMPORTED_MODULE_2__/* .isRegisteredArtifact */ .Jl)(artifact)) return { ok: false, reason: `"${artifact}" is not a registered state artifact` };
  if (!owner || typeof owner !== 'string') return { ok: false, reason: '--owner is required (identity-bound)' };
  if (!reason || typeof reason !== 'string') return { ok: false, reason: '--reason is required (reasoned)' };
  if (expires_at) {
    const t = Date.parse(expires_at);
    if (!Number.isFinite(t)) return { ok: false, reason: 'expires_at must be a parseable date' };
    if (t < Date.now()) return { ok: false, reason: 'expires_at is in the past — a hold that already expired protects nothing' };
  }
  const hold = { artifact, owner, reason, expires_at: expires_at || null, created_at: new Date().toISOString() };
  const holds = _loadRaw(scanRoot);
  holds.push(hold);
  const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE);
  if (!(0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.safeWriteState)(fp, JSON.stringify(holds, null, 2) + '\n')) {
    return { ok: false, reason: 'state writes are disabled (--no-state) or this is not a safe state directory' };
  }
  return { ok: true, hold };
}

/**
 * Remove every hold on `artifact` (lifting a hold, not letting it expire).
 * Returns the number removed. A no-op (0) if none existed — never an error.
 */
function removeLegalHold(scanRoot, artifact) {
  const holds = _loadRaw(scanRoot);
  const remaining = holds.filter(h => !(h && h.artifact === artifact));
  const removedCount = holds.length - remaining.length;
  if (removedCount > 0) {
    const fp = (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.statePath)(scanRoot, LEGAL_HOLD_FILE);
    (0,_state_dir_js__WEBPACK_IMPORTED_MODULE_1__.safeWriteState)(fp, JSON.stringify(remaining, null, 2) + '\n');
  }
  return removedCount;
}


/***/ })

};
