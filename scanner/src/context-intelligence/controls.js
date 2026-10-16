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

export const CONTROL_KINDS = Object.freeze(['authentication', 'authorization-role', 'ownership', 'tenant-scope']);

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
export function dependencyParams(signatureText) {
  const out = [];
  let m;
  DEP_PARAM.lastIndex = 0;
  while ((m = DEP_PARAM.exec(signatureText))) out.push({ param: m[1] || m[3], dependency: m[2] || m[4] });
  return out;
}
export function signatureText(lines, declLine, maxLines = 12) {
  let t = '';
  for (let i = declLine - 1; i < Math.min(lines.length, declLine - 1 + maxLines); i++) { t += ' ' + lines[i]; if (/\)\s*(?:->[^:]*)?:\s*(?:#.*)?$/.test(lines[i])) break; }
  return t;
}
const OWNER_FIELD = /(?:owner|tenant|org(?:anization)?|account|created_?by|author|user_?id|userId|team|workspace)/i;
const COMPARE = /(?:===|!==|==|!=|\.equals\(|\bis not\b|\bis\b|\bnot in\b|\bin\b|\.includes\(|\.has\()/;
const REJECT = /(?:\breturn\b|\bthrow\b|\braise\b|\babort\b|\bexit\b|\b40[0-9]\b|\bforbidden\b|\bunauthori[sz]ed\b|\bHttpError\b|\breject\b|\bnot_?allowed\b|\bdeny\b|\bdenied\b|throwError|\bfinish\b|\bhalt\b|\bPermissionDenied\b|\bAccessDenied\b|status\()/i;

const AUTH_NAME = /(?:^|[.:])(?:(?:require|ensure|check|assert|verify|validate|enforce|authori[sz]e|authenticate|protect|guard|must|need|has|is|can|cannot|allow)\w*(?:auth|login|session|token|jwt|user|perm|role|admin|owner|access|tenant|scope|member|polic|abilit|credential|principal)\w*|authori[sz]e\w*|authenticate\w*|isAuthenticated|requireAuth\w*|requireUser|requireAdmin|requireAuthId|can|cannot|ability\.\w+|policy\.\w+|hasRole|hasPermission|isAdmin|isOwner|checkOwner\w*|ownedBy|belongsTo)$/i;

const SENSITIVE_NAME = /(?:^|[.:])(?:query|queryOne|queryRow|exec|execute|executeQuery|raw|rawQuery|prepare|find|findAll|findOne|findById|findByPk|findUnique|findFirst|findMany|get|getById|getBy|select|selectList|selectFirst|insert|insertOne|insertMany|insert_|update|updateOne|updateMany|upsert|delete|deleteOne|deleteMany|remove|destroy|save|create|createMany|aggregate|runDB|writeFile|writeFileSync|appendFile|unlink|rm|rmdir|spawn|spawnSync|execSync|execFile|system|popen|fetch|request|post|put|patch)$/i;
const DB_RECEIVER = /(?:^|\b)(?:db|database|conn|connection|pool|client|cursor|session|repo|repository|dao|model|models|collection|table|prisma|knex|sequelize|orm|store|objects|manager|em|entityManager|mongo|redis|cache|conn|stmt|statement|fs|child_process|cp|axios|http|https|requests|httpx|got|superagent|Database|Persist|Yesod|System)\b/;
const SQL_TEXT = /\b(?:select\s[\s\S]{1,120}\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b/i;
const HS_SENSITIVE = /(?:^|\.)(?:runDB|selectList|selectFirst|getBy|getJust|insert_?|insertEntity|update|updateWhere|delete|deleteWhere|replace|upsert|query|query_|execute|execute_|readFile|writeFile|callProcess|readProcess)$|^(?:Database\.|System\.Process\.|System\.Directory\.)/;

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
export function blankComments(text, file = '') {
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

export function analyzeSymbolText(symbol, lines, { haskell = false } = {}) {
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
        const rej = REJECT.test(lines.slice(ln - 1, ln + 3).join(' ')) || /^(?:require|ensure|enforce|assert|authori[sz]e|authenticate|protect)/i.test(name.split(/[.:]/).pop());
        push({ line: ln, category: 'control', kind: kindOfAuthName(name), subkind: null, evidence: 'inferred', basis: 'call-name', rejectionSeen: rej, text: clip(raw) });
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
        const pr = sub.startsWith('data-') && OWNER_FIELD.test(stmt) ? principalIn(stmt, extraPrincipal) : null;
        if (pr) {
          push({ line: ln, category: 'control', kind: /tenant|org|workspace|team|account/i.test(stmt) ? 'tenant-scope' : 'ownership', subkind: null, evidence: pr === 'qualified' ? 'observed' : 'inferred', basis: pr === 'qualified' ? 'query-filter' : 'query-filter-bare-identifier', rejectionSeen: null, text: clip(raw) });
        }
      }
    }
    if (SQL_TEXT.test(raw)) {
      const verb = /\b(?:insert|update|delete)\b/i.test(raw) ? 'write' : 'read';
      push({ line: ln, category: 'sensitive', kind: `data-${verb}`, subkind: verb, evidence: 'observed', basis: 'sql-text', rejectionSeen: null, text: clip(raw) });
      const stmt = statementAt(lines, ln);
      const pr = OWNER_FIELD.test(stmt) ? principalIn(stmt, extraPrincipal) : null;
      if (pr) {
        push({ line: ln, category: 'control', kind: /tenant|org|workspace|team|account/i.test(stmt) ? 'tenant-scope' : 'ownership', subkind: null, evidence: pr === 'qualified' ? 'observed' : 'inferred', basis: pr === 'qualified' ? 'query-filter' : 'query-filter-bare-identifier', rejectionSeen: null, text: clip(raw) });
      }
    }

    // a resource field compared with the principal: the ownership check itself
    const cmpPr = COMPARE.test(raw) && OWNER_FIELD.test(raw) && /\b(?:if|unless|assert|when|guard|require|expect|where|elif|&&|\|\|)\b|\?/.test(raw) ? principalIn(raw, extraPrincipal) : null;
    if (cmpPr) {
      const rej = REJECT.test(lines.slice(ln - 1, ln + 3).join(' '));
      push({ line: ln, category: 'control', kind: /tenant|org|workspace|team|account/i.test(raw) ? 'tenant-scope' : 'ownership', subkind: null, evidence: cmpPr === 'qualified' ? 'observed' : 'inferred', basis: cmpPr === 'qualified' ? 'comparison' : 'comparison-bare-identifier', rejectionSeen: rej, text: clip(raw) });
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
export function isSecuritySignificant(facts) {
  return facts.length > 0;
}

const TELEMETRY_NAME = /(?:^|[.:_])(?:log(?:ger)?|logging|metrics?|telemetry|statsd|trace|tracing|span|instrument|monitor|analytics|track(?:ing)?|debug|audit_?log_?noop|format_?(?:date|time|currency|number)|pretty|humanize)\w*$/i;
export function looksLikeTelemetry(name) { return TELEMETRY_NAME.test(String(name || '')); }
