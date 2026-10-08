// Haskell web entry points, authentication and authorization (HS-006).
//
// Frameworks modelled (versions recorded in HS_WEB_FRAMEWORKS): Scotty, WAI/Warp, Servant, Yesod. For each
// route the analyser records the method, the path, the handler it could resolve, and what it can PROVE about
// who may call it, from the code, never from a type annotation, a server being present, or a name:
//
//   * Warp is a server, not authorization. A type annotation is not enforcement. An authentication
//     declaration that is not applied to the handler (a middleware defined but never installed, a guard
//     function nobody calls) earns no credit.
//   * An auth guard is a function that READS a credential (Authorization / Cookie header, a JWT decode, a
//     session lookup) AND has a rejection path (a 401/403 response, throwError err40x, finish/raise, notAuthenticated).
//     Guards are summarised on the IR across modules, transitively.
//   * A guard protects a handler only if it DOMINATES the first sensitive operation: a guard that runs after
//     the database call is reported as a late guard, not credited.
//   * Object ownership (BOLA) is judged on a comparison or a scoped query that involves the authenticated
//     principal; role checks (BFLA) on a role comparison or role guard; CSRF only for cookie-authenticated
//     state-changing routes, and Servant/Authorization-header APIs are not CSRF-exposed.
//   * What cannot be resolved (a handler built at runtime, routes registered in a loop, an opaque middleware)
//     is recorded as `unknown` coverage, never as protected and never omitted.

import { buildHaskellIR, lowerHandlerExpr, resolveName } from './haskell-ir.js';
import { qualifyAmbiguous, HS_WEB_FRAMEWORKS, HS_WEB_MODEL_VERSION, modelStatus } from './haskell-models.js';

export const HS_WEB_RULES_VERSION = 'haskell-web-rules/1';

export const WEB_RULES = Object.freeze({
  'hs-route-missing-auth': { cwe: 'CWE-306', severity: 'high', family: 'missing-authentication', vuln: 'State-changing route without authentication', remediation: 'Require an authenticated principal before the handler performs any state change.' },
  'hs-route-late-auth': { cwe: 'CWE-306', severity: 'high', family: 'missing-authentication', vuln: 'Authentication check runs after a sensitive operation', remediation: 'Move the authentication guard before the first database, file or process operation.' },
  'hs-route-bola': { cwe: 'CWE-639', severity: 'high', family: 'broken-object-authorization', vuln: 'Object looked up by a client-supplied id without an ownership check', remediation: 'Compare the object owner (or tenant) with the authenticated principal, or scope the query by the principal.' },
  'hs-route-bfla': { cwe: 'CWE-285', severity: 'high', family: 'broken-function-authorization', vuln: 'Privileged route without a role or permission check', remediation: 'Require an admin/role check in addition to authentication.' },
  'hs-route-csrf': { cwe: 'CWE-352', severity: 'medium', family: 'csrf', vuln: 'State-changing route authenticated by a cookie with no CSRF protection', remediation: 'Add a CSRF token check (or SameSite cookies plus an Origin check) for cookie-authenticated state changes.' },
  'hs-yesod-csrf-disabled': { cwe: 'CWE-352', severity: 'medium', family: 'csrf', vuln: 'Yesod middleware overridden without CSRF protection', remediation: 'Keep `defaultCsrfMiddleware` in `yesodMiddleware`.' },
});

const WRITE_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const SCOTTY_METHODS = { get: 'GET', post: 'POST', put: 'PUT', delete: 'DELETE', patch: 'PATCH', options: 'OPTIONS', matchAny: 'ANY', addroute: 'ANY' };
const SENSITIVE_PREFIX = ['Database.', 'System.Process.', 'System.Directory.', 'Prelude.readFile', 'Prelude.writeFile', 'Prelude.appendFile', 'System.IO.', 'Network.HTTP.Simple.', 'Network.HTTP.Client.'];
const PERSIST_FNS = new Set(['get', 'getBy', 'selectFirst', 'selectList', 'insert', 'insert_', 'update', 'updateWhere', 'delete', 'deleteWhere', 'replace', 'runDB', 'getJust', 'upsert']);
const GUARD_PRIMITIVES = new Set(['Yesod.Core.requireAuthId', 'Yesod.Core.requireAuth', 'Yesod.Auth.requireAuthId', 'Yesod.Auth.requireAuth', 'Yesod.requireAuthId', 'Yesod.requireAuth', 'Network.Wai.Middleware.HttpAuth.basicAuth']);
const CREDENTIAL_HEADER = /^(?:authorization|cookie|x-api-key|x-auth-token|x-access-token)$/i;
const ADMIN_PATH = /(?:^|\/)(?:admin|internal|manage|superuser)(?:\/|$|:)/i;
const ROLE_CALL = /(?:^|\.)(?:isAdmin|hasRole|requireAdmin|checkRole|hasPermission|requireRole|requirePermission|isSuperuser)$/i;
const OWNER_CALL = /(?:^|\.)(?:checkOwner|ownedBy|belongsTo|isOwner|requireOwner|authorizeOwner)$/i;
const CSRF_CALL = /csrf|xsrf/i;

// ── AST helpers ──────────────────────────────────────────────────────────────
function unparen(e) { while (e && e.t === 'paren') e = e.e; return e; }

/** Normalise `f a b`, `f a $ b` and `(f a) b` to { head, args }. */
export function spine(e) {
  e = unparen(e);
  if (!e) return null;
  if (e.t === 'op' && e.op === '$') {
    const l = spine(e.l);
    if (l) return { head: l.head, args: [...l.args, e.r] };
    return null;
  }
  if (e.t === 'app') {
    const f = unparen(e.f);
    if (f && (f.t === 'app' || (f.t === 'op' && f.op === '$'))) {
      const inner = spine(f);
      if (inner) return { head: inner.head, args: [...inner.args, ...e.args] };
    }
    return f && f.t === 'var' ? { head: f, args: e.args } : null;
  }
  if (e.t === 'var') return { head: e, args: [] };
  return null;
}

function* walkAst(node, depth = 0) {
  if (!node || typeof node !== 'object' || depth > 120) return;
  if (Array.isArray(node)) { for (const x of node) yield* walkAst(x, depth + 1); return; }
  if (typeof node.t === 'string') yield node;
  for (const k of Object.keys(node)) {
    if (k === 'line' || k === 't') continue;
    const v = node[k];
    if (v && typeof v === 'object') yield* walkAst(v, depth + 1);
  }
}

const strLit = (e) => { e = unparen(e); return e && e.t === 'lit' && e.kind === 'str' ? e.v : null; };

// ── analysis context ─────────────────────────────────────────────────────────
class Ctx {
  constructor(files) {
    this.files = files;
    this.ir = buildHaskellIR(files);
    this.project = this.ir.project;
    this.modules = [...this.ir.modules.values()];
    this.fnByQid = new Map();
    for (const f of Object.values(this.ir.perFile)) for (const fn of f.functions) this.fnByQid.set(fn.qid, fn);
    this.guardMemo = new Map();
    this.gaps = [];
    this.limits = [];
  }

  modOf(file) { return this.modules.find((m) => m.file === file); }

  /** Import-qualified name for a head variable, or null when it cannot be attributed. */
  qualify(mod, head) {
    const r = resolveName(this.project, mod, head.name, head.qual || null);
    if (r.kind === 'external') {
      if (r.module) return { name: `${r.module}.${head.name}`, certain: r.certain !== false };
      const qa = qualifyAmbiguous(head.name, r.candidates);
      if (qa) return { name: `${qa.module}.${head.name}`, certain: false };
      return null;
    }
    if (r.kind === 'def') return { name: `${r.mod}.${r.name}`, qid: r.qid, def: r.def, mod: r.mod };
    return null;
  }

  fnFor(qualified) {
    if (!qualified || !qualified.qid) return null;
    return this.fnByQid.get(qualified.qid) || null;
  }
}

// ── guard summaries (on the IR, across modules, transitive) ───────────────────
function callsOf(fn) { return (fn && fn.calls) || []; }

function headerArg(c) { const a = (c.args || [])[0]; return a && a.kind === 'literal' && typeof a.value === 'string' ? a.value : null; }

function credentialKind(c) {
  if (c.callee === 'Web.Scotty.header' || c.callee === 'Web.Scotty.Trans.header') {
    const h = headerArg(c);
    if (h && CREDENTIAL_HEADER.test(h)) return /cookie/i.test(h) ? 'cookie' : 'token';
  }
  if (c.callee === 'Web.Cookie.parseCookies') return 'cookie';
  if (c.callee === 'Network.Wai.requestHeaders') return 'token';
  if (c.callee.startsWith('Web.JWT.')) return 'token';
  // Yesod: the session principal, or a credential header, read by the handler itself (the caller still has to reject on it)
  if (/^Yesod(?:\.Core|\.Auth)?\.(?:maybeAuthId|maybeAuth)$/.test(c.callee)) return 'session';
  if (/^Yesod(?:\.Core)?\.lookupHeader$/.test(c.callee)) { const h = headerArg(c); if (h && CREDENTIAL_HEADER.test(h)) return /cookie/i.test(h) ? 'cookie' : 'token'; }
  if (/^Yesod(?:\.Core)?\.lookupBearerAuth$/.test(c.callee)) return 'token';
  if (/^Yesod(?:\.Core)?\.lookupBasicAuth$/.test(c.callee)) return 'basic';
  if (GUARD_PRIMITIVES.has(c.callee)) return c.callee.includes('HttpAuth') ? 'basic' : 'session';
  return null;
}

/**
 * Credential reads of one function, by call. A WAI `requestHeaders` read is classified by the key it is looked up with: a lookup of a
 * header that is not a credential (`lookup "X-Request-Id" (requestHeaders req)`) is not a credential read. An unrecognised use of
 * `requestHeaders` keeps its old meaning (a token read), so only the provable non-credential lookup is excluded.
 * The IR lowers `lookup k t` to a call on `t` with the key kept as `hs.selector`.
 */
function credentialReadsOf(fn) {
  const nodes = Object.values(fn.cfg.nodes);
  const hdrTargets = new Map();   // temp name -> line of the node that read requestHeaders
  for (const n of nodes) if (n.kind === 'assign' && n.source && n.source.kind === 'call' && n.source.callee === 'Network.Wai.requestHeaders') hdrTargets.set(n.target, n.line);
  const lineKind = new Map();     // line of a requestHeaders read -> 'token' | 'cookie' | null (a header that is not a credential)
  for (const n of nodes) for (const root of exprsOfNode(n)) for (const e of walkIr(root)) {
    if (e.kind !== 'call' || !/(?:^|\.)lookup$/.test(e.callee || '') || !e.hs || !e.hs.selector) continue;
    const sel = e.hs.selector;
    let name = null;
    if (sel.kind === 'literal' && typeof sel.value === 'string') name = sel.value;
    else if (sel.kind === 'ident' && /(?:^|\.)hAuthorization$/.test(sel.name || '')) name = 'Authorization';
    else if (sel.kind === 'ident' && /(?:^|\.)hCookie$/.test(sel.name || '')) name = 'Cookie';
    if (name === null) continue;
    const a0 = (e.args || [])[0];
    const line = a0 && a0.kind === 'ident' && hdrTargets.has(a0.name) ? hdrTargets.get(a0.name) : (a0 && a0.kind === 'call' && a0.callee === 'Network.Wai.requestHeaders' ? n.line : null);
    if (line === null) continue;
    lineKind.set(line, CREDENTIAL_HEADER.test(name) ? (/cookie/i.test(name) ? 'cookie' : 'token') : null);
  }
  const out = new Map();
  for (const c of callsOf(fn)) {
    let k;
    if (c.callee === 'Network.Wai.requestHeaders' && lineKind.has(c.line)) k = lineKind.get(c.line);
    else k = credentialKind(c);
    if (k) out.set(c, k);
  }
  return out;
}

/**
 * `notAuthenticated` takes no argument, so it is an identifier in the IR, not a call (like Scotty's `finish`). It ends the handler by itself,
 * so each occurrence is a rejection, reported as a pseudo-call at its enclosing node's line.
 */
function nullaryRejectionsOf(fn) {
  const out = [];
  for (const n of Object.values(fn.cfg.nodes)) for (const root of exprsOfNode(n)) for (const e of walkIr(root)) {
    if (e.kind === 'ident' && /^Yesod(?:\.Core)?\.notAuthenticated$/.test(e.name || '')) out.push({ kind: 'call', callee: e.name, args: [], line: Number.isFinite(e.line) ? e.line : n.line, hs: { nullary: true } });
  }
  return out;
}

// A WAI rejection is a response VALUE: it ends the handler only when it is handed back (`respond (responseLBS 401 ..)`, `return (..)`).
// Built and dropped, it rejects nothing. Servant's throwError, Yesod's permissionDenied/notAuthenticated and Scotty's raiseStatus end the
// handler by themselves.
function stopsHandler(c, allCalls) {
  if (c.callee !== 'Network.Wai.responseLBS') return true;
  return allCalls.some((p) => p !== c && (p.callee === 'return' || p.callee === 'pure' || (p.hs && p.hs.status === 'param') || p.callee === 'respond')
    && (p.args || []).some((a) => [...walkIr(a)].some((x) => x.kind === 'call' && x.args === c.args)));
}

function isRejection(c) {
  const name = c.callee;
  const argNames = (c.args || []).flatMap((a) => (a && a.kind === 'ident' ? [a.name] : []));
  if ((name === 'Web.Scotty.status' || name === 'Web.Scotty.Trans.status') && argNames.some((n) => /(?:status40[13]|unauthorized401|forbidden403)$/.test(n))) return true;
  if (/^Web\.Scotty(?:\.Trans)?\.raiseStatus$/.test(name) && argNames.some((n) => /(?:status40[13]|unauthorized401|forbidden403)$/.test(n))) return true;   // halts by itself
  if (name === 'Network.Wai.responseLBS' && argNames.some((n) => /(?:status40[13]|unauthorized401|forbidden403)$/.test(n))) return true;
  // `throwError err401 { errBody = .. }` is a record update: the status constructor is inside it
  if (/^(?:Servant|Servant\.Server|Control\.Monad\.Except)\.throwError$/.test(name) && (c.args || []).some((a) => a && [...walkIr(a)].some((x) => (x.kind === 'ident' && /err40[13]$/.test(x.name || '')) || (x.kind === 'call' && /err40[13]$/.test(x.callee || ''))))) return true;
  if (/^Yesod(?:\.Core)?\.(?:permissionDenied|notAuthenticated)$/.test(name)) return true;
  return false;
}

// Scotty's `status` only sets the response code: the handler keeps running unless something halts it.
const SCOTTY_STATUS = /^Web\.Scotty(?:\.Trans)?\.status$/;
const SCOTTY_HALT = /^Web\.Scotty(?:\.Trans)?\.(?:finish|raise|raiseStatus|redirect)$/;
/**
 * Source lines of every Scotty halting point in one function IR. `finish` is usually a bare operand (`status status401 >> finish`,
 * `when bad finish`), which the IR records as an identifier rather than a call, and an identifier has no line of its own: it inherits the
 * enclosing node's line. So both calls and identifiers are collected, by line.
 */
function haltLinesOf(fn) {
  const lines = [];
  for (const n of Object.values(fn.cfg.nodes)) for (const root of exprsOfNode(n)) for (const e of walkIr(root)) {
    const nm = e.kind === 'call' ? e.callee : e.kind === 'ident' ? e.name : null;
    if (nm && SCOTTY_HALT.test(nm)) lines.push(Number.isFinite(e.line) ? e.line : n.line);
  }
  return lines;
}

function guardSummary(ctx, fn, depth = 0, seen = new Set()) {
  if (!fn) return { auth: false, kinds: [], role: false, owner: false, csrf: false };
  if (ctx.guardMemo.has(fn.qid)) return ctx.guardMemo.get(fn.qid);
  if (seen.has(fn.qid) || depth > 3) return { auth: false, kinds: [], role: false, owner: false, csrf: false };
  seen.add(fn.qid);
  const kinds = new Set();
  let reads = false, rejects = false, statusRejects = [], role = false, owner = false, csrf = false, primitive = false;
  const credReads = credentialReadsOf(fn);
  for (const c of callsOf(fn)) {
    const k = credReads.get(c) || null;
    if (k) { kinds.add(k); reads = true; if (GUARD_PRIMITIVES.has(c.callee)) primitive = true; }
    if (isRejection(c)) { if (SCOTTY_STATUS.test(c.callee)) statusRejects.push(c.line); else rejects = true; }
    if (ROLE_CALL.test(c.callee || '')) role = true;
    if (OWNER_CALL.test(c.callee || '')) owner = true;
    if (CSRF_CALL.test(c.callee || '')) csrf = true;
    if (c.hs && c.hs.status === 'resolved' && c.hs.target && !c.hs.inlined) {
      const sub = guardSummary(ctx, ctx.fnByQid.get(c.hs.target), depth + 1, seen);
      if (sub.auth) { reads = true; rejects = true; sub.kinds.forEach((x) => kinds.add(x)); }
      if (sub.role) role = true; if (sub.owner) owner = true; if (sub.csrf) csrf = true;
    }
  }
  if (!rejects && nullaryRejectionsOf(fn).length) rejects = true;
  // A Scotty `status 40x` is a rejection only if the function also halts the handler (finish, raise, raiseStatus, redirect). Position is not
  // judged here: a bare `finish` operand carries its enclosing node's line (often the function head), so a line comparison would reject
  // the ordinary `Nothing -> status status401 >> finish`. The inline-guard path, which can order against the first sensitive call, does.
  if (!rejects && statusRejects.length && haltLinesOf(fn).length) rejects = true;
  // literal comparisons against an admin role count as a role check
  for (const n of Object.values(fn.cfg.nodes)) for (const e of exprsOfNode(n)) for (const x of walkIr(e)) {
    if (x.kind === 'binary' && (x.op === '==' || x.op === '===' || x.op === '!=')) {
      const sides = [x.left, x.right];
      if (sides.some((s) => s && s.kind === 'literal' && typeof s.value === 'string' && /^(?:admin|administrator|superuser|root)$/i.test(s.value))) role = true;
      if (sides.some((s) => s && s.kind === 'literal' && /^(?:Admin|SuperUser|Administrator)$/.test(String(s.value)) && s.hs && s.hs.con)) role = true;
    }
  }
  const out = { auth: primitive || (reads && rejects), kinds: [...kinds], role, owner, csrf };
  ctx.guardMemo.set(fn.qid, out);
  return out;
}

function exprsOfNode(n) { return [n.source, n.value, n.cond, ...(n.kind === 'call' ? [{ kind: 'call', callee: n.callee, args: n.args || [], hs: n.hs }] : [])].filter(Boolean); }
function kidsIr(e) {
  const out = [];
  for (const k of ['left', 'right', 'object', 'value']) if (e[k] && typeof e[k] === 'object') out.push(e[k]);
  for (const k of ['args', 'elements', 'branches', 'parts']) if (Array.isArray(e[k])) out.push(...e[k]);
  if (Array.isArray(e.props)) for (const p of e.props) if (p && p.value) out.push(p.value);
  return out;
}
function* walkIr(e, depth = 0) { if (!e || typeof e !== 'object' || depth > 80) return; yield e; for (const c of kidsIr(e)) yield* walkIr(c, depth + 1); }
const identsIr = (e) => { const out = new Set(); for (const x of walkIr(e)) { if (x.kind === 'ident' && x.name) out.add(x.name); if (x.kind === 'member' && x.object) { for (const y of walkIr(x.object)) if (y.kind === 'ident') out.add(y.name); } } return out; };

// ── handler summary ─────────────────────────────────────────────────────────
// Ordered call list (program order) + principal / id / ownership facts for one handler function IR.
function handlerFacts(ctx, fn, opts = {}) {
  const ordered = [];
  const nodes = Object.entries(fn.cfg.nodes).map(([id, n]) => ({ id, ...n })).sort((a, b) => Number(a.id.slice(1)) - Number(b.id.slice(1)));
  const assigns = [];
  const conds = [];
  for (const n of nodes) {
    if (n.kind === 'assign' && n.source) assigns.push(n);
    if (n.kind === 'if' && n.cond) conds.push(n.cond);
    for (const root of exprsOfNode(n)) for (const e of walkIr(root)) {
      if (e.kind === 'call' && typeof e.callee === 'string') ordered.push({ call: e, line: e.line || n.line, node: n });
      if (e.kind === 'union' && e.hs && e.hs.branchConds) for (const bc of e.hs.branchConds) conds.push(bc.cond);
    }
  }
  // Program order is SOURCE order. A wrapper guard (`guarded $ do ...`) encloses the statements it protects, but the lowering emits
  // those statements as earlier control-flow nodes than the call that contains them, so node order would make the guard look late.
  ordered.sort((a, b) => (Number.isFinite(a.line) && Number.isFinite(b.line) ? a.line - b.line : 0));
  const isGuardCall = (c) => {
    if (GUARD_PRIMITIVES.has(c.callee)) return true;
    if (c.hs && c.hs.status === 'resolved' && c.hs.target) return guardSummary(ctx, ctx.fnByQid.get(c.hs.target)).auth;
    return false;
  };
  const isSensitive = (c) => {
    if (SENSITIVE_PREFIX.some((p) => c.callee.startsWith(p))) return true;
    const bare = c.callee.split('.').pop();
    if (PERSIST_FNS.has(bare) && !/^(?:Prelude|Data|Web)\./.test(c.callee)) return true;
    if (c.hs && c.hs.status === 'resolved' && c.hs.target) {
      const sub = ctx.fnByQid.get(c.hs.target);
      if (sub && callsOf(sub).some((x) => SENSITIVE_PREFIX.some((p) => (x.callee || '').startsWith(p)))) return true;
    }
    return false;
  };
  const guardIdx = ordered.findIndex((o) => isGuardCall(o.call));
  const sensIdx = ordered.findIndex((o) => isSensitive(o.call));
  // An INLINE guard: the handler itself reads a credential and, before any sensitive operation, rejects. Scotty's `status` only sets the
  // code and the handler keeps running, so there a halting call (`finish`, `raise`, ...) must follow, still before the sensitive step;
  // a WAI response, a Servant throwError or a Yesod permissionDenied ends the handler by itself.
  // `finish` is usually a bare operand (`status status401 >> finish`, `when bad finish`), which the IR records as an identifier
  // rather than a call, so halting points are collected from both, by source line.
  const haltLines = haltLinesOf(fn);
  const sensLine = sensIdx >= 0 ? ordered[sensIdx].line : Infinity;
  const haltsAfter = (line) => haltLines.some((h) => Number.isFinite(h) && h >= line && h < sensLine);
  // The complete call list (not the node walk, which does not descend into case alternatives), ordered by source line.
  const allCalls = [...callsOf(fn), ...nullaryRejectionsOf(fn)].filter((c) => typeof c.callee === 'string' && Number.isFinite(c.line)).sort((x, y) => x.line - y.line);
  const credReads = credentialReadsOf(fn);
  // Credential reads in source order: calls that read one, and handler parameters bound to a credential header (Servant `Header "Authorization"`),
  // whose "read" is their first use in the body.
  const reads = [];
  for (const c of allCalls) if (credReads.has(c)) reads.push({ line: c.line, kind: credReads.get(c), callee: c.callee, call: c });
  for (const cp of opts.credentialParams || []) {
    let first = null;
    for (const n of nodes) for (const root of exprsOfNode(n)) for (const e of walkIr(root)) if (e.kind === 'ident' && e.name === cp.name && Number.isFinite(n.line) && (first === null || n.line < first)) first = n.line;
    if (first !== null) reads.push({ line: first, kind: cp.kind, callee: `param:${cp.name}`, call: null });
  }
  reads.sort((x, y) => x.line - y.line);
  let inlineIdx = -1, inlineKind = null, inlineLine = null, inlineCallee = null;
  for (let i = 0; i < reads.length && inlineIdx < 0; i++) {
    const rd = reads[i];
    if (!(rd.line <= sensLine)) break;
    // (a) a rejection at or after the read and before the first sensitive operation, by line. Scotty's `status` only sets the code, so there a
    // halting call must follow too.
    for (let j = 0; j < allCalls.length && allCalls[j].line < sensLine; j++) {
      const r = allCalls[j];
      if (r === rd.call || r.line < rd.line || !isRejection(r) || !stopsHandler(r, allCalls)) continue;
      if (SCOTTY_STATUS.test(r.callee) && !haltsAfter(rd.line)) continue;   // an identifier carries its enclosing node's line, so position is judged from the credential read
      inlineIdx = j; inlineKind = rd.kind; inlineLine = r.line; inlineCallee = rd.callee; break;
    }
    if (inlineIdx >= 0) break;
    // (b) a rejection that ends the handler by itself (WAI response handed back, throwError, permissionDenied, raiseStatus). A call in tail position
    // (the last statement, a case alternative) reports the enclosing line, not its own, so its line cannot be ordered against the sensitive
    // operation; the ordering that CAN be trusted is the credential read against the first sensitive operation, tested above.
    const hard = allCalls.findIndex((r) => r !== rd.call && isRejection(r) && !SCOTTY_STATUS.test(r.callee) && stopsHandler(r, allCalls));
    if (hard >= 0) { inlineIdx = hard; inlineKind = rd.kind; inlineLine = allCalls[hard].line; inlineCallee = rd.callee; break; }
  }
  const principals = new Set();
  for (const a of assigns) if (a.source.kind === 'call' && isGuardCall(a.source)) principals.add(a.target);
  // ids read from the request
  const idVars = new Set();
  for (const a of assigns) {
    const s = a.source;
    if (s.kind === 'call' && /^Web\.Scotty(?:\.Trans)?\.(?:param|captureParam|queryParam|pathParam)$/.test(s.callee)) {
      const nm = headerArg(s);
      if (nm && /id$/i.test(nm)) idVars.add(a.target);
    }
  }
  return { ordered, guardIdx, inlineIdx, inlineKind, inlineLine, inlineCallee, sensIdx, principals, idVars, conds, assigns, isGuardCall, isSensitive, fn };
}

function hasOwnership(ctx, facts) {
  const { principals, idVars } = facts;
  const mentionsPrincipal = (e) => { for (const n of identsIr(e)) if (principals.has(n)) return true; return false; };
  // 1. a comparison involving the principal
  for (const c of facts.conds) for (const x of walkIr(c)) {
    if (x.kind === 'binary' && ['==', '===', '!='].includes(x.op) && (mentionsPrincipal(x.left) || mentionsPrincipal(x.right))) return { kind: 'principal-comparison' };
    if (x.kind === 'call' && /(?:^|\.)(?:elem|notElem)$/.test(x.callee || '') && (x.args || []).some(mentionsPrincipal)) return { kind: 'principal-membership' };
  }
  for (const o of facts.ordered) {
    if (OWNER_CALL.test(o.call.callee || '')) return { kind: 'owner-check-call' };
    // 2. a lookup scoped by BOTH the id and the principal
    if (facts.isSensitive(o.call) && (o.call.args || []).some(mentionsPrincipal) && (o.call.args || []).some((a) => [...identsIr(a)].some((n) => idVars.has(n)))) return { kind: 'principal-scoped-query' };
  }
  // 3. a project function receiving both
  for (const o of facts.ordered) if (o.call.hs && o.call.hs.status === 'resolved' && (o.call.args || []).some(mentionsPrincipal) && (o.call.args || []).some((a) => [...identsIr(a)].some((n) => idVars.has(n)))) return { kind: 'principal-scoped-helper', callee: o.call.callee };
  return null;
}

// ── route record ─────────────────────────────────────────────────────────────
function newRoute(r) { return { auth: { status: 'unknown', kind: null, evidence: [] }, role: { status: 'none', evidence: [] }, params: [], uploads: false, limits: [], ...r }; }

function analyzeRoute(ctx, route, handlerFn, opts) {
  const R = route;
  if (!handlerFn) { R.handler = R.handler || { kind: 'unknown' }; R.auth = { status: 'unknown', kind: null, evidence: [], reason: 'handler not resolved' }; return; }
  const facts = handlerFacts(ctx, handlerFn, opts);
  for (const v of opts.principalVars || []) facts.principals.add(v);
  for (const v of opts.idVars || []) facts.idVars.add(v);
  const gs = guardSummary(ctx, handlerFn);
  R.facts = facts;
  R.credentialKinds = new Set(gs.kinds);
  // global (middleware / isAuthorized / type) protection first
  if (opts.globalAuth) { R.auth = { status: 'authenticated', kind: opts.globalAuth.kind, evidence: [{ ...opts.globalAuth, credential: opts.globalAuth.kind, kind: 'global-guard' }] }; R.credentialKinds.add(opts.globalAuth.kind); }
  else if (opts.typeAuth) { R.auth = { status: 'authenticated', kind: opts.typeAuth.kind, evidence: [{ ...opts.typeAuth, credential: opts.typeAuth.kind, kind: 'type-combinator' }] }; R.credentialKinds.add(opts.typeAuth.kind); }
  else if (facts.guardIdx >= 0) {
    if (facts.sensIdx >= 0 && facts.guardIdx > facts.sensIdx) {
      R.auth = { status: 'late', kind: null, evidence: [{ kind: 'late-guard', callee: facts.ordered[facts.guardIdx].call.callee, line: facts.ordered[facts.guardIdx].line }] };
    } else {
      const g = facts.ordered[facts.guardIdx].call;
      const sub = g.hs && g.hs.target ? guardSummary(ctx, ctx.fnByQid.get(g.hs.target)) : { kinds: g.callee.includes('requireAuth') ? ['session'] : [] };
      R.auth = { status: 'authenticated', kind: (sub.kinds && sub.kinds[0]) || null, evidence: [{ kind: 'handler-guard', callee: g.callee, line: facts.ordered[facts.guardIdx].line }] };
      (sub.kinds || []).forEach((k) => R.credentialKinds.add(k));
    }
  } else if (facts.inlineIdx >= 0) {
    R.auth = { status: 'authenticated', kind: facts.inlineKind, evidence: [{ kind: 'inline-guard', callee: facts.inlineCallee, line: facts.inlineLine }] };
  } else R.auth = { status: 'none', kind: null, evidence: [] };
  // role
  const roleCall = facts.ordered.find((o) => ROLE_CALL.test(o.call.callee || ''));
  const anyRole = gs.role || !!roleCall || (opts.globalRole === true) || (opts.typeRole === true);
  if (anyRole) R.role = { status: 'present', evidence: [{ kind: roleCall ? 'role-call' : 'role-guard' }] };
  // uploads
  R.uploads = facts.ordered.some((o) => /\.files$/.test(o.call.callee) || /fileUpload|FileInfo|Multipart/i.test(o.call.callee));
  // csrf evidence
  R.csrf = gs.csrf || facts.ordered.some((o) => CSRF_CALL.test(o.call.callee || ''));
  R.sensitive = facts.sensIdx >= 0;
  // ownership / BOLA inputs
  R.ownership = hasOwnership(ctx, facts);
  R.idLookups = facts.ordered.filter((o) => facts.isSensitive(o.call) && (o.call.args || []).some((a) => [...identsIr(a)].some((n) => facts.idVars.has(n))));
}

// ── Scotty ─────────────────────────────────────────────────────────────────
function scottyRoutes(ctx, add) {
  const globalMw = [];
  for (const mod of ctx.modules) {
    if (!/\.hs$/i.test(mod.file)) continue;
    for (const fun of mod.groups.funs) {
      for (const clause of fun.clauses) {
        const visit = (node, inLoop) => {
          for (const n of walkAst(node)) {
            if (n.t !== 'app' && n.t !== 'op' && n.t !== 'var') continue;
            const sp = spine(n);
            if (!sp || !sp.head) continue;
            const q = ctx.qualify(mod, sp.head);
            if (!q || !/^Web\.Scotty(?:\.Trans)?\./.test(q.name)) continue;
            const fn = q.name.split('.').pop();
            if (fn === 'middleware' && sp.args[0]) { globalMw.push({ mod, expr: sp.args[0], file: mod.file, line: sp.head.line || fun.line }); continue; }
            if (!(fn in SCOTTY_METHODS)) continue;
            if (sp.args.length < 2) continue;
            const path = strLit(sp.args[0]);
            const handlerAst = sp.args[sp.args.length - 1];
            add({ framework: 'scotty', method: SCOTTY_METHODS[fn], path: path ?? '<dynamic>', dynamicPath: path === null, file: mod.file, line: sp.head.line || fun.line, mod, handlerAst, inLoop, owner: `${mod.name}.${fun.name}` });
          }
        };
        visit(clause.rhs.body, false);
        // routes registered inside a traversal are dynamic registration
        for (const n of walkAst(clause.rhs.body)) {
          const sp = n.t === 'app' || n.t === 'op' ? spine(n) : null;
          if (sp && sp.head && /^(?:forM_|mapM_|forM|mapM|traverse_|for_|forever)$/.test(sp.head.name)) {
            for (const arg of sp.args) for (const inner of walkAst(arg)) {
              const isp = inner.t === 'app' || inner.t === 'op' ? spine(inner) : null;
              if (isp && isp.head) { const q = ctx.qualify(mod, isp.head); if (q && /^Web\.Scotty(?:\.Trans)?\.(?:get|post|put|delete|patch)$/.test(q.name)) ctx.gaps.push({ kind: 'dynamic-route-registration', detail: `Scotty ${q.name.split('.').pop()} registered inside ${sp.head.name}: the route set is computed at runtime`, file: mod.file, line: isp.head.line || fun.line }); }
            }
          }
        }
      }
    }
  }
  return globalMw;
}

// A middleware expression is an auth guard if it is `basicAuth ..` or a project function summarised as one.
function middlewareGuard(ctx, mod, expr) {
  const sp = spine(expr);
  if (!sp || !sp.head) return { opaque: true };
  const q = ctx.qualify(mod, sp.head);
  if (q && GUARD_PRIMITIVES.has(q.name)) return { kind: 'basic', via: q.name };
  if (q && q.qid) {
    const fn = ctx.fnFor(q);
    const gs = guardSummary(ctx, fn);
    if (gs.auth) return { kind: gs.kinds[0] || 'token', via: q.name, role: gs.role, csrf: gs.csrf };
    return { notGuard: true, via: q.name };
  }
  return { opaque: true };
}

// ── WAI ────────────────────────────────────────────────────────────────────
function waiRoutes(ctx, add) {
  for (const mod of ctx.modules) {
    for (const fun of mod.groups.funs) {
      for (const clause of fun.clauses) {
        for (const n of walkAst(clause.rhs.body)) {
          if (n.t !== 'case') continue;
          const scrutText = JSON.stringify(n.scrut);
          if (!/pathInfo|rawPathInfo|requestMethod/.test(scrutText)) continue;
          const hasMethod = /requestMethod/.test(scrutText);
          const hasPath = /pathInfo|rawPathInfo/.test(scrutText);
          const isTuple = unparen(n.scrut) && unparen(n.scrut).t === 'tuple';
          for (const alt of n.alts || []) {
            const pat = alt.pat;
            let method = 'ANY', segs = null;
            const patList = isTuple && pat.t === 'ptuple' ? pat.items : [pat];
            const mPat = hasMethod ? patList[0] : null;
            const pPat = hasPath ? (isTuple ? patList[hasMethod ? 1 : 0] : patList[0]) : null;
            if (mPat && mPat.t === 'plit') method = String(mPat.v).toUpperCase();
            else if (mPat && mPat.t === 'pwild') method = 'ANY';
            if (pPat && pPat.t === 'plist') segs = pPat.items.map((p) => (p.t === 'plit' ? String(p.v) : ':param'));
            else if (pPat && pPat.t === 'pwild') segs = null;
            if (!segs && !(mPat && mPat.t === 'plit')) continue;   // a pure fallback alternative is not a route
            add({ framework: 'wai', method, path: segs ? `/${segs.join('/')}` : '<any>', file: mod.file, line: alt.line || fun.line, mod, handlerAst: alt.rhs.body, owner: `${mod.name}.${fun.name}`, routerFn: `${mod.name}.${fun.name}` });
          }
        }
      }
    }
  }
}

// ── Servant ─────────────────────────────────────────────────────────────────
function servantTypeRoutes(ctx) {
  const out = [];
  for (const mod of ctx.modules) {
    const T = mod.parse.tokens;
    for (const td of mod.parse.typeDecls || []) {
      const slice = T.slice(td.a, td.b);
      const hasArrow = slice.some((t) => t.t === 'op' && t.v === ':>');
      const hasVerb = slice.some((t) => t.t === 'con' && /^(?:Get|Post|Put|Delete|Patch)(?:NoContent)?$/.test(t.v));
      if (!hasArrow || !hasVerb) continue;
      const eq = slice.findIndex((t) => t.t === 'rop' && t.v === '=');
      if (eq < 0) continue;
      const body = slice.slice(eq + 1);
      for (const alt of expandServant(body)) out.push({ mod, apiName: td.name, line: td.line, ...alt });
    }
  }
  return out;
}

function splitTop(tokens, sep) {
  const parts = [[]]; let depth = 0;
  for (const t of tokens) {
    if (t.t === 'sp' && (t.v === '(' || t.v === '[')) depth++;
    if (t.t === 'sp' && (t.v === ')' || t.v === ']')) depth--;
    if (depth === 0 && t.t === 'op' && t.v === sep) { parts.push([]); continue; }
    parts[parts.length - 1].push(t);
  }
  return parts;
}

function expandServant(tokens) {
  const alts = splitTop(tokens, ':<|>').filter((p) => p.length);
  const out = [];
  for (const alt of alts) {
    const chain = splitTop(alt, ':>').filter((p) => p.length);
    out.push(...expandChain(chain, { path: [], auth: null, params: [], captures: [], role: false, order: [] }));
  }
  return out;
}

function expandChain(chain, acc) {
  if (!chain.length) return [];
  const [head, ...rest] = chain;
  const a = { path: [...acc.path], auth: acc.auth, params: [...acc.params], captures: [...acc.captures], role: acc.role, order: [...(acc.order || [])] };
  const first = head[0];
  if (head.length === 1 && first.t === 'str') { a.path.push(first.v); return rest.length ? expandChain(rest, a) : [finishServant(a, head)]; }
  // a parenthesised group of alternatives at the tail distributes the prefix over each alternative
  if (head.length >= 2 && head[0].t === 'sp' && head[0].v === '(' && !rest.length) {
    const inner = head.slice(1, -1);
    return splitTop(inner, ':<|>').filter((p) => p.length).flatMap((alt) => expandChain(splitTop(alt, ':>').filter((p) => p.length), a));
  }
  const name = first.t === 'con' ? first.v : null;
  if (name === 'Capture' || name === 'Capture\'') { const nm = head.find((t) => t.t === 'str'); a.path.push(`:${nm ? nm.v : 'param'}`); a.captures.push(nm ? nm.v : 'param'); a.order.push(`capture:${nm ? nm.v : 'param'}`); }
  else if (name === 'QueryParam' || name === 'QueryParam\'' || name === 'QueryParams') { const nm = head.find((t) => t.t === 'str'); a.params.push(nm ? nm.v : '?'); a.order.push(`query:${nm ? nm.v : '?'}`); }
  else if (name === 'Header' || name === 'Header\'') { const nm = head.find((t) => t.t === 'str'); a.order.push(`header:${nm ? nm.v : '?'}`); }
  else if (name === 'ReqBody') a.order.push('body');
  else if (name === 'BasicAuth') { a.auth = { kind: 'basic', tag: 'BasicAuth' }; a.order.push('auth'); }
  else if (name === 'AuthProtect') { const nm = head.find((t) => t.t === 'str'); a.auth = { kind: 'token', tag: nm ? nm.v : 'AuthProtect' }; a.order.push('auth'); if (nm && /admin|role|perm/i.test(nm.v)) a.role = true; }
  else if (name === 'Auth') { a.auth = { kind: 'token', tag: 'Auth' }; a.order.push('auth'); }
  else if (name && /^(?:Get|Post|Put|Delete|Patch)(?:NoContent)?$/.test(name)) return [finishServant(a, head)];
  return rest.length ? expandChain(rest, a) : [finishServant(a, head)];
}

function finishServant(a, head) {
  const verb = head.find((t) => t.t === 'con' && /^(?:Get|Post|Put|Delete|Patch)(?:NoContent)?$/.test(t.v));
  return { method: verb ? verb.v.replace(/NoContent$/, '').toUpperCase() : 'ANY', path: `/${a.path.join('/')}`, auth: a.auth, params: a.params, captures: a.captures, role: a.role, order: a.order };
}

function servantHandlers(ctx, mod, apiName) {
  // `server :: Server API` ... `server = h1 :<|> h2` (flattened left to right)
  const sigFor = (name) => (mod.sigs.get(name) || {}).text || '';
  for (const fun of mod.groups.funs) {
    const text = sigFor(fun.name);
    if (!new RegExp(`\\b${apiName}\\b`).test(text) && !/\bServer\b|\bServerT\b/.test(text)) continue;
    const body = fun.clauses[0] && fun.clauses[0].rhs.body;
    const flat = [];
    const go = (e) => { e = unparen(e); if (e && e.t === 'op' && e.op === ':<|>') { go(e.l); go(e.r); } else flat.push(e); };
    if (body) go(body);
    if (flat.length > 0) return { fnName: fun.name, handlers: flat, fun };
  }
  return null;
}

// ── Yesod ──────────────────────────────────────────────────────────────────
function yesodRoutes(ctx) {
  const out = [];
  for (const mod of ctx.modules) {
    const text = ctx.files[mod.file];
    if (typeof text !== 'string') continue;
    const re = /\[parseRoutes\|([\s\S]*?)\|\]/g;
    let m;
    while ((m = re.exec(text))) {
      const base = text.slice(0, m.index).split('\n').length;
      const lines = m[1].split('\n');
      lines.forEach((raw, i) => {
        const line = raw.trim();
        if (!line || line.startsWith('--')) return;
        const parts = line.split(/\s+/);
        if (!parts[0].startsWith('/') || parts.length < 2) return;
        const res = parts[1];
        const methods = parts.slice(2).filter((x) => /^[A-Z]+$/.test(x));
        out.push({ mod, path: parts[0].replace(/#\w+/g, ':param'), resource: res, methods, line: base + i + 1 });
      });
    }
  }
  return out;
}

function yesodAuthorization(ctx) {
  // isAuthorized clauses by route constructor; a catch-all clause is the default
  const byRoute = new Map(); let fallback = null;
  for (const mod of ctx.modules) for (const inst of mod.parse.instances || []) {
    if (inst.name !== 'Yesod') continue;
    const funs = (inst.decls ? Object.values(groupLike(inst.decls)) : []);
    void funs;
  }
  return { byRoute, fallback };
}
function groupLike(decls) { const m = {}; for (const d of decls) if (d.t === 'clause') (m[d.name] ||= []).push(d); return m; }

// ── main ───────────────────────────────────────────────────────────────────
/**
 * @param {Record<string,string>} files path -> source
 * @param {{packageVersions?: Record<string,string>}} [opts]
 */
export function analyzeHaskellWeb(files, opts = {}) {
  const hs = {};
  for (const [f, t] of Object.entries(files || {})) if (/\.hs$/i.test(f) && typeof t === 'string') hs[f] = t;
  const result = { routes: [], findings: [], middleware: [], frameworks: [], coverage: {}, gaps: [], modelVersion: HS_WEB_MODEL_VERSION, rulesetVersion: HS_WEB_RULES_VERSION, versionStatus: {} };
  if (!Object.keys(hs).length) return result;
  const ctx = new Ctx(hs);
  const pending = [];
  const add = (r) => pending.push(r);

  // frameworks present (by import)
  const fw = new Set();
  for (const mod of ctx.modules) for (const imp of mod.imports) for (const [name, def] of Object.entries(HS_WEB_FRAMEWORKS)) if (def.modules.some((m) => imp.module === m || imp.module.startsWith(`${m}.`))) fw.add(name);
  result.frameworks = [...fw].sort();
  for (const name of fw) {
    const v = opts.packageVersions && opts.packageVersions[HS_WEB_FRAMEWORKS[name].package];
    result.versionStatus[name] = { package: HS_WEB_FRAMEWORKS[name].package, version: v || null, status: v ? (HS_WEB_FRAMEWORKS[name].tested.some((t) => v === t || v.startsWith(`${t}.`)) ? 'tested' : 'untested-version') : 'unknown-version', tested: HS_WEB_FRAMEWORKS[name].tested };
  }

  // 1. Scotty
  const scottyMw = fw.has('scotty') ? scottyRoutes(ctx, add) : [];
  let scottyGlobal = null;
  for (const mw of scottyMw) {
    const g = middlewareGuard(ctx, mw.mod, mw.expr);
    result.middleware.push({ framework: 'scotty', file: mw.file, line: mw.line, status: g.kind ? 'auth-guard' : (g.opaque ? 'opaque' : 'not-an-auth-guard'), via: g.via || null });
    if (g.kind && !scottyGlobal) scottyGlobal = { kind: g.kind, via: g.via, role: g.role, file: mw.file, line: mw.line };
    if (g.opaque) ctx.gaps.push({ kind: 'opaque-middleware', detail: 'a Scotty middleware could not be resolved to a project function, so it earns no protection credit', file: mw.file, line: mw.line });
  }
  // 2. WAI
  if (fw.has('wai')) waiRoutes(ctx, add);
  // WAI global middleware: `run port (authMw router)` protects exactly the routers named inside that expression
  const waiGlobals = [];
  if (fw.has('wai')) {
    for (const mod of ctx.modules) for (const fun of mod.groups.funs) for (const n of walkAst(fun.clauses[0] && fun.clauses[0].rhs.body)) {
      const sp = n.t === 'app' || n.t === 'op' ? spine(n) : null;
      if (!sp || !sp.head) continue;
      const q = ctx.qualify(mod, sp.head);
      if (!(q && /^Network\.Wai\.Handler\.Warp\.(?:run|runSettings)$/.test(q.name) && sp.args.length)) continue;
      const appArg = sp.args[sp.args.length - 1];
      const asp = spine(appArg);
      const routers = new Set();
      for (const x of walkAst(appArg)) if (x.t === 'var') routers.add(x.name);
      if (asp && asp.head && asp.args.length) {
        const g = middlewareGuard(ctx, mod, { t: 'var', name: asp.head.name, qual: asp.head.qual });
        result.middleware.push({ framework: 'wai', file: mod.file, line: asp.head.line || fun.line, status: g.kind ? 'auth-guard' : (g.opaque ? 'opaque' : 'not-an-auth-guard'), via: g.via || null });
        if (g.kind) waiGlobals.push({ kind: g.kind, via: g.via, role: g.role, file: mod.file, routers });
        else if (g.opaque) ctx.gaps.push({ kind: 'opaque-middleware', detail: `the WAI middleware ${asp.head.name} could not be resolved to a project function, so it earns no protection credit`, file: mod.file, line: asp.head.line || fun.line });
      } else {
        result.middleware.push({ framework: 'wai', file: mod.file, line: sp.head.line || fun.line, status: 'none-installed', via: null });
      }
    }
  }

  // 3. Servant (type-level)
  const servantEndpoints = fw.has('servant') ? servantTypeRoutes(ctx) : [];
  const servantByMod = new Map();
  servantEndpoints.forEach((e, i) => { if (!servantByMod.has(e.mod)) servantByMod.set(e.mod, []); servantByMod.get(e.mod).push({ ...e, idx: i }); });
  for (const [mod, list] of servantByMod) {
    const apiName = list[0].apiName;
    const h = servantHandlers(ctx, mod, apiName);
    list.forEach((e, i) => {
      const hAst = h && h.handlers.length === list.length ? h.handlers[i] : null;
      if (h && h.handlers.length !== list.length) ctx.gaps.push({ kind: 'servant-handler-arity', detail: `${apiName} has ${list.length} endpoints but ${h.fnName} lists ${h.handlers.length} handlers; handlers are not paired`, file: mod.file, line: e.line });
      add({ framework: 'servant', method: e.method, path: e.path, file: mod.file, line: e.line, mod, handlerAst: hAst, servant: e, owner: apiName, whereDecls: h && h.fun && h.fun.clauses[0] && h.fun.clauses[0].rhs.where });
    });
  }

  // 4. Yesod
  const yroutes = fw.has('yesod') ? yesodRoutes(ctx) : [];
  let yesodAuthz = null;
  if (fw.has('yesod')) yesodAuthz = collectYesodAuthz(ctx);
  for (const yr of yroutes) {
    const methods = yr.methods.length ? yr.methods : ['ANY'];
    for (const method of methods) {
      const hname = method === 'ANY' ? `handle${yr.resource}` : `${method.toLowerCase()}${yr.resource}`;
      add({ framework: 'yesod', method, path: yr.path, file: yr.mod.file, line: yr.line, mod: yr.mod, handlerName: hname, resource: yr.resource, owner: yr.resource });
    }
  }

  // ── resolve handlers and analyse ─────────────────────────────────────────
  for (const p of pending) {
    const R = newRoute({ framework: p.framework, method: p.method, path: p.path, file: p.file, line: p.line, owner: p.owner });
    if (p.dynamicPath) { R.auth = { status: 'unknown', kind: null, evidence: [], reason: 'route path is not a literal' }; ctx.gaps.push({ kind: 'dynamic-route-path', detail: `${p.framework} route path is computed at runtime`, file: p.file, line: p.line }); R.handler = { kind: 'unknown' }; result.routes.push(R); continue; }
    let handlerFn = null; let handlerName = null; let paramNames = [];
    const paramsOf = (clause) => ((clause && clause.pats) || []).map((x) => (x && x.t === 'pvar' ? x.name : null));
    const topFun = (mod, name) => mod.groups.funs.find((f) => f.name === name);
    if (p.handlerName) {
      const def = p.mod.defs.get(p.handlerName) || [...ctx.modules].map((m) => m.defs.get(p.handlerName)).find(Boolean);
      handlerName = p.handlerName;
      if (def) {
        handlerFn = ctx.fnByQid.get(def.qid) || null;
        const f = topFun(p.mod, p.handlerName);
        if (f && f.clauses[0]) paramNames = paramsOf(f.clauses[0]);
      }
    } else if (p.handlerAst) {
      const sp = spine(p.handlerAst);
      if (p.handlerAst.t === 'var' || (sp && sp.head && sp.args.length === 0)) {
        const head = sp ? sp.head : p.handlerAst;
        // a handler bound in the enclosing `where` (Servant servers usually are)
        const local = (p.whereDecls || []).find((d) => d.name === head.name && !head.qual);
        if (local && local.clause && local.clause.rhs && local.clause.rhs.body && !(local.clause.rhs.guards && local.clause.rhs.guards.length)) {
          try { handlerFn = lowerHandlerExpr(ctx.project, p.mod, local.clause.rhs.body, `${p.framework}-${head.name}`, local.line || p.line); handlerName = head.name; paramNames = paramsOf(local.clause); } catch { handlerFn = null; }
        } else {
          const q = ctx.qualify(p.mod, head);
          if (q && q.qid) { handlerFn = ctx.fnFor(q); handlerName = q.name; const f = topFun(p.mod, head.name); if (f && f.clauses[0]) paramNames = paramsOf(f.clauses[0]); }
          else if (q) handlerName = q.name;
        }
      } else {
        try { handlerFn = lowerHandlerExpr(ctx.project, p.mod, p.handlerAst, `${p.framework}-${p.line}`, p.line); handlerName = '<inline>'; } catch { handlerFn = null; }
      }
    }
    R.handler = handlerFn ? { kind: handlerName === '<inline>' ? 'inline' : 'named', name: handlerName } : { kind: 'unknown', name: handlerName };
    const o = {};
    // WAI: a middleware protects only the routers named in the `run` expression that installs it
    if (p.framework === 'scotty' && scottyGlobal) { o.globalAuth = scottyGlobal; if (scottyGlobal.role) o.globalRole = true; }
    if (p.framework === 'wai') {
      const g = waiGlobals.find((w) => w.file === p.file && w.routers.has((p.routerFn || '').split('.').pop()));
      if (g) { o.globalAuth = g; if (g.role) o.globalRole = true; }
    }
    if (p.framework === 'servant' && p.servant.auth) {
      o.typeAuth = p.servant.auth; if (p.servant.role) o.typeRole = true;
      o.principalVars = []; o.idVars = [];
      (p.servant.order || []).forEach((kind, i) => {
        const nm = paramNames[i]; if (!nm) return;
        if (kind === 'auth') o.principalVars.push(nm);
        else if (/^header:/.test(kind) && CREDENTIAL_HEADER.test(kind.slice(7))) (o.credentialParams ||= []).push({ name: nm, kind: /cookie/i.test(kind) ? 'cookie' : 'token' });
        else if (/^(?:capture|query):.*id$/i.test(kind)) o.idVars.push(nm);
      });
    } else if (p.framework === 'servant') {
      o.idVars = [];
      (p.servant.order || []).forEach((kind, i) => {
        const nm = paramNames[i]; if (!nm) return;
        if (/^(?:capture|query):.*id$/i.test(kind)) o.idVars.push(nm);
        else if (/^header:/.test(kind) && CREDENTIAL_HEADER.test(kind.slice(7))) (o.credentialParams ||= []).push({ name: nm, kind: /cookie/i.test(kind) ? 'cookie' : 'token' });
      });
    }
    if (p.framework === 'yesod') {
      o.idVars = paramNames.filter(Boolean);
      if (yesodAuthz) {
        const z = yesodAuthz.forRoute(p.resource);
        if (z && z.status === 'authenticated') o.globalAuth = { kind: 'session', via: 'isAuthorized', file: z.file, line: z.line };
        if (z && z.role) o.globalRole = true;
      }
    }
    analyzeRoute(ctx, R, handlerFn, o);
    if (p.framework === 'servant') { R.params = [...p.servant.captures, ...p.servant.params]; R.servant = { captures: p.servant.captures }; }
    if (p.framework === 'yesod') R.yesodExplicitPublic = !!(yesodAuthz && yesodAuthz.forRoute(p.resource) && yesodAuthz.forRoute(p.resource).status === 'public');
    result.routes.push(R);
  }

  result.yesod = yesodAuthz ? yesodAuthz.summary : null;
  emitFindings(ctx, result, yesodAuthz);

  // coverage reconciliation: every route is either analysed or unknown
  const analysed = result.routes.filter((r) => r.handler && r.handler.kind !== 'unknown').length;
  result.coverage = { routes: result.routes.length, analysed, unknown: result.routes.length - analysed, gaps: ctx.gaps.length };
  result.gaps = ctx.gaps;
  for (const r of result.routes) { delete r.facts; if (r.credentialKinds) r.credentialKinds = [...r.credentialKinds]; }
  return result;
}

function collectYesodAuthz(ctx) {
  const rules = new Map();
  let fallback = null;
  let yesodMiddlewareOverride = null;
  const summary = { isAuthorized: false, defaultStatus: null, middlewareOverride: null };
  for (const mod of ctx.modules) for (const inst of mod.parse.instances || []) {
    if (inst.name !== 'Yesod') continue;
    summary.isAuthorized = true;
    const clauses = (inst.decls || []).filter((d) => d.t === 'clause' && d.name === 'isAuthorized');
    for (const dcl of clauses) {
      const c = dcl.clause || dcl;
      const first = c.pats && c.pats[0];
      const body = c.rhs && c.rhs.body;
      const text = JSON.stringify(body || {});
      let status = 'unknown';
      let role = false;
      const sp = body ? (() => { const bodyIsDo = body.t === 'do'; return bodyIsDo; })() : false;
      void sp;
      const names = [];
      for (const n of walkAst(body)) if (n.t === 'var') names.push(n.name);
      if (names.some((n) => /^(?:requireAuthId|requireAuth|maybeAuthId|maybeAuth)$/.test(n)) || names.some((n) => { const q = ctx.qualify(mod, { name: n, qual: null }); return q && q.qid && guardSummary(ctx, ctx.fnFor(q)).auth; })) status = 'authenticated';
      else if (/"Authorized"/.test(text) || names.includes('Authorized')) status = 'public';
      if (names.some((n) => ROLE_CALL.test(n))) role = true;
      const rec = { status, role, file: mod.file, line: dcl.line || c.line };
      if (first && first.t === 'pcon') rules.set(first.con.replace(/^.*\./, ''), rec);
      else fallback = rec;
    }
    for (const d of inst.decls || []) if (d.t === 'clause' && d.name === 'yesodMiddleware') {
      const t = JSON.stringify((d.clause && d.clause.rhs && d.clause.rhs.body) || {});
      yesodMiddlewareOverride = { csrf: /csrf/i.test(t), file: mod.file, line: d.line };
    }
  }
  summary.defaultStatus = fallback ? fallback.status : null;
  summary.middlewareOverride = yesodMiddlewareOverride;
  return { forRoute: (resource) => rules.get(resource) || fallback, summary, middlewareOverride: yesodMiddlewareOverride, rules };
}

function emitFindings(ctx, result, yesodAuthz) {
  const out = result.findings;
  const emit = (rule, R, extra = {}) => {
    const r = WEB_RULES[rule];
    const text = ctx.files[R.file] || '';
    const line = extra.line || R.line;
    // A framework version the model was not written against still gets analysed, but says so.
    const vs = result.versionStatus[R.framework];
    const untested = vs && vs.status !== 'tested';
    if (untested) extra = { ...extra, confidence: (extra.confidence ?? 0.75) * 0.8, uncertainty: [...(extra.uncertainty || []), { kind: 'untested-model', detail: `${vs.package} ${vs.version || '(version unknown)'} is not in the tested set (${vs.tested.join(', ')}); the route model is applied best-effort` }] };
    const snip = (text.split('\n')[line - 1] || '').trim().slice(0, 240);
    out.push({
      id: `hs-web:${rule}:${R.file}:${line}:${R.method}:${R.path}`, severity: extra.severity || r.severity, file: R.file, line, vuln: r.vuln, cwe: r.cwe,
      description: `${r.vuln}: ${R.method} ${R.path} (${R.framework})${extra.detail ? ` - ${extra.detail}` : ''}`,
      remediation: r.remediation, parser: 'HS-WEB', family: r.family, language: 'haskell', capability: 'route-inventory', analysisKind: 'application', evidenceKind: 'source',
      originalLocation: { file: R.file, line, column: 0 }, snippet: snip, confidence: extra.confidence ?? 0.75, rule, ruleVersion: 1, rulesetVersion: HS_WEB_RULES_VERSION, modelVersion: HS_WEB_MODEL_VERSION,
      siteKey: `${R.method} ${R.path}`, route: { framework: R.framework, method: R.method, path: R.path, handler: R.handler }, ...(extra.evidence ? { evidence: extra.evidence } : {}),
      ...(extra.uncertainty ? { uncertainty: extra.uncertainty } : {}),
    });
  };
  for (const R of result.routes) {
    if (!R.handler || R.handler.kind === 'unknown') continue;
    const writes = WRITE_METHODS.has(R.method) || R.method === 'ANY';
    const privileged = ADMIN_PATH.test(R.path) || /admin/i.test(R.handler.name || '');
    if (R.auth.status === 'late') emit('hs-route-late-auth', R, { detail: `guard ${R.auth.evidence[0].callee} runs after the first sensitive operation`, evidence: R.auth.evidence });
    else if (R.auth.status === 'none' && (writes || privileged) && R.sensitive !== false) {
      if (!(R.framework === 'yesod' && R.yesodExplicitPublic && !writes)) emit('hs-route-missing-auth', R, { severity: writes ? 'high' : 'medium', detail: R.method === 'ANY' ? 'any method' : 'state-changing method' });
    }
    if ((R.auth.status === 'authenticated') && privileged && R.role.status !== 'present') emit('hs-route-bfla', R, { detail: 'authenticated but no role/permission check was found', evidence: { auth: R.auth.evidence } });
    if (R.auth.status === 'authenticated' && R.idLookups && R.idLookups.length && !R.ownership) {
      emit('hs-route-bola', R, { detail: 'the id from the request reaches a lookup with no ownership or tenant check', line: R.idLookups[0].line, evidence: { lookup: R.idLookups[0].call.callee } });
    }
    const cookie = R.credentialKinds && (R.credentialKinds.has('cookie') || R.credentialKinds.has('session'));
    if (writes && R.auth.status === 'authenticated' && cookie && !R.csrf && R.framework !== 'yesod') emit('hs-route-csrf', R, { detail: 'cookie/session credential with no CSRF token check' });
  }
  if (yesodAuthz && yesodAuthz.middlewareOverride && !yesodAuthz.middlewareOverride.csrf) {
    const o = yesodAuthz.middlewareOverride;
    out.push({
      id: `hs-web:hs-yesod-csrf-disabled:${o.file}:${o.line}`, severity: 'medium', file: o.file, line: o.line, vuln: WEB_RULES['hs-yesod-csrf-disabled'].vuln, cwe: 'CWE-352',
      description: 'yesodMiddleware is overridden and does not include a CSRF middleware', remediation: WEB_RULES['hs-yesod-csrf-disabled'].remediation, parser: 'HS-WEB', family: 'csrf', language: 'haskell',
      capability: 'route-inventory', analysisKind: 'application', evidenceKind: 'source', originalLocation: { file: o.file, line: o.line, column: 0 }, snippet: '', confidence: 0.7, rule: 'hs-yesod-csrf-disabled', ruleVersion: 1, rulesetVersion: HS_WEB_RULES_VERSION, modelVersion: HS_WEB_MODEL_VERSION,
    });
  }
  void modelStatus;
}

// The scan engine's route record (see scanRoutes) for each analysed Haskell route.
export function toEngineRoutes(web) {
  const FW = { scotty: 'Scotty', wai: 'WAI', servant: 'Servant', yesod: 'Yesod' };
  return web.routes.map((R) => ({
    method: R.method, path: R.path, framework: FW[R.framework] || R.framework, file: R.file, line: R.line,
    hasAuth: R.auth.status === 'authenticated', authStatus: R.auth.status, hasFileUpload: !!R.uploads,
    params: Array.isArray(R.params) ? R.params : [], classifications: [], classifiedFields: {},
    language: 'haskell', handler: R.handler ? { kind: R.handler.kind, name: R.handler.name || null } : null,
  }));
}
