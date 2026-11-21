// Authorization step deviation: CWE-863.
//
// THE SHAPE. In one directory, request handlers authenticate the caller and then
// check what the caller may do (a scope, a permission, a role, a policy):
//
//     const auth = await authenticateRequest(req);   if (!auth.ok) return deny(res);
//     const scope = authorizeScopes('models.list', auth.scopes);  if (!scope.allowed) return forbid(res);
//
// and one handler authenticates and goes straight on to the action. Being logged
// in is then the only requirement, which is the defect the siblings' second
// step exists to prevent: any authenticated caller, whatever their scopes, can
// reach it.
//
// WHAT MUST BE TRUE TO REPORT (all of it, measured per directory, test files
// excluded):
//   - at least MIN_STEPPED handlers authenticate and then call a permission check,
//     and at least MIN_SHARED of them call the SAME permission check (the
//     consensus check, named in the finding);
//   - those handlers are a strict majority of the directory's handlers that
//     authenticate through the same function, where a function counts as the same
//     when the siblings' authentication call wraps it (resolved by name across the
//     project, up to MAX_WRAP levels): a handler calling the inner function directly
//     is held to the convention of the handlers calling the wrapper;
//   - every handler counted, and the outlier, takes a request and tests the
//     authentication result (so the authentication is a gate, not a lookup);
//   - the outlier calls no permission check at all anywhere in its body;
//   - a function whose own name is an authentication or permission verb is a
//     wrapper, not a handler, and is neither counted nor reported.
//
// The finding sits on the authentication result test: the point after which the
// handler treats the caller as allowed. It claims an inconsistency with named
// siblings, not an exploit.
import path from 'node:path';
import { langOf, maskStrings, functionUnits, _valueInternals } from './convention-deviation-values.js';

const { callsIn } = _valueInternals;

const TEST_PATH_RE = /(?:^|[\\/])(?:tests?|specs?|__tests__|__mocks__|testdata|fixtures?|examples?|e2e)[\\/]|[._-](?:test|spec|stories)\.[a-z]{1,4}$|Tests?\.(?:java|kt|cs)$|_test\.go$|(?:^|[\\/])test_\w{1,80}\.py$/i;

export const MIN_STEPPED = 3;
export const MIN_SHARED = 3;

// A permission step: a verb, then the thing being checked.
const PERM_NOUN_RE = /scope|permission|privilege|role|polic|acl|capabilit|entitle|abilit|grant/i;
const PERM_VERB_RE = /^(?:authori[sz]e|check|require|assert|has|ensure|verify|can|is|allow|enforce|validate|must)/i;
// Bare permission calls with no noun: Laravel `$this->authorize(...)`, `can(...)`.
const PERM_BARE = new Set(['authorize', 'authorise', 'can', 'cannot', 'allows', 'denies', 'isGranted', 'denyAccessUnlessGranted', 'checkAccess', 'checkPermission']);

// An authentication step: establishes WHO the caller is.
const AUTHN_RE = /^(?:authenticate\w*|authori[sz]e\w*(?:Request|Connect|Http|Gateway|Session|Token|Caller|Client|Bearer)\w*|verify(?:Token|Jwt|JWT|Session|Auth|Credentials|ApiKey|Bearer|Signature)\w*|validate(?:Token|Jwt|JWT|Session|ApiKey|Bearer)\w*|require(?:Auth|Login|User|Authenticated|AuthenticatedUser|LoggedIn)|ensure(?:Auth|Login|Authenticated|LoggedIn)|get_?current_?user|getAuthenticatedUser|check_?auth\w*|checkAuth\w*)$/i;

export function isPermissionCall(name) {
  if (!name) return false;
  if (PERM_BARE.has(name)) return true;
  return PERM_VERB_RE.test(name) && PERM_NOUN_RE.test(name);
}
export function isAuthnCall(name) {
  return !!name && !isPermissionCall(name) && AUTHN_RE.test(name);
}

const REQ_PARAM_RE = /^(?:req|request|ctx|context|c|res|response|w|r|event|httpRequest|httpReq)$/;

function lineOf(src, off) { let n = 1; for (let i = 0; i < off && i < src.length; i++) if (src.charCodeAt(i) === 10) n++; return n; }

// The variable the authentication result is bound to, if any: `const x = await authn(...)`.
function boundName(masked, callStart) {
  const before = masked.slice(Math.max(0, callStart - 120), callStart);
  const m = before.match(/(?:const|let|var|val|\$)?\s{0,4}\$?([A-Za-z_]\w{0,60})\s{0,4}:?=\s{0,4}(?:await\s{1,4}|try\s{1,4})?(?:this\.|self\.|\$this->)?[\w.$>-]{0,80}$/);
  return m ? m[1] : null;
}

// Offset of the first test of the result after the call: `if (!x.ok)`, `if x is None`, `if err != nil`,
// `unless x`, or the call itself inside a condition.
function resultTest(masked, call, unitEnd) {
  const name = boundName(masked, call.start);
  const lineStart = masked.lastIndexOf('\n', call.start) + 1;
  const callLine = masked.slice(lineStart, call.start);
  if (/\b(?:if|unless|elif|while)\b[^\n]{0,40}$|[!?&|]\s{0,3}(?:await\s{1,4})?$/.test(callLine)) return lineStart + callLine.search(/\S/);
  if (!name) return -1;
  const tail = masked.slice(call.close, Math.min(unitEnd, call.close + 600));
  const re = new RegExp(`\\b(?:if|unless|elif)\\b[^\\n]{0,40}\\b(?:${name.replace(/[$]/g, '\\$')}|err)\\b`);
  const m = tail.match(re);
  return m ? call.close + m.index : -1;
}

const RETURN_BEFORE_RE = /\breturn\s{1,4}(?:await\s{1,4})?[\w.$>-]{0,80}$/;
const escapeRe = (t) => t.replace(/[$.*+?^(){}|[\]\\]/g, '\\$&');

// Pass 1 over one file: wrappers (functions named for authentication, with what they delegate to) and
// request-taking candidate handlers with their calls. Which call authenticates is decided in pass 2, once
// every wrapper in the project is known.
function unitsOf(file, src) {
  const lang = langOf(file);
  if (!lang) return { candidates: [], wrappers: [] };
  const masked = maskStrings(src, lang);
  const candidates = [], wrappers = [];
  for (const u of functionUnits(lang, masked)) {
    const calls = callsIn(masked, u.start, u.end);
    if (!calls.length) continue;
    if (isAuthnCall(u.name) || /^(?:authori[sz]e|authenticate)/i.test(u.name)) {
      // A wrapper delegates to the authentication calls inside it and to the call whose result it returns
      // (`return inner(...)`, or `const r = await inner(...); ...; return r;`), whatever that call is named.
      const body = masked.slice(u.start, u.end);
      const delegated = calls.filter(c => {
        if (isAuthnCall(c.method)) return true;
        if (RETURN_BEFORE_RE.test(masked.slice(Math.max(u.start, c.start - 100), c.start))) return true;
        const bn = boundName(masked, c.start);
        return !!bn && new RegExp(`\\breturn\\s{1,4}\\$?${escapeRe(bn)}\\b`).test(body);
      });
      wrappers.push({ name: u.name, calls: [...new Set(delegated.map(c => c.method))] });
      continue;
    }
    if (isPermissionCall(u.name)) continue;
    const params = (u.params || []).map(p => String(p).replace(/^[$*&]+/, ''));
    const takesRequest = params.some(p => REQ_PARAM_RE.test(p)) || /\b(?:req|request|ctx)\s{0,2}(?:\.|->|\[)/.test(masked.slice(u.start, u.end));
    if (!takesRequest) continue;
    candidates.push({ file, src, masked, unit: u, calls });
  }
  return { candidates, wrappers };
}

// Pass 2: a candidate is a handler when it gates on an authentication call (an authentication-named call
// or anything a wrapper delegates to) whose result it tests, and does not hand that result back.
function asHandler(c, isAuthn) {
  const authn = c.calls.find(x => isAuthn(x.method));
  if (!authn) return null;
  if (RETURN_BEFORE_RE.test(c.masked.slice(Math.max(c.unit.start, authn.start - 100), authn.start))) return null;
  const gate = resultTest(c.masked, authn, c.unit.end);
  if (gate < 0) return null;
  return { file: c.file, src: c.src, unit: c.unit, authn, perms: c.calls.filter(x => isPermissionCall(x.method)), gate };
}

// Authentication functions equivalent to `names`: each name plus the authentication calls inside a
// function of that name, followed through MAX_WRAP levels.
const MAX_WRAP = 3;
function closureOf(names, wrappers) {
  const out = new Set(names);
  let frontier = [...names];
  for (let d = 0; d < MAX_WRAP && frontier.length; d++) {
    const next = [];
    for (const n of frontier) for (const c of wrappers.get(n) || []) if (!out.has(c)) { out.add(c); next.push(c); }
    frontier = next;
  }
  return out;
}

/**
 * Project pass. `fileContents` maps a path to its source.
 */
export function scanAuthzStepDeviation(fileContents) {
  const candidates = [];
  const wrappers = new Map();
  for (const [file, src] of Object.entries(fileContents || {})) {
    if (typeof src !== 'string' || src.length > 400_000 || TEST_PATH_RE.test(file) || !langOf(file)) continue;
    if (!/auth/i.test(src)) continue;
    let r;
    try { r = unitsOf(file, src); } catch { continue; }
    for (const w of r.wrappers) {
      if (!wrappers.has(w.name)) wrappers.set(w.name, new Set());
      for (const c of w.calls) wrappers.get(w.name).add(c);
    }
    candidates.push(...r.candidates);
  }
  const delegatedTo = new Set();
  for (const set of wrappers.values()) for (const n of set) delegatedTo.add(n);
  const isAuthn = (name) => isAuthnCall(name) || wrappers.has(name) || delegatedTo.has(name);
  const byDir = new Map();
  for (const c of candidates) {
    const h = asHandler(c, isAuthn);
    if (!h) continue;
    const dir = path.dirname(h.file);
    if (!byDir.has(dir)) byDir.set(dir, []);
    byDir.get(dir).push(h);
  }
  const findings = [];
  const seen = new Set();
  for (const [dir, units] of byDir) {
    const after = u => u.perms.filter(p => p.start > u.authn.start);
    const stepped = units.filter(u => after(u).length);
    if (stepped.length < MIN_STEPPED) continue;
    const counts = new Map();
    for (const u of stepped) for (const name of new Set(after(u).map(p => p.method))) counts.set(name, (counts.get(name) || 0) + 1);
    const [consensus, shared] = [...counts].sort((a, b) => b[1] - a[1])[0] || [];
    if (!consensus || shared < MIN_SHARED) continue;
    const siblings = stepped.filter(u => after(u).some(p => p.method === consensus));
    // The population: handlers that authenticate through what the siblings authenticate with.
    const K = closureOf(new Set(siblings.map(s => s.authn.method)), wrappers);
    const population = units.filter(u => K.has(u.authn.method));
    if (siblings.length * 2 <= population.length) continue;
    for (const u of population) {
      if (u.perms.length) continue;
      const line = lineOf(u.src, u.gate);
      const key = `${u.file}:${line}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const sib = siblings.slice(0, 6).map(s => `${s.unit.name}() in ${path.basename(s.file)}`);
      findings.push({
        id: `authz-step-deviation:${u.file}:${line}:${u.unit.name}`,
        file: u.file, line,
        vuln: `Authorization step skipped: ${u.unit.name}() authenticates with ${u.authn.method}() and never calls the ${consensus}() check ${siblings.length} handlers in this directory make`,
        severity: 'medium',
        cwe: 'CWE-863',
        family: 'authz-step-deviation',
        parser: 'CONVENTION',
        confidence: 0.5,
        description:
          `In ${dir}, ${sib.join(', ')}${siblings.length > 6 ? ', and others' : ''} authenticate the caller and then call ${consensus}() before acting. ` +
          `${u.unit.name}() authenticates with ${u.authn.method}() and calls no permission check, so any authenticated caller reaches it. ` +
          "This is an inconsistency with the directory's own authorization handling, not a proof of exploitability.",
        remediation: `After the authentication check, call ${consensus}() with the permission this handler needs, as its siblings do, or document why any authenticated caller may use it.`,
        checkedFor: `a permission check after ${u.authn.method}() in ${u.unit.name}(); compared against ${siblings.length} handler(s) in the same directory that call ${consensus}()`,
        evidenceSiblings: siblings.map(s => `${s.file}:${s.unit.line}:${s.unit.name}`),
      });
    }
  }
  return findings;
}

export const _internals = { unitsOf, asHandler, resultTest, boundName, closureOf, TEST_PATH_RE };
