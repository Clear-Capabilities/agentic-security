// Authorization subject consistency: CWE-285.
//
// THE SHAPE. A controller's handlers take the same subject (a bound model, a route parameter, a loaded record) and pass it through an
// authorization check before acting on it, and one handler takes that subject and checks nothing:
//
//     public function edit(Invoice $invoice)    { $this->authorize('update', $invoice); ... }
//     public function update(.., Invoice $invoice) { $this->authorize('update', $invoice); ... }
//     public function destroy(Invoice $invoice) { $this->authorize('delete', $invoice); ... }
//     public function show(Invoice $invoice)    { return view('invoices.show', compact('invoice')); }   // no check
//
// The fix adds the siblings' check to the outlier. Measured need: run 83df9f624d98's `no_detector_candidate` cluster, where three
// development-split advisories (PHP, Java, TypeScript) have exactly this shape inside one file and produced no finding of any kind.
// docs/superpowers/plans/2026-11-14-recall-sibling-authz.md records the selection.
//
// WHY IT IS CREDIBLE. The rule never decides what the application's authorization model is. It OBSERVES the file checking a subject in
// at least MIN_GUARDED handlers, and those handlers being the majority of the ones that take it, then reports a handler that takes the
// same subject and runs no authorization check of any kind. The claim is "this file checks X here, here and here, and not there", which
// a reviewer can confirm on one screen, and the finding carries the guard and the siblings.
//
// HOW IT COMPARES TO ITS NEIGHBOURS. `api-authz.js` and `rbac-consistency.js` compare ROUTES by their registration (middleware, role
// annotations); this compares HANDLER BODIES by the subject the check is applied to, which is where a Laravel `authorize()`, a Spring
// permission validator call or a per-route `require*Access(c, id)` lives. `convention-deviation.js` compares option-bag forwarding.
//
// CWE-285, as `rbac-consistency.js` uses for the same "no check while siblings check" claim. The rule cannot tell a missing
// function-level check (CWE-862) from a missing object-level one (CWE-639); 285 states only what it observed.
//
// Deliberately NOT modelled:
//   · checks in middleware, a base class, a policy registered elsewhere or a callee: a handler with any such check in its body is left
//     alone, and one whose check lives outside the file is a known false-positive source, bounded by the majority rule.
//   · Go and Python: no development-split entry showed the shape yet, and each needs its own handler vocabulary verified on real code.
//   · cross-file conventions (one controller per file is the unit).

import { blankComments } from './_comment-strip.js';

const PHP_RE = /\.php$/i;
const JAVA_RE = /\.java$/i;
const JS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;

/** At least this many handlers must check the subject before an unchecked one means anything. */
export const MIN_GUARDED = 3;
/** And they must be most of the handlers that take it. */
export const MIN_GUARDED_RATIO = 0.6;

// An authorization-shaped callee. Verb-anchored so `getAccessToken` or `accessLog` is not a check, and authentication
// (`authenticate*`) never counts: knowing who the caller is says nothing about what they may touch. `is*Allowed` is left out on
// purpose: on real code it is as often a feature flag (`isEmergencyPublishAllowed`) as a permission check.
const AUTHZ_NAME = /^(?:authori[sz]e\w*|can|cannot|allows|denies|isGranted|denyAccessUnlessGranted|can[A-Z_]\w*|cannot[A-Z_]\w*|userCan\w*|user_can\w*|(?:require|check|ensure|assert|verify|has|enforce|validate|user_?has|must)_?\w*(?:Access|access|Permission|permission|Allowed|allowed|Authori[sz]ed|authori[sz]ed|Privilege|privilege|Rights?|rights?|Role|role|Authority|authority)\w*|should\w*(?:Hide|hide|Deny|deny|Forbid|forbid)\w*)$/;
const AUTHN = /authenticat/i;
const AUTHZ_ANNOTATION = /@(?:PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b/;

// Identifiers that are the request, the caller or the object itself, never the thing being authorized.
const NOT_A_SUBJECT = new Set(['this', '$this', 'self', 'super', 'c', 'ctx', 'context', 'req', 'request', '$request', 'res', 'response',
  'user', '$user', 'currentUser', 'identity', 'auth', '$auth', 'session', 'principal', 'authentication', 'new', 'true', 'false', 'null',
  'undefined', 'class', 'await', 'typeof', 'instanceof', 'function']);

const ROUTE_RE = /\b(?:app|router|api|server|route|routes|r)\s{0,4}\.\s{0,4}(get|post|put|patch|delete|all)\s{0,4}\(\s{0,4}(['"`])([^'"`\n]{1,300})\2/g;

// ── Text helpers (string-aware, over comment-blanked code) ─────────────────────────────────────────────────────────────────────────

/** Index of the bracket that closes the one at `open`, skipping string literals; -1 when unbalanced. */
function matchClose(code, open) {
  const o = code[open], c = o === '{' ? '}' : o === '(' ? ')' : ']';
  let depth = 0, inS = null;
  for (let i = open; i < code.length; i++) {
    const ch = code[i];
    if (inS) {
      if (ch === '\\') { i++; continue; }
      if (ch === inS || (ch === '\n' && inS !== '`')) inS = null;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') { inS = ch; continue; }
    if (ch === o) depth++;
    else if (ch === c && --depth === 0) return i;
  }
  return -1;
}

const lineAt = (code, idx) => code.slice(0, idx).split('\n').length;
const stripStrings = (s) => s.replace(/'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`/g, '""');

/** Root identifiers an expression list mentions: `$m->asset` gives `$m`, `release.getAppId()` gives `release`. */
function subjectsOf(args) {
  const out = new Set();
  const s = stripStrings(args);
  for (const m of s.matchAll(/(?<![\w$.>:#\\])(\$?[A-Za-z_]\w{0,63})(?!\w)(\s{0,4}(?:\(|::))?/g)) {
    const id = m[1];
    if (m[2]) continue;                                   // a call or a class reference, not a value
    if (/^[A-Z]/.test(id)) continue;                      // a type or constant
    if (NOT_A_SUBJECT.has(id)) continue;
    out.add(id);
  }
  return out;
}

/** Authorization calls in `body`: [{ name, args, subjects, index }]. */
function guardCalls(body) {
  const out = [];
  // No nested quantifiers anywhere in this module: it runs over untrusted code. The qualifier (`$this->`, `Gate::`, `a.b.`) is read
  // backwards from the name, one segment at a time, instead of by a repeated group.
  for (const m of body.matchAll(/(?<![\w$])([A-Za-z_]\w{0,80})\s{0,4}\(/g)) {
    const name = m[1];
    if (!AUTHZ_NAME.test(name) || AUTHN.test(name)) continue;
    let qual = '', before = body.slice(Math.max(0, m.index - 240), m.index);
    for (let k = 0; k < 3; k++) {
      const q = before.match(/([\w$]{1,64})\s{0,2}(->|\.|::)\s{0,2}$/);
      if (!q) break;
      qual = q[1] + q[2] + qual;
      before = before.slice(0, q.index);
    }
    const open = m.index + m[0].length - 1;
    const close = matchClose(body, open);
    const args = close === -1 ? body.slice(open + 1, open + 400) : body.slice(open + 1, close);
    out.push({ name: qual + name, args, subjects: subjectsOf(args), index: m.index });
  }
  return out;
}

/** Parameter names from a parameter list: the last identifier of each top-level comma-separated part. */
function paramNames(list) {
  const parts = [];
  let depth = 0, cur = '';
  for (const ch of stripStrings(list)) {
    if ('(<[{'.includes(ch)) depth++;
    else if (')>]}'.includes(ch)) depth--;
    if (ch === ',' && depth === 0) { parts.push(cur); cur = ''; } else cur += ch;
  }
  parts.push(cur);
  const out = new Set();
  for (const p of parts) {
    const head = p.split('=')[0];
    const ids = head.match(/\$?[A-Za-z_]\w*/g);
    if (!ids) continue;
    // TypeScript `name: Type` puts the name first; everything else puts it last.
    const id = /:/.test(head) && !/::/.test(head) ? ids[0] : ids[ids.length - 1];
    if (!NOT_A_SUBJECT.has(id)) out.add(id);
  }
  return out;
}

/** Locals a body assigns, with the line (relative to the body) of each assignment. */
function assignedLocals(body, lang) {
  const out = new Map();
  const re = lang === 'php' ? /(\$[A-Za-z_]\w*)\s{0,4}=(?![=>])/g
    : lang === 'java' ? /\b[\w<>\[\],.?]{1,80}\s{1,4}([a-z_]\w{0,63})\s{0,4}=(?!=)/g
      : /\b(?:const|let|var)\s{1,4}(?:([A-Za-z_$][\w$]{0,63})|\{([^}]{1,300})\})\s{0,4}(?::[^=]{1,120})?=(?!=)/g;
  for (const m of body.matchAll(re)) {
    const line = body.slice(0, m.index).split('\n').length;
    const names = m[2] ? m[2].split(',').map((x) => x.split(':').pop().trim().split(/\s/)[0]) : [m[1]];
    for (const n of names) if (n && !out.has(n)) out.set(n, line);
  }
  return out;
}

// ── Units ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

function unit(code, { name, line, paramsText, bodyOpen, prelude = '' }) {
  const close = matchClose(code, bodyOpen);
  if (close === -1) return null;
  const body = code.slice(bodyOpen + 1, close);
  return { name, line, bodyLine: lineAt(code, bodyOpen), params: paramNames(paramsText), body, prelude };
}

function phpUnits(code) {
  const units = [];
  for (const m of code.matchAll(/\bfunction\s{1,8}&?([A-Za-z_]\w{0,80})\s{0,8}\(/g)) {
    const lineStart = code.lastIndexOf('\n', m.index) + 1;
    const mods = code.slice(lineStart, m.index);
    // Only a method or function declared at the start of its line; a closure (`fn = function (`) is not a handler.
    if (!/^[\sA-Za-z]{0,120}$/.test(mods) || /\b(?:private|protected)\b/.test(mods) || m[1].startsWith('__')) continue;
    const open = m.index + m[0].length - 1;
    const pClose = matchClose(code, open);
    if (pClose === -1) continue;
    const brace = code.slice(pClose).search(/[{;]/);
    if (brace === -1 || code[pClose + brace] !== '{') continue;   // abstract or interface method
    const u = unit(code, { name: m[1], line: lineAt(code, m.index), paramsText: code.slice(open + 1, pClose), bodyOpen: pClose + brace });
    if (u) units.push(u);
  }
  return units;
}

function javaUnits(code) {
  const units = [];
  const lines = code.split('\n');
  let at = 0;
  for (let li = 0; li < lines.length; at += lines[li].length + 1, li++) {
    const text = lines[li];
    if (!/^\s{0,40}public\s/.test(text)) continue;
    const paren = text.indexOf('(');
    if (paren === -1 || /\b(?:class|interface|enum|record|new|return)\b/.test(text.slice(0, paren))) continue;
    // The method name is the identifier right before the first `(`, after a return type (a constructor has none: one word only).
    const head = text.slice(0, paren).trim().split(/\s+/);
    const nm = head[head.length - 1];
    if (head.length < 3 || !/^[a-z_]\w{0,80}$/.test(nm)) continue;
    const open = at + paren;
    const pClose = matchClose(code, open);
    if (pClose === -1) continue;
    const brace = code.slice(pClose).search(/[{;]/);
    if (brace === -1 || code[pClose + brace] !== '{') continue;
    const line = li + 1;
    // Annotations directly above the method are part of it: that is where `@PreAuthorize` lives. A mapping annotation can span lines
    // and contain braces (`consumes = {`), so the walk stops only at what ends the previous member: a blank line, a `;`, a lone `}` or the
    // class header.
    let k = line - 2;
    const prelude = [];
    while (k >= 0 && k > line - 16) {
      const t = lines[k].trim();
      if (!t || t.endsWith(';') || t === '}' || /\b(?:class|interface|enum|record)\b[^(]*\{$/.test(t)) break;
      prelude.unshift(lines[k]);
      k--;
    }
    const u = unit(code, { name: nm, line, paramsText: code.slice(open + 1, pClose), bodyOpen: pClose + brace, prelude: prelude.join('\n') });
    if (u) units.push(u);
  }
  return units;
}

function jsRouteUnits(code) {
  const units = [];
  for (const m of code.matchAll(ROUTE_RE)) {
    const callOpen = code.indexOf('(', m.index);
    const callClose = matchClose(code, callOpen);
    if (callClose === -1) continue;
    const call = code.slice(callOpen, callClose);
    // The handler is the LAST function literal among the arguments; everything between the path and it is middleware.
    const fns = [...call.matchAll(/(?:async\s{1,4})?(?:function\s{0,4}\w{0,64}\s{0,4}\(([^)]{0,300})\)|\(([^)]{0,300})\)\s{0,4}(?::\s{0,4}[^=>{]{1,120})?=>|(\w{1,64})\s{0,4}=>)\s{0,4}\{/g)];
    if (!fns.length) continue;
    const f = fns[fns.length - 1];
    const bodyOpen = callOpen + f.index + f[0].length - 1;
    const u = unit(code, {
      name: `${m[1].toUpperCase()} ${m[3]}`, line: lineAt(code, m.index), paramsText: '', bodyOpen,
      prelude: call.slice(0, f.index),
    });
    if (!u) continue;
    u.path = m[3];
    u.verb = m[1].toLowerCase();
    // The callback's own parameters are the request context, never a subject.
    u.contextParams = paramNames(f[1] || f[2] || f[3] || '');
    units.push(u);
  }
  return units;
}

// ── Analysis ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

function annotate(u, lang) {
  const calls = guardCalls(u.body);
  const preludeCalls = lang === 'js' ? guardCalls(u.prelude).concat(
    [...u.prelude.matchAll(/(?<![\w$.])([A-Za-z_]\w{0,80})\s{0,4}(?=,|\))/g)].filter((x) => AUTHZ_NAME.test(x[1]) && !AUTHN.test(x[1]))
      .map((x) => ({ name: x[1], subjects: new Set() }))) : [];
  const annotations = lang === 'java' && AUTHZ_ANNOTATION.test(u.prelude)
    ? [{ name: u.prelude.match(AUTHZ_ANNOTATION)[0], subjects: new Set([...u.prelude.matchAll(/#([A-Za-z_]\w*)/g)].map((x) => x[1])) }]
    : [];
  const guards = [...calls, ...preludeCalls, ...annotations];
  const ctx = u.contextParams || new Set();
  const locals = assignedLocals(u.body, lang);
  const introduces = new Set([...u.params, ...locals.keys()].filter((x) => !ctx.has(x) && !NOT_A_SUBJECT.has(x)));
  const guardedOn = new Map();
  for (const g of guards) for (const s of g.subjects) if (!ctx.has(s) && !guardedOn.has(s)) guardedOn.set(s, g.name);
  return { ...u, guards, introduces, guardedOn, locals };
}

// Route handlers are siblings when they serve the same resource. When the subject is a path parameter (`/teams/:teamId/...`), the
// handlers compared are the routes under that parameter, the grouping `api-authz.js` and `rbac-consistency.js` use; a route elsewhere in
// the file that happens to read a variable of the same name is not one of them. Units without a route path form one group.
function resourceGroups(s, units) {
  const groups = new Map();
  const bare = s.replace(/^\$/, '');
  const PARAM = new RegExp(`^(.*?[/](?::${bare}|\\{${bare}\\}|<${bare}>))(?:[/?]|$)`);
  for (const u of units) {
    const m = u.path ? u.path.match(PARAM) : null;
    const key = m ? m[1] : '';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(u);
  }
  return [...groups.values()];
}

// Read or write, when the code says so. Many applications check writes and leave reads open on purpose, so an unchecked READ is only
// compared with checked reads: a file that checks no read at all has not established that reads are checked.
const READ_NAME = /^(?:show|index|get|list|find|view|edit|search|export|download|load|fetch|read|preview|display)(?:[A-Z_]|$)/;
const WRITE_NAME = /^(?:store|create|update|destroy|delete|save|set|add|remove|post|put|patch|modify|import|upload|rollback|publish|revoke|assign)(?:[A-Z_]|$)/;
// A body that is one `return` of a redirect: the route it sends the caller to does its own checking.
const REDIRECT_ONLY = /^\s*return\s{1,4}(?:redirect\b|\$this\s{0,2}->\s{0,2}redirect|new\s{1,4}RedirectResponse\b|["']redirect:|(?:c|res|ctx|reply)\s{0,2}\.\s{0,2}redirect\b)[^;]{0,600};?\s*$/;

function kind(u) {
  if (u.verb) return u.verb === 'get' ? 'read' : u.verb === 'all' ? null : 'write';
  if (/@(?:GetMapping|GET)\b|RequestMethod\.GET\b/.test(u.prelude)) return 'read';
  if (/@(?:PostMapping|PutMapping|DeleteMapping|PatchMapping|POST|PUT|DELETE|PATCH)\b|RequestMethod\.(?:POST|PUT|DELETE|PATCH)\b/.test(u.prelude)) return 'write';
  return READ_NAME.test(u.name) ? 'read' : WRITE_NAME.test(u.name) ? 'write' : null;
}

/** Pure analysis over one file's units; returns the outliers with their evidence. */
export function analyseHandlers(units) {
  const bySubject = new Map();
  for (const u of units) for (const s of u.introduces) {
    if (!bySubject.has(s)) bySubject.set(s, []);
    bySubject.get(s).push(u);
  }
  const best = new Map();   // unit -> strongest evidence
  for (const [s, all] of bySubject) for (const pop of resourceGroups(s, all)) {
    const guarded = pop.filter((u) => u.guardedOn.has(s));
    if (guarded.length < MIN_GUARDED || guarded.length / pop.length < MIN_GUARDED_RATIO) continue;
    const guardedNames = new Set(guarded.map((u) => u.name));
    for (const u of pop) {
      if (u.guards.length) continue;                                        // checks something: not ours to second-guess
      if (AUTHZ_NAME.test(u.name)) continue;                                // the permission model itself, not a handler
      if (REDIRECT_ONLY.test(u.body)) continue;                             // sends the caller elsewhere, reads nothing
      if (kind(u) === 'read' && !guarded.some((g) => kind(g) === 'read')) continue;
      const delegates = [...guardedNames].some((n) => new RegExp(`(?:->|\\.|::|\\b)${n.replace(/[^\w]/g, '')}\\s{0,4}\\(`).test(u.body));
      if (delegates) continue;
      const prev = best.get(u);
      if (prev && prev.guarded.length >= guarded.length) continue;
      const tally = new Map();
      for (const g of guarded) tally.set(g.guardedOn.get(s), (tally.get(g.guardedOn.get(s)) || 0) + 1);
      const guard = [...tally.entries()].sort((a, b) => b[1] - a[1])[0][0];
      const siblingSubjects = new Set(guarded.flatMap((g) => [...g.guardedOn.keys()]));
      best.set(u, { unit: u, subject: s, guard, guarded, population: pop.length, siblingSubjects });
    }
  }
  return [...best.values()];
}

// Where the missing check belongs. An object-level check needs the object, so when the handler assigns a variable the siblings' checks
// read, the check goes after that assignment; otherwise it is the handler's first statement.
function insertionLine(d) {
  const u = d.unit;
  const bodyLines = u.body.split('\n');
  let rel = null;
  for (const [name, at] of u.locals) if (d.siblingSubjects.has(name)) rel = rel === null ? at : Math.min(rel, at);
  let i = rel === null ? 1 : rel;   // relative to the body; line 1 is the rest of the `{` line
  // From an assignment, step past the end of that statement.
  if (rel !== null) { while (i < bodyLines.length && !/[;})]\s*$/.test(bodyLines[i - 1]) && bodyLines[i - 1].trim()) i++; i++; }
  while (i <= bodyLines.length && !bodyLines[i - 1].trim()) i++;
  if (i > bodyLines.length) i = 1;
  return u.bodyLine + i - 1;
}

function finding(file, d) {
  const u = d.unit;
  const guard = d.guard.startsWith('@') ? d.guard : `${d.guard}()`;
  const line = insertionLine(d);
  const siblings = d.guarded.map((g) => g.name);
  return {
    id: `authz-subject-consistency:${file}:${line}:${u.name}`,
    severity: 'medium',
    file, line,
    vuln: `Missing authorization: ${u.name} takes ${d.subject} but runs no authorization check, while ${d.guarded.length} of the ${d.population} handlers that take it apply ${guard}`,
    cwe: 'CWE-285',
    family: 'broken-access-control',
    parser: 'AUTHZ-CONSISTENCY',
    confidence: 0.55,
    description:
      `${siblings.slice(0, 6).join(', ')} in this file pass ${d.subject} through ${guard} before acting on it; ${u.name} takes the same ` +
      `${d.subject} and performs no authorization check. A caller allowed to reach ${u.name} can read or change a ${d.subject} the other ` +
      'handlers would refuse them. The finding is an inconsistency, not a proof: the check may live in middleware or a policy outside this file.',
    remediation: `Apply the same check the sibling handlers use, ${guard} on ${d.subject}, in ${u.name}, or document why this handler is exempt.`,
    checkedFor: `an authorization call in ${u.name}; compared against ${d.guarded.length} sibling handler(s) that check ${d.subject}`,
    evidenceSiblings: siblings,
  };
}

/** Per-file entry point. */
export function scanAuthzSubjectConsistency(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 1_000_000) return [];
  const lang = PHP_RE.test(file) ? 'php' : JAVA_RE.test(file) ? 'java' : JS_RE.test(file) ? 'js' : null;
  if (!lang) return [];
  // Test code asserts on permissions; it does not enforce them.
  if (/(?:^|[\\/])(?:tests?|__tests__|spec|specs|testsuite)[\\/]|(?:Test|Tests|IT)\.java$|\.(?:test|spec)\.[cm]?[jt]sx?$|Test\.php$/i.test(file)) return [];
  try {
    const code = blankComments(raw, lang === 'php' ? 'php' : undefined);
    // Cheap relevance gate: no authorization-shaped word, nothing to compare.
    if (!/authori[sz]e|Permission|permission|Access|access|Allowed|allowed|can[A-Z(_]|Role|role|Granted|Hide/.test(code)) return [];
    const raw_units = lang === 'php' ? phpUnits(code) : lang === 'java' ? javaUnits(code) : jsRouteUnits(code);
    const units = raw_units.map((u) => annotate(u, lang));
    return analyseHandlers(units).map((d) => finding(file, d)).sort((a, b) => a.line - b.line);
  } catch { return []; }
}

export const _internals = { AUTHZ_NAME, subjectsOf, guardCalls, paramNames, assignedLocals, phpUnits, javaUnits, jsRouteUnits };
