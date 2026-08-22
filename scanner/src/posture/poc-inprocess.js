// In-process proof-of-concept synthesis (R2 — closing the automatic loop).
//
// WHY A SECOND POC KIND. `poc-generator.js` emits *HTTP* PoCs: they take a URL
// and a param and hit a running server. Those are the right artifact for a
// human reproducing a bug against a deployed app, but they cannot be executed
// by `execution-proof.js` — the sandbox denies network egress and there is no
// server inside it. That is the concrete reason nothing in the scan pipeline
// ever produced an `execution-proven` finding: the PoCs it generated were
// unrunnable *by construction* in the only place proofs are allowed to run.
//
// This module emits the other kind: a self-contained script that imports the
// vulnerable file directly, calls the exported handler with a crafted request,
// and lets the injected payload write the proof marker. No server, no network,
// no fixture discovery.
//
// DELIBERATELY NARROW. It refuses far more than it accepts, and that is the
// design rather than a gap to close later. A PoC that runs but proves nothing
// is worse than no PoC: `proof-failed` is a triage signal about the FINDING,
// so a template that misfires manufactures evidence against real bugs. Every
// refusal below is a case where the generated script would have been a guess.
//
// SAFETY. The payload is a shell redirect that creates a marker file inside
// the sandbox root (`> PROVEN`). It is the least destructive thing that still
// proves arbitrary command execution: no network, no writes outside the root,
// no privilege attempts, and it is only ever executed inside R1's sandbox with
// egress denied and the filesystem confined.

const MARKER = 'PROVEN';

// Only families where "the injected payload ran" is observable from a marker
// file. Others (XSS, weak crypto) need a browser or a judgement call about
// output, and a marker-file proof would be a category error.
// Families whose exploitation is observable from inside a sandbox.
//
// Injection classes are observable because the payload itself writes the
// marker. Webhook-signature bypass is observable for a different reason: the
// defect IS the handler accepting a request it should have rejected, so the
// PoC observes the acceptance and records it. Both are execution-based — code
// ran and behaved insecurely — but they are proven by different evidence, and
// conflating them is how a template ends up asserting something it never saw.
export const SUPPORTED = new Set([
  'command-injection',
  'code-injection',
  'webhook-missing-signature-verification',
  'sql-injection',
  'path-traversal',
  'ldap-injection',
  'xxe',
]);

// Classes proven by observing the HANDLER's behaviour rather than a payload
// side effect. Each has its own builder below; the shared refusals (language,
// content, module system) are applied before dispatch.
const BEHAVIOURAL = new Map([
  ['webhook-missing-signature-verification', (f, c) => _webhookPoc(f, c)],
  ['sql-injection', (f, c) => _sqlInjectionPoc(f, c)],
  ['path-traversal', (f, c) => _pathTraversalPoc(f, c)],
  ['ldap-injection', (f, c) => _ldapInjectionPoc(f, c)],
  ['xxe', (f, c) => _xxePoc(f, c)],
]);

// Classes deliberately NOT here, with the reason, so the gap is a decision
// rather than an oversight:
//
//   IDOR / broken-access-control — proving it means showing user A read user
//     B's record, which requires two authenticated identities and a populated
//     data store. A single-shot harness would have to invent both, and a PoC
//     built on invented state proves something about the invention.
//   SSRF — the proof is that the server fetched an attacker-named host. The
//     sandbox denies egress (that is the point of R1), and binding a loopback
//     listener is not guaranteed across backends, so a failed fetch would be
//     confinement talking, not the finding.
//   XSS — needs a browser to say whether the payload executed. A marker file
//     cannot observe a DOM.

const JS_EXT = /\.(js|cjs|mjs)$/i;

// A handler we can call: `module.exports = function (req, res)` or
// `module.exports.name = function (req, res)` / `exports.name = ...`.
// Arrow and function forms both count. The two-parameter (req, res) shape is
// required — a one-arg export is not an Express-style handler and calling it
// with a fake request would be inventing an interface.
const HANDLER_RES = [
  /module\.exports\s*=\s*(?:async\s+)?function\s*\w*\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/,
  /module\.exports\s*=\s*(?:async\s+)?\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>/,
];
const NAMED_HANDLER_RES = [
  /(?:module\.)?exports\.(\w+)\s*=\s*(?:async\s+)?function\s*\w*\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)/,
  /(?:module\.)?exports\.(\w+)\s*=\s*(?:async\s+)?\(\s*(\w+)\s*,\s*(\w+)\s*\)\s*=>/,
];

// The exported handler, default form preferred over a named one. Shared by
// every template — a template that found handlers its own way could accept a
// shape the others refuse, and the refusals are the safety property here.
function _findHandler(fileContent) {
  for (const re of HANDLER_RES) {
    const m = fileContent.match(re);
    if (m) return { call: { kind: 'default', name: null }, reqIdent: m[1] };
  }
  for (const re of NAMED_HANDLER_RES) {
    const m = fileContent.match(re);
    if (m) return { call: { kind: 'named', name: m[1] }, reqIdent: m[2] };
  }
  return null;
}

const NO_HANDLER = {
  ok: false,
  reason: 'no exported two-argument (req, res) handler found — nothing to call without inventing an interface',
};

// Import/invoke lines for a located handler.
function _binding(finding, call) {
  const base = finding.file.split(/[\\/]/).pop();
  return {
    base,
    importLine: `import ${call.kind === 'default' ? 'handler' : `{ ${call.name} }`} from './${base}';`,
    invoke: call.kind === 'default' ? 'handler' : call.name,
    handlerLabel: call.kind === 'default' ? 'module.exports' : `exports.${call.name}`,
  };
}

// The request property the handler reads. Anchored to the request identifier
// the export actually binds, so a file that reads `req.query` while exporting
// `(request, response)` does not produce a PoC built on the wrong name.
//
// A handler that reads more than one request property (extremely common —
// e.g. a harmless query param for pagination alongside the actual body
// param used in the sink) used to always get the first property found in a
// fixed query>body>params priority, with no relationship to which one
// actually reaches the sink — silently building a PoC against an inert
// parameter while the real injection point went untouched. When sinkLine
// is known, prefer whichever match sits closest to it (line proximity is a
// cheap, effective proxy for "this is the value that flows into the sink a
// few lines below/above it"); otherwise fall back to the old first-found
// behavior for callers that can't supply a line.
function _requestSource(content, reqIdent, sinkLine) {
  const esc = reqIdent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const candidates = [];
  for (const prop of ['query', 'body', 'params']) {
    const re = new RegExp(`\\b${esc}\\.${prop}\\.(\\w+)`, 'g');
    let m;
    while ((m = re.exec(content))) {
      const line = content.slice(0, m.index).split('\n').length;
      candidates.push({ prop, key: m[1], line });
    }
  }
  if (!candidates.length) return null;
  if (typeof sinkLine === 'number') {
    candidates.sort((a, b) => Math.abs(a.line - sinkLine) - Math.abs(b.line - sinkLine));
  }
  return { prop: candidates[0].prop, key: candidates[0].key };
}

// The sink must interpolate into a SHELL, not an argv array. `exec`/`execSync`
// run through a shell so `; > PROVEN` executes; `execFile`/`spawn` with an
// array do not, and a marker PoC against those would fail for a reason that
// has nothing to do with whether the finding is real.
const SHELL_SINK = /\b(?:exec|execSync)\s*\(/;
const ARGV_SINK = /\b(?:execFile|execFileSync|spawn|spawnSync)\s*\(/;

/**
 * Synthesize a sandbox-runnable PoC, or return a refusal explaining why not.
 *
 * @returns {{ok:true, poc:object} | {ok:false, reason:string}}
 */
export function synthesizeInProcessPoc(finding, fileContent) {
  if (!finding || typeof finding !== 'object') return { ok: false, reason: 'no finding' };
  if (!SUPPORTED.has(finding.family)) {
    return { ok: false, reason: `family '${finding.family || 'unknown'}' has no marker-observable in-process template` };
  }
  if (!finding.file || !JS_EXT.test(finding.file)) {
    return { ok: false, reason: 'in-process PoCs are JavaScript-only today' };
  }
  if (typeof fileContent !== 'string' || !fileContent.trim()) {
    return { ok: false, reason: 'the vulnerable file content was not available' };
  }
  if (/^\s*(?:import|export)\s/m.test(fileContent) && !/module\.exports/.test(fileContent)) {
    return { ok: false, reason: 'ES-module source: the CommonJS handler shapes do not apply' };
  }

  const behavioural = BEHAVIOURAL.get(finding.family);
  if (behavioural) return behavioural(finding, fileContent);

  if (!SHELL_SINK.test(fileContent)) {
    return {
      ok: false,
      reason: ARGV_SINK.test(fileContent)
        ? 'the sink passes an argv array, so a shell-metacharacter payload would not execute — absence of proof here would say nothing about the finding'
        : 'no shell-executing sink found in the file',
    };
  }

  // Default export first, then a named one.
  let call = null, reqIdent = null;
  for (const re of HANDLER_RES) {
    const m = fileContent.match(re);
    if (m) { call = { kind: 'default', name: null }; reqIdent = m[1]; break; }
  }
  if (!call) {
    for (const re of NAMED_HANDLER_RES) {
      const m = fileContent.match(re);
      if (m) { call = { kind: 'named', name: m[1] }; reqIdent = m[2]; break; }
    }
  }
  if (!call) {
    return { ok: false, reason: 'no exported two-argument (req, res) handler found — nothing to call without inventing an interface' };
  }

  const src = _requestSource(fileContent, reqIdent, finding.line);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the injection point is unknown` };
  }

  const base = finding.file.split(/[\\/]/).pop();
  const imported = call.kind === 'default' ? 'handler' : `{ ${call.name} }`;
  const invoke = call.kind === 'default' ? 'handler' : call.name;

  // The timer is unref'd so the process exits as soon as the handler responds.
  // Without that it stays alive for the full timeout even after the exploit
  // has landed, and on a loaded machine it can outlive the proof budget — at
  // which point `attachProofTier` demotes a real proof to its static tier
  // because `ran` is false. Correct, but it throws away a genuine result.
  const code = [
    `// Auto-generated in-process proof-of-concept for ${finding.file}.`,
    '// Proves arbitrary command execution by having the injected payload',
    `// create the marker file '${MARKER}' inside the sandbox root.`,
    `import ${imported} from './${base}';`,
    'await new Promise((resolve) => {',
    '  const res = {',
    '    send: () => resolve(), json: () => resolve(), end: () => resolve(),',
    '    status: () => ({ send: () => resolve(), json: () => resolve(), end: () => resolve() }),',
    '  };',
    `  const req = { ${src.prop}: ${JSON.stringify({ [src.key]: `x; > ${MARKER}` })} };`,
    `  try { ${invoke}(req, res); } catch { resolve(); }`,
    '  setTimeout(resolve, 4000).unref();',
    '});',
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js',
      kind: 'in-process',
      family: finding.family,
      cwe: finding.cwe || null,
      marker: MARKER,
      paramKey: src.key,
      paramSource: src.prop,
      handler: call.kind === 'default' ? 'module.exports' : `exports.${call.name}`,
      // The file the PoC imports. `execution-proof.js` materialises this into
      // the sandbox root; without it the import fails and nothing is proved.
      requires: [base],
      code,
    },
  };
}



// ── Webhook signature bypass ────────────────────────────────────────────────
//
// The proof is that an UNSIGNED request is processed. So the PoC calls the
// handler with no signature header and watches what the handler does with the
// response object: a success reply means the payload was accepted, and the
// marker is written only then.
//
// REFUSALS MATTER MORE HERE THAN FOR INJECTION. A handler that rejects the
// request produces no marker, which is correct — but a handler that never
// replies at all also produces no marker, and those are different facts. The
// template therefore refuses any handler it cannot observe a decision from,
// rather than letting "no reply" masquerade as "rejected".
function _webhookPoc(finding, fileContent) {
  const found = _findHandler(fileContent);
  if (!found) return NO_HANDLER;
  const { call, reqIdent } = found;
  // The handler must actually read the body, or "it accepted an unsigned
  // request" is not a statement about a webhook at all.
  const esc = reqIdent.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  if (!new RegExp(`\\b${esc}\\.(?:body|rawBody)\\b`).test(fileContent)) {
    return { ok: false, reason: `the handler does not read '${reqIdent}.body', so it is not processing a webhook payload` };
  }
  // If the file verifies a signature somewhere, this template cannot tell
  // whether the check is reachable on this path — that is a taint question, not
  // an execution one. Refuse rather than guess.
  if (/\b(?:createHmac|timingSafeEqual|verifySignature|constructEvent|hash_equals|X-Hub-Signature|stripe-signature)\b/i.test(fileContent)) {
    return { ok: false, reason: 'the file already references signature verification; whether it guards this path is a static question, not one this PoC can answer' };
  }

  const { base, importLine, invoke, handlerLabel } = _binding(finding, call);

  const code = [
    `// Auto-generated proof for ${finding.file}.`,
    '// Sends a webhook payload with NO signature header. If the handler replies',
    `// with success, it accepted an unsigned request — the marker '${MARKER}' is`,
    '// written only on that observation.',
    importLine,
    "import fs from 'node:fs';",
    'let decided = null;',
    'const ok = () => { if (decided === null) decided = "accepted"; };',
    'const rejected = () => { if (decided === null) decided = "rejected"; };',
    'await new Promise((resolve) => {',
    // The timer is REF'D and cleared on decision, not unref'd. The marker write
    // below happens AFTER this await, so an unref'd timer lets Node exit with
    // the promise still pending the moment a handler declines to reply — the
    // check never runs, and the test asserting "no decision writes no marker"
    // would pass without ever reaching the line it is testing.
    '  let timer = null;',
    '  const done = () => { clearTimeout(timer); resolve(); };',
    '  const res = {',
    '    send: () => { ok(); done(); }, json: () => { ok(); done(); }, end: () => { ok(); done(); },',
    '    // A 4xx/5xx is a rejection, whatever the body says.',
    '    status: (c) => { if (c >= 400) rejected(); else ok();',
    '      return { send: done, json: done, end: done }; },',
    '  };',
    '  const req = { headers: {}, body: { amount: 1, id: "poc" }, rawBody: "{}" };',
    // Armed BEFORE the call. A handler that replies synchronously would
    // otherwise clear a null handle and then arm a timer nobody cancels,
    // holding the process open for the full budget after the work is done.
    '  timer = setTimeout(resolve, 3000);',
    `  try { ${invoke}(req, res); } catch { decided = "threw"; done(); }`,
    '});',
    '// Only an observed acceptance proves the bypass. "No decision" is not',
    '// acceptance, and must not write the marker.',
    `if (decided === "accepted") fs.writeFileSync('${MARKER}', 'x');`,
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js', kind: 'in-process', family: finding.family, cwe: finding.cwe || null,
      marker: MARKER, handler: handlerLabel,
      observes: 'handler accepted an unsigned webhook payload',
      requires: [base], code,
    },
  };
}


// ── SQL injection, proven at the driver boundary ────────────────────────────
//
// There is no database in the sandbox and there is not going to be one. What
// there IS, and what actually settles the question, is the moment the query
// crosses into the driver: either the user's payload arrives inside the SQL
// TEXT, or it arrives as a bound parameter. The first is the vulnerability by
// definition; the second is the fix by definition. Nothing about schema, rows,
// or a live server is needed to tell them apart.
//
// So the PoC stubs the driver package with a recorder, calls the handler with a
// payload carrying a sentinel, and writes the marker only if the sentinel shows
// up inside a string that is recognisably SQL. A parameterised call records the
// sentinel in the params array and the marker is not written — which is the
// correct outcome, reached by execution rather than by reading the source.
//
// This is why the class needed no running app: the proof was never at the
// database, it was at the boundary.

const SQL_DRIVERS = ['mysql2', 'mysql', 'pg', 'sqlite3', 'better-sqlite3', 'mssql', 'oracledb'];
const SQL_SENTINEL = 'PROVEN_SQLI';
const SQL_LOG = 'driver-calls.jsonl';

// A universal recording stub. The drivers differ in surface (`createConnection`
// vs `new Pool` vs `new Database`), so rather than model each one, every
// property access yields a callable/constructible proxy that records its string
// and array arguments and drives any callback. `then` is undefined so an
// `await` on a result does not hang.
const DRIVER_STUB = [
  "const fs = require('fs');",
  'function record(args) {',
  '  const strings = [], arrays = [];',
  '  for (const a of args) {',
  "    if (typeof a === 'string') strings.push(a);",
  '    else if (Array.isArray(a)) arrays.push(a.map((x) => String(x)));',
  // mysql's `query({sql, values})` form, and pg's `query({text, values})`.
  "    else if (a && typeof a === 'object') {",
  "      if (typeof a.sql === 'string') strings.push(a.sql);",
  "      if (typeof a.text === 'string') strings.push(a.text);",
  '      if (Array.isArray(a.values)) arrays.push(a.values.map((x) => String(x)));',
  '    }',
  '  }',
  '  if (strings.length || arrays.length) {',
  `    try { fs.appendFileSync(${JSON.stringify(SQL_LOG)}, JSON.stringify({ strings, arrays }) + '\\n'); } catch {}`,
  '  }',
  '}',
  'const mk = () => new Proxy(function () {}, {',
  "  get(t, p) { if (typeof p === 'symbol' || p === 'then' || p === 'inspect') return undefined; return mk(); },",
  '  apply(t, self, args) {',
  '    record(args);',
  "    for (const a of args) if (typeof a === 'function') { try { a(null, []); } catch {} }",
  '    return mk();',
  '  },',
  '  construct(t, args) { record(args); return mk(); },',
  '});',
  'module.exports = mk();',
].join('\n');

// Compiled once at load rather than per call. Building these from a template
// inside the function meant a fresh RegExp per driver per finding, and it read
// as a dynamically-assembled pattern to anything analysing this file — this
// engine included, which flagged it.
const SQL_DRIVER_RES = SQL_DRIVERS.map((d) => [
  d,
  new RegExp(`require\\s*\\(\\s*['"\`]${d.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}['"\`]`),
]);

function _sqlInjectionPoc(finding, fileContent) {
  const driver = (SQL_DRIVER_RES.find(([, re]) => re.test(fileContent)) || [])[0];
  if (!driver) {
    return {
      ok: false,
      reason: `no recognised database driver is required by this file, so there is no boundary to observe the query at (looked for: ${SQL_DRIVERS.join(', ')})`,
    };
  }
  const found = _findHandler(fileContent);
  if (!found) return NO_HANDLER;
  const { call, reqIdent } = found;

  const src = _requestSource(fileContent, reqIdent, finding.line);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the injection point is unknown` };
  }

  const { base, importLine, invoke, handlerLabel } = _binding(finding, call);
  // Carries SQL syntax AND the sentinel: the sentinel alone would also appear
  // in a correctly parameterised call, and matching on it would call a fixed
  // handler vulnerable.
  const payload = `1' OR '1'='1' -- ${SQL_SENTINEL}`;

  const code = [
    `// Auto-generated proof for ${finding.file}.`,
    `// Stubs the '${driver}' driver with a recorder and calls the handler with a`,
    '// payload carrying SQL syntax. The marker is written only if the payload',
    '// arrived inside the QUERY TEXT — a bound parameter proves the opposite.',
    importLine,
    "import fs from 'node:fs';",
    'await new Promise((resolve) => {',
    '  let timer = null;',
    '  const done = () => { clearTimeout(timer); resolve(); };',
    '  const res = {',
    '    send: done, json: done, end: done,',
    '    status: () => ({ send: done, json: done, end: done }),',
    '  };',
    `  const req = { ${src.prop}: ${JSON.stringify({ [src.key]: payload })} };`,
    '  timer = setTimeout(resolve, 3000);',   // armed before the call, see the webhook template
    `  try { ${invoke}(req, res); } catch { done(); }`,
    '});',
    '',
    '// The whole decision, stated once: sentinel inside a SQL string is the bug;',
    '// sentinel inside a params array is the fix.',
    'let proven = false;',
    'try {',
    `  for (const line of fs.readFileSync(${JSON.stringify(SQL_LOG)}, 'utf8').split('\\n')) {`,
    '    if (!line.trim()) continue;',
    '    const rec = JSON.parse(line);',
    '    for (const s of rec.strings) {',
    `      if (s.includes(${JSON.stringify(SQL_SENTINEL)}) && /\\b(?:select|insert|update|delete|from|where)\\b/i.test(s)) proven = true;`,
    '    }',
    '  }',
    '} catch {}',
    `if (proven) fs.writeFileSync('${MARKER}', 'x');`,
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js', kind: 'in-process', family: finding.family, cwe: finding.cwe || null,
      marker: MARKER, paramKey: src.key, paramSource: src.prop, handler: handlerLabel,
      driver,
      observes: 'the request payload reached the database driver inside the SQL text rather than as a bound parameter',
      requires: [base],
      // The stub replaces the real package. Resolution finds `index.js` in a
      // package directory with no package.json, which is why no manifest is
      // written — one more file that could disagree with itself.
      extraFiles: { [`node_modules/${driver}/index.js`]: DRIVER_STUB },
      code,
    },
  };
}


// ── Path traversal, proven by reading a file outside the served directory ───
//
// The proof is a specific observable fact: content the handler had no business
// serving came back out of it. The PoC plants a sentinel file at the sandbox
// root, asks the handler for it by a path that has to climb out of the served
// directory to reach it, and writes the marker only if the sentinel's own
// content (or, for `sendFile`, the sentinel's resolved path) comes back.
//
// NO SOURCE-INSPECTION REFUSAL HERE, unlike the webhook class. There, a file
// mentioning signature verification left a question execution could not settle,
// so the template refused. Here execution settles it completely: a handler that
// normalises the path returns nothing, and that is a real `proof-failed` about
// the finding rather than a harness artefact. The template only refuses shapes
// whose FAILURE would be about the harness.
const TRAVERSAL_SENTINEL = 'PROVEN_TRAVERSAL_SENTINEL_CONTENT';
const READ_SINK = /\b(?:readFile|readFileSync|sendFile|readFileAsync)\s*\(/;


// ── LDAP injection (CWE-90) ────────────────────────────────────────────────
//
// Added because `ldap-injection` was the largest UNCLASSIFIED family in the
// published proof-coverage breakdown (10 of 280 corpus findings) and it has the
// same property that makes SQL provable: a decidable boundary where the
// question is settled without a running directory server.
//
// For SQL the question is "did the payload arrive as query TEXT or as a bound
// parameter". For LDAP it is "did the payload's filter METACHARACTERS survive".
// A correctly escaped value still contains the sentinel — `ldap_escape`,
// `EqualityFilter` and friends escape `(`, `)`, `*` and `\` to `\28`, `\29`,
// `\2a`, `\5c` — so matching the sentinel alone would call a FIXED handler
// vulnerable. The proof requires the sentinel AND an unescaped metacharacter in
// the same filter string.
const LDAP_SENTINEL = 'PROVEN_LDAPI';
// RELATIVE, like SQL_LOG. An absolute path (/tmp/...) is denied by the
// confinement backend, so the recorder silently wrote nothing and the proof
// came back proof-failed on a genuinely vulnerable handler — the sandbox
// working exactly as intended, and a reminder that a PoC must live entirely
// inside the sandbox root.
const LDAP_LOG = 'ldap-calls.jsonl';
const LDAP_DRIVERS = ['ldapjs', 'ldap-authentication', 'activedirectory', 'activedirectory2', 'ldapts'];
const LDAP_DRIVER_RES = LDAP_DRIVERS.map((d) => [
  d, new RegExp(`require\\(\\s*['"\`]${d}['"\`]|from\\s*['"\`]${d}['"\`]`),
]);

const LDAP_STUB = [
  "const fs = require('fs');",
  'function record(args) {',
  '  const filters = [];',
  '  for (const a of args) {',
  "    if (typeof a === 'string') filters.push(a);",
  "    else if (a && typeof a === 'object') {",
  "      if (typeof a.filter === 'string') filters.push(a.filter);",
  "      if (a.filter && typeof a.filter === 'object' && typeof a.filter.toString === 'function') filters.push(String(a.filter));",
  '    }',
  '  }',
  '  if (filters.length) {',
  `    try { fs.appendFileSync(${JSON.stringify(LDAP_LOG)}, JSON.stringify({ filters }) + '\\n'); } catch {}`,
  '  }',
  '}',
  'const mk = () => new Proxy(function () {}, {',
  "  get(t, p) { if (typeof p === 'symbol' || p === 'then' || p === 'inspect') return undefined; return mk(); },",
  '  apply(t, self, args) {',
  '    record(args);',
  "    for (const a of args) if (typeof a === 'function') { try { a(null, { on: () => {} }); } catch {} }",
  '    return mk();',
  '  },',
  '});',
  'module.exports = mk();',
].join('\n');

function _ldapInjectionPoc(finding, fileContent) {
  const driver = (LDAP_DRIVER_RES.find(([, re]) => re.test(fileContent)) || [])[0];
  if (!driver) {
    return {
      ok: false,
      reason: `no recognised LDAP client is required by this file, so there is no boundary to observe the filter at (looked for: ${LDAP_DRIVERS.join(', ')})`,
    };
  }
  const found = _findHandler(fileContent);
  if (!found) return NO_HANDLER;
  const { call, reqIdent } = found;

  const src = _requestSource(fileContent, reqIdent, finding.line);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the injection point is unknown` };
  }

  const { base, importLine, invoke, handlerLabel } = _binding(finding, call);
  // Filter metacharacters plus the sentinel. An escaping handler keeps the
  // sentinel and neutralises the parens/star, which is exactly the difference
  // the decision below reads.
  const payload = `*)(uid=*))(|(uid=*${LDAP_SENTINEL}`;
  // The distinctive raw tail of that payload. Present verbatim only if no
  // escaping happened between the request and the client.
  const RAW_TAIL = `)(|(uid=*${LDAP_SENTINEL}`;

  const code = [
    `// Auto-generated proof for ${finding.file}.`,
    `// Stubs the '${driver}' client with a recorder and calls the handler with a`,
    '// payload carrying LDAP filter metacharacters. The marker is written only if',
    '// those metacharacters reached the filter UNESCAPED — an escaped value still',
    '// carries the sentinel, so the sentinel alone proves nothing.',
    importLine,
    "import fs from 'node:fs';",
    'await new Promise((resolve) => {',
    '  let timer = null;',
    '  const done = () => { clearTimeout(timer); resolve(); };',
    '  const res = {',
    '    send: done, json: done, end: done,',
    '    status: () => ({ send: done, json: done, end: done }),',
    '  };',
    `  const req = { ${src.prop}: ${JSON.stringify({ [src.key]: payload })} };`,
    '  timer = setTimeout(resolve, 3000);',
    `  try { ${invoke}(req, res); } catch { done(); }`,
    '});',
    '',
    '// The whole decision, stated once: did the PAYLOAD\'s OWN metacharacters',
    '// survive verbatim? Looking for any raw paren near the sentinel does not',
    '// work — the application\'s filter template (\'(uid=\' + v + \')\') always',
    '// contributes raw parens of its own, so that test called an ESCAPING',
    '// handler vulnerable. Escaping rewrites the payload tail to \\2a\\29\\28…,',
    '// so its verbatim presence is the bug and its absence is the fix working.',
    'let proven = false;',
    'try {',
    `  for (const line of fs.readFileSync(${JSON.stringify(LDAP_LOG)}, 'utf8').split('\\n')) {`,
    '    if (!line.trim()) continue;',
    '    const rec = JSON.parse(line);',
    `    for (const f of rec.filters) if (f.includes(${JSON.stringify(RAW_TAIL)})) proven = true;`,
    '  }',
    '} catch {}',
    `if (proven) fs.writeFileSync('${MARKER}', 'x');`,
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js', kind: 'in-process', family: finding.family, cwe: finding.cwe || null,
      marker: MARKER, paramKey: src.key, paramSource: src.prop, handler: handlerLabel,
      driver,
      observes: 'the request payload reached the LDAP client with its filter metacharacters unescaped',
      requires: [base],
      extraFiles: { [`node_modules/${driver}/index.js`]: LDAP_STUB },
      code,
    },
  };
}


// ── XXE (CWE-611) ──────────────────────────────────────────────────────────
//
// The third-largest unclassified family in the published proof-coverage
// breakdown. It is provable in-process for a reason the SSRF class is NOT: the
// external entity can point at a LOCAL file the harness plants inside the
// sandbox, so the proof needs no network and a failed fetch can never be
// confinement talking.
//
// The decision is whether the parser RESOLVED the entity. The sentinel content
// lives only in a file the XML never contains, so its presence in the parsed
// output means the parser went and read it — which is the vulnerability. A
// parser with entity expansion off returns the entity unexpanded (or throws),
// and neither writes the marker.
const XXE_SENTINEL = 'PROVEN_XXE_ENTITY_RESOLVED';
const XXE_SENTINEL_FILE = 'xxe-sentinel.txt';
const XXE_PARSERS = ['libxmljs', 'libxmljs2', '@xmldom/xmldom', 'xmldom', 'node-expat'];
const XXE_PARSER_RES = XXE_PARSERS.map((d) => [
  d, new RegExp(`require\\(\\s*['"\`]${d.replace('/', '\\/')}['"\`]|from\\s*['"\`]${d.replace('/', '\\/')}['"\`]`),
]);

function _xxePoc(finding, fileContent) {
  const parser = (XXE_PARSER_RES.find(([, re]) => re.test(fileContent)) || [])[0];
  if (!parser) {
    return {
      ok: false,
      reason: `no recognised XML parser is required by this file, so there is nothing to observe entity resolution at (looked for: ${XXE_PARSERS.join(', ')})`,
    };
  }
  const found = _findHandler(fileContent);
  if (!found) return NO_HANDLER;
  const { call, reqIdent } = found;

  const src = _requestSource(fileContent, reqIdent, finding.line);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the XML entry point is unknown` };
  }

  const { base, importLine, invoke, handlerLabel } = _binding(finding, call);
  const xml = `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://./${XXE_SENTINEL_FILE}">]><r>&x;</r>`;

  const code = [
    `// Auto-generated proof for ${finding.file}.`,
    '// Plants a sentinel file, hands the handler XML whose external entity points',
    '// at it, and writes the marker only if the SENTINEL CONTENT comes back —',
    '// which can only happen if the parser resolved the entity and read the file.',
    '// A parser with entity expansion disabled returns it unexpanded or throws.',
    importLine,
    "import fs from 'node:fs';",
    `fs.writeFileSync(${JSON.stringify(XXE_SENTINEL_FILE)}, ${JSON.stringify(XXE_SENTINEL)});`,
    'let seen = "";',
    'await new Promise((resolve) => {',
    '  let timer = null;',
    '  const capture = (v) => { try { seen += typeof v === "string" ? v : JSON.stringify(v); } catch {} clearTimeout(timer); resolve(); };',
    '  const res = {',
    '    send: capture, json: capture, end: capture,',
    '    status: () => ({ send: capture, json: capture, end: capture }),',
    '  };',
    `  const req = { ${src.prop}: ${JSON.stringify({ [src.key]: xml })} };`,
    '  timer = setTimeout(resolve, 3000);',
    `  try { const r = ${invoke}(req, res); if (r && typeof r.then === "function") r.then(capture, () => resolve()); } catch { resolve(); }`,
    '});',
    '',
    '// The whole decision, stated once: the sentinel STRING is only reachable by',
    '// reading the planted file. Matching the entity name or the XML itself would',
    '// be satisfied by a parser that never expanded anything.',
    `if (seen.includes(${JSON.stringify(XXE_SENTINEL)})) fs.writeFileSync('${MARKER}', 'x');`,
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js', kind: 'in-process', family: finding.family, cwe: finding.cwe || null,
      marker: MARKER, paramKey: src.key, paramSource: src.prop, handler: handlerLabel,
      driver: parser,
      observes: 'the XML parser resolved an external entity and returned the contents of a local file',
      requires: [base],
      code,
    },
  };
}

function _pathTraversalPoc(finding, fileContent) {
  const found = _findHandler(fileContent);
  if (!found) return NO_HANDLER;
  const { call, reqIdent } = found;

  // Checked BEFORE the read-sink refusal: a streamed handler reads its file
  // through `createReadStream`, so the generic "no read sink" message would be
  // both wrong and the one the reader sees.
  //
  // A streamed response is written to a real socket. The fake response object
  // cannot be piped into, so the PoC would fail for harness reasons — which
  // would be recorded as `proof-failed`, a claim about the finding.
  if (/\.pipe\s*\(|createReadStream\s*\(/.test(fileContent)) {
    return { ok: false, reason: 'the response is streamed; a failure against the in-process response object would be the harness talking, not the finding' };
  }
  if (!READ_SINK.test(fileContent)) {
    return { ok: false, reason: 'no readFile/sendFile sink in the file, so there is no served content to observe coming back' };
  }
  const src = _requestSource(fileContent, reqIdent, finding.line);
  if (!src) {
    return { ok: false, reason: `the handler does not read query/body/params off '${reqIdent}', so the traversal point is unknown` };
  }

  const { base, importLine, invoke, handlerLabel } = _binding(finding, call);

  const code = [
    `// Auto-generated proof for ${finding.file}.`,
    '// Plants a sentinel file outside the served directory and asks the handler',
    `// for it. The marker '${MARKER}' is written only if the sentinel's own`,
    '// content — or the path it resolves to — comes back out of the handler.',
    importLine,
    "import fs from 'node:fs';",
    "import path from 'node:path';",
    `const SENTINEL = ${JSON.stringify(TRAVERSAL_SENTINEL)};`,
    "const file = 'traversal-sentinel.txt';",
    'fs.writeFileSync(file, SENTINEL);',
    'const target = path.resolve(file);',
    '',
    '// Both shapes a vulnerable handler falls to: an absolute path (string',
    "// concatenation, or a read with no join at all) and a climb out of the",
    '// served directory. The depth is unknown, so a few are tried; every one of',
    '// them resolves inside the sandbox root or fails harmlessly.',
    'const candidates = [target];',
    "for (let i = 1; i <= 6; i++) candidates.push('../'.repeat(i) + file);",
    '',
    'let proven = false;',
    'for (const candidate of candidates) {',
    '  if (proven) break;',
    '  const seen = [];',
    '  await new Promise((resolve) => {',
    '    let timer = null;',
    '    const done = () => { clearTimeout(timer); resolve(); };',
    '    const capture = (v) => { if (v !== undefined && v !== null) seen.push(v); done(); };',
    '    const res = {',
    '      send: capture, json: capture, end: capture, write: capture,',
    '      sendFile: capture, download: capture,',
    '      status: () => ({ send: capture, json: capture, end: capture }),',
    '      setHeader: () => {}, type: () => res, set: () => res,',
    '    };',
    `    const req = { ${src.prop}: { ${JSON.stringify(src.key)}: candidate } };`,
    '    timer = setTimeout(resolve, 3000);',   // armed before the call
    `    try { ${invoke}(req, res); } catch { done(); }`,
    '  });',
    '  for (const v of seen) {',
    "    const s = Buffer.isBuffer(v) ? v.toString('utf8') : typeof v === 'string' ? v : JSON.stringify(v) || '';",
    '    // Content coming back is the direct proof.',
    '    if (s.includes(SENTINEL)) { proven = true; break; }',
    '    // `sendFile` hands back a path, not content: the handler resolving the',
    '    // request to the sentinel OUTSIDE its directory is the same fact.',
    '    try { if (s && path.resolve(s) === target) { proven = true; break; } } catch {}',
    '  }',
    '}',
    `if (proven) fs.writeFileSync('${MARKER}', 'x');`,
  ].join('\n');

  return {
    ok: true,
    poc: {
      lang: 'js', kind: 'in-process', family: finding.family, cwe: finding.cwe || null,
      marker: MARKER, paramKey: src.key, paramSource: src.prop, handler: handlerLabel,
      observes: 'the handler returned a file from outside the directory it serves',
      requires: [base], code,
    },
  };
}


// Exported last: the template constants below are `const` in TDZ until their
// declarations are evaluated.
export const _internals = {
  MARKER, SUPPORTED, _requestSource, SQL_DRIVERS, SQL_SENTINEL, TRAVERSAL_SENTINEL,
  behaviouralFamilies: () => [...BEHAVIOURAL.keys()],
};
