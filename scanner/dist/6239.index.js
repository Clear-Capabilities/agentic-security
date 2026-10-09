export const id = 6239;
export const ids = [6239];
export const modules = {

/***/ 56239:
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

// ESM COMPAT FLAG
__webpack_require__.r(__webpack_exports__);

// EXPORTS
__webpack_require__.d(__webpack_exports__, {
  MANIFEST_SCHEMA: () => (/* binding */ MANIFEST_SCHEMA),
  getOracle: () => (/* binding */ getOracle),
  listOracles: () => (/* binding */ listOracles),
  manifestEntry: () => (/* binding */ manifestEntry),
  oracleManifest: () => (/* binding */ oracleManifest)
});

// EXTERNAL MODULE: ./src/posture/oracles/oracle.js + 4 modules
var oracle = __webpack_require__(80219);
// EXTERNAL MODULE: ./src/posture/assurance/identity.js
var identity = __webpack_require__(41877);
;// CONCATENATED MODULE: ./src/posture/oracles/adapters.js
// The five class-specific oracle adapters (X-202.AC01).
//
// Each adapter is data plus three small functions, all verifier-authored:
//   harnessSource  the script the boundary runs. It imports the target, drives it
//                  with a benign CONTROL input first and the hostile input second,
//                  and writes a result document. It never decides a verdict.
//   prepare        builds the harness input from the request inputs plus a
//                  per-run token the target cannot know in advance.
//   interpret      forms `{ satisfied, preconditionsHeld, observed, reason }` from
//                  what the run left behind, read by the verifier after the whole
//                  process tree is dead. `satisfied: true` means the hypothesised
//                  effect was observed; `false` with `preconditionsHeld: true`
//                  means it was not observed although the control proved the
//                  target was exercised (a refutation); anything else leaves the
//                  verdict open.
//
// Changing what an adapter asserts means bumping its `version`: the version and
// the harness text feed `logicDigest`, which replay manifests pin.
//
// Platform statements are about what this repository's tests have executed. The
// development host is macOS, so Linux is declared `unverified` everywhere: on
// Linux the boundary currently refuses to run (read denial and supervised
// tree termination are not implemented on the namespace backend), which the
// runner reports as `unsupported`, and no Linux outcome is claimed.



const PLATFORMS = Object.freeze({
  darwin: { status: 'supported', note: 'executed by this repository\'s tests on the macOS development host (userspace confinement backend)' },
  linux: { status: 'unverified', note: 'no Linux outcome is claimed: the boundary refuses to run on the namespace backend until read denial and supervised tree termination are implemented and executed there; the run reports unsupported' },
  win32: { status: 'unsupported', note: 'no confinement backend exists for Windows' },
});

const COMMON_BUDGETS = Object.freeze({ timeoutMs: 8000, graceMs: 1000, maxOutputBytes: 65536, maxFileBytes: 262144, maxFiles: 32 });

const PROLOGUE = `import fs from 'node:fs';
const INPUT = __INPUT__;
const ENTRY = __ENTRY__;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const text = (e) => String((e && e.message) || e).slice(0, 160);
const out = {};
function finish(extra) {
  Object.assign(out, extra);
  try { fs.writeFileSync('__oracle_result.json', JSON.stringify(out)); } catch {}
  process.exit(0);
}
let mod;
try { mod = await import('./' + ENTRY); } catch (e) { finish({ loadFailed: true }); }
const fn = mod && mod[INPUT.export];
if (typeof fn !== 'function') finish({ loadFailed: true });
`;

const isId = (s) => typeof s === 'string' && /^[A-Za-z_$][\w$]{0,63}$/.test(s);
const isStr = (s, max = 2000) => typeof s === 'string' && s.length > 0 && s.length <= max;

// ------------------------------------------------------------------ injection execution

const injection = (0,oracle/* defineOracle */.IL)({
  id: 'injection-execution', class: 'injection-execution', version: '1',
  description: 'Does attacker-controlled input reach a command interpreter and run? The harness calls the target with a benign control, then with a payload whose effect is a token-named file; the verifier looks for that file after the process tree is dead.',
  prerequisites: ['node-runtime', 'confinement-backend', 'posix-shell'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'argv-array-call', description: 'the same handler passing the input as a separate argv element (no shell) must not produce the effect', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/injection-execution', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['covers command injection through a shell only; SQL, template and code injection are not asserted here', 'the target is imported into the harness process, so it runs with the harness; a target written to recognise the payload and forge the effect file is not distinguishable from a real injection', 'asynchronous handlers that spawn without being awaited are given settleMs to finish, not guaranteed to'],
  harnessSource: `${PROLOGUE}
try { await Promise.resolve(fn(INPUT.benign)); out.controlOk = true; } catch (e) { out.controlOk = false; }
if (out.controlOk) {
  try { await Promise.resolve(fn(INPUT.attack)); out.attackReturned = true; } catch (e) { out.attackReturned = false; }
  await sleep(INPUT.settleMs);
}
finish({});
`,
  validateInputs(i) {
    if (!isId(i.export)) return 'export must be an identifier';
    if (!isStr(i.benign, 500)) return 'benign must be a short string';
    if (!isStr(i.attackTemplate, 500) || !i.attackTemplate.includes('{TOKEN}')) return 'attackTemplate must be a short string containing {TOKEN}';
    if (i.settleMs !== undefined && !(Number.isInteger(i.settleMs) && i.settleMs >= 0 && i.settleMs <= 2000)) return 'settleMs must be 0 to 2000';
    return null;
  },
  prepare: (i, token) => ({ export: i.export, benign: i.benign, attack: i.attackTemplate.split('{TOKEN}').join(token), settleMs: i.settleMs ?? 300 }),
  interpret({ token, result, read }) {
    const effect = read(`effect-${token}`, 256) === token;
    const controlOk = result?.controlOk === true;
    const observed = { effectObserved: effect, controlCompleted: controlOk, targetLoaded: result ? result.loadFailed !== true : null };
    if (effect) return { satisfied: true, preconditionsHeld: true, observed, reason: 'the injected command ran: its token-named effect file exists' };
    if (controlOk) return { satisfied: false, preconditionsHeld: true, observed, reason: 'the handler ran its benign control and the injected command left no effect' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: result?.loadFailed ? 'the target failed to load, so the payload was never delivered' : 'the benign control did not complete, so the payload was never delivered' };
  },
});

// ------------------------------------------------------------------ authorization decision

const DECISIONS = ['allow', 'deny', 'error', 'indeterminate'];

const authorization = (0,oracle/* defineOracle */.IL)({
  id: 'authorization-decision', class: 'authorization-decision', version: '1',
  description: 'Does an authorization function allow an actor it should deny? The harness evaluates declared control cases (the owner, expected allow) and attack cases (another tenant or a lower role, expected deny); the verifier recomputes the verdict from the raw decisions.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'tenant-checked', description: 'the same function comparing tenant ids must deny the cross-tenant attack case', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/authorization-decision', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['asserts the decision function in isolation; a route or middleware that enforces authorization elsewhere is not exercised', 'the cases describe the scenario; the oracle does not infer which actors should be denied', 'a thrown error is not read as a denial'],
  harnessSource: `${PROLOGUE}
const norm = (r) => (r === true || r === 'allow' || (r && r.allowed === true)) ? 'allow'
  : (r === false || r === 'deny' || (r && r.allowed === false)) ? 'deny' : 'indeterminate';
const decisions = {};
for (const c of INPUT.cases) {
  try { decisions[c.id] = norm(await Promise.resolve(fn(...c.args))); } catch (e) { decisions[c.id] = 'error'; }
}
finish({ decisions });
`,
  validateInputs(i) {
    if (!isId(i.export)) return 'export must be an identifier';
    if (!Array.isArray(i.cases) || i.cases.length < 2 || i.cases.length > 16) return 'cases must hold 2 to 16 entries';
    const ids = new Set();
    for (const c of i.cases) {
      if (!c || !isId(String(c.id).replace(/-/g, '_')) || ids.has(c.id)) return 'every case needs a unique id';
      ids.add(c.id);
      if (!['control', 'attack'].includes(c.role)) return 'case role must be control or attack';
      if (!Array.isArray(c.args) || c.args.length > 6) return 'case args must be an array of at most 6';
    }
    if (!i.cases.some((c) => c.role === 'control') || !i.cases.some((c) => c.role === 'attack')) return 'at least one control and one attack case are required';
    return null;
  },
  prepare: (i) => ({ export: i.export, cases: i.cases.map((c) => ({ id: c.id, args: c.args })) }),
  interpret({ inputs, result }) {
    const got = result && result.decisions && typeof result.decisions === 'object' ? result.decisions : null;
    if (!got || result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false }, reason: 'the target did not report decisions' };
    const decisions = {};
    for (const c of inputs.cases) decisions[c.id] = DECISIONS.includes(got[c.id]) ? got[c.id] : 'indeterminate';
    const controls = inputs.cases.filter((c) => c.role === 'control');
    const attacks = inputs.cases.filter((c) => c.role === 'attack');
    const controlsHeld = controls.every((c) => decisions[c.id] === 'allow');
    const allowed = attacks.filter((c) => decisions[c.id] === 'allow').map((c) => c.id);
    const allDenied = attacks.every((c) => decisions[c.id] === 'deny');
    const observed = { decisions, controlsAllowed: controlsHeld, attackCasesAllowed: allowed };
    if (allowed.length) return { satisfied: true, preconditionsHeld: controlsHeld, observed, reason: `the function allowed attack case(s): ${allowed.join(', ')}` };
    if (allDenied && controlsHeld) return { satisfied: false, preconditionsHeld: true, observed, reason: 'every attack case was denied and every control case was allowed' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: controlsHeld ? 'an attack case returned neither allow nor deny' : 'a control case was not allowed, so the function was not shown to be deciding' };
  },
});

// ------------------------------------------------------------------ state transition

const stateTransition = (0,oracle/* defineOracle */.IL)({
  id: 'state-transition', class: 'state-transition', version: '1',
  description: 'Does a state machine accept an event sequence that must be refused? The harness drives a fresh machine through the legal sequence (control) and a fresh one through the attack sequence; the verifier compares the final states.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'payment-required', description: 'the same machine refusing shipment before payment must not reach the forbidden state', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/state-transition', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['covers one factory and finite event lists; it is not a model checker', 'durable effects outside the machine object (a database row, a queued job) are not observed', 'the forbidden state is stated by the scenario; the oracle does not infer business rules'],
  harnessSource: `${PROLOGUE}
async function drive(events) {
  const m = await Promise.resolve(fn());
  const accepted = [];
  for (const e of events) {
    try { const r = await Promise.resolve(m.send(e)); accepted.push(r !== false); } catch (err) { accepted.push(false); }
  }
  return { state: String(m.state).slice(0, 80), accepted };
}
try { const c = await drive(INPUT.legal); out.controlState = c.state; } catch (e) { out.controlState = null; }
try { const a = await drive(INPUT.attack); out.attackState = a.state; out.attackAccepted = a.accepted; } catch (e) { out.attackState = null; }
finish({});
`,
  validateInputs(i) {
    if (!isId(i.factory)) return 'factory must be an identifier';
    const evs = (a) => Array.isArray(a) && a.length >= 1 && a.length <= 16 && a.every((e) => isStr(e, 64));
    if (!evs(i.legal) || !evs(i.attack)) return 'legal and attack must be lists of 1 to 16 short event names';
    if (!isStr(i.expectedFinal, 64) || !isStr(i.forbiddenState, 64)) return 'expectedFinal and forbiddenState are required';
    return null;
  },
  prepare: (i) => ({ export: i.factory, legal: i.legal, attack: i.attack }),
  interpret({ inputs, result }) {
    if (!result || result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false }, reason: 'the target failed to load' };
    const controlHeld = result.controlState === inputs.expectedFinal;
    const reached = result.attackState === inputs.forbiddenState;
    const observed = { controlState: result.controlState ?? null, controlReachedExpected: controlHeld, attackState: result.attackState ?? null, attackAccepted: Array.isArray(result.attackAccepted) ? result.attackAccepted.slice(0, 16).map((b) => b === true) : [] };
    if (reached) return { satisfied: true, preconditionsHeld: controlHeld, observed, reason: `the attack sequence reached the forbidden state '${inputs.forbiddenState}'` };
    if (controlHeld) return { satisfied: false, preconditionsHeld: true, observed, reason: 'the legal sequence reached its expected state and the attack sequence did not reach the forbidden one' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: 'the legal sequence did not reach its expected state, so the machine was not shown to be working' };
  },
});

// ------------------------------------------------------------------ side-effect reachability

const sideEffect = (0,oracle/* defineOracle */.IL)({
  id: 'side-effect-reachability', class: 'side-effect-reachability', version: '1',
  description: 'Does attacker-chosen input reach a privileged side-effecting operation? The harness injects a recording stand-in for the sink, calls the handler with a benign value (control) and an attacker value, and the verifier checks which values reached the sink.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'allowlisted-target', description: 'the same handler with a destination allowlist must not pass the attacker value to the sink', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/side-effect-reachability', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['the sink is a recording stand-in injected as the handler\'s second argument; handlers that import their sink directly are not covered', 'reaching the sink shows the operation would be invoked with the attacker value, not that the real operation would succeed', 'no network or privileged call is ever made'],
  harnessSource: `${PROLOGUE}
const calls = [];
const deps = { [INPUT.sink]: (...args) => { try { calls.push(JSON.stringify(args).slice(0, 600)); } catch {} return Promise.resolve({ ok: true, status: 200, text: async () => '' }); } };
const reached = (v) => calls.some((c) => c.includes(JSON.stringify(v).slice(1, -1)));
try { await Promise.resolve(fn(INPUT.benignValue, deps)); } catch (e) {}
out.benignReached = reached(INPUT.benignValue);
calls.length = 0;
try { await Promise.resolve(fn(INPUT.attackerValue, deps)); } catch (e) {}
out.attackReached = reached(INPUT.attackerValue);
finish({});
`,
  validateInputs(i) {
    if (!isId(i.export) || !isId(i.sink)) return 'export and sink must be identifiers';
    if (!isStr(i.benignValue, 500) || !isStr(i.attackerValue, 500) || i.benignValue === i.attackerValue) return 'benignValue and attackerValue must be distinct short strings';
    return null;
  },
  prepare: (i) => ({ export: i.export, sink: i.sink, benignValue: i.benignValue, attackerValue: i.attackerValue }),
  interpret({ result }) {
    if (!result || result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false }, reason: 'the target failed to load' };
    const benign = result.benignReached === true;
    const attack = result.attackReached === true;
    const observed = { benignReachedSink: benign, attackerValueReachedSink: attack };
    if (attack) return { satisfied: true, preconditionsHeld: benign, observed, reason: 'the attacker-chosen value reached the side-effecting sink' };
    if (benign) return { satisfied: false, preconditionsHeld: true, observed, reason: 'the benign value reached the sink and the attacker value did not' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: 'even the benign value never reached the sink, so the handler was not shown to use it' };
  },
});

// ------------------------------------------------------------------ parser / resource behaviour

const parserResource = (0,oracle/* defineOracle */.IL)({
  id: 'parser-resource', class: 'parser-resource', version: '1',
  description: 'Does a parser or matcher exhaust its budget on a bounded hostile input? The harness completes a benign control (marker file), then feeds the hostile input; the verifier\'s own supervisor deadline is the measurement, so no self-reported timing is trusted.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: { ...COMMON_BUDGETS, timeoutMs: 5000 },
  negativeControls: [{ id: 'linear-pattern', description: 'the same matcher written without nested quantifiers must finish the hostile input inside the budget', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/parser-resource', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['the hostile input is bounded (at most 64 KiB) and the run is cut at the supervisor deadline; this shows a budget was exceeded, not how large the blow-up is', 'a hard crash without a deadline or output-cap hit is left inconclusive rather than called exhaustion', 'memory is not measured: address-space limits are not enforceable on the macOS backend'],
  harnessSource: `${PROLOGUE}
const mark = (name) => { try { fs.writeFileSync(name, INPUT.token); } catch {} };
try { await Promise.resolve(fn(INPUT.benign)); mark('__oracle_benign_done'); } catch (e) { finish({ benignFailed: true }); }
try { await Promise.resolve(fn(INPUT.hostile)); } catch (e) {}
mark('__oracle_hostile_done');
finish({});
`,
  validateInputs(i) {
    if (!isId(i.export)) return 'export must be an identifier';
    if (!isStr(i.benign, 500)) return 'benign must be a short string';
    const h = i.hostile;
    if (!h || !isStr(h.unit, 16) || !Number.isInteger(h.count) || h.count < 1 || h.count > 65536 || (h.suffix !== undefined && !isStr(h.suffix, 16))) return 'hostile needs unit (short), count (1 to 65536) and an optional short suffix';
    return null;
  },
  prepare: (i, token) => ({ export: i.export, benign: i.benign, hostile: i.hostile.unit.repeat(i.hostile.count) + (i.hostile.suffix || ''), token }),
  interpret({ token, run, read }) {
    const benignDone = read('__oracle_benign_done', 128) === token;
    const hostileDone = read('__oracle_hostile_done', 128) === token;
    const observed = { benignCompleted: benignDone, hostileCompleted: hostileDone, deadlineHit: run.timedOut, outputCapHit: run.outputCapped };
    if (!benignDone) return { satisfied: null, preconditionsHeld: false, observed, reason: 'the benign control did not complete, so the target was not shown to be working' };
    if (hostileDone) return { satisfied: false, preconditionsHeld: true, observed, reason: 'the hostile input was handled inside the budget' };
    if (run.timedOut || run.outputCapped) return { satisfied: true, preconditionsHeld: true, observed, reason: run.timedOut ? 'the hostile input exhausted the time budget (the supervisor deadline fired)' : 'the hostile input exhausted the output budget' };
    return { satisfied: null, preconditionsHeld: true, observed, reason: 'the run ended without finishing the hostile input and without hitting a budget, so the cause is unknown' };
  },
});

// ------------------------------------------------------------------ replay / idempotency (X-205)

const replayIdempotency = (0,oracle/* defineOracle */.IL)({
  id: 'replay-idempotency', class: 'replay-idempotency', version: '1',
  description: 'Does delivering the same request again repeat its side effect? The harness builds a fresh handler around a recording stand-in for the effect, delivers a request and then a DISTINCT request (control: one effect each), then on a second fresh handler delivers the same request repeatedly; the verifier counts the effects.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'idempotency-key-honoured', description: 'the same handler remembering the idempotency key must produce exactly one effect for the repeated request', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/replay-idempotency', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['the target is a factory that receives a recording stand-in for its effect and returns a handler; code that imports its effect directly is not covered', 'deliveries are sequential: a race between concurrent deliveries is not exercised', 'durable deduplication in an external store is not observed, only the handler instance the factory returns', 'reaching the effect twice shows the handler would repeat it, not that the real operation would succeed'],
  harnessSource: `${PROLOGUE}
const mk = () => { const calls = []; return { calls, deps: { [INPUT.sink]: (...a) => { calls.push(1); return Promise.resolve({ ok: true }); } } }; };
async function build() { const m = mk(); const h = await Promise.resolve(fn(m.deps)); if (typeof h !== 'function') throw new Error('not a handler'); return { m, h }; }
try {
  const c = await build();
  try { await Promise.resolve(c.h(INPUT.request)); } catch (e) {}
  out.firstEffects = c.m.calls.length;
  try { await Promise.resolve(c.h(INPUT.distinctRequest)); } catch (e) {}
  out.distinctEffects = c.m.calls.length;
} catch (e) { out.controlFailed = true; }
try {
  const a = await build();
  for (let i = 0; i < INPUT.deliveries; i++) { try { await Promise.resolve(a.h(INPUT.request)); } catch (e) {} }
  out.replayEffects = a.m.calls.length;
} catch (e) { out.replayFailed = true; }
finish({});
`,
  validateInputs(i) {
    if (!isId(i.export) || !isId(i.sink)) return 'export and sink must be identifiers';
    const small = (v) => { try { const s = JSON.stringify(v); return typeof s === 'string' && s.length <= 2000 && v !== null && typeof v === 'object' && !Array.isArray(v); } catch { return false; } };
    if (!small(i.request) || !small(i.distinctRequest)) return 'request and distinctRequest must be small JSON objects';
    if ((0,identity/* digestOf */.ol)(i.request) === (0,identity/* digestOf */.ol)(i.distinctRequest)) return 'distinctRequest must differ from request';
    if (!(Number.isInteger(i.deliveries) && i.deliveries >= 2 && i.deliveries <= 6)) return 'deliveries must be 2 to 6';
    return null;
  },
  prepare: (i) => ({ export: i.export, sink: i.sink, request: i.request, distinctRequest: i.distinctRequest, deliveries: i.deliveries }),
  interpret({ result }) {
    if (!result || result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false }, reason: 'the target failed to load' };
    const first = Number.isInteger(result.firstEffects) ? result.firstEffects : null;
    const distinct = Number.isInteger(result.distinctEffects) ? result.distinctEffects : null;
    const replay = Number.isInteger(result.replayEffects) ? result.replayEffects : null;
    const controlHeld = first === 1 && distinct === 2;
    const observed = { targetLoaded: true, firstDeliveryEffects: first, distinctDeliveryTotalEffects: distinct, repeatedDeliveryTotalEffects: replay, controlHeld };
    if (replay !== null && replay > 1) return { satisfied: true, preconditionsHeld: controlHeld, observed, reason: `the same request delivered repeatedly produced ${replay} effects` };
    if (controlHeld && replay === 1) return { satisfied: false, preconditionsHeld: true, observed, reason: 'a distinct request produced its own effect and the repeated request produced exactly one' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: controlHeld ? 'the repeated deliveries did not report' : 'the handler did not produce exactly one effect per first delivery, so it was not shown to be working' };
  },
});

// ------------------------------------------------------------------ functional regression (X-204)

const functionalRegression = (0,oracle/* defineOracle */.IL)({
  id: 'functional-regression', class: 'functional-regression', version: '1',
  description: 'Does a revision still behave as intended? The harness calls the exported function with declared cases and records each result; the verifier compares them with the declared expectations. The hypothesis is that the behaviour REGRESSED, so a patch is clean when this is refuted.',
  prerequisites: ['node-runtime', 'confinement-backend'],
  platforms: PLATFORMS, budgets: COMMON_BUDGETS,
  negativeControls: [{ id: 'behaviour-preserved', description: 'a revision that returns the expected value for every declared case must show no regression', expectedOutcome: 'refuted' }],
  fixtures: { dir: 'test/fixtures/oracles/functional-regression', positive: 'positive', negative: 'negative', inconclusive: 'inconclusive' },
  limitations: ['only the declared cases are checked: behaviour outside them is not observed, and a patch that breaks an undeclared path is not detected', 'results are compared as JSON values, so identity, ordering of unordered data and timing are not compared', 'the expectations are supplied by the requester and are not inferred; expectations that are wrong for the ORIGINAL revision are reported by the baseline check, not hidden'],
  harnessSource: `${PROLOGUE}
const results = {};
for (const c of INPUT.cases) {
  try { const v = await Promise.resolve(fn(...c.args)); results[c.id] = { ok: true, value: v === undefined ? null : JSON.parse(JSON.stringify(v)) }; }
  catch (e) { results[c.id] = { ok: false }; }
}
finish({ results });
`,
  validateInputs(i) {
    if (!isId(i.export)) return 'export must be an identifier';
    if (!Array.isArray(i.cases) || i.cases.length < 1 || i.cases.length > 16) return 'cases must hold 1 to 16 entries';
    const ids = new Set();
    for (const c of i.cases) {
      if (!c || typeof c.id !== 'string' || !/^[a-z0-9-]{1,40}$/.test(c.id) || ids.has(c.id)) return 'every case needs a unique slug id';
      ids.add(c.id);
      if (!Array.isArray(c.args) || c.args.length > 6) return 'case args must be an array of at most 6';
      if (!('expected' in c)) return 'every case needs an expected value';
      try { if (JSON.stringify(c.expected) === undefined) return 'expected must be JSON'; } catch { return 'expected must be JSON'; }
    }
    return null;
  },
  prepare: (i) => ({ export: i.export, cases: i.cases.map((c) => ({ id: c.id, args: c.args })) }),
  interpret({ inputs, result }) {
    const got = result && result.results && typeof result.results === 'object' ? result.results : null;
    if (!got || result.loadFailed) return { satisfied: null, preconditionsHeld: false, observed: { targetLoaded: false }, reason: 'the target did not report results' };
    const regressions = [];
    let reported = 0;
    for (const c of inputs.cases) {
      const r = got[c.id];
      if (!r || typeof r !== 'object') continue;
      reported++;
      if (r.ok !== true || (0,identity/* digestOf */.ol)(r.value) !== (0,identity/* digestOf */.ol)(c.expected)) regressions.push(c.id);
    }
    const complete = reported === inputs.cases.length;
    const observed = { targetLoaded: true, casesDeclared: inputs.cases.length, casesReported: reported, regressedCases: regressions };
    if (regressions.length) return { satisfied: true, preconditionsHeld: complete, observed, reason: `behaviour differs from the declared expectation in case(s): ${regressions.join(', ')}` };
    if (complete) return { satisfied: false, preconditionsHeld: true, observed, reason: 'every declared case returned its expected value' };
    return { satisfied: null, preconditionsHeld: false, observed, reason: 'not every declared case reported a result' };
  },
});

const ADAPTERS = Object.freeze([injection, authorization, stateTransition, sideEffect, parserResource, replayIdempotency, functionalRegression]);

// EXTERNAL MODULE: ./src/posture/oracles/scenario-classes.js
var scenario_classes = __webpack_require__(57430);
;// CONCATENATED MODULE: ./src/posture/oracles/registry.js
// The oracle registry and its manifest (X-202).
//
// The registry is built once, at module load, from the static adapter list and
// frozen. There is no registration function: a candidate worker (or anything at
// run time) cannot add, replace or edit an adapter, which is half of "workers
// cannot alter adapter logic". The other half is the harness digest check in
// `runOracle`.
//
// `oracleManifest()` is the machine-readable description X-208 gates a release on:
// per adapter, its class, declared prerequisites, platforms (with an honest status
// per platform), budgets, negative controls, fixture locations, limitations and
// the logic digest a replay manifest pins. It contains no function bodies and no
// host details, and its order is fixed, so it is byte-stable across runs.




const BY_ID = new Map(ADAPTERS.map((a) => [a.id, a]));
if (BY_ID.size !== ADAPTERS.length) throw new Error('duplicate oracle adapter id');

function getOracle(id) {
  return typeof id === 'string' && BY_ID.has(id) ? BY_ID.get(id) : null;
}

function listOracles() {
  return [...ADAPTERS].sort((a, b) => a.id.localeCompare(b.id));
}

const MANIFEST_SCHEMA = 'agentic-security/oracle-manifest';

/** The manifest entry for one adapter: data only. */
function manifestEntry(a) {
  return {
    id: a.id, class: a.class, version: a.version, logicDigest: a.logicDigest, description: a.description,
    prerequisites: a.prerequisites.map((id) => ({ id, description: oracle/* PREREQUISITES */.sD[id].description })),
    platforms: a.platforms, budgets: a.budgets,
    negativeControls: a.negativeControls, fixtures: a.fixtures, limitations: a.limitations,
    receipts: 'issued by the verifier domain only (runOracle); a caller-supplied receipt is not valid',
  };
}

// X-205: the supported-class manifest for non-taint vulnerabilities. Each class names the adapter that executes it, whether
// that adapter was reused, its fixtures and the user-visible report text (prerequisites, platforms, limitations).
function scenarioClassEntries(adapters) {
  return scenario_classes/* SCENARIO_CLASSES */.ML.map((c) => {
    const a = adapters.find((x) => x.id === c.adapterId) || null;
    return {
      id: c.id, title: c.title, claim: c.claim, oracle: c.adapterId, adapterReuse: c.adapterReuse,
      requires: c.requires, limitations: c.limitations, fixtures: c.fixtures,
      prerequisites: a ? a.prerequisites.map((id) => ({ id, description: oracle/* PREREQUISITES */.sD[id].description })) : [],
      platforms: a ? a.platforms : null,
      report: (0,scenario_classes/* scenarioClassReportLines */.Uq)(c, a),
    };
  });
}

function oracleManifest(adapters = listOracles()) {
  const entries = adapters.map(manifestEntry);
  return {
    schema: MANIFEST_SCHEMA, schemaVersion: '1.0.0',
    classes: [...oracle/* ORACLE_CLASSES */.aI],
    oracles: entries,
    // Every class the PRD names must have an adapter; a missing one is stated, never implied.
    uncoveredClasses: oracle/* ORACLE_CLASSES */.aI.filter((c) => !adapters.some((a) => a.class === c)),
    problems: [
      ...adapters.flatMap((a) => (0,oracle/* validateOracleSpec */.GX)(a).map((p) => `${a.id}: ${p}`)),
      ...scenario_classes/* SCENARIO_CLASSES */.ML.filter((c) => !adapters.some((a) => a.id === c.adapterId)).map((c) => `scenario class ${c.id}: its oracle '${c.adapterId}' is not registered`),
    ],
    nonTaint: {
      schema: scenario_classes/* NON_TAINT_SCHEMA */.RF, schemaVersion: '1.0.0',
      classes: scenarioClassEntries(adapters),
      unsupported: scenario_classes/* UNSUPPORTED_NON_TAINT */.bm.map((u) => ({ id: u.id, cwes: u.cwes, reason: u.reason })),
      rules: ['taint absence never refutes a non-taint hypothesis', 'an unsupported or unrun case is never counted in the trusted-negative denominator'],
    },
  };
}


/***/ })

};
