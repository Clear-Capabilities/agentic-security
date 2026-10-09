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
import { defineOracle } from './oracle.js';

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

const injection = defineOracle({
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

const authorization = defineOracle({
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

const stateTransition = defineOracle({
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

const sideEffect = defineOracle({
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

const parserResource = defineOracle({
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

export const ADAPTERS = Object.freeze([injection, authorization, stateTransition, sideEffect, parserResource]);
