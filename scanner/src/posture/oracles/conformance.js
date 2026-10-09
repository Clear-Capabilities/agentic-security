// The oracle conformance suite (X-208).
//
// One reusable contract that every registered adapter must satisfy, used three ways: by the test suite (all registered
// adapters plus deliberately bad fakes), by the release gate (`scripts/verification-conformance-check.mjs`), and by a
// contributor adding an oracle (docs/guides/verification-oracle-conformance.md). It checks an adapter, it never grants one
// anything: it imports no registration function and adds no execution permission.
//
// Two layers, because they have different costs and different host requirements:
//
//   STATIC (`checkAdapterContract`, `checkFixturePins`): no execution, any host. An adapter must declare
//     - CLASS SCOPE: a known class, a stated status and note per platform (Linux never `supported`: no Linux enforcement is
//       verified by this build), stated limitations, and an existing fixture directory;
//     - RESOURCE BUDGETS: all five budgets finite, positive and under the hard ceilings below;
//     - NEGATIVE CONTROLS: at least one, each expecting `refuted`, and a negative fixture on disk that is a real file;
//     - AUTHORITATIVE EVIDENCE: verifier-authored `harnessSource`, `prepare` and `interpret` (the verdict is formed by the
//       verifier from what the run left behind, never by the target), and a `logicDigest` that matches its own logic;
//     - PINNED FIXTURES: the positive, negative and inconclusive fixtures and the scenario hash to the values committed in
//       `test/fixtures/oracles/conformance-pins.json`, together with the adapter's logic digest. A changed fixture or changed
//       adapter logic fails until someone re-pins it on purpose.
//
//   EXECUTION (`runAdapterConformance`): the adapter is run through `runOracle` and so through the trust boundary only.
//     - STATE MAPPING: positive confirms, negative refutes with proven preconditions, inconclusive stays open;
//     - RECEIPTS: the positive run's receipt is one `runOracle` issued (a copy is not), frozen, bound to the record id and the
//       logic digest, with trusted-runtime-proof evidence from the trusted runner and sanitized environment metadata;
//     - TAMPER: a target that rewrites the adapter harness yields `error` and no receipt; a target printing verdict-looking text
//       cannot move a refutation; an unavailable prerequisite is `unsupported`, executes nothing and issues no receipt;
//     - CANCELLATION: an aborted run is `inconclusive`, has no receipt and leaves no harness process behind;
//     - REPLAY: running the positive request again reproduces the outcome and the record id.
//   Where the boundary cannot run, execution is reported `not-run` with the reason; it is never reported as passed.
import fs from 'node:fs';
import path from 'node:path';
import { runOracle, validateOracleSpec, oracleLogicDigest, isIssuedReceipt, ORACLE_CLASSES, HARNESS_FILE, FEATURE_ID } from './oracle.js';
import { SCENARIO_CLASSES } from './scenario-classes.js';
import { digestOf } from '../assurance/identity.js';
import { validateVerificationRecord } from '../assurance/verification-record.js';
import { resolveAssuranceConfig } from '../assurance/config.js';
import { isPlainObject } from '../assurance/schema-kit.js';

const CONFORMANCE_SCHEMA = 'agentic-security/oracle-conformance';
export const PINS_FILE = 'test/fixtures/oracles/conformance-pins.json';

/** Hard ceilings the gate enforces on an adapter's declared budgets. A bigger budget is a bigger default execution permission. */
export const BUDGET_CEILINGS = Object.freeze({ timeoutMs: 60_000, graceMs: 10_000, maxOutputBytes: 1_048_576, maxFileBytes: 1_048_576, maxFiles: 64 });
const FIXTURE_KINDS = ['positive', 'negative', 'inconclusive'];
const CONFORMANCE_COMMIT = 'd'.repeat(40);

const entry = (check, ok, detail) => ({ check, ok: !!ok, detail });

// ---------------------------------------------------------------- static

/** Static contract problems for one adapter; `ok` only when every check passes. Never throws. */
export function checkAdapterContract(adapter, { scannerRoot } = {}) {
  const checks = [];
  try {
    if (!isPlainObject(adapter)) return { id: null, ok: false, checks: [entry('spec', false, 'adapter must be an object')] };
    const spec = { ...adapter }; delete spec.logicDigest;
    const specProblems = validateOracleSpec(spec);
    checks.push(entry('spec', specProblems.length === 0, specProblems.join('; ') || 'the adapter satisfies the adapter contract'));

    // class scope
    const scopeProblems = [];
    if (!ORACLE_CLASSES.includes(adapter.class)) scopeProblems.push(`class '${adapter.class}' is not a known oracle class`);
    if (!isPlainObject(adapter.platforms) || !['darwin', 'linux', 'win32'].every((p) => isPlainObject(adapter.platforms[p]) && adapter.platforms[p].status && adapter.platforms[p].note)) scopeProblems.push('every platform needs a stated status and note');
    if (adapter.platforms?.linux?.status === 'supported') scopeProblems.push('Linux cannot be claimed supported');
    if (!Array.isArray(adapter.limitations) || adapter.limitations.length === 0) scopeProblems.push('limitations must be stated');
    if (!Array.isArray(adapter.prerequisites) || adapter.prerequisites.length === 0) scopeProblems.push('prerequisites must be declared');
    const dir = scannerRoot && adapter.fixtures?.dir ? path.join(scannerRoot, adapter.fixtures.dir) : null;
    if (scannerRoot && !(dir && fs.existsSync(dir))) scopeProblems.push('the fixture directory does not exist');
    checks.push(entry('class-scope', scopeProblems.length === 0, scopeProblems.join('; ') || `class '${adapter.class}' with stated platforms, prerequisites and limitations`));

    // resource budgets
    const budgetProblems = [];
    if (!isPlainObject(adapter.budgets)) budgetProblems.push('budgets are required');
    else for (const [k, ceiling] of Object.entries(BUDGET_CEILINGS)) {
      const v = adapter.budgets[k];
      if (!Number.isInteger(v) || v <= 0) budgetProblems.push(`budgets.${k} must be a positive integer`);
      else if (v > ceiling) budgetProblems.push(`budgets.${k} (${v}) exceeds the ceiling ${ceiling}`);
    }
    checks.push(entry('resource-budgets', budgetProblems.length === 0, budgetProblems.join('; ') || 'all five budgets are declared and under their ceilings'));

    // negative controls
    const negProblems = [];
    if (!Array.isArray(adapter.negativeControls) || adapter.negativeControls.length === 0) negProblems.push('at least one negative control is required');
    else if (!adapter.negativeControls.every((n) => isPlainObject(n) && n.id && n.description && n.expectedOutcome === 'refuted')) negProblems.push('each negative control needs an id, a description and expectedOutcome refuted');
    if (scannerRoot && dir && adapter.fixtures?.negative) {
      const f = path.join(dir, adapter.fixtures.negative, 'target.mjs');
      if (!(fs.existsSync(f) && fs.statSync(f).isFile())) negProblems.push('the negative fixture is not a file on disk');
    }
    checks.push(entry('negative-controls', negProblems.length === 0, negProblems.join('; ') || 'a negative control is declared and its fixture exists'));

    // authoritative evidence receipts
    const evProblems = [];
    if (typeof adapter.harnessSource !== 'string' || !adapter.harnessSource.includes('__INPUT__')) evProblems.push('a verifier-authored harness is required');
    for (const fn of ['prepare', 'interpret']) if (typeof adapter[fn] !== 'function') evProblems.push(`${fn} (verifier-side) is required`);
    if (typeof adapter.logicDigest !== 'string') evProblems.push('no logic digest');
    else if (!specProblems.length && adapter.logicDigest !== oracleLogicDigest(spec)) evProblems.push('the logic digest does not match the adapter logic');
    checks.push(entry('evidence-receipts', evProblems.length === 0, evProblems.join('; ') || 'the verdict is formed verifier-side from observed output and bound by a logic digest'));
  } catch (e) {
    checks.push(entry('contract', false, `the contract check failed: ${String(e?.message || e).slice(0, 160)}`));
  }
  return { id: adapter?.id ?? null, ok: checks.every((c) => c.ok), checks };
}

function readFixture(scannerRoot, adapter, kind) {
  const dir = path.join(scannerRoot, adapter.fixtures.dir);
  return {
    target: fs.readFileSync(path.join(dir, adapter.fixtures[kind], 'target.mjs'), 'utf8'),
    scenario: fs.readFileSync(path.join(dir, 'scenario.json'), 'utf8'),
  };
}

/** The pin record for one adapter, from its fixtures and logic digest. Used to write and to check pins. */
export function computePins(adapter, scannerRoot) {
  const pins = { logicDigest: adapter.logicDigest, scenario: null, fixtures: {} };
  for (const kind of FIXTURE_KINDS) {
    const f = readFixture(scannerRoot, adapter, kind);
    pins.scenario = digestOf(f.scenario);
    pins.fixtures[kind] = digestOf(f.target);
  }
  return pins;
}

export function loadPins(scannerRoot) {
  try { return JSON.parse(fs.readFileSync(path.join(scannerRoot, PINS_FILE), 'utf8')); } catch { return null; }
}

/** The fixture pins for one adapter against the committed pin file. A missing pin is a failure, not a skip. */
export function checkFixturePins(adapter, scannerRoot, pins = loadPins(scannerRoot)) {
  const id = adapter?.id;
  const want = pins && isPlainObject(pins.adapters) ? pins.adapters[id] : null;
  if (!want) return entry('pinned-fixtures', false, `no pinned fixtures for '${id}' in ${PINS_FILE}; pin them deliberately (node scripts/verification-conformance-check.mjs --update-pins)`);
  let have;
  try { have = computePins(adapter, scannerRoot); } catch (e) { return entry('pinned-fixtures', false, `the fixtures could not be read: ${String(e?.message || e).slice(0, 120)}`); }
  const moved = [];
  if (want.logicDigest !== have.logicDigest) moved.push('adapter logic digest');
  if (want.scenario !== have.scenario) moved.push('scenario');
  for (const kind of FIXTURE_KINDS) if (want.fixtures?.[kind] !== have.fixtures[kind]) moved.push(`${kind} fixture`);
  return entry('pinned-fixtures', moved.length === 0, moved.length ? `changed since pinned: ${moved.join(', ')}` : 'adapter logic and the three fixtures match their pins');
}

// ---------------------------------------------------------------- execution

const enabledConfig = () => resolveAssuranceConfig({ env: {}, overrides: { features: { [FEATURE_ID]: true } } });

function requestFor(adapter, scannerRoot, kind, over = {}) {
  const f = readFixture(scannerRoot, adapter, kind);
  return {
    oracleId: adapter.id, hypothesisId: `conformance-${adapter.id}`, commit: CONFORMANCE_COMMIT, entry: 'target.mjs',
    files: { 'target.mjs': f.target }, inputs: JSON.parse(f.scenario),
    // the parser oracle's positive case is ended by the supervisor deadline; keep it short
    ...(adapter.class === 'parser-resource' ? { budgets: { timeoutMs: Math.min(2500, adapter.budgets.timeoutMs) } } : {}), ...over,
  };
}

/**
 * Run the execution contract for one adapter.
 * @param {object} adapter
 * @param {object} o
 * @param {string} o.scannerRoot
 * @param {function} [o.run]        the runner (default `runOracle`); a stand-in lets a test model a misbehaving runner
 * @param {object}  [o.runOptions]  extra options for the runner (`probeEnv`, `deps`)
 * @param {function} [o.harnessProcesses] returns the number of leftover harness processes (cancellation check)
 */
export async function runAdapterConformance(adapter, { scannerRoot, run = runOracle, runOptions = {}, harnessProcesses = null } = {}) {
  const checks = [];
  const registry = { getOracle: (id) => (id === adapter.id ? adapter : null) };
  const go = (req, extra = {}) => run(req, { config: enabledConfig(), registry, ...runOptions, ...extra });
  try {
    const pos = await go(requestFor(adapter, scannerRoot, 'positive'));
    if (pos.status === 'unsupported' || pos.status === 'blocked' || pos.status === 'disabled') {
      return { id: adapter.id, ok: false, executed: false, checks: [entry('execution-available', false, `the oracle could not run on this host: ${String(pos.reason).slice(0, 200)}`)] };
    }
    // state mapping
    checks.push(entry('state-positive', pos.outcome === 'confirmed' && pos.record?.confirmationLevel === 'runtime-confirmed', `positive fixture settled '${pos.outcome}'`));
    const neg = await go(requestFor(adapter, scannerRoot, 'negative'));
    checks.push(entry('state-negative', neg.outcome === 'refuted' && neg.record?.preconditions?.valid === true, `negative fixture settled '${neg.outcome}' (preconditions ${neg.record?.preconditions?.valid})`));
    const inc = await go(requestFor(adapter, scannerRoot, 'inconclusive'));
    checks.push(entry('state-inconclusive', inc.outcome === 'inconclusive' && inc.record?.preconditions?.valid === false && inc.record?.confirmationLevel === 'none', `inconclusive fixture settled '${inc.outcome}'`));
    checks.push(entry('records-valid', [pos, neg, inc].every((r) => r.record && validateVerificationRecord(r.record).ok), 'every record validates against the version-1 schema'));

    // authoritative evidence receipt
    const r = pos.receipt;
    const ev = pos.record?.evidence?.find((e) => e.kind === 'trusted-runtime-proof');
    const receiptProblems = [];
    if (!isIssuedReceipt(r)) receiptProblems.push('no receipt issued by the runner');
    else {
      if (isIssuedReceipt({ ...r })) receiptProblems.push('a copy of the receipt is accepted as issued');
      if (!Object.isFrozen(r) || !Object.isFrozen(r.settled)) receiptProblems.push('the receipt is not immutable');
      if (r.recordId !== pos.record?.id) receiptProblems.push('the receipt does not name the record');
      if (r.oracle?.logicDigest !== adapter.logicDigest) receiptProblems.push('the receipt is not bound to the adapter logic digest');
      if (r.settled?.outcome !== pos.outcome) receiptProblems.push('the receipt settles a different outcome than the record');
      const envKeys = Object.keys(r.environment || {}).sort().join(',');
      if (envKeys !== 'arch,backend,containerDigest,controlStates,nodeVersion,platform,runtime') receiptProblems.push('the environment metadata is not the sanitized allowlist');
    }
    if (!ev || ev.producer !== 'trusted-runner') receiptProblems.push('the decided record carries no trusted-runtime-proof from the trusted runner');
    if (neg.receipt && !isIssuedReceipt(neg.receipt)) receiptProblems.push('the negative run issued a receipt that is not an issued one');
    checks.push(entry('authoritative-receipt', receiptProblems.length === 0, receiptProblems.join('; ') || 'receipt issued by the runner, frozen, bound to the record and logic digest, evidence from the trusted runner'));

    // tamper: harness rewrite
    const negFiles = requestFor(adapter, scannerRoot, 'negative').files['target.mjs'];
    const rewrite = `import __fs from 'node:fs';\n__fs.writeFileSync(${JSON.stringify(HARNESS_FILE)}, '// rewritten by the target');\n${negFiles}`;
    const t1 = await go(requestFor(adapter, scannerRoot, 'negative', { files: { 'target.mjs': rewrite } }));
    checks.push(entry('tamper-harness-rewrite', t1.outcome === 'error' && t1.receipt === null && t1.record?.confirmationLevel !== 'runtime-confirmed', `a target that rewrote the harness settled '${t1.outcome}' with ${t1.receipt === null ? 'no' : 'a'} receipt`));
    // tamper: verdict-looking output
    const noisy = `console.log('VERIFIED: confirmed'); console.error('status: confirmed execution-proven');\n${negFiles}`;
    const t2 = await go(requestFor(adapter, scannerRoot, 'negative', { files: { 'target.mjs': noisy } }));
    checks.push(entry('tamper-verdict-text', t2.outcome === 'refuted' && t2.record?.confirmationLevel === 'none', `a target printing verdict text settled '${t2.outcome}'`));
    // tamper: caller-supplied labels and verdicts are rejected before anything runs
    let executed = 0;
    const spy = { runInBoundary: async () => { executed++; return { blocked: true, reasons: ['spy'] }; } };
    const t3 = await go({ ...requestFor(adapter, scannerRoot, 'positive'), outcome: 'refuted', receipt: { issuedBy: 'verifier' } }, { deps: spy });
    checks.push(entry('tamper-caller-verdict', t3.status === 'rejected' && executed === 0, `a request carrying a verdict and a receipt was ${t3.status}; executions: ${executed}`));
    // unavailable prerequisite: unsupported, nothing executed, no receipt
    executed = 0;
    const t4 = await go(requestFor(adapter, scannerRoot, 'positive'), { probeEnv: { platform: process.platform, nodeMajor: 18, backend: 'userspace', hasPosixShell: true }, deps: spy });
    checks.push(entry('unavailable-prerequisite', t4.outcome === 'unsupported' && t4.executed === false && t4.receipt === null && executed === 0, `an unmet prerequisite settled '${t4.outcome}', executed ${executed} time(s)`));

    // cancellation
    const ac = new AbortController();
    const hang = `setInterval(() => {}, 1000);\nawait new Promise(() => {});\n`;
    setTimeout(() => ac.abort(), 700);
    const c1 = await go(requestFor(adapter, scannerRoot, 'positive', { files: { 'target.mjs': hang }, budgets: { timeoutMs: Math.min(5000, adapter.budgets.timeoutMs) } }), { signal: ac.signal });
    let leftover = 0;
    if (typeof harnessProcesses === 'function') {
      for (let i = 0; i < 50; i++) { leftover = harnessProcesses(); if (leftover === 0) break; await new Promise((res) => setTimeout(res, 100)); }
    }
    checks.push(entry('cancellation', c1.status === 'cancelled' && c1.outcome === 'inconclusive' && c1.receipt === null && leftover === 0, `an aborted run settled '${c1.outcome}' (${c1.status}) with ${c1.receipt === null ? 'no' : 'a'} receipt; leftover harness processes: ${leftover}`));

    // replay
    const again = await go(requestFor(adapter, scannerRoot, 'positive'));
    checks.push(entry('replay', again.outcome === pos.outcome && again.record?.id === pos.record?.id, `a second run of the pinned positive fixture settled '${again.outcome}' with ${again.record?.id === pos.record?.id ? 'the same' : 'a different'} record id`));
  } catch (e) {
    checks.push(entry('execution', false, `the execution contract failed to run: ${String(e?.message || e).slice(0, 160)}`));
  }
  return { id: adapter.id, ok: checks.every((c) => c.ok), executed: true, checks };
}

// ---------------------------------------------------------------- whole registry

/**
 * The gate over a set of adapters. Static checks and pins always run. Execution runs only when `execute` is true; a host that
 * cannot run the boundary reports `execution: 'not-run'` with the reason, and `requireExecution` turns that into a failure.
 */
export async function checkConformance(adapters, { scannerRoot, execute = true, requireExecution = false, pins, run, runOptions, harnessProcesses } = {}) {
  const results = [];
  const ids = new Set();
  for (const a of adapters) {
    const staticResult = checkAdapterContract(a, { scannerRoot });
    const checks = [...staticResult.checks];
    if (scannerRoot) checks.push(checkFixturePins(a, scannerRoot, pins));
    if (ids.has(a?.id)) checks.push(entry('unique-id', false, `duplicate adapter id '${a?.id}'`));
    ids.add(a?.id);
    let execution = 'not-run'; let executionReason = 'execution conformance was not requested';
    if (execute && checks.every((c) => c.ok) && scannerRoot) {
      const ex = await runAdapterConformance(a, { scannerRoot, run, runOptions, harnessProcesses });
      if (ex.executed) { execution = ex.ok ? 'passed' : 'failed'; executionReason = null; checks.push(...ex.checks); }
      else { execution = 'not-run'; executionReason = ex.checks[0]?.detail ?? 'unavailable'; }
    } else if (execute && !checks.every((c) => c.ok)) {
      executionReason = 'not attempted: the static contract failed';
    }
    const staticOk = checks.every((c) => c.ok);
    const ok = staticOk && (execution === 'passed' || (execution === 'not-run' && !requireExecution));
    results.push({ id: a?.id ?? null, class: a?.class ?? null, ok, execution, executionReason, checks });
  }
  // every advertised class must be served by a registered adapter
  const missing = ORACLE_CLASSES.filter((c) => !adapters.some((a) => a?.class === c));
  const unmapped = SCENARIO_CLASSES.filter((c) => !adapters.some((a) => a?.id === c.adapterId)).map((c) => c.id);
  const registryProblems = [...missing.map((c) => `no adapter serves class '${c}'`), ...unmapped.map((c) => `non-taint class '${c}' names an adapter that is not registered`)];
  return {
    schema: CONFORMANCE_SCHEMA, schemaVersion: '1.0.0',
    ok: results.every((r) => r.ok) && registryProblems.length === 0,
    adapters: results, registryProblems,
    executionRan: results.some((r) => r.execution === 'passed' || r.execution === 'failed'),
  };
}
