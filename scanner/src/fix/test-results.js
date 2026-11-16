// Per-test outcomes and their delta between the original and the patched tree (verified-remediation PRD FR-02, GAP-02).
//
// test-commands.js used to run the pristine tree only when the patched run failed, and to call ANY pristine failure "pre-existing", so a
// patch that broke test B while test A was already red read as "the suite was already failing" and the verifier treated the leg as
// skipped. Here both trees run, each test has a stable identity, and the comparison is test by test:
//
//   newly failing (passed before, fails/errors/times out after)     -> failed
//   changed failure (failed before and after, different signature)  -> failed (never excused as pre-existing)
//   removed or newly skipped (present and running before, not after) -> failed
//   a required test failing in the baseline                          -> inconclusive (a required obligation cannot be excused)
//   unchanged failure, same signature, not required                  -> excused and RECORDED, never hidden
//   fixed (failed before, passes after), added (new test)            -> recorded
//   zero discovered tests, an incomplete or malformed report         -> inconclusive, never passed
//
// Adapters. `node-test` (Node's built-in runner, structured events from a verifier-owned reporter module loaded through NODE_OPTIONS, so no
// project file changes), `jest` and `vitest` (their JSON reports, requested with appended arguments; parsers unit-tested on captured
// report shapes, not yet integration-tested against installed runners: see ADAPTERS), and `exit-code` for everything else, whose
// attribution is explicitly limited to one suite-level unit with a failure signature taken from the output tail.
//
// Flaky policy: no retries. A test that fails on the patched tree after passing on the original is a new failure; repetition or majority
// voting never turns a failure into a pass. A caller that has measured flakiness may pass `flaky` ids: a flaky test cannot excuse a failure
// and cannot count as passing evidence (it is reported as flaky and, when required, makes the result inconclusive).
//
// Pure apart from the reporter module text (a constant written by the caller): no fs, no clock.

export const ADAPTERS = Object.freeze({
  'node-test': { structured: true, integration: 'tested', note: 'Node built-in test runner via a verifier-owned reporter module' },
  jest: { structured: true, integration: 'parser-only', note: 'parses `jest --json --outputFile`; not executed against an installed jest in this repository' },
  vitest: { structured: true, integration: 'parser-only', note: 'parses `vitest run --reporter=json --outputFile`; not executed against an installed vitest in this repository' },
  'exit-code': { structured: false, integration: 'tested', note: 'one suite-level unit; attribution is limited to the exit code and an output-tail signature' },
});

export const OUTCOMES = Object.freeze(['passed', 'failed', 'skipped', 'todo', 'timeout', 'error', 'cancelled', 'flaky']);
const FAILING = new Set(['failed', 'timeout', 'error', 'cancelled']);
const NOT_RUN = new Set(['skipped', 'todo']);

// The reporter the verifier hands Node's test runner. It writes one JSON line per event to AS_TEST_REPORT_OUT and a final `end` record,
// so a run that died early is visibly incomplete. It reads nothing from the project.
export const NODE_TEST_REPORTER = `import * as fs from 'node:fs';
const out = process.env.AS_TEST_REPORT_OUT;
const w = (o) => { try { fs.appendFileSync(out, JSON.stringify(o) + '\\n'); } catch {} };
export default async function* reporter(source) {
  const stacks = new Map();
  for await (const ev of source) {
    const d = ev.data || {};
    if (ev.type === 'test:start') { const s = stacks.get(d.file) || []; s[d.nesting] = d.name; s.length = d.nesting + 1; stacks.set(d.file, s); continue; }
    if (ev.type !== 'test:pass' && ev.type !== 'test:fail') continue;
    if (d.details && d.details.type === 'suite') continue;
    const s = stacks.get(d.file) || [];
    const err = d.details && d.details.error;
    const cause = err && err.cause;
    w({ k: 'test', type: ev.type, file: d.file || null, path: [...s.slice(0, d.nesting), d.name], skip: !!d.skip, todo: !!d.todo,
        failureType: err && err.failureType || null, code: (cause && cause.code) || (err && err.code) || null,
        message: String((cause && cause.message) || (err && err.message) || '').slice(0, 400) });
  }
  w({ k: 'end' });
}
`;

/** Volatile text (absolute paths, addresses, durations, temp names) removed so a signature compares the failure, not the run. */
export function normalizeFailureText(text, roots = []) {
  let t = String(text || '');
  for (const r of roots.filter(Boolean).sort((a, b) => b.length - a.length)) t = t.split(r).join('<root>');
  return t
    .replace(/\/(?:private\/)?(?:var|tmp)\/[^\s'"):]+/g, '<tmp>')
    .replace(/[A-Za-z]:\\[^\s'"):]+/g, '<path>')
    .replace(/0x[0-9a-f]{6,}/gi, '<addr>')
    .replace(/\b\d+(?:\.\d+)?\s?(?:ms|s)\b/g, '<dur>')
    .replace(/:\d+:\d+\b/g, ':<pos>')
    .replace(/\b(?:patched|pristine|original)-[A-Za-z0-9]+\b/g, '<copy>')
    .replace(/[ \t]+/g, ' ')
    .trim();
}

const relFile = (file, root) => {
  if (!file) return '<unknown>';
  let f = String(file);
  if (root && f.startsWith(root)) f = f.slice(root.length).replace(/^[/\\]+/, '');
  return f.replace(/\\/g, '/');
};

function withOrdinals(tests) {
  const seen = new Map();
  for (const t of tests) { const n = (seen.get(t.id) || 0) + 1; seen.set(t.id, n); if (n > 1) t.id = `${t.id}#${n}`; }
  return tests;
}

/**
 * Parse the node-test reporter output.
 * @returns {{adapter:'node-test', complete:boolean, malformed:number, tests:{id:string,file:string,name:string,outcome:string,signature:string|null}[]}}
 */
export function parseNodeTestReport(jsonl, { root = null } = {}) {
  const tests = []; let malformed = 0; let complete = false;
  for (const line of String(jsonl || '').split('\n')) {
    if (!line.trim()) continue;
    let r; try { r = JSON.parse(line); } catch { malformed++; continue; }
    if (r && r.k === 'end') { complete = true; continue; }
    if (!r || r.k !== 'test' || !Array.isArray(r.path)) { malformed++; continue; }
    const file = relFile(r.file, root);
    let outcome;
    if (r.todo) outcome = 'todo';
    else if (r.skip) outcome = 'skipped';
    else if (r.type === 'test:pass') outcome = 'passed';
    else if (r.failureType === 'testTimeoutFailure') outcome = 'timeout';
    else if (r.failureType === 'cancelledByParent' || r.failureType === 'testCodeFailure' && /cancel/i.test(r.message)) outcome = 'cancelled';
    else if (r.failureType === 'hookFailure' || r.failureType === 'uncaughtException' || r.failureType === 'unhandledRejection') outcome = 'error';
    else outcome = 'failed';
    const signature = FAILING.has(outcome) ? `${outcome}|${r.code || ''}|${normalizeFailureText(r.message, [root]).split('\n')[0].slice(0, 200)}` : null;
    tests.push({ id: `${file}::${r.path.join(' > ')}`, file, name: r.path.join(' > '), outcome, signature });
  }
  return { adapter: 'node-test', complete, malformed, tests: withOrdinals(tests) };
}

/** jest --json report. */
export function parseJestReport(json, { root = null } = {}) {
  let r; try { r = typeof json === 'string' ? JSON.parse(json) : json; } catch { return { adapter: 'jest', complete: false, malformed: 1, tests: [] }; }
  if (!r || !Array.isArray(r.testResults)) return { adapter: 'jest', complete: false, malformed: 1, tests: [] };
  const tests = [];
  for (const file of r.testResults) {
    const f = relFile(file.name || file.testFilePath, root);
    if (file.status === 'failed' && !(file.assertionResults || []).length) tests.push({ id: `${f}::<file>`, file: f, name: '<file>', outcome: 'error', signature: `error||${normalizeFailureText(file.message, [root]).split('\n')[0].slice(0, 200)}` });
    for (const a of file.assertionResults || []) {
      const name = [...(a.ancestorTitles || []), a.title].join(' > ');
      const outcome = a.status === 'passed' ? 'passed' : a.status === 'pending' || a.status === 'skipped' || a.status === 'disabled' ? 'skipped' : a.status === 'todo' ? 'todo' : 'failed';
      tests.push({ id: `${f}::${name}`, file: f, name, outcome, signature: outcome === 'failed' ? `failed||${normalizeFailureText((a.failureMessages || [])[0], [root]).split('\n')[0].slice(0, 200)}` : null });
    }
  }
  return { adapter: 'jest', complete: r.numTotalTests !== undefined, malformed: 0, tests: withOrdinals(tests) };
}

/** vitest --reporter=json report (jest-compatible shape). */
export function parseVitestReport(json, opts) { const r = parseJestReport(json, opts); return { ...r, adapter: 'vitest' }; }

/** The exit-code adapter: one suite-level unit. */
export function exitCodeUnit({ exitCode, timedOut, output, roots = [] }) {
  const outcome = timedOut ? 'timeout' : exitCode === 0 ? 'passed' : 'failed';
  const tail = normalizeFailureText(String(output || '').split('\n').slice(-20).join('\n'), roots);
  return { adapter: 'exit-code', complete: true, malformed: 0, tests: [{ id: '<suite>', file: '<suite>', name: '<suite>', outcome, signature: outcome === 'passed' ? null : `${outcome}|${exitCode ?? ''}|${tail}` }] };
}

const matchesAny = (id, list) => (list || []).some((p) => (p instanceof RegExp ? p.test(id) : id === p || id.endsWith(`::${p}`)));

/**
 * Compare a baseline run with a patched run.
 * @param {object} baseline  parsed report of the original tree
 * @param {object} patched   parsed report of the patched tree
 * @param {{required?:(string|RegExp)[], flaky?:(string|RegExp)[]}} [policy]
 * @returns {{verdict:'passed'|'failed'|'inconclusive', reasons:string[], attribution:'per-test'|'suite-only', counts:object,
 *   newlyFailing:object[], changedFailure:object[], removed:object[], newlySkipped:object[], preExisting:object[], fixed:object[],
 *   added:object[], flaky:object[], requiredBaselineFailing:object[]}}
 */
export function compareTestRuns(baseline, patched, policy = {}) {
  const reasons = [];
  const attribution = baseline.adapter === 'exit-code' || patched.adapter === 'exit-code' ? 'suite-only' : 'per-test';
  const b = new Map(baseline.tests.map((t) => [t.id, t])); const p = new Map(patched.tests.map((t) => [t.id, t]));
  const out = { newlyFailing: [], changedFailure: [], removed: [], newlySkipped: [], preExisting: [], fixed: [], added: [], flaky: [], requiredBaselineFailing: [] };
  for (const [id, bt] of b) {
    const pt = p.get(id);
    const flaky = matchesAny(id, policy.flaky);
    const required = matchesAny(id, policy.required);
    if (flaky) { out.flaky.push({ id, before: bt.outcome, after: pt?.outcome ?? 'missing', required }); continue; }
    if (!pt) { out.removed.push({ id, before: bt.outcome }); continue; }
    const bf = FAILING.has(bt.outcome); const pf = FAILING.has(pt.outcome);
    if (!bf && !NOT_RUN.has(bt.outcome) && NOT_RUN.has(pt.outcome)) out.newlySkipped.push({ id, before: bt.outcome, after: pt.outcome });
    else if (!bf && pf) out.newlyFailing.push({ id, before: bt.outcome, after: pt.outcome, signature: pt.signature });
    else if (bf && pf && bt.signature !== pt.signature) out.changedFailure.push({ id, before: bt.signature, after: pt.signature });
    else if (bf && pf) (required ? out.requiredBaselineFailing : out.preExisting).push({ id, outcome: pt.outcome, signature: pt.signature });
    else if (bf && !pf) out.fixed.push({ id, before: bt.outcome, after: pt.outcome });
  }
  for (const [id, pt] of p) if (!b.has(id)) { if (FAILING.has(pt.outcome)) out.newlyFailing.push({ id, before: 'absent', after: pt.outcome, signature: pt.signature }); else out.added.push({ id, outcome: pt.outcome }); }
  // a required test that is missing, skipped or failing on the patched tree is a failed obligation whatever the baseline did
  for (const t of patched.tests) if (matchesAny(t.id, policy.required) && !matchesAny(t.id, policy.flaky) && (NOT_RUN.has(t.outcome)) && !out.newlySkipped.some((x) => x.id === t.id)) out.newlySkipped.push({ id: t.id, before: b.get(t.id)?.outcome ?? 'absent', after: t.outcome });
  for (const r of policy.required || []) if (typeof r === 'string' && ![...p.keys()].some((id) => matchesAny(id, [r]))) out.removed.push({ id: r, before: b.has(r) ? b.get(r).outcome : 'required' });

  const ran = patched.tests.filter((t) => !NOT_RUN.has(t.outcome)).length;
  let verdict = 'passed';
  if (out.newlyFailing.length) reasons.push(`${out.newlyFailing.length} test(s) newly fail on the patched tree: ${out.newlyFailing.slice(0, 5).map((x) => x.id).join(', ')}`);
  if (out.changedFailure.length) reasons.push(`${out.changedFailure.length} test(s) fail before and after for a different reason, so the failure cannot be called pre-existing: ${out.changedFailure.slice(0, 5).map((x) => x.id).join(', ')}`);
  if (out.removed.length) reasons.push(`${out.removed.length} test(s) present before the patch are missing after it: ${out.removed.slice(0, 5).map((x) => x.id).join(', ')}`);
  if (out.newlySkipped.length) reasons.push(`${out.newlySkipped.length} test(s) that ran before are skipped after the patch: ${out.newlySkipped.slice(0, 5).map((x) => x.id).join(', ')}`);
  if (reasons.length) verdict = 'failed';
  const inconclusive = [];
  if (!baseline.complete) inconclusive.push('the original-tree test report is incomplete');
  if (!patched.complete) inconclusive.push('the patched-tree test report is incomplete');
  if (baseline.malformed || patched.malformed) inconclusive.push(`${baseline.malformed + patched.malformed} malformed report record(s)`);
  if (!patched.tests.length) inconclusive.push('no tests were discovered on the patched tree');
  else if (!ran) inconclusive.push('every discovered test was skipped on the patched tree');
  else if (!patched.tests.some((t) => t.outcome === 'passed')) inconclusive.push('no test passed on the patched tree, so nothing shows the behaviour was preserved');
  if (out.requiredBaselineFailing.length) inconclusive.push(`${out.requiredBaselineFailing.length} required test(s) already fail on the original tree, so the obligation cannot be shown: ${out.requiredBaselineFailing.slice(0, 5).map((x) => x.id).join(', ')}`);
  if (out.flaky.some((f) => f.required)) inconclusive.push('a required test is marked flaky, so it cannot establish the obligation');
  if (attribution === 'suite-only' && out.preExisting.length) inconclusive.push('the suite failed identically before and after the patch, and an exit code cannot show which tests the patch affected');
  if (verdict === 'passed' && inconclusive.length) verdict = 'inconclusive';
  reasons.push(...inconclusive);
  const counts = Object.fromEntries(OUTCOMES.map((o) => [o, patched.tests.filter((t) => t.outcome === o).length]));
  return { verdict, reasons, attribution, adapter: patched.adapter, counts: { ...counts, discovered: patched.tests.length, baselineDiscovered: baseline.tests.length }, ...out };
}

// Paths a patch must not change to gain acceptance: test files that existed before, runner configuration, and the test script itself.
const TEST_FILE = /(?:^|\/)(?:tests?|__tests__|spec|specs)\/|(?:^|\/)[^/]*\.(?:test|spec)\.[cm]?[jt]sx?$|(?:^|\/)test_[^/]*\.py$|(?:^|\/)[^/]*_test\.(?:py|go)$|(?:^|\/)conftest\.py$/;
const RUNNER_CONFIG = /(?:^|\/)(?:jest|vitest|vite|playwright|karma|ava|cypress)\.config\.[cm]?[jt]s$|(?:^|\/)\.mocharc(?:\.[a-z]+)?$|(?:^|\/)\.c8rc|(?:^|\/)\.nycrc|(?:^|\/)pytest\.ini$|(?:^|\/)tox\.ini$|(?:^|\/)setup\.cfg$|(?:^|\/)\.taprc$/;

/**
 * Which files of a patch touch the protected test surface. A new test file is allowed (a generated regression test may ship with the
 * fix) but it is not independent evidence; modifying or deleting an existing test, the runner configuration or the test script is not.
 * @param {Record<string,string|null>} files  the patch
 * @param {(rel:string)=>string|null} readOriginal
 */
export function testSurfaceChanges(files, readOriginal) {
  const blocked = []; const addedTests = [];
  for (const [rel, text] of Object.entries(files || {})) {
    const norm = rel.replace(/\\/g, '/');
    const before = readOriginal(rel);
    if (TEST_FILE.test(norm)) { if (before === null || before === undefined) addedTests.push(norm); else if (before !== text) blocked.push({ file: norm, reason: text === null ? 'deletes an existing test file' : 'modifies an existing test file' }); continue; }
    if (RUNNER_CONFIG.test(norm) && before !== text) { blocked.push({ file: norm, reason: 'changes the test runner configuration' }); continue; }
    if (/(?:^|\/)package\.json$/.test(norm) && before && text !== before) {
      let a = null; let c = null; try { a = JSON.parse(before); c = JSON.parse(text); } catch { blocked.push({ file: norm, reason: 'package.json does not parse on one side, so the test script cannot be compared' }); continue; }
      const keys = ['test', 'pretest', 'posttest'];
      if (keys.some((k) => (a?.scripts?.[k] ?? null) !== (c?.scripts?.[k] ?? null))) blocked.push({ file: norm, reason: 'changes the test script' });
      for (const k of ['jest', 'mocha', 'ava', 'c8', 'nyc']) if (JSON.stringify(a?.[k] ?? null) !== JSON.stringify(c?.[k] ?? null)) blocked.push({ file: norm, reason: `changes the ${k} configuration` });
    }
  }
  return { blocked, addedTests };
}

/** Which adapter applies to a detected command, from the command and the package.json test script. */
export function adapterFor(spec, testScript) {
  if (!spec) return 'exit-code';
  const argv = [spec.cmd, ...(spec.args || [])].join(' ');
  const script = String(testScript || '');
  const viaScript = ['npm', 'pnpm', 'yarn', 'bun'].includes(spec.kind) && script;
  const text = viaScript ? script : argv;
  if (/(?:^|[\s;&|])node\b[^;&|]*\s--test\b/.test(text) && !/--test-reporter/.test(text)) return 'node-test';
  if (/(?:^|[\s;&|/])jest\b/.test(text) && !/[;&|]/.test(text)) return 'jest';
  if (/(?:^|[\s;&|/])vitest\b/.test(text) && !/[;&|]/.test(text)) return 'vitest';
  return 'exit-code';
}
