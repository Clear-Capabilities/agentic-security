// Arms (adapters, egress, leakage guard), scoring and statistics for the Eval Lab (PRD 6).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { validateArm, runArmTask, usageOf } from '../../src/posture/evaluation/lab/arms.js';
import { scoreDetect, scoreFalsify, scoreExploit, scorePatch, scoreEconomics } from '../../src/posture/evaluation/lab/score.js';
import { summarize, median, MIN_REPRESENTATIVE_RUNS } from '../../src/posture/evaluation/lab/stats.js';

const FX = path.join(path.dirname(fileURLToPath(import.meta.url)), '../fixtures/eval-lab');
const ARM = path.join(FX, 'fake-arm.mjs');
const model = (profile, over = {}) => ({ id: `m-${profile}`, kind: 'model', tasks: ['detect', 'falsify', 'exploit', 'patch'], model: { id: profile, provider: 'fake', local: true }, adapter: { type: 'command', argv: [process.execPath, ARM, profile], timeoutMs: 6000 }, ...over });
const ws = () => { const d = mkTestTmp('lab-arm-'); fs.writeFileSync(path.join(d, 'a.js'), 'const q = 1;\ndb.query("SELECT " + id);\nexec(`ls ${x}`);\n'); return d; };

test('arm validation: local is declared and cannot be a lie; a bare command string is refused; the scanner is only a detector', () => {
  assert.equal(validateArm(model('good')).ok, true);
  const bad = (a, re) => { const v = validateArm(a); assert.equal(v.ok, false); assert.match(v.errors.join('|'), re); };
  bad(model('good', { model: { id: 'x', provider: 'p' } }), /model\.local must be true or false/);
  bad(model('good', { model: { id: 'x', provider: 'p', local: true, endpoint: 'https://api.example.com' } }), /not a loopback/);
  bad(model('good', { model: { id: 'x', provider: 'p', local: false } }), /must name its endpoint/);
  bad(model('good', { adapter: { type: 'command', argv: 'node arm.js' } }), /argv must be a non-empty array/);
  bad(model('good', { adapter: { type: 'command', argv: ['node'], timeoutMs: 5 } }), /timeoutMs/);
  bad(model('good', { id: 'Bad Id' }), /arm\.id/);
  bad(model('good', { tasks: ['hunt'] }), /arm\.tasks/);
  bad(model('good', { price: { inputPerMTok: -1, outputPerMTok: 1 } }), /price/);
  bad({ id: 's', kind: 'model', tasks: ['detect'], model: { id: 'x', provider: 'p', local: true }, adapter: { type: 'builtin-scanner' } }, /deterministic arm|command adapter/);
  bad({ id: 's', kind: 'deterministic', tasks: ['patch'], adapter: { type: 'builtin-scanner' } }, /only performs the detect task/);
  assert.equal(validateArm({ id: 's', kind: 'deterministic', tasks: ['detect'], adapter: { type: 'builtin-scanner', layer: 'deep-taint' } }).ok, true);
  assert.equal(validateArm(null).ok, false);
  assert.equal(validateArm(model('good', { model: { id: 'x', provider: 'ollama', local: true, endpoint: 'http://127.0.0.1:11434' } })).ok, true);
});

test('usage: reported figures are labelled, prices turn tokens into dollars, and unknown is never zero', () => {
  const priced = model('good', { price: { inputPerMTok: 3, outputPerMTok: 15 } });
  const u = usageOf(priced, { inputTokens: 1_000_000, outputTokens: 100_000 }, 50);
  assert.equal(u.usd, 4.5); assert.equal(u.usdSource, 'computed-from-reported-tokens');
  assert.equal(usageOf(model('good'), { inputTokens: 5, outputTokens: 5, usd: 0.25 }, 1).usdSource, 'reported');
  const unknown = usageOf(model('good'), undefined, 9);
  assert.equal(unknown.usd, null); assert.equal(unknown.usdSource, 'unknown');
  assert.equal(usageOf(model('good'), { usd: -5 }, 1).usd, null, 'a negative or non-finite figure is not believed');
  assert.equal(usageOf({ kind: 'deterministic' }, {}, 1).usd, 0);
});

test('command adapter: a well-behaved arm answers per task; the request travels in a file, never on stdin', async () => {
  const dir = ws();
  const arm = model('good');
  const d = await runArmTask({ arm, task: 'detect', request: { task: 'detect', workspace: dir }, workspaceDir: dir });
  assert.equal(d.status, 'completed');
  assert.deepEqual(d.output.findings.map((f) => `${f.line}:${f.cwe}`).sort(), ['2:CWE-89', '3:CWE-78']);
  assert.equal(d.usage.inputTokens, 1200);
  assert.ok(d.usage.latencyMs >= 0);
  const f = await runArmTask({ arm, task: 'falsify', request: { task: 'falsify', workspace: dir, candidates: [{ id: 'c1', file: 'a.js', line: 2, cwe: 'CWE-89' }] }, workspaceDir: dir });
  assert.equal(f.output.verdicts.c1, 'confirmed');
});

test('command adapter: every way an arm can fail is a recorded status, never a throw and never a score', async () => {
  const dir = ws();
  const run = (profile, over = {}) => runArmTask({ arm: model(profile, over), task: 'detect', request: { task: 'detect', workspace: dir }, workspaceDir: dir, timeoutMs: 1500 });
  assert.equal((await run('garbage')).status, 'error'); assert.match((await run('garbage')).reason, /invalid-response/);
  const slow = await run('slow', { adapter: { type: 'command', argv: [process.execPath, ARM, 'slow'], timeoutMs: 1200 } });
  assert.equal(slow.status, 'timeout');
  const missing = await run('good', { adapter: { type: 'command', argv: ['/no/such/binary-xyz'], timeoutMs: 3000 } });
  assert.equal(missing.status, 'error');
  const wrongTask = await runArmTask({ arm: model('good', { tasks: ['detect'] }), task: 'patch', request: {}, workspaceDir: dir });
  assert.equal(wrongTask.status, 'unavailable');
  const aborted = new AbortController(); aborted.abort();
  assert.equal((await runArmTask({ arm: model('good'), task: 'detect', request: { task: 'detect', workspace: dir }, workspaceDir: dir, signal: aborted.signal })).status, 'error');
});

test('a slow arm is killed with its whole process tree, not just its first process', async () => {
  const dir = ws();
  const marker = path.join(dir, 'child-alive');
  const child = path.join(dir, 'child.mjs');
  fs.writeFileSync(child, `import fs from 'node:fs'; setInterval(() => fs.writeFileSync(${JSON.stringify(marker)}, String(Date.now())), 50);`);
  const script = path.join(dir, 'parent.mjs');
  fs.writeFileSync(script, `import { spawn } from 'node:child_process'; spawn(process.execPath, [${JSON.stringify(child)}], { stdio: 'ignore' }); setTimeout(() => {}, 600000);`);
  const res = await runArmTask({ arm: model('x', { adapter: { type: 'command', argv: [process.execPath, script], timeoutMs: 1500 } }), task: 'detect', request: { task: 'detect', workspace: dir }, workspaceDir: dir });
  assert.equal(res.status, 'timeout');
  await new Promise((r) => setTimeout(r, 400));
  const before = fs.existsSync(marker) ? fs.statSync(marker).mtimeMs : 0;
  await new Promise((r) => setTimeout(r, 400));
  const after = fs.existsSync(marker) ? fs.statSync(marker).mtimeMs : 0;
  assert.equal(after, before, 'the grandchild must have stopped writing');
});

test('a non-local arm is judged by the egress policy BEFORE it runs, and a denial is `blocked`, not a score', async () => {
  const dir = ws(); let asked = null; let ran = false;
  const ext = model('good', { model: { id: 'big', provider: 'acme', local: false, endpoint: 'https://api.acme.invalid' }, adapter: { type: 'command', argv: [process.execPath, '-e', 'process.stdout.write("{}")'], timeoutMs: 3000 } });
  const denied = await runArmTask({ arm: ext, task: 'detect', request: { task: 'detect' }, workspaceDir: dir, egress: (ctx) => { asked = ctx; return { allowed: false, reason: 'provider is denied' }; } });
  assert.equal(denied.status, 'blocked'); assert.match(denied.reason, /egress policy: provider is denied/);
  assert.equal(asked.endpoint, 'https://api.acme.invalid'); assert.equal(asked.dataClass, 'source-code'); assert.equal(asked.purpose, 'eval-lab');
  const allowed = await runArmTask({ arm: ext, task: 'detect', request: { task: 'detect' }, workspaceDir: dir, egress: () => { ran = true; return { allowed: true }; } });
  assert.equal(ran, true); assert.equal(allowed.status, 'error', 'allowed to run, then judged on its answer ("{}" lacks findings)');
  let called = false;
  await runArmTask({ arm: model('good'), task: 'detect', request: { task: 'detect', workspace: dir }, workspaceDir: dir, egress: () => { called = true; return { allowed: false }; } });
  assert.equal(called, false, 'a local arm does not consult egress, and a non-local arm is never substituted for it');
});

test('the leakage guard blocks a request that contains a protected term, before the arm starts', async () => {
  const dir = ws(); const marker = path.join(dir, 'started');
  const arm = model('x', { adapter: { type: 'command', argv: [process.execPath, '-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '1')`], timeoutMs: 3000 } });
  const r = await runArmTask({ arm, task: 'detect', request: { task: 'detect', note: 'this is the answer key for CVE-2021-44228' }, workspaceDir: dir, terms: [] });
  assert.equal(r.status, 'blocked'); assert.match(r.reason, /leakage guard/);
  assert.equal(fs.existsSync(marker), false);
});

test('the arm runs with a scrubbed environment: credentials in the parent never reach it', async () => {
  const dir = ws();
  process.env.EVAL_LAB_TEST_API_KEY = 'sk-should-not-leak';
  try {
    const arm = model('x', { adapter: { type: 'command', argv: [process.execPath, '-e', 'process.stdout.write(JSON.stringify({ findings: [], usage: {}, saw: process.env.EVAL_LAB_TEST_API_KEY ?? null }))'], timeoutMs: 3000 } });
    const r = await runArmTask({ arm, task: 'detect', request: { task: 'detect' }, workspaceDir: dir });
    assert.equal(r.status, 'completed'); assert.equal(r.output.saw, undefined, 'only the declared output fields survive');
    const probe = model('x', { adapter: { type: 'command', argv: [process.execPath, '-e', 'process.exit(process.env.EVAL_LAB_TEST_API_KEY ? 7 : 0)'], timeoutMs: 3000 } });
    const p = await runArmTask({ arm: probe, task: 'detect', request: { task: 'detect' }, workspaceDir: dir });
    assert.doesNotMatch(p.reason ?? '', /exited 7/, 'the secret was visible to the arm');
  } finally { delete process.env.EVAL_LAB_TEST_API_KEY; }
});

// ------------------------------------------------------------------ scoring

const V = (id, cwe, file, s, e) => ({ id, kind: 'vulnerable', cwe, expectedSpan: { file, startLine: s, endLine: e } });
const N = (id, kind = 'fixed', category = undefined) => ({ id, kind, ...(category ? { category } : {}) });
const done = (findings) => ({ status: 'completed', output: { findings } });

test('detection is scored on LOCATION: right file and class but the wrong line is a miss', () => {
  const entries = [V('v1', 'CWE-89', 'a.js', 10, 12), V('v2', 'CWE-78', 'b.js', 5, 5), V('v3', 'CWE-22', 'c.js', 1, 1), N('n1'), N('n2', 'hard-negative', 'sanitization')];
  const attempts = new Map([
    ['v1', done([{ file: 'a.js', line: 13, cwe: 'CWE-89' }])],           // within tolerance 3 -> TP
    ['v2', done([{ file: 'b.js', line: 40, cwe: 'CWE-78' }])],           // right file/class, far away -> miss (wrong-location)
    ['v3', done([{ file: 'c.js', line: 1, cwe: 'CWE-79' }])],            // wrong class -> miss
    ['n1', done([])], ['n2', done([{ file: 'x.js', line: 1, cwe: 'CWE-89' }])],
  ]);
  const s = scoreDetect({ entries, attempts, targetCwes: ['CWE-89', 'CWE-78', 'CWE-22'] });
  assert.deepEqual([s.counts.tp, s.counts.fn, s.counts.fp, s.counts.tn], [1, 2, 1, 1]);
  assert.equal(s.precision, 0.5); assert.ok(Math.abs(s.recall - 1 / 3) < 1e-9);
  assert.equal(s.fileLevelRecall, 2 / 3); assert.equal(s.localizationAccuracy, 0.5);
  assert.deepEqual(s.misses.map((m) => m.reason).sort(), ['wrong-class', 'wrong-location']);
  assert.equal(s.hardNegativeFalsePositiveRate.sanitization.rate, 1);
  assert.ok(s.macroF1 != null);
});

test('detection: a timeout is a miss for a positive, UNSCORED for a negative, and never makes a model look good', () => {
  const entries = [V('v1', 'CWE-89', 'a.js', 1, 1), N('n1')];
  const crashed = new Map([['v1', { status: 'timeout' }], ['n1', { status: 'error' }]]);
  const s = scoreDetect({ entries, attempts: crashed });
  assert.equal(s.counts.fn, 1); assert.equal(s.counts.noResultPositives, 1); assert.equal(s.counts.unscoredNegatives, 1); assert.equal(s.counts.tn, 0);
  assert.equal(s.recall, 0); assert.equal(s.f1, 0); assert.equal(s.completion, 0);
  assert.equal(s.precision, null, 'no findings, no precision to speak of');
});

test('detection: a finding with no class in a negative counts against the model; the target set filters unrelated classes', () => {
  const entries = [V('v1', 'CWE-89', 'a.js', 1, 1), N('n1')];
  const unclassified = scoreDetect({ entries, attempts: new Map([['v1', done([{ file: 'a.js', line: 1, cwe: 'CWE-89' }])], ['n1', done([{ file: 'x.js', line: 1, cwe: null }])]]), targetCwes: ['CWE-89'] });
  assert.equal(unclassified.counts.fp, 1);
  const unrelated = scoreDetect({ entries, attempts: new Map([['v1', done([{ file: 'a.js', line: 1, cwe: 'CWE-89' }])], ['n1', done([{ file: 'x.js', line: 1, cwe: 'CWE-352' }])]]), targetCwes: ['CWE-89'] });
  assert.equal(unrelated.counts.fp, 0);
});

test('falsification: refuting a real vulnerability is its own, dangerous, error rate', () => {
  const truth = new Map([['a', 'vulnerable'], ['b', 'vulnerable'], ['c', 'not-vulnerable'], ['d', 'not-vulnerable']]);
  const s = scoreFalsify({ truth, verdicts: new Map([['a', 'confirmed'], ['b', 'refuted'], ['c', 'refuted'], ['d', 'confirmed']]) });
  assert.equal(s.truePositiveRate, 0.5); assert.equal(s.trueNegativeRate, 0.5); assert.equal(s.balancedAccuracy, 0.5);
  assert.equal(s.falseRefutationRate, 0.5); assert.equal(s.falseConfirmationRate, 0.5);
  const abstain = scoreFalsify({ truth, verdicts: new Map([['a', 'uncertain'], ['b', 'uncertain'], ['c', 'uncertain'], ['d', null]]) });
  assert.equal(abstain.balancedAccuracy, 0); assert.equal(abstain.counts.noResult, 1);
});

test('exploit proof: confirmed on a negative is a FALSE confirmation; an unexecutable reproducer is unmeasured, not a failure', () => {
  const s = scoreExploit({ proofs: [
    { entryKind: 'vulnerable', reproducerValid: true, executed: true, state: 'EXPLOIT_CONFIRMED', successes: 3 },
    { entryKind: 'vulnerable', reproducerValid: true, executed: true, state: 'REPRODUCER_GENERATED', successes: 0 },
    { entryKind: 'vulnerable', reproducerValid: false },
    { entryKind: 'fixed', reproducerValid: true, executed: true, state: 'EXPLOIT_CONFIRMED', successes: 3 },
    { entryKind: 'hard-negative', reproducerValid: true, executed: false },
  ] });
  assert.equal(s.confirmationRate, 1 / 3); assert.equal(s.falseConfirmationRate, 0.5);
  assert.equal(s.reproductionRate, 1 / 2, 'reproduction is judged on the vulnerable code only');
  assert.equal(s.pocGenerationSuccess, 4 / 5); assert.equal(s.counts.notExecuted, 1); assert.match(s.unmeasured, /could not be executed/);
});

test('remediation: valid means the exploit is blocked AND the tests pass; unmeasured tests never make a patch valid', () => {
  const s = scorePatch({ patches: [
    { applicable: true, patchProvided: true, exploitBlocked: true, testsPass: true, completeness: 'FULL' },
    { applicable: true, patchProvided: true, exploitBlocked: true, testsPass: null, completeness: 'DEGRADED' },
    { applicable: true, patchProvided: true, exploitBlocked: false, testsPass: true, completeness: 'INCOMPLETE' },
    { applicable: true, patchProvided: true, exploitBlocked: true, testsPass: false, completeness: 'FULL' },
    { applicable: true, patchProvided: false },
  ] });
  assert.equal(s.validPatchRate, 1 / 5); assert.equal(s.exploitBlockedRate, 3 / 5);
  assert.equal(s.testPreservationRate, 2 / 3); assert.equal(s.regressionRate, 1 / 3);
  assert.deepEqual(s.completenessTier, { FULL: 2, DEGRADED: 1, INCOMPLETE: 1 });
  assert.match(s.unmeasured, /1 patch/);
});

test('economics: unknown cost is counted as unknown, and failures and timeouts are visible', () => {
  const e = scoreEconomics([
    { status: 'completed', usage: { usd: 0.5, inputTokens: 10, outputTokens: 5, latencyMs: 100 } },
    { status: 'timeout', usage: { usd: null, inputTokens: null, outputTokens: null, latencyMs: 900 } },
    { status: 'error', usage: { usd: 0.25, inputTokens: 1, outputTokens: 1, latencyMs: 300 } },
  ]);
  assert.equal(e.usdMeasured, 0.75); assert.equal(e.attemptsWithUnknownCost, 1); assert.equal(e.tokensUnknownAttempts, 1);
  assert.equal(e.timeouts, 1); assert.equal(e.failures, 1); assert.equal(e.latencyMs.median, 300);
});

test('statistics: a single run is never representative, spread sits beside the mean, and unmeasured values are excluded and counted', () => {
  const one = summarize([0.9]);
  assert.equal(one.representative, false); assert.match(one.note, /not representative/); assert.equal(one.stdev, null);
  const three = summarize([0.8, 0.9, 1.0]);
  assert.equal(three.representative, true); assert.equal(three.n, MIN_REPRESENTATIVE_RUNS);
  assert.ok(Math.abs(three.mean - 0.9) < 1e-12); assert.ok(Math.abs(three.stdev - 0.1) < 1e-9);
  assert.ok(three.ci95.low < 0.9 && three.ci95.high > 0.9);
  const withNull = summarize([0.5, null, 0.7, NaN]);
  assert.equal(withNull.n, 2); assert.equal(withNull.unmeasured, 2);
  assert.equal(summarize([]).mean, null); assert.equal(summarize([null]).representative, false);
  assert.equal(median([3, 1, 2]), 2); assert.equal(median([1, 2, 3, 4]), 2.5); assert.equal(median([]), null);
});
