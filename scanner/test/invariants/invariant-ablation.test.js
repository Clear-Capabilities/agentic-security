// X-408: the held-out scenario ablation. EVERY case, label and figure here is SYNTHETIC: the benchmark is authored and labelled by
// the tooling's developers, no independent adjudication exists, and nothing below is evidence of real-world benefit or of engine
// accuracy. What is tested is the machinery: a frozen, hash-pinned benchmark; three arms over one denominator and one budget;
// intervals and paired counts; and claims that need executed evidence. Execution tests go through the trust boundary and say
// SKIPPED, NOT PASSED where it cannot run.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import { _resetKeyCacheForTests } from '../../src/posture/integrity.js';
import {
  loadBenchmark, pinBenchmark, runInvariantAblation, renderAblation, releaseClaims, wilson, manifestHashOf, defaultSourceAnalyzer, ARMS, PIN_FILE,
} from '../../src/posture/evaluation/invariant-ablation.js';
import { configWith, boundaryProbe } from '../helpers/invariant-fixtures.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const DIR = path.join(SCANNER, 'test', 'fixtures', 'invariant-benchmark');
// An independent copy of the pin: any edit to a case or its label fails here until this is changed deliberately, in review.
const PINNED_MANIFEST_HASH = 'sha256:322d39bcd149ba14f38be47b01e7eccca77cb64f8735c6890a6983a2d9f0eb7f';
const COMMIT = 'c'.repeat(40);

const KEY_VAR = 'AGENTIC_SECURITY_HMAC_KEY';
let savedKey;
let boundary = { ready: false, why: '' };
let config;
before(async () => {
  savedKey = process.env[KEY_VAR];
  process.env[KEY_VAR] = 'ab'.repeat(32);
  _resetKeyCacheForTests();
  boundary = await boundaryProbe();
  config = await configWith('verification-oracles', 'invariant-scenarios');
});
after(() => {
  if (savedKey === undefined) delete process.env[KEY_VAR]; else process.env[KEY_VAR] = savedKey;
  _resetKeyCacheForTests();
});
const needsBoundary = (fn) => (t) => (boundary.ready ? fn(t) : t.skip(boundary.why));
const clone = (o) => JSON.parse(JSON.stringify(o));

const NO_FINDINGS = async () => ({ findings: [] });
const loaded = () => { const l = loadBenchmark(DIR); assert.equal(l.ok, true, JSON.stringify(l.errors)); return l.benchmark; };

let cachedReport;
const fullRun = async () => (cachedReport ??= await runInvariantAblation({ benchmark: loaded(), commit: COMMIT, config, sourceAnalyzer: NO_FINDINGS }));

describe('[X-408.AC01] a frozen benchmark includes non-taint authorization and workflow defects plus valid workflows and reviewer-approved contracts', () => {
  test('[X-408.AC01] the benchmark is frozen: manifest, every file and the pin agree, and the pin equals the independently recorded hash', () => {
    const b = loaded();
    assert.equal(b.manifestHash, PINNED_MANIFEST_HASH);
    assert.equal(manifestHashOf(b.manifest), PINNED_MANIFEST_HASH);
    assert.equal(b.version, 1);
    assert.equal(b.manifest.synthetic, true);
    assert.match(b.manifest.purpose, /no independent adjudication/);
    assert.match(b.manifest.frozen, /not edited after observing results/);
    assert.equal(Object.keys(b.manifest.files).length, b.cases.length * 3, 'app, contract and hint for every case');
  });

  test('[X-408.AC01] it holds non-taint authorization defects, workflow defects, valid workflows and a reviewer-authored contract per case', () => {
    const b = loaded();
    const by = (cls, defective) => b.cases.filter((c) => c.class === cls && c.defective === defective).map((c) => c.id);
    assert.ok(by('tenant-isolation', true).length >= 2, 'cross-tenant authorization defects');
    assert.ok(by('privilege-constraint', true).length >= 1, 'privilege defects');
    assert.ok(by('workflow-order', true).length >= 1, 'workflow defects');
    assert.ok(by('workflow-order', false).length >= 2, 'valid workflows, including one whose intended design looks like a violation to a naive miner');
    for (const cls of ['tenant-isolation', 'privilege-constraint', 'workflow-order', 'value-conservation', 'idempotency']) {
      assert.ok(by(cls, true).length >= 1 && by(cls, false).length >= 1, `${cls} has both defective and valid cases`);
    }
    assert.deepEqual(b.manifest.counts, { cases: 15, defective: 8, valid: 7 });
    for (const c of b.cases) {
      assert.equal(c.contract.author.kind, 'human', `${c.id}: the contract is reviewer-authored`);
      assert.equal(c.contract.oracle.adapter, 'business-state');
      assert.equal(c.contract.scope.environment, 'disposable-fixture');
      assert.equal(c.contract.review.state, 'proposed', `${c.id}: the file records no approval; approval is a ledger entry made at run time`);
      assert.match(c.files['app.mjs'], /export function createApp/);
      assert.equal(c.hint.source, 'specification-mining');
    }
    // the benchmark is held out from the development fixtures: none of its applications is one of theirs
    const helperSrc = fs.readFileSync(path.join(SCANNER, 'test', 'helpers', 'invariant-fixtures.js'), 'utf8');
    for (const c of b.cases) assert.equal(helperSrc.includes(c.files['app.mjs'].trim()), false, c.id);
  });

  test('[X-408.AC01] a changed case, a changed label, a missing pin and a stray file are all refused (the loader fails closed)', () => {
    const copy = () => { const d = mkTestTmp('as-x408-'); fs.cpSync(DIR, d, { recursive: true }); return d; };
    const expectRefused = (mutate, pattern) => { const d = copy(); mutate(d); const l = loadBenchmark(d); assert.equal(l.ok, false); assert.match(l.errors.join('\n'), pattern); };
    expectRefused((d) => fs.appendFileSync(path.join(d, 'cases', 'plans-admin-only', 'app.mjs'), '// tuned\n'), /digest differs/);
    expectRefused((d) => fs.appendFileSync(path.join(d, 'cases', 'plans-admin-only', 'contract.json'), ' '), /digest differs/);
    expectRefused((d) => fs.rmSync(path.join(d, 'cases', 'plans-admin-only', 'hint.json')), /missing/);
    expectRefused((d) => {
      const m = JSON.parse(fs.readFileSync(path.join(d, 'manifest.json'), 'utf8'));
      m.cases.find((c) => c.id === 'plans-admin-only').defective = true; // relabel a valid case as defective
      fs.writeFileSync(path.join(d, 'manifest.json'), JSON.stringify(m, null, 2));
    }, /no longer matches its pin/);
    expectRefused((d) => fs.rmSync(path.join(d, PIN_FILE)), /not frozen/);
    expectRefused((d) => fs.writeFileSync(path.join(d, 'manifest.json'), '{'), /unreadable/);
    // a deliberate re-pin makes the changed benchmark load again, with a different hash: that is a new version, not this one
    const d = copy();
    const m = JSON.parse(fs.readFileSync(path.join(d, 'manifest.json'), 'utf8'));
    m.version = 2;
    fs.writeFileSync(path.join(d, 'manifest.json'), JSON.stringify(m, null, 2));
    pinBenchmark(d);
    const v2 = loadBenchmark(d);
    assert.equal(v2.ok, true);
    assert.notEqual(v2.benchmark.manifestHash, PINNED_MANIFEST_HASH);
  });
});

describe('[X-408.AC02] evaluation compares source-only analysis, inferred contracts and approved-contract scenario verification with consistent denominators and budgets', () => {
  test('[X-408.AC02] all three arms score the same cases with the same denominators; the budgets are one object recorded once', needsBoundary(async () => {
    const r = await fullRun();
    assert.deepEqual(Object.keys(r.arms), [...ARMS]);
    for (const arm of ARMS) {
      const c = r.arms[arm].counts;
      assert.deepEqual([c.cases, c.positives, c.negatives], [15, 8, 7], arm);
      assert.equal(c.tp + c.fp + c.fn + c.tn, 15, `${arm}: every case is in exactly one cell`);
      assert.equal(r.arms[arm].outcomes.length, 15);
    }
    assert.equal(r.budgets.identicalForEveryArm, true);
    assert.equal(r.budgets.seed, 1);
    assert.ok(r.budgets.sourceTimeoutMs > 0);
    for (const p of Object.values(r.paired)) {
      assert.equal(p.defects.both + p.defects.armOnly + p.defects.baselineOnly + p.defects.neither, 8);
      assert.equal(p.valid.bothFlagged + p.valid.armOnly + p.valid.baselineOnly + p.valid.neither, 7);
    }
  }));

  test('[X-408.AC02] a case an arm cannot evaluate stays in its denominator as a miss and is named, never dropped', needsBoundary(async () => {
    const r = await fullRun();
    const inferred = r.arms['inferred-contract'];
    const noContract = inferred.outcomes.filter((o) => o.status === 'no-contract').map((o) => o.caseId).sort();
    assert.deepEqual(noContract, ['ledger-duplicate-credit', 'ledger-idempotent-settle', 'payments-concurrent-double-charge', 'payments-single-capture', 'refunds-no-dedupe']);
    assert.equal(inferred.counts.cases, 15, 'the five classes the miner has no skeleton for are still scored');
    assert.deepEqual(inferred.notEvaluated.map((n) => n.caseId).sort().filter((id) => noContract.includes(id)), noContract);
    assert.ok(inferred.counts.fn >= 3, 'the defects it could not even propose a contract for are misses');
    assert.ok(inferred.recall.value < r.arms['approved-contract'].recall.value);
    // a source-only arm that crashes is a miss on every case, not an exclusion
    const crashed = await runInvariantAblation({ benchmark: loaded(), commit: COMMIT, config, sourceAnalyzer: async () => { throw new Error('scanner unavailable'); }, bounds: { scenarios: 1 } });
    assert.equal(crashed.arms['source-only'].counts.cases, 15);
    assert.equal(crashed.arms['source-only'].counts.fn, 8);
    assert.equal(crashed.arms['source-only'].notEvaluated.length, 15);
    assert.match(crashed.arms['source-only'].outcomes[0].reason, /scanner unavailable/);
  }));

  test('[X-408.AC02] the unapproved arm can only produce candidates: nothing it flags is confirmed', needsBoundary(async () => {
    const r = await fullRun();
    assert.equal(r.arms['inferred-contract'].confirmedTruePositives, 0);
    assert.ok(r.arms['inferred-contract'].outcomes.every((o) => o.confirmed === false));
    assert.equal(r.arms['source-only'].confirmedTruePositives, 0);
    assert.ok(r.arms['approved-contract'].confirmedTruePositives > 0);
    assert.equal(r.unique['approved-contract'].uniqueConfirmed, r.unique['approved-contract'].uniqueTruePositives);
    assert.equal(r.unique['inferred-contract'].uniqueConfirmed, 0);
  }));

  test('[X-408.AC02] flags are produced before any label is consulted: relabelling the cases moves the scores and not one flag', needsBoundary(async () => {
    const b = loaded();
    const flipped = { ...b, cases: b.cases.map((c) => ({ ...c, defective: !c.defective })) };
    const r2 = await runInvariantAblation({ benchmark: flipped, commit: COMMIT, config, sourceAnalyzer: NO_FINDINGS });
    const r1 = await fullRun();
    for (const arm of ARMS) {
      assert.deepEqual(r2.arms[arm].outcomes.map((o) => [o.caseId, o.flagged]), r1.arms[arm].outcomes.map((o) => [o.caseId, o.flagged]), `${arm}: identical flags`);
    }
    assert.notEqual(r2.arms['approved-contract'].counts.tp, r1.arms['approved-contract'].counts.tp, 'only the scoring moved');
  }));

  test('[X-408.AC02] the report is deterministic apart from wall time', needsBoundary(async () => {
    const a = await fullRun();
    const b = await runInvariantAblation({ benchmark: loaded(), commit: COMMIT, config, sourceAnalyzer: NO_FINDINGS });
    assert.equal(b.fingerprint, a.fingerprint);
    const stub = await runInvariantAblation({ benchmark: loaded(), commit: COMMIT, config, sourceAnalyzer: async ({ caseId }) => ({ findings: caseId === 'plans-admin-only' ? [{ severity: 'high', file: 'app.mjs', family: 'x' }] : [] }) });
    assert.notEqual(stub.fingerprint, a.fingerprint, 'a different baseline outcome changes the fingerprint');
    assert.equal(stub.arms['source-only'].counts.fp, 1, 'a medium-or-above finding in the case file is a flag of any family');
  }));

  test('[X-408.AC02] the source-only arm is the real engine: a deep-mode scan of the case file runs and returns its findings', async () => {
    const b = loaded();
    const r = await defaultSourceAnalyzer({ files: b.cases[0].files, tmpRoot: mkTestTmp('as-x408-src-'), timeoutMs: 90000 });
    assert.ok(Array.isArray(r.findings), 'a real scan result came back');
    assert.deepEqual(Object.keys(b.cases[0].files), ['app.mjs'], 'the engine sees only the source, never a contract, hint or label');
  });

  test('[X-408.AC02] intervals are Wilson 95%: wide for small n, honest at the edges, and absent rather than invented for n = 0', () => {
    assert.deepEqual(wilson(0, 0), { low: null, high: null });
    const all = wilson(8, 8); assert.equal(all.high, 1); assert.ok(all.low > 0.6 && all.low < 0.7, `${all.low}`);
    const none = wilson(0, 8); assert.equal(none.low, 0); assert.ok(none.high > 0.3 && none.high < 0.35);
    const mid = wilson(4, 8); assert.ok(mid.low < 0.5 && mid.high > 0.5);
    assert.ok(wilson(80, 80).low > wilson(8, 8).low, 'more data, tighter interval');
  });
});

describe('[X-408.AC03] supported-class release claims require executable evidence and report precision, recall, unique confirmed findings and scenario cost', () => {
  const cases = [
    { id: 'd1', class: 'k', defective: true }, { id: 'v1', class: 'k', defective: false },
  ];
  const mk = (flags, extra = {}) => Object.fromEntries(Object.entries(flags).map(([id, f]) => [id, { flagged: f, confirmed: f, executed: true, decided: true, complete: true, cost: { scenarios: 1, requests: 3, ms: 1 }, ...extra }]));
  const base = (over = {}) => ({
    'source-only': mk({ d1: false, v1: false }, { confirmed: false, cost: { scenarios: 0, requests: 0, ms: 1 } }), 'inferred-contract': mk({ d1: false, v1: false }, { confirmed: false }),
    'approved-contract': mk({ d1: true, v1: false }), ...over,
  });
  const policy = { minDefectCasesPerClass: 1, minValidCasesPerClass: 1, minPrecision: 1, minRecall: 1, noLossVersusSourceOnly: true };

  test('[X-408.AC03] a class is supported only from executed, settled evidence that meets the registered policy', () => {
    const c = releaseClaims({ cases, outcomes: base(), policy }).k;
    assert.equal(c.status, 'supported');
    assert.equal(c.precision.value, 1); assert.equal(c.recall.value, 1);
    assert.equal(c.uniqueConfirmed, 1, 'the approved arm confirmed a defect neither other arm found');
    assert.deepEqual(c.scenarioCost, { scenarios: 2, requests: 6 });
    assert.match(c.scope, /synthetic fixtures only; no real-world claim/);
    assert.ok(c.precision.low !== null && c.recall.high !== null, 'intervals accompany every rate');
  });

  test('[X-408.AC03] anything not executed is UNMEASURED, never supported and never unsupported-by-absence', () => {
    const notRun = base({ 'approved-contract': mk({ d1: false, v1: false }, { executed: false, decided: false, confirmed: false }) });
    const c = releaseClaims({ cases, outcomes: notRun, policy }).k;
    assert.equal(c.status, 'unmeasured');
    assert.match(c.reasons[0], /not executed: d1, v1/);
    const one = base(); one['approved-contract'].v1 = { ...one['approved-contract'].v1, executed: false };
    assert.equal(releaseClaims({ cases, outcomes: one, policy }).k.status, 'unmeasured', 'one unexecuted case is enough');
  });

  test('[X-408.AC03] a missed defect, a false positive, an unsettled case, a thin class or a lost baseline defect each make a class unsupported, with the reason', () => {
    const missed = releaseClaims({ cases, outcomes: base({ 'approved-contract': mk({ d1: false, v1: false }, { confirmed: false }) }), policy }).k;
    assert.equal(missed.status, 'unsupported'); assert.match(missed.reasons.join(), /recall 0\.00 below 1/);
    const fp = releaseClaims({ cases, outcomes: base({ 'approved-contract': mk({ d1: true, v1: true }) }), policy }).k;
    assert.equal(fp.status, 'unsupported'); assert.match(fp.reasons.join(), /precision 0\.50 below 1/);
    const unsettled = base(); unsettled['approved-contract'].v1 = { ...unsettled['approved-contract'].v1, decided: false };
    assert.match(releaseClaims({ cases, outcomes: unsettled, policy }).k.reasons.join(), /did not settle: v1/);
    const thin = releaseClaims({ cases: [cases[0]], outcomes: { 'source-only': { d1: base()['source-only'].d1 }, 'inferred-contract': { d1: base()['inferred-contract'].d1 }, 'approved-contract': { d1: base()['approved-contract'].d1 } }, policy }).k;
    assert.equal(thin.status, 'unsupported'); assert.match(thin.reasons.join(), /fewer than 1 valid case/);
    const lost = base({ 'source-only': mk({ d1: true, v1: false }, { confirmed: false }), 'approved-contract': mk({ d1: false, v1: false }, { confirmed: false }) });
    assert.match(releaseClaims({ cases, outcomes: lost, policy }).k.reasons.join(), /lost baseline-found defect\(s\): d1/);
    const stricter = releaseClaims({ cases, outcomes: base(), policy: { ...policy, minDefectCasesPerClass: 2 } }).k;
    assert.equal(stricter.status, 'unsupported', 'a registered minimum is enforced');
  });

  test('[X-408.AC03] the full run reports precision, recall, unique findings, scenario cost and per-class claims, labelled synthetic', needsBoundary(async () => {
    const r = await fullRun();
    assert.equal(r.synthetic, true);
    assert.equal(r.realWorldClaim, false);
    assert.match(r.note, /SYNTHETIC/);
    for (const arm of ARMS) {
      const a = r.arms[arm];
      for (const m of ['precision', 'recall']) assert.ok('value' in a[m] && 'low' in a[m] && 'high' in a[m] && Number.isInteger(a[m].k) && Number.isInteger(a[m].n), `${arm} ${m}`);
      assert.ok(Number.isInteger(a.cost.scenarios) && Number.isInteger(a.cost.requests), `${arm} scenario cost`);
      assert.ok(Number.isInteger(r.unique[arm].uniqueTruePositives) && Number.isInteger(r.unique[arm].uniqueConfirmed));
    }
    assert.ok(r.arms['approved-contract'].cost.scenarios > 0 && r.arms['source-only'].cost.scenarios === 0);
    assert.deepEqual(Object.keys(r.claims).sort(), ['idempotency', 'privilege-constraint', 'tenant-isolation', 'value-conservation', 'workflow-order']);
    for (const c of Object.values(r.claims)) assert.ok(['supported', 'unsupported', 'unmeasured'].includes(c.status));
    const text = renderAblation(r).join('\n');
    assert.match(text, /SYNTHETIC/);
    assert.match(text, /class claims \(executed evidence only\)/);
    assert.equal(/real-world benefit (is|was) (shown|demonstrated|proven)/i.test(text), false);
  }));

  test('[X-408.AC03] when nothing can be executed, no class is supported: the claims read UNMEASURED', async () => {
    const spy = { deps: { runInBoundary: async () => ({ blocked: true, reasons: ['spy'] }) } };
    const r = await runInvariantAblation({ benchmark: loaded(), commit: COMMIT, config, sourceAnalyzer: NO_FINDINGS, runOptions: spy });
    for (const [cls, c] of Object.entries(r.claims)) assert.equal(c.status, 'unmeasured', cls);
    assert.equal(r.arms['approved-contract'].counts.tp, 0);
    assert.ok(r.arms['approved-contract'].outcomes.every((o) => o.executed === false));
    assert.equal(r.arms['approved-contract'].counts.cases, 15, 'the denominator does not shrink because nothing ran');
  });

  test('[X-408.AC03] the committed driver exits 0 on the intact benchmark and 1 on a changed one', async () => {
    const { spawnSync } = await import('node:child_process');
    const script = path.join(SCANNER, '..', 'scripts', 'invariant-ablation.mjs');
    const ok = spawnSync(process.execPath, [script, 'verify'], { encoding: 'utf8' });
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /benchmark intact: v1, 15 synthetic cases/);
    const d = mkTestTmp('as-x408-drv-'); fs.cpSync(DIR, d, { recursive: true });
    fs.appendFileSync(path.join(d, 'cases', 'plans-admin-only', 'app.mjs'), '//\n');
    const bad = spawnSync(process.execPath, [script, 'verify', '--fixtures', d], { encoding: 'utf8' });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /NOT intact/);
    assert.equal(spawnSync(process.execPath, [script, 'bogus'], { encoding: 'utf8' }).status, 2);
  });
});
