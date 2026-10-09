// X-205: non-taint vulnerability classes. Each criterion is tested in both directions: a supported class executes and a
// flawed target is confirmed while a fixed one is refuted; and the hostile reading (taint absence read as a refutation,
// an unsupported case counted as a clean result, a class advertised without fixtures) is refused.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as registry from '../../src/posture/oracles/registry.js';
import { runOracle, FEATURE_ID } from '../../src/posture/oracles/oracle.js';
import {
  SCENARIO_CLASSES, UNSUPPORTED_NON_TAINT, nonTaintClassOf, judgeNonTaintHypothesis, trustedNegativeDenominator, scenarioClassReportLines,
} from '../../src/posture/oracles/scenario-classes.js';
import { emitVerification } from '../../src/posture/verification/emit.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { validateVerificationRecord } from '../../src/posture/assurance/verification-record.js';
import { runFullScan } from '../../src/engine.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';
import { mkTestTmp } from '../helpers/tmp.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const COMMIT = 'e'.repeat(40);
const config = resolveAssuranceConfig({ env: {}, overrides: { features: { [FEATURE_ID]: true } } });

let boundaryReady = false;
let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const report = await probeControls({});
  const unmet = unmetControls(report, [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  boundaryReady = backend === 'userspace' && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the non-taint oracle executions are UNVERIFIED here`;
});
const needsBoundary = (fn) => (t) => (boundaryReady ? fn(t) : t.skip(whyNot));

function classFixture(cls, kind) {
  const dir = path.join(SCANNER, cls.fixtures.dir);
  const sub = path.join(dir, cls.fixtures[kind]);
  const names = fs.readdirSync(sub).filter((n) => n.endsWith('.mjs'));
  assert.equal(names.length, 1, `${cls.id}/${kind}: one source file`);
  return { files: { [names[0]]: fs.readFileSync(path.join(sub, names[0]), 'utf8') }, entry: names[0], inputs: JSON.parse(fs.readFileSync(path.join(dir, cls.fixtures.scenario), 'utf8')) };
}
const requestFor = (cls, kind) => {
  const f = classFixture(cls, kind);
  return { oracleId: cls.adapterId, hypothesisId: `hyp-${cls.id}`, commit: COMMIT, files: f.files, entry: f.entry, inputs: f.inputs, ...(cls.adapterId === 'parser-resource' ? { budgets: { timeoutMs: 2500 } } : {}) };
};
const runClass = (cls, kind) => runOracle(requestFor(cls, kind), { config });

const REQUIRED_CLASSES = ['tenant-authorization', 'privileged-action', 'workflow-order', 'replay-idempotency', 'resource-exhaustion'];

// ---------------------------------------------------------------- AC01

describe('[X-205.AC01] the supported-class manifest names every non-taint class with an executable oracle', () => {
  test('[X-205.AC01] the manifest lists tenant authorization, privileged actions, workflow order, replay/idempotency and bounded resource exhaustion', () => {
    const m = registry.oracleManifest();
    assert.deepEqual(m.problems, []);
    assert.deepEqual(m.nonTaint.classes.map((c) => c.id), REQUIRED_CLASSES);
    for (const c of m.nonTaint.classes) {
      const oracle = registry.getOracle(c.oracle);
      assert.ok(oracle, `${c.id}: its oracle '${c.oracle}' is a registered, executable adapter`);
      assert.ok(oracle.harnessSource.includes('__INPUT__'), `${c.id}: the adapter carries an executable harness`);
      assert.ok(c.prerequisites.length >= 2 && c.requires.length >= 1);
    }
    // reuse is stated, not implied: four classes reuse an existing adapter, replay/idempotency needed a new one
    assert.deepEqual(m.nonTaint.classes.filter((c) => c.adapterReuse).map((c) => c.id), ['tenant-authorization', 'privileged-action', 'workflow-order', 'resource-exhaustion']);
    assert.equal(m.nonTaint.classes.find((c) => c.id === 'replay-idempotency').adapterReuse, false);
    assert.ok(m.nonTaint.classes.every((c) => c.report.join('\n').includes(c.adapterReuse ? 'reused' : 'added for this class')));
    assert.deepEqual(registry.oracleManifest(), m, 'byte-stable');
  });

  test('[X-205.AC01] a class whose oracle is not registered is reported as a problem, never silently advertised', () => {
    const without = registry.listOracles().filter((a) => a.id !== 'replay-idempotency');
    const m = registry.oracleManifest(without);
    assert.ok(m.problems.some((p) => /replay-idempotency/.test(p)), 'the dangling class is named');
    assert.ok(m.uncoveredClasses.includes('replay-idempotency'));
    assert.equal(m.nonTaint.classes.find((c) => c.id === 'replay-idempotency').prerequisites.length, 0, 'a missing adapter contributes no prerequisites');
  });

  test('[X-205.AC01] unsupported non-taint classes are listed by name with their reason', () => {
    const m = registry.oracleManifest();
    assert.deepEqual(m.nonTaint.unsupported.map((u) => u.id), UNSUPPORTED_NON_TAINT.map((u) => u.id));
    assert.ok(m.nonTaint.unsupported.every((u) => u.reason.length > 20 && u.cwes.length));
    assert.ok(m.nonTaint.rules.some((r) => /taint absence never refutes/.test(r)));
  });
});

// ---------------------------------------------------------------- AC02

describe('[X-205.AC02] every advertised class has a real-code positive and a matching negative, and reports disclose limits', () => {
  test('[X-205.AC02] every advertised class has a positive and a negative fixture on disk that differ only by the fix', () => {
    for (const cls of SCENARIO_CLASSES) {
      const pos = classFixture(cls, 'positive');
      const neg = classFixture(cls, 'negative');
      assert.equal(pos.entry, neg.entry, `${cls.id}: matching negative uses the same module name`);
      assert.notEqual(pos.files[pos.entry], neg.files[neg.entry], `${cls.id}: the negative is a different (fixed) revision`);
      assert.ok(pos.files[pos.entry].length > 200, `${cls.id}: real application-style code, not a stub`);
      assert.deepEqual(pos.inputs, neg.inputs, `${cls.id}: both are judged by the same scenario`);
    }
  });

  test('[X-205.AC02] a class advertised without both fixtures is detected', () => {
    const tmp = mkTestTmp('nt-fixtures-');
    fs.mkdirSync(path.join(tmp, 'positive'), { recursive: true });
    fs.writeFileSync(path.join(tmp, 'positive', 'x.mjs'), 'export const a = 1;');
    const missing = (dir) => ['positive', 'negative'].filter((k) => !fs.existsSync(path.join(dir, k)) || fs.readdirSync(path.join(dir, k)).length === 0);
    assert.deepEqual(missing(tmp), ['negative'], 'the helper sees a missing negative');
    for (const cls of SCENARIO_CLASSES) assert.deepEqual(missing(path.join(SCANNER, cls.fixtures.dir)), [], cls.id);
  });

  for (const cls of SCENARIO_CLASSES) {
    test(`[X-205.AC02] ${cls.id}: the positive is confirmed and the matching negative is refuted by the executed oracle`, needsBoundary(async () => {
      const pos = await runClass(cls, 'positive');
      assert.equal(pos.outcome, 'confirmed', pos.reason);
      assert.equal(pos.record.confirmationLevel, 'runtime-confirmed');
      assert.equal(validateVerificationRecord(pos.record).ok, true);
      const neg = await runClass(cls, 'negative');
      assert.equal(neg.outcome, 'refuted', neg.reason);
      assert.equal(neg.record.preconditions.valid, true, 'a refutation needs proven preconditions');
      assert.equal(validateVerificationRecord(neg.record).ok, true);
    }));
  }

  test('[X-205.AC02] user-visible report text carries the prerequisites and every limitation of each class', () => {
    for (const cls of SCENARIO_CLASSES) {
      const adapter = registry.getOracle(cls.adapterId);
      const text = scenarioClassReportLines(cls, adapter).join('\n');
      for (const r of cls.requires) assert.ok(text.includes(r), `${cls.id}: prerequisite shown`);
      for (const p of adapter.prerequisites) assert.ok(text.includes(`host: ${p}`), `${cls.id}: host prerequisite ${p} shown`);
      for (const l of cls.limitations) assert.ok(text.includes(l), `${cls.id}: limitation shown`);
      assert.match(text, /not proof the class is absent/);
      assert.match(text, /Linux unverified/, 'the Linux status is stated honestly');
    }
    // the hostile reading: a report generated from a class stripped of its limitations visibly lacks them
    const cls = SCENARIO_CLASSES[0];
    const stripped = scenarioClassReportLines({ ...cls, limitations: [] }, registry.getOracle(cls.adapterId)).join('\n');
    assert.equal(/limitation:/.test(stripped), false);
  });

  test('[X-205.AC02] every oracle result carries its prerequisites, platform statement and limitations as disclosure', async () => {
    let spawned = 0;
    const deps = { runInBoundary: async () => { spawned++; throw new Error('must not run'); } };
    const cls = SCENARIO_CLASSES.find((c) => c.id === 'replay-idempotency');
    const r = await runOracle(requestFor(cls, 'positive'), { config, deps, probeEnv: { platform: 'darwin', nodeMajor: 18, backend: 'userspace', hasPosixShell: true } });
    assert.equal(r.outcome, 'unsupported', 'an unmet prerequisite is unsupported');
    assert.equal(spawned, 0);
    assert.ok(r.disclosure.prerequisites.some((p) => p.id === 'node-runtime'));
    assert.ok(r.disclosure.limitations.length >= 3);
    assert.ok(r.disclosure.scenarioClasses.some((c) => c.id === 'replay-idempotency' && c.report.join('\n').includes('limitation:')));
  });
});

// ---------------------------------------------------------------- AC03

const authFlawFinding = { stableId: 'stable-authz-1', ruleId: 'missing-tenant-check', cwe: 'CWE-639', family: 'authz', parser: 'logic', file: 'documents-service.mjs', line: 14 };

describe('[X-205.AC03] taint absence never refutes a non-taint hypothesis, and unsupported cases stay out of the denominator', () => {
  test('[X-205.AC03] a taint-clean file with an authorization flaw stays unrefuted (not-run), never refuted', async () => {
    const cls = SCENARIO_CLASSES.find((c) => c.id === 'tenant-authorization');
    const { files } = classFixture(cls, 'positive');
    // the file really is taint-clean: the deep engine finds no taint flow in it
    const scan = await runFullScan({ fileContents: files, scanRoot: mkTestTmp('nt-scan-'), provenance: false, deep: true }, () => {});
    assert.ok(Array.isArray(scan.findings), 'the scan ran');
    const taintFindings = (scan.findings || []).filter((f) => /taint/i.test(String(f.parser)) || /injection|traversal|ssrf/i.test(String(f.family)));
    assert.deepEqual(taintFindings, [], 'no source-to-sink flow exists in this file');

    const verdict = judgeNonTaintHypothesis({ finding: authFlawFinding, taint: { clean: true } });
    assert.equal(verdict.nonTaint, true);
    assert.equal(verdict.outcome, 'not-run');
    assert.notEqual(verdict.outcome, 'refuted');
    assert.equal(verdict.taintAbsenceUsed, false);
    assert.match(verdict.reason, /not a refutation/);

    const hunt = { ...authFlawFinding, discovery: { lens: 'authz', confirmation: { tier: 'unconfirmed', reason: 'no taint probe applies' } } };
    const e = emitVerification('hunt', hunt, { commit: COMMIT });
    assert.equal(e.ok, true, JSON.stringify(e.errors));
    assert.equal(e.record.outcome, 'not-run', 'the emitted record leaves the hypothesis unrefuted');
    assert.match(e.record.reason, /not a refutation/);
    assert.equal(e.legacy.verified, null, 'a legacy consumer sees unknown, not false');
  });

  test('[X-205.AC03] a flawed taint-clean target is confirmed by the executed oracle, so the clean taint result was wrong to rely on', needsBoundary(async () => {
    const cls = SCENARIO_CLASSES.find((c) => c.id === 'tenant-authorization');
    const run = await runClass(cls, 'positive');
    assert.equal(run.outcome, 'confirmed');
    const verdict = judgeNonTaintHypothesis({ finding: authFlawFinding, taint: { clean: true }, oracleResult: { outcome: run.outcome, oracleId: run.record.oracle.id, preconditionsValid: run.record.preconditions.valid } });
    assert.equal(verdict.outcome, 'confirmed');
    const fixed = await runClass(cls, 'negative');
    const refuted = judgeNonTaintHypothesis({ finding: authFlawFinding, taint: { clean: true }, oracleResult: { outcome: fixed.outcome, oracleId: fixed.record.oracle.id, preconditionsValid: fixed.record.preconditions.valid } });
    assert.equal(refuted.outcome, 'refuted', 'only an executed oracle of the class refutes');
  }));

  test('[X-205.AC03] hostile refutation inputs are refused: a taint-probe, another class\'s oracle, or unproved preconditions do not refute', () => {
    const f = authFlawFinding;
    const wrongOracle = judgeNonTaintHypothesis({ finding: f, taint: { clean: true }, oracleResult: { outcome: 'refuted', oracleId: 'parser-resource', preconditionsValid: true } });
    assert.equal(wrongOracle.outcome, 'not-run');
    const taintProbe = judgeNonTaintHypothesis({ finding: f, taint: { clean: true }, oracleResult: { outcome: 'refuted', oracleId: 'taint-engine-confirmation', preconditionsValid: true } });
    assert.equal(taintProbe.outcome, 'not-run');
    const unproved = judgeNonTaintHypothesis({ finding: f, oracleResult: { outcome: 'refuted', oracleId: 'authorization-decision', preconditionsValid: false } });
    assert.equal(unproved.outcome, 'inconclusive');
    const forged = judgeNonTaintHypothesis({ finding: f, taint: { clean: true }, oracleResult: { outcome: 'refuted', oracleId: 'authorization-decision' } });
    assert.equal(forged.outcome, 'inconclusive', 'preconditions must be positively proved');
    for (const v of [wrongOracle, taintProbe, unproved, forged]) assert.equal(v.taintAbsenceUsed, false);
    // a finding that is not a non-taint hypothesis is outside this rule
    assert.equal(judgeNonTaintHypothesis({ finding: { cwe: 'CWE-78', family: 'command-injection' } }).nonTaint, false);
    assert.equal(nonTaintClassOf({ cwe: 'CWE-78' }), null);
  });

  test('[X-205.AC03] an unsupported non-taint case is explicit: unsupported, with its reason, through the judge and the record', () => {
    const race = { stableId: 'stable-race-1', cwe: 'CWE-362', family: 'concurrent-race', parser: 'logic' };
    const verdict = judgeNonTaintHypothesis({ finding: race, taint: { clean: true } });
    assert.equal(verdict.outcome, 'unsupported');
    assert.equal(verdict.supported, false);
    assert.match(verdict.reason, /does not execute/);
    const e = emitVerification('hunt', { ...race, discovery: { lens: 'race', confirmation: { tier: 'unconfirmed' } } }, { commit: COMMIT });
    assert.equal(e.ok, true);
    assert.equal(e.record.outcome, 'unsupported');
    assert.equal(e.record.attempt, 0);
  });

  test('[X-205.AC03] the trusted-negative denominator counts only executed, decided, proved results of advertised classes', () => {
    const runtime = (outcome, over = {}) => ({
      id: `vrec:${outcome}${over.tag || ''}`, outcome, oracle: { id: 'authorization-decision', kind: 'runtime-replay', version: '1' },
      preconditions: { valid: true }, evidence: [{ id: 'oracle-observation', kind: 'trusted-runtime-proof' }], ...over,
    });
    const records = [
      runtime('refuted', { tag: 'a' }), runtime('refuted', { tag: 'b' }), runtime('confirmed', { tag: 'c' }),
      // everything below must be excluded, each for its own stated reason
      { id: 'vrec:u', outcome: 'unsupported', oracle: null, preconditions: { valid: false }, evidence: [] },
      { id: 'vrec:n', outcome: 'not-run', oracle: null, preconditions: { valid: false }, evidence: [] },
      runtime('inconclusive', { tag: 'i' }), runtime('error', { tag: 'e' }),
      runtime('refuted', { tag: 'x', preconditions: { valid: false } }),
      runtime('refuted', { tag: 'y', oracle: { id: 'taint-engine-confirmation', kind: 'static-proof', version: '1' } }),
      runtime('refuted', { tag: 'z', oracle: { id: 'some-unadvertised-oracle', kind: 'runtime-replay', version: '1' } }),
      runtime('refuted', { tag: 'm', evidence: [{ id: 'verdict', kind: 'inference' }] }),
      null,
    ];
    const d = trustedNegativeDenominator(records);
    assert.equal(d.denominator, 3);
    assert.equal(d.trustedNegatives, 2);
    assert.equal(d.trustedPositives, 1);
    assert.equal(d.total, records.length);
    assert.equal(d.excluded.length, records.length - 3);
    const reasons = Object.fromEntries(d.excluded.map((e) => [e.id, e.reason]));
    assert.equal(reasons['vrec:u'], 'unsupported');
    assert.equal(reasons['vrec:n'], 'not-run');
    assert.equal(reasons['vrec:inconclusivei'], 'inconclusive');
    assert.equal(reasons['vrec:errore'], 'error');
    assert.equal(reasons['vrec:refutedx'], 'preconditions-not-proved');
    assert.equal(reasons['vrec:refutedy'], 'no-executed-oracle');
    assert.equal(reasons['vrec:refutedz'], 'oracle-not-in-supported-class-manifest');
    assert.equal(reasons['vrec:refutedm'], 'no-trusted-runtime-proof');
    assert.deepEqual(d.unsupported.map((u) => u.id), ['vrec:u'], 'unsupported cases are listed explicitly');
    assert.deepEqual(trustedNegativeDenominator(undefined).denominator, 0);
  });

  test('[X-205.AC03] a real unsupported record never enters the denominator', () => {
    const race = { stableId: 'stable-race-2', cwe: 'CWE-362', parser: 'logic', discovery: { lens: 'race', confirmation: { tier: 'unconfirmed' } } };
    const e = emitVerification('hunt', race, { commit: COMMIT });
    const d = trustedNegativeDenominator([e.record]);
    assert.equal(d.denominator, 0);
    assert.equal(d.unsupported.length, 1);
  });
});
