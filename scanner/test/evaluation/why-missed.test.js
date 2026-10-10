// QA-005.AC01 and QA-005.AC03: every labelled development miss gets a deterministic earliest failed stage (or an explicit unknown),
// and a fix to suppression or attribution is shown by before/after stage counts with the recovered examples named.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { classifyMiss, classifyMisses, stageCounts, compareMisses, collectDiagnostics, STAGES, UNKNOWN } from '../../src/posture/evaluation/why-missed.js';
import { buildDevSuite, devResolver } from '../../src/posture/evaluation/dev-cases.js';
import { runEvaluation } from '../../src/posture/evaluation/runner.js';
import { scoreRun } from '../../src/posture/evaluation/score.js';
import { protectedTermsFrom } from '../../src/posture/evaluation/custody.js';
import { mkTestTmp } from '../helpers/tmp.js';

const FIXTURES = path.resolve(import.meta.dirname, '../fixtures/engine-mechanisms');
const policy = { lineWindow: 3 };
const label = (over = {}) => ({ id: 'dlab:1', targetId: 't1', language: 'javascript', family: 'ssrf', cwe: 'CWE-918', location: { file: 'app.js', startLine: 10, endLine: 10 }, ...over });
const done = (findings = []) => ({ status: 'completed', findings });
const diag = (over = {}) => ({ suppressions: [], stageEvidence: { dedupe: [], guard: [] }, sources: [], sinks: [], ir: { files: { 'app.js': { lowered: true, functions: [{ line: 1, name: 'h' }] } }, parseFailures: { count: 0, byLanguage: {}, firstError: null } }, ...over });
const classify = (o) => classifyMiss({ label: label(), outcome: done(), diagnostics: diag(), policy, ...o });

describe('[QA-005.AC01] each miss gets a deterministic earliest failed stage, with the evidence that decided it', () => {
  test('a scan that did not complete fails at scan-execution, with its own reason; no diagnostics at all is an explicit unknown', () => {
    for (const status of ['timeout', 'error', 'unavailable', 'quarantined']) {
      const c = classify({ outcome: { status, findings: [], failureReason: 'x' } });
      assert.equal(c.stage, 'scan-execution'); assert.equal(c.reason, `scan-${status}`);
    }
    assert.equal(classify({ outcome: null }).reason, 'no-outcome-recorded');
    const u = classify({ diagnostics: null });
    assert.equal(u.stage, UNKNOWN); assert.equal(u.reason, 'no-diagnostic-evidence');
  });

  test('parser-ir: the file lowered to no function, or the parser reported a failure for the language', () => {
    const none = classify({ diagnostics: diag({ ir: { files: { 'app.js': { lowered: true, functions: [] } }, parseFailures: { count: 0, byLanguage: {}, firstError: null } } }) });
    assert.equal(none.stage, 'parser-ir'); assert.equal(none.reason, 'no-function-lowered');
    const failed = classify({ diagnostics: diag({ ir: { files: {}, parseFailures: { count: 2, byLanguage: { js: 2 }, firstError: { file: 'app.js', message: 'x' } } } }) });
    assert.equal(failed.stage, 'parser-ir'); assert.equal(failed.reason, 'ir-parse-failure');
  });

  test('source-modelling, then sink-modelling, then propagation: each only when everything before it was recognised', () => {
    const noSource = classify({ diagnostics: diag() });
    assert.equal(noSource.stage, 'source-modelling'); assert.equal(noSource.reason, 'no-source-recognized');
    const elsewhere = classify({ diagnostics: diag({ sources: [{ file: 'other.js', line: 3 }] }) });
    assert.equal(elsewhere.reason, 'no-source-in-defect-file');
    const noSink = classify({ diagnostics: diag({ sources: [{ file: 'app.js', line: 4 }] }) });
    assert.equal(noSink.stage, 'sink-modelling'); assert.equal(noSink.reason, 'no-sink-recognized-near-defect');
    const both = classify({ diagnostics: diag({ sources: [{ file: 'app.js', line: 4 }], sinks: [{ file: 'app.js', line: 10 }] }) });
    assert.equal(both.stage, 'propagation'); assert.equal(both.reason, 'source-and-sink-recognized-no-flow');
    const farSink = classify({ diagnostics: diag({ sources: [{ file: 'app.js', line: 4 }], sinks: [{ file: 'app.js', line: 90 }] }) });
    assert.equal(farSink.stage, 'sink-modelling', 'a sink far from the defect does not stand in for it');
  });

  test('filters and suppression: a dropped candidate names the mechanism and keeps its identity; policy is told apart from precision filters', () => {
    const entry = (reason) => ({ id: 'ir-taint:app.js:10:x', file: 'app.js', line: 10, vuln: 'SSRF', cwe: 'CWE-918', family: 'ssrf', reason });
    const f = classify({ diagnostics: diag({ suppressions: [entry('guard-recognized:ssrf-host-guard:dominates@8:early-exit-on-guard-line')] }) });
    assert.equal(f.stage, 'filters'); assert.equal(f.reason, 'guard-recognized:ssrf-host-guard');
    assert.equal(f.evidence.ledger.id, 'ir-taint:app.js:10:x'); assert.equal(f.evidence.ledger.family, 'ssrf'); assert.equal(f.evidence.ledger.identity, 'family');
    const s = classify({ diagnostics: diag({ suppressions: [entry('inline-pragma:ssrf')] }) });
    assert.equal(s.stage, 'suppression');
    const s2 = classify({ diagnostics: diag({ suppressions: [entry('custom-rule:legacy')] }) });
    assert.equal(s2.stage, 'suppression');
    // unrelated: another family at the same line, or the same family far away, is not this defect's drop
    const other = classify({ diagnostics: diag({ suppressions: [{ ...entry('guard-recognized:x'), family: 'xss', cwe: 'CWE-79' }, { ...entry('guard-recognized:x'), line: 80 }] }) });
    assert.notEqual(other.stage, 'filters');
  });

  test('deduplication: a candidate collapsed into a winner at another location; attribution: reported at the wrong line or under the wrong family', () => {
    const d = classify({ diagnostics: diag({ stageEvidence: { guard: [], dedupe: [{ file: 'app.js', family: 'ssrf', loser: { id: 'a', file: 'app.js', line: 10, parser: 'JS-FW' }, winner: { id: 'b', file: 'app.js', line: 90, parser: 'REGEX' } }] } }) });
    assert.equal(d.stage, 'deduplication'); assert.equal(d.evidence.winner.line, 90);
    const keptNearby = classify({ diagnostics: diag({ stageEvidence: { guard: [], dedupe: [{ file: 'app.js', family: 'ssrf', loser: { file: 'app.js', line: 10 }, winner: { file: 'app.js', line: 11 } }] } }) });
    assert.notEqual(keptNearby.stage, 'deduplication', 'a winner inside the window is not a loss');
    const wrongLine = classify({ outcome: done([{ id: 'f', file: 'app.js', line: 31, family: 'ssrf', cwe: 'CWE-918' }]) });
    assert.equal(wrongLine.stage, 'attribution'); assert.equal(wrongLine.reason, 'right-file-and-family-wrong-line'); assert.equal(wrongLine.evidence.distanceLines, 18);
    const wrongFamily = classify({ outcome: done([{ id: 'f', file: 'app.js', line: 10, family: 'xss', cwe: 'CWE-79' }]) });
    assert.equal(wrongFamily.stage, 'attribution'); assert.equal(wrongFamily.reason, 'right-location-wrong-family');
  });

  test('a candidate observed downstream proves the early stages worked: it is named even when the early-stage evidence is empty', () => {
    const c = classify({ diagnostics: diag({ sources: [], sinks: [], suppressions: [{ id: 'z', file: 'app.js', line: 10, cwe: 'CWE-918', family: 'ssrf', reason: 'guard-recognized:ssrf-host-guard' }] }) });
    assert.equal(c.stage, 'filters', 'not source-modelling');
  });

  test('a family with no taint flow (a pattern rule) is a sink-modelling miss when nothing fired; the taint-less layer says so', () => {
    const weak = { family: 'weak-crypto', cwe: 'CWE-327' };
    assert.equal(classify({ label: label(weak) }).reason, 'no-detector-rule-fired');
    assert.equal(classify({ label: label({ family: 'sql-injection', cwe: 'CWE-89' }), layer: 'deterministic-only' }).reason, 'no-pattern-rule-fired-and-taint-layer-not-run');
  });

  test('classification is deterministic and independent of input order; every result names a known stage or the explicit unknown', () => {
    const labels = [label({ id: 'dlab:b', targetId: 'tb' }), label({ id: 'dlab:a', targetId: 'ta' })];
    const score = { misses: [{ labelId: 'dlab:b', targetId: 'tb' }, { labelId: 'dlab:a', targetId: 'ta' }] };
    const run = { outcomes: [{ targetId: 'ta', variant: 'pre', ...done() }, { targetId: 'tb', variant: 'pre', status: 'timeout', findings: [], failureReason: 'x' }] };
    const out1 = classifyMisses({ score, defects: labels, run, diagnosticsFor: () => diag(), policy });
    const out2 = classifyMisses({ score: { misses: [...score.misses].reverse() }, defects: [...labels].reverse(), run, diagnosticsFor: () => diag(), policy });
    assert.deepEqual(out1, out2);
    assert.deepEqual(out1.map((c) => c.labelId), ['dlab:a', 'dlab:b']);
    for (const c of out1) assert.ok([...STAGES, UNKNOWN].includes(c.stage));
    const counts = stageCounts(out1);
    assert.equal(counts.total, 2); assert.equal(counts.byStage['scan-execution'], 1); assert.equal(counts.byStage['source-modelling'], 1);
  });

  test('a miss whose label was not supplied is an explicit unknown, never dropped', () => {
    const out = classifyMisses({ score: { misses: [{ labelId: 'dlab:ghost', targetId: 't' }] }, defects: [], run: { outcomes: [] }, diagnosticsFor: () => null, policy });
    assert.equal(out[0].stage, UNKNOWN); assert.equal(out[0].reason, 'label-not-supplied');
  });
});

describe('[QA-005.AC01] diagnostics come from the engine itself, over the DEVELOPMENT split only', () => {
  test('the sealed split is refused outright: a sealed miss is never re-scanned for diagnosis', async () => {
    const suite = buildDevSuite({ fixturesDir: FIXTURES });
    const sealedProtocol = { ...suite.protocol, splits: { dev: [], sealed: suite.protocol.splits.dev } };
    const r = await collectDiagnostics({ protocol: sealedProtocol, score: { misses: [{ labelId: 'x', targetId: suite.protocol.splits.dev[0] }] }, defects: suite.defects, resolveTarget: devResolver(FIXTURES) });
    assert.equal(r.ok, false); assert.equal(r.errors[0].code, 'SEALED_ACCESS'); assert.equal(r.diagnostics.size, 0);
  });

  test('a real miss, diagnosed by a real scan: a defect label on a tree whose candidate a guard cleared is a `filters` miss with the ledger identity', async () => {
    const root = mkTestTmp('qa5-diag-');
    const cases = [{ id: 'cleared-by-guard', mechanism: 'x', language: 'javascript', family: 'ssrf', cwe: 'CWE-918', file: 'app.js', startLine: 10, endLine: 10 }];
    for (const v of ['pre', 'post']) { fs.mkdirSync(path.join(root, 'cleared-by-guard', v), { recursive: true }); fs.copyFileSync(path.join(FIXTURES, 'guard-after-sink-js', 'post', 'app.js'), path.join(root, 'cleared-by-guard', v, 'app.js')); }
    const suite = buildDevSuite({ fixturesDir: root, cases });
    assert.ok(suite.protocol, JSON.stringify(suite.freezeErrors));
    const terms = protectedTermsFrom({ defects: suite.defects, negatives: suite.negatives });
    const r = await runEvaluation({ protocol: suite.protocol, config: { layer: 'deep-taint' }, resolveTarget: devResolver(root), protectedTerms: terms, split: 'dev' });
    const score = scoreRun({ run: r.run, protocol: suite.protocol, defects: suite.defects, negatives: suite.negatives });
    assert.equal(score.misses.length, 1, 'the guarded call is not reported, so the label is a miss');
    const dg = await collectDiagnostics({ protocol: suite.protocol, score, defects: suite.defects, resolveTarget: devResolver(root), protectedTerms: terms });
    assert.equal(dg.ok, true);
    const [c] = classifyMisses({ score, defects: suite.defects, run: r.run, diagnosticsFor: (t) => dg.diagnostics.get(t) || null, policy: suite.protocol.matching });
    assert.equal(c.stage, 'filters'); assert.equal(c.reason, 'guard-recognized:ssrf-host-guard');
    assert.equal(c.evidence.ledger.family, 'ssrf'); assert.equal(c.evidence.ledger.line, 10); assert.match(c.evidence.ledger.reason, /dominates@/);
  });

  test('diagnose mode only observes: the findings of a plain scan and a diagnosed scan are identical', async () => {
    const { defaultScanFn } = await import('../../src/posture/evaluation/runner.js');
    const env = { PATH: process.env.PATH, LANG: 'C', HOME: mkTestTmp('qa5-home-') };
    const dir = path.join(FIXTURES, 'guard-after-sink-js', 'pre');
    const plain = await defaultScanFn(dir, { layer: 'deep-taint', timeoutMs: 120000, env });
    const diagnosed = await defaultScanFn(dir, { layer: 'deep-taint', timeoutMs: 120000, env, diagnose: true });
    assert.deepEqual(diagnosed.findings, plain.findings);
    assert.ok(diagnosed.diagnostics && Array.isArray(diagnosed.diagnostics.suppressions));
    assert.equal(plain.diagnostics, undefined);
  });
});

describe('[QA-005.AC03] a fix to suppression or attribution is shown by stage counts and named recoveries, and new false positives are never netted away', () => {
  const miss = (id, stage, reason) => ({ labelId: id, targetId: `t-${id}`, stage, reason });
  const fp = (t, line) => ({ labelId: 'n', targetId: t, finding: { file: 'a.js', family: 'ssrf', line } });

  test('recoveries are the labels that were misses before and are not after, each with the stage that lost it', () => {
    const before = [miss('a', 'filters', 'guard-recognized:ssrf-host-guard'), miss('b', 'attribution', 'right-file-and-family-wrong-line'), miss('c', 'source-modelling', 'no-source-recognized')];
    const after = [miss('c', 'source-modelling', 'no-source-recognized')];
    const cmp = compareMisses({ before, after, scoreBefore: { falsePositives: [] }, scoreAfter: { falsePositives: [] } });
    assert.deepEqual(cmp.recovered.map((r) => [r.labelId, r.lostAtStage]), [['a', 'filters'], ['b', 'attribution']]);
    assert.equal(cmp.stageCounts.before.byStage.filters, 1); assert.equal(cmp.stageCounts.after.byStage.filters, 0);
    assert.equal(cmp.stageCounts.before.total, 3); assert.equal(cmp.stageCounts.after.total, 1);
    assert.equal(cmp.verdict, 'recovered-without-new-false-positives');
  });

  test('a recovery that brings a new false positive is reported as such (control: the same recovery without one is clean)', () => {
    const before = [miss('a', 'filters', 'x')]; const after = [];
    const dirty = compareMisses({ before, after, scoreBefore: { falsePositives: [fp('t1', 5)] }, scoreAfter: { falsePositives: [fp('t1', 5), fp('t2', 9)] } });
    assert.equal(dirty.verdict, 'recovered-with-new-false-positives');
    assert.equal(dirty.falsePositives.newFalsePositives.length, 1); assert.equal(dirty.falsePositives.newFalsePositives[0].targetId, 't2');
    const clean = compareMisses({ before, after, scoreBefore: { falsePositives: [fp('t1', 5)] }, scoreAfter: { falsePositives: [fp('t1', 5)] } });
    assert.equal(clean.verdict, 'recovered-without-new-false-positives');
    assert.equal(compareMisses({ before, after: before, scoreBefore: { falsePositives: [] }, scoreAfter: { falsePositives: [] } }).verdict, 'no-recovery');
  });

  test('the recorded before/after measurement of the development suite is retained, and its after-side matches the engine as it is now', async () => {
    const rec = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'measured-before-after.json'), 'utf8'));
    assert.match(rec.note, /development/i);
    assert.ok(rec.before.development.cases.length === rec.after.development.cases.length && rec.after.development.cases.length >= 8);
    assert.ok(rec.after.development.micro.tp > rec.before.development.micro.tp, 'recovery rose');
    assert.ok(rec.after.development.micro.fp <= rec.before.development.micro.fp, 'false positives on patched trees did not rise');
    // the after-side must be true of the engine in this checkout
    const suite = buildDevSuite({ fixturesDir: FIXTURES });
    const terms = protectedTermsFrom({ defects: suite.defects, negatives: suite.negatives });
    const r = await runEvaluation({ protocol: suite.protocol, config: { layer: 'deep-taint' }, resolveTarget: devResolver(FIXTURES), protectedTerms: terms, split: 'dev' });
    const score = scoreRun({ run: r.run, protocol: suite.protocol, defects: suite.defects, negatives: suite.negatives });
    assert.equal(score.endToEnd.micro.tp, rec.after.development.micro.tp);
    assert.equal(score.endToEnd.micro.fn, rec.after.development.micro.fn);
    assert.equal(score.endToEnd.micro.fp, rec.after.development.micro.fp);
    assert.equal(score.misses.length, 0, 'every development defect is recovered');
    assert.equal(score.falsePositives.length, 0, 'every patched twin stays silent');
  });
});
