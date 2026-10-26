// Structural tests for bench/dag. They do not run scans (the bench itself does);
// they pin the properties that make its numbers trustworthy:
//   * the synthetic generators are seeded, reproducible and match their
//     construction-derived properties under the repository's own SCC code;
//   * the label sets are well formed, point at real lines of the pinned
//     sources when those are cached, and the held-out split is stable;
//   * the scored fixture carries no answer key;
//   * scoring uses equality-style, explicit-denominator arithmetic.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generate, FAMILIES, SCC_BLOCK_SIZE } from '../../../bench/dag/synthetic/generate.mjs';
import { measureSynthetic } from '../../../bench/dag/synthetic/measure.mjs';
import { CLASS_CWE, isHeldOut, outcome, aggregate, scoreSiteLabel, scoreFlowLabel } from '../../../bench/dag/lib/labels.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DAG = path.resolve(HERE, '..', '..', '..', 'bench', 'dag');
const manifest = JSON.parse(fs.readFileSync(path.join(DAG, 'manifest.json'), 'utf8'));
const real = JSON.parse(fs.readFileSync(path.join(DAG, 'labels', 'real.json'), 'utf8')).labels;
const fixtureDoc = JSON.parse(fs.readFileSync(path.join(DAG, 'labels', 'multiservice.json'), 'utf8'));
const mutants = JSON.parse(fs.readFileSync(path.join(DAG, 'fixtures', 'mutants.json'), 'utf8')).mutants;

test('synthetic generators are reproducible for a seed and differ across seeds where randomness is used', () => {
  for (const f of FAMILIES) {
    const a = generate(f, 256, 5);
    const b = generate(f, 256, 5);
    assert.equal(a.digest, b.digest, f);
    assert.deepEqual(a.edges, b.edges, f);
  }
  assert.notEqual(generate('scc-rich', 256, 1).digest, generate('scc-rich', 256, 2).digest);
});

test('every synthetic family matches its construction-derived SCC properties and verifies', () => {
  for (const f of FAMILIES) {
    for (const n of [64, 1000, SCC_BLOCK_SIZE * 40 + 3]) {
      const r = measureSynthetic({ family: f, n, seed: 11 });
      assert.equal(r.matchesExpected, true, `${f}/${n}: ${JSON.stringify(r.observed)} vs ${JSON.stringify(r.expected)}`);
      assert.equal(r.verifyScc, true, `${f}/${n}`);
    }
  }
});

test('generator rejects unusable input rather than guessing', () => {
  assert.throws(() => generate('nope', 10, 1));
  assert.throws(() => generate('chain', 1, 1));
  assert.throws(() => generate('scc-rich', 4, 1));
});

test('manifest pins are full 40-hex commits with licenses, roots and a documented exclusion', () => {
  const langs = new Set(manifest.projects.map((p) => p.language));
  assert.deepEqual([...langs].sort(), ['haskell', 'js', 'nix']);
  for (const p of manifest.projects) {
    assert.match(p.commit, /^[0-9a-f]{40}$/, p.id);
    assert.match(p.url, /^https:\/\/github\.com\/[^/]+\/[^/]+\.git$/, p.id);
    assert.ok(p.license && p.licenseFile && p.buildConfig && p.excluded && p.commitDate, p.id);
    assert.ok(p.scanRoots.length > 0, p.id);
  }
  const count = (l) => manifest.projects.filter((p) => p.language === l).length;
  assert.ok(count('js') >= 2 && count('haskell') >= 2 && count('nix') >= 2, 'PRD 8.3 minimum project counts');
  assert.match(manifest.acquiredAt, /^\d{4}-\d{2}-\d{2}$/);
});

test('real labels are well formed, uniquely identified and cover every language', () => {
  const ids = new Set();
  const projects = new Map(manifest.projects.map((p) => [p.id, p]));
  for (const l of real) {
    assert.ok(!ids.has(l.id), `duplicate ${l.id}`);
    ids.add(l.id);
    assert.ok(projects.has(l.project), l.id);
    assert.equal(projects.get(l.project).language, l.language, l.id);
    assert.ok(CLASS_CWE[l.class], `unknown class ${l.class}`);
    assert.ok(['positive', 'negative', 'ambiguous'].includes(l.verdict), l.id);
    assert.ok(Number.isInteger(l.line) && l.line > 0, l.id);
    assert.ok(l.evidence && l.evidence.length > 10, `${l.id} has no evidence note`);
  }
  for (const lang of ['js', 'haskell', 'nix']) {
    const rows = real.filter((l) => l.language === lang && l.verdict !== 'ambiguous');
    assert.ok(rows.some((l) => l.verdict === 'positive'), `${lang} has a positive`);
    assert.ok(rows.some((l) => l.verdict === 'negative'), `${lang} has a negative`);
  }
});

test('label sites exist in the pinned sources when the cache is present', (t) => {
  const cache = path.join(DAG, '.cache');
  if (!fs.existsSync(cache)) { t.skip('bench/dag/.cache not acquired (run node bench/dag/acquire.mjs)'); return; }
  let checked = 0;
  for (const l of real) {
    const file = path.join(cache, l.project, l.file);
    if (!fs.existsSync(path.join(cache, l.project))) continue;
    assert.ok(fs.existsSync(file), `${l.id}: ${l.file} missing at the pinned commit`);
    const lines = fs.readFileSync(file, 'utf8').split('\n');
    assert.ok(l.line <= lines.length, `${l.id}: line ${l.line} beyond end (${lines.length})`);
    assert.ok(lines[l.line - 1].trim().length > 0, `${l.id}: line ${l.line} is blank`);
    checked++;
  }
  assert.ok(checked > 0);
});

test('held-out split depends on the id only and is roughly one third', () => {
  assert.equal(isHeldOut('x'), isHeldOut('x'));
  const held = real.filter((l) => isHeldOut(l.id)).length;
  assert.ok(held > real.length * 0.15 && held < real.length * 0.55, `held ${held}/${real.length}`);
});

test('the scanned fixture carries no answer key', () => {
  const root = path.join(DAG, 'fixtures', 'multiservice', 'src');
  const walk = (d) => fs.readdirSync(d, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]));
  for (const f of walk(root)) {
    const text = fs.readFileSync(f, 'utf8');
    assert.ok(!/(^|\s)(\/\/|\/\*|#)/.test(text), `${f} contains a comment`);
    assert.ok(!/\b(vuln|vulnerable|positive|negative|expected|label|bench|TODO|FIXME)\b/i.test(text), `${f} mentions benchmark vocabulary`);
  }
  assert.ok(!fixtureDoc.root.includes('labels'), 'labels live beside src, not inside it');
});

test('fixture labels reference real lines and every mutant applies to the fixture', () => {
  const root = path.join(DAG, 'fixtures', 'multiservice', 'src');
  for (const l of fixtureDoc.labels.filter((x) => x.type === 'site')) {
    const n = fs.readFileSync(path.join(root, l.file), 'utf8').split('\n').length;
    assert.ok(l.line >= 1 && l.line <= n, l.id);
  }
  for (const m of mutants) {
    const src = fs.readFileSync(path.join(root, m.file), 'utf8');
    assert.ok(src.includes(m.find), `${m.id}: find string absent`);
    assert.notEqual(m.find, m.replace, m.id);
    assert.equal(src.split(m.find).length - 1, 1, `${m.id}: find string must be unique`);
    assert.ok(m.site || m.flow, m.id);
    assert.ok(['reported', 'silent'].includes(m.expectAfter), m.id);
  }
});

test('scoring: outcomes, denominators and file-level credit', () => {
  assert.equal(outcome('positive', true), 'TP');
  assert.equal(outcome('positive', false), 'FN');
  assert.equal(outcome('negative', true), 'FP');
  assert.equal(outcome('negative', false), 'TN');
  assert.equal(outcome('ambiguous', true), 'excluded');
  const a = aggregate([{ outcome: 'TP' }, { outcome: 'TP' }, { outcome: 'FP' }, { outcome: 'FN' }, { outcome: 'TN' }, { outcome: 'excluded' }]);
  assert.equal(a.precision, 0.6667);
  assert.equal(a.precisionDenominator, 3);
  assert.equal(a.recall, 0.6667);
  assert.equal(a.recallDenominator, 3);
  assert.equal(aggregate([]).precision, null);
  const label = { file: 'a.js', line: 10, class: 'xss' };
  assert.deepEqual(scoreSiteLabel(label, [{ file: 'a.js', line: 10, cwe: 'CWE-79' }]), { reported: true, fileLevel: false });
  assert.deepEqual(scoreSiteLabel(label, [{ file: 'a.js', line: 11, cwe: 'CWE-79' }]), { reported: false, fileLevel: false });
  assert.deepEqual(scoreSiteLabel(label, [{ file: 'a.js', line: null, cwe: 'CWE-79' }]), { reported: true, fileLevel: true });
  assert.deepEqual(scoreSiteLabel(label, [{ file: 'a.js', line: 10, cwe: 'CWE-89' }]), { reported: false, fileLevel: false });
  assert.deepEqual(scoreSiteLabel(label, [{ file: 'b.js', line: 10, cwe: 'CWE-79' }]), { reported: false, fileLevel: false });
});

test('scoring: flow labels match by data element, source kind and file; sink kind is reported separately', () => {
  const flows = [{ fields: ['note'], files: ['api/server.js'], sourceKind: 'http-body', sinkKind: 'unresolved', sinkSub: 'file' }];
  const l = { field: 'note', sourceKind: 'http-body', sourceFile: 'api/server.js', sinkKind: 'queue' };
  assert.deepEqual(scoreFlowLabel(l, flows), { reported: true, sinkMatch: false });
  assert.deepEqual(scoreFlowLabel({ ...l, sinkKind: 'unresolved' }, flows), { reported: true, sinkMatch: true });
  assert.deepEqual(scoreFlowLabel({ ...l, field: 'qty' }, flows), { reported: false, sinkMatch: false });
  assert.deepEqual(scoreFlowLabel({ ...l, sourceKind: 'queue-message' }, flows), { reported: false, sinkMatch: false });
});

// ---- evidence measurements (replay, attribution, call/return) --------------------------------

test('attribution scoring: correct field, sibling field, spurious flow and negative-label hits', async () => {
  const { scoreFixtureAttribution, scoreRealAttribution } = await import('../../../bench/dag/lib/attribution.mjs');
  const doc = { labels: [
    { id: 'p1', type: 'flow', verdict: 'positive', field: 'note', sourceFile: 'a.js', sinkKind: 'queue' },
    { id: 'p2', type: 'flow', verdict: 'positive', field: 'bio', sourceFile: 'a.js', sinkKind: 'database' },
    { id: 'n1', type: 'flow', verdict: 'negative', field: 'secret' },
  ] };
  const flows = [
    { fields: ['note'], files: ['a.js'], sinkKind: 'unresolved', sinkSub: 'file' }, // unresolved sink: field only
    { fields: ['bio'], files: ['a.js'], sinkKind: 'queue', sinkSub: 'queue' }, // right field, wrong known sink
    { fields: ['other'], files: ['a.js'], sinkKind: 'store', sinkSub: 'database' }, // field no label names
    { fields: ['x'], files: ['z.js'], sinkKind: 'store', sinkSub: 'database' }, // not examined
  ];
  const r = scoreFixtureAttribution(doc, flows);
  assert.equal(r.examined, 3);
  assert.equal(r.correct, 1);
  assert.equal(r.falseAttributions, 2);
  assert.equal(r.unexamined, 1);
  assert.equal(r.negativeLabelHits, 0);
  assert.equal(scoreFixtureAttribution(doc, [{ fields: ['secret'], files: ['q.js'], sinkKind: 'store', sinkSub: 'database' }]).negativeLabelHits, 1);

  const labels = { labels: [
    { id: 'a', unit: 'u', file: 'f.js', line: 1, field: 'x', expectedField: 'x', verdict: 'correct' },
    { id: 'b', unit: 'u', file: 'f.js', line: 2, field: 'y', expectedField: 'z', verdict: 'wrong-field' },
    { id: 'c', unit: 'u', file: 'f.js', line: 3, field: 'w', expectedField: null, verdict: 'no-flow', expectedSourceKind: 'k' },
  ] };
  const mk = (field, line, kind = 'k') => ({ fields: [field], sources: [{ field, file: 'f.js', line }], sourceKind: kind });
  const rr = scoreRealAttribution(labels, 'u', [mk('x', 1), mk('y', 2), mk('w', 3, 'other'), mk('q', 9)]);
  assert.deepEqual([rr.correct, rr.wrongField, rr.spurious, rr.unlabeled, rr.sourceKindMismatch], [1, 1, 1, 1, 1]);
});

test('real-flow labels are well formed and point at real lines of the pinned sources when cached', (t) => {
  const doc = JSON.parse(fs.readFileSync(path.join(DAG, 'labels', 'real-flows.json'), 'utf8'));
  const ids = new Set();
  for (const l of doc.labels) {
    assert.ok(!ids.has(l.id), `duplicate ${l.id}`); ids.add(l.id);
    assert.ok(doc.verdicts[l.verdict], l.id);
    assert.ok(l.evidence && l.evidence.length > 10, l.id);
    assert.equal(l.verdict === 'no-flow', l.expectedField === null, `${l.id}: expectedField is null exactly for no-flow`);
  }
  const cache = path.join(DAG, '.cache');
  if (!fs.existsSync(cache)) { t.skip('bench/dag/.cache not acquired'); return; }
  for (const l of doc.labels) {
    const project = l.unit.split('/')[0];
    const file = path.join(cache, project, l.file);
    if (!fs.existsSync(path.join(cache, project))) continue;
    const line = fs.readFileSync(file, 'utf8').split('\n')[l.line - 1] || '';
    assert.ok(line.includes(l.field), `${l.id}: line ${l.line} does not mention ${l.field}`);
  }
});

test('call/return checker: a return through another call site is impossible, a matched pair is not, a witness that starts inside a callee is not', async () => {
  const { checkCallReturn } = await import('../../../bench/dag/lib/evidence-unit.mjs');
  const nodes = {
    arg1: { scope: 'caller', context: 'c' }, arg2: { scope: 'caller', context: 'c' }, param: { scope: 'callee', context: 'k' },
    ret: { scope: 'callee', context: 'k' }, res1: { scope: 'caller', context: 'c' },
  };
  const store = { getNode: (id) => nodes[id] };
  const hop = (from, to, site) => ({ fromNodeId: from, toNodeId: to, scope: 'caller', context: 'c', siteNodeId: site });
  const ok = checkCallReturn(store, { hops: [hop('arg1', 'param', 's1'), hop('ret', 'res1', 's1')] });
  assert.equal(ok.violation, null);
  assert.deepEqual([ok.calls, ok.returns], [1, 1]);
  const bad = checkCallReturn(store, { hops: [hop('arg2', 'param', 's2'), hop('ret', 'res1', 's1')] });
  assert.equal(bad.violation.reason, 'returned-through-another-call-site');
  const inside = checkCallReturn(store, { hops: [hop('ret', 'res1', 's1')] });
  assert.equal(inside.violation, null);
  assert.equal(inside.unmatchedReturns, 1);
});

test('evidence probe on the call/return fixture: version 1 yields impossible witnesses, version 2 none, and every bundle replays', async () => {
  const { evidenceProbe } = await import('../../../bench/dag/lib/evidence-unit.mjs');
  const r = evidenceProbe({ id: 'fixture/callreturn', dir: path.join(DAG, 'fixtures', 'callreturn', 'src'), prefix: '' });
  assert.equal(r.status, 'ok');
  assert.ok(r.callReturn.v1.impossible > 0, 'the checker finds the shared-callee mix-up in version 1');
  assert.equal(r.callReturn.v2.impossible, 0);
  assert.ok(r.callReturn.v2.balancingPrunedEdges > 0);
  assert.equal(r.witness.replayed, r.witness.built);
  assert.ok(r.witness.built > 0);
  for (const [k, v] of Object.entries(r.witness.tamper)) assert.equal(v.rejected, v.attempted, k);
});

test('package.json exposes the check script and it is not part of the pre-push gate list', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(DAG, '..', '..', 'scanner', 'package.json'), 'utf8'));
  assert.equal(pkg.scripts['bench:dag:check'], 'node ../bench/dag/run.mjs --check');
  const gate = fs.readFileSync(path.join(DAG, '..', '..', 'scripts', 'pre-push-gate.mjs'), 'utf8');
  assert.ok(!/bench:dag|bench\/dag/.test(gate), 'bench/dag must not be wired into the pre-push gate');
});
