// X-308: validate deployment-aware differentiation on a frozen, SYNTHETIC ablation set.
//
// Everything here is authored by the tooling's developers. The counts it pins check a mechanism on constructed cases; they are
// not engine accuracy and not a benefit on real code, and the real-code gates refuse the set (asserted below).

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkTestTmp } from '../helpers/tmp.js';
import {
  ABLATION_SET_SCHEMA, FROZEN_FILE, VARIANTS, DECISION_RULE, loadAblationCases, freezeAblationSet, verifyFrozenSet, runPairedAblation,
  pairedBootstrap, adapterValidation, graphFreshness, graphArmKeeps, deterministicView, deploymentTreesCarryNoSource,
} from '../../src/posture/evaluation/deployment-ablation.js';
import { validateProtocol } from '../../src/posture/evaluation/protocol.js';
import { evaluateGates } from '../../src/posture/evaluation/gates.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { runBoundaries } from '../../src/lineage/deployment/boundaries-run.js';
import { ADAPTER_NAMES } from '../../src/lineage/deployment/ingest.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURES = path.join(HERE, '..', 'fixtures', 'deployment-ablation');
const stored = JSON.parse(fs.readFileSync(path.join(FIXTURES, FROZEN_FILE), 'utf8'));

function copyFixtures() {
  const dir = mkTestTmp('ablation-');
  fs.cpSync(FIXTURES, dir, { recursive: true });
  return dir;
}

describe('X-308.AC01 a frozen test set with identical source under exploitable and non-exploitable configurations', () => {
  test('[X-308.AC01] the committed set verifies against the fixtures and is marked synthetic', () => {
    const v = verifyFrozenSet({ fixturesDir: FIXTURES, stored });
    assert.deepEqual(v.errors, []);
    assert.equal(v.ok, true);
    assert.equal(stored.schema, ABLATION_SET_SCHEMA);
    assert.equal(stored.synthetic, true);
    assert.equal(stored.protocol.synthetic, true);
    assert.equal(validateProtocol(stored.protocol).ok, true);
    assert.match(stored.frozenHash, /^sha256:[0-9a-f]{64}$/);
  });

  test('[X-308.AC01] every case has one source tree and two deployments with opposite labels, and no deployment carries code', () => {
    const { cases, errors } = loadAblationCases(FIXTURES);
    assert.deepEqual(errors, []);
    assert.ok(cases.length >= 6, 'enough cases to pair');
    for (const c of cases) {
      assert.deepEqual(VARIANTS.map((v) => c.deployments[v].exploitable), [true, false], `${c.id} labels`);
      assert.deepEqual(deploymentTreesCarryNoSource(c), [], `${c.id}: deployment trees must not carry source`);
      const rec = stored.cases.find((x) => x.id === c.id);
      assert.notEqual(rec.deployments.exploitable.digest, rec.deployments['non-exploitable'].digest, `${c.id}: the two deployments must differ`);
      assert.match(rec.sourceDigest, /^sha256:/);
    }
    assert.ok(cases.some((c) => c.kind === 'source-finding') && cases.some((c) => c.kind === 'deployment-only'));
  });

  test('[X-308.AC01] the two configurations of one case really change the boundary graph, using only the shipped entry point', () => {
    const config = resolveAssuranceConfig({ scanRoot: FIXTURES, overrides: { features: { 'deployment-boundaries': true } } });
    const finding = { id: 'f', file: 'services/api/handler.js', family: 'command-injection', cwe: 'CWE-78', vuln: 'Command Injection', severity: 'critical' };
    const state = (variant) => runBoundaries({ config, from: path.join(FIXTURES, 'cases', 'k8s-ingress-vs-internal', variant), findings: [finding] }).report.findings[0].boundaryContext.exposure.state;
    assert.equal(state('exploitable'), 'possible');
    assert.equal(state('non-exploitable'), 'none-found');
  });

  test('[X-308.AC01] a change to a source file, a deployment file, a label or the rule is refused, naming what moved', () => {
    const mutate = (rel, edit) => {
      const dir = copyFixtures();
      const p = path.join(dir, rel);
      fs.writeFileSync(p, edit(fs.readFileSync(p, 'utf8')));
      return verifyFrozenSet({ fixturesDir: dir, stored });
    };
    const src = mutate('cases/k8s-ingress-vs-internal/source/services/api/handler.js', (t) => `${t}// edited\n`);
    assert.equal(src.ok, false);
    assert.ok(src.errors.some((e) => /k8s-ingress-vs-internal: source tree changed/.test(e)), src.errors.join('|'));
    const dep = mutate('cases/compose-published-vs-internal/exploitable/docker-compose.yml', (t) => t.replace('8080:3000', '8081:3000'));
    assert.equal(dep.ok, false);
    assert.ok(dep.errors.some((e) => /compose-published-vs-internal: exploitable deployment changed/.test(e)), dep.errors.join('|'));
    const label = mutate('cases/k8s-gateway-auth/case.json', (t) => t.replace('"exploitable": false', '"exploitable": true'));
    assert.equal(label.ok, false, 'a label contradicting its directory name is refused');
    const rule = verifyFrozenSet({ fixturesDir: FIXTURES, stored: { ...stored, decisionRule: { ...DECISION_RULE, version: 2 } } });
    assert.ok(rule.errors.some((e) => /decision rule changed/.test(e)));
    const tampered = structuredClone(stored);
    tampered.protocol = { ...tampered.protocol, thresholds: { ...tampered.protocol.thresholds, pooledPrecision: 0.5 } };
    assert.equal(verifyFrozenSet({ fixturesDir: FIXTURES, stored: tampered }).ok, false, 'a loosened threshold breaks the protocol hash');
  });

  test('[X-308.AC01] a deployment tree that smuggles source code cannot be frozen, and the set never satisfies a real-code gate', () => {
    const dir = copyFixtures();
    fs.writeFileSync(path.join(dir, 'cases', 'k8s-ingress-vs-internal', 'non-exploitable', 'extra.js'), 'module.exports = 1;\n');
    const f = freezeAblationSet({ fixturesDir: dir });
    assert.equal(f.ok, false);
    assert.ok(f.errors.some((e) => /must not carry source code/.test(e)));
    const g = evaluateGates({ protocol: stored.protocol, score: null, defects: [], negatives: [] });
    assert.notEqual(g.overall, 'pass');
    assert.ok(g.gates.every((x) => x.status !== 'pass'));
  });
});

describe('X-308.AC02 graph-enabled versus source-only on paired cases, with uncertainty', () => {
  let first, second;
  before(async () => {
    first = await runPairedAblation({ fixturesDir: FIXTURES, stored });
    second = await runPairedAblation({ fixturesDir: FIXTURES, stored });
  });

  test('[X-308.AC02] the paired evaluation runs the real scan and reports precision, recall, runtime and coverage for both arms', () => {
    assert.equal(first.ok, true, first.errors?.join('; '));
    const r = first.report;
    assert.equal(r.synthetic, true);
    assert.match(r.statement, /SYNTHETIC/);
    for (const arm of [r.arms.sourceOnly, r.arms.graphEnabled]) {
      for (const k of ['tp', 'fp', 'fn', 'precision', 'recall']) assert.ok(k in arm, k);
    }
    assert.deepEqual([r.arms.sourceOnly.tp, r.arms.sourceOnly.fp, r.arms.sourceOnly.fn], [4, 4, 3]);
    assert.deepEqual([r.arms.graphEnabled.tp, r.arms.graphEnabled.fp, r.arms.graphEnabled.fn], [7, 2, 0]);
    assert.equal(r.runtime.deterministic, false);
    assert.equal(typeof r.runtime.sourceOnlyScanMsMedian, 'number');
    assert.equal(typeof r.runtime.graphEnabledAddedMsMedian, 'number');
    assert.equal(r.coverage.sourceOnly.scansCompleted, r.coverage.sourceOnly.of);
    assert.equal(r.coverage.graphEnabled.graphBuilt, 14);
    assert.equal(r.realCodeGates.overall === 'pass', false);
  });

  test('[X-308.AC02] paired counts: false positives reduced, defects added, none lost, and a false positive the graph added is published too', () => {
    const p = first.report.paired;
    assert.equal(p.instances, 14);
    assert.equal(p.cases, 7);
    assert.equal(p.falsePositivesReduced, 3);
    assert.equal(p.confirmedDefectsAdded, 3);
    assert.equal(p.baselineConfirmedDefectsLost, 0, 'no baseline confirmed defect may be lost');
    assert.equal(p.falsePositivesAdded, 1, 'the graph adds one false positive (gateway authentication it cannot see)');
    const reduced = first.report.instances.filter((i) => i.fpReduced.length).map((i) => i.caseId).sort();
    assert.deepEqual(reduced, ['compose-published-vs-internal', 'k8s-ingress-vs-internal', 'k8s-unresolved-ingress']);
    const added = first.report.instances.filter((i) => i.fpAdded.length).map((i) => `${i.caseId}/${i.variant}`);
    assert.deepEqual(added, ['k8s-gateway-auth/non-exploitable']);
  });

  test('[X-308.AC02] uncertainty is a labelled simple paired bootstrap, deterministic, and the point estimate lies inside its interval', () => {
    const u = first.report.uncertainty;
    assert.equal(u.method, 'paired-case-bootstrap');
    assert.match(u.label, /NOT the grouped bootstrap/);
    assert.equal(u.cases, 7);
    for (const k of ['precision', 'recall']) {
      assert.ok(u[k].low <= u[k].difference + 1e-9 && u[k].difference <= u[k].high + 1e-9, `${k} estimate inside its interval`);
      assert.ok(u[k].high > u[k].low, 'a 7-case interval is not a point');
      assert.ok(u[k].difference > 0);
    }
    assert.deepEqual(deterministicView(first.report), deterministicView(second.report), 'two runs agree on everything but wall-clock time');
    assert.equal(first.report.runId, second.report.runId);
  });

  test('[X-308.AC02] the bootstrap responds to the data: identical arms give a zero difference, and a fixed seed repeats', () => {
    const same = Array.from({ length: 5 }, () => ({ source: { tp: 1, fp: 1, fn: 0 }, graph: { tp: 1, fp: 1, fn: 0 } }));
    const z = pairedBootstrap(same);
    assert.equal(z.precision.difference, 0);
    assert.equal(z.precision.low, 0);
    assert.equal(z.precision.high, 0);
    const better = Array.from({ length: 5 }, () => ({ source: { tp: 1, fp: 1, fn: 1 }, graph: { tp: 2, fp: 0, fn: 0 } }));
    const b = pairedBootstrap(better);
    assert.ok(b.precision.low > 0 && b.recall.low > 0);
    assert.deepEqual(pairedBootstrap(better), b);
    const empty = pairedBootstrap([]);
    assert.equal(empty.precision.low, null, 'no cases, no interval, nothing invented');
  });

  test('[X-308.AC02] the graph arm demotes only on an explicit deny or an absent path in a gap-free graph, and keeps everything it cannot assess', () => {
    const row = (state) => ({ boundaryContext: { exposure: { state } } });
    assert.equal(graphArmKeeps(row('blocked'), 3).keep, false);
    assert.equal(graphArmKeeps(row('none-found'), 0).keep, false);
    assert.equal(graphArmKeeps(row('none-found'), 1).keep, true, 'a gap means absence of a path is not shown');
    for (const s of ['possible', 'runtime-supported', 'unresolved', 'not-assessed']) assert.equal(graphArmKeeps(row(s), 0).keep, true, s);
    assert.equal(graphArmKeeps({}, 0).keep, true, 'no context at all keeps the finding');
  });

  test('[X-308.AC02] a scan that fails is an end-to-end miss for the source arm, never a silent skip', async () => {
    const r = await runPairedAblation({ fixturesDir: FIXTURES, stored, scanFn: async () => { throw new Error('scan crashed'); } });
    assert.equal(r.ok, true);
    assert.equal(r.report.coverage.sourceOnly.scansCompleted, 0);
    assert.equal(r.report.arms.sourceOnly.tp, 0);
    assert.equal(r.report.arms.sourceOnly.fn, 7, 'every labelled defect is missed when the scan fails');
  });

  test('[X-308.AC02] a set that no longer matches its frozen hashes is refused before any measurement', async () => {
    const dir = copyFixtures();
    const p = path.join(dir, 'cases', 'k8s-gateway-auth', 'exploitable', 'manifests.yaml');
    fs.writeFileSync(p, `${fs.readFileSync(p, 'utf8')}# drift\n`);
    const r = await runPairedAblation({ fixturesDir: dir, stored });
    assert.equal(r.ok, false);
    assert.equal(r.report, null);
    assert.ok(r.errors.some((e) => /k8s-gateway-auth: exploitable deployment changed/.test(e)));
  });
});

const DOC = path.join(HERE, '..', '..', '..', 'docs', 'guides', 'deployment-aware-support.md');

/** Adapter rows of the doc's validated-adapters table: `| \`name\` | validated | ... |`. */
export function docAdapterClaims(text) {
  const out = {};
  for (const m of text.matchAll(/^\| `([a-z-]+)` \| (validated|not validated) \|/gm)) out[m[1]] = m[2] === 'validated';
  return out;
}

describe('X-308.AC03 deployment-aware support is claimed only for validated adapters; unresolved and stale coverage is reported apart', () => {
  let report;
  before(async () => { report = (await runPairedAblation({ fixturesDir: FIXTURES, stored })).report; });

  const instance = (adapters, exploitable, graphReported, truth, lost = []) => ({ adapters, exploitable, truth, graph: { reported: graphReported }, lost });

  test('[X-308.AC03] only adapters with a positive and a negative fixture and no lost defect are validated; the rest say why not', () => {
    const byName = Object.fromEntries(report.adapters.map((a) => [a.adapter, a]));
    assert.deepEqual(Object.keys(byName).sort(), [...ADAPTER_NAMES].sort());
    assert.equal(byName.kubernetes.validated, true);
    assert.equal(byName.compose.validated, true);
    assert.equal(byName['terraform-plan'].validated, false);
    assert.equal(byName['iam-policy'].validated, false);
    assert.match(byName['terraform-plan'].reason, /no fixture/);
  });

  test('[X-308.AC03] validation needs both directions: positive only, negative only, a lost defect, and an unused adapter all fail', () => {
    const t = ['src:c'];
    const get = (list, name) => adapterValidation(list).find((a) => a.adapter === name);
    assert.equal(get([instance(['kubernetes'], true, t, t), instance(['kubernetes'], false, [], [])], 'kubernetes').validated, true);
    const positiveOnly = get([instance(['kubernetes'], true, t, t)], 'kubernetes');
    assert.equal(positiveOnly.validated, false);
    assert.match(positiveOnly.reason, /no negative/);
    const negativeOnly = get([instance(['kubernetes'], false, [], [])], 'kubernetes');
    assert.equal(negativeOnly.validated, false);
    assert.match(negativeOnly.reason, /no positive/);
    const lost = get([instance(['kubernetes'], true, t, t, ['src:c']), instance(['kubernetes'], false, [], [])], 'kubernetes');
    assert.equal(lost.validated, false);
    assert.match(lost.reason, /lost/);
    assert.equal(get([], 'compose').validated, false);
    const wrongNeg = get([instance(['kubernetes'], true, t, t), instance(['kubernetes'], false, ['src:x'], [])], 'kubernetes');
    assert.equal(wrongNeg.validated, false, 'a negative instance the graph still reports is not a negative fixture');
  });

  test('[X-308.AC03] unresolved and stale graph coverage are separate counts, not folded into the paired result', () => {
    const c = report.coverage.graphEnabled;
    assert.equal(c.instancesWithGraphGaps, 1);
    assert.equal(c.graphGapsTotal, 1);
    assert.equal(c.staleSources, 0);
    assert.equal(c.missingSources, 0);
    assert.match(c.traces, /unmeasured/);
    const unresolved = report.instances.find((i) => i.caseId === 'k8s-unresolved-ingress' && i.variant === 'exploitable');
    assert.equal(unresolved.graph.coverage.graphGaps, 1);
    assert.ok('staleSources' in unresolved.graph.coverage && 'unresolvedNodes' in unresolved.graph.coverage);
    assert.equal(unresolved.graph.reported.length, 1, 'the unresolved case keeps its finding instead of calling it safe');
  });

  test('[X-308.AC03] a source file that changed after ingest is reported stale, and an unchanged one is not', () => {
    const dir = mkTestTmp('stale-');
    fs.cpSync(path.join(FIXTURES, 'cases', 'compose-published-vs-internal', 'exploitable'), dir, { recursive: true });
    const config = resolveAssuranceConfig({ scanRoot: dir, overrides: { features: { 'deployment-boundaries': true } } });
    const res = runBoundaries({ config, from: dir, findings: [] });
    assert.equal(res.status, 'ok');
    assert.deepEqual(graphFreshness(res.graph, dir), { stale: [], missing: [] });
    fs.appendFileSync(path.join(dir, 'docker-compose.yml'), '# changed after ingest\n');
    assert.deepEqual(graphFreshness(res.graph, dir), { stale: ['docker-compose.yml'], missing: [] });
    fs.rmSync(path.join(dir, 'docker-compose.yml'));
    assert.deepEqual(graphFreshness(res.graph, dir), { stale: [], missing: ['docker-compose.yml'] });
  });

  test('[X-308.AC03] the release page claims exactly the validated adapters and quotes the paired counts of the frozen evaluation', () => {
    const text = fs.readFileSync(DOC, 'utf8');
    const claims = docAdapterClaims(text);
    const validated = Object.fromEntries(report.adapters.map((a) => [a.adapter, a.validated]));
    assert.deepEqual(claims, validated, 'the page and the evaluation disagree about which adapters are validated');
    assert.match(text, /synthetic/i);
    const rowOf = (label) => new RegExp(`^\\| ${label} \\| (\\d+) \\|`, 'm').exec(text)?.[1];
    assert.equal(Number(rowOf('False positives the graph reduced')), report.paired.falsePositivesReduced);
    assert.equal(Number(rowOf('Confirmed defects the graph added')), report.paired.confirmedDefectsAdded);
    assert.equal(Number(rowOf('Baseline confirmed defects the graph lost')), report.paired.baselineConfirmedDefectsLost);
    assert.equal(Number(rowOf('False positives the graph added')), report.paired.falsePositivesAdded);
    assert.equal(Number(rowOf('Instances unchanged')), report.paired.unchanged);
    const pct = (x) => `${(x * 100).toFixed(1)}%`;
    assert.ok(text.includes(`| source-only | ${report.arms.sourceOnly.tp} | ${report.arms.sourceOnly.fp} | ${report.arms.sourceOnly.fn} | ${pct(report.arms.sourceOnly.precision)} | ${pct(report.arms.sourceOnly.recall)} |`));
    assert.ok(text.includes(`| graph-enabled | ${report.arms.graphEnabled.tp} | ${report.arms.graphEnabled.fp} | ${report.arms.graphEnabled.fn} | ${pct(report.arms.graphEnabled.precision)} | ${pct(report.arms.graphEnabled.recall)} |`));
    assert.ok(/Unresolved and stale coverage, reported separately/.test(text));
    assert.ok(text.includes(`${report.coverage.graphEnabled.instancesWithGraphGaps} instance has a graph gap`));
  });

  test('[X-308.AC03] a page that claimed an unvalidated adapter would be caught by the same check', () => {
    const real = fs.readFileSync(DOC, 'utf8');
    const validated = Object.fromEntries(report.adapters.map((a) => [a.adapter, a.validated]));
    const overclaim = real.replace('| `terraform-plan` | not validated |', '| `terraform-plan` | validated |');
    assert.notEqual(overclaim, real);
    assert.notDeepEqual(docAdapterClaims(overclaim), validated);
    assert.equal(docAdapterClaims('no table here').kubernetes, undefined);
  });
});
