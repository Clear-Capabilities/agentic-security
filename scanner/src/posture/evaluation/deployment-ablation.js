// deployment-ablation.js: a frozen, SYNTHETIC deployment-context ablation (X-308).
//
// Question: does reading deployment configuration change which findings are worth acting on, compared with the source alone?
// The test set holds IDENTICAL source deployed under two boundary configurations per case, one exploitable and one not. Two
// arms are scored on the same instances:
//   source-only    the engine's findings on the source, every one reported (what the scan does today);
//   graph-enabled  the same findings plus the boundary context built from the deployment files by the shipped
//                  `agentic-security boundaries` code path (`runBoundaries`), under the frozen rule below.
//
// What this is NOT. The cases, their labels and the decision rule were all authored by the tooling's developers, the labels
// carry no independent adjudication, and the set is tiny. It is flagged `synthetic: true` everywhere and the real-code gates
// refuse it (gates.js). It checks a MECHANISM on constructed cases; it estimates nothing about real programs, and one case
// (the unresolved-ingress one) exists because the rule was tightened after the first run exposed a lost defect. Do not quote
// its figures as engine accuracy or as a benefit on real code.
//
// Frozen with the QA-001 machinery: the case set is bound into a protocol (`freezeProtocol`, hash-pinned, `synthetic: true`)
// whose target digests pin each case's source tree, and a separate `frozenHash` also covers every deployment tree digest, the
// labels and the decision rule. `verifyFrozenSet` recomputes both from disk. Nothing here counts toward a real-population gate.
//
// Uncertainty uses a SIMPLE PAIRED CASE BOOTSTRAP (resample cases, both of a case's instances travel together, fixed seed).
// It is not the grouped bootstrap the QA-004 report calls for; that code is not in this base. With a handful of cases the
// interval is wide and exploratory, and it says so.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { digestOf, digestOfBytes } from '../assurance/identity.js';
import { resolveAssuranceConfig } from '../assurance/config.js';
import { runBoundaries } from '../../lineage/deployment/boundaries-run.js';
import { computeAttackPaths } from '../../lineage/deployment/attack-paths.js';
import { ADAPTER_NAMES } from '../../lineage/deployment/ingest.js';
import { digestTree, targetDigestOf, runEvaluation } from './runner.js';
import { freezeProtocol, validateProtocol, CORE_LANGUAGES, PREREGISTERED_THRESHOLDS, DEFAULT_MATCHING } from './protocol.js';
import { evaluateGates } from './gates.js';

export const ABLATION_SET_SCHEMA = 'agentic-security/deployment-ablation-set';
const ABLATION_REPORT_SCHEMA = 'agentic-security/deployment-ablation-report';
const ABLATION_VERSION = 1;
export const VARIANTS = Object.freeze(['exploitable', 'non-exploitable']);
export const FROZEN_FILE = 'frozen.json';
const BOOTSTRAP = Object.freeze({ method: 'paired-case-bootstrap', resamples: 4000, seed: 20261009, interval: 0.95 });

/**
 * The frozen decision rule of the graph-enabled arm. Changing any of it changes `frozenHash`.
 *  - A source finding is demoted (dropped from the reported set) only when its boundary context says exposure is `blocked`, or
 *    `none-found` AND the boundary graph has no gap at all. A gap can stand for a missing relationship, so it never licenses
 *    treating absence of a path as absence of exposure. An unbound finding, an unresolved or possible exposure is kept.
 *  - A deployment-exposure finding is added for a case when a `possible` or `runtime-supported` path leads from an exposed
 *    entry point to a privileged resource. A blocked or unresolved path adds nothing.
 */
export const DECISION_RULE = Object.freeze({
  id: 'graph-arm-decision-rule', version: 1,
  demoteSourceFindingWhen: Object.freeze(['exposure:blocked', 'exposure:none-found and graph-gap-count:0']),
  keepSourceFindingWhen: Object.freeze(['exposure:possible', 'exposure:runtime-supported', 'exposure:unresolved', 'exposure:not-assessed']),
  addDeploymentFindingWhen: Object.freeze(['path-state:possible or runtime-supported from an exposed entry to a privileged resource']),
});

const SYNTHETIC_LICENSE = 'synthetic-test-fixture';
const SHA = (c) => c.repeat(40);

function readJson(file) { return JSON.parse(fs.readFileSync(file, 'utf8')); }

/** Read the case definitions under `<fixturesDir>/cases`. Structure problems are returned, never thrown. */
export function loadAblationCases(fixturesDir) {
  const errors = [];
  const root = path.join(fixturesDir, 'cases');
  let names = [];
  try { names = fs.readdirSync(root, { withFileTypes: true }).filter((e) => e.isDirectory()).map((e) => e.name).sort(); } catch (e) { return { cases: [], errors: [`cannot read ${root}: ${e.code || e.message}`] }; }
  const cases = [];
  for (const name of names) {
    const dir = path.join(root, name);
    let meta;
    try { meta = readJson(path.join(dir, 'case.json')); } catch (e) { errors.push(`${name}: case.json unreadable (${e.message})`); continue; }
    if (meta.id !== name) errors.push(`${name}: case.json id '${meta.id}' does not match the directory`);
    if (!['source-finding', 'deployment-only'].includes(meta.kind)) errors.push(`${name}: kind must be source-finding or deployment-only`);
    for (const v of VARIANTS) {
      if (!fs.existsSync(path.join(dir, v))) errors.push(`${name}: missing deployment '${v}'`);
      const label = meta.deployments?.[v]?.exploitable;
      if (typeof label !== 'boolean') errors.push(`${name}: deployment '${v}' has no boolean exploitable label`);
      else if (label !== (v === 'exploitable')) errors.push(`${name}: deployment '${v}' is labelled exploitable=${label}, which contradicts its directory name`);
    }
    if (!fs.existsSync(path.join(dir, 'source'))) errors.push(`${name}: missing source tree`);
    cases.push({ ...meta, dir });
  }
  if (!cases.length && !errors.length) errors.push('no cases found');
  return { cases, errors };
}

/** Identical source across both deployments is structural: the source tree lives once and no deployment tree carries code. */
export function deploymentTreesCarryNoSource(c) {
  const bad = [];
  for (const v of VARIANTS) {
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/\.(?:[cm]?js|ts|py|java|go|rb|php)$/i.test(e.name)) bad.push(path.relative(c.dir, p)); } };
    walk(path.join(c.dir, v));
  }
  return bad;
}

function digestsOf(c) {
  return {
    source: digestTree(path.join(c.dir, 'source')),
    deployments: Object.fromEntries(VARIANTS.map((v) => [v, digestTree(path.join(c.dir, v))])),
  };
}

function caseRecord(c, d) {
  return {
    id: c.id, title: c.title, kind: c.kind, defect: c.defect, sourceDigest: d.source,
    deployments: Object.fromEntries(VARIANTS.map((v) => [v, { digest: d.deployments[v], exploitable: c.deployments[v].exploitable, rationale: c.deployments[v].rationale }])),
  };
}

/**
 * Freeze the set: hash-pin every tree, the labels and the decision rule, and bind the cases into a QA-001 protocol. Never throws.
 * @returns {{ ok: boolean, errors: string[], set: object|null }}
 */
export function freezeAblationSet({ fixturesDir } = {}) {
  const loaded = loadAblationCases(fixturesDir);
  const errors = [...loaded.errors];
  for (const c of loaded.cases) { const bad = deploymentTreesCarryNoSource(c); if (bad.length) errors.push(`${c.id}: deployment trees must not carry source code (${bad.join(', ')})`); }
  if (errors.length) return { ok: false, errors, set: null };
  const records = loaded.cases.map((c) => caseRecord(c, digestsOf(c)));
  const targets = loaded.cases.map((c, i) => ({
    id: c.id, language: 'javascript', upstream: `example.invalid/synthetic/deployment-ablation/${c.id}`, pairId: `pair-${c.id}`, advisoryIds: [],
    preCommit: SHA((i + 1).toString(16)[0]), postCommit: null, license: SYNTHETIC_LICENSE, digest: targetDigestOf({ pre: records[i].sourceDigest, post: null }),
  }));
  const draft = {
    synthetic: true,
    engine: { version: '0.0.0-synthetic', bundleDigest: digestOf('synthetic-deployment-ablation-engine') },
    measurement: { commit: SHA('d'), cleanTree: true },
    tools: { node: 'synthetic' },
    models: [],
    datasetLicenses: { [SYNTHETIC_LICENSE]: 'authored for tooling tests; not real-world code' },
    scope: { languages: [...CORE_LANGUAGES], families: ['command-injection', 'deployment-exposure'] },
    matching: { ...DEFAULT_MATCHING },
    limits: { perTargetTimeoutMs: 120000, spendCeilingUsd: 0, replicates: 1 },
    thresholds: { ...PREREGISTERED_THRESHOLDS },
    targets,
    splits: { dev: [], sealed: targets.map((t) => t.id).sort() },
    grouping: { method: 'union-find', keys: ['pair', 'upstream', 'advisory', 'commit', 'template'], salt: 'synthetic-deployment-ablation' },
  };
  const frozen = freezeProtocol(draft);
  if (!frozen.ok) return { ok: false, errors: frozen.errors.map((e) => `${e.path}: ${e.message}`), set: null };
  const labels = records.map((r) => ({ id: r.id, exploitable: VARIANTS.map((v) => r.deployments[v].exploitable) }));
  const body = {
    schema: ABLATION_SET_SCHEMA, schemaVersion: ABLATION_VERSION, synthetic: true,
    note: 'Authored by the tooling developers; labels are not independently adjudicated. Never counted toward a real-population gate.',
    protocolHash: frozen.protocol.protocolHash, decisionRule: DECISION_RULE, labelsHash: digestOf(labels), cases: records,
  };
  const set = { ...body, protocol: frozen.protocol, frozenHash: digestOf(body) };
  return { ok: true, errors: [], set };
}

/** Recompute the set from disk and compare it with a stored one. Names what moved. */
export function verifyFrozenSet({ fixturesDir, stored } = {}) {
  const errors = [];
  if (!stored || stored.schema !== ABLATION_SET_SCHEMA) return { ok: false, errors: ['no frozen set to verify against'] };
  const fresh = freezeAblationSet({ fixturesDir });
  if (!fresh.ok) return { ok: false, errors: fresh.errors };
  const v = validateProtocol(stored.protocol);
  if (!v.ok) errors.push(...v.errors.map((e) => `stored protocol: ${e.code} ${e.path}`));
  if (stored.synthetic !== true) errors.push('stored set is not marked synthetic');
  const byId = new Map(stored.cases.map((c) => [c.id, c]));
  for (const c of fresh.set.cases) {
    const s = byId.get(c.id);
    if (!s) { errors.push(`${c.id}: not in the frozen set`); continue; }
    if (s.sourceDigest !== c.sourceDigest) errors.push(`${c.id}: source tree changed since it was frozen`);
    for (const x of VARIANTS) {
      if (s.deployments?.[x]?.digest !== c.deployments[x].digest) errors.push(`${c.id}: ${x} deployment changed since it was frozen`);
      if (s.deployments?.[x]?.exploitable !== c.deployments[x].exploitable) errors.push(`${c.id}: ${x} label changed since it was frozen`);
    }
    byId.delete(c.id);
  }
  for (const id of byId.keys()) errors.push(`${id}: in the frozen set but no longer on disk`);
  if (stored.labelsHash !== fresh.set.labelsHash) errors.push('labels changed since they were frozen');
  if (digestOf(stored.decisionRule) !== digestOf(DECISION_RULE)) errors.push('the decision rule changed since it was frozen');
  if (stored.frozenHash !== fresh.set.frozenHash) errors.push('frozenHash does not match the recomputed set');
  return { ok: errors.length === 0, errors };
}

// ------------------------------------------------------------ arms

/** Does a graph source (file + digest recorded at ingest) still match the file on disk? Missing and changed are separate. */
export function graphFreshness(graph, dir) {
  const stale = [], missing = [];
  for (const s of graph.sources) {
    let bytes;
    try { bytes = fs.readFileSync(path.join(dir, s.file)); } catch { missing.push(s.file); continue; }
    if (digestOfBytes(bytes) !== s.digest) stale.push(s.file);
  }
  return { stale: stale.sort(), missing: missing.sort() };
}

/** The graph arm's verdict on one source finding, from its boundary context. Pure. */
export function graphArmKeeps(row, graphGapCount) {
  const state = row?.boundaryContext?.exposure?.state ?? 'not-assessed';
  if (state === 'blocked') return { keep: false, state, why: 'every path from an exposed entry crosses an explicit deny' };
  if (state === 'none-found' && graphGapCount === 0) return { keep: false, state, why: 'no path from an exposed entry in a graph with no gaps' };
  return { keep: true, state, why: state === 'none-found' ? 'no path found, but the graph has gaps so absence is not shown' : `exposure is ${state}` };
}

function matchesDefect(finding, defect) { return defect.file ? finding.file === defect.file && finding.family === defect.family : false; }

const median = (xs) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

function graphArm({ c, variant, findings, config, now }) {
  const dir = path.join(c.dir, variant);
  const t0 = performance.now();
  const res = runBoundaries({ config, from: dir, findings, now });
  if (res.status !== 'ok') {
    return { ok: false, reason: `${res.status}: ${res.reason}`, reported: [], demoted: [], ms: performance.now() - t0, coverage: null, adapters: [] };
  }
  const reported = [], demoted = [], states = [];
  const rows = res.report.findings;
  for (const [idx, row] of rows.entries()) {
    const matched = matchesDefect(findings[idx] ?? {}, c.defect);
    const verdict = graphArmKeeps(row, res.report.graph.gapCount);
    states.push(verdict.state);
    if (matched) (verdict.keep ? reported : demoted).push(`src:${c.id}`);
  }
  const paths = computeAttackPaths(res.graph).paths;
  const exposed = paths.filter((p) => p.state === 'possible' || p.state === 'runtime-supported');
  if (exposed.length) reported.push(`dep:${c.id}`);
  const fresh = graphFreshness(res.graph, dir);
  const bound = res.report.coverage.bound;
  return {
    ok: true, reported: [...new Set(reported)].sort(), demoted: [...new Set(demoted)].sort(), ms: performance.now() - t0,
    adapters: [...new Set(res.report.graph.files.map((f) => f.adapter).filter(Boolean))].sort(),
    coverage: {
      findings: rows.length, bound, notAssessed: rows.length - bound, exposureStates: states.sort(),
      unresolvedExposure: states.filter((s) => s === 'unresolved').length,
      graphGaps: res.report.graph.gapCount, unresolvedNodes: res.report.graph.unresolvedNodeCount,
      staleSources: fresh.stale.length, missingSources: fresh.missing.length,
      pathsFound: paths.length, pathsUnresolved: paths.filter((p) => p.state === 'unresolved').length, pathsBlocked: paths.filter((p) => p.state === 'blocked').length,
      traces: res.report.observation.status,
    },
  };
}

function prf(tp, fp, fn) {
  const precision = tp + fp ? tp / (tp + fp) : null;
  const recall = tp + fn ? tp / (tp + fn) : null;
  const f1 = precision !== null && recall !== null && precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : null;
  return { tp, fp, fn, precision, recall, f1 };
}

function mulberry32(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6d2b79f5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

/** Simple paired case bootstrap of (graph - source) precision and recall. Deterministic for a fixed seed. */
export function pairedBootstrap(perCase, { resamples = BOOTSTRAP.resamples, seed = BOOTSTRAP.seed } = {}) {
  const rnd = mulberry32(seed);
  const n = perCase.length;
  const sum = (idx, arm) => idx.reduce((a, i) => ({ tp: a.tp + perCase[i][arm].tp, fp: a.fp + perCase[i][arm].fp, fn: a.fn + perCase[i][arm].fn }), { tp: 0, fp: 0, fn: 0 });
  const diffs = { precision: [], recall: [] };
  const undefinedCount = { precision: 0, recall: 0 };
  for (let b = 0; b < resamples && n; b++) {
    const idx = Array.from({ length: n }, () => Math.floor(rnd() * n));
    const s = sum(idx, 'source'), g = sum(idx, 'graph');
    for (const k of ['precision', 'recall']) {
      const a = prf(s.tp, s.fp, s.fn)[k], z = prf(g.tp, g.fp, g.fn)[k];
      if (a === null || z === null) undefinedCount[k] += 1; else diffs[k].push(z - a);
    }
  }
  const q = (xs, p) => { if (!xs.length) return null; const s = [...xs].sort((x, y) => x - y); return s[Math.min(s.length - 1, Math.max(0, Math.floor(p * s.length)))]; };
  const all = Array.from({ length: n }, (_, i) => i);
  const s0 = prf(...Object.values(sum(all, 'source'))), g0 = prf(...Object.values(sum(all, 'graph')));
  const out = {};
  for (const k of ['precision', 'recall']) {
    out[k] = { sourceOnly: s0[k], graphEnabled: g0[k], difference: s0[k] === null || g0[k] === null ? null : g0[k] - s0[k], low: q(diffs[k], 0.025), high: q(diffs[k], 0.975), undefinedResamples: undefinedCount[k] };
  }
  return {
    method: BOOTSTRAP.method, resamples, seed, interval: BOOTSTRAP.interval, cases: n, ...out,
    label: 'Simple paired case bootstrap (cases resampled with both of their instances, fixed seed). NOT the grouped bootstrap of the QA-004 report, which is not in this base. With this few cases the interval is wide and exploratory.',
  };
}

/** Which adapters have positive AND negative fixtures with no lost defect? Only those may be claimed as deployment-aware. */
export function adapterValidation(instances) {
  const out = ADAPTER_NAMES.map((name) => ({ adapter: name, positives: 0, negatives: 0, lostDefects: 0, instances: 0 }));
  const by = new Map(out.map((o) => [o.adapter, o]));
  for (const i of instances) {
    for (const a of i.adapters) {
      const o = by.get(a);
      if (!o) continue;
      o.instances += 1;
      const truthIds = new Set(i.truth);
      const graphHit = i.graph.reported.some((id) => truthIds.has(id));
      if (i.exploitable && graphHit) o.positives += 1;
      if (!i.exploitable && i.graph.reported.length === 0) o.negatives += 1;
      o.lostDefects += i.lost.length;
    }
  }
  return out.map((o) => {
    const validated = o.positives >= 1 && o.negatives >= 1 && o.lostDefects === 0;
    const reason = validated ? 'positive and negative fixtures, no baseline defect lost'
      : o.instances === 0 ? 'no fixture in the frozen set uses this adapter'
        : o.lostDefects ? 'a baseline confirmed defect was lost'
          : o.positives < 1 ? 'no positive fixture' : 'no negative fixture';
    return { ...o, validated, reason };
  });
}

// ------------------------------------------------------------ the evaluation

/**
 * Run both arms on every frozen instance and report paired counts. Refuses a set that does not verify against the disk.
 *
 * @param {object} o
 * @param {string} o.fixturesDir
 * @param {object} o.stored      the committed frozen set
 * @param {Function} [o.scanFn]  injectable engine scan (tests); the default is the QA-003 child-process scan
 * @param {string} [o.now]       ISO clock for staleness judgements (fixed by default so the counts are deterministic)
 */
export async function runPairedAblation({ fixturesDir, stored, scanFn, now = '2026-10-09T00:00:00.000Z' } = {}) {
  const verified = verifyFrozenSet({ fixturesDir, stored });
  if (!verified.ok) return { ok: false, errors: verified.errors, report: null };
  const loaded = loadAblationCases(fixturesDir);
  const config = resolveAssuranceConfig({ scanRoot: fixturesDir, overrides: { features: { 'deployment-boundaries': true } } });

  // source-only arm: one scan per case; the source is the same under both deployments.
  const run = await runEvaluation({
    protocol: stored.protocol, config: { layer: 'deterministic-only' }, split: 'all', allowSealed: true, protectedTerms: [],
    resolveTarget: (t) => ({ dir: path.join(fixturesDir, 'cases', t.id, 'source') }), ...(scanFn ? { scanFn } : {}),
  });
  if (!run.ok) return { ok: false, errors: run.errors.map((e) => `${e.code}: ${e.message}`), report: null };

  const instances = [], perCase = [], unscored = [];
  const scanMs = [];
  for (const c of loaded.cases) {
    const oc = run.run.outcomes.find((o) => o.targetId === c.id && o.variant === 'pre');
    const completed = oc?.status === 'completed';
    const findings = completed ? oc.findings : [];
    if (completed) scanMs.push(oc.durationMs);
    const matched = findings.filter((f) => matchesDefect(f, c.defect));
    for (const f of findings) if (!matchesDefect(f, c.defect)) unscored.push({ case: c.id, file: f.file, family: f.family, reason: 'a finding the case labels do not account for' });
    const caseStats = { id: c.id, source: { tp: 0, fp: 0, fn: 0 }, graph: { tp: 0, fp: 0, fn: 0 } };
    for (const variant of VARIANTS) {
      const exploitable = c.deployments[variant].exploitable;
      const defectId = c.kind === 'source-finding' ? `src:${c.id}` : `dep:${c.id}`;
      const truth = exploitable ? [defectId] : [];
      const sourceReported = matched.length ? [`src:${c.id}`] : [];
      const g = graphArm({ c, variant, findings, config, now });
      const t = new Set(truth);
      const count = (reported, arm) => {
        const r = new Set(reported);
        for (const id of r) { if (t.has(id)) caseStats[arm].tp += 1; else caseStats[arm].fp += 1; }
        for (const id of t) if (!r.has(id)) caseStats[arm].fn += 1;
      };
      count(sourceReported, 'source'); count(g.reported, 'graph');
      const sr = new Set(sourceReported), gr = new Set(g.reported);
      instances.push({
        caseId: c.id, variant, exploitable, truth, adapters: g.adapters, graphOk: g.ok, graphFailure: g.ok ? null : g.reason,
        sourceOnly: { reported: sourceReported, completed },
        graph: { reported: g.reported, demoted: g.demoted, ms: g.ms, coverage: g.coverage },
        fpReduced: sourceReported.filter((id) => !t.has(id) && !gr.has(id)),
        fpAdded: g.reported.filter((id) => !t.has(id) && !sr.has(id)),
        confirmedAdded: g.reported.filter((id) => t.has(id) && !sr.has(id)),
        lost: sourceReported.filter((id) => t.has(id) && !gr.has(id)),
      });
    }
    perCase.push(caseStats);
  }

  const tot = (arm) => perCase.reduce((a, c) => ({ tp: a.tp + c[arm].tp, fp: a.fp + c[arm].fp, fn: a.fn + c[arm].fn }), { tp: 0, fp: 0, fn: 0 });
  const s = tot('source'), g = tot('graph');
  const sum = (key) => instances.reduce((a, i) => a + i[key].length, 0);
  const cov = instances.map((i) => i.graph.coverage).filter(Boolean);
  const graphMs = instances.map((i) => i.graph.ms);
  const paired = {
    instances: instances.length, cases: loaded.cases.length,
    falsePositivesReduced: sum('fpReduced'), confirmedDefectsAdded: sum('confirmedAdded'),
    baselineConfirmedDefectsLost: sum('lost'), falsePositivesAdded: sum('fpAdded'),
    unchanged: instances.filter((i) => !i.fpReduced.length && !i.fpAdded.length && !i.confirmedAdded.length && !i.lost.length).length,
  };
  const gates = evaluateGates({ protocol: stored.protocol, score: null, defects: [], negatives: [] });
  const report = {
    schema: ABLATION_REPORT_SCHEMA, schemaVersion: ABLATION_VERSION, synthetic: true,
    statement: 'SYNTHETIC cases authored by the tooling developers. These counts check a mechanism on constructed cases; they say nothing about benefit on real programs.',
    frozenHash: stored.frozenHash, protocolHash: stored.protocol.protocolHash, runId: run.run.runId, decisionRule: DECISION_RULE,
    arms: {
      sourceOnly: { ...prf(s.tp, s.fp, s.fn) }, graphEnabled: { ...prf(g.tp, g.fp, g.fn) },
    },
    paired,
    uncertainty: pairedBootstrap(perCase),
    runtime: {
      deterministic: false,
      sourceOnlyScanMsMedian: median(scanMs), graphEnabledAddedMsMedian: median(graphMs),
      note: 'Wall-clock milliseconds on the machine that ran this; they differ run to run and are not part of the frozen comparison. The graph-enabled arm costs its scan plus the added time.',
    },
    coverage: {
      sourceOnly: { scansCompleted: loaded.cases.filter((c) => run.run.outcomes.find((o) => o.targetId === c.id)?.status === 'completed').length, of: loaded.cases.length, deploymentContext: 'none: every finding is reported without any deployment evidence' },
      graphEnabled: {
        graphBuilt: instances.filter((i) => i.graphOk).length, of: instances.length,
        findingsWithContext: cov.reduce((a, c) => a + c.findings, 0), findingsBoundToAService: cov.reduce((a, c) => a + c.bound, 0), findingsNotAssessed: cov.reduce((a, c) => a + c.notAssessed, 0),
        exposureUnresolved: cov.reduce((a, c) => a + c.unresolvedExposure, 0),
        instancesWithGraphGaps: cov.filter((c) => c.graphGaps > 0).length, graphGapsTotal: cov.reduce((a, c) => a + c.graphGaps, 0), unresolvedNodesTotal: cov.reduce((a, c) => a + c.unresolvedNodes, 0),
        staleSources: cov.reduce((a, c) => a + c.staleSources, 0), missingSources: cov.reduce((a, c) => a + c.missingSources, 0),
        traces: 'no runtime traces are part of this set, so observed, sampled and stale trace coverage are all unmeasured here',
      },
    },
    unscoredFindings: unscored,
    adapters: adapterValidation(instances),
    realCodeGates: { overall: gates.overall, note: 'the protocol is synthetic, so no real-code gate can pass' },
    instances,
  };
  return { ok: true, errors: [], report };
}

/** The deterministic part of a report (no wall-clock figures), for comparison across runs and for the docs. */
export function deterministicView(report) {
  const { runtime, instances, ...rest } = report;
  void runtime;
  return { ...rest, instances: instances.map(({ graph, ...i }) => ({ ...i, graph: { reported: graph.reported, demoted: graph.demoted, coverage: graph.coverage } })) };
}
