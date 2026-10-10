// Held-out scenario ablation: what does an executable business-logic contract add? (X-408)
//
// Three arms are run over ONE frozen set of cases, with one denominator and one budget:
//
//   source-only        the deterministic engine in deep mode (the layer the CLI uses) over the case's source file, as an
//                      unmodified `scan-child` run: no contract, nothing executed. FLAGGED means a finding at medium or above
//                      in that file, of ANY family: deliberately generous to the baseline, so a gap against it is not an artefact
//                      of a strict matching rule.
//   inferred-contract  a contract a miner could plausibly propose from the code (`inferredInvariant`), run as scenarios through
//                      the business-state oracle with NO approval: a violation is a CANDIDATE (advisory), never a confirmed
//                      finding. A class with no skeleton is a miss, not an exclusion.
//   approved-contract  the reviewer-authored contract, approved in a signed ledger by a local policy, run the same way: a
//                      violation is CONFIRMED (executed, receipted, approved).
//
// Rules that keep the comparison honest:
//   - Same cases, same labels, same denominators. A case an arm could not evaluate (no skeleton, unsupported scenario, nothing
//     settled, a crash) stays in that arm's denominator as "not flagged"; it is counted and named, never dropped. An arm cannot
//     look better by skipping what it cannot do.
//   - Same budgets: one `bounds`, one seed and one source timeout are applied to every arm and recorded in the report.
//   - Positives and negatives are fixed in the frozen manifest; the runner never sees a label it could tune against (the
//     labels are read only by the scorer, after every arm has produced its flags).
//   - Precision and recall carry Wilson 95% intervals, and every arm is compared with the baseline on the SAME cases with
//     paired counts (found by both, only by the arm, only by the baseline, by neither; and the same for false positives).
//   - Unique findings are defects an arm flags that NO other arm flags; unique CONFIRMED ones additionally need execution and an
//     approved contract. Scenario cost is reported (scenarios run, requests, wall time); wall time is reported but never gated
//     and is excluded from the report fingerprint.
//   - A class is called SUPPORTED only from executed evidence: every case of the class ran under the approved arm and settled,
//     the registered policy thresholds were met, and no baseline-found defect was lost. Anything not executed (the trust boundary
//     could not run) is UNMEASURED, never unsupported-by-absence and never supported-by-assumption.
//
// WHAT THIS IS NOT. The cases are SYNTHETIC: small applications written by this tooling's developers, labelled by them, in the
// factory shape the business-state oracle can run. No independent adjudication exists. Every report is flagged
// `synthetic: true` and `realWorldClaim: false`; a figure from it describes the machinery on these fixtures and must not be
// quoted as engine accuracy or as a real-world benefit. The baseline arm sees framework-free factories, which is not the code it
// is built for, so its recall here says nothing about its recall on applications.
//
// The benchmark is frozen: `manifest.json` lists the sha256 of every file, `pin.json` pins the manifest's own digest, and
// `loadBenchmark` fails closed on any mismatch. Changing a case is a new version with a new pin, deliberately (`pinBenchmark`).
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { digestOf, digestOfBytes } from '../assurance/identity.js';
import { verifyInvariant } from '../invariants/run.js';
import { emptyLedger, recordTransition, inferredInvariant } from '../invariants/lifecycle.js';
import { validateInvariant } from '../invariants/schema.js';
import { defaultScanFn } from './runner.js';
import { engineEnvironment } from './custody.js';

const ABLATION_SCHEMA = 'agentic-security/invariant-ablation';
export const ARMS = Object.freeze(['source-only', 'inferred-contract', 'approved-contract']);
export const PIN_FILE = 'pin.json';
const MANIFEST_FILE = 'manifest.json';
const FLAG_SEVERITIES = new Set(['medium', 'high', 'critical']);
const REVIEWER = Object.freeze({ id: 'benchmark-fixture-reviewer', kind: 'human' });
const POLICY = Object.freeze({ id: 'benchmark-fixture-policy', reviewers: [REVIEWER.id] });
const SYNTHETIC_NOTE = 'SYNTHETIC: authored and labelled by the tooling developers; no independent adjudication. These figures exercise the comparison and are not engine accuracy or evidence of real-world benefit.';

// ---------------------------------------------------------------- the frozen benchmark

export function manifestHashOf(manifest) { return digestOf(manifest); }

const sha256 = (text) => digestOfBytes(Buffer.from(text, 'utf8'));

/** Write the pin for the benchmark in `dir`. Deliberate: run this only when a new version of the benchmark is meant. */
export function pinBenchmark(dir) {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, MANIFEST_FILE), 'utf8'));
  const pin = { manifestHash: manifestHashOf(manifest), version: manifest.version, files: Object.keys(manifest.files).length };
  fs.writeFileSync(path.join(dir, PIN_FILE), `${JSON.stringify(pin, null, 2)}\n`);
  return pin;
}

/**
 * Load and verify the frozen benchmark. Fails closed: a missing pin, a changed manifest, or any file whose digest differs from the
 * manifest is `{ ok: false, errors }` and nothing is returned to run.
 */
export function loadBenchmark(dir) {
  const errors = [];
  let manifest; let pin;
  try { manifest = JSON.parse(fs.readFileSync(path.join(dir, MANIFEST_FILE), 'utf8')); } catch { return { ok: false, errors: ['the benchmark manifest is missing or unreadable'] }; }
  try { pin = JSON.parse(fs.readFileSync(path.join(dir, PIN_FILE), 'utf8')); } catch { return { ok: false, errors: ['the benchmark has no pin: it is not frozen'] }; }
  if (manifest.schema !== 'agentic-security/invariant-benchmark' || manifest.synthetic !== true) errors.push('the manifest is not a synthetic invariant benchmark');
  if (pin.manifestHash !== manifestHashOf(manifest)) errors.push('the manifest no longer matches its pin: the benchmark was changed after it was frozen');
  const cases = [];
  for (const [rel, want] of Object.entries(manifest.files || {})) {
    let text;
    try { text = fs.readFileSync(path.join(dir, rel), 'utf8'); } catch { errors.push(`${rel}: missing`); continue; }
    if (sha256(text) !== want) errors.push(`${rel}: digest differs from the frozen manifest`);
  }
  if (errors.length) return { ok: false, errors };
  for (const c of manifest.cases) {
    const base = path.join(dir, 'cases', c.id);
    const read = (f) => fs.readFileSync(path.join(base, f), 'utf8');
    const contract = JSON.parse(read('contract.json'));
    if (!validateInvariant(contract).ok) { errors.push(`${c.id}: the approved contract is not valid`); continue; }
    cases.push({ ...c, files: { 'app.mjs': read('app.mjs') }, contract, hint: JSON.parse(read('hint.json')) });
  }
  if (errors.length) return { ok: false, errors };
  return { ok: true, benchmark: { dir, manifest, manifestHash: pin.manifestHash, version: manifest.version, claimPolicy: manifest.claimPolicy, cases } };
}

// ---------------------------------------------------------------- statistics

/** Wilson score interval for k successes in n trials (95%). `null` bounds when n is 0: no interval is invented. */
export function wilson(k, n, z = 1.959964) {
  if (!Number.isInteger(n) || n <= 0) return { low: null, high: null };
  const p = k / n; const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (p + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((p * (1 - p)) / n + z2 / (4 * n * n))) / denom;
  return { low: Math.max(0, centre - half), high: Math.min(1, centre + half) };
}

const rate = (k, n) => ({ k, n, value: n > 0 ? k / n : null, ...wilson(k, n) });

// ---------------------------------------------------------------- arms

function cost(scenarios, requests, ms) { return { scenarios, requests, ms }; }

function fromInvariantRun(res, ms) {
  const results = Array.isArray(res?.results) ? res.results : [];
  const executed = results.filter((r) => r.status === 'completed');
  const decided = executed.filter((r) => r.outcome === 'confirmed' || r.outcome === 'refuted');
  const violated = results.filter((r) => r.outcome === 'confirmed');
  const approved = results.filter((r) => r.classification?.kind === 'approved-violation');
  return {
    flagged: violated.length > 0, confirmed: approved.length > 0, executed: executed.length > 0, decided: decided.length > 0,
    complete: results.length > 0 && decided.length === results.length && (res?.unsupported || []).length === 0,
    status: res?.status === 'ok' ? (decided.length ? 'decided' : executed.length ? 'inconclusive' : 'not-executed') : (res?.status ?? 'error'),
    reason: res?.reason ?? (results.find((r) => r.reason)?.reason ?? null),
    kinds: results.map((r) => r.kind), unsupported: (res?.unsupported || []).map((u) => u.kind ?? u.reason),
    cost: cost(executed.length, executed.reduce((n, r) => n + (r.limits?.requests ?? 0), 0), ms),
  };
}

/** The default baseline: one deep-mode engine scan of the case's file in a child process, through the evaluation runner. */
export async function defaultSourceAnalyzer({ files, tmpRoot, timeoutMs }) {
  const dir = fs.mkdtempSync(path.join(tmpRoot || os.tmpdir(), 'inv-bench-src-'));
  try {
    for (const [rel, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, rel), text);
    const r = await defaultScanFn(dir, { layer: 'deep-taint', timeoutMs, env: engineEnvironment(process.env) });
    return { findings: r.findings || [] };
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
}

async function sourceArm(c, o) {
  const t0 = Date.now();
  try {
    const r = await o.sourceAnalyzer({ files: c.files, caseId: c.id, tmpRoot: o.tmpRoot, timeoutMs: o.sourceTimeoutMs });
    const hit = (r.findings || []).filter((f) => FLAG_SEVERITIES.has(f.severity) && (!f.file || String(f.file).endsWith('app.mjs')));
    return { flagged: hit.length > 0, confirmed: false, executed: true, decided: true, complete: true, status: 'analyzed', reason: hit.length ? `${hit.length} finding(s) at medium or above` : null, findings: hit.map((f) => ({ family: f.family ?? null, cwe: f.cwe ?? null, severity: f.severity })), cost: cost(0, 0, Date.now() - t0) };
  } catch (e) {
    return { flagged: false, confirmed: false, executed: false, decided: false, complete: false, status: 'error', reason: String(e?.message || e).slice(0, 200), cost: cost(0, 0, Date.now() - t0) };
  }
}

async function inferredArm(c, o) {
  const t0 = Date.now();
  const inv = inferredInvariant({ ...c.hint });
  if (!inv) return { flagged: false, confirmed: false, executed: false, decided: false, complete: false, status: 'no-contract', reason: `no inferred skeleton exists for the '${c.hint.class}' class`, cost: cost(0, 0, 0) };
  const res = await verifyInvariant({ invariant: inv, fixture: { files: c.files }, commit: o.commit, config: o.config, seed: o.seed, bounds: o.bounds, runOptions: o.runOptions });
  const out = fromInvariantRun(res, Date.now() - t0);
  out.confirmed = false; // an unapproved contract can never confirm anything
  return out;
}

async function approvedArm(c, o) {
  const t0 = Date.now();
  const inv = c.contract;
  const proposed = recordTransition(emptyLedger(), { action: 'propose', invariant: inv, actor: { id: 'benchmark-loader', kind: 'code' }, reason: 'frozen benchmark fixture' }, { signer: o.signer });
  const approved = proposed.ok ? recordTransition(proposed.ledger, { action: 'approve', invariantId: inv.id, actor: REVIEWER, reason: 'reviewer-approved contract of the frozen benchmark' }, { policy: POLICY, signer: o.signer }) : proposed;
  if (!approved.ok) return { flagged: false, confirmed: false, executed: false, decided: false, complete: false, status: 'error', reason: approved.errors?.[0]?.message ?? 'the fixture contract could not be recorded', cost: cost(0, 0, 0) };
  const res = await verifyInvariant({ invariant: inv, fixture: { files: c.files }, commit: o.commit, config: o.config, seed: o.seed, bounds: o.bounds, ledger: approved.ledger, signer: o.signer, runOptions: o.runOptions });
  return fromInvariantRun(res, Date.now() - t0);
}

// ---------------------------------------------------------------- scoring

function scoreArm(cases, outcomes) {
  let tp = 0; let fp = 0; let fn = 0; let tn = 0; let confirmed = 0;
  const notEvaluated = [];
  for (const c of cases) {
    const o = outcomes[c.id];
    if (o.flagged) { if (c.defective) tp++; else fp++; } else if (c.defective) fn++; else tn++;
    if (o.flagged && o.confirmed && c.defective) confirmed++;
    if (!o.executed || !o.decided || o.complete === false) notEvaluated.push({ caseId: c.id, status: o.status, reason: o.reason ?? null });
  }
  const positives = tp + fn; const negatives = fp + tn;
  return {
    counts: { tp, fp, fn, tn, positives, negatives, cases: cases.length },
    precision: rate(tp, tp + fp), recall: rate(tp, positives), falsePositiveRate: rate(fp, negatives),
    confirmedTruePositives: confirmed, notEvaluated,
  };
}

function paired(cases, baseline, arm) {
  const out = { defects: { both: 0, armOnly: 0, baselineOnly: 0, neither: 0 }, valid: { bothFlagged: 0, armOnly: 0, baselineOnly: 0, neither: 0 } };
  for (const c of cases) {
    const b = baseline[c.id].flagged; const a = arm[c.id].flagged;
    if (c.defective) out.defects[a && b ? 'both' : a ? 'armOnly' : b ? 'baselineOnly' : 'neither']++;
    else out.valid[a && b ? 'bothFlagged' : a ? 'armOnly' : b ? 'baselineOnly' : 'neither']++;
  }
  return { ...out, lostBaselineDefects: out.defects.baselineOnly, falsePositivesRemoved: out.valid.baselineOnly, falsePositivesAdded: out.valid.armOnly };
}

function uniques(cases, outcomes) {
  const out = {};
  for (const arm of ARMS) {
    const others = ARMS.filter((a) => a !== arm);
    const ids = cases.filter((c) => c.defective && outcomes[arm][c.id].flagged && !others.some((o) => outcomes[o][c.id].flagged)).map((c) => c.id);
    out[arm] = { uniqueTruePositives: ids.length, uniqueConfirmed: ids.filter((id) => outcomes[arm][id].confirmed).length, caseIds: ids };
  }
  return out;
}

const median = (xs) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };

/**
 * Per-class claims from executed evidence only. `supported` needs: every case of the class executed and settled under the approved
 * arm, at least the registered number of defect and valid cases, precision and recall at the registered thresholds, and no
 * defect the baseline found lost. `unmeasured` when anything was not executed. Otherwise `unsupported`, with the reasons.
 */
export function releaseClaims({ cases, outcomes, policy }) {
  const pol = policy || {};
  const classes = [...new Set(cases.map((c) => c.class))].sort();
  const claims = {};
  for (const cls of classes) {
    const mine = cases.filter((c) => c.class === cls);
    const d = mine.filter((c) => c.defective); const v = mine.filter((c) => !c.defective);
    const ap = outcomes['approved-contract']; const src = outcomes['source-only'];
    const reasons = [];
    const notRun = mine.filter((c) => !ap[c.id].executed);
    const unsettled = mine.filter((c) => ap[c.id].executed && (!ap[c.id].decided || ap[c.id].complete === false));
    let status;
    if (notRun.length) { status = 'unmeasured'; reasons.push(`not executed: ${notRun.map((c) => c.id).join(', ')}`); }
    else {
      const tp = d.filter((c) => ap[c.id].flagged).length; const fp = v.filter((c) => ap[c.id].flagged).length;
      const precision = tp + fp ? tp / (tp + fp) : null; const recall = d.length ? tp / d.length : null;
      if (d.length < (pol.minDefectCasesPerClass ?? 1)) reasons.push(`fewer than ${pol.minDefectCasesPerClass ?? 1} defect case(s)`);
      if (v.length < (pol.minValidCasesPerClass ?? 1)) reasons.push(`fewer than ${pol.minValidCasesPerClass ?? 1} valid case(s)`);
      if (unsettled.length) reasons.push(`did not settle: ${unsettled.map((c) => c.id).join(', ')}`);
      if (precision === null || precision < (pol.minPrecision ?? 1)) reasons.push(`precision ${precision === null ? 'undefined' : precision.toFixed(2)} below ${pol.minPrecision ?? 1}`);
      if (recall === null || recall < (pol.minRecall ?? 1)) reasons.push(`recall ${recall === null ? 'undefined' : recall.toFixed(2)} below ${pol.minRecall ?? 1}`);
      const lost = d.filter((c) => src[c.id].flagged && !ap[c.id].flagged);
      if (pol.noLossVersusSourceOnly !== false && lost.length) reasons.push(`lost baseline-found defect(s): ${lost.map((c) => c.id).join(', ')}`);
      status = reasons.length ? 'unsupported' : 'supported';
    }
    const tpN = d.filter((c) => ap[c.id].flagged).length; const fpN = v.filter((c) => ap[c.id].flagged).length;
    claims[cls] = {
      status, reasons, defectCases: d.length, validCases: v.length,
      precision: rate(tpN, tpN + fpN), recall: rate(tpN, d.length),
      uniqueConfirmed: d.filter((c) => ap[c.id].confirmed && !src[c.id].flagged && !outcomes['inferred-contract'][c.id].flagged).length,
      scenarioCost: { scenarios: mine.reduce((n, c) => n + ap[c.id].cost.scenarios, 0), requests: mine.reduce((n, c) => n + ap[c.id].cost.requests, 0) },
      scope: 'frozen synthetic fixtures only; no real-world claim',
    };
  }
  return claims;
}

// ---------------------------------------------------------------- the run

/**
 * Run all three arms over the frozen benchmark and score them. Never throws.
 *
 * @param {object} o
 * @param {object} o.benchmark        from `loadBenchmark`
 * @param {string} o.commit           exact commit the fixtures are treated as belonging to (a decided verdict needs one)
 * @param {object} o.config           assurance config with `invariant-scenarios` and `verification-oracles` enabled
 * @param {object} [o.bounds]         scenario bounds, identical for every arm
 * @param {number} [o.seed]
 * @param {Function} [o.sourceAnalyzer]  ({ files, caseId, tmpRoot, timeoutMs }) => { findings }; default is a real deep-mode scan
 * @param {number} [o.sourceTimeoutMs]
 * @param {object} [o.signer]         ledger signer (test seam); default is the per-install key
 * @param {object} [o.runOptions]     oracle runner seams (test)
 */
export async function runInvariantAblation(o = {}) {
  const b = o.benchmark;
  const opts = {
    commit: o.commit, config: o.config, bounds: o.bounds, seed: o.seed ?? 1, signer: o.signer, runOptions: o.runOptions,
    sourceAnalyzer: o.sourceAnalyzer || defaultSourceAnalyzer, tmpRoot: o.tmpRoot, sourceTimeoutMs: o.sourceTimeoutMs ?? 90_000,
  };
  // every arm is run before any label is consulted
  const outcomes = { 'source-only': {}, 'inferred-contract': {}, 'approved-contract': {} };
  for (const c of b.cases) {
    const safe = async (fn) => { try { return await fn(c, opts); } catch (e) { return { flagged: false, confirmed: false, executed: false, decided: false, complete: false, status: 'error', reason: String(e?.message || e).slice(0, 200), cost: cost(0, 0, 0) }; } };
    outcomes['source-only'][c.id] = await safe(sourceArm);
    outcomes['inferred-contract'][c.id] = await safe(inferredArm);
    outcomes['approved-contract'][c.id] = await safe(approvedArm);
  }
  const labelled = b.cases.map((c) => ({ id: c.id, class: c.class, defective: c.defective }));
  const arms = {};
  for (const arm of ARMS) {
    const ms = b.cases.map((c) => outcomes[arm][c.id].cost.ms);
    arms[arm] = {
      ...scoreArm(labelled, outcomes[arm]),
      cost: { scenarios: b.cases.reduce((n, c) => n + outcomes[arm][c.id].cost.scenarios, 0), requests: b.cases.reduce((n, c) => n + outcomes[arm][c.id].cost.requests, 0), medianMsPerCase: median(ms), totalMs: ms.reduce((a, x) => a + x, 0) },
      outcomes: b.cases.map((c) => ({ caseId: c.id, ...outcomes[arm][c.id] })),
    };
  }
  const base = outcomes['source-only'];
  const report = {
    schema: ABLATION_SCHEMA, schemaVersion: '1.0.0', synthetic: true, realWorldClaim: false, note: SYNTHETIC_NOTE,
    benchmark: { version: b.version, manifestHash: b.manifestHash, counts: b.manifest.counts, claimPolicy: b.claimPolicy },
    budgets: { bounds: o.bounds ?? 'defaults', seed: opts.seed, sourceTimeoutMs: opts.sourceTimeoutMs, identicalForEveryArm: true },
    arms,
    paired: { 'inferred-contract': paired(labelled, base, outcomes['inferred-contract']), 'approved-contract': paired(labelled, base, outcomes['approved-contract']) },
    unique: uniques(labelled, outcomes),
    claims: releaseClaims({ cases: labelled, outcomes, policy: b.claimPolicy }),
  };
  const stable = JSON.parse(JSON.stringify(report, (k, v) => (k === 'ms' || k === 'medianMsPerCase' || k === 'totalMs' ? undefined : v)));
  report.fingerprint = digestOf(stable);
  return report;
}

export function renderAblation(report) {
  const pct = (r) => (r.value === null ? 'n/a' : `${(r.value * 100).toFixed(0)}% [${(r.low * 100).toFixed(0)}-${(r.high * 100).toFixed(0)}] (${r.k}/${r.n})`);
  const lines = [report.note, `benchmark v${report.benchmark.version} ${report.benchmark.manifestHash.slice(0, 19)}  cases: ${report.benchmark.counts.cases} (${report.benchmark.counts.defective} defective, ${report.benchmark.counts.valid} valid)`, ''];
  lines.push('arm                  precision                   recall                      unique TP  unique confirmed  scenarios  requests');
  for (const arm of ARMS) {
    const a = report.arms[arm]; const u = report.unique[arm];
    lines.push(`${arm.padEnd(20)} ${pct(a.precision).padEnd(27)} ${pct(a.recall).padEnd(27)} ${String(u.uniqueTruePositives).padEnd(10)} ${String(u.uniqueConfirmed).padEnd(17)} ${String(a.cost.scenarios).padEnd(10)} ${a.cost.requests}`);
  }
  lines.push('', 'class claims (executed evidence only):');
  for (const [cls, c] of Object.entries(report.claims)) lines.push(`  ${cls.padEnd(22)} ${c.status.toUpperCase().padEnd(11)} ${c.reasons.join('; ') || 'policy met on the frozen synthetic fixtures'}`);
  return lines;
}
