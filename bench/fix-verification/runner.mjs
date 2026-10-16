#!/usr/bin/env node
// Fix verification benchmark runner (E3-08). Runs every candidate patch of every case through the one verifier (verifyPatch) in a fresh
// project and scores the verdict against the label.
//   node bench/fix-verification/runner.mjs            print the report
//   node bench/fix-verification/runner.mjs --check    compare with baseline.json; exit 1 on any drift
//   node bench/fix-verification/runner.mjs --update-baseline
//   node bench/fix-verification/runner.mjs --write-doc   regenerate docs/engineering-excellence/FIX_BENCHMARK.md
//
// A verdict is "accepted" when verifyPatch says ok. The scores that matter:
//   unsafe accepted  fake-but-green fixes the pipeline let through (the number that must stay 0 except for recorded gaps)
//   safe rejected    real fixes it refused
//   degraded rate    accepted patches that were not fully verified (tests absent, replay not run, ...)
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CASES, NOT_COVERED } from './cases.mjs';
import { runScan } from '../../scanner/src/runScan.js';
import { signLastScan } from '../../scanner/src/posture/integrity.js';
import { verifyPatch } from '../../scanner/src/fix/verify-patch.js';
import { sandboxAvailable } from '../../scanner/src/sandbox/index.js';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
// FIXBENCH_BASELINE_PATH lets a test point the gate at a doctored copy instead of editing the committed file (an interrupted test used to leave it doctored)
const BASELINE = process.env.FIXBENCH_BASELINE_PATH || path.join(HERE, 'baseline.json');
const DOC = path.join(HERE, '../../docs/engineering-excellence/FIX_BENCHMARK.md');

async function setup(c) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), `fixbench-${c.id}-`));
  fs.writeFileSync(path.join(root, 'package.json'), JSON.stringify({ name: 'case', version: '1.0.0', scripts: { test: 'node test.js' } }));
  for (const [rel, text] of Object.entries(c.files)) { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); }
  const saved = process.env.AGENTIC_SECURITY_DEEP; process.env.AGENTIC_SECURITY_DEEP = '1';
  let scan; try { ({ scan } = await runScan(root)); } finally { if (saved === undefined) delete process.env.AGENTIC_SECURITY_DEEP; else process.env.AGENTIC_SECURITY_DEEP = saved; }
  const finding = scan.findings.find((f) => f.cwe === c.cwe && f.file === 'app.js');
  if (finding) {
    const st = path.join(root, '.agentic-security'); fs.mkdirSync(st, { recursive: true }); const body = JSON.stringify(scan);
    fs.writeFileSync(path.join(st, 'last-scan.json'), body); fs.writeFileSync(path.join(st, 'last-scan.json.sig'), signLastScan(body));
  }
  return { root, finding };
}

export async function runBench({ only = null } = {}) {
  await disableStateWrites();
  const rows = [];
  const unscored = [];
  const canReplay = sandboxAvailable();
  for (const c of CASES) {
    if (only && c.id !== only) continue;
    const { root, finding } = await setup(c);
    try {
      if (!finding) { unscored.push({ case: c.id, reason: `the scanner produced no ${c.cwe} finding in app.js, so no patch can be verified against it` }); continue; }
      for (const p of c.patches) {
        const t0 = Date.now();
        const usesReplay = !!c.reproducer && canReplay;
        let r; let error = null;
        try { r = await verifyPatch({ scanRoot: root, finding: { id: finding.id, stableId: finding.stableId }, files: p.files, route: 'fix-bench', mode: 'verify', ...(usesReplay ? { reproducer: c.reproducer, replayAttempts: 2 } : {}) }); } catch (e) { error = String(e.message || e); }
        if (error) { unscored.push({ case: c.id, patch: p.id, reason: `the verifier threw: ${error}` }); continue; }
        const rec = r.fixVerification;
        rows.push({
          case: c.id, cls: c.cls, patch: p.id, safe: p.safe, kind: p.kind || null, knownGap: p.gap === true,
          accepted: r.verdict.ok === true, rejectedBy: r.verdict.rejectedBy || (r.verdict.ok ? null : 'verifier'),
          completeness: rec.fixCompleteness, verifiedFull: rec.verifiedFull, degraded: rec.degradedLegs.length,
          replayRequested: usesReplay, replayRan: rec.exploitProofAfter.status !== 'not_run', exploitAfter: rec.exploitProofAfter.status,
          newFindings: (r.verdict.rescan?.introduced || []).length, durationMs: Date.now() - t0,
        });
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  return { rows, unscored, canReplay };
}

const pct = (n, d) => (d ? `${((100 * n) / d).toFixed(1)}%` : 'n/a');

export function summarize({ rows, unscored, canReplay }) {
  const safe = rows.filter((r) => r.safe); const unsafe = rows.filter((r) => !r.safe);
  const unsafeAccepted = unsafe.filter((r) => r.accepted);
  const accepted = rows.filter((r) => r.accepted);
  const byClass = {};
  for (const r of rows) { const b = (byClass[r.cls] ??= { safe: 0, safeAccepted: 0, unsafe: 0, unsafeAccepted: 0 }); if (r.safe) { b.safe++; if (r.accepted) b.safeAccepted++; } else { b.unsafe++; if (r.accepted) b.unsafeAccepted++; } }
  return {
    schema: 'agentic-security/fix-verification-bench', version: 1,
    denominators: { patches: rows.length, safe: safe.length, unsafe: unsafe.length, cases: new Set(rows.map((r) => r.case)).size, unscored: unscored.length },
    unsafeAccepted: { n: unsafeAccepted.length, of: unsafe.length, rate: pct(unsafeAccepted.length, unsafe.length), patches: unsafeAccepted.map((r) => `${r.case}/${r.patch}`).sort() },
    safeRejected: { n: safe.filter((r) => !r.accepted).length, of: safe.length, rate: pct(safe.filter((r) => !r.accepted).length, safe.length), patches: safe.filter((r) => !r.accepted).map((r) => `${r.case}/${r.patch}`).sort() },
    degradedRateAmongAccepted: { n: accepted.filter((r) => !r.verifiedFull).length, of: accepted.length, rate: pct(accepted.filter((r) => !r.verifiedFull).length, accepted.length) },
    rejectedBy: Object.fromEntries([...new Set(rows.filter((r) => !r.accepted).map((r) => r.rejectedBy))].sort().map((k) => [k, rows.filter((r) => !r.accepted && r.rejectedBy === k).length])),
    replay: { hostCanReplay: canReplay, patchesWithReproducer: rows.filter((r) => r.replayRequested).length, ran: rows.filter((r) => r.replayRan).length, unavailableMisreadAsBlocked: rows.filter((r) => r.replayRequested && !r.replayRan && r.exploitAfter === 'passed').length },
    newFindingsIntroduced: rows.reduce((a, r) => a + r.newFindings, 0),
    cost: { totalMs: rows.reduce((a, r) => a + r.durationMs, 0), medianMsPerPatch: rows.length ? [...rows].map((r) => r.durationMs).sort((a, b) => a - b)[Math.floor(rows.length / 2)] : 0 },
    byClass, notCovered: NOT_COVERED, unscored,
  };
}

const gapSet = (rows) => rows.filter((r) => !r.safe && r.knownGap).map((r) => `${r.case}/${r.patch}`).sort();

/** The pinned part of a run: what the gate compares. Costs and timings are reported, never compared. */
export function pinned(rows, s) {
  return { unsafeAccepted: s.unsafeAccepted.patches, safeRejected: s.safeRejected.patches, declaredGaps: gapSet(rows), denominators: { patches: s.denominators.patches, safe: s.denominators.safe, unsafe: s.denominators.unsafe }, unscored: s.unscored.map((u) => `${u.case}/${u.patch || '*'}`).sort(), unavailableMisreadAsBlocked: s.replay.unavailableMisreadAsBlocked };
}

export function decide(base, now) {
  const problems = [];
  const j = JSON.stringify;
  const newUnsafe = now.unsafeAccepted.filter((x) => !base.unsafeAccepted.includes(x));
  if (newUnsafe.length) problems.push(`NEW unsafe fixes accepted: ${newUnsafe.join(', ')}`);
  const closed = base.unsafeAccepted.filter((x) => !now.unsafeAccepted.includes(x));
  if (closed.length) problems.push(`gaps closed but not recorded (re-baseline and clear the gap flag): ${closed.join(', ')}`);
  const newReject = now.safeRejected.filter((x) => !base.safeRejected.includes(x));
  if (newReject.length) problems.push(`NEW safe fixes rejected: ${newReject.join(', ')}`);
  if (j(now.declaredGaps) !== j(base.declaredGaps)) problems.push('the declared gap list changed without a re-baseline');
  const undeclared = now.unsafeAccepted.filter((x) => !now.declaredGaps.includes(x));
  if (undeclared.length) problems.push(`unsafe fixes accepted that are not declared gaps: ${undeclared.join(', ')}`);
  if (j(now.denominators) !== j(base.denominators)) problems.push(`corpus size changed ${j(base.denominators)} -> ${j(now.denominators)}`);
  if (j(now.unscored) !== j(base.unscored)) problems.push(`unscored set changed: ${j(base.unscored)} -> ${j(now.unscored)}`);
  if (now.unavailableMisreadAsBlocked !== 0) problems.push(`${now.unavailableMisreadAsBlocked} unavailable replays were read as a blocked exploit`);
  return problems;
}

function doc(s, rows) {
  const L = [];
  L.push('# Fix verification benchmark', '', 'Generated by `node bench/fix-verification/runner.mjs --write-doc`. Do not edit by hand.', '');
  L.push('Every candidate patch of every case goes through the one verifier (`scanner/src/fix/verify-patch.js`) in a fresh project: rescan, the project tests run on a copy with the patch applied, the functional-footprint check, the secret-persistence check and, where the case has a reproducer and the host can confine it, a pre/post exploit replay.', '');
  L.push('## Denominators', '');
  L.push(`- ${s.denominators.patches} patches scored across ${s.denominators.cases} cases: ${s.denominators.safe} safe (real fixes that keep the feature) and ${s.denominators.unsafe} unsafe (look fixed, are not).`);
  L.push(`- ${s.denominators.unscored} patches or cases could not be scored${s.unscored.length ? `: ${s.unscored.map((u) => `${u.case}${u.patch ? '/' + u.patch : ''} (${u.reason})`).join('; ')}` : ''}.`);
  L.push(`- Not covered by this pipeline: ${s.notCovered.map((n) => `${n.cls} (${n.reason})`).join('; ')}.`, '');
  L.push('## Results', '');
  L.push('| Measure | Count | Of | Rate |', '|---|---|---|---|');
  L.push(`| Unsafe fixes accepted | ${s.unsafeAccepted.n} | ${s.unsafeAccepted.of} | ${s.unsafeAccepted.rate} |`);
  L.push(`| Safe fixes rejected | ${s.safeRejected.n} | ${s.safeRejected.of} | ${s.safeRejected.rate} |`);
  L.push(`| Accepted patches that were not fully verified | ${s.degradedRateAmongAccepted.n} | ${s.degradedRateAmongAccepted.of} | ${s.degradedRateAmongAccepted.rate} |`, '');
  L.push(`Unsafe fixes accepted today (declared gaps, each a real hole): ${s.unsafeAccepted.patches.length ? s.unsafeAccepted.patches.map((p) => '`' + p + '`').join(', ') : 'none'}.`, '');
  L.push(`Real fixes refused today (the scanner or the new-finding check objected; each is a false rejection): ${s.safeRejected.patches.length ? s.safeRejected.patches.map((p) => '`' + p + '`').join(', ') : 'none'}.`, '');
  L.push(`Rejected by: ${Object.entries(s.rejectedBy).map(([k, v]) => `${k} ${v}`).join(', ') || 'n/a'}.`, '');
  L.push(`Exploit replay: host can confine a run: ${s.replay.hostCanReplay}; patches with a reproducer ${s.replay.patchesWithReproducer}; replay ran for ${s.replay.ran}; unavailable replays misread as a blocked exploit: ${s.replay.unavailableMisreadAsBlocked}.`, '');
  L.push(`New findings introduced by patches: ${s.newFindingsIntroduced}. Cost is printed by the runner and not recorded here: it varies with the machine.`, '');
  L.push('## By class', '', '| Class | Safe accepted | Unsafe accepted |', '|---|---|---|');
  for (const [k, b] of Object.entries(s.byClass)) L.push(`| ${k} | ${b.safeAccepted}/${b.safe} | ${b.unsafeAccepted}/${b.unsafe} |`);
  L.push('', '## Per patch', '', '| Case | Patch | Label | Verdict | Tier | Rejected by |', '|---|---|---|---|---|---|');
  for (const r of rows) L.push(`| ${r.case} | ${r.patch} | ${r.safe ? 'safe' : 'unsafe' + (r.knownGap ? ' (gap)' : '')} | ${r.accepted ? 'accepted' : 'rejected'} | ${r.completeness} | ${r.rejectedBy || ''} |`);
  L.push('', '## Limitations', '');
  L.push('- The corpus is hand-written, synthetic and tiny (JavaScript only, one weakness per project). A 0% on this corpus is not a 0% in the wild; it says these patterns are handled and these specific ones are not.');
  L.push('- A fake fix is anything the author thought of. Fakes nobody thought of are not measured.');
  L.push('- IDOR and authorization cases are judged by the footprint heuristic and by source-level tests, not by running an authenticated request, so a fix that keeps the lookup but checks the wrong thing can pass (declared gaps).');
  L.push('- The exploit replay is exercised for command injection only, in the lower-assurance local sandbox.');
  L.push('- Dependency upgrades are verified by a different route and are not scored here.');
  L.push('- Timings are one machine and one run.', '');
  return L.join('\n');
}

async function main() {
  const a = process.argv.slice(2);
  const res = await runBench({ only: (a.find((x) => x.startsWith('--case=')) || '').slice(7) || null });
  const s = summarize(res);
  const now = pinned(res.rows, s);
  if (a.includes('--write-doc')) { fs.writeFileSync(DOC, doc(s, res.rows)); console.log(`wrote ${path.relative(process.cwd(), DOC)}`); }
  console.log(`patches ${s.denominators.patches} (safe ${s.denominators.safe}, unsafe ${s.denominators.unsafe}); unsafe accepted ${s.unsafeAccepted.n}/${s.unsafeAccepted.of}; safe rejected ${s.safeRejected.n}/${s.safeRejected.of}; degraded among accepted ${s.degradedRateAmongAccepted.rate}; unscored ${s.denominators.unscored}`);
  for (const r of res.rows) if (a.includes('-v')) console.log(`  ${r.case}/${r.patch}: ${r.safe ? 'safe' : 'unsafe'} -> ${r.accepted ? 'ACCEPTED' : 'rejected'} ${r.completeness} ${r.rejectedBy || ''}`);
  if (a.includes('--update-baseline')) { fs.writeFileSync(BASELINE, JSON.stringify(now, null, 2) + '\n'); console.log('baseline written'); return 0; }
  if (a.includes('--check')) {
    if (!fs.existsSync(BASELINE)) { console.error('no baseline: run --update-baseline'); return 1; }
    const problems = decide(JSON.parse(fs.readFileSync(BASELINE, 'utf8')), now);
    if (problems.length) { for (const p of problems) console.error(`FAIL ${p}`); return 1; }
    console.log('fix verification bench: matches baseline');
  }
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().then((c) => process.exit(c), (e) => { console.error(e); process.exit(2); });
