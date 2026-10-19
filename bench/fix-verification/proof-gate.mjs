#!/usr/bin/env node
// The proof gate on fix application (`fix --apply --require-proof`), measured on the fix-verification corpus.
//
//   node bench/fix-verification/proof-gate.mjs            print the report
//   node bench/fix-verification/proof-gate.mjs --check    compare with proof-gate-baseline.json; exit 1 on any drift
//   node bench/fix-verification/proof-gate.mjs --update-baseline
//
// `fix --apply --require-proof` applies a patch only if the original exploit is confirmed beforehand and demonstrably blocked afterwards
// (posture/proof-fabric/fix-proof.js). This runs exactly that decision, `verifyFixWithProof`, for every candidate patch of every case, with
// the reproducer the case supplies or the one generated from the finding, and scores whether the patch would be APPLIED against its label:
//
//   unsafe applied      a fake-but-green fix the proof gate let through (must be 0, the number this exists to hold)
//   safe applied        real fixes the gate allows
//   safe refused        real fixes the gate refuses, with the reason (no reproducer, exploit not confirmed first, replay incomplete)
//
// A refusal is always the safe side: the gate fails closed. What the gate cannot do is also measured, not hidden: a case with no reproducer
// refuses every one of its patches, so the safe ones in it are `safe refused: no reproducer`, listed by name.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CASES } from './cases.mjs';
import { setup } from './runner.mjs';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';
import { sandboxAvailable, detectBackend } from '../../scanner/src/sandbox/index.js';
import { resolveReproducer } from '../../scanner/src/posture/proof-fabric/cli.js';
import { verifyFixWithProof } from '../../scanner/src/posture/proof-fabric/fix-proof.js';
import { verifyFix } from '../../scanner/src/posture/fix-verify.js';
import { verifyPatch } from '../../scanner/src/fix/verify-patch.js';
import * as os from 'node:os';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const BASELINE = process.env.FIXPROOF_BASELINE_PATH || path.join(HERE, 'proof-gate-baseline.json');

export async function runProofGate() {
  await disableStateWrites();
  if (!sandboxAvailable()) throw new Error('no confinement backend on this host: the proof gate cannot be measured');
  const rows = []; const unscored = [];
  for (const c of CASES) {
    const { root, finding } = await setup(c);
    try {
      if (!finding) { unscored.push({ case: c.id, reason: `the scanner produced no ${c.cwe} finding in app.js` }); continue; }
      const loaded = c.reproducer ? { reproducer: structuredClone(c.reproducer), source: 'case' } : (() => { const r = resolveReproducer(root, finding, null); return r.reproducer ? { reproducer: r.reproducer, source: 'generated' } : { reproducer: null, reason: r.reason }; })();
      for (const p of c.patches) {
        // the same static verdict the fix-verification bench scores (rescan, tests on a copy, honesty, and the case's own replay where it has one)
        let st;
        try { st = await verifyPatch({ scanRoot: root, finding: { id: finding.id, stableId: finding.stableId }, files: p.files, route: 'fix-bench', mode: 'verify', ...(c.reproducer ? { reproducer: c.reproducer, replayAttempts: 2 } : {}) }); } catch (e) { unscored.push({ case: c.id, patch: p.id, reason: `the verifier threw: ${e.message}` }); continue; }
        const staticOk = st.verdict.ok === true;
        if (!loaded.reproducer) {
          rows.push({ case: c.id, cls: c.cls, patch: p.id, safe: p.safe, knownGap: p.gap === true, reproducer: 'none', staticOk, proofVerified: false, applied: false, refusedBy: 'no-reproducer' });
          continue;
        }
        let fp;
        try {
          const staticVerification = await verifyFix({ scanRoot: root, originalFindingStableId: finding.stableId || null, files: p.files, recordMetrics: false });
          fp = await verifyFixWithProof({ finding, reproducer: loaded.reproducer, files: p.files, scanRoot: root, staticVerification, siblings: [], siblingSearchTruncated: [] });
        } catch (e) { unscored.push({ case: c.id, patch: p.id, reason: `the proof gate threw: ${e.message}` }); continue; }
        const proofVerified = fp.verified === true;
        rows.push({
          case: c.id, cls: c.cls, patch: p.id, safe: p.safe, knownGap: p.gap === true, reproducer: loaded.source, staticOk, proofVerified, applied: staticOk && proofVerified,
          refusedBy: staticOk && proofVerified ? null : (!proofVerified ? (fp.incompleteStep || fp.state || 'not-verified') : 'static-verifier'),
        });
      }
    } finally { fs.rmSync(root, { recursive: true, force: true }); }
  }
  return { rows, unscored, host: { platform: process.platform, backend: detectBackend() } };
}

export function summarize({ rows, unscored }) {
  const safe = rows.filter((r) => r.safe); const unsafe = rows.filter((r) => !r.safe);
  const with_ = rows.filter((r) => r.reproducer !== 'none');
  return {
    schema: 'agentic-security/fix-proof-gate-bench', version: 1,
    denominators: { patches: rows.length, safe: safe.length, unsafe: unsafe.length, withReproducer: with_.length, withoutReproducer: rows.length - with_.length, unscored: unscored.length },
    unsafeApplied: unsafe.filter((r) => r.applied).map((r) => `${r.case}/${r.patch}`).sort(),
    // fake fixes the static pipeline alone would have applied (declared gaps) that the proof gate refuses: what the gate adds
    gapsClosedByProof: unsafe.filter((r) => r.staticOk && r.reproducer !== 'none' && !r.proofVerified).map((r) => `${r.case}/${r.patch}`).sort(),
    gapsStillOpen: unsafe.filter((r) => r.staticOk && r.reproducer === 'none').map((r) => `${r.case}/${r.patch}`).sort(),
    safeApplied: safe.filter((r) => r.applied).map((r) => `${r.case}/${r.patch}`).sort(),
    safeRefused: Object.fromEntries([...new Set(safe.filter((r) => !r.applied).map((r) => r.refusedBy))].sort().map((k) => [k, safe.filter((r) => !r.applied && r.refusedBy === k).map((r) => `${r.case}/${r.patch}`).sort()])),
    unsafeRefusedBy: Object.fromEntries([...new Set(unsafe.filter((r) => !r.applied).map((r) => r.refusedBy))].sort().map((k) => [k, unsafe.filter((r) => !r.applied && r.refusedBy === k).length])),
    unscored,
  };
}

export function decide(base, now) {
  const problems = []; const j = JSON.stringify;
  const newUnsafe = now.unsafeApplied.filter((x) => !base.unsafeApplied.includes(x));
  if (newUnsafe.length) problems.push(`NEW unsafe fixes applied by the proof gate: ${newUnsafe.join(', ')}`);
  const reopened = base.gapsClosedByProof.filter((x) => !now.gapsClosedByProof.includes(x));
  if (reopened.length) problems.push(`gaps the proof gate used to close and no longer does: ${reopened.join(', ')}`);
  if (j(now.gapsStillOpen) !== j(base.gapsStillOpen)) problems.push(`the gaps the gate cannot see (no reproducer) changed: ${j(base.gapsStillOpen)} -> ${j(now.gapsStillOpen)}`);
  if (now.unsafeApplied.length) problems.push(`the proof gate applied ${now.unsafeApplied.length} unsafe fix(es): ${now.unsafeApplied.join(', ')}`);
  const lost = base.safeApplied.filter((x) => !now.safeApplied.includes(x));
  if (lost.length) problems.push(`safe fixes the gate used to apply and now refuses: ${lost.join(', ')}`);
  const gained = now.safeApplied.filter((x) => !base.safeApplied.includes(x));
  if (gained.length) problems.push(`safe fixes now applied that the baseline did not record (re-baseline deliberately): ${gained.join(', ')}`);
  if (j(now.denominators) !== j(base.denominators)) problems.push(`corpus size changed ${j(base.denominators)} -> ${j(now.denominators)}`);
  if (j(now.safeRefused) !== j(base.safeRefused)) problems.push(`the set of refused safe fixes changed: ${j(base.safeRefused)} -> ${j(now.safeRefused)}`);
  if (j(now.unscored) !== j(base.unscored)) problems.push(`unscored set changed: ${j(base.unscored)} -> ${j(now.unscored)}`);
  return problems;
}

async function main() {
  const a = process.argv.slice(2);
  const res = await runProofGate();
  const s = summarize(res);
  console.log(`host ${res.host.platform}/${res.host.backend}; patches ${s.denominators.patches} (safe ${s.denominators.safe}, unsafe ${s.denominators.unsafe}); with a reproducer ${s.denominators.withReproducer}`);
  console.log(`gaps closed by the proof gate: ${s.gapsClosedByProof.join(', ') || 'none'}; fake fixes the gate cannot see (no reproducer): ${s.gapsStillOpen.join(', ') || 'none'}`);
  console.log(`unsafe applied ${s.unsafeApplied.length}/${s.denominators.unsafe}; safe applied ${s.safeApplied.length}/${s.denominators.safe}; safe refused ${Object.values(s.safeRefused).flat().length}`);
  for (const [k, v] of Object.entries(s.safeRefused)) console.log(`  safe refused (${k}): ${v.join(', ')}`);
  if (a.includes('-v')) for (const r of res.rows) console.log(`  ${r.case}/${r.patch}: ${r.safe ? 'safe' : 'unsafe'} -> ${r.applied ? 'APPLIED' : 'refused'} ${r.refusedBy || ''} [${r.reproducer}]`);
  if (a.includes('--update-baseline')) { fs.writeFileSync(BASELINE, JSON.stringify(s, null, 2) + '\n'); console.log('baseline written'); return 0; }
  if (a.includes('--check')) {
    if (!fs.existsSync(BASELINE)) { console.error('no baseline: run --update-baseline'); return 1; }
    const problems = decide(JSON.parse(fs.readFileSync(BASELINE, 'utf8')), s);
    if (problems.length) { for (const p of problems) console.error(`FAIL ${p}`); return 1; }
    console.log('fix proof gate: matches baseline');
  }
  return s.unsafeApplied.length ? 1 : 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main().then((c) => process.exit(c), (e) => { console.error(e); process.exit(2); });
