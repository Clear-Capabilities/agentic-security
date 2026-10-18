// The unified finding view (PRD 7, requirement 8): FIND, PROVE, HUNT, FIX, VERIFY, DETECT in one place, assembled only from
// records that exist. A step with no record is shown as missing, not inferred from its neighbours; a tampered record is
// shown as such and not used.
import fs from 'node:fs';
import { statePath } from '../state-dir.js';
import { listProofs } from '../proof-fabric/store.js';
import { stateRank } from '../proof-fabric/states.js';
import { latestRecord, listRecords } from './store.js';

export function loadFindingFromLastScan(root, id) {
  try {
    const last = JSON.parse(fs.readFileSync(statePath(root, 'last-scan.json'), 'utf8'));
    return (last.findings || []).find((f) => f.id === id || f.stableId === id) ?? null;
  } catch { return null; }
}

const days = (w) => (w?.start && w?.end ? Math.max(1, Math.round((Date.parse(w.end) - Date.parse(w.start)) / 86400000)) : null);

export function buildLifecycleView(root, findingId) {
  const finding = loadFindingFromLastScan(root, findingId);
  const proofs = listProofs(root, findingId);
  const proofTampered = proofs.some((p) => p.tampered);
  const proof = proofs.find((p) => p.record && !p.tampered)?.record ?? null;
  // An earlier hunt that OBSERVED matches must not be hidden by a later hunt over different logs that did not.
  const hunts = listRecords(root, findingId, 'hunt').filter((r) => r.record && !r.tampered).map((r) => r.record);
  const hunt = hunts.find((h) => h.verdict === 'OBSERVED') ?? hunts[0] ?? null;
  const otherVerdicts = hunt ? [...new Set(hunts.filter((h) => h !== hunt).map((h) => h.verdict))] : [];
  const fix = latestRecord(root, findingId, 'fix')?.record ?? null;
  const det = latestRecord(root, findingId, 'detection')?.record ?? null;
  const tampered = [proofTampered ? 'proof' : null, ...['hunt', 'fix', 'detection'].map((k) => (listRecords(root, findingId, k).some((r) => r.tampered) ? k : null))].filter(Boolean);

  const confirmed = proof && stateRank(proof.state) >= stateRank('EXPLOIT_CONFIRMED');
  const steps = {
    FIND: finding ? { status: 'done', text: `${confirmed ? 'Confirmed vulnerability' : 'Candidate finding'}: ${finding.vuln ?? finding.id}${finding.file ? ` (${finding.file}${finding.line ? `:${finding.line}` : ''})` : ''}` } : { status: 'missing', text: 'Finding not found in the last scan' },
    PROVE: proof ? { status: confirmed ? 'done' : 'partial', text: confirmed ? `Exploit reproduced ${proof.attempts?.successes ?? 0}/${proof.attempts?.run ?? 0}, independent replay ${proof.independentReplay?.status ?? 'not run'}` : `Not confirmed (${proof.state})` } : { status: 'missing', text: 'No exploit proof' },
    HUNT: hunt ? { status: hunt.verdict === 'OBSERVED' || hunt.verdict === 'NOT_OBSERVED' ? 'done' : 'partial', text: `${days(hunt.window) ?? 'unknown'} day(s) of telemetry searched, ${hunt.verdict === 'OBSERVED' ? `${hunt.matches?.count ?? 0} matching event(s) observed` : hunt.verdict === 'NOT_OBSERVED' ? 'no matching events (not the same as not exploited)' : `${hunt.verdict.toLowerCase().replace('_', ' ')}`}${otherVerdicts.length ? `; other hunt(s): ${otherVerdicts.join(', ')}` : ''}` } : { status: 'missing', text: 'No historical hunt run' },
    FIX: fix ? { status: fix.verified ? 'done' : 'partial', text: fix.verified ? `${fix.completeness} verified remediation` : `Fix not verified: ${fix.reason ?? fix.incompleteStep ?? 'incomplete'}` } : { status: 'missing', text: 'No verified remediation recorded' },
    VERIFY: fix ? (fix.legs?.postPatch && fix.legs.postPatch.exploitSucceeded === 0 && fix.legs.postPatch.completed === fix.legs.postPatch.attempts ? { status: 'done', text: 'Original exploit blocked' } : { status: 'partial', text: 'Original exploit not shown to be blocked' }) : { status: 'missing', text: 'No post-fix replay recorded' },
    DETECT: det ? (det.validation?.status === 'VALIDATED' ? { status: 'done', text: `Recurrence rule enabled (${det.ir?.id})` } : { status: 'partial', text: `Detection ${det.ir?.id} generated but not validated (${det.validation?.status ?? 'no validation'}); not enabled` }) : { status: 'missing', text: 'No detection generated' },
  };
  return { findingId, steps, tampered, links: { detection: det ? { id: det.ir?.id, recordDigest: det.recordDigest, proofRecordDigest: det.proof?.recordDigest ?? null } : null, proofRecordDigest: proof?.recordDigest ?? null } };
}

export function formatLifecycleView(v) {
  const mark = { done: 'x', partial: '~', missing: ' ' };
  const lines = [`Finding ${v.findingId}`, ''];
  for (const [name, s] of Object.entries(v.steps)) lines.push(`[${mark[s.status]}] ${name.padEnd(7)} ${s.text}`);
  if (v.tampered.length) lines.push('', `WARNING: ${v.tampered.join(', ')} record(s) failed their integrity check and were not used.`);
  lines.push('', '[x] done   [~] partial or unconfirmed   [ ] missing');
  return lines.join('\n');
}
