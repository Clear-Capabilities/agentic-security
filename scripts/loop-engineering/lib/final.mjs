// Final verification (LOOP-004.AC02). The last phase re-runs EVERY registered
// criterion and the release gates against one source digest. Completion is a
// property of that single, stable observation, not of the sum of earlier ones:
//
//   - any skipped test, unsupported required backend, unavailable evidence, failed
//     criterion or failed/missing gate prevents completion;
//   - the whole-tree digest must be identical before the phase, after every
//     verification and after the last gate (a watched file that changed anywhere
//     in between is named);
//   - the verdict is a signed record bound to the acceptance hash, the PRD, the
//     profile and that digest, so a later edit to any of them un-completes it.
import { createHmac, createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { canonicalJson, atomicWriteJson, readJson, nowIso } from './util.mjs';

export const FINAL_SCHEMA = 1;

/**
 * Pure decision. Input:
 *   requirements: [{ id, result, evidenceId, skipped, blockerType, treeDigest }]  (one per manifest requirement)
 *   expectedRequirements: [ids]; gates: [{ id, ok, exitCode }]; expectedGates: [ids]
 *   treeDigests: { before, afterEach: [digest], after }
 * -> { verdict: 'all-required-criteria-verified' | 'incomplete', stable, unmet: [{ kind, id, reason }] }
 */
export function evaluateFinal({ requirements, expectedRequirements, gates, expectedGates, treeDigests }) {
  const unmet = [];
  const byId = new Map(requirements.map((r) => [r.id, r]));
  for (const id of expectedRequirements) {
    const r = byId.get(id);
    if (!r) { unmet.push({ kind: 'evidence-unavailable', id, reason: 'no evidence was issued for this requirement in the final phase' }); continue; }
    if (r.blockerType) unmet.push({ kind: 'unsupported-backend', id, reason: `required backend unavailable (${r.blockerType}); an unsupported backend is never a pass` });
    else if (r.skipped > 0) unmet.push({ kind: 'skip', id, reason: `${r.skipped} test(s) skipped; a skipped required test counts as failed` });
    else if (r.result !== 'pass') unmet.push({ kind: 'requirement', id, reason: `final-phase verification result ${r.result}` });
  }
  const gById = new Map(gates.map((g) => [g.id, g]));
  for (const id of expectedGates) {
    const g = gById.get(id);
    if (!g) unmet.push({ kind: 'gate', id, reason: 'release gate did not run' });
    else if (!g.ok) unmet.push({ kind: 'gate', id, reason: `release gate failed (exit ${g.exitCode ?? 'n/a'})` });
  }
  const { before, afterEach = [], after } = treeDigests;
  const stable = !!before && before === after && afterEach.every((d) => d === before);
  if (!stable) unmet.push({ kind: 'tree-unstable', id: 'tree', reason: 'the source digest changed during the final phase (a watched file changed); completion requires one stable digest' });
  return { verdict: unmet.length === 0 ? 'all-required-criteria-verified' : 'incomplete', stable, unmet };
}

const signFinal = (rec, key) => createHmac('sha256', key).update(canonicalJson({ ...rec, signature: undefined })).digest('hex');

export function writeFinalEvidence(file, rec, key) {
  const full = { schemaVersion: FINAL_SCHEMA, ...rec, createdAt: nowIso() };
  full.signature = signFinal(full, key);
  atomicWriteJson(file, full);
  return full;
}

/**
 * Is there a final record that still describes THIS tree? -> { required, present, valid, ok, reasons }.
 * `required` is a property of the frozen manifest; a manifest without
 * finalVerification keeps the previous behaviour (the release requirement is the gate).
 */
export function assessFinal({ file, manifest, tree, key }) {
  const closure = manifest.finalVerification?.closure || null;
  const required = !!manifest.finalVerification?.required;
  if (!required) return { required: false, present: false, valid: true, ok: true, reasons: [] };
  const rec = readJson(file, null);
  if (!rec) return { required, present: false, valid: false, ok: false, reasons: ['no final verification has run'] };
  const reasons = [];
  if (typeof rec.signature !== 'string' || signFinal(rec, key) !== rec.signature) reasons.push('final record signature is invalid (forged or edited)');
  if (rec.acceptanceHash !== manifest.acceptanceHash) reasons.push('acceptance definition changed since the final verification');
  if (rec.prdSha256 !== manifest.prd.sha256) reasons.push('PRD changed since the final verification');
  if (rec.profileSha256 !== manifest.profile?.sha256) reasons.push('profile changed since the final verification');
  if (rec.verdict !== 'all-required-criteria-verified') reasons.push(`final verdict was ${rec.verdict}`);
  if (rec.stable !== true) reasons.push('final verification did not observe a stable tree');
  if (closure) {
    // A closure profile accepts only a record that says it closed: every expected requirement and criterion, with the evidence files it
    // cites unchanged since issuance.
    const c = rec.closure;
    if (!c || c.closed !== true) reasons.push('the final record is not a closure record (closure.closed is not true)');
    else {
      if (c.counts?.requirements?.verified !== closure.expect.requirements || c.counts?.criteria?.verified !== closure.expect.criteria) reasons.push(`closure counts ${c.counts?.requirements?.verified}/${closure.expect.requirements} requirements and ${c.counts?.criteria?.verified}/${closure.expect.criteria} criteria`);
      if (c.open?.length) reasons.push(`${c.open.length} item(s) remain open`);
      for (const r of c.receipts || []) {
        let now = null;
        try { now = createHash('sha256').update(readFileSync(r.file)).digest('hex'); } catch { /* unreadable counts as changed */ }
        if (now !== r.sha256) { reasons.push(`evidence file for ${r.id} changed since closure was issued`); break; }
      }
    }
  }
  if (reasons.length === 0 && tree.wholeTree().digest !== rec.treeDigest) reasons.push('the source tree changed since the final verification');
  return { required, present: true, valid: reasons.every((r) => !/signature/.test(r)), ok: reasons.length === 0, reasons, recordedAt: rec.createdAt, treeDigest: rec.treeDigest };
}
