// PRD Epic 4 — the autonomous loop.
//
// Every stage already existed as a separate command. What did not exist was the
// chain: scan → prove → validate → fix → RE-VERIFY, with state between stages
// and a gate before anything is written. This module is that chain and nothing
// else — it owns no analysis, and each stage is injected, so the orchestration
// can be tested without running an engine or calling a model.
//
// THE RULE THAT MAKES IT SAFE TO AUTOMATE: a fix is applied only if the PoC
// that proved the bug no longer fires AND the test suite still passes. That is
// `VERIFIED_FIXED`. Anything else is `NEEDS_REVIEW` and is NOT written. A loop
// that applies patches on the strength of "the scanner stopped complaining"
// automates the failure mode where a cosmetic edit silences a detector while
// the vulnerability remains — the re-scan proves the DETECTOR went quiet, and
// only re-running the exploit proves the hole is shut.
//
// GATES ARE ON BY DEFAULT. `apply` requires an explicit opt-in. Autonomy plus
// write access is the combination that turns a bad patch into a bad commit, and
// the default must be the one that cannot.
//
// RESUMABLE, AND HONEST ABOUT WHAT IT SKIPPED. Each stage records its outcome
// per finding; a resumed run replays completed stages from state rather than
// re-running them. A stage that was skipped is reported as skipped — never
// folded into "nothing to do", which is how an interrupted run reads as a clean
// one.

import fs from 'node:fs';
import path from 'node:path';

const SCHEMA = 'agentic-security/autopilot@1';

export const STAGES = Object.freeze(['scan', 'prove', 'validate', 'fix', 'reverify']);

// Outcomes a finding can end a run in. Closed set: a new outcome must be
// declared here, because the report groups on it and an unknown value would
// silently vanish from every count.
export const OUTCOMES = Object.freeze([
  'VERIFIED_FIXED',   // patch applied (or ready): PoC no longer fires, tests pass
  'NEEDS_REVIEW',     // a fix exists but did not re-verify — NOT applied
  'NO_FIX',           // nothing was synthesised
  'UNPROVEN',         // no PoC fired, so no fix was attempted at this tier
]);

export function loadAutopilotState(stateFile) {
  try {
    const j = JSON.parse(fs.readFileSync(stateFile, 'utf8'));
    if (j && j.schema === SCHEMA) return j;
  } catch { /* absent -> clean */ }
  return { schema: SCHEMA, stages: {}, findings: {} };
}

function _save(stateFile, state) {
  if (!stateFile) return;
  try {
    fs.mkdirSync(path.dirname(stateFile), { recursive: true });
    fs.writeFileSync(stateFile, JSON.stringify(state, null, 2));
  } catch { /* state is an optimisation; losing it must not fail a run */ }
}

/**
 * Run the loop.
 *
 * Every stage is injected. `apply` defaults to false: the loop produces
 * VERIFIED_FIXED patches and does not write them unless told to.
 *
 * @param {object} stages
 *   scan()                      -> { findings: [] }
 *   prove(finding)              -> { proofTier, proofEvidence, poc }
 *   validate(finding)           -> { verdict: 'upheld'|'refuted'|'undecided' }
 *   synthesizeFix(finding)      -> { patch: {file: content} } | null
 *   verifyFix(finding, patch)   -> { ok, pocStillFires, testsPass, reason }
 *   applyFix(finding, patch)    -> void   (only called when apply === true)
 */
export async function runAutopilot({
  stages = {}, stateFile = null, resume = true, apply = false,
  onStage = () => {}, severities = ['critical', 'high'], maxFindings = Infinity,
} = {}) {
  const required = ['scan'];
  for (const r of required) {
    if (typeof stages[r] !== 'function') return { ok: false, reason: `no ${r} stage supplied` };
  }
  const state = resume && stateFile ? loadAutopilotState(stateFile) : { schema: SCHEMA, stages: {}, findings: {} };
  const skipped = [];

  // ── scan ────────────────────────────────────────────────────────────────
  let findings;
  if (resume && state.stages.scan) {
    findings = state.stages.scan.findings || [];
    skipped.push('scan');
  } else {
    const r = await stages.scan();
    findings = r?.findings || [];
    state.stages.scan = { findings };
    _save(stateFile, state);
  }
  onStage({ stage: 'scan', count: findings.length });

  // Only the severities asked for reach the expensive stages. Reported, so a
  // reader can see what was in scope rather than assuming everything was.
  const all = findings.filter(f => severities.includes(String(f.severity || '').toLowerCase()));
  const outOfScope = findings.length - all.length;
  // Every stage costs a sandboxed process and possibly a test-suite run, so the
  // count is bounded. Reported, never silent: findings past the cap were NOT
  // examined, and a run that quietly stopped at N would read as a run that
  // found only N.
  const inScope = all.slice(0, Number.isFinite(maxFindings) ? Math.max(0, maxFindings) : all.length);
  const capped = all.length - inScope.length;

  const results = [];
  for (const f of inScope) {
    const key = f.stableId || `${f.file}:${f.line}:${f.vuln}`;
    const prior = resume ? state.findings[key] : null;
    // A cached VERIFIED_FIXED whose patch was gated (not written) on a prior
    // apply:false run is not a terminal outcome once the caller asks for
    // apply:true — replaying it verbatim would silently never call
    // applyFix on the exact two-step workflow (preview, then --apply) this
    // gate exists to support. Everything else cached IS terminal and is
    // replayed as before.
    const gatedOnlyByApply = prior?.outcome === 'VERIFIED_FIXED' && prior.applied !== true && apply === true;
    if (prior?.outcome && !gatedOnlyByApply) { results.push(prior); continue; }

    const rec = { key, file: f.file, line: f.line, vuln: f.vuln, severity: f.severity };

    // ── prove ─────────────────────────────────────────────────────────────
    let proved = null;
    if (typeof stages.prove === 'function') {
      proved = await stages.prove(f).catch(e => ({ error: String(e?.message || e) }));
      rec.proofTier = proved?.proofTier || null;
    }
    const isProven = rec.proofTier === 'execution-proven';

    // ── validate ──────────────────────────────────────────────────────────
    if (typeof stages.validate === 'function') {
      const v = await stages.validate(f).catch(() => null);
      rec.validation = v?.verdict || null;
      // A refuted finding is NOT dropped — same recall-preserving rule the rest
      // of the engine follows. It is recorded and skipped for fixing.
      if (rec.validation === 'refuted') {
        rec.outcome = 'NEEDS_REVIEW';
        rec.reason = 'an independent verifier refuted this finding; not fixed automatically';
        results.push(rec); state.findings[key] = rec; _save(stateFile, state);
        onStage({ stage: 'validate', key, verdict: 'refuted' });
        continue;
      }
    }

    // Fixing is gated on proof at this tier. An unproven finding may still be
    // real — it is reported UNPROVEN, not dismissed.
    if (!isProven) {
      rec.outcome = 'UNPROVEN';
      rec.reason = proved?.proofEvidence?.reason || 'no proof-of-concept demonstrated this finding';
      results.push(rec); state.findings[key] = rec; _save(stateFile, state);
      continue;
    }

    // ── fix ───────────────────────────────────────────────────────────────
    let patch = null;
    if (typeof stages.synthesizeFix === 'function') {
      patch = await stages.synthesizeFix(f).catch(() => null);
    }
    if (!patch || !patch.patch) {
      rec.outcome = 'NO_FIX';
      rec.reason = 'no patch was synthesised';
      results.push(rec); state.findings[key] = rec; _save(stateFile, state);
      continue;
    }

    // ── re-verify ─────────────────────────────────────────────────────────
    // The gate. Without a verifier we cannot claim VERIFIED_FIXED, so we do
    // not — an unverifiable patch is NEEDS_REVIEW even if it looks right.
    if (typeof stages.verifyFix !== 'function') {
      rec.outcome = 'NEEDS_REVIEW';
      rec.reason = 'no verifyFix stage supplied — a patch that cannot be re-verified is never applied';
      results.push(rec); state.findings[key] = rec; _save(stateFile, state);
      continue;
    }
    const v = await stages.verifyFix(f, patch).catch(e => ({ ok: false, reason: String(e?.message || e) }));
    rec.pocStillFires = v?.pocStillFires === true;
    rec.testsPass = v?.testsPass !== false;

    if (v?.ok && !rec.pocStillFires && rec.testsPass) {
      rec.outcome = 'VERIFIED_FIXED';
      if (apply && typeof stages.applyFix === 'function') {
        try { await stages.applyFix(f, patch); rec.applied = true; }
        catch (e) { rec.applied = false; rec.outcome = 'NEEDS_REVIEW'; rec.reason = `apply failed: ${e.message}`; }
      } else {
        rec.applied = false;
        rec.reason = apply ? 'no applyFix stage supplied' : 'gates on: patch is ready but was not written';
      }
    } else {
      rec.outcome = 'NEEDS_REVIEW';
      rec.reason = rec.pocStillFires
        ? 'the proof-of-concept still fires against the patch — the vulnerability is not fixed'
        : (!rec.testsPass ? 'the project test suite fails with this patch'
          : (v?.reason || 'the patch did not re-verify'));
    }
    results.push(rec);
    state.findings[key] = rec;
    _save(stateFile, state);
    onStage({ stage: 'reverify', key, outcome: rec.outcome });
  }

  return { ok: true, results, skipped, outOfScope, capped, summary: summarizeAutopilot(results, outOfScope, capped) };
}

export function summarizeAutopilot(results, outOfScope = 0, capped = 0) {
  const byOutcome = Object.fromEntries(OUTCOMES.map(o => [o, 0]));
  for (const r of results) if (r.outcome in byOutcome) byOutcome[r.outcome]++;
  return {
    considered: results.length,
    outOfScope,
    capped,
    byOutcome,
    applied: results.filter(r => r.applied).length,
  };
}

/** One line. Leads with what was NOT fixed, because that is the actionable part. */
export function renderAutopilotSummary(s) {
  if (!s) return null;
  const b = s.byOutcome;
  const bits = [`${s.considered} finding(s) in scope`];
  if (b.VERIFIED_FIXED) bits.push(`${b.VERIFIED_FIXED} VERIFIED_FIXED (${s.applied} applied)`);
  if (b.NEEDS_REVIEW) bits.push(`${b.NEEDS_REVIEW} NEEDS_REVIEW — not applied`);
  if (b.NO_FIX) bits.push(`${b.NO_FIX} with no patch`);
  if (b.UNPROVEN) bits.push(`${b.UNPROVEN} unproven (not dismissed — no PoC fired)`);
  if (s.outOfScope) bits.push(`${s.outOfScope} below the severity floor and not considered`);
  if (s.capped) bits.push(`${s.capped} in scope but NOT examined (per-run cap) — unexamined, not clean`);
  return bits.join('; ') + '.';
}

export const _internals = { SCHEMA };
