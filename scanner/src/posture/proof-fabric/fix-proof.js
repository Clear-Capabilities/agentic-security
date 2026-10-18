// Verified remediation, extended with exploit replay. This EXTENDS the fix-verify vocabulary (`verifiedFull`,
// `degradedLegs`); it does not define a competing meaning of "verified".
//
//   1. pre-patch: the original exploit must be EXPLOIT_CONFIRMED (3/3 + independent replay) on the unpatched code;
//   2. the candidate patch is overlaid on the imported sources and the SAME exploit is replayed;
//   3. the patched replay must COMPLETE in every attempt and the oracle must not fire in any: BLOCKED.
//      An attempt that did not complete (timeout, build failure, no environment) is inconclusive, never "blocked";
//   4. static legs (re-scan, lint, tests, honesty) come from `verifyFix`, passed in so they are not re-implemented;
//   5. FIX_VERIFIED only when 1-4 hold and the static verification had no degraded leg.
import { advance } from './states.js';
import { proveFinding } from './orchestrator.js';
import { runAttempt } from './runner.js';
import { reproducerDigest, sha256, canonicalize } from './reproducer.js';

export async function verifyFixWithProof({ finding, reproducer, files, scanRoot, revision = null, policy = {}, staticVerification = null, siblings = null, siblingSearchTruncated = [], signal, deps = {} } = {}) {
  const t0 = Date.now();
  const attemptFn = deps.attemptFn ?? runAttempt;
  const patchHash = sha256(canonicalize(files || {}));
  const legs = { prePatch: null, postPatch: null, regression: staticVerification ? { ok: !!staticVerification.ok, verifiedFull: !!staticVerification.verifiedFull } : { status: 'not-run' }, rescan: staticVerification?.rescan ?? { status: 'not-run' } };
  const out = (extra) => ({ schema: 'agentic-security/fix-proof', version: 1, findingId: finding?.stableId ?? finding?.id ?? null, patchHash, reproducerDigest: reproducerDigest(reproducer), legs, durationMs: Date.now() - t0, ...extra });

  const pre = await proveFinding({ finding, revision, reproducer, policy, signal, deps, sourceRoot: scanRoot });
  legs.prePatch = { state: pre.state, outcome: pre.outcome, completeness: pre.completeness };
  if (pre.state !== 'EXPLOIT_CONFIRMED') {
    return out({ state: pre.state, verified: false, completeness: 'INCOMPLETE', incompleteStep: 'pre-patch-exploit', reason: `the original exploit was not confirmed before the patch (${pre.outcome}); a fix cannot be proven against an exploit that does not reproduce` });
  }

  const attempts = Math.max(1, Math.min(10, policy.attempts ?? 3));
  const results = [];
  for (let i = 0; i < attempts; i++) {
    if (signal?.aborted) break;
    results.push(await attemptFn(structuredClone(reproducer), { limits: { timeoutMs: policy.timeoutMs }, signal, sourceRoot: scanRoot, overlay: files, requireContainer: policy.requireContainer, force: policy.force }));
  }
  const completed = results.filter((r) => r.status === 'completed' && !r.oracle?.inconclusive);
  const fired = completed.filter((r) => r.oracle?.fired).length;
  legs.postPatch = { attempts: results.length, completed: completed.length, exploitSucceeded: fired, statuses: results.map((r) => r.status) };

  if (fired > 0) return out({ state: 'EXPLOIT_CONFIRMED', verified: false, completeness: 'FULL', incompleteStep: 'post-patch-exploit', reason: 'the exploit still succeeds against the patched code' });
  if (completed.length < results.length || results.length === 0) {
    return out({ state: 'EXPLOIT_CONFIRMED', verified: false, completeness: 'INCOMPLETE', incompleteStep: 'post-patch-replay', reason: 'the patched replay did not complete in every attempt, so the patch is not shown to block the exploit' });
  }
  let state = advance('EXPLOIT_CONFIRMED', 'FIX_REPLAY_BLOCKED').state;

  const degraded = [];
  if (!staticVerification) degraded.push('static-verification-not-run');
  else {
    if (!staticVerification.ok) return out({ state, verified: false, completeness: 'FULL', incompleteStep: 'static-verification', reason: `exploit blocked, but static verification failed: ${staticVerification.rescan?.reason || 'a leg failed'}` });
    for (const d of staticVerification.degradedLegs || []) degraded.push(d);
  }
  const lowAssurance = pre.environment?.assurance === 'lower';
  if (lowAssurance) degraded.push('lower-assurance-local-confinement');
  const siblingCount = Array.isArray(siblings) ? siblings.length : null;
  if (siblingCount === null) degraded.push('sibling-search-not-run');
  else if (siblingCount > 0) degraded.push(`sibling-exposures:${siblingCount}`);
  if (siblingCount !== null && siblingSearchTruncated?.length) degraded.push('sibling-search-incomplete');

  const full = degraded.length === 0;
  // Same split as fix-verify: `ok` (nothing that ran failed) earns FIX_VERIFIED; `completeness` says whether anything was skipped.
  if (staticVerification && staticVerification.ok) state = advance(state, 'FIX_VERIFIED').state;
  return out({ state, verified: state === 'FIX_VERIFIED', completeness: full ? 'FULL' : 'DEGRADED', degradedLegs: degraded, siblings: siblings ?? null });
}

export function formatFixProof(r) {
  const L = r.legs || {};
  return [
    `Pre-patch exploit: ${L.prePatch?.state === 'EXPLOIT_CONFIRMED' ? 'PASS' : 'NOT CONFIRMED'}`,
    `Post-patch exploit: ${!L.postPatch ? 'NOT RUN' : L.postPatch.exploitSucceeded > 0 ? 'STILL SUCCEEDS' : L.postPatch.completed === L.postPatch.attempts ? 'BLOCKED' : 'INCONCLUSIVE'}`,
    `Regression tests: ${L.regression?.status === 'not-run' ? 'not run' : L.regression?.verifiedFull ? 'PASS' : L.regression?.ok ? 'PASS (degraded)' : 'FAIL'}`,
    `Security rescan: ${L.rescan?.ok === true ? 'PASS' : L.rescan?.status === 'not-run' ? 'not run' : 'FAIL'}`,
    `Completeness: ${r.completeness}${r.degradedLegs?.length ? ` (${r.degradedLegs.join('; ')})` : ''}`,
    '',
    `Evidence: ${r.state}${r.verified ? '' : ` (not verified: ${r.reason || r.incompleteStep || 'degraded'})`}`,
  ].join('\n');
}
