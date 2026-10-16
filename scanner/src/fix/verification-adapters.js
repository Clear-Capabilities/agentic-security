// Adapters from the results the existing routes already produce to the patch-level verification record (E3-02).
//
// An adapter only RELAYS: it maps what a route observed onto legs, and anything the route did not observe becomes `not_run` with the
// reason. It never upgrades a result. In particular a test run that happened before the patch was written (verifyFix sets
// `testedPrePatch`) is recorded as `not_run` for the patched tree, not as passed.
import { createHash } from 'node:crypto';
import { digestOf } from '../posture/assurance/identity.js';
import { buildFixVerificationRecord, evidenceItem, leg } from './verification-record.js';

const sha256Hex = (s) => createHash('sha256').update(s).digest('hex');

/** Digest of a patch: the files it writes, by path and content digest. Independent of key order. */
export function patchHashOf(files) {
  const rows = Object.keys(files || {}).sort().map((p) => [p, sha256Hex(String(files[p]))]);
  return digestOf({ files: rows });
}

/** Digest of the files as they were before the patch, for the paths the patch touches. `read(path)` returns the text or null. */
export function treeHashOf(paths, read) {
  const rows = [...paths].sort().map((p) => { const t = read(p); return [p, t === null || t === undefined ? null : sha256Hex(String(t))]; });
  return digestOf({ files: rows });
}

const asEvidence = (kind, value, note = null) => evidenceItem({ kind, mediaType: 'application/json', sha256: digestOf(value).slice('sha256:'.length), note });

/**
 * @param {object} v        the object verifyFix returns
 * @param {object} ctx      { finding:{id,stableId}, files, route, mode, preCommit, preFiles(read), tools, requiredLegs, findingPresent }
 */
export function recordFromVerifyFix(v, ctx) {
  const evidence = [];
  const add = (kind, value, note) => { const e = asEvidence(kind, value, note); if (!evidence.some((x) => x.id === e.id)) evidence.push(e); return e.id; };
  const failures = [];

  const rescanId = v.rescan ? add('rescan-result', v.rescan, 'verifyFix rescan leg') : null;
  const securityAfter = !v.rescan ? leg('not_run', { reason: 'the route returned no rescan result' })
    : v.rescan.ok ? leg('passed', { evidenceIds: [rescanId] }) : leg('failed', { evidenceIds: [rescanId], reason: `the original finding is still present (${v.rescan.reason})` });
  const introduced = v.rescan?.introduced || [];
  const newFindingDelta = !v.rescan ? leg('not_run', { reason: 'the route returned no rescan result' })
    : introduced.length ? leg('failed', { evidenceIds: [rescanId], reason: `${introduced.length} finding(s) introduced by the patch` }) : leg('passed', { evidenceIds: [rescanId] });

  let lint;
  if (!v.lint) lint = leg('not_run', { reason: 'the route returned no lint result' });
  else if (v.lint.runner === 'none') lint = leg('not_applicable', { reason: 'no linter is configured for this project' });
  else lint = v.lint.ok ? leg('passed', { evidenceIds: [add('lint-result', v.lint)] }) : leg('failed', { evidenceIds: [add('lint-result', v.lint)], reason: 'the linter reported errors on the patched files' });

  let behaviorTests;
  if (!v.tests) behaviorTests = leg('not_run', { reason: 'the route returned no test result' });
  else if (v.tests.skipped) behaviorTests = leg('not_run', { reason: `tests were skipped (${v.tests.reason || 'no reason recorded'})` });
  else if (v.tests.preExistingFailure || v.tests.reason === 'suite-already-failing-before-the-patch') behaviorTests = leg('blocked', { reason: 'the project test suite was already failing before the patch, so it cannot show the patch preserved behaviour' });
  else if (v.testedPrePatch) behaviorTests = leg('not_run', { evidenceIds: [], reason: 'the tests ran on the tree BEFORE the patch was written, so they say nothing about the patch' });
  else behaviorTests = v.tests.passed ? leg('passed', { evidenceIds: [add('test-result', v.tests)] }) : leg('failed', { evidenceIds: [add('test-result', v.tests)], reason: 'the project tests failed on the patched tree' });

  const poc = v.poc?.status;
  const pocId = v.poc && poc !== 'not-requested' ? add('exploit-replay', v.poc) : null;
  const replay = ctx.replay || null;
  const replayId = replay ? add('exploit-replay', replay, 'pre/post replay of the same reproducer') : null;
  const replayLeg = (status, ok, bad) => status === 'passed' ? leg('passed', { evidenceIds: [replayId] }) : status === 'failed' ? leg('failed', { evidenceIds: [replayId], reason: bad }) : leg('not_run', { reason: replay.reason || ok });
  const exploitProofAfter = replay ? replayLeg(replay.afterStatus, 'the replay did not run', replay.reason) : !v.poc || poc === 'not-requested' ? leg('not_run', { reason: 'no exploit replay was requested by this route' })
    : poc === 'no-longer-proven' ? leg('passed', { evidenceIds: [pocId] })
    : poc === 'still-exploitable' ? leg('failed', { evidenceIds: [pocId], reason: 'the exploit still works against the patched code' })
    : leg('not_run', { evidenceIds: [], reason: `the exploit replay was inconclusive (${v.poc.reason || 'no reason recorded'})` });
  const exploitProofBefore = replay ? replayLeg(replay.beforeStatus, 'the replay did not run', replay.reason) : !v.poc || poc === 'not-requested' ? leg('not_run', { reason: 'no exploit replay was requested by this route' })
    : poc === 'inconclusive' ? leg('not_run', { reason: 'the exploit could not be reproduced on the original code' })
    : leg('passed', { evidenceIds: [pocId] });

  const findingEv = ctx.findingPresent === true && ctx.finding ? add('finding', { id: ctx.finding.id, stableId: ctx.finding.stableId ?? null }, 'the finding in the signed scan') : null;
  const securityBefore = findingEv ? leg('passed', { evidenceIds: [findingEv] }) : leg('not_run', { reason: 'the finding was not shown to be present on the original code' });

  if (v.honesty && v.honesty.ok === false) failures.push({ leg: 'securityAfter', reason: 'the honesty gate refused the claimed fix quality' });

  const fp = ctx.footprint || null;
  const footprintLeg = !fp ? leg('not_run', { reason: 'this route does not check that intended functionality survived' })
    : fp.status === 'passed' ? leg('passed', { evidenceIds: [add('footprint', fp, 'sensitive operation kinds before and after the patch')] })
    : fp.status === 'failed' ? leg('failed', { evidenceIds: [add('footprint', fp, 'sensitive operation kinds before and after the patch')], reason: fp.reason })
    : leg('not_run', { reason: fp.reason });
  const files = ctx.files || {};
  return buildFixVerificationRecord({
    findingId: ctx.finding?.id ?? 'unknown', findingStableId: ctx.finding?.stableId, mode: ctx.mode || 'verify', route: ctx.route || 'verify-fix',
    preCommit: ctx.preCommit ?? null, preTreeHash: ctx.preFiles ? treeHashOf(Object.keys(files), ctx.preFiles) : null, postPatchHash: patchHashOf(files), patchHash: patchHashOf(files),
    affectedFiles: Object.keys(files),
    securityBefore, securityAfter, exploitProofBefore, exploitProofAfter, newFindingDelta, behaviorTests, lint,
    behaviorPreservation: footprintLeg,
    regressionTests: leg('not_run', { reason: 'this route runs a single test leg' }),
    typecheck: leg('not_run', { reason: 'this route does not run a type checker' }),
    dependencyChecks: leg('not_applicable', { reason: 'a source patch changes no dependency' }),
    requiredLegs: ctx.requiredLegs || ['securityAfter', 'newFindingDelta', 'behaviorTests'],
    failures, evidence, tools: ctx.tools || { engineVersion: null, verifier: 'verifyFix' },
    residualRisk: ctx.residualRisk,
    confidence: ctx.confidence || (replay?.executionProven ? { level: 'proven', policy: 'exploit-replay-v1', evidenceIds: [replayId] } : undefined),
    ...(ctx.timestamps ? { timestamps: ctx.timestamps } : {}),
  });
}
