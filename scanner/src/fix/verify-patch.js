// The one verifier every patch route calls (E3-03).
//
// Routes used to call verifyFix themselves, with different inputs (only verify_fix looked up the exploit PoC; one branch swapped the
// verifier when an env flag was set), and each shaped the result its own way. verifyPatch runs verifyFix ONCE with one set of inputs and
// returns the raw verdict beside the canonical patch-level record, so identical patch and settings give the same record id on every route.
//
// Route and mode are NOT part of the record id (see FIX_RECORD_ID_FIELDS): they say who asked, not what was established.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { verifyFix } from '../posture/fix-verify.js';
import { verifyLastScan } from '../posture/integrity.js';
import { stateDir } from '../posture/state-dir.js';
import { recordFromVerifyFix } from './verification-adapters.js';
import { replayExploit } from './exploit-replay.js';
import { checkFootprint } from './footprint.js';
import { runTestsOnPatchedCopy } from './test-commands.js';
import { legacyViewOf } from './verification-record.js';

const REQUIRED_LEGS = Object.freeze(['securityAfter', 'newFindingDelta', 'behaviorPreservation', 'behaviorTests']);

function readOriginal(scanRoot) {
  return (rel) => { try { return fs.readFileSync(path.join(scanRoot, rel), 'utf8'); } catch { return null; } };
}

/** The scan, only when its signature verifies: a stored PoC is code that will be run, so an unsigned scan supplies none. */
function readSignedScan(scanRoot) {
  const file = path.join(stateDir(scanRoot), 'last-scan.json');
  const body = fs.readFileSync(file, 'utf8');
  return verifyLastScan(body, `${file}.sig`) === true ? JSON.parse(body) : null;
}

function lookupFinding(scanRoot, stableId, readScan) {
  try {
    const scan = (readScan || readSignedScan)(scanRoot);
    return (scan?.findings || []).find((f) => f.stableId === stableId) || null;
  } catch { return null; }
}

/**
 * @param {{scanRoot:string, finding:{id?:string,stableId:string}, files:Record<string,string>, route:string, mode?:'preview'|'verify'|'apply',
 *   fixMeta?:object, poc?:object|null, readScan?:(root:string)=>object|null, verify?:Function, extra?:object}} o
 * @returns {Promise<{verdict:object, fixVerification:object, canonical:object}>}
 */
export async function verifyPatch(o) {
  const { scanRoot, finding, files, route, mode = 'verify', fixMeta, readScan, extra } = o;
  const run = o.verify || verifyFix;
  const stored = lookupFinding(scanRoot, finding.stableId, readScan);
  // One PoC rule for every route: the stored one for this finding, unless the caller supplied its own.
  const poc = o.poc !== undefined ? o.poc : (stored?.poc?.code ? { ...stored.poc, finding: stored } : null);
  // An explicit local reproducer turns the replay on for every route alike; without one the leg is not_run and says so.
  const replay = o.reproducer ? await replayExploit({ scanRoot, reproducer: o.reproducer, files, attempts: o.replayAttempts, timeoutMs: o.replayTimeoutMs, attemptFn: o.attemptFn }) : null;
  // The tests run on a copy WITH the patch applied. A suite that was already red says nothing about the patch, so it is reported as such.
  const runTests = () => {
    const t = runTestsOnPatchedCopy({ scanRoot, files, command: o.testCommand || fixMeta?.testCommand, timeoutMs: o.testTimeoutMs });
    return t.preExistingFailure ? { ...t, status: 'skipped', passed: null, skipped: true, reason: 'suite-already-failing-before-the-patch' } : t;
  };
  const read = readOriginal(scanRoot);
  const footprint = checkFootprint({ before: Object.fromEntries(Object.keys(files).map((r) => [r, read(r)])), after: files, cwe: stored?.cwe || o.cwe || null, intentionalRemoval: fixMeta?.intentionalRemoval || null });
  let verdict = await run({ scanRoot, originalFindingStableId: finding.stableId, files, fixMeta, runTests, ...(poc ? { poc } : {}), ...(extra || {}) });
  // The finding disappearing is not enough: a patch that removed the feature is rejected here, for every route at once.
  if (footprint.status === 'failed' && verdict.ok) verdict = { ...verdict, ok: false, rejectedBy: 'behavior-preservation', summary: `${footprint.reason}\n${verdict.summary || ''}`.trim() };
  const fixVerification = recordFromVerifyFix(verdict, {
    finding: { id: finding.id ?? stored?.id ?? finding.stableId, stableId: finding.stableId },
    files, route, mode, findingPresent: !!(stored || finding.present), preFiles: readOriginal(scanRoot),
    requiredLegs: replay ? [...REQUIRED_LEGS, 'exploitProofAfter'] : REQUIRED_LEGS, replay, footprint,
  });
  return { verdict, fixVerification, canonical: legacyViewOf(fixVerification), replay, footprint };
}

/** The additive fields every route puts on its result. Existing fields are untouched. */
export function additiveFields(fixVerification) {
  return {
    fixVerification,
    fixCompleteness: fixVerification.fixCompleteness,
    verifiedFull: fixVerification.verifiedFull,
    degradedLegs: fixVerification.degradedLegs,
  };
}
