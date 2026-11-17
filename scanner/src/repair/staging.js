// Staging and operational completion of a repair (verified-remediation PRD FR-16, AC-16.3, AC-16.6).
//
// stagingVerdict  the record's `environment` from three things that must agree: the artifact the repair was verified in (the record's
//                 `artifact-verified` digest), a statement of where that artifact runs (an operator-supplied deployment receipt, or a
//                 readback from a deployment connector the operator invoked), and the contract checks re-executed in this invocation on
//                 the image the statement names. `staging-verified` needs all three for a staging environment; `deployment-observed`
//                 needs a connector READBACK for production (a receipt file is a declaration, not an observation). A receipt alone,
//                 however signed, upgrades nothing (AC-16.6). A failed check on the staged artifact sets `unavailable` and records the
//                 failure while the source verification stays as it was (AC-16.3).
// observe         post-merge operational observations, kept apart from the verification: whether the verified patch is still on disk
//                 (present, reverted to the pre-patch content, or changed since), and operator reports of a reopen, a reversion or a
//                 regression. An observation never edits the disposition: a later regression is a new fact, not a rewritten past.
//
// Limits, stated: no deployment connector ships in this build (the readback is an injected interface); the contract checks run on the
// image's files inside the trust boundary, not against the live staging service; nothing is deployed, promoted or rolled back here.
import fs from 'node:fs';
import path from 'node:path';
import { digestOf } from '../posture/assurance/identity.js';
import { isPlainObject } from '../posture/assurance/schema-kit.js';

export const RECEIPT_SCHEMA = 'agentic-security/deployment-receipt';
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/** A deployment receipt: closed, versioned, bound to one artifact digest and one environment. Returns problems. */
export function validateReceipt(r) {
  const errs = [];
  if (!isPlainObject(r)) return ['the receipt must be a JSON object'];
  for (const k of Object.keys(r)) if (!['schema', 'schemaVersion', 'environment', 'artifactDigest', 'deployedAt', 'deployer', 'reference'].includes(k)) errs.push(`unknown receipt field '${k}'`);
  if (r.schema !== RECEIPT_SCHEMA) errs.push(`schema must be '${RECEIPT_SCHEMA}'`);
  if (r.schemaVersion !== '1.0.0') errs.push("schemaVersion must be '1.0.0'");
  if (!['staging', 'production'].includes(r.environment)) errs.push("environment must be 'staging' or 'production'");
  if (typeof r.artifactDigest !== 'string' || !DIGEST.test(r.artifactDigest)) errs.push('artifactDigest must be sha256:<64 hex>');
  if (typeof r.deployedAt !== 'string' || Number.isNaN(Date.parse(r.deployedAt))) errs.push('deployedAt must be a timestamp');
  if (typeof r.deployer !== 'string' || !r.deployer.trim() || r.deployer.length > 120) errs.push('deployer must name who deployed');
  if (r.reference !== undefined && (typeof r.reference !== 'string' || r.reference.length > 200)) errs.push('reference must be a short string');
  return errs;
}

/**
 * @param {{record:object, imageDigest?:string|null, receipt?:object|null, readback?:{environment:string, artifactDigest:string, connector:string, observedAt:string}|null, checks?:object[]}} o
 * @returns {{environment:string, staging:object}}
 */
export function stagingVerdict({ record, imageDigest = null, receipt = null, readback = null, checks = [] }) {
  const problems = [];
  const stmt = readback ? { ...readback, basis: 'connector-readback' } : receipt ? { ...receipt, basis: 'operator-receipt' } : null;
  const keep = record.environment;
  const done = (status, environment, extra = {}) => ({
    environment,
    staging: {
      status, environment: stmt?.environment ?? null, basis: stmt?.basis ?? null, artifactDigest: stmt?.artifactDigest ?? null, imageDigest,
      ...(stmt?.basis === 'connector-readback' ? { connector: stmt.connector, observedAt: stmt.observedAt } : stmt ? { deployer: stmt.deployer, deployedAt: stmt.deployedAt, reference: stmt.reference ?? null } : {}),
      checks: checks.map((c) => ({ obligation: c.obligation, status: c.status, reason: String(c.reason || '').slice(0, 200) })), problems: [...problems, ...(extra.problems || [])].slice(0, 30),
      note: 'contract checks re-run on the named image inside the trust boundary; the live service was not exercised and nothing was deployed',
    },
  });
  if (receipt) { const p = validateReceipt(receipt); if (p.length) { problems.push(...p.map((x) => `receipt: ${x}`)); return done('invalid', keep); } }
  if (!stmt) { problems.push('nothing states where the artifact runs: supply a deployment receipt or a connector readback'); return done('not-observed', keep); }
  if (record.disposition !== 'verified-for-contract') { problems.push(`the run is ${record.disposition}: there is no verified repair to stage`); return done('blocked', keep); }
  // AC-16.6: a receipt or readback cannot stand in for the artifact comparison and the executed checks
  if (record.artifact !== 'artifact-verified' || !DIGEST.test(record.source?.artifactDigest || '')) { problems.push('the artifact was not verified (run `repair artifact` first): a deployment statement alone upgrades nothing'); return done('blocked', keep); }
  if (stmt.artifactDigest !== record.source.artifactDigest) { problems.push(`the ${stmt.environment} artifact ${stmt.artifactDigest} is not the verified artifact ${record.source.artifactDigest}`); return done('mismatch', 'unavailable'); }
  if (imageDigest && imageDigest !== stmt.artifactDigest) { problems.push(`the image supplied (${imageDigest}) is not the one the ${stmt.basis === 'connector-readback' ? 'readback' : 'receipt'} names`); return done('mismatch', 'unavailable'); }
  if (!checks.length || !imageDigest) { problems.push('the contract checks were not re-executed on the staged image in this invocation (pass --image and --allow-execution)'); return done('not-executed', keep); }
  const failed = checks.filter((c) => c.status === 'failed');
  const open = checks.filter((c) => c.status !== 'passed' && c.status !== 'failed');
  // AC-16.3: a staging failure blocks the environment state and leaves the source verification as recorded
  if (failed.length) { problems.push(...failed.map((c) => `${c.obligation} failed on the staged artifact`)); return done('failed', 'unavailable'); }
  if (open.length) { problems.push(...open.map((c) => `${c.obligation}: ${c.status}`)); return done('inconclusive', 'unavailable'); }
  if (stmt.environment === 'production') {
    if (stmt.basis !== 'connector-readback') { problems.push('a production receipt file is a declaration: deployment-observed needs a readback from a deployment connector'); return done('declared', keep); }
    return done('verified', 'deployment-observed');
  }
  return done('verified', 'staging-verified');
}

const OBS_KINDS = new Set(['reopen', 'reversion', 'regression']);

/** Whether the verified patch is still what the files on disk hold. Pure over a reader. */
export function patchPresence(record, readFile) {
  const p = record.exactPatch;
  if (!p) return { state: 'no-patch', files: [] };
  const files = Object.keys(p.afterDigests || {}).map((rel) => {
    let text; try { text = readFile(rel); } catch { text = undefined; }
    const after = p.afterDigests[rel]; const before = p.beforeDigests?.[rel] ?? null;
    if (after === null) return { file: rel, state: text === undefined ? 'present' : before && digestOf(text) === before ? 'reverted' : 'changed' };
    if (text === undefined) return { file: rel, state: before === null ? 'reverted' : 'missing' };
    const d = digestOf(text);
    return { file: rel, state: d === after ? 'present' : d === before ? 'reverted' : 'changed' };
  });
  let st = files.every((f) => f.state === 'present') ? 'present' : files.every((f) => f.state === 'reverted') ? 'reverted' : 'changed';
  // the pre-patch content on disk is a reversion only when the patch was applied; otherwise it was never there
  if (st === 'reverted' && record.application !== 'applied') st = 'not-applied';
  return { state: st, files };
}

/** Append one observation to the run's operational log (never the record). */
export function observe({ runDir, root, record, report = null, note = null, now = new Date() }) {
  const entries = [];
  const presence = patchPresence(record, (rel) => fs.readFileSync(path.join(root, rel), 'utf8'));
  entries.push({ kind: 'patch-presence', at: now.toISOString(), state: presence.state, files: presence.files });
  if (report) {
    if (!OBS_KINDS.has(report)) return { ok: false, reason: `report must be one of ${[...OBS_KINDS].join(', ')}` };
    entries.push({ kind: report, at: now.toISOString(), note: String(note || '').slice(0, 500), source: 'operator-report' });
  }
  const file = path.join(runDir, 'observations.jsonl');
  for (const e of entries) fs.appendFileSync(file, `${JSON.stringify(e)}\n`);
  return { ok: true, entries, history: readObservations(runDir) };
}

export function readObservations(runDir) {
  try { return fs.readFileSync(path.join(runDir, 'observations.jsonl'), 'utf8').split('\n').filter(Boolean).flatMap((l) => { try { return [JSON.parse(l)]; } catch { return []; } }); } catch { return []; }
}
