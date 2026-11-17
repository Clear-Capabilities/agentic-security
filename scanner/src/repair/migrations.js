// Schema migrations in a repair (verified-remediation PRD FR-16, AC-16.4): does the migration the candidate ships keep the deployment
// window, the rollback and the forward recovery working, and what does each rollback do to the exposure?
//
// The candidate writes the up and down files the profile names. Every application run of the PATCHED revision applies its up file after
// the declared seed (oracle version 6 `migrations`), so the contract's attacks and controls judge the patched code on the schema it
// needs. This module adds the `migration-window` legs, each an ordinary oracle run through the trust boundary on a fresh database:
//
//   window     the revision live while the other half of the deployment is pending: the ORIGINAL code on the migrated schema
//              (migrate-then-deploy), or the PATCHED code on the old schema (deploy-then-migrate). Its legitimate workflows must work.
//   rollback   up then down, then the ORIGINAL code: the down file must apply and the original must serve its legitimate workflows.
//   recovery   up, down, the rows the profile says an older revision writes while rolled back, then up again, then the PATCHED code:
//              the migration must re-apply over those rows, and the patched code must still block the attacks and serve the workflows.
//
// Exposure facts, stated and never a pass condition: whether the attacks reach their forbidden effect in the window, after a full
// rollback (original code, old schema), with the code rolled back and the schema kept, and with the schema rolled back and the code
// kept. A rollback that reinstates the exposure is reported with it; a combination that keeps it closed is reported as a mitigation.
//
// Limits, stated: only the declared rows stand in for data written between steps (what a running application writes is not carried
// across runs); one SQLite file per run, no locking, long-running migration or replica behaviour; the deployment itself is not observed.
import { judge } from './lab.js';

/** The inputs of an obligation with the migration steps a revision's files call for. A revision without the up file gets none. */
export function withMigrations(inputs, steps) {
  return { ...inputs, migrations: steps };
}

/** The steps for the patched revision's normal runs: its up file, when present. */
export function patchedSteps(decl, files) {
  return typeof files[decl.up] === 'string' && files[decl.up].trim() ? [{ exec: files[decl.up] }] : [];
}

const exposureOf = (res, ob) => {
  if (['unavailable', 'invalid'].includes(res.observed)) return 'unknown';
  if (res.details?.setupFailed) return 'unknown';
  const s = judge(res.observed, ob.patchedExpectation);
  return s === 'passed' ? 'closed' : s === 'failed' ? 'exposed' : 'unknown';
};

/**
 * Run the legs for one candidate. `run(ob, files, inputs)` is the coordinator's runner (budget accounting, trust boundary).
 * @returns {Promise<{ok:boolean, status:'passed'|'failed'|'inconclusive', reason:string, legs:object[], exposure:object, mitigations:string[], counterexample:object|null}>}
 */
export async function checkMigration({ decl, original, patched, behaviour, attack, inputsOf, run, stopped }) {
  const up = patched[decl.up]; const down = patched[decl.down];
  const missing = [decl.up, decl.down].filter((f) => typeof patched[f] !== 'string' || !patched[f].trim());
  if (missing.length) return { ok: false, status: 'failed', reason: `the contract requires a migration and the candidate does not write ${missing.join(' and ')}`, legs: [], exposure: {}, mitigations: [], counterexample: { obligation: 'migration-window', property: 'migration-missing', message: `missing ${missing.join(', ')}` } };
  const U = { exec: up }; const D = { exec: down };
  const interim = (decl.interim || []).map((r) => ({ sql: r.sql, params: r.params }));
  const legs = [];
  const exec = async (leg, who, files, steps, ob, required) => {
    const res = await run(ob, files, withMigrations(inputsOf(ob), steps));
    const status = res.details?.setupFailed ? 'failed' : judge(res.observed, ob.patchedExpectation);
    const reason = res.details?.migrationFailed ? `a migration step did not apply: ${res.details.migrationFailed}` : res.reason;
    const r = { leg, code: who, steps: steps.map((s) => (s === U ? 'up' : s === D ? 'down' : 'interim-row')), obligation: ob.id, required, status, observed: res.observed, reason: String(reason || '').slice(0, 300), res };
    legs.push(r);
    return r;
  };
  // the window
  const windowLeg = decl.deployOrder === 'migrate-then-deploy'
    ? { code: 'original', files: original, steps: [U] }
    : { code: 'patched', files: patched, steps: [] };
  const w = await exec('window', windowLeg.code, windowLeg.files, windowLeg.steps, behaviour, true);
  if (stopped()) return null;
  const wx = attack ? await exec('window', windowLeg.code, windowLeg.files, windowLeg.steps, attack, false) : null;
  if (stopped()) return null;
  // the rollback
  const rb = await exec('rollback', 'original', original, [U, D], behaviour, true);
  if (stopped()) return null;
  const rbx = attack ? await exec('rollback', 'original', original, [U, D], attack, false) : null;
  if (stopped()) return null;
  const schemaOnly = attack ? await exec('schema-rollback', 'patched', patched, [U, D], attack, false) : null;
  if (stopped()) return null;
  // the forward recovery
  const rec = await exec('recovery', 'patched', patched, [U, D, ...interim, U], behaviour, true);
  if (stopped()) return null;
  const recx = attack ? await exec('recovery', 'patched', patched, [U, D, ...interim, U], attack, true) : null;
  if (stopped()) return null;

  const required = legs.filter((l) => l.required);
  const failed = required.filter((l) => l.status === 'failed');
  const open = required.filter((l) => l.status !== 'passed' && l.status !== 'failed');
  const exposure = {
    window: wx ? exposureOf(wx.res, attack) : 'unknown',
    fullRollback: rbx ? exposureOf(rbx.res, attack) : 'unknown',
    codeRollbackSchemaKept: decl.deployOrder === 'migrate-then-deploy' && wx ? exposureOf(wx.res, attack) : 'unknown',
    schemaRollbackCodeKept: schemaOnly ? exposureOf(schemaOnly.res, attack) : 'unknown',
  };
  const mitigations = [];
  if (exposure.codeRollbackSchemaKept === 'closed') mitigations.push('roll back the code and keep the migrated schema: the attacks stayed blocked');
  if (exposure.schemaRollbackCodeKept === 'closed') mitigations.push('roll back the schema and keep the patched code: the attacks stayed blocked');
  if (exposure.fullRollback === 'exposed' && !mitigations.length) mitigations.push('none observed: every rollback tested reinstates the exposure, so a rollback needs a control outside this contract');
  const describe = (l) => `${l.leg} (${l.code} code, ${l.steps.join(' > ') || 'old schema'}) ${l.obligation}: ${l.reason}`;
  const reason = failed.length ? failed.map(describe).join('; ') : open.length ? open.map(describe).join('; ') : `window, rollback and recovery passed (${decl.deployOrder}); full rollback ${exposure.fullRollback === 'exposed' ? 'reinstates the exposure' : exposure.fullRollback === 'closed' ? 'keeps it closed' : 'exposure unknown'}`;
  const status = failed.length ? 'failed' : open.length ? 'inconclusive' : 'passed';
  for (const l of legs) delete l.res;
  return {
    ok: status === 'passed', status, reason: reason.slice(0, 600), legs, exposure, mitigations,
    counterexample: failed.length ? { obligation: 'migration-window', property: `migration-${failed[0].leg}`, leg: failed[0].leg, code: failed[0].code, steps: failed[0].steps, message: describe(failed[0]).slice(0, 300) } : null,
  };
}
