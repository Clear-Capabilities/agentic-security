// Completion report (LOOP-004.AC03). A resumable account of where a run ended,
// written at every terminal state and computable at any time from the run
// directory alone, so a crashed controller still has a report. It names every
// unmet criterion, every blocker and every budget stop, what is implemented
// (fresh and verified), where the release evidence lives, and the exact bounded
// commands to continue. It never claims unattended completion: the strongest
// statement it can make is that the criteria it lists were verified, on one
// stable digest, by this controller, inside the stated finite budgets.
import { readJson } from './util.mjs';
import { commandsFor } from './status.mjs';

const BASE = 'node scripts/loop-engineering/run.mjs';

function criterionReasons(row) {
  const ev = row.evidence?.file ? readJson(row.evidence.file, null) : null;
  const byId = new Map((ev?.criteria || []).map((c) => [c.id, c]));
  return row.unmetCriteria.map((id) => ({ requirement: row.id, criterion: id, state: byId.get(id)?.state || 'not-verified', reason: byId.get(id)?.reason || (row.evidence ? 'not passing in the latest evidence' : 'no evidence has been issued') }));
}

/** status: the object buildStatus returns. -> plain JSON-serialisable report. */
export function buildCompletionReport(status, { generatedAt = new Date().toISOString() } = {}) {
  const rows = status.requirements || [];
  const unmetRequirements = rows.filter((r) => r.state !== 'verified');
  const lim = status.limits || {};
  const bud = status.budgets || {};
  const budgetStops = [];
  if (status.status === 'paused-budget') budgetStops.push({ kind: 'run-budget', detail: status.statusReason || 'a run budget is exhausted' });
  for (const r of rows) {
    for (const b of r.blockers || []) {
      if (b.type === 'attempts-exhausted') budgetStops.push({ kind: 'attempts-per-requirement', requirement: r.id, detail: b.detail, limit: lim.attemptsPerRequirement ?? null });
      if (b.type === 'repeated-failure') budgetStops.push({ kind: 'same-failure-repeats', requirement: r.id, detail: b.detail, limit: lim.sameFailureRepeats ?? null });
    }
  }
  const blockers = [
    ...(status.blockers || []).map((b) => ({ scope: 'run', type: b.type, detail: b.detail })),
    ...unmetRequirements.flatMap((r) => (r.blockers || []).map((b) => ({ scope: 'requirement', requirement: r.id, type: b.type, detail: b.detail }))),
  ];
  if (status.drift?.reasons?.length) for (const d of status.drift.reasons) blockers.push({ scope: 'run', type: 'drift', detail: `${d.input}${d.path ? ` ${d.path}` : ''}: ${d.detail}` });
  const fin = status.final || { required: false };
  const complete = status.status === 'completed' && unmetRequirements.length === 0 && (fin.required ? fin.ok === true : true);
  const cmds = commandsFor(status.runId);
  const firstUnmet = unmetRequirements[0]?.id;
  const nextCommands = [
    { command: status.continuation?.command || cmds.status, why: status.continuation?.why || 'inspect the run', bound: 'finite: stops at the profile budgets (runWallSeconds, runMaxAttempts, attemptsPerRequirement, sameFailureRepeats, claudeBudgetUsd)' },
    { command: cmds.status, why: 'liveness-checked status', bound: 'returns within 2 s' },
    ...(firstUnmet ? [{ command: `${BASE} verify --requirement ${firstUnmet}`, why: `re-run the registered suite for ${firstUnmet}`, bound: 'the suite timeoutSeconds' }] : []),
    { command: cmds.stop, why: 'stop only this run and its owned processes', bound: 'grace period, then kill' },
  ];
  return {
    schemaVersion: 1, generatedAt, runId: status.runId, runStatus: status.status, statusReason: status.statusReason || null,
    verdict: complete ? 'verified-complete' : 'incomplete',
    claim: complete
      ? 'Every required criterion was freshly verified by this controller on one stable source digest, and every release gate passed. This states what was verified under the finite budgets of the profile; it is not a promise that any later change keeps it true.'
      : 'Not complete. The unmet criteria, blockers and budget stops below are the whole account; nothing here is a claim of completion.',
    progress: { verifiedPercent: status.verifiedPercent, verifiedWeight: status.verifiedWeight, totalWeight: status.totalWeight, verifiedRequirements: status.verifiedRequirements, totalRequirements: status.totalRequirements },
    final: fin,
    unmetCriteria: unmetRequirements.flatMap(criterionReasons),
    unmetRequirements: unmetRequirements.map((r) => ({ id: r.id, state: r.state, attempts: r.attempts, blockers: (r.blockers || []).map((b) => b.type) })),
    blockers, budgetStops,
    budgets: { used: { attempts: bud.attemptsUsed ?? 0, usd: bud.usdUsed ?? 0, usdIsEstimateWhenKilled: true, wallMs: bud.wallUsedMs ?? 0 }, limits: { runMaxAttempts: lim.runMaxAttempts ?? null, claudeBudgetUsd: lim.claudeBudgetUsd ?? null, runWallSeconds: lim.runWallSeconds ?? null } },
    implemented: rows.filter((r) => r.state === 'verified').map((r) => ({ id: r.id, title: r.title, weight: r.weight, evidence: r.evidence?.id || null })),
    implementedButStale: rows.filter((r) => r.state === 'stale').map((r) => ({ id: r.id, reasons: r.staleReasons })),
    releaseEvidence: status.evidencePaths || {},
    nextCommands,
    limits: [
      'Finite termination: the run ended because it finished or because a stated bound was reached; it is never described as unconditionally unattended.',
      'Evidence is bound to a digest of the watched files: any later change makes the affected requirements stale again.',
      'A worker claim of completion, and any evidence file a worker wrote, contribute nothing.',
    ],
  };
}
