// Organization-level scan health (PRD 4, requirement 9). Pure.
//
//   Repositories requested: 1,250
//   Complete: 1,228   Partial: 11   Failed: 6   Timed out: 5   Not run: ...
//
// The one rule: an organization is not GREEN while a required repository has no usable result. A repository that was requested but
// has no job, was cancelled, is still queued or leased, failed or timed out is counted under its own heading and can never disappear
// from the total. `partial` (the scan finished but the engine itself reported a degraded scan) keeps the organization out of GREEN
// as well, because a partial scan is not evidence of a clean repository.
//
//   green      every required repository has a complete result and no optional repository has a problem
//   degraded   every required repository has a result, but some result is partial, or an optional repository has a problem
//   red        at least one required repository has no result
import { isTerminal } from './job-store.js';

export const ASSURANCE = Object.freeze(['green', 'degraded', 'red']);

export function computeOrgHealth({ manifest, jobs }) {
  const byRepo = new Map(jobs.map((j) => [j.repoId, j]));
  const counts = { requested: manifest.repositories.length, complete: 0, partial: 0, failed: 0, timedOut: 0, cancelled: 0, notRun: 0 };
  const repos = [];
  for (const r of manifest.repositories) {
    const j = byRepo.get(r.id);
    let state;
    if (!j) state = 'not-run';
    else if (j.status === 'succeeded') state = 'complete';
    else if (j.status === 'partial') state = 'partial';
    else if (j.status === 'failed') state = 'failed';
    else if (j.status === 'timed_out') state = 'timed-out';
    else if (j.status === 'cancelled') state = 'cancelled';
    else state = 'not-run'; // queued or leased: no result yet
    counts[{ complete: 'complete', partial: 'partial', failed: 'failed', 'timed-out': 'timedOut', cancelled: 'cancelled', 'not-run': 'notRun' }[state]]++;
    repos.push({ id: r.id, required: r.required, state, attempts: j?.attempts ?? 0, error: j?.error ?? null, cached: !!j?.summary?.cached, findings: j?.summary?.total ?? null, jobStatus: j?.status ?? null, finished: j ? isTerminal(j.status) : false });
  }
  const noResult = (x) => !['complete', 'partial'].includes(x.state);
  const requiredMissing = repos.filter((x) => x.required && noResult(x));
  const requiredPartial = repos.filter((x) => x.required && x.state === 'partial');
  const optionalProblems = repos.filter((x) => !x.required && x.state !== 'complete');
  const assurance = requiredMissing.length ? 'red' : (requiredPartial.length || optionalProblems.length) ? 'degraded' : 'green';
  const reasons = [
    ...(requiredMissing.length ? [`${requiredMissing.length} required ${requiredMissing.length === 1 ? 'repository has' : 'repositories have'} no result: ${requiredMissing.slice(0, 8).map((x) => `${x.id} (${x.state})`).join(', ')}${requiredMissing.length > 8 ? ', ...' : ''}`] : []),
    ...(requiredPartial.length ? [`${requiredPartial.length} required ${requiredPartial.length === 1 ? 'repository was' : 'repositories were'} only partially scanned: ${requiredPartial.map((x) => x.id).join(', ')}`] : []),
    ...(optionalProblems.length ? [`${optionalProblems.length} optional ${optionalProblems.length === 1 ? 'repository has' : 'repositories have'} a problem: ${optionalProblems.map((x) => `${x.id} (${x.state})`).join(', ')}`] : []),
  ];
  return { counts, assurance, reasons, repositories: repos };
}

const n = (x) => x.toLocaleString('en-US');
export function renderOrgHealth(h) {
  const c = h.counts;
  const L = [`Repositories requested: ${n(c.requested)}`, `Complete: ${n(c.complete)}`, `Partial: ${n(c.partial)}`, `Failed: ${n(c.failed)}`, `Timed out: ${n(c.timedOut)}`];
  if (c.cancelled) L.push(`Cancelled: ${n(c.cancelled)}`);
  if (c.notRun) L.push(`Not run: ${n(c.notRun)}`);
  L.push('', `Assurance: ${h.assurance.toUpperCase()}`, ...h.reasons.map((r) => `  ${r}`));
  return L.join('\n');
}
