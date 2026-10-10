// Per-child leases inside a suite (LOOP-002). A suite wrapper runs several real test files. Each file is one CHILD with its own finite
// lease, and every lease is also capped by what is left of the suite's ceiling, so one hung file can neither run forever nor spend the
// whole ceiling unnoticed: it is killed as a process group at its lease and the result NAMES the file.
//
// The ceiling is a deadline for the whole set (children may run side by side up to `concurrency`, as `node --test` runs files side by
// side). A child that has not started when the ceiling is spent is not started and is reported as `not-run`, never as passed.
import { runBounded } from './proc.mjs';
import { Deadline } from './util.mjs';

/**
 * files        the child identifiers (test file paths)
 * argvFor(f)   -> argv for one child
 * ceilingSeconds, childLeaseSeconds   finite positive numbers (the lease is clamped to the ceiling)
 * Returns { children[], outcome, exitCode, hung[], reason }:
 *   child.outcome  exited | lease-expired | ceiling-expired | not-run | spawn-failed | signaled | resource-limit
 *   outcome        'exited' only when every child exited; else the first non-exited child's outcome
 *   hung[]         the files whose lease or ceiling expired (they were killed)
 */
export async function runLeasedChildren({ files, argvFor, cwd, env, ceilingSeconds, childLeaseSeconds, graceMs = 5000, concurrency = 1, runner = runBounded, label = 'child', runId, owned, extra = {} }) {
  if (!Number.isFinite(ceilingSeconds) || ceilingSeconds <= 0) throw new RangeError('ceilingSeconds must be a finite positive number');
  if (!Number.isFinite(childLeaseSeconds) || childLeaseSeconds <= 0) throw new RangeError('childLeaseSeconds must be a finite positive number');
  const lease = Math.min(childLeaseSeconds, ceilingSeconds);
  const ceiling = new Deadline(ceilingSeconds * 1000);
  const children = new Array(files.length);
  let next = 0;
  const worker = async () => {
    for (;;) {
      const i = next++;
      if (i >= files.length) return;
      const file = files[i];
      const remainingMs = ceiling.remaining();
      if (remainingMs <= 0) { children[i] = { file, outcome: 'not-run', exitCode: null, leaseSeconds: 0, durationMs: 0, reason: `the suite ceiling of ${ceilingSeconds}s was spent before this file started`, stdoutTail: '', stderrTail: '', bytes: { stdout: 0, stderr: 0 } }; continue; }
      const leaseMs = Math.min(lease * 1000, remainingMs);
      const cappedByCeiling = remainingMs < lease * 1000;
      const r = await runner({ argv: argvFor(file), cwd, env, wallMs: leaseMs, graceMs, label: `${label}:${file}`, runId, owned, tailBytes: 64 * 1024 * 1024, ...extra });
      let outcome = r.outcome;
      if (outcome === 'timeout-wall') outcome = cappedByCeiling ? 'ceiling-expired' : 'lease-expired';
      children[i] = { file, outcome, exitCode: r.exitCode, signal: r.signal, leaseSeconds: Math.round(leaseMs) / 1000, durationMs: r.durationMs, reason: outcome === 'lease-expired' ? `${file} exceeded its ${lease}s lease and its process group was killed` : outcome === 'ceiling-expired' ? `${file} was still running when the suite ceiling of ${ceilingSeconds}s ran out and its process group was killed` : r.reason, stdoutTail: r.stdoutTail, stderrTail: r.stderrTail, bytes: r.bytes, orphansKilled: r.orphansKilled?.length || 0, peakRssKb: r.peakRssKb || 0 };
    }
  };
  await Promise.all(Array.from({ length: Math.max(1, Math.min(concurrency, files.length)) }, worker));
  const bad = children.find((c) => c.outcome !== 'exited');
  const hung = children.filter((c) => c.outcome === 'lease-expired' || c.outcome === 'ceiling-expired').map((c) => c.file);
  const nonzero = children.find((c) => c.outcome === 'exited' && c.exitCode !== 0);
  return {
    children, hung, outcome: bad ? bad.outcome : 'exited', exitCode: bad ? null : (nonzero ? nonzero.exitCode : 0),
    reason: bad ? bad.reason : null, lease, ceilingSeconds, elapsedMs: Math.round(ceiling.elapsed()),
  };
}

const SUMMARY = /^# (tests|suites|pass|fail|cancelled|skipped|todo|duration_ms) /;

/**
 * One TAP stream out of several children (for the verifier, which reads one stream): the children's test lines in order, then ONE
 * summary whose counts are the sums, so the verifier's `tests`/`fail`/`skipped` figures are the whole set's.
 */
export function mergeTap(children) {
  const sums = { tests: 0, suites: 0, pass: 0, fail: 0, cancelled: 0, skipped: 0, todo: 0 };
  const lines = [];
  for (const c of children) {
    for (const l of (c.stdoutTail || '').split('\n')) {
      const m = /^# (tests|suites|pass|fail|cancelled|skipped|todo) (\d+)\s*$/.exec(l);
      if (m) { sums[m[1]] += +m[2]; continue; }
      if (SUMMARY.test(l) || /^TAP version/.test(l) || /^1\.\.\d+/.test(l)) continue;
      lines.push(l);
    }
  }
  return `TAP version 13\n${lines.join('\n')}\n${Object.entries(sums).map(([k, v]) => `# ${k} ${v}`).join('\n')}\n`;
}
