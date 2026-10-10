// How much slower than an idle machine this one currently is, for tests whose bound is wall-clock time. A bound such as "this documented
// command finishes within 60 s" is a statement about the command, not about whatever else the machine is doing; scaling it by the current
// load (never below 1, capped) keeps it strict on an idle machine and stops it failing when the machine is oversubscribed.
import os from 'node:os';

export function loadFactor(loadavg = os.loadavg()[0], cpus = os.availableParallelism()) {
  const f = loadavg / Math.max(1, cpus);
  return Math.min(6, Math.max(1, Number.isFinite(f) ? f : 1));
}
