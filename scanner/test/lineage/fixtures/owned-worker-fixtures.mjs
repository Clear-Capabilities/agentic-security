// Work functions for the owned-worker tests (DAG-07 R07.7).
// Each is called as fn(...args, { shouldStop }).

/** Busy loop that polls the cancellation flag, like the bounded analyses do. */
export function cooperative(opts) {
  let spins = 0;
  while (!opts.shouldStop()) spins += 1;
  return { spins: spins > 0 };
}

/** Busy loop that never looks at the flag: only the watchdog can end it. */
export function unresponsive() {
  for (;;) { /* never yields, never polls */ }
}

/** A lineage-shaped body that never polls: only the watchdog can end it. */
export function lineageUnresponsive() {
  for (;;) { /* never yields, never polls */ }
}

export function quick(x) {
  return { doubled: x * 2 };
}
