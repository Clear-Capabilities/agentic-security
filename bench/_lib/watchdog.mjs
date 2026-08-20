// PRD F12.3 — a single pathological entry must not be able to end a measurement.
//
// MEASURED, NOT HYPOTHETICAL. On 2026-08-19 a full `bench/independent` run wedged
// at entry 186 of 315 on GHSA-hcm8-x79p-wx2w (apache/camel, a 649 MB tree): the
// process stayed alive in state `S` at 0.0% CPU with no progress for over six
// hours, had to be killed, and 129 entries were never scored. It reproduced on a
// clean checkout, so it was a property of the harness rather than a regression.
//
// `runScan` carries a deep-mode walltime budget (AGENTIC_SECURITY_DEEP_TIMEOUT_MS)
// and a per-file timeout, but NOTHING bounded a whole-entry scan — and a promise
// that never settles is not a budget overrun that any of them observe.
//
// WHAT THIS DOES AND DOES NOT DO. It bounds the awaited PROMISE, not the work:
// JavaScript cannot cancel an in-flight async operation, so a wedged scan keeps
// its handle and the runner must exit explicitly (`process.exit`) rather than
// waiting for the event loop to drain. That is the intended trade — a completed
// measurement that names its casualties beats an indefinite hang that names
// nothing.
//
// The timer is unref'd so the watchdog itself never holds the loop open.
//
// DOCTRINE FOR THE CALLER: a timed-out entry is UNSCORED — excluded from every
// denominator and reported by name — never a miss. Counting infrastructure
// failure as a detection failure is the exact error the UNSCORED rule exists to
// prevent (see bench/independent/README.md).

export class EntryTimeout extends Error {
  constructor(message, { label, ms } = {}) {
    super(message);
    this.name = 'EntryTimeout';
    this.label = label;
    this.ms = ms;
  }
}

/**
 * Resolve `promise`, or reject with EntryTimeout after `ms`.
 *
 * @param {Promise<T>} promise  work to bound
 * @param {string}     label    identifies the entry in the rejection message
 * @param {number}     ms       budget in milliseconds
 * @returns {Promise<T>}
 * @template T
 */
export async function withEntryTimeout(promise, label, ms) {
  let timer;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new EntryTimeout(`entry exceeded ${ms}ms (${label})`, { label, ms })),
          ms);
        if (typeof timer.unref === 'function') timer.unref();
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Per-entry budget for a bench runner, overridable per-harness.
 * Default 600_000 ms — chosen because the six entries it excludes on the
 * independent population are all very large Java trees that exceeded it even
 * with a 4 GB heap, while every other entry of 309 finished well inside it.
 */
export function entryTimeoutMs(envVar = 'AGENTIC_SECURITY_BENCH_ENTRY_TIMEOUT_MS') {
  const raw = Number(process.env[envVar]);
  return Number.isFinite(raw) && raw > 0 ? raw : 600_000;
}
