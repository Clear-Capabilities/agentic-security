// Scan telemetry (E6-01): where the time and memory of ONE scan went, and which stage failed, as structured aggregates inside the scan result.
//
// LOCAL ONLY. Nothing here sends anything anywhere: the snapshot is a field of the scan object the caller already holds. There is no endpoint, no
// identifier of the user or the machine, no file path and no source text; stage names are fixed strings and an error carries a class and a short
// message, never code.
//
// WHAT IT RECORDS
//   stages   wall time and call count per named stage (file read, detectors, deep analysis, lineage, each annotator, ...)
//   detectors time and call count per detector, accumulated by runDetector
//   memory   resident-set and heap high-water marks sampled at stage boundaries (a sample, not a profiler: a spike between two samples is missed)
//   counters named integer counts (files scanned, files skipped, cache hits and misses)
//   errors   attributed failures: the stage, a class, a short message and a count, from the existing error arrays
//   overhead the time this module itself spent bookkeeping, so its cost is measured, not asserted
//
// DETERMINISM. Under --deterministic, every duration and memory figure is reported as 0 and the stage list is sorted by name, so two runs of the same
// input give byte-identical telemetry; the counts, which are properties of the input, are kept.
const MB = 1024 * 1024;

export function createTelemetry({ deterministic = false } = {}) {
  const stages = new Map(); const detectors = new Map(); const counters = new Map(); const errors = new Map();
  const mem = { rssHighWaterBytes: 0, heapHighWaterBytes: 0, samples: 0 };
  let selfNs = 0n; const startedNs = process.hrtime.bigint();
  const own = (fn) => { const a = process.hrtime.bigint(); try { return fn(); } finally { selfNs += process.hrtime.bigint() - a; } };
  const bump = (map, key, ms) => own(() => { const c = map.get(key) || { ms: 0, calls: 0 }; c.ms += ms; c.calls += 1; map.set(key, c); });
  const sample = () => own(() => {
    if (deterministic) { mem.samples++; return; }
    const m = process.memoryUsage();
    if (m.rss > mem.rssHighWaterBytes) mem.rssHighWaterBytes = m.rss;
    if (m.heapUsed > mem.heapHighWaterBytes) mem.heapHighWaterBytes = m.heapUsed;
    mem.samples++;
  });
  const api = {
    /** Time a synchronous function as stage `name`. Errors propagate; the time is still recorded. */
    time(name, fn) { const a = process.hrtime.bigint(); try { return fn(); } finally { bump(stages, name, Number(process.hrtime.bigint() - a) / 1e6); sample(); } },
    /** Time an async function as stage `name`. */
    async timeAsync(name, fn) { const a = process.hrtime.bigint(); try { return await fn(); } finally { bump(stages, name, Number(process.hrtime.bigint() - a) / 1e6); sample(); } },
    /** Record a duration measured elsewhere. */
    record(name, ms) { bump(stages, name, Number.isFinite(ms) ? ms : 0); sample(); },
    detector(name, ms) { bump(detectors, name, ms); },
    count(name, n = 1) { own(() => counters.set(name, (counters.get(name) || 0) + n)); },
    set(name, n) { own(() => counters.set(name, n)); },
    sample,
    /** Attribute a failure. `kind` is a short class (an error name or code); `message` is clipped and carries no source text. */
    error(stage, kind, message) {
      own(() => {
        const key = `${stage}|${kind}`; const c = errors.get(key) || { stage, kind, count: 0, example: String(message ?? '').replace(/\s+/g, ' ').slice(0, 120) };
        c.count += 1; errors.set(key, c);
      });
    },
    snapshot() {
      return own(() => {
        sample();
        const z = (v) => (deterministic ? 0 : Math.round(v * 100) / 100);
        const byName = (a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0);
        const rows = (map) => [...map].sort(deterministic ? byName : (a, b) => b[1].ms - a[1].ms || byName(a, b)).map(([name, v]) => ({ name, ms: z(v.ms), calls: v.calls }));
        return {
          schema: 'agentic-security/scan-telemetry', version: 1, deterministic,
          totalMs: z(Number(process.hrtime.bigint() - startedNs) / 1e6),
          stages: rows(stages),
          detectors: rows(detectors).slice(0, 25),
          memory: { rssHighWaterMb: z(mem.rssHighWaterBytes / MB), heapHighWaterMb: z(mem.heapHighWaterBytes / MB), samples: mem.samples },
          counters: Object.fromEntries([...counters].sort(byName)),
          errors: [...errors.values()].sort((a, b) => (a.stage + a.kind < b.stage + b.kind ? -1 : 1)),
          overhead: { selfMs: z(Number(selfNs) / 1e6) },
          outbound: 'none: this record stays in the scan result',
        };
      });
    },
  };
  return api;
}

/** Fold the existing error arrays of a scan into telemetry errors, by stage. Reads the arrays; changes nothing. */
export function attributeErrors(tel, { annotatorErrors = [], detectorErrors = [], deepFailure = null, filesTimedOut = 0 } = {}) {
  for (const e of annotatorErrors) tel.error(`annotator:${e.phase || e.annotator || 'unknown'}`, e.name || 'Error', e.message || e.err);
  for (const e of detectorErrors) tel.error(`detector:${e.analyzer || 'unknown'}`, 'DetectorError', e.err);
  if (deepFailure) tel.error('deep-analysis', 'DeepFailure', deepFailure);
  if (filesTimedOut > 0) tel.error('per-file-timeout', 'Timeout', `${filesTimedOut} file(s) exceeded the per-file budget`);
}
