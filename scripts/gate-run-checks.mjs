// The pre-push gate's check executor: cache lookup, run, record, optional
// parallel groups. Everything environmental is INJECTED so the tests can drive
// it with fake checks and a fake clock; pre-push-gate.mjs supplies the real ones.
//
// Rules this enforces, each pinned by scanner/test/pre-push-gate.test.js:
//  - A hit needs a record whose key equals the freshly computed key, whose
//    verdict is a pass, and which verifies (that part is loadCache's job).
//  - A hit is ANNOUNCED: `cached (inputs unchanged since <time>)`, immediately
//    and again in the summary. Never silent.
//  - Only a PASS is recorded, and only if the inputs are STILL what they were
//    when the check started (a check that rewrites its own inputs is not cached).
//  - Nothing is cached when caching is off, when the key could not be computed,
//    or when the check has no scope (the in-process guards).
//  - A failure stops the run after the current group. An unrunnable check is a
//    failure (that decision lives in runCheck's result, see evaluateCheckOutcome).
//  - Checks run concurrently only when they carry the same `parallelGroup`.
import { evaluateCachedVerdict, scopedRecordId, renderScopedProvenance } from './gate-verdict-cache.mjs';

/**
 * @param {object} o
 * @param {Array}  o.checks         check descriptors in execution order
 * @param {Function} o.runCheck     async (check, {parallel}) => {ok, errors, warnings}
 * @param {object|null} o.scoped    { keyFor(check)->{key,digest,fileCount}|null, records, record(check, keyInfo, durationMs) } or null when caching is off
 * @param {object|null} o.legacy    { hit(check)->record|null, record(check, durationMs) } whole-tree cache shared with release-check, or null
 * @param {Function} o.log          (line) => void
 * @param {Function} o.now          () => ms
 * @returns {Promise<Array>} entries in order, each {...check, result, cached?}; stops after the first failing group
 */
export async function executeChecks({ checks, runCheck, scoped = null, legacy = null, log = () => {}, now = Date.now }) {
  const entries = [];
  let i = 0;
  while (i < checks.length) {
    const group = [checks[i]];
    while (checks[i].parallelGroup && i + group.length < checks.length && checks[i + group.length].parallelGroup === checks[i].parallelGroup) {
      group.push(checks[i + group.length]);
    }
    i += group.length;

    // 1. Resolve cache hits up front (cheap), leaving only what must run.
    const planned = group.map((check) => {
      const cacheable = Boolean(check.npmScript);
      let keyInfo = null;
      if (cacheable && scoped && (!scoped.eligible || scoped.eligible(check))) {
        keyInfo = scoped.keyFor(check);
        if (!keyInfo) log(`  (no cache key for ${check.id}: an input could not be read, so it runs)`);
        else {
          const rec = scoped.records[scopedRecordId(check.id)];
          const v = evaluateCachedVerdict({ record: rec, key: keyInfo.key, checkId: scopedRecordId(check.id), now: now() });
          if (v.usable) {
            const prov = renderScopedProvenance(rec);
            log(`  ${check.id}: ${prov}`);
            return { check, keyInfo, hit: { result: ok(), cached: prov } };
          }
        }
      }
      if (cacheable && legacy) {
        const rec = legacy.hit(check);
        if (rec) {
          const prov = renderScopedProvenance(rec);
          log(`  ${check.id}: ${prov}`);
          return { check, keyInfo, hit: { result: ok(), cached: prov } };
        }
      }
      return { check, keyInfo, hit: null };
    });

    // 2. Run the rest, concurrently only inside a declared group.
    const parallel = group.length > 1;
    const outcomes = await Promise.all(planned.map(async (p) => {
      if (p.hit) return { p, ...p.hit, ms: 0, ran: false };
      const t0 = now();
      let result;
      try { result = await runCheck(p.check, { parallel }); }
      catch (e) { result = { ok: false, errors: [`check threw: ${e?.message || e}`], warnings: [] }; }
      return { p, result, ms: now() - t0, ran: true };
    }));

    // 3. Record passes sequentially (one writer: the cache file is a single signed document).
    for (const o of outcomes) {
      const { check, keyInfo } = o.p;
      entries.push({ ...check, result: o.result, ...(o.cached ? { cached: o.cached } : {}) });
      if (!o.ran || !o.result.ok || !check.npmScript) continue;
      if (scoped && keyInfo) {
        const after = scoped.keyFor(check);
        if (after && after.key === keyInfo.key) scoped.record(check, keyInfo, o.ms);
        else log(`  (${check.id} passed but its inputs changed while it ran, so the verdict is NOT cached)`);
      }
      if (legacy) legacy.record(check, o.ms);
    }
    if (outcomes.some((o) => !o.result.ok)) break; // fastest-fail-first
  }
  return entries;
}

function ok() { return { ok: true, errors: [], warnings: [] }; }
