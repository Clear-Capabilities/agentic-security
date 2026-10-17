// A small, bounded memo for pure functions of (source text, tag) (E6-03).
//
// Profiling a deep scan (see docs/engineering-excellence/PARSE_REUSE.md) showed the same source text being comment-blanked and string-stripped again
// by every detector that wants a clean view of it: `blankComments` alone was 7% of scan CPU, called about fifteen times per file. The function is
// pure (same text and language, same output), so the output is computed once per distinct text and reused.
//
// BOUNDED: at most `maxEntries` entries and `maxChars` characters of retained output; the least recently used entry is dropped first. A text longer
// than `maxChars / 4` is not cached at all, so one huge file cannot evict everything else or hold memory.
// VERSIONED: the cache key includes `version`, so a change to the function that forgets to be reflected in the memo cannot serve stale output
// after the version is bumped. It is also off when the named environment variable is "1", which is how the measurement compares with and without.
// CORRECT BY CONSTRUCTION ONLY IF THE FUNCTION IS PURE and its result is never mutated: strings are immutable in JavaScript, and a test checks the
// memoized output equals the direct output over many inputs.
export function createStringMemo(fn, { version, maxEntries = 64, maxChars = 24_000_000, disableEnv = null } = {}) {
  // text -> { size, byTag: Map<tag, output> }; insertion order is recency order (a hit re-inserts)
  const bySrc = new Map();
  let chars = 0; let hits = 0; let misses = 0; let skipped = 0;
  const evict = () => {
    while (bySrc.size > maxEntries || chars > maxChars) {
      const oldest = bySrc.keys().next();
      if (oldest.done) break;
      chars -= bySrc.get(oldest.value).size; bySrc.delete(oldest.value);
    }
  };
  const memo = function memoized(src, tag = '') {
    if (typeof src !== 'string' || (disableEnv && process.env[disableEnv] === '1') || src.length > maxChars / 4) { skipped++; return fn(src, tag); }
    let e = bySrc.get(src);
    if (e) { bySrc.delete(src); bySrc.set(src, e); if (e.byTag.has(tag)) { hits++; return e.byTag.get(tag); } }
    misses++;
    const out = fn(src, tag);
    if (!e) { e = { size: src.length, byTag: new Map() }; bySrc.set(src, e); chars += src.length; }
    e.byTag.set(tag, out); e.size += out.length; chars += out.length;
    evict();
    return out;
  };
  memo.stats = () => ({ version, entries: bySrc.size, chars, hits, misses, skipped });
  memo.reset = () => { bySrc.clear(); chars = 0; hits = 0; misses = 0; skipped = 0; };
  return memo;
}
