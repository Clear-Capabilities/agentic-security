// How a CVE-replay corpus entry is scored against a scan result.
//
// Extracted from `bench/cve-replay/runner.mjs` so the corpus GATE and corpus
// ENROLLMENT (`corpus-enroll.js`) cannot drift apart. That drift is not
// hypothetical: enrollment only writes an entry it has verified scores
// `pre:TP post:TN`, and if it verified that with a different matcher than the
// gate uses, it would cheerfully commit entries that fail CI. One
// implementation, two callers.
//
// THE PRE/POST ASYMMETRY IS DELIBERATE AND PRESERVED VERBATIM. The `pre`
// matcher accepts a hit on `vuln` OR `family` and regex-tests `cwe`; the
// `post` matcher is strict on `vuln` and requires an exact `cwe`. This means
// an entry faces a looser bar to score a TP than an FP, which
// `bench/cve-replay/CONTRIBUTING.md` records as known imprecision to resolve
// before the corpus grows toward 500. It is reproduced here rather than
// quietly fixed: changing it would silently re-verdict entries across the
// whole committed baseline, which is a corpus migration, not a refactor.
//
// The scanner emits into several arrays — `findings` (SAST), `secrets`,
// `supplyChain` (SCA) and `logicVulns` (business-logic + behavioural) — and a
// CVE can land in any of them, so all four are consulted.

const CHANNELS = ['findings', 'secrets', 'supplyChain', 'logicVulns'];

/** The regex an entry's manifest scores with. */
export function matcherFor(manifest) {
  return new RegExp(manifest?.expected?.vuln_match || manifest?.family || manifest?.cwe || '(?!)', 'i');
}

function _any(scan, predicate) {
  for (const channel of CHANNELS) {
    const arr = scan?.[channel];
    if (Array.isArray(arr) && arr.some(predicate)) return true;
  }
  return false;
}

/** Did the vulnerable (`pre/`) tree produce a matching finding? */
export function preHit(scan, manifest, matcher = matcherFor(manifest)) {
  return _any(scan, f =>
    (matcher.test(f.vuln || '') || matcher.test(f.family || '')) &&
    (manifest?.cwe ? f.cwe === manifest.cwe || matcher.test(f.cwe || '') : true));
}

/** Did the fixed (`post/`) tree still produce a matching finding? */
export function postHit(scan, manifest, matcher = matcherFor(manifest)) {
  return _any(scan, f =>
    matcher.test(f.vuln || '') &&
    (manifest?.cwe ? f.cwe === manifest.cwe : true));
}

export const _internals = { CHANNELS };
