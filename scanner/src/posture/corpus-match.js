// How a CVE-replay corpus entry is scored against a scan result.
//
// Extracted from `bench/cve-replay/runner.mjs` so the corpus GATE and corpus
// ENROLLMENT (`corpus-enroll.js`) cannot drift apart. That drift is not
// hypothetical: enrollment only writes an entry it has verified scores
// `pre:TP post:TN`, and if it verified that with a different matcher than the
// gate uses, it would cheerfully commit entries that fail CI. One
// implementation, two callers.
//
// THE PRE/POST MATCHERS ARE NOW SYMMETRIC. They were not: `pre` accepted a hit
// on `vuln` OR `family` and regex-tested `cwe`, while `post` was strict on
// `vuln` and required an exact `cwe`. An entry therefore faced a LOOSER bar to
// score a true positive than a false positive, which flatters the corpus —
// exactly the direction a measurement must not lean. `CONTRIBUTING.md` recorded
// it as known imprecision to resolve before the corpus grows toward 500.
//
// WHICH DIRECTION, AND WHY. The two sides were unified on the LOOSE predicate,
// not the strict one. The question a corpus entry asks is "does the scanner
// still report this vulnerability?", and a scanner that reports it under the
// family name rather than the exact vuln string is still reporting it. Loose-
// on-both means an entry must genuinely go quiet to score `post:TN` — a HIGHER
// bar for a pass. Unifying on the strict predicate would instead have made
// `pre:TP` harder and `post:TN` easier, i.e. it would have made the corpus
// easier to satisfy. When a symmetry fix can go either way, take the direction
// that makes the gate harder to pass.
//
// This re-verdicts every committed entry, so it is a corpus migration: the full
// baseline was re-run against it and any entry whose verdict moved was fixed or
// recorded, never baselined over.
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

// One predicate, both sides. See the header for why the symmetric form is the
// LOOSE one.
function _matches(f, manifest, matcher) {
  return (matcher.test(f.vuln || '') || matcher.test(f.family || '')) &&
    (manifest?.cwe ? f.cwe === manifest.cwe || matcher.test(f.cwe || '') : true);
}

/** Did the vulnerable (`pre/`) tree produce a matching finding? */
export function preHit(scan, manifest, matcher = matcherFor(manifest)) {
  return _any(scan, f => _matches(f, manifest, matcher));
}

/** Did the fixed (`post/`) tree still produce a matching finding? */
export function postHit(scan, manifest, matcher = matcherFor(manifest)) {
  return _any(scan, f => _matches(f, manifest, matcher));
}

export const _internals = { CHANNELS };
