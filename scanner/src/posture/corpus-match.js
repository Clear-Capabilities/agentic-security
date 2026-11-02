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

// A finding the scanner itself has PROVED clean (`proof.verdict` `proven-*`: the sink is reached only through a sanitizer that covers the
// finding's class, or only through a parameterizer) is a refuted report, not a detection: the fix lifecycle already drops it and the report
// marks it refuted. It scores on neither side, so a fix that sanitises through a recognised escaper reads as `post:TN` and a vulnerable
// shape the engine wrongly proves clean reads as `pre:FN`, both the honest direction. Added for the first real-advisory Haskell entry (keter,
// HSEC-2024-0001, whose fix is an HTML escaper); the full baseline was re-run and no synthetic entry's verdict moved.
function _refuted(f) { return !!(f && f.proof && typeof f.proof.verdict === 'string' && f.proof.verdict.startsWith('proven-')); }
// A finding at `info` with a guard note is one the engine lowered on evidence it read (a non-HTML content type, a redirect body, a fixed
// host): kept in the report so the lowering is visible, not a vulnerability it reports. It scores on neither side either. An `info`
// finding WITHOUT such a note (a rule that is informational by design) still scores, so no synthetic entry's verdict moves.
function _loweredOnEvidence(f) { return !!(f && f.severity === 'info' && f.guardNote && typeof f.guardNote === 'object'); }

// One predicate, both sides. See the header for why the symmetric form is the
// LOOSE one.
function _matches(f, manifest, matcher) {
  if (_refuted(f) || _loweredOnEvidence(f)) return false;
  return (matcher.test(f.vuln || '') || matcher.test(f.family || '')) &&
    (manifest?.cwe ? f.cwe === manifest.cwe || matcher.test(f.cwe || '') : true);
}

/**
 * Every finding, across every channel, that scores this entry.
 *
 * Third caller of the ONE predicate (gate, enrollment, and now the per-layer
 * recall instrument in `bench/layer-recall/`). That instrument needs to know
 * WHICH findings matched so it can attribute them to the analysis layer that
 * produced them; re-deriving the predicate there is precisely the drift this
 * module was extracted to prevent, so it reuses `_matches` instead.
 */
export function matchingFindings(scan, manifest, matcher = matcherFor(manifest)) {
  const out = [];
  for (const channel of CHANNELS) {
    const arr = scan?.[channel];
    if (!Array.isArray(arr)) continue;
    for (const f of arr) if (_matches(f, manifest, matcher)) out.push(f);
  }
  return out;
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
