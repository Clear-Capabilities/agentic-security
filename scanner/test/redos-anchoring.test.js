// FIX-DISCRIMINATION: anchoring is a real ReDoS mitigation.
//
// From GHSA-29g2-3rmr-qm68 (sveltejs/kit). The upstream fix changed exactly
// one thing — it anchored the accept-header regex:
//
//   pre:  /([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?/
//   post: /^[ \t]*([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?/
//
// The engine's scanReDoS fired identically on both, so the finding reported
// the presence of a quantifier rather than the presence of a vulnerability.
//
// WHY ANCHORING IS THE RIGHT CONTROL TO RECOGNISE, on its own terms:
// an UNANCHORED exec() retries the match at every start offset, so a greedy
// leading quantifier that fails late costs O(n) per offset — O(n^2) overall.
// That is this advisory's actual defect. A leading `^` (or a sticky flag)
// leaves exactly one start position and removes that multiplier entirely.
//
// It does NOT make every pattern safe: `/^(a+)+$/` is anchored and still
// catastrophically backtracks, because the nested quantifier is intrinsic to
// the pattern rather than a product of where matching starts. So the rule
// only forgives an anchored pattern when it has no nested quantifier — the
// last test below pins that, and is the reason this is not simply "an anchor
// silences the rule".
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { _internals, scanReDoS } from '../src/engine.js';

const { _isLikelyUnsafeRegex, _extractRegexLiterals } = _internals;

const PRE = String.raw`([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?`;
const POST = String.raw`^[ \t]*([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?`;

test('REAL CODE: the unanchored (vulnerable) accept-header regex is still reported', () => {
  assert.equal(_isLikelyUnsafeRegex(PRE), true,
    'the pre/ revision is a real advisory — it must keep firing');
});

test('REAL CODE: anchoring it (the upstream fix) silences the finding', () => {
  assert.equal(_isLikelyUnsafeRegex(POST), false,
    'the anchor is the control the maintainers added; the finding must discriminate');
});

test('an anchored pattern with a NESTED quantifier still fires', () => {
  // Anchoring removes the start-offset multiplier, not intrinsic catastrophic
  // backtracking. Without this the fix would be "any ^ suppresses ReDoS",
  // which would silence the classic exponential case.
  assert.equal(_isLikelyUnsafeRegex(String.raw`^(a+)+$`), true);
  assert.equal(_isLikelyUnsafeRegex(String.raw`^(?:\w+\s?)*$`), true);
});

test('an unanchored nested quantifier still fires', () => {
  assert.equal(_isLikelyUnsafeRegex(String.raw`(a+)+`), true);
});

// ── the extractor bug the anchoring fix uncovered ────────────────────────────
//
// The anchoring rule alone did NOT silence the fixed revision, because the
// regex-literal extractor was splitting the real pattern in two at the `/`
// inside `[^/ \t]`. Anchoring cured the first fragment; the second — a tail
// that never existed as a regex, and had lost the `^` to the split — kept
// firing. Both fixes are required, which is why both are pinned here.

test('a regex literal containing / inside a character class is extracted whole', () => {
  const src = String.raw`const re = /^[ \t]*([^/ \t]+)\/([^; \t]+)/;`;
  const found = _extractRegexLiterals(src);
  assert.equal(found.length, 1, `expected ONE literal, got ${JSON.stringify(found.map(f => f.body))}`);
  assert.equal(found[0].body, String.raw`^[ \t]*([^/ \t]+)\/([^; \t]+)`);
});

test('REAL CODE: the fixed sveltejs/kit line produces no ReDoS finding', () => {
  const line = String.raw`		const match = /^[ \t]*([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?/.exec(str);`;
  assert.deepEqual(scanReDoS('http.js', line), []);
});

test('REAL CODE: the vulnerable sveltejs/kit line still produces one', () => {
  const line = String.raw`		const match = /([^/ \t]+)\/([^; \t]+)[ \t]*(?:;[ \t]*q=([0-9.]+))?/.exec(str);`;
  assert.equal(scanReDoS('http.js', line).length, 1);
});

// ── safe-regex over-reporting: require a MECHANISM, not just star height ─────
//
// safe-regex is a star-height heuristic and flagged plain file matchers in
// this project's own source that cannot backtrack at all. redos-nfa.js cannot
// be used as the arbiter either — it models exponential backtracking only, and
// clears BOTH revisions of the sveltejs pattern, so deferring to it would drop
// a real advisory. The rule now requires an actual mechanism to be present.

test('REFUSES: a plain file matcher with no backtracking mechanism', () => {
  // Reported on laravel-hardening.js / springboot-hardening.js / quarkus-
  // hardening.js once the extractor started yielding whole regexes.
  assert.equal(_isLikelyUnsafeRegex(String.raw`(?:^|[\\/])\.env(?:\.[\w-]+)?$`), false);
  assert.equal(_isLikelyUnsafeRegex(
    String.raw`(?:^|[\\/])application(?:[-.][\w-]+)?\.(?:properties|ya?ml)$`), false);
});

test('the leading-unbounded-quantifier test is what separates them', () => {
  const { _hasLeadingUnboundedQuantifier: lead } = _internals;
  // `+` runs before the required `/` — the scan-and-retry shape.
  assert.equal(lead(String.raw`([^/ \t]+)\/`), true);
  // a required literal comes first, so most start offsets reject in O(1).
  assert.equal(lead(String.raw`(?:^|[\\/])\.env(?:\.[\w-]+)?$`), false);
});
