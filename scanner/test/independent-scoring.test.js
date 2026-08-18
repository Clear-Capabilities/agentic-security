// T0.1/T0.5/T0.7 — the honest-instrument scoring primitives.
//
// These exist because the 2026-08-17 audit found the previous scoring rule
// (labelled CWE appears ANYWHERE in the advisory's files) awarded 17 of 21
// "true positives" to findings that were demonstrably about different code —
// in one hand-checked case, a finding claiming a function had no auth
// dependency when that function visibly declared one, 200 lines from the
// actual fix. Recall read 6.67%; the localized figure was 1.3%.
//
// The bias throughout: a scoring change may only ever be adopted if it can be
// shown to REFUSE credit it used to give. Every test below pins a refusal.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  isLocalized, LOCALIZATION_WINDOW, changedLineRanges,
  cweSatisfies, cweAncestors, findMatchingFindings, matchesCwe,
  isHeldOut,
} from '../../bench/independent/runner.mjs';

// ─────────────────────────────────────────────── T0.1 localization
test('a finding on a changed line is localized', () => {
  assert.equal(isLocalized(15, [[15, 15]]), true);
});

test('a finding just outside a hunk is localized within the window, not beyond', () => {
  assert.equal(isLocalized(12, [[15, 15]], 3), true);   // 15-3
  assert.equal(isLocalized(18, [[15, 15]], 3), true);   // 15+3
  assert.equal(isLocalized(11, [[15, 15]], 3), false);
  assert.equal(isLocalized(19, [[15, 15]], 3), false);
});

test('the real coincidence case is REFUSED (this is the whole point)', () => {
  // GHSA-3cg5-48j3-v4gv: finding at line 617, fix hunks at 629-644.
  // Old rule: TP. New rule: not localized.
  assert.equal(isLocalized(617, [[629, 629], [631, 644]]), false);
});

test('no ranges, or a finding with no line, can never be localized', () => {
  assert.equal(isLocalized(15, []), false);
  assert.equal(isLocalized(15, null), false);
  // struct: detectors emit findings with no integer line; they cannot be
  // localized, and must not be silently credited.
  assert.equal(isLocalized(undefined, [[1, 99]]), false);
  assert.equal(isLocalized(0, [[1, 99]]), false);
});

test('the default window is small and explicit', () => {
  assert.equal(LOCALIZATION_WINDOW, 3);
});

// ─────────────────────────────────────────────── changedLineRanges (I/O)
test('changedLineRanges reports the changed span, [] when identical, null when a side is missing', () => {
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ranges-'));
  try {
    const pre = path.join(d, 'pre.js'), post = path.join(d, 'post.js');
    const base = Array.from({ length: 10 }, (_, i) => `line${i + 1}`);
    fs.writeFileSync(pre, base.join('\n') + '\n');
    const changed = [...base]; changed[4] = 'CHANGED';
    fs.writeFileSync(post, changed.join('\n') + '\n');
    const ranges = changedLineRanges(pre, post);
    assert.ok(Array.isArray(ranges) && ranges.length >= 1, `expected ranges, got ${JSON.stringify(ranges)}`);
    assert.ok(isLocalized(5, ranges, 0), `line 5 should be in ${JSON.stringify(ranges)}`);
    assert.ok(!isLocalized(10, ranges, 0));

    fs.writeFileSync(post, base.join('\n') + '\n');   // identical now
    assert.deepEqual(changedLineRanges(pre, post), []);

    assert.equal(changedLineRanges(pre, path.join(d, 'nope.js')), null);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('changedLineRanges anchors a PURE INSERTION at its point, not an empty range', () => {
  // A fix that only ADDS lines (nothing removed) produces a unified-diff hunk
  // like `@@ -82,0 +85 @@` — pre-side length 0. That is the single most
  // common shape for a security fix (add a check, delete nothing), and a
  // version of this function that only pushed ranges when `len > 0` silently
  // dropped every one of them — found via GHSA-2364-jh4q-m9vm, whose fix
  // (assertStripeIdMatchesSession inserted after line 82) never localized
  // no matter which line the detector reported, because the insertion
  // point contributed no range at all to compare against.
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ranges-ins-'));
  try {
    const pre = path.join(d, 'pre.js'), post = path.join(d, 'post.js');
    const base = Array.from({ length: 10 }, (_, i) => `line${i + 1}`);
    fs.writeFileSync(pre, base.join('\n') + '\n');
    const inserted = [...base.slice(0, 5), 'NEW_CHECK', ...base.slice(5)];
    fs.writeFileSync(post, inserted.join('\n') + '\n');
    const ranges = changedLineRanges(pre, post);
    assert.ok(Array.isArray(ranges) && ranges.length >= 1, `expected a range for a pure insertion, got ${JSON.stringify(ranges)}`);
    assert.ok(isLocalized(5, ranges, 0) || isLocalized(6, ranges, 0),
      `the insertion point (around pre-side line 5) should localize, got ${JSON.stringify(ranges)}`);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

// ─────────────────────────────────────────────── T0.5 CWE hierarchy
test('an exact CWE always satisfies itself', () => {
  assert.equal(cweSatisfies('CWE-89', 'CWE-89'), true);
});

test('parent/child satisfy in BOTH directions (engine may be broader or narrower)', () => {
  // The real case: engine reports CWE-94, advisory labelled CWE-95.
  assert.equal(cweSatisfies('CWE-94', 'CWE-95'), true);
  assert.equal(cweSatisfies('CWE-95', 'CWE-94'), true);
  // Transitive: CWE-78 -> CWE-77 -> CWE-74
  assert.equal(cweSatisfies('CWE-78', 'CWE-74'), true);
});

test('unrelated CWEs never satisfy — the table must not manufacture recall', () => {
  assert.equal(cweSatisfies('CWE-79', 'CWE-89'), false);   // XSS is not SQLi
  assert.equal(cweSatisfies('CWE-22', 'CWE-918'), false);  // traversal is not SSRF
  assert.equal(cweSatisfies('CWE-790', 'CWE-79'), false);  // numeric prefix is not kinship
  assert.equal(cweSatisfies('CWE-7', 'CWE-79'), false);
});

test('siblings do NOT satisfy each other (only ancestor lines count)', () => {
  // CWE-862 and CWE-863 are both children of CWE-285, but a missing-authz
  // finding is not an incorrect-authz finding.
  assert.equal(cweSatisfies('CWE-862', 'CWE-863'), false);
});

test('malformed CWEs match nothing', () => {
  for (const bad of ['', null, undefined, 'CWE-noinfo', 'sql-injection']) {
    assert.equal(cweSatisfies('CWE-89', bad), false);
    assert.equal(cweSatisfies(bad, 'CWE-89'), false);
  }
});

test('cweAncestors is transitive and terminates', () => {
  const a = cweAncestors('CWE-78');
  assert.ok(a.has('CWE-77') && a.has('CWE-74'));
  assert.equal(cweAncestors('CWE-99999').size, 0);
});

// ─────────────────────────────────────────────── matching contract
test('hierarchy matching is OPT-IN; the default stays exact', () => {
  const findings = [{ cwe: 'CWE-94', file: 'a.js', line: 5 }];
  assert.equal(matchesCwe(findings, 'CWE-95', null), false);
  assert.equal(matchesCwe(findings, 'CWE-95', null, { hierarchy: true }), true);
});

test('findMatchingFindings returns the findings themselves, for line/parser attribution', () => {
  const findings = [
    { cwe: 'CWE-89', file: 'db.js', line: 12, parser: 'IR-TAINT' },
    { cwe: 'CWE-79', file: 'db.js', line: 30, parser: 'REGEX' },
  ];
  const m = findMatchingFindings(findings, 'CWE-89', ['db.js']);
  assert.equal(m.length, 1);
  assert.equal(m[0].parser, 'IR-TAINT');
  assert.equal(m[0].line, 12);
});

// ─────────────────────────────────────────────── T0.7 held-out slice
test('held-out membership is deterministic and stable for the same id', () => {
  const a = isHeldOut('GHSA-22jq-vg5j-6vgg');
  for (let i = 0; i < 5; i++) assert.equal(isHeldOut('GHSA-22jq-vg5j-6vgg'), a);
});

test('held-out fraction is approximately honoured over many ids', () => {
  const ids = Array.from({ length: 2000 }, (_, i) => `GHSA-synthetic-${i}`);
  const held = ids.filter(id => isHeldOut(id, 0.2)).length;
  const frac = held / ids.length;
  assert.ok(frac > 0.15 && frac < 0.25, `expected ~20% held out, got ${(frac * 100).toFixed(1)}%`);
});

test('a larger fraction is a superset of a smaller one (no reshuffling as it grows)', () => {
  const ids = Array.from({ length: 500 }, (_, i) => `GHSA-x-${i}`);
  const small = new Set(ids.filter(id => isHeldOut(id, 0.1)));
  for (const id of small) assert.equal(isHeldOut(id, 0.3), true, `${id} must stay held out`);
});

// ─────────────────────────────────────── changedLineRangesPost (T0.2 scoping)
test('changedLineRangesPost reports the POST-side ranges the fix produced', async () => {
  const { changedLineRangesPost } = await import('../../bench/independent/runner.mjs');
  const d = fs.mkdtempSync(path.join(os.tmpdir(), 'ranges-post-'));
  try {
    const pre = path.join(d, 'pre.js'), post = path.join(d, 'post.js');
    const base = Array.from({ length: 10 }, (_, i) => `line${i + 1}`);
    fs.writeFileSync(pre, base.join('\n') + '\n');
    // Insert two guard lines after line 5 — the shape of a real security fix.
    const fixed = [...base.slice(0, 5), 'GUARD_A', 'GUARD_B', ...base.slice(5)];
    fs.writeFileSync(post, fixed.join('\n') + '\n');
    const ranges = changedLineRangesPost(pre, post);
    assert.ok(Array.isArray(ranges) && ranges.length >= 1, JSON.stringify(ranges));
    // The inserted guards land at POST lines 6-7; pre-side ranges would say 5.
    assert.ok(isLocalized(6, ranges, 0) && isLocalized(7, ranges, 0),
      `post-side range should cover the inserted lines, got ${JSON.stringify(ranges)}`);
    // A line far from the change must not be considered part of the fix.
    assert.equal(isLocalized(12, ranges, 0), false);
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});
