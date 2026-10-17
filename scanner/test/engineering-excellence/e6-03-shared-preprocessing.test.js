// E6-03: the shared source-text memo gives byte-identical results, is bounded, can be turned off, and removes repeated work.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createStringMemo } from '../../src/util/string-memo.js';
import { _blankCommentsUncached, blankComments } from '../../src/sast/_comment-strip.js';
import { runFullScan } from '../../src/engine.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { canonicalizeScan } from '../../src/pipeline/canonical-output.js';

setStateWritesEnabled(false);
const FIX = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'fixtures');

function rng(seed) { let x = seed; return () => { x = (x * 1103515245 + 12345) & 0x7fffffff; return x / 0x7fffffff; }; }
const PIECES = ['//', '/*', '*/', '#', '"', "'", '`', '\n', ' ', 'a', 'exec(', ')', '=begin\n', '=end\n', '#[', '\\', '${', '/', '*', 'x = 1;'];
const randomSource = (r) => Array.from({ length: 5 + Math.floor(r() * 60) }, () => PIECES[Math.floor(r() * PIECES.length)]).join('');

test('PURITY: the memoized comment blanking equals the direct function over 3000 random inputs in every language mode, on first call and on a repeat', () => {
  const r = rng(7);
  for (let i = 0; i < 3000; i++) {
    const s = randomSource(r); const lang = [undefined, 'py', 'rb', 'php', null][i % 5];
    const direct = _blankCommentsUncached(s, lang);
    assert.equal(blankComments(s, lang), direct, JSON.stringify([s, lang]));
    assert.equal(blankComments(s, lang), direct, 'second call (a hit)');
    assert.equal(direct.length, s.length, 'offsets still line up with the original');
  }
});

test('different languages for the same text do not share an answer', () => {
  const s = 'a // c\nb # d\n';
  assert.notEqual(blankComments(s), blankComments(s, 'py'));
  assert.equal(blankComments(s, 'py'), _blankCommentsUncached(s, 'py')); assert.equal(blankComments(s), _blankCommentsUncached(s));
});

test('BOUNDED: entries and characters are capped, the least recently used goes first, and an oversized text is never cached', () => {
  let calls = 0; const m = createStringMemo((s) => { calls++; return s.toUpperCase(); }, { version: 't@1', maxEntries: 3, maxChars: 1000 });
  for (const s of ['a', 'b', 'c']) m(s);
  m('a'); // a is now most recent; b is oldest
  m('d');
  assert.equal(m.stats().entries, 3); const before = calls;
  m('a'); m('c'); m('d'); assert.equal(calls, before, 'a, c and d are still cached');
  m('b'); assert.equal(calls, before + 1, 'b was evicted');
  const big = 'x'.repeat(400); const callsBefore = calls; m(big); m(big);
  assert.equal(calls, callsBefore + 2, 'text longer than maxChars/4 is computed every time, never retained'); assert.ok(m.stats().skipped >= 2);
  const m2 = createStringMemo((s) => s + s, { version: 't@1', maxEntries: 1000, maxChars: 400 });
  for (let i = 0; i < 50; i++) m2(String(i).padEnd(20, 'z'));
  assert.ok(m2.stats().chars <= 400, `retained ${m2.stats().chars} chars`);
});

test('the memo can be turned off, reports its version and counts, and non-string input passes straight through', () => {
  let calls = 0; const m = createStringMemo((s) => { calls++; return s; }, { version: 'v9', disableEnv: 'E6_03_TEST_OFF' });
  m('q'); m('q'); assert.equal(calls, 1); assert.equal(m.stats().hits, 1); assert.equal(m.stats().version, 'v9');
  process.env.E6_03_TEST_OFF = '1';
  try { m('q'); m('q'); assert.equal(calls, 3, 'off means every call computes'); } finally { delete process.env.E6_03_TEST_OFF; }
  assert.equal(m(undefined, 'x'), undefined); m.reset(); assert.deepEqual(m.stats(), { version: 'v9', entries: 0, chars: 0, hits: 0, misses: 0, skipped: 0 });
});

function load(...dirs) {
  const files = {};
  for (const d of dirs) (function walk(p, rel) {
    for (const e of fs.readdirSync(p, { withFileTypes: true })) {
      if (e.name === '.agentic-security' || e.name === 'node_modules') continue;
      const r = path.join(rel, e.name);
      if (e.isDirectory()) walk(path.join(p, e.name), r);
      else if (/\.(js|py|java|json|ts|php|rb|go)$/.test(e.name) && fs.statSync(path.join(p, e.name)).size < 200_000) files[`${d}/${r}`] = fs.readFileSync(path.join(p, e.name), 'utf8');
    }
  })(path.join(FIX, d), '');
  return files;
}

for (const dirs of [['vulnerable-js'], ['python-vulnerable', 'xxe-java', 'java-taint-flow'], ['deep-taint', 'js-code-injection', 'ruby-sast', 'php-sast']]) {
  test(`SAME FINDINGS: a deep scan with the memo on and off gives the same canonical digest (${dirs.join(', ')})`, async () => {
    const files = load(...dirs);
    try {
      delete process.env.AGENTIC_SECURITY_NO_STRING_MEMO; blankComments.reset();
      const on = canonicalizeScan(await runFullScan({ fileContents: files, scanRoot: null, deep: true }));
      const stats = blankComments.stats();
      process.env.AGENTIC_SECURITY_NO_STRING_MEMO = '1';
      const off = canonicalizeScan(await runFullScan({ fileContents: files, scanRoot: null, deep: true }));
      assert.ok(on.canonical.findings.length > 0, 'the comparison is not over an empty result');
      assert.equal(on.digest, off.digest);
      assert.ok(stats.hits > 0 && stats.misses > 0, JSON.stringify(stats));
    } finally { delete process.env.AGENTIC_SECURITY_NO_STRING_MEMO; }
  });
}

test('REPEATED WORK IS REMOVED: on a real scan most comment-blanking calls are served from the memo', async () => {
  const files = load('vulnerable-js', 'python-vulnerable', 'deep-taint', 'js-code-injection');
  delete process.env.AGENTIC_SECURITY_NO_STRING_MEMO; blankComments.reset();
  await runFullScan({ fileContents: files, scanRoot: null, deep: true });
  const s = blankComments.stats();
  const total = s.hits + s.misses;
  assert.ok(total > Object.keys(files).length * 3, `each file was blanked several times (${total} calls for ${Object.keys(files).length} files)`);
  assert.ok(s.hits / total >= 0.5, `at least half the calls reused earlier work: ${s.hits}/${total}`);
  assert.ok(s.chars < 24_000_000 && s.entries <= 64);
});

test('the recorded measurement matches its claims: identical findings, bounded memory, and the numbers are present', () => {
  const m = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', 'docs', 'engineering-excellence', 'data', 'parse-reuse.json'), 'utf8'));
  assert.equal(m.schema, 'agentic-security/parse-reuse-measurement@1'); assert.equal(m.canonicalFindingsIdentical, true);
  assert.ok(m.runsPerArm >= 3 && m.corpus.files > 50 && m.hardware.cpus > 0);
  for (const arm of ['memoOn', 'memoOff']) { assert.ok(m[arm].cpuMs.median > 0 && m[arm].wallMs.median > 0); assert.ok(m[arm].cpuMs.min <= m[arm].cpuMs.median && m[arm].cpuMs.median <= m[arm].cpuMs.max); }
  assert.ok(m.memoOn.memoStats.hits > m.memoOn.memoStats.misses);
  assert.ok(m.memoOn.memoStats.chars < 24_000_000);
  assert.ok(Array.isArray(m.caveats) && m.caveats.length >= 1);
});
