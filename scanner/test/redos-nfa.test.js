import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isUnsafeRegex, extractPyRegexBodies, extractJavaRegexBodies, scanRegexReDoS } from '../src/sast/redos-nfa.js';

// ── isUnsafeRegex: known-dangerous patterns ─────────────────────────────────

test('detects (a+)+ nested quantifier', () => {
  const r = isUnsafeRegex('(a+)+');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (a|aa)* alternation ambiguity', () => {
  const r = isUnsafeRegex('(a|aa)*');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects ([a-z]+)+$ nested quantifier', () => {
  const r = isUnsafeRegex('([a-z]+)+$');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (\\d+\\.?\\d+)+ overlapping nullable under quantifier', () => {
  const r = isUnsafeRegex('(\\d+\\.?\\d+)+');
  assert.ok(r.unsafe, 'expected unsafe');
});

test('detects (.*a){10} nested quantifier', () => {
  const r = isUnsafeRegex('(.*a){10}');
  assert.ok(r.unsafe, 'expected unsafe');
});

// `(\w+\s+)+` was pinned as unsafe by a rule that reported every syntactic nesting. Its runs are disjoint and each is required,
// so a string has exactly one split into iterations: linear. The exponential form makes the separator optional.
test('detects (\\w+\\s?)+ nested quantifier (optional separator lets a word run split across iterations)', () => {
  assert.ok(isUnsafeRegex('(\\w+\\s?)+$').unsafe, 'expected unsafe');
});

test('safe: (\\w+\\s+)+ (disjoint, required runs: one split)', () => {
  assert.ok(!isUnsafeRegex('(\\w+\\s+)+').unsafe);
});

test('safe: a quoted run closed by its delimiter inside a repetition', () => {
  assert.ok(!isUnsafeRegex('[^,\\s"](?:[^,"]|"[^"]*")*').unsafe);
});

test('lookaround is zero-width: a possessive run idiom fixes a nested quantifier', () => {
  assert.ok(isUnsafeRegex('(?:[^\\*]|\\*{2,})+?').unsafe);
  assert.ok(!isUnsafeRegex('(?:[^\\*]|\\*{2,}(?!\\*))+?').unsafe);
});

// ── isUnsafeRegex: known-safe patterns ──────────────────────────────────────

test('safe: [a-z]+', () => {
  assert.ok(!isUnsafeRegex('[a-z]+').unsafe);
});

test('safe: \\d{1,3}\\.\\d{1,3}', () => {
  assert.ok(!isUnsafeRegex('\\d{1,3}\\.\\d{1,3}').unsafe);
});

test('safe: [^/]+', () => {
  assert.ok(!isUnsafeRegex('[^/]+').unsafe);
});

test('safe: \\w+@\\w+\\.com', () => {
  assert.ok(!isUnsafeRegex('\\w+@\\w+\\.com').unsafe);
});

test('safe: ^\\d+$', () => {
  assert.ok(!isUnsafeRegex('^\\d+$').unsafe);
});

test('safe: empty or null', () => {
  assert.ok(!isUnsafeRegex('').unsafe);
  assert.ok(!isUnsafeRegex(null).unsafe);
});

// ── Python/Java extraction ──────────────────────────────────────────────────

test('extractPyRegexBodies: captures re.compile patterns', () => {
  const code = `
import re
pat = re.compile(r'(a+)+')
m = re.match(r'\\d+', text)
`;
  const bodies = extractPyRegexBodies(code);
  assert.ok(bodies.length >= 2);
  assert.ok(bodies.some(b => b.body === '(a+)+'));
});

test('extractJavaRegexBodies: captures Pattern.compile and .matches', () => {
  const code = `
Pattern p = Pattern.compile("(a+)+");
boolean ok = input.matches("\\\\d+");
`;
  const bodies = extractJavaRegexBodies(code);
  assert.ok(bodies.length >= 1);
  assert.ok(bodies.some(b => b.body === '(a+)+'));
});

// ── scanRegexReDoS: end-to-end ──────────────────────────────────────────────

test('scanRegexReDoS: flags JS file with dangerous regex', () => {
  const code = `const re = /(a+)+/;`;
  const findings = scanRegexReDoS('app.js', code);
  assert.ok(findings.length >= 1);
  assert.ok(findings[0].vuln.includes('ReDoS'));
});

test('scanRegexReDoS: flags Python file with dangerous regex', () => {
  const code = `import re\npat = re.compile(r'(a+)+')`;
  const findings = scanRegexReDoS('app.py', code);
  assert.ok(findings.length >= 1);
});

test('scanRegexReDoS: no findings for safe JS regex', () => {
  const code = `const re = /[a-z]+/;`;
  const findings = scanRegexReDoS('app.js', code);
  assert.equal(findings.length, 0);
});

// ── the extractors must be linear on their own input (round 7 of the Haskell real-code work found this on a Kotlin app) ──
// `(?:\\.|[^"\n])+` lets a backslash match either branch, so a string literal with many escapes and no `.toRegex(` after it
// backtracks exponentially: simplex-chat's desktop app took the whole scan past 3 hours 40 minutes. A backslash must be
// consumed only by the escape branch. Pinned for every language extractor, with the literal still extracted when it IS a regex.
test('a string literal with many escapes does not stall the Kotlin, Java, C#, Go, Ruby or JS extractors', () => {
  const esc = '\\\\'.repeat(28); // 28 backslash pairs inside one literal
  const t0 = Date.now();
  const kt = `val p = "${esc}"\nval q = "a\\\\d+".toRegex()\nval r = Regex("${esc}")\n`;
  const ktBodies = scanRegexReDoS('App.kt', kt);
  assert.ok(Array.isArray(ktBodies));
  scanRegexReDoS('App.java', `String p = "${esc}"; Pattern.compile("${esc}"); s.matches("${esc}");`);
  scanRegexReDoS('App.cs', `var p = "${esc}"; new Regex("${esc}"); Regex.IsMatch(s, "${esc}");`);
  scanRegexReDoS('app.rb', `p = "${esc}"; Regexp.new("${esc}"); s =~ /${esc}/`);
  scanRegexReDoS('app.js', `const p = "${esc}"; new RegExp("${esc}"); s.match(/${esc}/);`);
  scanRegexReDoS('app.php', `$p = preg_match("/${esc}/", $s);`);
  assert.ok(Date.now() - t0 < 2000, `extractors took ${Date.now() - t0} ms`);
});

// ── Quadratic backtracking under an unanchored search, and regex constants ─────
// Independently authored examples (no advisory or benchmark tree).
import { quadraticSearchRisk, scanRegexReDoS as scanQ } from '../src/sast/redos-nfa.js';

test('quadratic: a leading run before a character it excludes, or before the end anchor', () => {
  assert.ok(quadraticSearchRisk('\\s*,\\s*').risk);
  assert.ok(quadraticSearchRisk('\\s+$').risk);
  assert.ok(!quadraticSearchRisk(',\\s*').risk, 'starts with the required character');
  assert.ok(!quadraticSearchRisk('^\\s*,').risk, 'anchored');
  assert.ok(!quadraticSearchRisk('\\s+').risk, 'nothing required after the run');
  assert.ok(!quadraticSearchRisk('a*a').risk, 'the run can supply the requirement');
  assert.ok(!quadraticSearchRisk('.*x').risk, 'a dot run is not claimed');
});

test('Ruby: a regex constant is analysed; the separator-first rewrite is not reported', () => {
  const pre = 'module M\n  SEP = /\\s*;\\s*q="?/\n  def parse(h)\n    h.index(SEP)\n  end\nend\n';
  const post = 'module M\n  SEP = /;\\s*q="?/\n  def parse(h)\n    h.index(SEP)\n  end\nend\n';
  assert.deepEqual(scanQ('lib/m.rb', pre).map((f) => [f.line, f.id.split(':')[0]]), [[2, 'redos-poly']]);
  assert.deepEqual(scanQ('lib/m.rb', post), []);
});

test('Python: a raw-string constant used by name is analysed for exponential ambiguity', () => {
  const pre = "STRONG = r'(\\*)((?:[^\\*]|\\*{2,})+?)(\\*)'\nclass P:\n    pattern = STRONG\n";
  const post = "STRONG = r'(\\*)((?:[^\\*]|\\*{2,}(?!\\*))+?)(\\*)'\nclass P:\n    pattern = STRONG\n";
  assert.equal(scanQ('pkg/em.py', pre).length, 1);
  assert.equal(scanQ('pkg/em.py', post).length, 0);
  assert.equal(scanQ('pkg/once.py', "UNUSED = r'(a+)+'\n").length, 0, 'a constant never referenced again is not assumed to be a regex');
});

test('Python: the quadratic rule needs search-mode evidence; re.match is anchored', () => {
  assert.equal(scanQ('a.py', "import re\nre.search(r'\\s*;', s)\n").length, 1);
  assert.equal(scanQ('a.py', "import re\nre.match(r'\\s*;', s)\n").length, 0);
  assert.equal(scanQ('a.py', "import re\nP = re.compile(r'\\s*;')\nP.split(s)\n").length, 1);
});

test('JavaScript: a division is not a regex literal for the quadratic rule; the sticky flag anchors', () => {
  assert.equal(scanQ('a.js', 'const parts = s.split(/\\s*,\\s*/);\n').length, 1);
  assert.equal(scanQ('a.js', 'const r = /\\s*,/y;\n').length, 0);
  assert.equal(scanQ('a.js', 'const x = a /\\s*,/ b;\n').length, 0);
});

test('fixture pair redos-quadratic: vulnerable fires, clean is silent', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const { fileURLToPath } = await import('node:url');
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'redos-quadratic');
  for (const f of ['accept.rb', 'emphasis.py']) {
    assert.ok(scanQ(f, fs.readFileSync(path.join(dir, 'vulnerable', f), 'utf8')).length >= 1, `vulnerable/${f}`);
    assert.deepEqual(scanQ(f, fs.readFileSync(path.join(dir, 'clean', f), 'utf8')), [], `clean/${f}`);
  }
});
