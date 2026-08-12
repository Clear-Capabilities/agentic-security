// TDD for addition #1 — default falsification pass.
// A finding is "blocked" (falsified) only when a context-matched control for its
// CWE family sits on the path; genuine vulns "survive". Blocked findings are
// demoted + quarantined, NEVER removed (recall-preserving, like proof-gate).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyFinding, annotateFalsification } from '../src/posture/falsification.js';

function fc(map) { return map; } // fileContents is a plain {path: source} object

test('classifyFinding: a context-matched sanitizer on the path blocks (falsifies) the finding', () => {
  const files = fc({
    'app.js':
      'function render(req, res) {\n' +
      '  const name = req.query.name;\n' +
      '  const safe = DOMPurify.sanitize(name);\n' +
      '  res.send(safe);\n' +
      '}\n',
  });
  const finding = {
    cwe: 'CWE-79', file: 'app.js',
    source: { line: 2, snippet: 'const name = req.query.name' },
    sink: { line: 4, type: 'res.send', snippet: 'res.send(safe)' },
  };
  const { verdict, reasons } = classifyFinding(finding, files);
  assert.equal(verdict, 'blocked');
  assert.ok(reasons.length > 0 && /HTML|escap|sanitiz/i.test(reasons.join(' ')));
});

test('classifyFinding: a direct source→sink with no control survives falsification', () => {
  const files = fc({
    'db.js':
      'function search(req) {\n' +
      '  const q = req.query.q;\n' +
      '  return db.query("SELECT * FROM t WHERE x=" + q);\n' +
      '}\n',
  });
  const finding = {
    cwe: 'CWE-89', file: 'db.js',
    source: { line: 2, snippet: 'const q = req.query.q' },
    sink: { line: 3, type: 'db.query', snippet: 'db.query("SELECT..." + q)' },
  };
  assert.equal(classifyFinding(finding, files).verdict, 'survived');
});

test('classifyFinding: a wrong-context sanitizer does NOT block — the finding survives', () => {
  const files = fc({
    'u.js':
      'function go(req, res) {\n' +
      '  const url = encodeURIComponent(req.query.next);\n' + // URL-encoder on an XSS sink = wrong context
      '  res.send("<a href=" + url + ">x</a>");\n' +
      '}\n',
  });
  const finding = {
    cwe: 'CWE-79', file: 'u.js', sanitizerMismatch: true,
    source: { line: 2, snippet: 'req.query.next' },
    sink: { line: 3, type: 'res.send', snippet: 'res.send(...)' },
  };
  assert.equal(classifyFinding(finding, files).verdict, 'survived');
});

// Stage 3 correctness audit (detection depth): sanitizerMismatch's REAL
// producer (engine.js's applySanitizerEffectiveness) sets it to a STRING
// sanitizer-type label ("Type Guard", "JWT Algo Pinning", ...), never the
// literal boolean `true` the test above uses — `finding.sanitizerMismatch
// === true` could never match that real shape, making the whole
// fast-path branch dead code (every OTHER consumer of this field checks
// it via plain truthiness). This test uses a window that WOULD otherwise
// classify as 'blocked' (a real context-matched DOMPurify.sanitize call
// visible on the path) specifically to prove the sanitizerMismatch
// fast-path is what forces 'survived' here — not a coincidental
// non-match on the normal isValidSanitizerFor path, which the test above
// can't distinguish from the bug (encodeURIComponent never matches an
// XSS-family sanitizer regardless of the mismatch flag).
test('classifyFinding: a STRING sanitizerMismatch (the real shape) still forces survival even when the path otherwise looks blocked', () => {
  const files = fc({
    'u.js':
      'function go(req, res) {\n' +
      '  const name = req.query.name;\n' +
      '  const safe = DOMPurify.sanitize(name);\n' +
      '  res.send(safe);\n' +
      '}\n',
  });
  const finding = {
    cwe: 'CWE-79', file: 'u.js', sanitizerMismatch: 'URL Encoder',
    source: { line: 2, snippet: 'req.query.name' },
    sink: { line: 4, type: 'res.send', snippet: 'res.send(safe)' },
  };
  assert.equal(classifyFinding(finding, files).verdict, 'survived',
    'a string sanitizerMismatch must force survival even when the window otherwise looks blocked');
});

test('classifyFinding: no file contents / no snippet → unproven (never a false "blocked")', () => {
  const finding = { cwe: 'CWE-89', file: 'x.js', source: { line: 1 }, sink: { line: 2 } };
  assert.equal(classifyFinding(finding, {}).verdict, 'unproven');
});

test('annotateFalsification: blocked findings are demoted + quarantined but NOT removed', () => {
  const files = fc({
    'app.js':
      'function render(req, res) {\n' +
      '  const name = req.query.name;\n' +
      '  const safe = DOMPurify.sanitize(name);\n' +
      '  res.send(safe);\n' +
      '}\n',
  });
  const findings = [{
    cwe: 'CWE-79', file: 'app.js', severity: 'high', confidence: 0.9, confidenceTier: 'high',
    source: { line: 2, snippet: 'req.query.name' },
    sink: { line: 4, type: 'res.send', snippet: 'res.send(safe)' },
  }];
  const out = annotateFalsification(findings, files);
  assert.equal(out.length, 1, 'never removes findings');
  assert.equal(out[0].falsification.verdict, 'blocked');
  assert.equal(out[0].quarantined, true);
  assert.ok(out[0].confidence < 0.9, 'confidence demoted');
  assert.equal(out[0].severity, 'high', 'severity untouched — recall-preserving');
});

// Stage 3 correctness audit (detection depth): _dropTier's TIERS ladder was
// missing 'critical' — exploitability.js sets exploitabilityTier='critical'
// at score >= 0.80, exactly the tier a falsified finding most needs demoted
// (a false "survives" verdict at 'critical' overstates the most). Because
// 'critical' wasn't in the ladder, _dropTier's `indexOf` returned -1, hit
// the "unknown tier, leave unchanged" fallback, and the demotion silently
// no-op'd for the highest tier in the whole system.
test('annotateFalsification: a blocked finding at the critical exploitability tier is actually demoted, not left at critical', () => {
  const files = fc({
    'app.js':
      'function render(req, res) {\n' +
      '  const name = req.query.name;\n' +
      '  const safe = DOMPurify.sanitize(name);\n' +
      '  res.send(safe);\n' +
      '}\n',
  });
  const findings = [{
    cwe: 'CWE-79', file: 'app.js', severity: 'high', confidence: 0.9,
    confidenceTier: 'high', exploitabilityTier: 'critical',
    source: { line: 2, snippet: 'req.query.name' },
    sink: { line: 4, type: 'res.send', snippet: 'res.send(safe)' },
  }];
  const out = annotateFalsification(findings, files);
  assert.equal(out[0].falsification.verdict, 'blocked');
  assert.equal(out[0].exploitabilityTier, 'high',
    `expected the critical tier to demote to 'high', got '${out[0].exploitabilityTier}'`);
});

test('annotateFalsification: surviving findings keep confidence and are not quarantined', () => {
  const files = fc({
    'db.js':
      'function search(req) {\n' +
      '  const q = req.query.q;\n' +
      '  return db.query("SELECT * FROM t WHERE x=" + q);\n' +
      '}\n',
  });
  const findings = [{
    cwe: 'CWE-89', file: 'db.js', confidence: 0.8, confidenceTier: 'high',
    source: { line: 2, snippet: 'req.query.q' },
    sink: { line: 3, type: 'db.query', snippet: 'db.query(...)' },
  }];
  const out = annotateFalsification(findings, files);
  assert.equal(out[0].falsification.verdict, 'survived');
  assert.notEqual(out[0].quarantined, true);
  assert.equal(out[0].confidence, 0.8, 'confidence unchanged for survivors');
});

test('annotateFalsification: optional LLM tier runs only over survivors', () => {
  const files = fc({
    'a.js': 'function f(req){ return db.query("x"+req.query.q); }\n',
    'b.js': 'function g(req,res){ res.send(DOMPurify.sanitize(req.query.n)); }\n',
  });
  const findings = [
    { cwe: 'CWE-89', file: 'a.js', confidence: 0.8, source: { line: 1, snippet: 'req.query.q' }, sink: { line: 1, type: 'db.query', snippet: 'db.query(...)' } },
    { cwe: 'CWE-79', file: 'b.js', confidence: 0.8, source: { line: 1, snippet: 'req.query.n' }, sink: { line: 1, type: 'res.send', snippet: 'res.send(...)' } },
  ];
  const reviewed = [];
  annotateFalsification(findings, files, { llmReview: (f) => { reviewed.push(f.file); return { verdict: 'survived', reason: 'llm' }; } });
  assert.deepEqual(reviewed, ['a.js'], 'LLM tier is invoked only for the survivor, not the blocked finding');
});

test('annotateFalsification: never throws on empty / malformed input', () => {
  assert.doesNotThrow(() => annotateFalsification([], {}));
  assert.doesNotThrow(() => annotateFalsification(null, null));
  assert.doesNotThrow(() => annotateFalsification([{ vuln: 'x' }], {}));
});
