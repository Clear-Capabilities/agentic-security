// FR-VER-3 regression-test generator tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { annotateRegressionTests } from '../src/posture/regression-test-gen.js';
import { generatePoc } from '../src/posture/poc-generator.js';

test('annotateRegressionTests emits Jest test for a Node PoC with route context', () => {
  // Post-recommendation #3: regression-test-gen refuses to emit a runnable
  // test when the PoC's param key was inferred with low confidence. To get
  // an emit, give the PoC enough context (route + file body) to land at
  // 'high' confidence — that's what real engine runs do too.
  const fileContents = {
    'app.js': "app.get('/u/:id', (req, res) => db.query('SELECT * WHERE id=' + req.params.id));",
  };
  const routes = [{ file: 'app.js', line: 1, method: 'GET', path: '/u/:id' }];
  const finding = {
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    file: 'app.js',
    line: 1,
    stableId: 'abc123',
    poc: generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89', file: 'app.js', line: 1 }, { routes, fileContents }),
  };
  annotateRegressionTests([finding]);
  assert.ok(finding.regression_test);
  assert.equal(finding.regression_test.framework, 'jest');
  assert.equal(finding.regression_test.lang, 'node');
  assert.match(finding.regression_test.filename, /\.test\.mjs$/);
  assert.ok(finding.regression_test.code.includes('@jest/globals'));
  assert.ok(finding.regression_test.code.includes("expect(demonstrated).toBe(false)"));
});

test('annotateRegressionTests refuses to emit a test when PoC has no route context', () => {
  // Post-recommendation #3: low-confidence PoCs (no inferrable handler key)
  // get a structured `_skipped` instead of a fake-runnable test.
  const finding = {
    vuln: 'SQL Injection',
    cwe: 'CWE-89',
    stableId: 'no-context',
    poc: generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89' }, { routes: [] }),
  };
  annotateRegressionTests([finding]);
  assert.ok(finding.regression_test);
  assert.equal(finding.regression_test.code, null);
  assert.equal(finding.regression_test._skipped, 'poc-param-key-unverified');
});

// Stage 5 correctness audit: _renderPytest never referenced its `poc`
// argument at all — it emitted a hardcoded URL, method, and SQL-injection
// payload for EVERY finding, regardless of the actual vulnerability. A
// path-traversal or command-injection finding routed to the pytest path
// would get a test whose URL/payload has nothing to do with the finding it
// claims to regression-test. Currently unreachable in the shipped pipeline
// (poc-generator.js's CWE_TEMPLATES all hardcode lang:'node'), which is why
// no existing test caught it — this constructs a Python-lang poc by hand,
// following the same URL_/METHOD/PAYLOAD synthesis convention the Jest
// path's extraction already works against.
test('annotateRegressionTests emits a pytest test that reflects the actual finding, not a hardcoded SQLi payload', () => {
  const finding = {
    vuln: 'Path Traversal via unsanitized filename',
    cwe: 'CWE-22',
    file: 'download.py',
    line: 10,
    stableId: 'py-path-traversal',
    poc: {
      lang: 'python',
      paramKeyConfidence: 'high',
      code: [
        "const URL_ = 'http://victim.internal:8080/download';",
        "const METHOD = 'GET';",
        "const PAYLOAD = `../../etc/passwd`;",
      ].join('\n'),
    },
  };
  annotateRegressionTests([finding]);
  assert.ok(finding.regression_test, `expected a regression test to be emitted; got null`);
  assert.equal(finding.regression_test.framework, 'pytest');
  const code = finding.regression_test.code;
  assert.ok(code, `expected runnable code, got _skipped: ${finding.regression_test._skipped}`);
  assert.match(code, /victim\.internal:8080\/download/, 'expected the finding-specific URL, not the hardcoded localhost:3000');
  assert.match(code, /\.\.\/\.\.\/etc\/passwd/, 'expected the finding-specific payload, not the hardcoded SQL UNION string');
  assert.doesNotMatch(code, /UNION SELECT/, 'must not emit the old hardcoded SQL-injection payload for a path-traversal finding');
});

test('annotateRegressionTests emits null when no PoC', () => {
  const f = { vuln: 'X', cwe: 'CWE-1' };
  annotateRegressionTests([f]);
  assert.equal(f.regression_test, null);
});

test('annotateRegressionTests never throws on garbage', () => {
  assert.doesNotThrow(() => annotateRegressionTests(null));
  assert.doesNotThrow(() => annotateRegressionTests([null, undefined, {}]));
});

test('filename slug is bounded length', () => {
  // Provide route context so the PoC reaches `paramKeyConfidence: 'high'`
  // and the generator actually emits a test (with a filename).
  const long = 'a'.repeat(200);
  const fileContents = {
    'app.js': "app.get('/u/:id', (req, res) => db.query('SELECT * WHERE id=' + req.params.id));",
  };
  const routes = [{ file: 'app.js', line: 1, method: 'GET', path: '/u/:id' }];
  const f = {
    vuln: 'X', stableId: long, file: 'app.js', line: 1,
    poc: generatePoc({ vuln: 'SQL Injection', cwe: 'CWE-89', file: 'app.js', line: 1 }, { routes, fileContents }),
  };
  annotateRegressionTests([f]);
  assert.ok(f.regression_test.filename);
  assert.ok(f.regression_test.filename.length < 80);
});
