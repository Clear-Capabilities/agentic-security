// QA-005.AC02: a guard must DOMINATE the sink, and a sanitizer must match the sink's context, before anything is cleared.
//
// Every "kept" case below is a guard-looking line that does not actually protect the sink; every "dropped" case is the same code with
// the guard in the place that does protect it. Both directions are asserted for each shape, so a change that makes the recognizer
// blanket-permissive OR blanket-strict fails one of them.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { dropGuardedFindings } from '../../src/engine.js';
import { guardDominatesSink } from '../../src/dataflow/guard-dominance.js';
import { applySanitizerGate } from '../../src/dataflow/sanitizer-gate.js';
import { runScan } from '../../src/runScan.js';
import { mkTestTmp } from '../helpers/tmp.js';

const kept = (src, line, { cwe = 'CWE-918', file = 'a.js' } = {}) => dropGuardedFindings([{ id: 'x', file, line, cwe, vuln: 'x' }], { [file]: src }).length === 1;
const lines = (s) => s.split('\n');

describe('[QA-005.AC02] a guard clears a finding only when it dominates the sink', () => {
  const TARGET = 'const target = req.query.u;';

  test('a guard BEFORE the sink that stops the request on failure clears it; the same guard AFTER the sink does not', () => {
    const before = `function h(req){\n  ${TARGET}\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) throw new Error('no');\n  return fetch(target);\n}`;
    const after = `function h(req){\n  ${TARGET}\n  const r = fetch(target);\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) log('bad');\n  return r;\n}`;
    assert.equal(kept(before, 4), false, 'dominating guard: cleared');
    assert.equal(kept(after, 3), true, 'guard after the sink: kept');
    assert.equal(guardDominatesSink({ lines: lines(after), guardIdx: 3, sinkIdx: 2 }).reason, 'guard-after-sink');
  });

  test('a check whose failing branch only logs does not clear it; one that exits does', () => {
    const logs = `function h(req){\n  ${TARGET}\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) { console.log('warn'); }\n  return fetch(target);\n}`;
    const exits = `function h(req){\n  ${TARGET}\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) { return null; }\n  return fetch(target);\n}`;
    assert.equal(kept(logs, 4), true);
    assert.equal(kept(exits, 4), false);
    assert.equal(guardDominatesSink({ lines: lines(logs), guardIdx: 2, sinkIdx: 3 }).reason, 'failing-branch-does-not-exit');
  });

  test('a guard in a block that has already closed does not clear it', () => {
    const closed = `function h(req){\n  ${TARGET}\n  if (DEBUG) {\n    validateUrl(target);\n  }\n  return fetch(target);\n}`;
    const open = `function h(req){\n  ${TARGET}\n  validateUrl(target);\n  return fetch(target);\n}`;
    assert.equal(kept(closed, 6), true);
    assert.equal(kept(open, 4), false, 'control: the same call at the sink\'s own level clears it');
  });

  test('a sink INSIDE the allow branch is protected; the same code with the sink after the branch is not', () => {
    const inside = `function h(req){\n  ${TARGET}\n  if (ALLOWED_HOSTS.has(new URL(target).hostname)) {\n    return fetch(target);\n  }\n  return null;\n}`;
    const outside = `function h(req){\n  ${TARGET}\n  if (ALLOWED_HOSTS.has(new URL(target).hostname)) {\n    console.log('ok');\n  }\n  return fetch(target);\n}`;
    assert.equal(kept(inside, 4), false);
    assert.equal(kept(outside, 6), true);
  });

  test('a membership test computed and never branched on does not clear it; the same value used in a branch does', () => {
    const unused = `function h(req){\n  ${TARGET}\n  const ok = ALLOWED_HOSTS.has(new URL(target).hostname);\n  return fetch(target);\n}`;
    const used = `function h(req){\n  ${TARGET}\n  const ok = ALLOWED_HOSTS.has(new URL(target).hostname);\n  if (!ok) return null;\n  return fetch(target);\n}`;
    assert.equal(kept(unused, 4), true);
    assert.equal(kept(used, 5), false);
  });

  test('a line that only DEFINES the allow-list is not a guard, however guard-shaped its name', () => {
    const defOnly = `const ALLOWED_HOSTS = new Set(['api.example.com']);\napp.get('/p', async (req, res) => {\n  ${TARGET}\n  const r = await axios.get(target);\n});`;
    assert.equal(kept(defOnly, 4), true);
    assert.equal(guardDominatesSink({ lines: lines(defOnly), guardIdx: 0, sinkIdx: 3 }).reason, 'data-declaration-not-a-check');
    const withCheck = `const ALLOWED_HOSTS = new Set(['api.example.com']);\napp.get('/p', async (req, res) => {\n  ${TARGET}\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) return res.status(400).end();\n  const r = await axios.get(target);\n});`;
    assert.equal(kept(withCheck, 5), false, 'control');
  });

  test('a validator in ANOTHER function clears the sink only if the sink\'s own code calls it first', () => {
    const helper = `function validateUrl(target) {\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) {\n    throw new Error('no');\n  }\n}\nfunction h(req) {\n  ${TARGET}\n  return fetch(target);\n}`;
    const called = `function validateUrl(target) {\n  if (!ALLOWED_HOSTS.has(new URL(target).hostname)) {\n    throw new Error('no');\n  }\n}\nfunction h(req) {\n  ${TARGET}\n  validateUrl(target);\n  return fetch(target);\n}`;
    assert.equal(kept(helper, 8), true, 'defined above, never called: kept');
    assert.equal(kept(called, 9), false, 'called before the sink: cleared');
    assert.equal(guardDominatesSink({ lines: lines(called), guardIdx: 1, sinkIdx: 8 }).reason, 'validator-helper-called-before-sink');
  });

  test('a validator helper that only validates on one path does not clear a sink that calls it', () => {
    const weak = `function check(t) {\n  if (strict) {\n    if (!ALLOWED_HOSTS.has(new URL(t).hostname)) throw new Error('no');\n  }\n}\nfunction h(req) {\n  ${TARGET}\n  check(target);\n  return fetch(target);\n}`;
    assert.equal(kept(weak, 9), true);
  });

  test('indentation languages follow the same rules (python): raise clears, print does not, a guard after the sink does not', () => {
    const py = (guard) => `def h(req):\n    target = req.args.get('u')\n${guard}\n    return requests.get(target)\n`;
    const raises = py("    if urlparse(target).hostname not in ALLOWED_HOSTS:\n        raise ValueError('no')");
    const prints = py("    if urlparse(target).hostname not in ALLOWED_HOSTS:\n        print('no')");
    const closed = py("    if DEBUG:\n        if urlparse(target).hostname not in ALLOWED_HOSTS:\n            raise ValueError('no')");
    assert.equal(kept(raises, 5, { file: 'a.py' }), false);
    assert.equal(kept(prints, 5, { file: 'a.py' }), true);
    assert.equal(kept(closed, 6, { file: 'a.py' }), true);
    const after = `def h(req):\n    target = req.args.get('u')\n    r = requests.get(target)\n    if urlparse(target).hostname not in ALLOWED_HOSTS:\n        raise ValueError('no')\n    return r\n`;
    assert.equal(kept(after, 3, { file: 'a.py' }), true);
  });

  test('a path-containment guard is judged the same way: helper called before the sink clears it, a bare definition or later check does not', () => {
    const ok = `fun buildPath(name: String): String {\n    val c = File(BASE, name).canonicalFile\n    if (!c.path.startsWith(BASE.path)) throw SecurityException("bad path")\n    return c.path\n}\nfun handler(req: Req) {\n    val path = buildPath(req.getParameter("file"))\n    val f = File(path)\n}`;
    const notCalled = `fun buildPath(name: String): String {\n    val c = File(BASE, name).canonicalFile\n    if (!c.path.startsWith(BASE.path)) throw SecurityException("bad path")\n    return c.path\n}\nfun handler(req: Req) {\n    val path = req.getParameter("file")\n    val f = File(path)\n}`;
    assert.equal(kept(ok, 8, { cwe: 'CWE-22', file: 'a.kt' }), false);
    assert.equal(kept(notCalled, 8, { cwe: 'CWE-22', file: 'a.kt' }), true);
  });

  test('an open-redirect target guard in the sink expression (the framework\'s own predicate) clears it; an unrelated allow-list definition does not', () => {
    const guarded = `public IActionResult Go(string next) {\n    return LocalRedirect(Url.IsLocalUrl(next) ? next : "/");\n}`;
    const bare = `public IActionResult Go(string next) {\n    return LocalRedirect(next);\n}`;
    assert.equal(kept(guarded, 2, { cwe: 'CWE-601', file: 'a.cs' }), false);
    assert.equal(kept(bare, 2, { cwe: 'CWE-601', file: 'a.cs' }), true);
  });

  test('the sibling-guard-omission family is still exempt: its claim IS the guard\'s presence', () => {
    const f = { id: 's', file: 'a.js', line: 4, cwe: 'CWE-22', family: 'sibling-guard-omission', vuln: 'x' };
    const src = `function h(a, b){\n  const x = safeJoin(base, a);\n  \n  return read(b);\n}`;
    assert.equal(dropGuardedFindings([f], { 'a.js': src }).length, 1);
  });
});

describe('[QA-005.AC02] a sanitizer must match the sink\'s context, and an unmodelled call clears nothing', () => {
  const finding = (over) => ({ id: 'f1', stableId: 'f1', cwe: 'CWE-89', vuln: 'SQL Injection', ...over });

  test('an HTML escaper on a SQL flow does not label it sanitized; a SQL-family sanitizer does', () => {
    const wrong = applySanitizerGate([finding()], { sanitizersOnPath: { f1: ['escapeHtml'] } })[0];
    assert.notEqual(wrong.sanitized, true);
    const right = applySanitizerGate([finding()], { sanitizersOnPath: { f1: ['parseInt'] } })[0];
    assert.equal(right.sanitized, true, 'control: a coercion applies to every injection family');
  });

  test('a callee the catalog does not know is not a sanitizer', () => {
    const f = applySanitizerGate([finding()], { sanitizersOnPath: { f1: ['cleanse', 'myHelper.makeSafe'] } })[0];
    assert.notEqual(f.sanitized, true);
  });

  test('an encoder\'s inverse on the path voids the claim', () => {
    const x = { id: 'x1', stableId: 'x1', cwe: 'CWE-79', vuln: 'Reflected XSS' };
    const ok = applySanitizerGate([{ ...x }], { sanitizersOnPath: { x1: ['escapeHtml'] } })[0];
    assert.equal(ok.sanitized, true);
    const undone = applySanitizerGate([{ ...x }], { sanitizersOnPath: { x1: ['escapeHtml'] }, unsanitizersOnPath: { x1: ['htmlspecialchars_decode'] } })[0];
    assert.notEqual(undone.sanitized, true);
    assert.equal(undone.sanitizerReversedBy, 'htmlspecialchars_decode');
  });

  test('end to end: an unmodelled cleaning function and a wrong-family escaper leave the SQL finding unsanitized; a coercion labels it', async () => {
    process.env.AGENTIC_SECURITY_DEEP = '1'; process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
    const scan = async (body) => {
      const dir = mkTestTmp('qa5-san-');
      fs.writeFileSync(path.join(dir, 'h.js'), body);
      const { scan: s } = await runScan(dir);
      return (s.findings || []).filter((f) => f.parser === 'IR-TAINT' && f.cwe === 'CWE-89');
    };
    try {
      const mk = (expr) => `const db = require('./db');\nmodule.exports = (req, res) => {\n  const q = ${expr};\n  db.query("SELECT * FROM users WHERE name = '" + q + "'");\n  res.end();\n};\n`;
      const unknown = await scan(mk('cleanse(req.query.name)'));
      const wrongFamily = await scan(`const escapeHtml = require('escape-html');\n${mk('escapeHtml(req.query.name)')}`);
      const coerced = await scan(mk('parseInt(req.query.name, 10)'));
      assert.equal(unknown.length, 1); assert.notEqual(unknown[0].sanitized, true);
      assert.equal(wrongFamily.length, 1); assert.notEqual(wrongFamily[0].sanitized, true);
      assert.equal(coerced.length, 1); assert.equal(coerced[0].sanitized, true, 'control: a real coercion is labelled');
    } finally { delete process.env.AGENTIC_SECURITY_DEEP; delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; }
  });
});

describe('[QA-005.AC01] a guard-recognized drop is a recorded suppression with a matchable identity and its positive blocking evidence', () => {
  test('the ledger entry names the finding (id, cwe, family, line), the mechanism and the dominating guard line', async () => {
    process.env.AGENTIC_SECURITY_DEEP = '1'; process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
    try {
      const dir = mkTestTmp('qa5-ledger-');
      fs.writeFileSync(path.join(dir, 'app.js'), fs.readFileSync(path.resolve(import.meta.dirname, '../fixtures/engine-mechanisms/guard-after-sink-js/post/app.js'), 'utf8'));
      const { scan } = await runScan(dir);
      const dropped = (scan.suppressions || []).filter((s) => String(s.reason).startsWith('guard-recognized:'));
      assert.ok(dropped.length >= 1, JSON.stringify(scan.suppressions));
      const d = dropped.find((s) => s.cwe === 'CWE-918');
      assert.ok(d, 'the SSRF candidate is in the ledger');
      assert.equal(d.family, 'ssrf'); assert.equal(typeof d.id, 'string'); assert.equal(d.file, 'app.js'); assert.equal(d.line, 10);
      assert.match(d.reason, /^guard-recognized:ssrf-host-guard:dominates@\d+:/);
      assert.equal((scan.findings || []).some((f) => f.cwe === 'CWE-918'), false, 'cleared, and the clearing is visible');
    } finally { delete process.env.AGENTIC_SECURITY_DEEP; delete process.env.AGENTIC_SECURITY_DEEP_IN_CI; }
  });
});
