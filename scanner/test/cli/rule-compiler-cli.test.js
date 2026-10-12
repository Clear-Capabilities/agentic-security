// Killer E2E scenario (PRD 3): the deterministic scanner misses a real vulnerability shape (`db.rawQuery`
// string-concatenation — verified below to score 0 findings from a real `scan` before anything else happens).
// A rule is synthesized from that one finding, validated against its own corpus, promoted, and a STRUCTURALLY
// DIFFERENT unseen sibling (variable renamed, wrapped in another function, different file) is then caught by a
// plain deterministic `scan` with NO model call — the promoted rule is loaded through the exact pre-existing
// `loadCustomRules`/`applyCustomRules` path.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const run = (args, opts = {}) => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS: '1' }, ...opts });
const runIn = (dir, args, opts = {}) => run(args, { cwd: dir, ...opts });

function mkProject(findings = []) {
  const dir = mkTestTmp('rc-cli-');
  fs.mkdirSync(path.join(dir, '.git'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings }));
  return dir;
}

const VULN_HANDLER = `function handler(req, res) {
  const userId = req.query.id;
  const row = db.rawQuery("SELECT * FROM users WHERE id = " + userId);
  res.json(row);
}
module.exports = handler;
`;
// Structurally different: renamed identifiers, wrapped in an outer function, a different file entirely.
const UNSEEN_SIBLING = `function orderHandler(request, response) {
  function run() {
    const orderId = request.params.orderId;
    const result = db.rawQuery("SELECT * FROM orders WHERE id = " + orderId);
    response.json(result);
  }
  run();
}
module.exports = orderHandler;
`;
const SAFE_HANDLER = `function handler(req, res) {
  const userId = req.query.id;
  const row = db.rawQuery("SELECT * FROM users WHERE id = ?", [userId]);
  res.json(row);
}
module.exports = handler;
`;

test('killer scenario: deterministic engine misses it, rule compiler learns it, promoted rule catches an unseen sibling with zero model calls', () => {
  const dir = mkProject();
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER);

  // 1. Confirm the genuine miss: the deterministic engine does not flag this shape today.
  const preScan = runIn(dir, ['scan', '.', '--format', 'json']);
  const preFindings = JSON.parse(preScan.stdout).findings || [];
  assert.equal(preFindings.length, 0, `expected the deterministic engine to miss this shape; got ${JSON.stringify(preFindings)}`);

  // 2. hunt (in a real deployment) or a reviewer finds it; recorded here as a last-scan.json entry (what either
  // path leaves behind) with IR-TAINT-equivalent flow evidence.
  const findingId = 'hunt-rawquery-0001';
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{
    id: findingId, stableId: findingId, file: 'server.js', line: 3, cwe: 'CWE-89', vuln: 'SQL injection via rawQuery concatenation',
    severity: 'critical', parser: 'IR-TAINT', snippet: 'db.rawQuery("SELECT * FROM users WHERE id = " + userId)',
  }] }));

  // 3. Synthesize: the candidate pattern is supplied (a model would propose this; nothing here calls one).
  const spec = {
    id: 'orm-raw-query-concat', title: 'ORM rawQuery built from string concatenation', severity: 'critical', cwe: 'CWE-89',
    family: 'sql-injection', languages: ['javascript'], match: { pattern: 'rawQuery\\s*\\(\\s*["\'][^"\']*["\']\\s*\\+' },
    remediation: 'Bind parameters; never concatenate untrusted input into rawQuery().',
  };
  const specFile = path.join(dir, 'spec.json');
  fs.writeFileSync(specFile, JSON.stringify(spec));
  const syn = runIn(dir, ['rules', 'synthesize', findingId, '--spec', specFile]);
  assert.equal(syn.status, 0, syn.stderr + syn.stdout);
  assert.match(syn.stdout, /DRAFT -> CANDIDATE/);

  // 4. Evaluate against a corpus the caller supplies (original + an explicit patch + a nearby clean call).
  const corpus = {
    originalCode: VULN_HANDLER, patchedCode: SAFE_HANDLER,
    nearbyCleanCode: ['db.rawQuery("SELECT * FROM users");'],
    protectedVariantsCode: [SAFE_HANDLER],
  };
  const corpusFile = path.join(dir, 'corpus.json');
  fs.writeFileSync(corpusFile, JSON.stringify(corpus));
  const evalR = runIn(dir, ['rules', 'evaluate', 'orm-raw-query-concat', '--corpus', corpusFile]);
  assert.equal(evalR.status, 0, evalR.stderr + evalR.stdout);
  assert.match(evalR.stdout, /VALIDATED/);
  assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'rule-compiler', 'orm-raw-query-concat', 'fixtures')));

  // 5. Promote: ONLY now does anything become a live, loaded rule.
  const beforePromote = runIn(dir, ['scan', '.', '--format', 'json']);
  assert.equal((JSON.parse(beforePromote.stdout).findings || []).length, 0, 'must not be live before promotion');
  const promote = runIn(dir, ['rules', 'promote', 'orm-raw-query-concat']);
  assert.equal(promote.status, 0, promote.stderr + promote.stdout);
  assert.match(promote.stdout, /VALIDATED -> PROMOTED/);
  assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'rules', 'orm-raw-query-concat.yml')));

  // 6. The ORIGINAL finding's own file is now caught by the promoted deterministic rule.
  const postOriginal = runIn(dir, ['scan', '.', '--format', 'json']);
  const postFindings = JSON.parse(postOriginal.stdout).findings || [];
  assert.ok(postFindings.some((f) => f.cwe === 'CWE-89' && f.file === 'server.js'), JSON.stringify(postFindings));

  // 7. THE KILLER CHECK: an UNSEEN sibling, never part of the corpus, in a different file, with renamed
  // identifiers and extra indirection, is caught too — by the deterministic rule alone, no model call possible
  // in this environment (no AGENTIC_SECURITY_LLM_ENDPOINT is set).
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER); // keep the original present too
  fs.writeFileSync(path.join(dir, 'orders.js'), UNSEEN_SIBLING);
  const final = runIn(dir, ['scan', '.', '--format', 'json']);
  const finalFindings = JSON.parse(final.stdout).findings || [];
  assert.ok(finalFindings.some((f) => f.file === 'orders.js' && f.cwe === 'CWE-89'), `unseen sibling was not caught: ${JSON.stringify(finalFindings)}`);

  // 8. Status and rollback both work and are reflected immediately.
  const status = runIn(dir, ['rules', 'status', 'orm-raw-query-concat']);
  assert.equal(status.status, 0);
  assert.match(status.stdout, /PROMOTED/);
  const rollback = runIn(dir, ['rules', 'rollback', 'orm-raw-query-concat']);
  assert.equal(rollback.status, 0, rollback.stderr);
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security', 'rules', 'orm-raw-query-concat.yml')));
  const afterRollback = runIn(dir, ['scan', '.', '--format', 'json']);
  assert.equal((JSON.parse(afterRollback.stdout).findings || []).filter((f) => f.cwe === 'CWE-89').length, 0);
});

test('a rule that would also fire on its own protected/sanitized variant is refused, never promoted', () => {
  const dir = mkProject([{ id: 'f2', stableId: 'f2', file: 'a.js', line: 1, cwe: 'CWE-89', parser: 'IR-TAINT', snippet: 'rawQuery(' }]);
  const spec = { id: 'overbroad-rawquery', title: 'overbroad', severity: 'high', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], match: { pattern: 'rawQuery\\s*\\(' } };
  const specFile = path.join(dir, 'spec.json');
  fs.writeFileSync(specFile, JSON.stringify(spec));
  assert.equal(runIn(dir, ['rules', 'synthesize', 'f2', '--spec', specFile]).status, 0);
  const corpus = { originalCode: 'db.rawQuery("x" + y);', protectedVariantsCode: ['db.rawQuery("x", [y]);'] };
  const corpusFile = path.join(dir, 'corpus.json');
  fs.writeFileSync(corpusFile, JSON.stringify(corpus));
  const evalR = runIn(dir, ['rules', 'evaluate', 'overbroad-rawquery', '--corpus', corpusFile]);
  assert.equal(evalR.status, 1);
  assert.match(evalR.stdout, /gate FAILED/);
  const promote = runIn(dir, ['rules', 'promote', 'overbroad-rawquery']);
  assert.equal(promote.status, 4);
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security', 'rules', 'overbroad-rawquery.yml')));
});

test('synthesize refuses an ineligible finding (no CWE/family, no flow evidence)', () => {
  const dir = mkProject([{ id: 'f3', stableId: 'f3', file: 'a.js', line: 1, parser: 'REGEX' }]);
  const spec = { id: 'x', title: 'x', severity: 'low', cwe: 'CWE-1', family: 'x', languages: ['javascript'], match: { pattern: 'x' } };
  const specFile = path.join(dir, 'spec.json');
  fs.writeFileSync(specFile, JSON.stringify(spec));
  const r = runIn(dir, ['rules', 'synthesize', 'f3', '--spec', specFile]);
  assert.equal(r.status, 4);
  assert.match(r.stderr, /Not eligible/);
});
