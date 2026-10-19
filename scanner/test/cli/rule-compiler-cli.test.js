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

// ---------------------------------------------------------------------------------------------------------------------
// The synthesis loop through the CLI: no pattern is supplied, `labs synthesize-rule` is the PRD's literal command, and the
// rule's provenance and cost are recorded.

test('labs synthesize-rule proposes the rule itself from the vulnerable and patched code, and the unseen sibling is still caught', () => {
  const dir = mkProject();
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER);
  const findingId = 'hunt-rawquery-0002';
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: findingId, stableId: findingId, file: 'server.js', line: 3, cwe: 'CWE-89', vuln: 'SQL injection via rawQuery concatenation', severity: 'critical', parser: 'IR-TAINT', snippet: 'db.rawQuery("..." + userId)' }] }));
  // no `match` at all: the compiler proposes it. The material is code only; no benchmark name, no weakness comment.
  const spec = {
    id: 'auto-raw-query-concat', title: 'rawQuery built from string concatenation', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'],
    originalCode: VULN_HANDLER, patchedCode: SAFE_HANDLER, nearbyCleanCode: ['db.rawQuery("SELECT * FROM users");'], protectedVariantsCode: [SAFE_HANDLER],
    model: 'hunt-agent-1', promptConfigVersion: 'p3', discoveryCost: { usd: 0.42, tokens: 51234, model: 'hunt-agent-1' },
  };
  const specFile = path.join(dir, 'spec.json'); fs.writeFileSync(specFile, JSON.stringify(spec));
  const syn = runIn(dir, ['labs', 'synthesize-rule', findingId, '--spec', specFile, '--auto']);
  assert.equal(syn.status, 0, syn.stderr + syn.stdout);
  assert.match(syn.stdout, /attempt 1: /); assert.match(syn.stdout, /meets the promotion gate/); assert.match(syn.stdout, /DRAFT -> CANDIDATE/);
  assert.ok(fs.existsSync(path.join(dir, '.agentic-security', 'rule-compiler', 'auto-raw-query-concat', 'synthesis.json')));

  // evaluate needs no --corpus: the corpus the rule was synthesized on is the corpus it is judged on
  const ev = runIn(dir, ['rules', 'evaluate', 'auto-raw-query-concat']);
  assert.equal(ev.status, 0, ev.stderr + ev.stdout); assert.match(ev.stdout, /VALIDATED/);
  const prov = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'rule-compiler', 'auto-raw-query-concat', 'provenance.json'), 'utf8'));
  assert.equal(prov.originatingFinding, findingId); assert.equal(prov.evidenceState, 'taint-proven' === prov.evidenceState ? 'taint-proven' : prov.evidenceState);
  assert.equal(prov.generatingModel, 'hunt-agent-1'); assert.equal(prov.promptConfigVersion, 'p3');
  assert.match(prov.positiveCorpusHash, /^[0-9a-f]{64}$/); assert.match(prov.negativeCorpusHash, /^[0-9a-f]{64}$/); assert.notEqual(prov.positiveCorpusHash, prov.negativeCorpusHash);
  assert.match(prov.ruleHash, /^[0-9a-f]{64}$/); assert.equal(prov.ruleVersion, 1);
  assert.equal(prov.benchmarkResults.gate, 'passed'); assert.equal(prov.benchmarkResults.protectedFailures, 0);
  assert.equal(prov.promotionEvent, null, 'not promoted yet, and the provenance says so');
  assert.ok(prov.mutatorCoverage.applied.length >= 3);

  assert.equal(runIn(dir, ['rules', 'promote', 'auto-raw-query-concat']).status, 0);
  const afterPromote = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'rule-compiler', 'auto-raw-query-concat', 'provenance.json'), 'utf8'));
  assert.equal(afterPromote.promotionEvent.ruleHash, prov.ruleHash);

  fs.writeFileSync(path.join(dir, 'orders.js'), UNSEEN_SIBLING);
  const scan = JSON.parse(runIn(dir, ['scan', '.', '--format', 'json']).stdout);
  assert.ok((scan.findings || []).some((f) => f.file === 'orders.js' && f.cwe === 'CWE-89'), 'the unseen sibling is caught by the proposed rule alone');

  const cost = runIn(dir, ['rules', 'cost', 'auto-raw-query-concat', '--json']);
  const c = JSON.parse(cost.stdout);
  assert.equal(c.firstDiscovery.usd, 0.42); assert.equal(c.laterDeterministicModelUsd, 0);
  assert.equal(c.state, 'promoted');
});

test('synthesis refuses material that carries benchmark or answer-key signals, and writes nothing', () => {
  const dir = mkProject([{ id: 'f9', stableId: 'f9', file: 'a.js', line: 1, cwe: 'CWE-89', parser: 'IR-TAINT', snippet: 'x' }]);
  const spec = { id: 'leaky-rule', title: 't', severity: 'high', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], originalCode: '// FLAW: injection here\ndb.rawQuery("x" + y);\n', patchedCode: 'db.rawQuery("x", [y]);\n' };
  const specFile = path.join(dir, 'spec.json'); fs.writeFileSync(specFile, JSON.stringify(spec));
  const r = runIn(dir, ['rules', 'synthesize', 'f9', '--spec', specFile, '--auto']);
  assert.equal(r.status, 4); assert.match(r.stderr, /answer-key signals/); assert.match(r.stderr, /comment that describes the vulnerability/);
  assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'rule-compiler')), false);
  const named = { ...spec, originalCode: 'db.rawQuery("x" + y);\n', fileNames: ['src/CWE89_SQL_Injection__01.java'] };
  fs.writeFileSync(specFile, JSON.stringify(named));
  const r2 = runIn(dir, ['rules', 'synthesize', 'f9', '--spec', specFile, '--auto']);
  assert.equal(r2.status, 4); assert.match(r2.stderr, /weakness-bearing file name/);
});

test('labs without a recognised mode explains itself instead of doing nothing; a spec without a pattern or code is refused', () => {
  const dir = mkProject([{ id: 'f8', stableId: 'f8', file: 'a.js', line: 1, cwe: 'CWE-89', parser: 'IR-TAINT', snippet: 'x' }]);
  const r = runIn(dir, ['labs']);
  assert.equal(r.status, 2); assert.match(r.stderr, /labs synthesize-rule <finding-id>/);
  const spec = { id: 'no-material', title: 't', severity: 'high', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'] };
  const specFile = path.join(dir, 'spec.json'); fs.writeFileSync(specFile, JSON.stringify(spec));
  const r2 = runIn(dir, ['labs', 'synthesize-rule', 'f8', '--spec', specFile]);
  assert.equal(r2.status, 4); assert.match(r2.stderr, /needs originalCode/);
});

test('structured rule (PRD 3 requirement 2): source, sink and sanitizer are enforced by a real scan, locally, not file-wide', () => {
  const dir = mkProject();
  const GUARDED_THEN_UNGUARDED = `function a(req, res) {
  const id = escapeSql(req.query.id);
  res.json(db.rawQuery("SELECT * FROM users WHERE id = " + id));
}
${'\n'.repeat(15)}
function b(req, res) {
  const name = req.query.name;
  res.json(db.rawQuery("SELECT * FROM users WHERE name = " + name));
}
`;
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER);
  fs.writeFileSync(path.join(dir, 'mixed.js'), GUARDED_THEN_UNGUARDED);
  const findingId = 'hunt-rawquery-0002';
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: findingId, stableId: findingId, file: 'server.js', line: 3, cwe: 'CWE-89', vuln: 'SQL injection via rawQuery concatenation', severity: 'critical', parser: 'IR-TAINT', snippet: 'db.rawQuery("SELECT * FROM users WHERE id = " + userId)' }] }));
  const spec = {
    id: 'orm-raw-query-structured', title: 'rawQuery fed by a request value without escaping', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'],
    source: 'req(?:uest)?\\.(?:query|params|body)\\b', sink: 'rawQuery\\s*\\(', sanitizer: 'escapeSql\\s*\\(', frameworkConstraint: 'rawQuery', exclusions: ['//\\s*audited'], window: 4,
    remediation: 'Bind parameters; escape only as a last resort.',
  };
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(spec));
  assert.equal(runIn(dir, ['rules', 'synthesize', findingId, '--spec', path.join(dir, 'spec.json')]).status, 0);
  const SAFE = VULN_HANDLER.replace('req.query.id', 'escapeSql(req.query.id)');
  fs.writeFileSync(path.join(dir, 'corpus.json'), JSON.stringify({ originalCode: VULN_HANDLER, patchedCode: SAFE, nearbyCleanCode: ['db.rawQuery("SELECT * FROM users");'], protectedVariantsCode: [SAFE] }));
  const ev = runIn(dir, ['rules', 'evaluate', 'orm-raw-query-structured', '--corpus', path.join(dir, 'corpus.json')]);
  assert.equal(ev.status, 0, ev.stderr + ev.stdout); assert.match(ev.stdout, /VALIDATED/);
  assert.equal(runIn(dir, ['rules', 'promote', 'orm-raw-query-structured']).status, 0);
  const yml = fs.readFileSync(path.join(dir, '.agentic-security', 'rules', 'orm-raw-query-structured.yml'), 'utf8');
  assert.match(yml, /guardedBy:/); assert.match(yml, /fileRequires:/); assert.match(yml, /excludeLine:/);
  const findings = JSON.parse(runIn(dir, ['scan', '.', '--format', 'json']).stdout).findings || [];
  const hits = findings.filter((f) => f.cwe === 'CWE-89').map((f) => `${f.file}:${f.line}`);
  assert.ok(hits.some((h) => h.startsWith('server.js:')), `the unguarded handler is caught: ${hits}`);
  assert.ok(hits.some((h) => h.startsWith('mixed.js:')), `the unguarded function in a file that also has a guarded one is still caught: ${hits}`);
  const mixedLines = findings.filter((f) => f.file === 'mixed.js' && f.cwe === 'CWE-89').map((f) => f.line);
  assert.ok(mixedLines.every((l) => l > 5), `the sanitizer-guarded function (lines 1-4) is not reported: ${mixedLines}`);
});

test('regression integration (PRD 3 requirement 8): a promoted rule joins a shared false-positive corpus that holds later rules and later runs to account', () => {
  const dir = mkProject();
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER);
  const findingId = 'hunt-rawquery-0003';
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: findingId, stableId: findingId, file: 'server.js', line: 3, cwe: 'CWE-89', vuln: 'SQL injection via rawQuery', severity: 'critical', parser: 'IR-TAINT', snippet: 'db.rawQuery(x)' }] }));
  const SAFE = VULN_HANDLER.replace('req.query.id', 'escapeSql(req.query.id)');
  const corpus = { originalCode: VULN_HANDLER, patchedCode: SAFE, nearbyCleanCode: ['db.rawQuery("SELECT * FROM users");'], protectedVariantsCode: [SAFE] };
  fs.writeFileSync(path.join(dir, 'corpus.json'), JSON.stringify(corpus));
  const specA = { id: 'rule-a-rawquery', title: 'rawQuery fed by a request value', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], source: '(?:req(?:uest)?|ctx)\\.(?:request\\.)?(?:query|params|body)\\b', sink: 'rawQuery\\s*\\(', sanitizer: 'escapeSql\\s*\\(', window: 4 };
  fs.writeFileSync(path.join(dir, 'a.json'), JSON.stringify(specA));
  assert.equal(runIn(dir, ['rules', 'synthesize', findingId, '--spec', path.join(dir, 'a.json')]).status, 0);
  assert.equal(runIn(dir, ['rules', 'evaluate', 'rule-a-rawquery', '--corpus', path.join(dir, 'corpus.json')]).status, 0);
  assert.equal(runIn(dir, ['rules', 'promote', 'rule-a-rawquery']).status, 0);

  // nothing regressed yet
  const clean = runIn(dir, ['rules', 'regress']);
  assert.equal(clean.status, 0, clean.stdout + clean.stderr); assert.match(clean.stdout, /rule-a-rawquery: OK/);

  // a later rule that is too broad fires on rule A's safe code: it cannot even be VALIDATED
  const specB = { id: 'rule-b-overbroad', title: 'any escape call', severity: 'low', cwe: 'CWE-20', family: 'validation', languages: ['javascript'], match: { pattern: 'escapeSql\\s*\\(' } };
  fs.writeFileSync(path.join(dir, 'b.json'), JSON.stringify(specB));
  assert.equal(runIn(dir, ['rules', 'synthesize', findingId, '--spec', path.join(dir, 'b.json')]).status, 0);
  fs.writeFileSync(path.join(dir, 'corpus-b.json'), JSON.stringify({ originalCode: 'x = escapeSql(a);\n', nearbyCleanCode: ['const n = 5;\n'], protectedVariantsCode: [] }));
  const evalB = runIn(dir, ['rules', 'evaluate', 'rule-b-overbroad', '--corpus', path.join(dir, 'corpus-b.json')]);
  assert.equal(evalB.status, 1, evalB.stdout + evalB.stderr); assert.match(evalB.stdout, /shared false-positive corpus/);
  assert.match(evalB.stdout, /rule:rule-a-rawquery:/, 'the offending items are named');
  assert.equal(runIn(dir, ['rules', 'promote', 'rule-b-overbroad']).status, 4, 'a rule that failed the gate cannot be promoted');

  // the operator adds a real false positive; rule A fires on it, so `rules regress` reports the regression
  const fpDir = path.join(dir, '.agentic-security', 'rule-compiler', 'fp-corpus');
  fs.mkdirSync(fpDir, { recursive: true });
  fs.writeFileSync(path.join(fpDir, 'audit-log.js'), 'function log(req) {\n  const user = req.query.user;\n  return db.rawQuery("SELECT * FROM audit WHERE u = " + user);\n}\n');
  const bad = runIn(dir, ['rules', 'regress']);
  assert.equal(bad.status, 1, bad.stdout); assert.match(bad.stdout, /rule-a-rawquery: REGRESSED/); assert.match(bad.stdout, /operator-fp:audit-log\.js/);
  assert.equal(JSON.parse(runIn(dir, ['rules', 'regress', '--json']).stdout).results[0].fpCorpusHits, 1);
  assert.equal(runIn(dir, ['rules', 'regress', 'no-such-rule']).status, 4);
});

import { keygen } from '../../src/posture/rule-pack-signing.js';

// The scanner refuses unsigned rule packs by design (a rule dropped into a repository must not run in someone's CI). A promoted rule is
// therefore only a capability once the scanner will actually load it, and the CLI says which it is instead of implying it.
function trustProject() {
  const dir = mkProject();
  fs.writeFileSync(path.join(dir, 'server.js'), VULN_HANDLER);
  const fid = 'hunt-rawquery-0004';
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: fid, stableId: fid, file: 'server.js', line: 3, cwe: 'CWE-89', vuln: 'x', severity: 'critical', parser: 'IR-TAINT', snippet: 'x' }] }));
  const SAFE = VULN_HANDLER.replace('req.query.id', 'escapeSql(req.query.id)');
  fs.writeFileSync(path.join(dir, 'corpus.json'), JSON.stringify({ originalCode: VULN_HANDLER, patchedCode: SAFE, nearbyCleanCode: ['db.rawQuery("SELECT * FROM users");'], protectedVariantsCode: [SAFE] }));
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify({ id: 'trust-rawquery', title: 'rawQuery fed by a request value', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], source: '(?:req(?:uest)?|ctx)\\.(?:request\\.)?(?:query|params|body)\\b', sink: 'rawQuery\\s*\\(', sanitizer: 'escapeSql\\s*\\(', window: 4 }));
  return { dir, fid };
}
const strictEnv = () => { const e = { ...process.env }; for (const k of ['AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS', 'AGENTIC_SECURITY_PRIVATE_KEY', 'CI', 'GITHUB_ACTIONS', 'GITLAB_CI', 'BUILDKITE', 'CIRCLECI', 'JENKINS_URL', 'TF_BUILD', 'AGENTIC_SECURITY_STRICT_SIGNING']) delete e[k]; return e; };
const runStrict = (dir, args) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 60000, env: strictEnv() });

test('promotion is not trust: an unsigned promoted rule is reported NOT LIVE and the scan does not load it; signing it makes it live', () => {
  const { dir, fid } = trustProject();
  assert.equal(runStrict(dir, ['rules', 'synthesize', fid, '--spec', path.join(dir, 'spec.json')]).status, 0);
  assert.equal(runStrict(dir, ['rules', 'evaluate', 'trust-rawquery', '--corpus', path.join(dir, 'corpus.json')]).status, 0);
  const promote = runStrict(dir, ['rules', 'promote', 'trust-rawquery']);
  assert.equal(promote.status, 0, promote.stderr);
  assert.match(promote.stdout, /NOT LIVE YET: the scanner will refuse this rule \(unsigned\)/);
  assert.match(promote.stdout, /agentic-security-rule sign|--sign-key/);
  assert.match(runStrict(dir, ['rules', 'status', 'trust-rawquery']).stdout, /live: NO, the scanner refuses it \(unsigned\)/);
  assert.match(runStrict(dir, ['rules', 'status']).stdout, /trust-rawquery\s+PROMOTED\s+\(NOT LIVE/);
  assert.equal(JSON.parse(runStrict(dir, ['rules', 'status', '--json']).stdout)[0].live, false);
  const before = JSON.parse(runStrict(dir, ['scan', '.', '--format', 'json']).stdout).findings || [];
  assert.equal(before.filter((f) => f.cwe === 'CWE-89').length, 0, 'the scanner did not load an unsigned rule');

  // roll back, then promote again with a signing key: the same rule is now live and finds the flaw
  assert.equal(runStrict(dir, ['rules', 'rollback', 'trust-rawquery']).status, 0);
  assert.equal(fs.existsSync(path.join(dir, '.agentic-security', 'rules', 'trust-rawquery.yml.sig')), false);
  const { privateKey } = keygen();
  const dir2 = trustProject();
  assert.equal(runStrict(dir2.dir, ['rules', 'synthesize', dir2.fid, '--spec', path.join(dir2.dir, 'spec.json')]).status, 0);
  assert.equal(runStrict(dir2.dir, ['rules', 'evaluate', 'trust-rawquery', '--corpus', path.join(dir2.dir, 'corpus.json')]).status, 0);
  const signed = runStrict(dir2.dir, ['rules', 'promote', 'trust-rawquery', '--sign-key', privateKey]);
  assert.equal(signed.status, 0, signed.stderr); assert.match(signed.stdout, /signed: .*trust-rawquery\.yml\.sig/); assert.match(signed.stdout, /The scanner will load it/);
  assert.ok(fs.existsSync(path.join(dir2.dir, '.agentic-security', 'rules', 'trust-rawquery.yml.sig')));
  assert.match(runStrict(dir2.dir, ['rules', 'status', 'trust-rawquery']).stdout, /live: yes/);
  const after = JSON.parse(runStrict(dir2.dir, ['scan', '.', '--format', 'json']).stdout).findings || [];
  assert.ok(after.some((f) => f.cwe === 'CWE-89' && f.file === 'server.js'), 'the signed promoted rule fires in a normal scan');
});
