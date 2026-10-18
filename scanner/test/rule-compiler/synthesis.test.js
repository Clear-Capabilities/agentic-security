// The rule compiler's remaining PRD 3 pieces: all seven mutators, deterministic proposal and the bounded synthesis loop, the
// anti-cheating leakage gate, and a safe side that is mutated too (so a rule keyed to one sanitizer is caught).
import test from 'node:test';
import assert from 'node:assert/strict';
import { generateVariants, mutatorCoverage, MUTATOR_NAMES, equivalentApi, alternateSanitizer, frameworkVariant, reorderStatements } from '../../src/posture/rule-compiler/mutation.js';
import { generalizeLine, proposeCandidates, safeNames, synthesizeCandidate } from '../../src/posture/rule-compiler/proposal.js';
import { checkLeakage, evaluateRule } from '../../src/posture/rule-compiler/promotion.js';
import { buildCorpus, scoreRule } from '../../src/posture/rule-compiler/corpus.js';
import { draftRuleIR } from '../../src/posture/rule-compiler/ir.js';

const base = (over = {}) => ({ id: 'raw-query-concat', title: 'SQL built by concatenation', severity: 'high', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], evidenceState: 'execution-proven', originatingFindingId: 'F1', ...over });
const VULN = "const id = req.query.id;\nconst rows = await db.rawQuery('SELECT * FROM users WHERE id = ' + id);\nres.json(rows);\n";
const SAFE = "const id = req.query.id;\nconst rows = await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);\nres.json(rows);\n";
const PROTECTED = "const id = parseInt(req.query.id, 10);\nconst rows = await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);\n";

test('all seven mutators exist, are deterministic, and never claim a variant they did not make', () => {
  assert.deepEqual([...MUTATOR_NAMES].sort(), ['alternate-sanitizer', 'equivalent-api', 'framework-variant', 'insert-indirection', 'reorder-statements', 'variable-rename', 'wrap-in-function']);
  const code = 'const q = req.query.id;\nconst note = 1;\ndb.query("SELECT " + q);\n';
  assert.deepEqual(generateVariants(code), generateVariants(code));
  for (const v of generateVariants(code)) assert.notEqual(v.code, code, v.mutator);
  assert.equal(generateVariants('').length, 0, 'nothing to mutate, nothing returned');
});

test('equivalent API, framework variant, alternate sanitizer and reordering each rewrite what they say and nothing else', () => {
  assert.equal(equivalentApi('child_process.exec(cmd);'), 'child_process.execSync(cmd);');
  assert.equal(equivalentApi('cursor.execute(sql)'), 'cursor.executemany(sql)');
  assert.equal(equivalentApi('nothing to see'), null);
  assert.equal(frameworkVariant('x = req.body.name;'), 'x = ctx.request.body.name;');
  assert.equal(frameworkVariant("y = request.args.get('q')"), "y = request.form.get('q')");
  assert.equal(frameworkVariant("z = $_GET['q'];"), "z = $_REQUEST['q'];");
  assert.equal(frameworkVariant('plain'), null);
  assert.equal(alternateSanitizer('out = escapeHtml(x);'), 'out = validator.escape(x);');
  assert.equal(alternateSanitizer("q = shlex.quote(x)"), 'q = pipes.quote(x)');
  assert.equal(alternateSanitizer('nothing'), null);
  assert.equal(reorderStatements('const a = 1;\nconst b = 2;\nfoo(a, b);\n'), 'const b = 2;\nconst a = 1;\nfoo(a, b);\n');
  assert.equal(reorderStatements('const a = 1;\nconst c = a + 1;\n'), null, 'a statement that uses the other is not swapped');
  assert.equal(reorderStatements('if (x) {\n  y();\n}\n'), null, 'control flow is never reordered');
  assert.deepEqual(mutatorCoverage('x = escapeHtml(req.body.n);\nres.send(x);\n').applied.includes('alternate-sanitizer'), true);
  assert.ok(mutatorCoverage('hello').notApplicable.length >= 4, 'coverage says what was not exercised');
});

test('the safe side is mutated: a rule keyed to ONE sanitizer name fails its protected siblings and cannot be promoted', () => {
  const SAFE_ESC = 'const name = escapeHtml(req.body.name);\nres.send("<b>" + name + "</b>");\n';
  const VULN_XSS = 'const name = req.body.name;\nres.send("<b>" + name + "</b>");\n';
  const brittle = draftRuleIR({ ...base({ id: 'xss-brittle', cwe: 'CWE-79', family: 'xss' }), match: { pattern: 'res\\.send\\(', notMatch: 'escapeHtml\\(' } });
  const corpus = buildCorpus(brittle, { originalCode: VULN_XSS, protectedVariantsCode: [SAFE_ESC] });
  assert.ok(corpus.negatives.some((n) => n.label === 'protected-0-sibling:alternate-sanitizer' && n.code.includes('validator.escape(')));
  const score = scoreRule(brittle, corpus);
  assert.ok(score.protectedFailures >= 1, 'it fires on the validator.escape sibling');
  assert.equal(evaluateRule(brittle, corpus).pass, false);
  const robust = draftRuleIR({ ...base({ id: 'xss-robust', cwe: 'CWE-79', family: 'xss' }), match: { pattern: 'res\\.send\\(', notMatch: '(?:escapeHtml|validator\\.escape|DOMPurify\\.sanitize)\\(' } });
  assert.equal(scoreRule(robust, buildCorpus(robust, { originalCode: VULN_XSS, protectedVariantsCode: [SAFE_ESC] })).protectedFailures, 0);
});

test('generalizeLine keeps the call, turns strings and other identifiers into classes, and still matches renamed code', () => {
  const rx = new RegExp(generalizeLine("const rows = await db.rawQuery('SELECT * FROM users WHERE id = ' + id);"));
  assert.ok(rx.test("const rows = await db.rawQuery('SELECT * FROM users WHERE id = ' + id);"));
  assert.ok(rx.test('const result = await db.rawQuery("SELECT * FROM orders WHERE id = " + orderId);'), 'renamed identifiers and a different string');
  assert.ok(!rx.test("const rows = await db.rawQuery('SELECT * FROM users WHERE id = ?', [id]);"), 'the parameterized call is a different shape');
  assert.ok(!rx.test('const rows = await db.otherQuery("x" + id);'));
  assert.doesNotThrow(() => new RegExp(generalizeLine('a.b.c(1, "x", `y${z}`) // end')));
});

test('proposals come from the lines only the vulnerable version has, and the safe version supplies the exclusion vocabulary', () => {
  const props = proposeCandidates({ vulnerableCode: VULN, patchedCode: SAFE });
  assert.ok(props.length >= 3);
  assert.equal(props[0].strategy, 'line-shape');
  assert.ok(props.some((p) => p.strategy === 'sink-with-interpolation'));
  assert.ok(props.some((p) => p.strategy === 'source-and-sink' && p.match.allOf && p.match.window));
  assert.ok(props.every((p) => { const parts = p.structure ? [p.structure.source, p.structure.sink] : (p.match.pattern ? [p.match.pattern] : p.match.allOf); return parts.every((r) => { try { new RegExp(r); return true; } catch { return false; } }); }));
  assert.deepEqual(safeNames({ vulnerableCode: VULN, patchedCode: SAFE }), ['?']);
  assert.ok(safeNames({ vulnerableCode: 'exec(cmd + x)', patchedCode: 'execFile("ls", [x])' }).includes('execFile'));
  assert.deepEqual(safeNames({ vulnerableCode: VULN, patchedCode: null }), []);
});

test('the synthesis loop finds a rule that passes the gate, bounded, deterministically, and says what it tried', () => {
  const corpusSpec = { originalCode: VULN, patchedCode: SAFE, nearbyCleanCode: ["const n = 5;\nconsole.log(n);\n", "const rows = await db.rawQuery('SELECT 1');\n"], protectedVariantsCode: [PROTECTED] };
  const a = synthesizeCandidate({ base: base(), corpusSpec });
  const b = synthesizeCandidate({ base: base(), corpusSpec });
  assert.deepEqual(a, b, 'no clock, no randomness');
  assert.equal(a.best.pass, true); assert.equal(a.exhausted, false);
  assert.equal(a.best.score.precision, 1); assert.equal(a.best.score.recall, 1); assert.equal(a.best.score.protectedFailures, 0);
  assert.ok(a.attempts.length >= 1 && a.attempts.length <= 6);
  assert.ok(a.attempts.every((x) => x.strategy && x.match));
});

test('a model\'s proposal is tried first; a bad one is revised from why it failed (the safe version is excluded) and the loop is bounded', () => {
  const corpusSpec = { originalCode: VULN, patchedCode: SAFE, nearbyCleanCode: [], protectedVariantsCode: [PROTECTED] };
  const overbroad = { pattern: 'rawQuery\\s*\\(' };
  const r = synthesizeCandidate({ base: base(), corpusSpec, proposed: overbroad });
  assert.equal(r.attempts[0].strategy, 'proposed'); assert.equal(r.attempts[0].pass, false);
  assert.ok(r.attempts[0].reasons.some((x) => /protected-negative|precision/.test(x)));
  assert.ok(r.attempts.some((x) => x.strategy === 'proposed+exclude-safe'), 'revised by excluding the safe version\'s vocabulary');
  assert.equal(r.best.pass, true, 'a later attempt is accepted instead');
  const capped = synthesizeCandidate({ base: base(), corpusSpec, proposed: overbroad, maxAttempts: 1 });
  assert.equal(capped.attempts.length, 1); assert.equal(capped.exhausted, true); assert.equal(capped.best.pass, false);
  const invalid = synthesizeCandidate({ base: base(), corpusSpec, proposed: { pattern: '(' }, maxAttempts: 2 });
  assert.equal(invalid.attempts[0].valid, false); assert.match(invalid.attempts[0].errors[0], /invalid regex/);
});

test('with no evidence of what makes the code safe or unsafe, the loop says so instead of inventing a rule', () => {
  const r = synthesizeCandidate({ base: base(), corpusSpec: { originalCode: '// nothing\n', patchedCode: '// nothing\n', nearbyCleanCode: [], protectedVariantsCode: [] } });
  assert.equal(r.best?.pass ?? false, false);
  assert.equal(r.exhausted, true);
  const unsafeOnly = synthesizeCandidate({ base: base(), corpusSpec: { originalCode: VULN, patchedCode: null, nearbyCleanCode: [], protectedVariantsCode: [SAFE] } });
  assert.ok(unsafeOnly.attempts.length >= 1);
});

test('anti-cheating: benchmark names, answer-key and CWE-bearing file names, vulnerability comments and advisory ids all fail closed', () => {
  assert.equal(checkLeakage('db.rawQuery(x + y)').ok, true);
  const hits = [
    ['a line from the OWASP Benchmark corpus', /benchmark name/], ['see juliet testcase', /benchmark name/], ['compare with the ground truth', /benchmark name/],
    ['fixed in CVE-2021-44228', /identifier/], ['// FLAW: this is the vulnerable call', /comment/], ['/* BAD */ exec(x)', /comment/], ['# vulnerable to injection\nos.system(x)', /comment/],
  ];
  for (const [text, re] of hits) { const r = checkLeakage(text); assert.equal(r.ok, false, text); assert.match(r.offendingTerms.join('|'), re, text); }
  const f = checkLeakage('x', { fileNames: ['src/CWE89_SQL_Injection__01.java', 'tests/expected.json', 'src/app.js', 'labels.csv'] });
  assert.equal(f.ok, false); assert.equal(f.offendingTerms.length, 3);
  assert.equal(checkLeakage('x', { benchmarkNames: ['project-zeta'] }).ok, true);
  assert.equal(checkLeakage('uses project-zeta', { benchmarkNames: ['project-zeta'] }).ok, false);
});
