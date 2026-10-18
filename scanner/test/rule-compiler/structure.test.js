// The rule IR's structural fields (PRD 3, requirement 2): source, propagator, sink, sanitizer, dominating guard, framework constraint,
// exclusions and language. Each must be a regular expression the runtime matcher ENFORCES; free text that looks like a constraint
// and is ignored is the mistake this file exists to prevent.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { mkTestTmp } from '../helpers/tmp.js';
import { runRule, normalizeCustomRule, loadCustomRules } from '../../src/posture/custom-rules.js';
import { draftRuleIR, validateRuleIR, compileToCustomRule } from '../../src/posture/rule-compiler/ir.js';
import { buildCorpus, scoreRule } from '../../src/posture/rule-compiler/corpus.js';
import { evaluateRule } from '../../src/posture/rule-compiler/promotion.js';
import { publishCustomRule } from '../../src/posture/rule-compiler/store.js';
import { proposeCandidates, synthesizeCandidate } from '../../src/posture/rule-compiler/proposal.js';

const base = (over = {}) => ({ id: 'sql-from-request', title: 'SQL built from a request value', severity: 'high', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'], evidenceState: 'execution-proven', originatingFindingId: 'F1', ...over });
const fire = (ir, code, file = 'x.js') => runRule(normalizeCustomRule(compileToCustomRule(ir).doc), file, code).length > 0;

const VULN = "const id = req.query.id;\nconst rows = await db.rawQuery('SELECT * FROM t WHERE id = ' + id);\n";
const GUARDED = "const id = escapeSql(req.query.id);\nconst rows = await db.rawQuery('SELECT * FROM t WHERE id = ' + id);\n";

test('the structure is consulted: source and sink co-occur, a sink alone does not fire, a source alone does not fire', () => {
  const ir = draftRuleIR(base({ source: String.raw`req\.query\b`, sink: String.raw`rawQuery\s*\(`, window: 4 }));
  assert.deepEqual(validateRuleIR(ir), []);
  const doc = compileToCustomRule(ir).doc;
  assert.deepEqual(doc.match.allOf, [String.raw`rawQuery\s*\(`, String.raw`req\.query\b`], 'the sink leads: the finding and the guards belong at the sink'); assert.equal(doc.match.window, 4);
  assert.equal(fire(ir, VULN), true);
  assert.equal(fire(ir, "db.rawQuery('SELECT 1');\n"), false, 'no source in the window');
  assert.equal(fire(ir, `const id = req.query.id;\n${'\n'.repeat(30)}db.rawQuery(x);\n`), false, 'source too far from the sink');
  const withProp = draftRuleIR(base({ source: String.raw`req\.query\b`, propagator: String.raw`\bparseInt\b`, sink: String.raw`rawQuery\s*\(`, window: 4 }));
  assert.equal(compileToCustomRule(withProp).doc.match.allOf.length, 3);
  assert.equal(fire(withProp, VULN), false, 'the propagator is part of the chain, so its absence means no match');
  assert.equal(fire(withProp, "const id = parseInt(req.query.id);\ndb.rawQuery('x' + id);\n"), true);
});

test('a sink alone is a pattern; an explicit match wins over the derived one', () => {
  assert.deepEqual(compileToCustomRule(draftRuleIR(base({ sink: String.raw`rawQuery\s*\(` }))).doc.match, { pattern: String.raw`rawQuery\s*\(` });
  const explicit = compileToCustomRule(draftRuleIR(base({ sink: 'ignored_sink', match: { pattern: 'explicit_wins' } }))).doc.match;
  assert.equal(explicit.pattern, 'explicit_wins');
});

test('sanitizer and dominating guard are LOCAL: they drop the hit they precede, not every hit in the file', () => {
  const ir = draftRuleIR(base({ source: String.raw`req\.query\b`, sink: String.raw`rawQuery\s*\(`, sanitizer: String.raw`escapeSql\s*\(`, window: 3 }));
  assert.equal(fire(ir, GUARDED), false, 'the sanitizer precedes the sink within the window');
  assert.equal(fire(ir, VULN), true);
  // two call sites in one file: the guarded one is quiet, the unguarded one still fires (a file-level notMatch would silence both)
  const two = `${GUARDED}\n${'\n'.repeat(12)}const other = req.query.name;\nawait db.rawQuery('SELECT * FROM u WHERE n = ' + other);\n`;
  assert.equal(fire(ir, two), true, 'the second, unguarded call is still reported');
  const fileLevel = draftRuleIR(base({ source: String.raw`req\.query\b`, sink: String.raw`rawQuery\s*\(`, match: { allOf: [String.raw`req\.query\b`, String.raw`rawQuery\s*\(`], window: 3, notMatch: String.raw`escapeSql\s*\(` } }));
  assert.equal(fire(fileLevel, two), false, 'the file-level exclusion silences the vulnerable call too, which is why the guard is a structural field');
  const guardAfter = "const rows = await db.rawQuery('x' + req.query.id);\nconst later = escapeSql(1);\n";
  assert.equal(fire(ir, guardAfter), true, 'a sanitizer AFTER the sink does not dominate it');
  const dom = draftRuleIR(base({ sink: String.raw`rawQuery\s*\(`, dominatingGuard: String.raw`if\s*\(\s*!isAdmin`, guardWindow: 3 }));
  assert.equal(fire(dom, "if (!isAdmin(u)) return;\ndb.rawQuery(q);\n"), false);
  assert.equal(fire(dom, "db.rawQuery(q);\n"), true);
});

test('framework constraint is a file-level precondition; exclusions drop a hit by its own line; language gates by extension', () => {
  const fw = draftRuleIR(base({ sink: String.raw`rawQuery\s*\(`, frameworkConstraint: String.raw`require\(['"]express['"]\)` }));
  assert.equal(fire(fw, "const express = require('express');\n\n\n\n\n\n\n\n\n\n\n\ndb.rawQuery(q);\n"), true, 'the marker may be far from the hit');
  assert.equal(fire(fw, 'db.rawQuery(q);\n'), false);
  const ex = draftRuleIR(base({ sink: String.raw`rawQuery\s*\(`, exclusions: [String.raw`//\s*audited`, String.raw`\btest\w*\.`] }));
  assert.equal(fire(ex, 'db.rawQuery(q); // audited\n'), false);
  assert.equal(fire(ex, 'testDb.rawQuery(q);\n'), false);
  assert.equal(fire(ex, 'db.rawQuery(q);\n'), true);
  assert.equal(fire(ex, 'db.rawQuery(q);\n', 'x.py'), false, 'a javascript rule does not run on a python file');
});

test('free text is rejected: a field that looks like a constraint cannot be ignored by the matcher', () => {
  for (const [k, v] of [['sink', 'the exec call ('], ['source', '[unclosed'], ['sanitizer', 'a(b'], ['frameworkConstraint', '*bad'], ['dominatingGuard', '(?<'], ['propagator', '+']]) {
    const e = validateRuleIR(draftRuleIR(base({ sink: 'ok', ...{ [k]: v } })));
    assert.ok(e.some((x) => x.includes(k)), `${k}: ${e.join('; ')}`);
  }
  assert.ok(validateRuleIR(draftRuleIR(base({ source: 'x' }))).some((e) => /needs a sink/.test(e)));
  assert.ok(validateRuleIR(draftRuleIR(base({}))).some((e) => /match required/.test(e)));
  assert.ok(validateRuleIR(draftRuleIR(base({ sink: 'x', exclusions: ['('] }))).some((e) => /invalid exclusion/.test(e)));
  assert.ok(validateRuleIR(draftRuleIR(base({ sink: 'x', guardWindow: 0 }))).some((e) => /guardWindow/.test(e)));
});

test('a rule the scanner\'s loader would reject is not compiled, so it can never score well and never fire', () => {
  const origErr = console.error; console.error = () => {};
  try {
    const r = compileToCustomRule(draftRuleIR(base({ match: { pattern: '(a+)+b' } })));
    assert.equal(r.ok, false); assert.match(r.errs[0], /rule loader would reject this rule/);
    const s = compileToCustomRule(draftRuleIR(base({ sink: 'ok', sanitizer: '(x+)+y' })));
    assert.equal(s.ok, false, 'a structural field gets the same safety check');
  } finally { console.error = origErr; }
});

test('published rule round-trips through YAML and the real loader with its structure intact', () => {
  const root = mkTestTmp('rc-struct-'); fs.mkdirSync(path.join(root, '.git'));
  const ir = draftRuleIR(base({ source: String.raw`req\.query\b`, sink: String.raw`rawQuery\s*\(`, sanitizer: String.raw`escapeSql\s*\(`, frameworkConstraint: 'express', exclusions: [String.raw`//\s*audited`], window: 3 }));
  assert.equal(publishCustomRule(root, ir).ok, true);
  const text = fs.readFileSync(path.join(root, '.agentic-security', 'rules', `${ir.id}.yml`), 'utf8');
  assert.match(text, /fileRequires:/); assert.match(text, /guardedBy:/); assert.match(text, /excludeLine:/);
  const origErr = console.error; console.error = () => {};
  process.env.AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS = '1';
  let rules; try { rules = loadCustomRules(root); } finally { delete process.env.AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS; console.error = origErr; }
  assert.equal(rules.length, 1);
  const run = (code) => runRule(rules[0], 'a.js', `// express\n${code}`).length > 0;
  assert.equal(run(VULN), true); assert.equal(run(GUARDED), false); assert.equal(run(`${VULN.trimEnd()} // audited\n`), false);
  assert.equal(runRule(rules[0], 'a.js', VULN).length, 0, 'without the framework marker the rule does not run');
});

test('synthesis proposes a structural candidate, and a structural candidate with the patched code\'s sanitizer meets the gate', () => {
  const PATCHED = "const id = req.query.id;\nconst rows = await db.rawQuery('SELECT * FROM t WHERE id = ' + escapeSql(id));\n";
  const props = proposeCandidates({ vulnerableCode: VULN, patchedCode: PATCHED });
  const st = props.find((p) => p.strategy === 'structural');
  assert.ok(st && st.structure.source && st.structure.sink && !st.match, 'a structure, not a hand-built match');
  assert.ok(props.every((p) => p.match || p.structure));
  // evaluated on a corpus: the unguarded call is caught, the sanitizer-guarded siblings are not
  const ir = draftRuleIR(base({ ...st.structure, sanitizer: String.raw`escapeSql\s*\(` }));
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: GUARDED, nearbyCleanCode: ["const n = 5;\nconsole.log(n);\n"], protectedVariantsCode: [GUARDED] });
  const ev = evaluateRule(ir, corpus);
  assert.equal(ev.score.protectedFailures, 0); assert.ok(ev.score.recall > 0 && ev.score.precision === 1, JSON.stringify({ p: ev.score.precision, r: ev.score.recall }));
  // and the loop itself carries a structure through to its attempts when that is what it tried
  const r = synthesizeCandidate({ base: base(), corpusSpec: { originalCode: VULN, patchedCode: PATCHED, nearbyCleanCode: [], protectedVariantsCode: [GUARDED] }, maxAttempts: 10 });
  assert.ok(r.attempts.length >= 1 && r.attempts.every((a) => a.match || a.structure));
});

test('scoring uses the loader\'s own normalizer: the corpus score and the production behavior cannot diverge', () => {
  const ir = draftRuleIR(base({ source: String.raw`(?:req(?:uest)?|ctx(?:\.request)?)\.(?:query|params|body|args)\b`, sink: String.raw`(?:rawQuery|executemany|execute|query)\s*\(`, sanitizer: String.raw`(?:escapeSql|validator\.escape)\s*\(`, window: 3 }));
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: GUARDED, nearbyCleanCode: [], protectedVariantsCode: [GUARDED] });
  const score = scoreRule(ir, corpus);
  assert.equal(score.recall, 1); assert.equal(score.protectedFailures, 0);
  assert.equal(evaluateRule(ir, corpus).pass, true);
});
