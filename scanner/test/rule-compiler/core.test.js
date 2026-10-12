import test from 'node:test';
import assert from 'node:assert/strict';
import { draftRuleIR, validateRuleIR, compileToCustomRule, ruleIRDigest, RULE_STATES } from '../../src/posture/rule-compiler/ir.js';
import { checkEligibility } from '../../src/posture/rule-compiler/eligibility.js';
import { generateVariants, variableRename, wrapInFunction } from '../../src/posture/rule-compiler/mutation.js';
import { buildCorpus, scoreRule } from '../../src/posture/rule-compiler/corpus.js';
import { evaluateRule, gatePromotion, checkLeakage } from '../../src/posture/rule-compiler/promotion.js';
import { newLedger, recordTransition, verifyLedger, stateOf } from '../../src/posture/rule-compiler/lifecycle.js';

const VULN = 'const row = db.rawQuery("SELECT * FROM t WHERE id = " + userId);';
const PATCHED = 'const row = db.rawQuery("SELECT * FROM t WHERE id = ?", [userId]);';
const baseIR = (over = {}) => draftRuleIR({
  id: 'orm-raw-query-concat', title: 'ORM rawQuery built from concatenation', severity: 'critical', cwe: 'CWE-89',
  family: 'sql-injection', languages: ['javascript'], match: { pattern: 'rawQuery\\s*\\(\\s*["\'][^"\']*["\']\\s*\\+' },
  originatingFindingId: 'F1', evidenceState: 'taint-proven', ...over,
});

test('rule IR validation: closed match vocabulary, no shell, well-formed provenance', () => {
  assert.deepEqual(validateRuleIR(baseIR()), []);
  assert.ok(validateRuleIR({ ...baseIR(), cwe: 'nope' }).length);
  assert.ok(validateRuleIR({ ...baseIR(), match: { pattern: '(a+)+' } }).length === 0); // still a valid regex; ReDoS guard lives in custom-rules.js, not here
  assert.ok(validateRuleIR({ ...baseIR(), match: {} }).length);
  assert.ok(validateRuleIR({ ...baseIR(), provenance: { originatingFindingId: 'F1', evidenceState: 'model-said-so' } }).length);
  assert.equal(RULE_STATES[0], 'DRAFT');
});

test('compile emits a custom-rules.js-compatible document, not a parallel matcher', () => {
  const { ok, doc } = compileToCustomRule(baseIR());
  assert.equal(ok, true);
  assert.match(doc.id, /^rule-compiler\//);
  assert.ok(doc.match.pattern);
});

test('digest changes with content, not with mutable state fields', () => {
  const a = ruleIRDigest(baseIR());
  const b = ruleIRDigest({ ...baseIR(), state: 'PROMOTED' });
  assert.equal(a, b); // state is excluded
  const c = ruleIRDigest(baseIR({ title: 'different' }));
  assert.notEqual(a, c);
});

test('eligibility requires stable id, span, cwe/family, flow evidence, and corroboration', () => {
  const good = checkEligibility({ stableId: 'F1', file: 'a.js', line: 3, cwe: 'CWE-89', parser: 'IR-TAINT' });
  assert.equal(good.eligible, true);
  assert.equal(good.evidenceState, 'taint-proven');
  const bad = checkEligibility({ file: 'a.js', line: 3, parser: 'REGEX' });
  assert.equal(bad.eligible, false);
  assert.ok(bad.reasons.some((r) => r.includes('stable id')));
  assert.ok(bad.reasons.some((r) => r.includes('CWE')));
});

test('mutations do not change semantics by construction (variable rename, wrap) and apply only when they can', () => {
  const r = variableRename('const myVar = 1; return myVar;');
  assert.match(r, /myVar_v2/);
  assert.equal(variableRename('ALLCAPS + 1;'), null); // no lowercase identifier to rename
  const w = wrapInFunction('doThing();');
  assert.match(w, /^function wrapped_v2/);
  assert.ok(generateVariants(VULN).length >= 1);
});

test('corpus + scoring: positives fire (original and siblings), negatives decline (patched, siblings, nearby-clean)', () => {
  const ir = baseIR();
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED, nearbyCleanCode: ['db.rawQuery("SELECT * FROM t");'] });
  const score = scoreRule(ir, corpus);
  assert.equal(score.fn, 0);
  assert.equal(score.fp, 0);
  assert.equal(score.precision, 1);
  assert.equal(score.recall, 1);
});

test('promotion gate refuses below threshold and on protected-negative failures', () => {
  const ir = baseIR();
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED });
  const good = evaluateRule(ir, corpus);
  assert.equal(good.pass, true);

  // An overbroad pattern that also fires on the "protected" (sanitizer-carrying) variant must be refused.
  const overbroad = baseIR({ id: 'overbroad-raw-query', match: { pattern: 'rawQuery\\s*\\(' } });
  const corpus2 = buildCorpus(overbroad, { originalCode: VULN, patchedCode: PATCHED, protectedVariantsCode: [PATCHED] });
  const bad = evaluateRule(overbroad, corpus2);
  assert.equal(bad.pass, false);
  assert.ok(bad.reasons.some((r) => r.includes('protected-negative')));
});

test('leakage check refuses a prompt that embeds a protected advisory id', () => {
  const clean = checkLeakage(JSON.stringify({ originalCode: VULN }));
  assert.equal(clean.ok, true);
  const leaky = checkLeakage('see CVE-2024-12345 for the exact fixture', { benchmarkNames: ['CVE-2024-12345'] });
  assert.equal(leaky.ok, false);
});

test('gatePromotion refuses with no leakage check at all (fail closed, never fail open)', () => {
  const ir = baseIR();
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED });
  const r = gatePromotion({ ir, corpus, leakageCheck: null });
  assert.equal(r.pass, false);
  assert.ok(r.reasons.some((x) => x.includes('leakage')));
});

test('lifecycle ledger: valid edges only, chain is tamper-evident', () => {
  const ledger = newLedger();
  assert.equal(recordTransition(ledger, { ruleId: 'r1', from: 'DRAFT', to: 'PROMOTED', actor: 'x' }).ok, false); // no first entry yet; from must be null
  assert.equal(recordTransition(ledger, { ruleId: 'r1', from: null, to: 'DRAFT', actor: 'x' }).ok, true);
  assert.equal(recordTransition(ledger, { ruleId: 'r1', from: 'DRAFT', to: 'PROMOTED', actor: 'x' }).ok, false); // skips CANDIDATE/VALIDATED
  assert.equal(recordTransition(ledger, { ruleId: 'r1', from: 'DRAFT', to: 'CANDIDATE', actor: 'x' }).ok, true);
  assert.equal(stateOf(ledger, 'r1'), 'CANDIDATE');
  assert.equal(verifyLedger(ledger).ok, true);
  ledger.entries[0].to = 'VALIDATED'; // tamper
  assert.equal(verifyLedger(ledger).ok, false);
});

test('a rule cannot promote itself: no path from CANDIDATE to PROMOTED skipping VALIDATED', () => {
  const ledger = newLedger();
  recordTransition(ledger, { ruleId: 'r2', from: null, to: 'DRAFT', actor: 'x' });
  recordTransition(ledger, { ruleId: 'r2', from: 'DRAFT', to: 'CANDIDATE', actor: 'x' });
  assert.equal(recordTransition(ledger, { ruleId: 'r2', from: 'CANDIDATE', to: 'PROMOTED', actor: 'x' }).ok, false);
});
