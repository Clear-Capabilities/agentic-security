// Contract test for the finding-to-rule compiler (docs/reference/rule-compiler-contract.md): drives the real commands over a fixture
// finding and holds the rule, the evaluation, the provenance record, the ledger, the status and the regression result to the page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { readPage, fieldsUnder, sameFields } from '../helpers/contract-page.js';
import { RULE_STATES, validateRuleIR, draftRuleIR } from '../../src/posture/rule-compiler/ir.js';
import { PROMOTION_DEFAULTS } from '../../src/posture/rule-compiler/promotion.js';
import { verifyLedger } from '../../src/posture/rule-compiler/lifecycle.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/rule-compiler-contract.md');
const ID = 'orm-raw-query-concat';
const spec = {
  id: ID, title: 'ORM rawQuery built from concatenation', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'],
  match: { pattern: 'rawQuery\\s*\\(\\s*["\'][^"\']*["\']\\s*\\+' },
  originalCode: 'const row = db.rawQuery("SELECT * FROM t WHERE id = " + userId);',
  patchedCode: 'const row = db.rawQuery("SELECT * FROM t WHERE id = ?", [userId]);',
  nearbyCleanCode: ['const n = items.length;'], protectedVariantsCode: [],
};

function project() {
  const root = mkTestTmp('agsec-rule-contract-');
  fs.writeFileSync(path.join(root, 'package.json'), '{"name":"rc","version":"1.0.0"}');
  fs.mkdirSync(path.join(root, '.agentic-security'));
  fs.writeFileSync(path.join(root, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ stableId: 'F1', id: 'F1', file: 'a.js', line: 3, cwe: 'CWE-89', parser: 'IR-TAINT', vuln: 'x', severity: 'high' }] }));
  fs.writeFileSync(path.join(root, 'spec.json'), JSON.stringify(spec));
  return root;
}
const rules = (root, ...a) => spawnSync(process.execPath, [CLI, 'rules', ...a], { cwd: root, encoding: 'utf8', timeout: 120000 });
const readJson = (root, ...p) => JSON.parse(fs.readFileSync(path.join(root, '.agentic-security', ...p), 'utf8'));

const root = project();
const synth = rules(root, 'synthesize', 'F1', '--spec', 'spec.json');
const evaluate = rules(root, 'evaluate', ID, '--json');
const promote = rules(root, 'promote', ID);
const status = JSON.parse(rules(root, 'status', '--json').stdout);
const regress = JSON.parse(rules(root, 'regress', '--json').stdout);
const dir = ['rule-compiler', ID];
const ir = readJson(root, ...dir, 'ir.json');
const provenance = readJson(root, ...dir, 'provenance.json');
const ledger = readJson(root, 'rule-compiler', 'ledger.json');

test('contract: the commands run in order with the documented exit codes', () => {
  assert.equal(synth.status, 0, synth.stderr);
  assert.equal(evaluate.status, 0, evaluate.stderr);
  assert.equal(promote.status, 0, promote.stderr);
  assert.equal(rules(root, 'evaluate', 'no-such-rule').status, 4, 'an unknown rule is a usage problem');
  assert.equal(rules(root, 'synthesize', 'NOPE', '--spec', 'spec.json').status, 4, 'an unknown finding is a usage problem');
  for (const code of ['`0`', '`1`', '`4`']) assert.ok(PAGE.includes(`| ${code} |`), `exit ${code} is on the page`);
});

test('contract: the rule has the documented fields; structure and corpus inputs are the only extras', () => {
  const carried = ['originalCode', 'patchedCode', 'nearbyCleanCode', 'protectedVariantsCode'];
  sameFields(ir, fieldsUnder(PAGE, 'Rule fields'), 'rule', carried);
  for (const k of carried) assert.ok(PAGE.includes(`\`${k}\``), `${k} is on the page`);
  sameFields(ir.provenance, fieldsUnder(PAGE, 'Rule provenance'), 'rule provenance');
  assert.equal(ir.schema, 'agentic-security/rule-ir');
  assert.equal(ir.version, 1);
});

test('contract: the lifecycle states are the documented six, in order', () => {
  assert.deepEqual([...RULE_STATES], ['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED', 'DEPRECATED', 'ROLLED_BACK']);
  for (const s of RULE_STATES) assert.ok(PAGE.includes(`\`${s}\``));
  assert.equal(status[0].state, 'PROMOTED');
});

test('contract: the evaluation, the score and the provenance record have the documented fields', () => {
  const ev = readJson(root, ...dir, 'evaluation.json');
  assert.ok(evaluate.stdout.startsWith(JSON.stringify(ev, null, 2)), '--json prints the stored evaluation');
  sameFields(ev, fieldsUnder(PAGE, 'Evaluation'), 'evaluation');
  sameFields(ev.evaluation, fieldsUnder(PAGE, 'Evaluation score'), 'evaluation score');
  sameFields(ev.evaluation.score, fieldsUnder(PAGE, 'Score'), 'score');
  sameFields(provenance, fieldsUnder(PAGE, 'Provenance record'), 'provenance record');
  assert.equal(provenance.schema, 'agentic-security/rule-provenance');
  assert.ok(provenance.promotionEvent && provenance.promotionEvent.actor, 'promotion is recorded in the provenance');
  assert.deepEqual(ev.evaluation.thresholds, PROMOTION_DEFAULTS);
  assert.equal(PROMOTION_DEFAULTS.minPrecision, 0.95);
  assert.equal(PROMOTION_DEFAULTS.minRecall, 0.8);
  assert.equal(PROMOTION_DEFAULTS.maxProtectedFailures, 0);
});

test('contract: the ledger entries, the status and the regression result have the documented fields', () => {
  sameFields(ledger.entries[0], fieldsUnder(PAGE, 'Ledger entry'), 'ledger entry');
  assert.deepEqual(ledger.entries.map(e => e.to), ['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED']);
  sameFields(status[0], fieldsUnder(PAGE, 'Status entry'), 'status entry');
  sameFields(regress.results[0], fieldsUnder(PAGE, 'Regression result'), 'regression result');
  assert.equal(regress.results[0].status, 'ok');
});

test('contract: promotion is not trust, an unsigned promoted rule is not live', () => {
  assert.equal(status[0].live, false);
  assert.match(promote.stdout, /NOT LIVE YET/);
});

test('contract: a broken ledger chain is detected, and a command that would change state refuses it', () => {
  assert.equal(verifyLedger(ledger).ok, true);
  const tampered = structuredClone(ledger);
  tampered.entries[1].reason = 'edited after the fact';
  assert.equal(verifyLedger(tampered).ok, false);
  const r2 = project();
  rules(r2, 'synthesize', 'F1', '--spec', 'spec.json');
  const file = path.join(r2, '.agentic-security', 'rule-compiler', 'ledger.json');
  const l = JSON.parse(fs.readFileSync(file, 'utf8'));
  l.entries[0].reason = 'edited';
  fs.writeFileSync(file, JSON.stringify(l));
  assert.equal(rules(r2, 'regress').status, 4, 'a tampered ledger refuses to run');
});

test('contract: a rule that fires on the safe code it is held to does not pass (exit 1), and the invalid rule is refused', () => {
  const r3 = project();
  const bad = { ...spec, id: 'too-broad-rule', match: { pattern: 'const' } };
  fs.writeFileSync(path.join(r3, 'spec.json'), JSON.stringify(bad));
  assert.equal(rules(r3, 'synthesize', 'F1', '--spec', 'spec.json').status, 0);
  assert.equal(rules(r3, 'evaluate', 'too-broad-rule').status, 1, 'the gate fails when the pattern fires on clean code');
  assert.deepEqual(validateRuleIR(draftRuleIR({ ...spec, originatingFindingId: 'F1', evidenceState: 'taint-proven', cwe: 'nope' })).length > 0, true);
});

test('contract: the comparison itself fails when a field is added or dropped', () => {
  const doc = fieldsUnder(PAGE, 'Status entry');
  assert.throws(() => sameFields({ ...status[0], extra: 1 }, doc, 'status'));
  const { live, ...rest } = status[0];
  assert.throws(() => sameFields(rest, doc, 'status'));
  assert.equal(live, false);
});
