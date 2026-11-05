// GA-07 gates on the rule compiler (0.195.23): the superlinear-regex guard, the signed lifecycle ledger, the reviewed promotion with
// provenance and conflict checks, and the independent-example requirement. Each is pinned in both directions through the real CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { normalizeCustomRule, unsafePatternReason } from '../../src/posture/custom-rules.js';
import { buildCorpus, scoreRule } from '../../src/posture/rule-compiler/corpus.js';
import { gatePromotion, evaluateRule } from '../../src/posture/rule-compiler/promotion.js';
import { draftRuleIR } from '../../src/posture/rule-compiler/ir.js';
import { loadLedger, saveLedger } from '../../src/posture/rule-compiler/store.js';
import { newLedger, recordTransition } from '../../src/posture/rule-compiler/lifecycle.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const baseEnv = { ...process.env, AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS: '1' };
delete baseEnv.AGENTIC_SECURITY_RULES_UNSIGNED;
const run = (dir, args, env = {}) => spawnSync(process.execPath, [CLI, ...args], { cwd: dir, encoding: 'utf8', timeout: 60000, env: { ...baseEnv, ...env } });

const VULN = 'const row = db.rawQuery("SELECT * FROM t WHERE id = " + userId);\n';
const PATCHED = 'const row = db.rawQuery("SELECT * FROM t WHERE id = ?", [userId]);\n';
const IND_VULN = 'const rows = db.rawQuery("SELECT * FROM orders WHERE owner = " + ownerId);\n';
const IND_CLEAN = 'const rows = db.rawQuery("SELECT * FROM orders WHERE owner = ?", [ownerId]);\n';
const SPEC = {
  id: 'orm-raw-query-concat', title: 'rawQuery built from concatenation', severity: 'critical', cwe: 'CWE-89', family: 'sql-injection', languages: ['javascript'],
  match: { pattern: 'rawQuery\\s*\\(\\s*["\'][^"\']*["\']\\s*\\+' },
  originalCode: VULN, patchedCode: PATCHED, nearbyCleanCode: ['const n = items.length;'], protectedVariantsCode: [],
  independentVulnerableCode: [IND_VULN], independentCleanCode: [IND_CLEAN],
};
const REVIEWED = ['--reviewed-by', 'a reviewer', '--scope', 'the fixture project'];

function project({ spec = SPEC, git = false } = {}) {
  const dir = mkTestTmp('rc-gates-');
  if (git) {
    execFileSync('git', ['init', '-q'], { cwd: dir });
    fs.writeFileSync(path.join(dir, 'a.js'), `${VULN}// ${path.basename(dir)}\n`); // distinct content, so two fixture repositories never share a commit id
    execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'add', '.'], { cwd: dir });
    execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init'], { cwd: dir });
  } else fs.mkdirSync(path.join(dir, '.git'));
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: 'F1', stableId: 'F1', file: 'a.js', line: 1, cwe: 'CWE-89', parser: 'IR-TAINT', vuln: 'x', severity: 'high', snippet: VULN }] }));
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(spec));
  return dir;
}
const ledgerFile = (dir) => path.join(dir, '.agentic-security', 'rule-compiler', 'ledger.json');
const validated = (dir) => { assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0); const ev = run(dir, ['rules', 'evaluate', SPEC.id]); assert.equal(ev.status, 0, ev.stdout + ev.stderr); };

test('regex guard: an ambiguous alternation under a quantifier is refused by the loader, not only nested quantifiers', () => {
  assert.equal(unsafePatternReason('(a+)+b'), 'nested quantifiers');
  assert.equal(unsafePatternReason('(a|a)*b'), 'alternation ambiguity under quantifier');
  assert.equal(unsafePatternReason('rawQuery\\s*\\('), null);
  const origErr = console.error; console.error = () => {};
  try {
    assert.equal(normalizeCustomRule({ id: 'x', match: { pattern: '(a|a)*b' } }), null, 'the loader refuses it');
    assert.ok(normalizeCustomRule({ id: 'x', match: { pattern: 'rawQuery\\s*\\(' } }), 'a plain pattern still loads');
  } finally { console.error = origErr; }
});

test('independent examples: the gate refuses without them, counts them apart, and requires every vulnerable one detected and no safe one fired on', () => {
  const ir = draftRuleIR({ ...SPEC, originatingFindingId: 'F1', evidenceState: 'taint-proven' });
  const leak = { ok: true, offendingTerms: [] };
  const without = gatePromotion({ ir, corpus: buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED }), leakageCheck: leak });
  assert.equal(without.pass, false);
  assert.ok(without.reasons.some((r) => /independent vulnerable/.test(r)) && without.reasons.some((r) => /independent safe/.test(r)), without.reasons.join('; '));
  assert.equal(evaluateRule(ir, buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED })).pass, true, 'the synthesis-time score does not need them');
  const corpus = buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED, independentVulnerableCode: [IND_VULN], independentCleanCode: [IND_CLEAN] });
  assert.ok(!corpus.positives.some((p) => p.label.startsWith('independent-vulnerable-0-sibling')), 'independent examples are never mutated');
  const score = scoreRule(ir, corpus);
  assert.deepEqual(score.independent, { positives: 1, negatives: 1, detected: 1, falseAlarms: 0 });
  const withThem = gatePromotion({ ir, corpus, leakageCheck: leak });
  assert.equal(withThem.pass, true, withThem.reasons.join('; '));
  const missed = gatePromotion({ ir, corpus: buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED, independentVulnerableCode: ['const r = db.rawQuery(sql);\n'], independentCleanCode: [IND_CLEAN] }), leakageCheck: leak });
  assert.equal(missed.pass, false);
  assert.ok(missed.reasons.some((r) => /misses 1 of 1 independent vulnerable/.test(r)), missed.reasons.join('; '));
  const noisy = gatePromotion({ ir, corpus: buildCorpus(ir, { originalCode: VULN, patchedCode: PATCHED, independentVulnerableCode: [IND_VULN], independentCleanCode: [IND_VULN] }), leakageCheck: leak });
  assert.ok(noisy.reasons.some((r) => /fires on 1 of 1 independent safe/.test(r)), noisy.reasons.join('; '));
});

test('signed ledger: a saved ledger carries a signature, an edited one refuses every command, and it is never replaced by an empty one', () => {
  const dir = project();
  validated(dir);
  const f = ledgerFile(dir);
  assert.ok(fs.existsSync(`${f}.sig`), 'the ledger is signed on save');
  const before = fs.readFileSync(f, 'utf8');
  const l = JSON.parse(before);
  l.entries[0].reason = 'edited';
  fs.writeFileSync(f, JSON.stringify(l));
  for (const args of [['rules', 'status'], ['rules', 'status', SPEC.id], ['rules', 'regress'], ['rules', 'cost', SPEC.id], ['rules', 'promote', SPEC.id, ...REVIEWED], ['rules', 'rollback', SPEC.id], ['rules', 'synthesize', 'F1', '--spec', 'spec.json'], ['rules', 'evaluate', SPEC.id]]) {
    const r = run(dir, args);
    assert.equal(r.status, 4, `${args.join(' ')}: ${r.stdout}${r.stderr}`);
    assert.match(r.stderr, /integrity check/);
  }
  assert.equal(JSON.parse(fs.readFileSync(f, 'utf8')).entries.length, l.entries.length, 'the tampered ledger was not overwritten');
  const loaded = loadLedger(dir);
  assert.equal(loaded.tampered, true);
  assert.equal(saveLedger(dir, loaded).ok, false, 'a tampered ledger cannot be saved');
  // a re-signed but chain-broken file is still refused: both checks hold
  fs.writeFileSync(f, before);
  fs.writeFileSync(`${f}.sig`, 'deadbeef');
  assert.match(run(dir, ['rules', 'status']).stderr, /signature does not verify/);
});

test('signed ledger: an unsigned ledger with entries (pre-0.195.23) is refused by default, accepted once with AGENTIC_SECURITY_RULES_UNSIGNED=1, and signed on the next save', () => {
  const dir = project();
  const ledger = newLedger();
  assert.equal(recordTransition(ledger, { ruleId: 'old-rule', from: null, to: 'DRAFT', actor: 'x' }).ok, true);
  fs.mkdirSync(path.dirname(ledgerFile(dir)), { recursive: true });
  fs.writeFileSync(ledgerFile(dir), JSON.stringify(ledger));
  const refused = run(dir, ['rules', 'status']);
  assert.equal(refused.status, 4);
  assert.match(refused.stderr, /unsigned/);
  assert.equal(run(dir, ['rules', 'status'], { AGENTIC_SECURITY_RULES_UNSIGNED: '1' }).status, 0);
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json'], { AGENTIC_SECURITY_RULES_UNSIGNED: '1' }).status, 0);
  assert.ok(fs.existsSync(`${ledgerFile(dir)}.sig`), 'signed on save');
  assert.equal(run(dir, ['rules', 'status']).status, 0, 'and accepted without the switch from then on');
  assert.equal(loadLedger(dir, {}).entries.length, 3);
});

test('reviewed promotion: no reviewer, or a model as the reviewer, is refused; a named reviewer and scope are recorded in the ledger and the provenance', () => {
  const dir = project();
  validated(dir);
  for (const extra of [[], ['--reviewed-by', 'model'], ['--reviewed-by', 'agent'], ['--reviewed-by', '']]) {
    const r = run(dir, ['rules', 'promote', SPEC.id, ...extra]);
    assert.equal(r.status, 4, extra.join(' '));
    assert.match(r.stderr, /--reviewed-by/);
  }
  const ok = run(dir, ['rules', 'promote', SPEC.id, '--reviewed-by', 'Dana Reviewer', '--scope', 'the orders service']);
  assert.equal(ok.status, 0, ok.stderr);
  const prov = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'provenance.json'), 'utf8'));
  assert.equal(prov.promotionEvent.reviewer, 'Dana Reviewer');
  assert.equal(prov.promotionEvent.scope, 'the orders service');
  assert.deepEqual(prov.benchmarkResults.independent, { positives: 1, negatives: 1, detected: 1, falseAlarms: 0 });
  const entry = loadLedger(dir).entries.find((e) => e.to === 'PROMOTED');
  assert.equal(entry.evidence.reviewer, 'Dana Reviewer');
  assert.equal(entry.actor, 'Dana Reviewer');
});

test('provenance: a rule edited after its evaluation is refused, and an originating commit that is not in the history is refused', () => {
  const dir = project({ git: true });
  validated(dir);
  const irFile = path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'ir.json');
  const ir = JSON.parse(fs.readFileSync(irFile, 'utf8'));
  fs.writeFileSync(irFile, JSON.stringify({ ...ir, match: { pattern: 'rawQuery' } }));
  const edited = run(dir, ['rules', 'promote', SPEC.id, ...REVIEWED]);
  assert.equal(edited.status, 4);
  assert.match(edited.stderr, /changed after it was evaluated/);
  fs.writeFileSync(irFile, JSON.stringify(ir));

  const dir2 = project({ git: true, spec: { ...SPEC, originatingCommit: 'f'.repeat(40) } });
  validated(dir2);
  const bad = run(dir2, ['rules', 'promote', SPEC.id, ...REVIEWED]);
  assert.equal(bad.status, 4);
  assert.match(bad.stderr, /not in this repository's history/);

  const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir, encoding: 'utf8' }).trim();
  const dir3 = project({ git: true, spec: { ...SPEC, originatingCommit: head } });
  // the commit belongs to dir, not dir3: a real commit in the wrong repository is still invalid provenance
  assert.equal(run(dir3, ['rules', 'promote', SPEC.id, ...REVIEWED]).status, 4);
  const own = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: dir3, encoding: 'utf8' }).trim();
  fs.writeFileSync(path.join(dir3, 'spec.json'), JSON.stringify({ ...SPEC, originatingCommit: own }));
  validated(dir3);
  const good = run(dir3, ['rules', 'promote', SPEC.id, ...REVIEWED]);
  assert.equal(good.status, 0, good.stderr);
});

test('conflicts: a rule file the compiler did not write under the same id, and a promoted rule with the identical match, are refused', () => {
  const dir = project();
  validated(dir);
  const live = path.join(dir, '.agentic-security', 'rules', `${SPEC.id}.yml`);
  fs.mkdirSync(path.dirname(live), { recursive: true });
  fs.writeFileSync(live, `- id: ${SPEC.id}\n  title: hand written\n  severity: low\n  match:\n    pattern: nothing\n`);
  const foreign = run(dir, ['rules', 'promote', SPEC.id, ...REVIEWED]);
  assert.equal(foreign.status, 4);
  assert.match(foreign.stderr, /did not write/);
  fs.unlinkSync(live);
  assert.equal(run(dir, ['rules', 'promote', SPEC.id, ...REVIEWED]).status, 0);

  // a second rule with the same match on the same languages
  const twin = { ...SPEC, id: 'orm-raw-query-concat-twin' };
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(twin));
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0);
  // the first rule's negatives join the shared false-positive corpus; the twin passes them the same way the original did
  const ev = run(dir, ['rules', 'evaluate', twin.id]);
  assert.equal(ev.status, 0, ev.stdout + ev.stderr);
  const dup = run(dir, ['rules', 'promote', twin.id, ...REVIEWED]);
  assert.equal(dup.status, 4);
  assert.match(dup.stderr, /duplicates the promoted rule orm-raw-query-concat/);
});

test('regress re-scores the independent examples too: a promoted rule whose independent vulnerable example it no longer catches regresses', () => {
  const dir = project();
  validated(dir);
  assert.equal(run(dir, ['rules', 'promote', SPEC.id, ...REVIEWED]).status, 0);
  assert.equal(run(dir, ['rules', 'regress']).status, 0);
  const corpusFile = path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'corpus.json');
  const c = JSON.parse(fs.readFileSync(corpusFile, 'utf8'));
  c.independentVulnerableCode = ['const rows = db.rawQuery(sql);\n'];
  fs.writeFileSync(corpusFile, JSON.stringify(c));
  const r = run(dir, ['rules', 'regress', '--json']);
  assert.equal(r.status, 1);
  const res = JSON.parse(r.stdout).results[0];
  assert.equal(res.status, 'regressed');
  assert.ok(res.reasons.some((x) => /recall/.test(x)), res.reasons.join('; '));
});
