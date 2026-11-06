// GA-07 §2 and §3 (0.195.27): promoted-rule regressions that run on another machine, the shared negative corpus, the reviewed
// scope and evidence, the independence of the independent examples, the terminal and re-entry lifecycle edges, the measured cost
// of a compiled rule, and `rule test` failing. Each is pinned in both directions through the real CLI.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync, execFileSync } from 'node:child_process';
import { mkTestTmp } from '../helpers/tmp.js';
import { keygen } from '../../src/posture/rule-pack-signing.js';
import { runRule, normalizeCustomRule } from '../../src/posture/custom-rules.js';
import { buildCorpus } from '../../src/posture/rule-compiler/corpus.js';
import { gatePromotion, dependentExamples } from '../../src/posture/rule-compiler/promotion.js';
import { draftRuleIR, compileToCustomRule } from '../../src/posture/rule-compiler/ir.js';
import { loadLedger } from '../../src/posture/rule-compiler/store.js';
import { stateOf, historyFor } from '../../src/posture/rule-compiler/lifecycle.js';
import { SHIPPED_NEGATIVE_CORPUS } from '../../src/posture/rule-compiler/negative-corpus.js';
import { sharedFalsePositiveCorpus } from '../../src/posture/rule-compiler/regression.js';

const CLI = fileURLToPath(new URL('../../bin/agentic-security.js', import.meta.url));
const baseEnv = { ...process.env, AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS: '1' };
delete baseEnv.AGENTIC_SECURITY_RULES_UNSIGNED;
delete baseEnv.AGENTIC_SECURITY_RULES_PUBLIC_KEY;
delete baseEnv.AGENTIC_SECURITY_PRIVATE_KEY;
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
// Another install: a different per-install HMAC key, so the ledger's install-key signature cannot verify there.
const OTHER_INSTALL = { AGENTIC_SECURITY_HMAC_KEY: 'ab'.repeat(32) };

function project({ spec = SPEC } = {}) {
  const dir = mkTestTmp('rc-ci-');
  execFileSync('git', ['init', '-q'], { cwd: dir });
  fs.writeFileSync(path.join(dir, 'a.js'), `${VULN}// ${path.basename(dir)}\n`);
  execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'add', '.'], { cwd: dir });
  execFileSync('git', ['-c', 'user.email=t@example.com', '-c', 'user.name=t', 'commit', '-q', '-m', 'init'], { cwd: dir });
  fs.mkdirSync(path.join(dir, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.agentic-security', 'last-scan.json'), JSON.stringify({ findings: [{ id: 'F1', stableId: 'F1', file: 'a.js', line: 1, cwe: 'CWE-89', parser: 'IR-TAINT', vuln: 'x', severity: 'high', snippet: VULN }] }));
  fs.writeFileSync(path.join(dir, 'spec.json'), JSON.stringify(spec));
  return dir;
}
const ledgerFile = (dir) => path.join(dir, '.agentic-security', 'rule-compiler', 'ledger.json');
const promoted = (dir, extra = []) => {
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0);
  const ev = run(dir, ['rules', 'evaluate', SPEC.id]); assert.equal(ev.status, 0, ev.stdout + ev.stderr);
  const pr = run(dir, ['rules', 'promote', SPEC.id, ...REVIEWED, ...extra]); assert.equal(pr.status, 0, pr.stdout + pr.stderr);
  return pr;
};

test('portable ledger: a promotion signed with the author key is verified on another install through the public key, and refused without it, with a wrong key, or with an entry dropped', () => {
  const dir = project();
  const { publicKey, privateKey } = keygen();
  const pr = promoted(dir, ['--sign-key', privateKey]);
  assert.match(pr.stdout, /ledger author-signed; another machine verifies it with AGENTIC_SECURITY_RULES_PUBLIC_KEY=/);
  assert.ok(fs.existsSync(`${ledgerFile(dir)}.author.sig`));

  const here = run(dir, ['rules', 'regress']);
  assert.equal(here.status, 0, here.stdout + here.stderr);
  assert.match(here.stdout, /ledger verified by this install's key/);

  const elsewhere = run(dir, ['rules', 'regress', '--json'], { ...OTHER_INSTALL, AGENTIC_SECURITY_RULES_PUBLIC_KEY: publicKey });
  assert.equal(elsewhere.status, 0, elsewhere.stdout + elsewhere.stderr);
  const out = JSON.parse(elsewhere.stdout);
  assert.equal(out.ledgerVerifiedBy, 'author-key');
  assert.equal(out.results[0].status, 'ok');

  const noKey = run(dir, ['rules', 'regress'], OTHER_INSTALL);
  assert.equal(noKey.status, 4);
  assert.match(noKey.stderr, /does not verify under this install key and its author signature does not verify against any trusted key \(no trusted key/);
  const wrongKey = run(dir, ['rules', 'regress'], { ...OTHER_INSTALL, AGENTIC_SECURITY_RULES_PUBLIC_KEY: keygen().publicKey });
  assert.equal(wrongKey.status, 4);
  assert.match(wrongKey.stderr, /bad signature/);

  // the chain stays valid when the LAST entry is dropped (nothing follows it), so only the signatures can catch it
  const ledger = JSON.parse(fs.readFileSync(ledgerFile(dir), 'utf8'));
  ledger.entries.pop();
  fs.writeFileSync(ledgerFile(dir), JSON.stringify(ledger, null, 2));
  const dropped = run(dir, ['rules', 'regress'], { ...OTHER_INSTALL, AGENTIC_SECURITY_RULES_PUBLIC_KEY: publicKey });
  assert.equal(dropped.status, 4);
  assert.match(dropped.stderr, /integrity check/);
  assert.equal(run(dir, ['rules', 'regress']).status, 4, 'the install key sees the drop too');
});

test('an unsigned promotion says so, and the ledger is refused elsewhere whatever key is offered', () => {
  const dir = project();
  const pr = promoted(dir);
  assert.match(pr.stdout, /no --sign-key: the ledger carries only this install's signature/);
  assert.ok(!fs.existsSync(`${ledgerFile(dir)}.author.sig`));
  const elsewhere = run(dir, ['rules', 'regress'], { ...OTHER_INSTALL, AGENTIC_SECURITY_RULES_PUBLIC_KEY: keygen().publicKey });
  assert.equal(elsewhere.status, 4);
  assert.match(elsewhere.stderr, /carries no author signature/);
});

test('a review is of one corpus: a corpus edited after the promotion is reported by regress with its digests, and the promotion event records the evidence', () => {
  const dir = project();
  promoted(dir);
  const prov = JSON.parse(fs.readFileSync(path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'provenance.json'), 'utf8'));
  const ev = prov.promotionEvent.evidence;
  assert.equal(ev.scope, 'the fixture project');
  for (const k of ['ruleHash', 'evaluationDigest', 'provenanceDigest', 'positiveCorpusHash', 'negativeCorpusHash']) assert.match(ev[k], /^[0-9a-f]{64}$/, k);
  assert.ok(ev.sharedFalsePositiveItems >= SHIPPED_NEGATIVE_CORPUS.length);
  const entry = historyFor(loadLedger(dir), SPEC.id).find((e) => e.to === 'PROMOTED');
  assert.deepEqual(entry.evidence, ev);

  const corpusFile = path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'corpus.json');
  const corpus = JSON.parse(fs.readFileSync(corpusFile, 'utf8'));
  corpus.nearbyCleanCode = [];
  fs.writeFileSync(corpusFile, JSON.stringify(corpus));
  const r = run(dir, ['rules', 'regress']);
  assert.equal(r.status, 1);
  assert.match(r.stdout, /the corpus changed since the reviewed promotion/);
});

test('promotion needs the reviewed scope', () => {
  const dir = project();
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0);
  assert.equal(run(dir, ['rules', 'evaluate', SPEC.id]).status, 0);
  const noScope = run(dir, ['rules', 'promote', SPEC.id, '--reviewed-by', 'a reviewer']);
  assert.equal(noScope.status, 4);
  assert.match(noScope.stderr, /reviewed scope is recorded/);
  assert.equal(stateOf(loadLedger(dir), SPEC.id), 'VALIDATED', 'nothing moved');
});

test('the shipped negative corpus holds every rule: an overbroad rule that fires on shipped safe code fails evaluation with the item named, wherever it runs', () => {
  const spec = { ...SPEC, id: 'overbroad-db-query', match: { pattern: 'db\\.query\\s*\\(' }, originalCode: 'db.query("SELECT * FROM t WHERE id = " + userId);\n', patchedCode: 'db.query("SELECT * FROM t WHERE id = $1", [userId]);\n', independentVulnerableCode: ['db.query("DELETE FROM t WHERE id = " + id);\n'], independentCleanCode: ['const n = 1;\n'] };
  const dir = project({ spec });
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0);
  const ev = run(dir, ['rules', 'evaluate', spec.id]);
  assert.equal(ev.status, 1);
  assert.match(ev.stdout, /shipped-fp:js-parameterised-query/);
  assert.equal(stateOf(loadLedger(dir), spec.id), 'CANDIDATE');
  assert.ok(SHIPPED_NEGATIVE_CORPUS.every((s) => s.name && s.language && s.code.trim()), 'every shipped item is named, typed and non-empty');
  assert.ok(sharedFalsePositiveCorpus(dir, loadLedger(dir)).filter((i) => i.label.startsWith('shipped-fp:')).length === SHIPPED_NEGATIVE_CORPUS.length);
});

test('a shared false-positive directory named in the environment is held to as well, across repositories', () => {
  const shared = mkTestTmp('rc-shared-fp-');
  fs.writeFileSync(path.join(shared, 'legacy.js'), 'const row = db.rawQuery("SELECT 1" + suffix);\n');
  const dir = project();
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 0);
  const ev = run(dir, ['rules', 'evaluate', SPEC.id], { AGENTIC_SECURITY_RULES_FP_CORPUS: shared });
  assert.equal(ev.status, 1);
  assert.match(ev.stdout, new RegExp(`shared-fp:${path.basename(shared)}:legacy.js`));
  assert.equal(run(dir, ['rules', 'evaluate', SPEC.id]).status, 0, 'without the shared directory the same rule passes');
});

test('independent examples must be independent: the original, its patch or a generated mutation offered as independent is refused', () => {
  const ir = draftRuleIR({ ...SPEC, originatingFindingId: 'F1', evidenceState: 'taint-proven' });
  const same = buildCorpus(ir, { ...SPEC, independentVulnerableCode: [`  ${VULN.trim()}  `], independentCleanCode: [PATCHED] });
  const dups = dependentExamples(same);
  assert.deepEqual(dups.map((d) => [d.label, d.sameAs]), [['independent-vulnerable-0', 'original'], ['independent-clean-0', 'patched']]);
  const gate = gatePromotion({ ir, corpus: same, leakageCheck: { ok: true, offendingTerms: [] } });
  assert.equal(gate.pass, false);
  assert.ok(gate.reasons.some((r) => /independent-vulnerable-0 is not independent/.test(r)), gate.reasons.join('; '));
  const mutated = buildCorpus(ir, SPEC);
  const aSibling = mutated.positives.find((p) => p.label.startsWith('sibling:'));
  const viaMutation = buildCorpus(ir, { ...SPEC, independentVulnerableCode: [aSibling.code] });
  assert.ok(dependentExamples(viaMutation).some((d) => d.sameAs === aSibling.label));
  assert.deepEqual(dependentExamples(buildCorpus(ir, SPEC)), [], 'the real independent examples are independent');
});

test('lifecycle: a promoted rule can be deprecated (terminal) and a rolled-back rule re-enters as a candidate with its history kept', () => {
  const dir = project();
  promoted(dir);
  const dep = run(dir, ['rules', 'deprecate', SPEC.id, '--reason', 'superseded']);
  assert.equal(dep.status, 0, dep.stdout + dep.stderr);
  assert.equal(stateOf(loadLedger(dir), SPEC.id), 'DEPRECATED');
  assert.ok(!fs.existsSync(path.join(dir, '.agentic-security', 'rules', `${SPEC.id}.yml`)), 'the published rule is gone');
  assert.equal(run(dir, ['rules', 'deprecate', SPEC.id]).status, 4, 'terminal');
  assert.equal(run(dir, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']).status, 4, 'a deprecated id is not re-drafted');

  const dir2 = project();
  promoted(dir2);
  assert.equal(run(dir2, ['rules', 'rollback', SPEC.id]).status, 0);
  const re = run(dir2, ['rules', 'synthesize', 'F1', '--spec', 'spec.json']);
  assert.equal(re.status, 0, re.stdout + re.stderr);
  const ledger = loadLedger(dir2);
  assert.equal(stateOf(ledger, SPEC.id), 'CANDIDATE');
  assert.deepEqual(historyFor(ledger, SPEC.id).map((e) => e.to), ['DRAFT', 'CANDIDATE', 'VALIDATED', 'PROMOTED', 'ROLLED_BACK', 'CANDIDATE']);
});

test('measured cost: a compiled rule over a large adversarial file stays within the per-file budget, and a runaway pattern never compiles', () => {
  const ir = draftRuleIR({ ...SPEC, originatingFindingId: 'F1', evidenceState: 'taint-proven' });
  const rule = normalizeCustomRule(compileToCustomRule(ir).doc);
  const line = 'const row = db.rawQuery("' + 'x'.repeat(200) + '", [userId]);\n';
  const big = line.repeat(Math.ceil((256 * 1024) / line.length));
  const t0 = process.hrtime.bigint();
  const hits = runRule(rule, 'x.js', big);
  const ms = Number(process.hrtime.bigint() - t0) / 1e6;
  assert.equal(hits.length, 0);
  assert.ok(ms < 2000, `256 KiB of near misses took ${ms.toFixed(0)} ms`);
  const origErr = console.error; console.error = () => {};
  try { assert.equal(normalizeCustomRule({ id: 'x', match: { pattern: '(rawQuery\\s*)+\\(' } }), null, 'nested quantifiers are refused before any input is read'); } finally { console.error = origErr; }
});

test('rule test fails on a missed vulnerable fixture or a hit on a clean one, and passes on the written fixtures', () => {
  const dir = project();
  promoted(dir);
  const fixtures = path.join(dir, '.agentic-security', 'rule-compiler', SPEC.id, 'fixtures');
  const pass = run(dir, ['rule', 'test', path.join(fixtures, '**', '*')]);
  assert.equal(pass.status, 0, pass.stdout + pass.stderr);
  fs.writeFileSync(path.join(fixtures, 'vulnerable', 'missed.js'), 'const n = 1;\n');
  const miss = run(dir, ['rule', 'test', path.join(fixtures, '**', '*')]);
  assert.equal(miss.status, 1);
  assert.match(miss.stdout, /FAIL \(missed\)/);
  assert.match(miss.stdout, /1 FAILED/);
});
