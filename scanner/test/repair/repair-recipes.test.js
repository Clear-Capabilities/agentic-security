// Verified remediation M3: repair recipes (FR-11, section 6.6) and the password-storage family (FR-12, M3-04).
//
// The static half checks the transformations, the recipe documents and the signed lifecycle without executing anything. The executed
// half evaluates both shipped recipes on their examples, including a held-out project each was not developed against, and judges a
// portfolio of password-storage repairs through the trust boundary. A skip is not a pass.
import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  SHIPPED_RECIPES, TRANSFORMS, validateRecipe, recipeDigest, applicability, transition, draftRecipe, usableRecipes,
  loadRecipeLedger, stateOf, evaluateRecipe, containPathTransform,
} from '../../src/repair/recipes.js';
import { exampleRunner } from '../../src/repair/recipe-eval.js';
import { planRepair, runRepair } from '../../src/repair/coordinator.js';
import { queueProposer } from '../../src/repair/candidates.js';
import { PROFILE_SUPPORT } from '../../src/repair/contracts.js';
import { resolveAssuranceConfig } from '../../src/posture/assurance/config.js';
import { runFullScan } from '../../src/engine.js';
import { detectBackend } from '../../src/sandbox/capabilities.js';
import { probeControls, unmetControls } from '../../src/sandbox/control-probes.js';
import { DEFAULT_REQUIRED_CONTROLS } from '../../src/sandbox/trust-boundary.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SCANNER = path.resolve(HERE, '..', '..');
const REPO = path.resolve(SCANNER, '..');
const FIX = path.join(SCANNER, 'test', 'fixtures', 'repair');
const ON = resolveAssuranceConfig({ env: {}, overrides: { features: { 'verification-oracles': true } } });
const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p));
const SQL = SHIPPED_RECIPES.find((r) => r.recipeId === 'sql-parameterize-template');
const PATHR = SHIPPED_RECIPES.find((r) => r.recipeId === 'path-realpath-containment');

let ready = false; let whyNot = '';
before(async () => {
  const backend = detectBackend();
  const unmet = unmetControls(await probeControls({}), [...DEFAULT_REQUIRED_CONTROLS, 'network']);
  ready = (backend === 'userspace' || backend === 'namespace') && unmet.length === 0;
  whyNot = `SKIPPED, NOT PASSED: the trust boundary cannot run on this host (backend '${backend}'); the recipe and password execution tests are UNVERIFIED here`;
});
const needs = (fn) => async (t) => (ready ? fn(t) : t.skip(whyNot));

describe('[FR-11] recipe transformations and documents (no execution)', () => {
  test('[AC-11.1] the SQL recipe binds values with the driver\'s ? convention and refuses an identifier built from input', () => {
    const r = TRANSFORMS['sql-parameterize-template'].apply(fs.readFileSync(path.join(FIX, 'sql-tasks', 'src', 'app.mjs'), 'utf8'));
    assert.equal(r.applied, 1);
    assert.match(r.text, /WHERE project = \? AND status = \? ORDER BY id'\)\.all\(project, status\)/);
    const s = TRANSFORMS['sql-parameterize-template'].apply(fs.readFileSync(path.join(FIX, 'sql-sort', 'src', 'app.mjs'), 'utf8'));
    assert.equal(s.applied, 0);
    assert.match(s.refused.join(' '), /placeholder cannot carry it/);
  });

  test('[AC-11.2] an unsupported runtime version, runtime or driver is not applicable', () => {
    const contract = { family: 'sql-injection', profile: { runtime: 'node', database: { engine: 'sqlite' } } };
    assert.equal(applicability(SQL, contract, { nodeVersion: '24.1.0' }).ok, true);
    assert.match(applicability(SQL, contract, { nodeVersion: '22.4.0' }).reasons.join(' '), /below the supported 22\.5\.0/);
    assert.match(applicability(SQL, { ...contract, profile: { runtime: 'python', database: { engine: 'sqlite' } } }).reasons.join(' '), /node runtime only/);
    assert.match(applicability(SQL, { ...contract, profile: { runtime: 'node', database: { engine: 'postgres' } } }).reasons.join(' '), /sqlite driver only/);
  });

  test('the path recipe resolves links before checking containment, on both example shapes; an unhandled read or other bindings are refused', () => {
    const a = containPathTransform(fs.readFileSync(path.join(FIX, 'files-download', 'src', 'app.mjs'), 'utf8'));
    assert.equal(a.applied, 1);
    assert.match(a.text, /const file = containedPath\(filesRoot, 'resolve', name\);/);
    assert.match(a.text, /fs\.realpathSync\(target\)/);
    const b = containPathTransform(fs.readFileSync(path.join(FIX, 'avatar-store', 'src', 'app.mjs'), 'utf8'));
    assert.equal(b.applied, 1);
    assert.match(b.text, /containedPath\(filesRoot, 'join', user, 'avatar\.txt'\)/);
    assert.equal(containPathTransform("import fs from 'node:fs';\nimport path from 'node:path';\nconst p = path.join(root, n);\nexport const x = fs.readFileSync(p);\n").applied, 0);
    assert.match(containPathTransform("import * as nodefs from 'node:fs';\nimport path from 'node:path';\n").refused.join(' '), /not bound by those names/);
  });

  test('[AC-11.3] a recipe document cannot carry code, widen its scope or lower its runtime floor', () => {
    for (const r of SHIPPED_RECIPES) assert.deepEqual(validateRecipe(r), [], r.recipeId);
    assert.match(validateRecipe({ ...SQL, transform: 'shell-script' }).join(' '), /cannot carry code/);
    assert.match(validateRecipe({ ...SQL, editScope: { ...SQL.editScope, maxFiles: 9 } }).join(' '), /maxFiles must be 1 to 3/);
    assert.match(validateRecipe({ ...SQL, supports: { ...SQL.supports, runtime: { name: 'node', min: '18.0.0' } } }).join(' '), /may only raise the minimum/);
    assert.match(validateRecipe({ ...SQL, command: 'rm -r /' }).join(' '), /unknown field 'command'/);
  });

  test('the recipe digest covers the transformation source, not only the document', () => {
    const a = recipeDigest(PATHR);
    assert.notEqual(a, recipeDigest({ ...PATHR, transform: 'sql-parameterize-template' }));
    assert.equal(a, recipeDigest(JSON.parse(JSON.stringify(PATHR))));
  });
});

describe('[FR-11] the signed recipe lifecycle (no execution)', () => {
  const okEval = (r) => ({ ok: true, recipeDigest: recipeDigest(r), evaluationDigest: 'sha256:' + 'a'.repeat(64), results: [] });
  const draft = () => ({ ...JSON.parse(JSON.stringify(PATHR)), recipeId: 'path-contain-narrow', version: '1', provenance: { origin: 'operator', author: 'a reviewer' }, signer: 'operator', editScope: { maxFiles: 1, files: 'one file' } });

  test('shipped recipes are used until retired; a retired recipe is never used again and its history is kept (AC-11.6)', () => {
    const root = tmp('recipes-retire-');
    assert.ok(usableRecipes(root, 'sql-injection').recipes.some((r) => r.recipeId === 'sql-parameterize-template'));
    assert.equal(transition(root, SQL, 'retired', { reason: '' }).ok, false, 'a reason is required');
    assert.equal(transition(root, SQL, 'retired', { reason: 'a regression was found in review', actor: 'reviewer' }).ok, true);
    const u = usableRecipes(root, 'sql-injection');
    assert.equal(u.recipes.length, 0);
    assert.match(u.notes.join(' '), /is retired: not used/);
    assert.equal(transition(root, SQL, 'evaluated', { reason: 'try again', evaluation: okEval(SQL) }).ok, false, 'retired is terminal');
    assert.equal(loadRecipeLedger(root).entries.length, 1);
  });

  test('a draft is used only after an evaluation of exactly that recipe and a promotion; a changed recipe needs evaluating again (AC-11.4)', () => {
    const root = tmp('recipes-promote-');
    const d = draft();
    assert.equal(draftRecipe(root, d, { reason: 'narrowed to one file' }).ok, true);
    assert.equal(draftRecipe(root, d, { reason: 'again' }).ok, false, 'drafts are immutable');
    assert.ok(!usableRecipes(root, 'path-traversal').recipes.some((r) => r.recipeId === d.recipeId), 'a draft is not used');
    assert.equal(transition(root, d, 'promoted', { reason: 'skip evaluation' }).ok, false, 'draft cannot jump to promoted');
    assert.equal(transition(root, d, 'evaluated', { reason: 'fake', evaluation: { ...okEval(d), recipeDigest: 'sha256:' + 'b'.repeat(64) } }).ok, false, 'an evaluation of another digest does not count');
    assert.equal(transition(root, d, 'evaluated', { reason: 'failed example', evaluation: { ...okEval(d), ok: false } }).ok, false);
    assert.equal(transition(root, d, 'evaluated', { reason: 'all examples met', evaluation: okEval(d) }).ok, true);
    const altered = { ...d, contraindications: [...d.contraindications, 'added after evaluation'] };
    assert.match(transition(root, altered, 'promoted', { reason: 'ship it' }).reason, /cannot go from draft|changed since it was evaluated/);
    assert.equal(transition(root, d, 'promoted', { reason: 'reviewed', actor: 'reviewer' }).ok, true);
    assert.ok(usableRecipes(root, 'path-traversal').recipes.some((r) => r.recipeId === d.recipeId));
    assert.equal(stateOf(loadRecipeLedger(root), d).state, 'promoted');
    assert.equal(transition(root, d, 'rolled-back', { reason: 'bad output in production review' }).ok, true);
    assert.ok(!usableRecipes(root, 'path-traversal').recipes.some((r) => r.recipeId === d.recipeId));
  });

  test('a hand-edited ledger fails verification: nothing is used and nothing more is written', () => {
    const root = tmp('recipes-tamper-');
    assert.equal(transition(root, SQL, 'retired', { reason: 'review', actor: 'r' }).ok, true);
    const f = path.join(root, '.agentic-security', 'repair-recipes', 'ledger.json');
    const doc = JSON.parse(fs.readFileSync(f, 'utf8'));
    doc.entries[0].to = 'shipped';
    fs.writeFileSync(f, JSON.stringify(doc));
    const u = usableRecipes(root, 'sql-injection');
    assert.equal(u.recipes.length, 0);
    assert.match(u.notes[0], /failed verification/);
    assert.equal(transition(root, PATHR, 'retired', { reason: 'x' }).ok, false);
  });

  test('the CLI lists the recipes with their states and records a retirement', () => {
    const root = tmp('recipes-cli-');
    const bin = path.join(SCANNER, 'bin', 'agentic-security.js');
    const list = spawnSync(process.execPath, [bin, 'repair', 'recipes', 'list', '--root', root, '--json'], { encoding: 'utf8', timeout: 60000 });
    assert.equal(list.status, 0, list.stderr);
    const rows = JSON.parse(list.stdout).recipes;
    assert.deepEqual(rows.map((r) => `${r.recipe}:${r.state}`).sort(), ['path-realpath-containment@1:shipped', 'sql-parameterize-template@2:shipped']);
    const noReason = spawnSync(process.execPath, [bin, 'repair', 'recipes', 'retire', 'sql-parameterize-template', '--root', root], { encoding: 'utf8', timeout: 60000 });
    assert.equal(noReason.status, 2);
    const ret = spawnSync(process.execPath, [bin, 'repair', 'recipes', 'retire', 'sql-parameterize-template', '--reason', 'review', '--root', root], { encoding: 'utf8', timeout: 60000 });
    assert.equal(ret.status, 0, ret.stderr);
    const after = JSON.parse(spawnSync(process.execPath, [bin, 'repair', 'recipes', 'list', '--root', root, '--json'], { encoding: 'utf8', timeout: 60000 }).stdout).recipes;
    assert.equal(after.find((r) => r.recipe.startsWith('sql-')).state, 'retired');
  });
});

describe('[M3-06] per-profile support', () => {
  test('every supported row names an existing executed test; macOS and Linux are separate and Linux is not claimed', () => {
    for (const s of PROFILE_SUPPORT) {
      if (s.macos === 'integration-tested') assert.ok(s.evidence && fs.existsSync(path.join(REPO, s.evidence)), `${s.family}/${s.runtime}`);
      assert.ok(['blocked', 'unverified'].includes(s.linux), `${s.family}: Linux is never claimed`);
      if (s.recipe) assert.ok(SHIPPED_RECIPES.some((r) => r.recipeId === s.recipe));
    }
  });
});

describe('[M3-01/M3-02/AC-11.5] shipped recipes evaluated on their examples, including a held-out project', () => {
  for (const r of SHIPPED_RECIPES) {
    test(`${r.recipeId}: every example meets its expectation, the independent one included`, needs(async () => {
      const e = await evaluateRecipe(r, { repoRoot: SCANNER, run: exampleRunner({ config: ON }) });
      assert.equal(e.ok, true, JSON.stringify(e.results));
      const indep = e.results.find((x) => x.kind === 'independent');
      assert.equal(indep.outcome, 'verified-for-contract');
      assert.ok(e.results.some((x) => x.kind === 'safe-negative' && x.outcome === 'refused'));
      assert.ok(e.results.some((x) => x.kind === 'unsupported-version' && x.outcome === 'not-applicable'));
      assert.equal(e.recipeDigest, recipeDigest(r));
      const root = tmp('recipes-eval-');
      assert.equal(transition(root, r, 'evaluated', { reason: 'every example met', evaluation: e }).ok, true);
    }));
  }
});

describe('[M3-04] password storage, executed', () => {
  const HASH = "function hashPassword(password) {\n  return crypto.createHash('md5').update(String(password)).digest('hex');\n}\n";
  const CMP = 'row.pw !== hashPassword(b.password)';
  const OK = "      return send(res, 200, { ok: true, user: row.name });\n";
  const rep = (t, a, b) => { assert.ok(t.includes(a), a.slice(0, 40)); return t.replace(a, () => b); };
  const kdf = (salt, N) => `function hashPassword(password) {\n  const salt = ${salt};\n  const key = crypto.scryptSync(String(password), salt, 32, { N: ${N}, r: 8, p: 1 });\n  return ['scrypt', ${N}, 8, 1, salt.toString('hex'), key.toString('hex')].join('$');\n}\n`;
  const verify = (legacy) => "function verifyPassword(password, stored) {\n  if (stored.startsWith('scrypt$')) {\n    const [, n, r, p, saltHex, keyHex] = stored.split('$');\n    const key = crypto.scryptSync(String(password), Buffer.from(saltHex, 'hex'), keyHex.length / 2, { N: Number(n), r: Number(r), p: Number(p) });\n    return crypto.timingSafeEqual(key, Buffer.from(keyHex, 'hex'));\n  }\n"
    + (legacy ? "  const legacy = crypto.createHash('md5').update(String(password)).digest('hex');\n  return legacy.length === stored.length && crypto.timingSafeEqual(Buffer.from(legacy), Buffer.from(stored));\n" : '  return false;\n') + '}\n';
  const variant = (original, { salt = 'crypto.randomBytes(16)', N = 16384, legacy = true, rehash = false }) => {
    let t = rep(rep(original, HASH, kdf(salt, N) + verify(legacy)), CMP, '!verifyPassword(b.password, row.pw)');
    if (rehash) t = rep(t, OK, "      if (!row.pw.startsWith('scrypt$')) db.prepare('UPDATE users SET pw = ? WHERE name = ?').run(hashPassword(b.password), row.name);\n" + OK);
    return t;
  };

  test('a fast digest, a constant salt, a low cost, locked-out legacy users and an unmigrated legacy hash are each rejected by the obligation that covers them; salted scrypt with migration is verified', needs(async () => {
    const root = tmp('pw-');
    fs.cpSync(path.join(FIX, 'password-login'), root, { recursive: true });
    const profile = JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
    const original = fs.readFileSync(path.join(root, 'src', 'app.mjs'), 'utf8');
    const scan = await runFullScan({ fileContents: { 'src/app.mjs': original }, scanRoot: root, provenance: false }, () => {});
    const f = scan.findings.find((x) => x.cwe === 'CWE-916');
    assert.ok(f, 'the scanner reports the unsalted digest');
    const p = planRepair({ root, finding: { findingId: f.id, id: f.id, stableId: f.stableId, file: 'src/app.mjs', cwe: f.cwe }, family: 'password-storage', profile, profileOrigin: 'repository-file' });
    assert.ok(p.plan, [...p.problems, ...p.blocked].join('; '));
    const items = [
      [original.split("createHash('md5')").join("createHash('sha256')"), 1, 'fast'],
      [variant(original, { salt: "Buffer.from('0123456789abcdef0123456789abcdef', 'hex')", rehash: true }), 1, 'constant-salt'],
      [variant(original, { N: 1024, rehash: true }), 1, 'low-cost'],
      [variant(original, { legacy: false, rehash: true }), 2, 'locked-out'],
      [variant(original, {}), 2, 'no-migration'],
      [variant(original, { rehash: true }), 3, 'migrated'],
    ];
    const r = await runRepair({ root, plan: p.plan, config: ON, proposers: [queueProposer(items.map(([t, round, strategy]) => ({ round, strategy, files: { 'src/app.mjs': t } })))], policy: { schema: 'agentic-security/repair-policy', schemaVersion: '1.0.0', budgets: { rounds: 3 } } });
    const base = Object.fromEntries(r.record.obligationResults.filter((o) => o.revision === 'original').map((o) => [o.obligation, o.observed]));
    assert.deepEqual(base, { 'password-storage': 'confirmed', 'password-legitimate-logins': 'refuted', 'password-legacy-migrated': 'confirmed' });
    const by = Object.fromEntries(r.record.candidates.map((c) => [c.strategy, c]));
    const failed = (s) => by[s].results.filter((x) => x.status === 'failed').map((x) => x.obligation);
    assert.ok(failed('fast').includes('password-legitimate-logins') || failed('fast').includes('password-storage'));
    assert.ok(failed('constant-salt').includes('password-storage'));
    const cx = r.record.counterexamples.find((x) => x.candidateId === by['constant-salt'].candidateId);
    assert.equal(cx.property, 'credential-storage');
    assert.ok(failed('low-cost').includes('password-storage'));
    assert.ok(failed('locked-out').includes('password-legitimate-logins'));
    assert.deepEqual(failed('no-migration'), ['password-legacy-migrated']);
    assert.equal(by.migrated.status, 'verified-for-contract', r.record.reasons.join('; '));
    assert.equal(r.record.disposition, 'verified-for-contract');
  }));
});
