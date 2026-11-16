// Verified remediation M1, no execution: contracts, profiles, schemas, the candidate scope gate, the recipe, budgets, the record
// validator and CLI/MCP parity (FR-04, FR-17, FR-18, section 6).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildContract, snapshotSource, obligationSummary, PROTECTED_PATTERNS } from '../../src/repair/contracts.js';
import { validateProfile } from '../../src/repair/profile.js';
import { validateContract, validateRepairRecord, contractIdOf, SCHEMAS } from '../../src/repair/schemas.js';
import { checkCandidate, parameterizeTemplateSql, makeCandidate } from '../../src/repair/candidates.js';
import { resolveBudgets, validatePolicy } from '../../src/repair/coordinator.js';
import { planFromInputs } from '../../src/repair/intake.js';
import { makeRepairTools } from '../../src/mcp/repair-tools.js';
import { getOracle } from '../../src/posture/oracles/registry.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'repair');
const copy = (name) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), `rc-${name}-`)); fs.cpSync(path.join(FIX, name), d, { recursive: true }); return d; };
const profileOf = (root) => JSON.parse(fs.readFileSync(path.join(root, 'profile.json'), 'utf8'));
const build = (root, over) => {
  const profile = over.profile || profileOf(root);
  return buildContract({ finding: { findingId: 'f1', file: 'src/app.mjs' }, profile, profileOrigin: over.origin || 'repository-file', source: snapshotSource(root, profile), family: over.family });
};
const sqlRoot = () => copy('sql-notes');
const authzRoot = () => copy('authz-notes');

describe('[AC-04.1/AC-04.2] contract identity', () => {
  test('identical inputs give an identical contract id and digest; no clock enters it', () => {
    const r = sqlRoot();
    const a = build(r, { family: 'sql-injection' }); const b = build(r, { family: 'sql-injection' });
    assert.deepEqual(a.problems, []);
    assert.equal(a.contract.contractId, b.contract.contractId);
    assert.equal(a.contract.contractDigest, b.contract.contractDigest);
    assert.equal(contractIdOf(a.contract), a.contract.contractId);
  });
  test('a change to source, a lockfile, the policy facts or a pinned oracle digest gives a different contract', () => {
    const r = sqlRoot();
    const base = build(r, { family: 'sql-injection' }).contract;
    fs.appendFileSync(path.join(r, 'src', 'http.mjs'), '\n// changed\n');
    const src = build(r, { family: 'sql-injection' }).contract;
    assert.notEqual(src.contractId, base.contractId);
    fs.writeFileSync(path.join(r, 'package-lock.json'), '{"lockfileVersion":3}');
    const lock = build(r, { family: 'sql-injection' }).contract;
    assert.notEqual(lock.contractId, src.contractId);
    const p = profileOf(r); p.sql.inputs[0].benign[0].expectIncludes = ['milk'];
    assert.notEqual(build(r, { family: 'sql-injection', profile: p }).contract.contractId, lock.contractId);
    const tampered = { ...lock, obligations: lock.obligations.map((o, i) => (i === 0 ? { ...o, oracleLogicDigest: `sha256:${'0'.repeat(64)}` } : o)) };
    assert.equal(validateContract(tampered).ok, false, 'a changed pinned oracle digest no longer matches the contract digest');
  });
});

describe('[AC-04.3/AC-04.4/AC-04.7] family obligations', () => {
  test('a SQL contract requires injection prevention AND legitimate queries, including a quoted value the original mishandles', () => {
    const c = build(sqlRoot(), { family: 'sql-injection' }).contract;
    const kinds = c.obligations.map((o) => o.kind);
    for (const k of ['app-attack-blocked', 'app-attack-sealed', 'app-behaviour-preserved', 'app-behaviour-after', 'project-tests']) assert.ok(kinds.includes(k), k);
    assert.ok(c.obligations.every((o) => o.required));
    const after = c.obligations.find((o) => o.kind === 'app-behaviour-after');
    assert.ok(after.inputs.requests.every((r) => r.role === 'control'), 'attacker input is never held to behavioural equivalence');
    assert.equal(c.obligations.find((o) => o.kind === 'app-attack-blocked').oracleLogicDigest, getOracle('application-security').logicDigest);
  });
  test('an authorization contract names actor, role, tenant, ownership, effect and every allowed workflow', () => {
    const r = build(authzRoot(), { family: 'object-authorization' });
    const m = r.contract.profile.actorMatrix;
    for (const k of ['actor', 'role', 'tenant', 'owner', 'effect', 'allowed', 'object', 'operation']) assert.ok(k in m[0], k);
    const allowed = m.filter((x) => x.allowed).map((x) => `${x.operation}:${x.object}:${x.actor}`).sort();
    assert.deepEqual(allowed, ['read-note:alice-note:alice', 'read-note:alice-note:dave', 'read-note:mallory-note:mallory', 'update-note:alice-note:alice', 'update-note:alice-note:dave', 'update-note:mallory-note:mallory']);
    const sec = r.contract.obligations.find((o) => o.id === 'authz-denied-actors');
    assert.ok(sec.inputs.stateChecks.every((c) => Array.isArray(c.guards) && c.guards.length), 'every denied write is judged by durable state, not by status');
    const roles = sec.inputs.requests.map((x) => x.role);
    assert.ok(roles.indexOf('attack') > roles.lastIndexOf('control'), 'allowed reads run before any denied write');
  });
});

describe('[AC-04.6] a missing prerequisite blocks, it never weakens the contract', () => {
  test('no planted secret to observe, a missing application file, or a profile for the wrong family', () => {
    const r = sqlRoot(); const p = profileOf(r);
    p.database.seed = p.database.seed.filter((s) => !JSON.stringify(s).includes('secret'));
    assert.match(build(r, { family: 'sql-injection', profile: p }).blocked.join(), /plants no/);
    fs.rmSync(path.join(r, 'src', 'http.mjs'));
    assert.match(build(r, { family: 'sql-injection' }).blocked.join(), /missing/);
    assert.match(build(sqlRoot(), { family: 'object-authorization' }).blocked.join(), /no authorization section/);
  });
  test('profiles are closed: unknown fields, non-identifiers reaching SQL and unsupported engines are errors', () => {
    const p = profileOf(authzRoot());
    assert.deepEqual(validateProfile(p), []);
    assert.match(validateProfile({ ...p, surprise: 1 }).join(), /unknown field 'surprise'/);
    assert.match(validateProfile({ ...p, authorization: { ...p.authorization, table: 'notes; x' } }).join(), /identifier/);
    assert.match(validateProfile({ ...p, database: { ...p.database, engine: 'postgres' } }).join(), /only 'sqlite'/);
    assert.match(validateProfile({ ...p, authorization: { ...p.authorization, operations: [{ ...p.authorization.operations[0], effect: 'delete' }] } }).join(), /not supported/);
  });
});

describe('schemas are closed and versioned', () => {
  test('unknown contract fields, unknown obligation kinds and a foreign major version are refused', () => {
    const c = build(sqlRoot(), { family: 'sql-injection' }).contract;
    assert.equal(validateContract({ ...c, extra: true }).ok, false);
    assert.equal(validateContract({ ...c, schemaVersion: '2.0.0' }).errors[0].code, 'UNSUPPORTED_MAJOR');
    const bad = { ...c, obligations: [{ ...c.obligations[0], kind: 'run-my-script' }] };
    assert.match(validateContract(bad).errors.map((e) => e.message).join(), /unknown obligation kind/);
  });
  test('a verified-for-contract record needs a complete run with every required obligation passed; artifact claims need a digest', () => {
    const base = { schema: SCHEMAS.record, schemaVersion: '1.0.0', runId: 'rrun-0000000000000000', contractId: 'rcon:x', disposition: 'verified-for-contract', application: 'not-applied', artifact: 'source-only', environment: 'not-checked', completion: 'complete', reasons: [], scope: 's' };
    assert.equal(validateRepairRecord({ ...base, obligationResults: [{ required: true, status: 'passed' }] }).ok, true);
    assert.equal(validateRepairRecord({ ...base, obligationResults: [{ required: true, status: 'inconclusive' }] }).ok, false);
    assert.equal(validateRepairRecord({ ...base, obligationResults: [] }).ok, false);
    assert.equal(validateRepairRecord({ ...base, completion: 'partial', obligationResults: [{ required: true, status: 'passed' }] }).ok, false);
    assert.equal(validateRepairRecord({ ...base, artifact: 'artifact-verified', obligationResults: [{ required: true, status: 'passed' }] }).ok, false, 'AC-18.3: no artifact claim for a source-only repair');
  });
});

describe('[T-05/T-12] the candidate scope gate runs before anything executes', () => {
  const c = build(sqlRoot(), { family: 'sql-injection' }).contract;
  const orig = snapshotSource(sqlRoot(), profileOf(sqlRoot())).files;
  test('protected paths, out-of-scope files, a no-op and an over-budget rewrite are refused', () => {
    assert.match(checkCandidate(c, orig, { 'test/app.test.mjs': 'x' }).reasons.join(), /protected path/);
    assert.match(checkCandidate(c, orig, { '.agentic-security/receipts.json': '{}' }).reasons.join(), /protected path/);
    assert.match(checkCandidate(c, orig, { 'src/other.mjs': 'x' }).reasons.join(), /outside the contract/);
    assert.match(checkCandidate(c, orig, { 'src/app.mjs': orig['src/app.mjs'] }).reasons.join(), /changes nothing/);
    const big = orig['src/app.mjs'] + Array.from({ length: 150 }, (_, i) => `// line ${i}`).join('\n');
    assert.match(checkCandidate(c, orig, { 'src/app.mjs': big }).reasons.join(), /change budget/);
    assert.ok(PROTECTED_PATTERNS.includes('**/__oracle_*'));
  });
  test('identity is computed by the coordinator from the files, not taken from the proposer', () => {
    const files = { 'src/app.mjs': parameterizeTemplateSql(orig['src/app.mjs']).text };
    const chk = checkCandidate(c, orig, files);
    assert.equal(chk.ok, true, chk.reasons.join());
    const a = makeCandidate(c, orig, { generator: 'user-supplied', generatorIdentity: 'x', files, accounting: { tokens: 5 } }, chk).candidate;
    const b = makeCandidate(c, orig, { generator: 'user-supplied', generatorIdentity: 'y', files, accounting: { tokens: 999 } }, chk).candidate;
    assert.equal(a.candidateId, b.candidateId);
    assert.equal(a.accounting.usd, null, 'unknown cost is null, never zero');
  });
});

describe('the deterministic SQL recipe', () => {
  test('parameterizes quoted values and refuses an interpolation a placeholder cannot carry', () => {
    const r = parameterizeTemplateSql("const r = db.prepare(`SELECT a FROM t WHERE x = '${x}' AND y = '${y}'`).all();");
    assert.equal(r.text, "const r = db.prepare('SELECT a FROM t WHERE x = ? AND y = ?').all(x, y);");
    const ident = parameterizeTemplateSql('const r = db.prepare(`SELECT a FROM ${table} WHERE x = 1`).all();');
    assert.equal(ident.applied, 0);
    assert.match(ident.refused.join(), /not a quoted SQL value/);
    assert.equal(parameterizeTemplateSql("db.prepare(`SELECT a FROM t WHERE x = '${x}'`).all(extra);").applied, 0);
  });
});

describe('[FR-17] budgets and policy', () => {
  test('budgets stay within their ceilings; an unknown key or a zero is an error, never clamped', () => {
    assert.equal(resolveBudgets({}).budgets.rounds, 3);
    assert.match(resolveBudgets({ rounds: 0 }).errors.join(), /rounds/);
    assert.match(resolveBudgets({ rounds: 99 }).errors.join(), /rounds/);
    assert.match(resolveBudgets({ forever: 1 }).errors.join(), /unknown budget/);
  });
  test('[AC-17.6] a policy cannot ask for a model in this milestone, and cannot carry execution', () => {
    assert.match(validatePolicy({ schema: 'agentic-security/repair-policy', model: 'remote' }).errors.join(), /only 'none'/);
    assert.match(validatePolicy({ schema: 'agentic-security/repair-policy', allowExecution: true }).errors.join(), /unknown field/);
  });
});

describe('[AC-04.5] CLI and MCP derive the same obligations', () => {
  test('repair_plan returns the same contract and obligations as the shared plan function, executes nothing and echoes no header value', async () => {
    const root = authzRoot();
    const viaShared = planFromInputs({ root, profilePath: path.join(root, 'profile.json'), family: 'object-authorization', file: 'src/app.mjs' });
    const { repair_plan } = makeRepairTools({ confine: (r, p) => path.resolve(r, p), META: {} });
    const viaMcp = await repair_plan.handler({ profile_file: 'profile.json', family: 'object-authorization', file: 'src/app.mjs' }, { sessionRoot: root });
    assert.equal(viaMcp.ok, true, viaMcp.reason);
    assert.equal(viaMcp.contractId, viaShared.plan.contract.contractId);
    assert.deepEqual(viaMcp.obligations, obligationSummary(viaShared.plan.contract));
    assert.equal(JSON.stringify(viaMcp).includes('tokalice'), false);
    assert.equal(viaShared.plan.contract.policyFacts[0].approval, 'declared', 'a profile inside the repository is declared, never approved');
    assert.equal(fs.existsSync(path.join(root, '.agentic-security')), false, 'planning wrote nothing');
  });
});

describe('[M3-03] server-side request forgery and path traversal contracts (no execution)', () => {
  const ssrfRoot = () => copy('ssrf-preview');
  const fsRoot = () => copy('files-download');
  const attacks = (c, id) => c.obligations.find((o) => o.id === id).inputs.requests.filter((r) => r.role === 'attack').map((r) => decodeURIComponent(r.path.split('=')[1]));

  test('the SSRF contract attacks every forbidden host by name and address, follows a declared redirect off the approved set, and seals respellings', () => {
    const b = build(ssrfRoot(), { family: 'ssrf' });
    assert.deepEqual([...b.problems, ...b.blocked], []);
    const dev = attacks(b.contract, 'ssrf-attacks-development');
    for (const v of ['http://metadata.internal/latest/meta-data/', 'http://169.254.169.254/latest/meta-data/', 'http://admin.internal/', 'http://10.0.0.7/', 'http://api.partner.test/r/meta']) assert.ok(dev.includes(v), v);
    assert.ok(!dev.some((v) => v.includes('cdn.partner.test')), 'an approved host is never an attack target');
    const sealed = attacks(b.contract, 'ssrf-attacks-sealed');
    assert.ok(sealed.includes('http://2852039166/latest/meta-data/') && sealed.includes('http://METADATA.INTERNAL./latest/meta-data/'));
    assert.ok(sealed.every((v) => !dev.includes(v)), 'the sealed set never repeats a development value');
    const dreq = b.contract.obligations.find((o) => o.id === 'ssrf-attacks-development').inputs.requests.find((r) => r.role === 'attack');
    assert.deepEqual(dreq.forbid, { secrets: ['cloud-credential', 'admin-panel'], connections: true });
    assert.equal(b.contract.obligations.find((o) => o.id === 'ssrf-attacks-development').inputs.network.policy, 'allowlist');
  });

  test('a public-only policy forbids a host that can rebind from a public to a private address', () => {
    const b = build(copy('ssrf-rebind'), { family: 'ssrf' });
    assert.deepEqual([...b.problems, ...b.blocked], []);
    const dev = attacks(b.contract, 'ssrf-attacks-development');
    assert.ok(dev.includes('http://rebind.example.test/'));
    assert.ok(!dev.some((v) => v.includes('hooks.example.test')));
  });

  test('the traversal contract escapes by relative path, by absolute path and through a link out of the root; the link inside the root is legitimate', () => {
    const b = build(fsRoot(), { family: 'path-traversal' });
    assert.deepEqual([...b.problems, ...b.blocked], []);
    const dev = attacks(b.contract, 'filesystem-attacks-development');
    for (const v of ['../outside/secret.txt', '{{fs:abs}}/outside/secret.txt', 'latest/secret.txt', '../public-archive/old.txt']) assert.ok(dev.includes(v), v);
    assert.ok(!dev.some((v) => v.startsWith('current/')), 'a link that stays inside the root is not an attack');
    assert.ok(attacks(b.contract, 'filesystem-attacks-sealed').includes('docs/../../outside/secret.txt'));
  });

  test('a declaration with nothing forbidden, or no planted secret outside the root, is blocked, never a contract that could pass', () => {
    const r = ssrfRoot(); const p = profileOf(r);
    p.ssrf.approved = p.ssrf.hosts.map((h) => h.name);
    assert.match(build(r, { family: 'ssrf', profile: p }).blocked.join(' '), /no forbidden destination/);
    const f = fsRoot(); const q = profileOf(f);
    q.filesystem.tree['outside/secret.txt'] = 'nothing planted';
    q.filesystem.tree['public-archive/old.txt'] = 'nothing planted';
    assert.match(build(f, { family: 'path-traversal', profile: q }).blocked.join(' '), /no file outside the allowed root plants/);
  });

  test('profiles: a link that escapes the tree, an unknown host field, an IP as a host name and the python runtime are refused', () => {
    const q = profileOf(fsRoot());
    q.filesystem.links = { 'public/up': '../../..' };
    assert.match(validateProfile(q).join(' '), /must point inside the tree/);
    const p = profileOf(ssrfRoot());
    p.ssrf.hosts[0].weight = 1;
    assert.match(validateProfile(p).join(' '), /unknown field 'weight'/);
    const p2 = profileOf(ssrfRoot());
    p2.ssrf.hosts[0].name = '10.0.0.1';
    assert.match(validateProfile(p2).join(' '), /unique lower-case host name/);
    const p3 = profileOf(ssrfRoot());
    p3.application.runtime = 'python'; p3.application.entry = 'app.py'; p3.application.files = ['app.py'];
    assert.match(validateProfile(p3).join(' '), /node runtime only/);
  });

  test('the network and the file tree are part of the contract identity', () => {
    const r = ssrfRoot();
    const base = build(r, { family: 'ssrf' }).contract.contractId;
    const p = profileOf(r);
    p.ssrf.hosts[2].addresses = ['169.254.169.253'];
    assert.notEqual(build(r, { family: 'ssrf', profile: p }).contract.contractId, base);
  });

  test('[AC-12.2] a candidate may not introduce a primitive below the layer the oracles observe', () => {
    const r = ssrfRoot();
    const c = build(r, { family: 'ssrf' }).contract;
    const original = fs.readFileSync(path.join(r, 'src', 'app.mjs'), 'utf8');
    for (const [snippet, what] of [["import { execFile } from 'node:child_process';\n", 'a child process'], ["const tcp = process.binding('tcp_wrap');\n", 'a raw runtime binding'], ["import dgram from 'dgram';\n", 'a datagram socket']]) {
      const chk = checkCandidate(c, { 'src/app.mjs': original }, { 'src/app.mjs': snippet + original });
      assert.equal(chk.ok, false, what);
      assert.match(chk.reasons.join(' '), new RegExp(`introduces ${what}`));
    }
  });
});
