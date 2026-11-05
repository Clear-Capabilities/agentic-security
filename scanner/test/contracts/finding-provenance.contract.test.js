// Contract test for finding provenance (docs/reference/finding-provenance-contract.md): runs the real scan over small git
// histories and holds the record, its parts, the terminal states, the confidence reasons, the eligibility categories, the identity
// rules, the default behaviour, the shared timeout and the latency budget to the page, in both directions.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import { readPage, fieldsUnder, sameFields, REPO } from '../helpers/contract-page.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runScan } from '../../src/runScan.js';
import { PROVENANCE_STATUS, redactFindingProvenance } from '../../src/posture/provenance/schema.js';
import { PROVENANCE_DEFAULT_TIMEOUT_MS, MIN_PER_FINDING_BUDGET_MS, MAX_PROVIDER_ENRICHMENTS_PER_SCAN } from '../../src/posture/provenance/coordinator.js';
import { ATTRIBUTION_CATEGORIES, ATTRIBUTION_TARGET, MIN_ELIGIBLE_FOR_RATE } from '../../src/posture/provenance/coverage.js';

const CLI = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'bin', 'agentic-security.js');
const PAGE = readPage('docs/reference/finding-provenance-contract.md');
const SAFE = 'function h(req) {\n  return 1;\n}\n';
const VULN = 'function h(req) {\n  const input = req.query.id;\n  db.query("SELECT * FROM t WHERE id = " + input);\n}\n';
const git = (cwd, args) => execFileSync('git', args, { cwd, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();

function introduced(fx) {
  fx.writeFile('server.js', SAFE);
  fx.commit('safe baseline', { date: '2026-01-01T00:00:00Z', authorName: 'Alice', authorEmail: 'alice@example.com' });
  fx.writeFile('server.js', VULN);
  return fx.commit('introduce sqli', { date: '2026-01-02T00:00:00Z', authorName: 'Bob', authorEmail: 'bob@example.com' });
}

async function withEnv(overrides, fn) {
  const prior = {};
  for (const [k, v] of Object.entries(overrides)) { prior[k] = process.env[k]; if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  try { return await fn(); } finally {
    for (const [k, v] of Object.entries(prior)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  }
}

async function provenanceOf(root, env = {}) {
  const { scan } = await withEnv(env, () => runScan(root, { network: false }));
  const f = (scan.findings || []).find((x) => x.file === 'server.js' && /^SQL Injection$/.test(x.vuln || ''));
  assert.ok(f, 'the fixture finding fires');
  return f.findingProvenance;
}

function statesOnPage() { return fieldsUnder(PAGE, 'Terminal states'); }

test('record: every table on the page matches the record a deep-mode scan emits, field for field', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  const origin = introduced(fx);
  const fp = await provenanceOf(fx.root, { AGENTIC_SECURITY_PROVENANCE_MODE: 'deep' });
  assert.equal(fp.status, 'complete');
  assert.equal(fp.findingOrigin.commit, origin);
  sameFields(fp, fieldsUnder(PAGE, 'Record'), 'record');
  sameFields(fp.findingOrigin, fieldsUnder(PAGE, 'Origin'), 'origin');
  sameFields(fp.branchIntroduction, fieldsUnder(PAGE, 'Branch introduction'), 'branch introduction');
  sameFields(fp.firstObserved, fieldsUnder(PAGE, 'First observed'), 'first observed');
  assert.ok(fp.evidenceAttribution.length >= 1);
  for (const node of fp.evidenceAttribution) sameFields(node, fieldsUnder(PAGE, 'Evidence node'), 'evidence node', ['depChain']);
  sameFields(fp.confidence, fieldsUnder(PAGE, 'Confidence'), 'confidence');
  sameFields(fp.historyCoverage, fieldsUnder(PAGE, 'History coverage'), 'history coverage');
  sameFields(fp.analysisBasis, fieldsUnder(PAGE, 'Analysis basis'), 'analysis basis');
  assert.equal(fp.schemaVersion, '1.0');
  assert.equal(fp.findingOrigin.presentInCommit, true);
  assert.equal(fp.findingOrigin.revertOf, null);
  assert.equal(fp.findingOrigin.cherryPickOf, null);
  assert.deepEqual(fp.findingOrigin.aiAuthorship, { status: 'unknown', verifier: null });
  assert.equal(fp.confidence.level, 'high');
  assert.deepEqual(fp.confidence.reasons, ['parent_absence_verified', 'complete_history']);
  assert.equal(fp.method, 'semantic-history-replay');
  assert.match(fp.evidenceDigest, /^[0-9a-f]{64}$/);
});

test('terminal states and eligibility categories: the enums and the page list the same values', () => {
  assert.deepEqual([...statesOnPage()].sort(), Object.values(PROVENANCE_STATUS).sort());
  assert.deepEqual([...fieldsUnder(PAGE, 'Eligibility categories')].sort(), [...ATTRIBUTION_CATEGORIES].sort());
  assert.ok(PAGE.includes(`The target is \`${ATTRIBUTION_TARGET}\` on \`eligibleRate\`; with fewer than \`${MIN_ELIGIBLE_FOR_RATE}\` eligible findings`));
});

test('confidence reasons: every code the implementation can emit is on the page, and nothing else is', () => {
  const src = ['confidence.js', 'coordinator.js'].map((f) => fs.readFileSync(path.join(REPO, 'scanner/src/posture/provenance', f), 'utf8')).join('\n');
  const codes = new Set();
  for (const m of src.matchAll(/reasons\.push\(([^)]*)\)/g)) for (const c of m[1].matchAll(/'([a-z_]+)'/g)) codes.add(c[1]);
  for (const m of src.matchAll(/reasons: \[([^\]]*)\]/g)) for (const c of m[1].matchAll(/'([a-z_]+)'/g)) codes.add(c[1]);
  assert.deepEqual([...fieldsUnder(PAGE, 'Confidence reasons')].sort(), [...codes].sort());
});

test('never false certainty: a shallow clone is partial, a root commit is complete but capped at medium, an uncommitted line is uncommitted', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  introduced(fx);
  const clone = fs.mkdtempSync(path.join(os.tmpdir(), 'as-prov-contract-shallow-'));
  t.after(() => fs.rmSync(clone, { recursive: true, force: true }));
  execFileSync('git', ['clone', '--depth', '1', '--no-local', `file://${fx.root}`, clone], { stdio: 'ignore' });
  const shallow = await provenanceOf(clone);
  assert.equal(shallow.status, 'partial');
  assert.equal(shallow.historyCoverage.shallow, true);
  assert.equal(shallow.confidence.level, 'low');

  const root = createGitFixture();
  t.after(() => root.cleanup());
  root.writeFile('server.js', VULN);
  const only = root.commit('root commit with the flaw');
  const atRoot = await provenanceOf(root.root);
  assert.equal(atRoot.status, 'complete');
  assert.equal(atRoot.findingOrigin.commit, only);
  assert.deepEqual(atRoot.findingOrigin.absentInParents, []);
  assert.equal(atRoot.confidence.level, 'medium');
  assert.ok(atRoot.confidence.reasons.includes('no_parent_to_test'));

  const dirty = createGitFixture();
  t.after(() => dirty.cleanup());
  dirty.writeFile('server.js', SAFE);
  dirty.commit('safe');
  dirty.writeFile('server.js', VULN);
  const un = await provenanceOf(dirty.root);
  assert.equal(un.status, 'uncommitted');
  assert.equal(un.findingOrigin, null);
});

test('budget: an expired scan budget is budget_exhausted and is not cached, so the next scan resolves the finding', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  const origin = introduced(fx);
  const exhausted = await provenanceOf(fx.root, { AGENTIC_SECURITY_PROVENANCE_TIMEOUT_MS: '1' });
  assert.equal(exhausted.status, 'budget_exhausted');
  const later = await provenanceOf(fx.root);
  assert.equal(later.status, 'complete');
  assert.equal(later.findingOrigin.commit, origin);
  assert.equal(PROVENANCE_DEFAULT_TIMEOUT_MS, 60000);
  assert.equal(MIN_PER_FINDING_BUDGET_MS, 2000);
  assert.equal(MAX_PROVIDER_ENRICHMENTS_PER_SCAN, 20);
  const engine = fs.readFileSync(path.join(REPO, 'scanner/src/engine.js'), 'utf8');
  assert.ok(engine.includes('DETERMINISTIC_PROVENANCE_TIMEOUT_MS = 300000'));
  for (const n of ['`60000`', '`300000`', '`max(2000, remaining / findings)`', 'At most `20` per scan', '`8000` millisecond']) assert.ok(PAGE.includes(n), `the page states ${n}`);
});

test('deep mode: the origin carries the cherry-pick source when the walk resolves it directly, and a configured provider that cannot be reached is a recorded limitation', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  fx.writeFile('server.js', SAFE);
  fx.commit('safe baseline');
  const main = fx.currentBranch();
  fx.checkoutBranch('feature');
  fx.writeFile('server.js', VULN);
  const source = fx.commit('introduce on feature');
  fx.checkout(main);
  fx.writeFile('README.md', 'x\n');
  fx.commit('unrelated');
  git(fx.root, ['cherry-pick', '-x', source]);
  const picked = git(fx.root, ['rev-parse', 'HEAD']);
  git(fx.root, ['remote', 'add', 'origin', 'https://github.com/example/app.git']);
  fs.mkdirSync(path.join(fx.root, '.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(fx.root, '.agentic-security', 'provenance-providers.yml'), 'github:\n  token: t\n  baseUrl: http://127.0.0.1:9\n');
  const fp = await provenanceOf(fx.root, { AGENTIC_SECURITY_PROVENANCE_MODE: 'deep' });
  assert.equal(fp.status, 'complete');
  assert.equal(fp.findingOrigin.commit, picked);
  assert.equal(fp.findingOrigin.cherryPickOf, source);
  assert.equal(fp.providerEnrichment, null);
  assert.ok(fp.limitations.some((l) => /^provider metadata unavailable \(github: (network|timeout|http-\d+)\)/.test(l)), JSON.stringify(fp.limitations));
  assert.equal(fp.confidence.level, 'high');
});

test('identity: email withheld by default, included on request, and pseudonyms are stable', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  introduced(fx);
  const fp = await provenanceOf(fx.root);
  assert.equal(fp.findingOrigin.authorEmail, 'bob@example.com', 'the record itself holds the email; redaction is an output rule');
  assert.equal(redactFindingProvenance(fp).findingOrigin.authorEmail, null);
  assert.equal(redactFindingProvenance(fp).findingOrigin.authorName, 'Bob');
  assert.equal(redactFindingProvenance(fp, { includeEmail: true }).findingOrigin.authorEmail, 'bob@example.com');
  const a = redactFindingProvenance(fp, { pseudonymize: true }).findingOrigin;
  const b = redactFindingProvenance(fp, { pseudonymize: true }).findingOrigin;
  assert.match(a.authorName, /^Contributor-[0-9a-f]{8}$/);
  assert.equal(a.authorName, b.authorName);
  assert.equal(a.authorEmail, null);
});

test('defaults: scan leaves provenance off until a provenance flag is given; the overhead baseline is within the frozen budget the page states', async (t) => {
  const fx = createGitFixture();
  t.after(() => fx.cleanup());
  const origin = introduced(fx);
  const run = (args) => {
    const r = spawnSync(process.execPath, [CLI, 'scan', fx.root, '--format', 'json', ...args], { encoding: 'utf8', env: { ...process.env, AGENTIC_SECURITY_OFFLINE: '1', NO_COLOR: '1' } });
    const out = JSON.parse(r.stdout);
    const f = (out.findings || []).find((x) => /server\.js$/.test(x.file || '') && /^SQL Injection/.test(x.vuln || ''));
    assert.ok(f, `the finding is in the JSON output (${args.join(' ') || 'no flags'})`);
    return f.findingProvenance;
  };
  assert.equal(run([]).status, 'not_available');
  const on = run(['--provenance']);
  assert.equal(on.status, 'complete');
  assert.equal(on.findingOrigin.commit, origin);
  assert.equal(on.findingOrigin.authorEmail, null, 'the CLI output withholds the email by default');

  const baseline = JSON.parse(fs.readFileSync(path.join(REPO, 'bench/provenance/BASELINE.json'), 'utf8'));
  assert.equal(baseline.schema, 'provenance/v4');
  const budget = fieldsUnder(PAGE, 'Latency budget');
  assert.deepEqual(budget, ['cold', 'warm']);
  const onPage = (arm) => Number(/\| `(?:cold|warm)` \| `(\d+)` ms/.exec(PAGE.split('\n').find((l) => l.startsWith(`| \`${arm}\` |`)))[1]);
  assert.equal(onPage('cold'), baseline.budgetMs.coldAddedP95);
  assert.equal(onPage('warm'), baseline.budgetMs.warmAddedP95);
  assert.ok(baseline.cold.addedMs.p95 <= baseline.budgetMs.coldAddedP95, `committed cold p95 ${baseline.cold.addedMs.p95} within ${baseline.budgetMs.coldAddedP95}`);
  assert.ok(baseline.warm.addedMs.p95 <= baseline.budgetMs.warmAddedP95, `committed warm p95 ${baseline.warm.addedMs.p95} within ${baseline.budgetMs.warmAddedP95}`);
  const runner = fs.readFileSync(path.join(REPO, 'bench/provenance/runner.mjs'), 'utf8');
  assert.ok(runner.includes(`coldAddedP95: ${baseline.budgetMs.coldAddedP95}, warmAddedP95: ${baseline.budgetMs.warmAddedP95}`), 'the budget is frozen in the runner, not read from the baseline');
});
