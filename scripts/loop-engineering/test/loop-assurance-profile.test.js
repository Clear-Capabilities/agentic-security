// LOOP-001 of the assurance-differentiation PRD: register that PRD with the
// existing controller. Criterion tags are the PRD's own IDs, so they are
// verified through the same tag convention as every other suite.
//
// The committed fixture keeps the section 8 STRUCTURE (70 requirements, 269
// weight, 210 criteria, weights, dependencies, suite keys) with placeholder
// text, so nothing here depends on the untracked PRD file being present. A
// separate untagged check compares the fixture with the real PRD when it exists.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync, existsSync, chmodSync, copyFileSync } from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { parsePrd, ImportError } from '../lib/prd-import.mjs';
import { loadProfile, validateProfile, ProfileError, suiteLaunchBlockers } from '../lib/profile.mjs';
import { buildRequirements, createManifest, loadManifest, writeManifest, computeAcceptanceHash, diffManifests } from '../lib/manifest.mjs';
import { effectiveWatch } from '../lib/evidence.mjs';
import { computeProgress } from '../lib/progress.mjs';
import { MiniRepo } from './helpers.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..', '..', '..');
const FIXTURE = join(HERE, 'fixtures', 'assurance-prd-section8.md');
const PROFILE_PATH = join(REPO, 'scripts', 'loop-engineering', 'profiles', 'assurance-differentiation.json');
const HASKELL_PROFILE_PATH = join(REPO, 'scripts', 'loop-engineering', 'profiles', 'haskell-nix.json');
const REAL_PRD = join(REPO, 'AGENTIC_SECURITY_DIFFERENTIATION_PRD.md');
const IMPORTER_SHA256 = 'de00e52c6fef81eb5471d8853fcae47ac54dafcd83247a6705032d6710c07a9e';

const fixtureText = () => readFileSync(FIXTURE, 'utf8');
const profile = () => structuredClone(loadProfile(PROFILE_PATH).profile);
const sha = (b) => createHash('sha256').update(b).digest('hex');

function expectedIds() {
  const ids = [];
  const range = (p, n) => { for (let i = 1; i <= n; i++) ids.push(`${p}-${String(i).padStart(3, '0')}`); };
  range('CORE', 4); range('LOOP', 4); range('QA', 8);
  for (const h of [2, 3, 4, 5, 6, 7]) for (let i = 1; i <= 8; i++) ids.push(`X-${h}0${i}`);
  range('DOC', 3); range('REL', 3);
  return ids;
}

function freshRoot() {
  const root = mkdtempSync(join(tmpdir(), 'loop-assurance-'));
  copyFileSync(FIXTURE, join(root, 'PRD.md'));
  return root;
}
const manifestFor = (root, prof = profile(), prdPath = 'PRD.md') => createManifest({ repoRoot: root, prdPath, profile: prof, profileSha: 'a'.repeat(64) });

// ---------------------------------------------------------------- AC01

test('[LOOP-001.AC01] the unmodified importer parses all 70 requirement IDs, the declared totals, sequential criteria, weights, dependencies and suite keys', () => {
  assert.equal(sha(readFileSync(join(HERE, '..', 'lib', 'prd-import.mjs'))), IMPORTER_SHA256, 'the section-8 importer must stay byte-identical; changing it is a deliberate, reviewed act that updates this pin');
  const parsed = parsePrd(fixtureText());
  assert.deepEqual(parsed.totals, { requirements: 70, criteria: 210, weight: 269 });
  assert.deepEqual(parsed.declared, { requirements: 70, weight: 269, criteria: 210 });
  assert.deepEqual(parsed.requirements.map((r) => r.id), expectedIds());
  for (const r of parsed.requirements) {
    assert.deepEqual(r.criteria.map((c) => c.id), [1, 2, 3].map((n) => `${r.id}.AC0${n}`), `${r.id} criteria are sequential`);
    assert.ok(Number.isInteger(r.weight) && r.weight >= 1 && r.weight <= 5, `${r.id} weight`);
    assert.ok(Array.isArray(r.dependencies));
  }
  const byId = new Map(parsed.requirements.map((r) => [r.id, r]));
  assert.deepEqual(byId.get('CORE-002').dependencies, ['CORE-001']);
  assert.deepEqual(byId.get('CORE-004').dependencies, ['CORE-002', 'CORE-003']);
  assert.equal(byId.get('CORE-003').weight, 5);
  assert.deepEqual([...new Set(parsed.requirements.map((r) => r.suite))].sort(), ['capabilities', 'deployment-graph', 'documentation', 'evaluation', 'foundation', 'invariants', 'loop', 'portfolio', 'release', 'routing', 'verification']);
  assert.equal(parsed.requirements.reduce((n, r) => n + r.weight, 0), 269);
});

test('[LOOP-001.AC01] negative fixtures: duplicate IDs, cycles, unknown dependencies and wrong declared totals are each detected', () => {
  assert.doesNotThrow(() => parsePrd(fixtureText()), 'control: the unmodified fixture imports');
  const t = fixtureText();
  const must = (mutated, re, label) => assert.throws(() => parsePrd(mutated), (e) => e instanceof ImportError && re.test(e.message), label);
  must(t.replace('### CORE-002 — Fixture requirement CORE-002', '### CORE-001 — Fixture requirement CORE-001'), /duplicate requirement ID CORE-001/, 'duplicate ID');
  must(t.replace('Weight: 2 | Dependencies: none | Verification suite: `foundation`', 'Weight: 2 | Dependencies: CORE-004 | Verification suite: `foundation`'), /dependency cycle/, 'cycle');
  must(t.replace('Dependencies: CORE-001 | Verification suite: `foundation`', 'Dependencies: CORE-099 | Verification suite: `foundation`'), /unknown ID CORE-099/, 'unknown dependency');
  must(t.replace('**70 required requirements,', '**71 required requirements,'), /declares 71 requirements but 70 were parsed/, 'wrong requirement total');
  must(t.replace('269 total weight points', '270 total weight points'), /declares 270 weight points but 269 were parsed/, 'wrong weight total');
  must(t.replace('210 acceptance criteria**', '211 acceptance criteria**'), /declares 211 acceptance criteria but 210 were parsed/, 'wrong criteria total');
  must(t.replace('- **CORE-001.AC02:** Placeholder acceptance text for CORE-001.AC02.\n', ''), /declares 210 acceptance criteria but 209 were parsed/, 'lost criterion');
});

test('[LOOP-001.AC01] altered acceptance text changes the acceptance hash and a frozen manifest then fails closed', () => {
  const root = freshRoot();
  try {
    const base = manifestFor(root);
    const text = fixtureText();
    const altered = text.replace('Placeholder acceptance text for CORE-001.AC01.', 'Placeholder acceptance text for CORE-001.AC01, quietly weakened.');
    assert.notEqual(altered, text);
    // The importer cannot know the text was edited (totals still agree), so the hash is the detector.
    const parsedAltered = parsePrd(altered);
    assert.deepEqual(parsedAltered.totals, { requirements: 70, criteria: 210, weight: 269 });
    writeFileSync(join(root, 'PRD.md'), altered);
    const next = manifestFor(root);
    assert.notEqual(next.manifest.acceptanceHash, base.manifest.acceptanceHash, 'altered text produces a different acceptance hash');
    assert.deepEqual(diffManifests(base.manifest, next.manifest).changed, ['CORE-001'], 'the diff names exactly the requirement whose text changed');
    // control: re-importing identical text reproduces the hash
    writeFileSync(join(root, 'PRD.md'), text);
    assert.equal(manifestFor(root).manifest.acceptanceHash, base.manifest.acceptanceHash);
    // a frozen manifest edited after the fact is rejected on load
    writeManifest(root, base.manifest);
    assert.equal(loadManifest(root).ok, true, 'control: the untouched frozen manifest loads');
    const file = join(root, '.loop-engineering', 'manifest', 'requirements.v1.json');
    const frozen = existsSync(file) ? file : null;
    assert.ok(frozen, 'manifest file location');
    writeFileSync(frozen, readFileSync(frozen, 'utf8').replace('Placeholder acceptance text for CORE-001.AC01.', 'weakened after freezing'));
    const bad = loadManifest(root);
    assert.equal(bad.ok, false);
    assert.match(bad.error, /acceptance hash mismatch/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('[real-prd] the committed fixture matches the real PRD structure when the untracked PRD is present', (t) => {
  if (!existsSync(REAL_PRD)) { t.skip('AGENTIC_SECURITY_DIFFERENTIATION_PRD.md is not present in this checkout (it is untracked by convention); real-PRD parity NOT checked'); return; }
  const real = parsePrd(readFileSync(REAL_PRD, 'utf8'));
  const fix = parsePrd(fixtureText());
  assert.deepEqual(real.totals, { requirements: 70, criteria: 210, weight: 269 });
  const shape = (p) => p.requirements.map((r) => ({ id: r.id, weight: r.weight, dependencies: r.dependencies, suite: r.suite, criteria: r.criteria.map((c) => c.id) }));
  assert.deepEqual(shape(fix), shape(real), 'fixture drifted from the real PRD structure; regenerate it');
});

// ---------------------------------------------------------------- AC02

const PRODUCT = ['evaluation', 'verification', 'deployment-graph', 'invariants', 'capabilities', 'routing', 'portfolio'];
const EXPECT_WS = (id) => {
  const [p, n] = id.split('-');
  if (p === 'CORE') return 'foundation';
  if (p === 'LOOP') return 'loop';
  if (p === 'QA') return 'evaluation';
  if (p === 'DOC') return 'documentation';
  if (p === 'REL') return 'release';
  return { 2: 'verification', 3: 'deployment-graph', 4: 'invariants', 5: 'capabilities', 6: 'routing', 7: 'portfolio' }[n[0]];
};

test('[LOOP-001.AC02] every one of the 70 requirements maps to an executable suite, a non-empty evidence watch set and exactly one workstream', () => {
  const root = freshRoot();
  try {
    const prof = profile();
    assert.doesNotThrow(() => validateProfile(prof, root));
    const { manifest } = manifestFor(root, prof);
    assert.equal(manifest.requirements.length, 70);
    for (const r of manifest.requirements) {
      const suite = prof.suites[r.suite];
      assert.ok(suite, `${r.id}: suite ${r.suite} is registered`);
      assert.equal(r.verification.kind, 'node-test', `${r.id} runs through the node-test verifier`);
      assert.ok(r.verification.files.length >= 1 && r.verification.args[0] === '--test', `${r.id}: executable suite command`);
      assert.ok(r.verification.timeoutSeconds > 0 && Number.isInteger(r.verification.timeoutSeconds), `${r.id}: finite suite timeout`);
      assert.ok(r.watch.length >= 1, `${r.id}: evidence watch set`);
      assert.equal(r.workstream, EXPECT_WS(r.id), `${r.id}: workstream`);
      assert.equal(r.workstream, r.suite, `${r.id}: the PRD suite key and the workstream coincide`);
    }
    const counts = {};
    for (const r of manifest.requirements) counts[r.workstream] = (counts[r.workstream] || 0) + 1;
    assert.deepEqual(counts, { foundation: 4, loop: 4, evaluation: 8, verification: 8, 'deployment-graph': 8, invariants: 8, capabilities: 8, routing: 8, portfolio: 8, documentation: 3, release: 3 });
    assert.deepEqual(manifest.workstreams.order.filter((k) => manifest.workstreams.kinds[k] === 'product'), PRODUCT, 'seven product workstreams');
    assert.equal(manifest.workstreams.order.length, 11, 'seven product workstreams plus foundation, loop, documentation, release');
    // evidence invalidation includes transitive dependencies' watch sets
    const byId = new Map(manifest.requirements.map((r) => [r.id, r]));
    const core001Only = byId.get('CORE-001').watch;
    const w = effectiveWatch(manifest, byId.get('X-201'));
    for (const g of core001Only) assert.ok(w.includes(g), `X-201 inherits transitive watch ${g}`);
    assert.ok(w.includes('scanner/src/fix/**'), 'X-201 watches its own workstream scope');
    assert.ok(w.includes('scripts/loop-engineering/profiles/assurance-differentiation.json'), 'the profile is in every watch set');
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('[LOOP-001.AC02] a requirement with no workstream, two workstreams, no suite or no watch set is refused with a named reason', () => {
  const root = freshRoot();
  try {
    const parsed = parsePrd(fixtureText());
    const build = (p) => buildRequirements({ parsed, profile: p, repoRoot: root });
    assert.doesNotThrow(() => build(profile()), 'control');
    const unassigned = profile(); unassigned.workstreams.assign = unassigned.workstreams.assign.filter((r) => r.prefix !== 'DOC');
    assert.throws(() => build(unassigned), /DOC-001: matches no workstream rule/);
    const overlap = profile(); overlap.workstreams.assign.push({ prefix: 'X', from: 201, to: 210, workstream: 'routing' });
    assert.throws(() => build(overlap), /X-201: matches 2 workstream rules/);
    const noSuite = profile(); delete noSuite.suites.routing;
    assert.throws(() => build(noSuite), /X-601: suite "routing" has no command mapping/);
    const noWatch = profile(); delete noWatch.workstreams.definitions.release.watch;
    assert.throws(() => validateProfile(noWatch, root), (e) => e instanceof ProfileError && /definitions\.release\.watch must be a non-empty list/.test(e.message));
    const unknownWs = profile(); unknownWs.workstreams.assign[0].workstream = 'nope';
    assert.throws(() => validateProfile(unknownWs, root), /not a defined workstream/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test('[LOOP-001.AC02] optional grouping adds a workstream view for this PRD and leaves the haskell-nix profile and manifest shape untouched', () => {
  const root = freshRoot();
  try {
    const { manifest } = manifestFor(root);
    const assess = new Map(manifest.requirements.map((r) => [r.id, { verified: false, stale: false, fresh: false, passedCriteria: 0, latest: null }]));
    const p = computeProgress(manifest, assess);
    assert.deepEqual(Object.keys(p.workstreams), manifest.workstreams.order);
    assert.equal(Object.values(p.workstreams).reduce((n, w) => n + w.totalWeight, 0), 269, 'workstream weights partition the denominator');
    assert.equal(Object.values(p.workstreams).reduce((n, w) => n + w.totalRequirements, 0), 70);
    assert.equal(p.workstreams.evaluation.totalWeight, manifest.requirements.filter((r) => r.workstream === 'evaluation').reduce((n, r) => n + r.weight, 0));
    assert.equal(p.verifiedPercent, 0);
    // one verified requirement moves exactly its own workstream
    assess.set('CORE-001', { verified: true, stale: false, fresh: true, passedCriteria: 3, latest: { ev: { criteria: [], evidenceId: 'e', result: 'pass', createdAt: 'now' }, file: 'f' } });
    const p2 = computeProgress(manifest, assess);
    assert.equal(p2.workstreams.foundation.verifiedRequirements, 1);
    assert.equal(p2.workstreams.loop.verifiedRequirements, 0);
    assert.equal(p2.verifiedWeight, 2);

    // compatibility: haskell-nix has no workstreams block, still validates, and produces no workstream fields
    const hs = loadProfile(HASKELL_PROFILE_PATH).profile;
    assert.equal(hs.workstreams, undefined);
    assert.doesNotThrow(() => validateProfile(hs, root));
    const mini = ['### HS-001 — one', '', 'Weight: 2 | Dependencies: none | Verification suite: `haskell-parser`', '', 'x', '', 'Acceptance:', '', '- **HS-001.AC01:** works', '', '### QA-001 — two', '', 'Weight: 1 | Dependencies: HS-001 | Verification suite: `haskell-ir`', '', 'y', '', 'Acceptance:', '', '- **QA-001.AC01:** works', ''].join('\n');
    const prd = `# t\n\n## 8. Atomic implementation requirements\n\n**2 required requirements, 3 total weight points, 2 acceptance criteria**\n\n${mini}\n## 9. End\n`;
    const reqs = buildRequirements({ parsed: parsePrd(prd), profile: hs, repoRoot: root });
    for (const r of reqs) assert.equal('workstream' in r, false, `${r.id} has no workstream field under haskell-nix`);
    const hsManifest = { requirements: reqs };
    const hp = computeProgress(hsManifest, new Map(reqs.map((r) => [r.id, { verified: false, stale: false, fresh: false, passedCriteria: 0, latest: null }])));
    assert.equal('workstreams' in hp, false);
    assert.deepEqual(Object.keys(hp.categories).sort(), ['haskell', 'quality']);
  } finally { rmSync(root, { recursive: true, force: true }); }
});

// ---------------------------------------------------------------- AC03

const STAND_IN = `#!/usr/bin/env node
// Stand-in for the model CLI used by preflight tests. It never calls a model: it answers --version, --help
// and \`auth status\` and records every invocation, so a test can prove nothing else was ever run.
const fs = require('node:fs');
const a = process.argv.slice(2);
fs.appendFileSync(__dirname + '/stand-in-calls.log', JSON.stringify(a) + '\\n');
if (a[0] === '--version') { console.log('0.0.0-stand-in'); process.exit(0); }
if (a[0] === '--help') { console.log(['--print', '--output-format', '--verbose', '--permission-mode', '--allowedTools', '--disallowedTools', '--max-budget-usd', '--permission-prompts', '--no-session-persistence', '--strict-mcp-config', '--mcp-config', '--model'].join('\\n')); process.exit(0); }
if (a[0] === 'auth' && a[1] === 'status') { console.log(JSON.stringify({ loggedIn: true, authMethod: 'stand-in', apiProvider: 'none' })); process.exit(0); }
process.stderr.write('stand-in refuses to act as a model\\n'); process.exit(3);
`;

// A disposable checkout holding the fixture PRD, the assurance profile with
// every suite wrapper present (as it will be once the wrappers are authored),
// and a stand-in worker command.
function disposable(mutate = () => {}, { keepNotYetRunnable = false } = {}) {
  const repo = new MiniRepo([{ id: 'LOOP-001', weight: 2, criteria: ['one'] }]);
  copyFileSync(FIXTURE, repo.path('PRD.md'));
  const bin = repo.path('stand-in-claude');
  writeFileSync(bin, STAND_IN); chmodSync(bin, 0o755);
  const p = profile();
  p.worker.command = bin;
  p.serve.port = 0;
  p.limits.resource.minFreeDiskGiB = 1;
  for (const [k, s] of Object.entries(p.suites)) {
    if (!keepNotYetRunnable) delete s.notYetRunnable;
    s.files = [`t/${k}.test.js`];
    writeFileSync(repo.path('t', `${k}.test.js`), `import test from 'node:test';\ntest('[disposable] ${k}', () => {});\n`);
  }
  mutate(p, repo);
  repo.writeProfile(p);
  return repo;
}
const pre = async (repo) => { const r = await repo.cli(['preflight', '--json']); let j = null; try { j = JSON.parse(r.stdout); } catch { /* not json */ } return { ...r, json: j }; };
const check = (r, name) => r.json?.checks.find((c) => c.check === name);

test('[LOOP-001.AC03] validation and a bounded preflight succeed on a disposable checkout with a scripted worker, and no model is ever called', async () => {
  const repo = disposable();
  try {
    const init = await repo.init();
    assert.equal(init.code, 0, init.stdout + init.stderr);
    assert.match(init.stdout, /70 requirements, 210 criteria, 269 weight points/);
    const r = await pre(repo);
    assert.equal(r.code, 0, r.stdout + r.stderr);
    assert.equal(r.json.ok, true);
    for (const name of ['manifest', 'profile', 'claude-cli', 'verification-executables', 'suites-runnable', 'process-isolation']) assert.equal(check(r, name)?.status, 'pass', `${name}: ${JSON.stringify(check(r, name))}`);
    assert.match(check(r, 'profile').detail, /assurance-differentiation; finite budgets: 43200s wall, 150 attempts, \$50/);
    assert.ok(r.ms < 30000, `bounded: ${r.ms} ms`);
    const calls = readFileSync(repo.path('stand-in-calls.log'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    for (const c of calls) assert.ok(['--version', '--help', 'auth'].includes(c[0]), `unexpected stand-in invocation ${JSON.stringify(c)}`);
    assert.equal(calls.some((c) => c.includes('--print')), false, 'preflight never runs a prompt');
  } finally { await repo.cleanup(); }
});

test('[LOOP-001.AC03] a nonexistent suite refuses launch with the suite and the reason, at init, preflight and start', async () => {
  // (a) a requirement whose suite key has no mapping: init refuses
  const unmapped = disposable((p) => { delete p.suites.routing; });
  try {
    const init = await unmapped.init();
    assert.equal(init.code, 1, 'init refuses');
    assert.match(init.stdout + init.stderr, /X-601: suite "routing" has no command mapping/);
  } finally { await unmapped.cleanup(); }
  // (b) a registered suite whose protected wrapper file is absent: preflight and start refuse
  const missingFile = disposable((p) => { p.suites.routing.files = ['t/does-not-exist.test.js']; });
  try {
    assert.equal((await missingFile.init()).code, 0, 'structurally valid profiles still initialise');
    const r = await pre(missingFile);
    assert.equal(r.code, 1);
    assert.match(check(r, 'suites-runnable').detail, /routing \(protected wrapper file\(s\) not found: t\/does-not-exist\.test\.js; author them in the supervising session before launch\)/);
    const s = await missingFile.cli(['start', '--background']);
    assert.notEqual(s.code, 0, 'start refuses');
    assert.match(s.stderr, /refusing to launch: 1 suite\(s\) cannot run yet: routing/);
    assert.equal(missingFile.exists('.loop-engineering/lock.json') && missingFile.read('.loop-engineering/lock.json').includes('pid'), false, 'no controller was started');
  } finally { await missingFile.cleanup(); }
  // (c) a suite declared not yet runnable is reported as a blocker, never silently passed
  const declared = disposable(() => {}, { keepNotYetRunnable: true });
  try {
    assert.equal((await declared.init()).code, 0);
    const r = await pre(declared);
    assert.equal(r.code, 1);
    assert.match(check(r, 'suites-runnable').detail, /10 suite\(s\) cannot run yet: .*foundation \(declared not yet runnable: protected wrapper scripts\/assurance-differentiation\/test\/foundation\.test\.js is not authored yet/);
    assert.doesNotMatch(check(r, 'suites-runnable').detail, /loop \(/, 'the loop suite is runnable and is not listed');
  } finally { await declared.cleanup(); }
});

test('[LOOP-001.AC03] a missing tool refuses launch and names the tool and the remedy', async () => {
  const noTool = disposable((p) => {
    p.approvedExecutables.push('no-such-tool-xyz');
    p.suites.release.executable = 'no-such-tool-xyz';
  });
  try {
    assert.equal((await noTool.init()).code, 0);
    const r = await pre(noTool);
    assert.equal(r.code, 1);
    assert.equal(check(r, 'verification-executables').status, 'fail');
    assert.match(check(r, 'verification-executables').detail, /not found on PATH: no-such-tool-xyz; install it, or remove it from approvedExecutables/);
  } finally { await noTool.cleanup(); }
  const noWorker = disposable((p) => { p.worker.command = join(tmpdir(), 'no-such-worker-binary-xyz'); });
  try {
    assert.equal((await noWorker.init()).code, 0);
    const r = await pre(noWorker);
    assert.equal(r.code, 1);
    assert.equal(check(r, 'claude-cli').status, 'fail');
    assert.match(check(r, 'claude-cli').detail, /not found on PATH/);
  } finally { await noWorker.cleanup(); }
});

test('[LOOP-001.AC03] an unbounded budget refuses launch (init, preflight and start), while the bounded profile passes', async () => {
  for (const [label, mutate, re] of [
    ['null run budget', (p) => { p.limits.claudeBudgetUsd = null; }, /limits\.claudeBudgetUsd must be a finite positive number \(budgets are never unbounded\)/],
    ['"unlimited" per-attempt budget', (p) => { p.limits.perAttemptBudgetUsd = 'unlimited'; }, /limits\.perAttemptBudgetUsd must be a finite positive number/],
    ['missing wall-clock limit', (p) => { delete p.limits.runWallSeconds; }, /limits\.runWallSeconds must be a finite positive number/],
    ['zero attempt cap', (p) => { p.limits.runMaxAttempts = 0; }, /limits\.runMaxAttempts must be a finite positive number/],
    ['per-attempt above the run budget', (p) => { p.limits.perAttemptBudgetUsd = 60; }, /perAttemptBudgetUsd exceeds the whole-run budget/],
  ]) {
    const bad = disposable(mutate);
    try {
      const init = await bad.init();
      assert.equal(init.code, 1, `${label}: init refuses`);
      assert.match(init.stdout + init.stderr, re, label);
    } finally { await bad.cleanup(); }
  }
  // a profile edited to be unbounded AFTER init is still refused by preflight and start
  const repo = disposable();
  try {
    assert.equal((await repo.init()).code, 0);
    const p = JSON.parse(repo.read('profile.json')); p.limits.claudeBudgetUsd = null; repo.writeProfile(p);
    const r = await pre(repo);
    assert.equal(r.code, 1);
    assert.equal(check(r, 'profile').status, 'fail');
    assert.match(check(r, 'profile').detail, /finite positive number/);
    const s = await repo.cli(['start', '--background']);
    assert.notEqual(s.code, 0);
    assert.match(s.stderr, /refusing to launch: invalid execution profile/);
  } finally { await repo.cleanup(); }
});

test('[LOOP-001.AC03] an incompatible profile refuses launch with an actionable reason', async () => {
  for (const [label, mutate, re] of [
    ['future profile version', (p) => { p.profileVersion = 2; }, /profileVersion 2 is not supported: this controller reads profileVersion 1; migrate the profile/],
    ['missing profile version', (p) => { delete p.profileVersion; }, /profileVersion undefined is not supported|profileVersion .* is not supported/],
    ['non-loopback dashboard', (p) => { p.serve.host = '0.0.0.0'; }, /serve\.host must be 127\.0\.0\.1/],
    ['two editing workers', (p) => { p.worker.concurrency = 2; }, /worker\.concurrency must be 1/],
    ['bypass permission mode', (p) => { p.worker.permissionMode = 'bypassPermissions'; }, /not an approved non-bypass mode/],
    ['unknown workstream', (p) => { p.workstreams.assign[0].workstream = 'nope'; }, /not a defined workstream/],
    ['workstream without a watch set', (p) => { p.workstreams.definitions.loop.watch = []; }, /definitions\.loop\.watch must be a non-empty list/],
    ['unenforced entry without a reason', (p) => { p.unenforced[0].note = ''; }, /unenforced\[0\]\.note must say why/],
  ]) {
    const bad = disposable(mutate);
    try {
      const init = await bad.init();
      assert.equal(init.code, 1, `${label}: init refuses`);
      assert.match(init.stdout + init.stderr, re, label);
    } finally { await bad.cleanup(); }
  }
  // control: the same disposable with no mutation initialises
  const ok = disposable();
  try { assert.equal((await ok.init()).code, 0); } finally { await ok.cleanup(); }
  // an unsuspecting profile for another controller version is also refused by start after init
  const later = disposable();
  try {
    assert.equal((await later.init()).code, 0);
    const p = JSON.parse(later.read('profile.json')); p.profileVersion = 2; later.writeProfile(p);
    const s = await later.cli(['start', '--background']);
    assert.notEqual(s.code, 0);
    assert.match(s.stderr, /refusing to launch: .*profileVersion 2 is not supported/s);
  } finally { await later.cleanup(); }
});

test('[LOOP-001.AC03] the real profile carries the PRD section 7 limits as finite caps and discloses every control the controller cannot enforce', () => {
  const p = profile();
  assert.doesNotThrow(() => validateProfile(p, REPO));
  assert.deepEqual({ ...p.limits, resource: undefined }, {
    heartbeatSeconds: 5, workerIdleSeconds: 180, noProgressSeconds: 600, subprocessWallSeconds: 120, killGraceSeconds: 10,
    claudeAttemptSeconds: 1200, claudeMaxTurns: 80, attemptsPerRequirement: 3, sameFailureRepeats: 2,
    runWallSeconds: 43200, runMaxAttempts: 150, claudeBudgetUsd: 50, perAttemptBudgetUsd: 6, retryBackoffMaxSeconds: 60, resource: undefined,
  });
  assert.deepEqual({ ...p.limits.resource, cpu: undefined }, { maxRssMiB: 6144, maxOutputMiB: 256, maxLogMiB: 5, minFreeDiskGiB: 5, cpu: undefined });
  assert.equal(p.worker.concurrency, 1);
  assert.equal(p.worker.permissionMode, 'dontAsk');
  assert.deepEqual([p.serve.host, p.serve.port], ['127.0.0.1', 4317]);
  const gaps = new Map(p.unenforced.map((u) => [u.field, u]));
  for (const f of ['heartbeatSeconds', 'networkRequestSeconds', 'networkRetries', 'providerEnvelopeUsd', 'budgetsAreCapsNotAuthorization', 'linuxEnforcementBackend']) assert.ok(gaps.has(f), `${f} is disclosed`);
  for (const u of p.unenforced) assert.ok(u.note.length > 20 && u.status, `${u.field} states a status and a reason`);
  // honest status of the registered suites on THIS checkout: loop is runnable, the rest are declared blockers
  const blockers = new Map(suiteLaunchBlockers(p, REPO).map((b) => [b.suite, b.reason]));
  assert.equal(blockers.has('loop'), false, 'the loop suite wrapper exists');
  assert.equal(blockers.size, 10, 'every other suite is reported as a blocker');
  for (const [k, reason] of blockers) assert.match(reason, /not yet runnable/, `${k} is declared, not silently passed`);
  // control: a runnable suite reports no blocker, and the mutation path reports one
  const q = profile(); delete q.suites.foundation.notYetRunnable;
  assert.match(suiteLaunchBlockers(q, REPO).find((b) => b.suite === 'foundation').reason, /protected wrapper file\(s\) not found/);
});
