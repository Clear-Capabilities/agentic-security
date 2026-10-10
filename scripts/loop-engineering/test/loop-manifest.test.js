// LOOP-001: versioned manifest, baseline and execution profile.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdirSync, existsSync, readdirSync, mkdtempSync, symlinkSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { parsePrd, ImportError } from '../lib/prd-import.mjs';
import { loadProfile, validateProfile, ProfileError } from '../lib/profile.mjs';
import { createManifest, loadManifest, computeAcceptanceHash, writeManifest } from '../lib/manifest.mjs';
import { MiniRepo, prdText } from './helpers.js';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
// The real document is untracked by convention (this repository is public), so a clean checkout, including the hosted release runner, has
// no copy of it. These tests use the committed structural fixture of its section 8; the comparison with the real document is the separate
// maintainer check `npm run test:loop-real-prd`.
const PRD_REL = 'scripts/loop-engineering/test/fixtures/haskell-prd-section8.md';
const PRD_PATH = join(REPO, PRD_REL);
const PROFILE_PATH = join(REPO, 'scripts', 'loop-engineering', 'profiles', 'haskell-nix.json');
const realPrd = () => readFileSync(PRD_PATH, 'utf8');
const realProfile = () => loadProfile(PROFILE_PATH).profile;

test('[LOOP-001.AC01] the committed section-8 fixture of the Haskell/Nix PRD imports to exactly the declared 57 requirements, 202 criteria and 220 weight', () => {
  const parsed = parsePrd(realPrd());
  assert.deepEqual(parsed.totals, { requirements: 57, criteria: 202, weight: 220 });
  assert.deepEqual(parsed.declared, { requirements: 57, weight: 220, criteria: 202 });
  const ids = parsed.requirements.map((r) => r.id);
  assert.equal(new Set(ids).size, ids.length, 'every requirement ID appears exactly once');
  const crit = parsed.requirements.flatMap((r) => r.criteria.map((c) => c.id));
  assert.equal(new Set(crit).size, 202, 'every criterion ID appears exactly once');
  // every criterion bullet in section 8 of the PRD text was captured (none lost)
  const sec8 = realPrd().split(/^## 8\. /m)[1].split(/^## 9\. /m)[0];
  const bullets = [...sec8.matchAll(/^- \*\*([A-Z]+-\d+\.AC\d{2}):\*\*/gm)].map((m) => m[1]);
  assert.deepEqual(crit.sort(), bullets.sort());
});

// A view of the repository without its controller state. createManifest reads the checkout's own frozen manifest to refuse a shrinking
// scope, so building from REPO itself fails the moment this checkout holds an initialised run of a DIFFERENT document, which is exactly
// the state the final gate runs this suite in. Everything else is symlinked, so suite files and watch paths still resolve.
function stateFreeView() {
  const root = mkdtempSync(join(tmpdir(), 'loop-manifest-view-'));
  for (const n of readdirSync(REPO)) {
    if (['.loop-engineering', '.git', 'node_modules'].includes(n)) continue;
    try { symlinkSync(join(REPO, n), join(root, n)); } catch { /* a name that cannot be linked is not needed */ }
  }
  return root;
}

test('[LOOP-001.AC01] the frozen manifest built from the section-8 fixture has no missing or circular dependencies and keeps weights', () => {
  const view = stateFreeView();
  let manifest;
  try { ({ manifest } = createManifest({ repoRoot: view, prdPath: PRD_REL, profile: realProfile(), profileSha: 'a'.repeat(64) })); } finally { rmSync(view, { recursive: true, force: true }); }
  const ids = new Set(manifest.requirements.map((r) => r.id));
  for (const r of manifest.requirements) for (const d of r.dependencies) assert.ok(ids.has(d), `${r.id} -> ${d} exists`);
  assert.equal(manifest.totals.weight, 220);
  assert.equal(manifest.requirements.find((r) => r.id === 'HS-005').weight, 5);
  assert.deepEqual(manifest.requirements.find((r) => r.id === 'HS-005').dependencies, ['HS-002', 'HS-003', 'HS-004']);
  assert.equal(manifest.requirements.find((r) => r.id === 'HS-005').criteria.length, 4);
  assert.equal(manifest.acceptanceHash, computeAcceptanceHash(manifest.requirements));
});

test('[LOOP-001.AC01] the importer fails closed on duplicates, malformed metadata, lost criteria and cycles', () => {
  const good = [{ id: 'HS-001', weight: 2, criteria: ['one', 'two'] }, { id: 'HS-002', weight: 3, deps: ['HS-001'], criteria: ['three'] }];
  assert.doesNotThrow(() => parsePrd(prdText(good)));
  // duplicate requirement ID
  assert.throws(() => parsePrd(prdText([...good, { id: 'HS-001', weight: 1, criteria: ['dup'] }])), /duplicate requirement ID HS-001/);
  // malformed metadata line
  assert.throws(() => parsePrd(prdText(good).replace('Weight: 2 |', 'Weighty: 2 |')), /missing or malformed Weight/);
  // lost criterion: a bullet removed while the PRD still declares the old totals
  const lost = prdText(good).replace('- **HS-001.AC02:** two\n', '');
  assert.throws(() => parsePrd(lost), /declares 3 acceptance criteria but 2 were parsed/);
  // criterion numbering gap
  assert.throws(() => parsePrd(prdText(good).replace('HS-001.AC02', 'HS-001.AC03')), /expected HS-001\.AC02/);
  // dependency on an unknown ID
  assert.throws(() => parsePrd(prdText([{ id: 'HS-001', weight: 1, deps: ['HS-099'], criteria: ['x'] }])), /unknown ID HS-099/);
  // cycle
  assert.throws(() => parsePrd(prdText([{ id: 'HS-001', weight: 1, deps: ['HS-002'], criteria: ['x'] }, { id: 'HS-002', weight: 1, deps: ['HS-001'], criteria: ['y'] }])), /dependency cycle/);
  // unreadable section
  assert.throws(() => parsePrd('# nothing here'), ImportError);
});

test('[LOOP-001.AC02] an unmapped suite, an unapproved executable and an empty test list fail closed', () => {
  const reqs = [{ id: 'HS-001', weight: 1, criteria: ['x'] }];
  const prof = (mut) => { const r = new MiniRepo(reqs); const p = mut(JSON.parse(JSON.stringify(r.profile))); return { r, p }; };
  // suite referenced by the PRD has no command mapping => unknown mandatory command
  const a = prof((p) => { delete p.suites['suite-HS-001']; p.suites.other = { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/x.test.js'], timeoutSeconds: 5 }; return p; });
  assert.throws(() => createManifest({ repoRoot: a.r.root, prdPath: 'PRD.md', profile: a.p, profileSha: 'b'.repeat(64) }), /no command mapping/);
  // executable outside the approved list
  const b = prof((p) => { p.suites['suite-HS-001'].executable = 'bash'; return p; });
  assert.throws(() => createManifest({ repoRoot: b.r.root, prdPath: 'PRD.md', profile: b.p, profileSha: 'b'.repeat(64) }), (e) => e instanceof ProfileError && /not approved/.test(e.message));
  // empty test selection
  const c = prof((p) => { p.suites['suite-HS-001'].files = []; return p; });
  assert.throws(() => createManifest({ repoRoot: c.r.root, prdPath: 'PRD.md', profile: c.p, profileSha: 'b'.repeat(64) }), /at least one test file/);
  // cwd escaping the repository
  const d = prof((p) => { p.suites['suite-HS-001'].cwd = '../elsewhere'; return p; });
  assert.throws(() => createManifest({ repoRoot: d.r.root, prdPath: 'PRD.md', profile: d.p, profileSha: 'b'.repeat(64) }), /inside the repository/);
});

test('[LOOP-001.AC02] a changed acceptance hash or a silently removed requirement is detected on load', () => {
  const reqs = [{ id: 'HS-001', weight: 2, criteria: ['one', 'two'] }, { id: 'HS-002', weight: 3, criteria: ['three'] }];
  const r = new MiniRepo(reqs);
  const { manifest } = createManifest({ repoRoot: r.root, prdPath: 'PRD.md', profile: r.profile, profileSha: 'c'.repeat(64) });
  const file = writeManifest(r.root, manifest);
  assert.equal(loadManifest(r.root).ok, true);
  // edit criterion text without a new version
  const edited = JSON.parse(readFileSync(file, 'utf8'));
  edited.requirements[0].criteria[0].text = 'something easier';
  writeFileSync(file, JSON.stringify(edited));
  let res = loadManifest(r.root);
  assert.equal(res.ok, false); assert.match(res.error, /acceptance hash mismatch/);
  // lower a weight
  const w = JSON.parse(JSON.stringify(manifest)); w.requirements[1].weight = 1; writeFileSync(file, JSON.stringify(w));
  assert.match(loadManifest(r.root).error, /acceptance hash mismatch/);
  // silently remove a requirement AND fix up the hash and totals: still caught by the totals/PRD cross-checks elsewhere
  const rm = JSON.parse(JSON.stringify(manifest)); rm.requirements.pop();
  rm.acceptanceHash = computeAcceptanceHash(rm.requirements);
  writeFileSync(file, JSON.stringify(rm));
  assert.match(loadManifest(r.root).error, /totals disagree/);
  // creating a NEW manifest version that drops a requirement is refused outright
  writeFileSync(file, JSON.stringify(manifest));
  const shrunk = [{ id: 'HS-001', weight: 2, criteria: ['one', 'two'] }];
  writeFileSync(join(r.root, 'PRD.md'), prdText(shrunk));
  assert.throws(() => createManifest({ repoRoot: r.root, prdPath: 'PRD.md', profile: r.profile, profileSha: 'c'.repeat(64) }), /shrink the frozen scope/);
});

test('[LOOP-001.AC02] a newly added requirement makes a visible new manifest version and a larger denominator', () => {
  const reqs = [{ id: 'HS-001', weight: 2, criteria: ['one'] }];
  const r = new MiniRepo(reqs);
  const v1 = createManifest({ repoRoot: r.root, prdPath: 'PRD.md', profile: r.profile, profileSha: 'd'.repeat(64) });
  writeManifest(r.root, v1.manifest);
  const p2 = JSON.parse(JSON.stringify(r.profile));
  p2.suites['added-suite'] = { kind: 'node-test', cwd: '.', executable: 'node', files: ['t/added.test.js'], timeoutSeconds: 5 };
  p2.extraRequirements = [{ id: 'CORE-900', title: 'Newly discovered capability', weight: 3, dependencies: ['HS-001'], suite: 'added-suite', criteria: [{ id: 'CORE-900.AC01', text: 'discovered scope is tracked' }] }];
  const v2 = createManifest({ repoRoot: r.root, prdPath: 'PRD.md', profile: p2, profileSha: 'e'.repeat(64) });
  assert.equal(v2.manifest.manifestVersion, 2);
  assert.equal(v2.manifest.supersedes, 1);
  assert.deepEqual(v2.diff.added, ['CORE-900']);
  assert.equal(v2.diff.denominator.before.weight, 2);
  assert.equal(v2.diff.denominator.after.weight, 5);
  assert.equal(v2.manifest.requirements.find((x) => x.id === 'CORE-900').addedAfterBaseline, true);
  writeManifest(r.root, v2.manifest);
  assert.equal(loadManifest(r.root).version, 2);
  assert.equal(loadManifest(r.root, 1).version, 1, 'the old version stays on disk');
});

test('[LOOP-001.AC03] the shipped profile records finite limits, scoped permissions and platform support', () => {
  const p = realProfile();
  assert.doesNotThrow(() => validateProfile(p, REPO));
  for (const k of ['workerIdleSeconds', 'noProgressSeconds', 'claudeAttemptSeconds', 'claudeMaxTurns', 'attemptsPerRequirement', 'runWallSeconds', 'runMaxAttempts', 'claudeBudgetUsd']) assert.ok(Number.isFinite(p.limits[k]) && p.limits[k] > 0, k);
  assert.equal(p.limits.workerIdleSeconds, 180); assert.equal(p.limits.noProgressSeconds, 600); assert.equal(p.limits.claudeMaxTurns, 80);
  assert.equal(p.limits.runWallSeconds, 43200); assert.equal(p.limits.runMaxAttempts, 150); assert.equal(p.limits.claudeBudgetUsd, 50);
  assert.equal(p.worker.concurrency, 1);
  assert.notEqual(p.worker.permissionMode, 'bypassPermissions');
  assert.ok(p.worker.disallowedTools.includes('Bash(git push:*)'));
  assert.ok(!p.worker.allowedTools.includes('Bash'));
  assert.deepEqual(p.platforms.supported, ['darwin', 'linux']);
  assert.ok(p.platforms.unsupported.includes('win32'));
  // unbounded or non-finite budgets are rejected
  for (const [k, v] of [['runWallSeconds', Infinity], ['claudeBudgetUsd', 0], ['runMaxAttempts', -1], ['claudeAttemptSeconds', null]]) {
    const q = JSON.parse(JSON.stringify(p)); q.limits[k] = v;
    assert.throws(() => validateProfile(q, REPO), (e) => e instanceof ProfileError && e.message.includes(k), `${k}=${v}`);
  }
  const bypass = JSON.parse(JSON.stringify(p)); bypass.worker.permissionMode = 'bypassPermissions';
  assert.throws(() => validateProfile(bypass, REPO), /not an approved non-bypass mode/);
  const open = JSON.parse(JSON.stringify(p)); open.worker.allowedTools.push('Bash');
  assert.throws(() => validateProfile(open, REPO), /unscoped/);
  const remote = JSON.parse(JSON.stringify(p)); remote.serve.host = '0.0.0.0';
  assert.throws(() => validateProfile(remote, REPO), /loopback/);
});

test('[LOOP-001.AC03] init records a pre-existing baseline failure without treating it as a regression and does not overwrite user files', async () => {
  const reqs = [{ id: 'HS-001', weight: 1, criteria: ['x'] }];
  const r = new MiniRepo(reqs, { profile: { baselineGates: [{ id: 'already-red', cwd: '.', executable: 'node', args: ['-e', 'process.exit(3)'], timeoutSeconds: 20 }, { id: 'green', cwd: '.', executable: 'node', args: ['-e', ''], timeoutSeconds: 20 }] } });
  try {
    writeFileSync(r.path('user-notes.txt'), 'precious\n');
    writeFileSync(r.path('t', 'user-edit.js'), '// user wip\n');
    const before = createHash('sha256').update(readFileSync(r.path('user-notes.txt'))).digest('hex');
    const res = await r.cli(['init', '--prd', 'PRD.md', '--profile', 'profile.json']);
    assert.equal(res.code, 0, res.stderr);
    const m = JSON.parse(readFileSync(r.path('.loop-engineering/manifest/requirements.v1.json'), 'utf8'));
    const red = m.baselineGates.find((g) => g.id === 'already-red');
    assert.equal(red.exitCode, 3); assert.equal(red.ok, false);
    assert.match(red.note, /pre-existing, not a regression/);
    assert.equal(m.baselineGates.find((g) => g.id === 'green').ok, true);
    assert.ok(m.checkout.dirtyFiles.some((f) => f.includes('user-notes.txt')), 'pre-existing dirty files are recorded');
    assert.equal(createHash('sha256').update(readFileSync(r.path('user-notes.txt'))).digest('hex'), before);
    assert.equal(readFileSync(r.path('t', 'user-edit.js'), 'utf8'), '// user wip\n');
    // preflight must not mutate user files either
    const snap = () => readdirSync(r.root).filter((f) => !f.startsWith('.')).sort().join(',');
    const s1 = snap();
    await r.cli(['preflight']);
    assert.equal(snap(), s1);
    // re-running init with nothing changed does not create a new manifest version
    const again = await r.cli(['init', '--prd', 'PRD.md', '--profile', 'profile.json', '--skip-baseline-gates']);
    assert.match(again.stdout, /already matches/);
    assert.ok(!existsSync(r.path('.loop-engineering/manifest/requirements.v2.json')));
  } finally { await r.cleanup(); }
});

test('[LOOP-001.AC03] unknown or duplicated CLI options are errors, never ignored', async () => {
  const r = new MiniRepo([{ id: 'HS-001', weight: 1, criteria: ['x'] }]);
  try {
    for (const args of [['init', '--prd', 'PRD.md', '--profile', 'profile.json', '--bogus'], ['init', '--prd', 'PRD.md'], ['status', '--nope'], ['start'], ['start', '--background', '--foreground'], ['start', '--background', '--serve', '0.0.0.0:80'], ['verify'], ['verify', '--all'], ['stop'], ['frobnicate']]) {
      const res = await r.cli(args);
      assert.notEqual(res.code, 0, `${args.join(' ')} must fail`);
    }
  } finally { await r.cleanup(); }
});
