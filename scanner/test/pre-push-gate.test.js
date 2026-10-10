// Pre-push gate — unit tests for the pure decision functions.
//
// See scripts/pre-push-gate.mjs for the full design rationale. The shape
// mirrors test/release-check.test.js on purpose: the I/O + child-process path
// is proven by hand (clean tree passes, deliberately broken tree fails, both
// directions with exit codes captured) and recorded in the change report;
// these tests pin the decision logic on constructed inputs so a refactor
// cannot quietly loosen the gate.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  CHECKS,
  orderedCheckIds,
  parsePushRefs,
  decidePushScope,
  evaluateCheckOutcome,
  evaluateHookActivation,
  summarize,
  HOOKS_PATH,
  envWithoutGitContext,
  evaluateWorktreeMatchesPush,
  evaluatePushBlastRadius,
} from '../../scripts/pre-push-gate.mjs';

const ZERO = '0'.repeat(40);
const A = 'a'.repeat(40);
const B = 'b'.repeat(40);

// ------------------------------------------------------------ ref parsing
test('pre-push-gate — parses a single well-formed ref line', () => {
  const { refs, malformed } = parsePushRefs(
    `refs/heads/main ${A} refs/heads/main ${B}\n`);
  assert.equal(malformed.length, 0);
  assert.deepEqual(refs, [{
    localRef: 'refs/heads/main',
    localSha: A,
    remoteRef: 'refs/heads/main',
    remoteSha: B,
  }]);
});

test('pre-push-gate — parses several ref lines and ignores blank lines', () => {
  const { refs } = parsePushRefs(
    `refs/heads/main ${A} refs/heads/main ${B}\n\nrefs/heads/x ${B} refs/heads/x ${ZERO}\n`);
  assert.equal(refs.length, 2);
  assert.equal(refs[1].localRef, 'refs/heads/x');
});

test('pre-push-gate — a malformed line is reported, never silently dropped', () => {
  const { refs, malformed } = parsePushRefs(`refs/heads/main ${A}\n`);
  assert.equal(refs.length, 0);
  assert.equal(malformed.length, 1);
  assert.match(malformed[0], /refs\/heads\/main/);
});

// ------------------------------------------------------------ push scope
test('pre-push-gate — a normal update of an existing branch is gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: B }]);
  assert.equal(d.shouldRun, true);
  assert.equal(d.gated.length, 1);
});

test('pre-push-gate — a brand-new branch (zero remote sha) is gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/feat', localSha: A, remoteRef: 'refs/heads/feat', remoteSha: ZERO }]);
  assert.equal(d.shouldRun, true);
  assert.equal(d.gated.length, 1);
});

test('pre-push-gate — a delete (zero local sha) is not gated', () => {
  const d = decidePushScope([{ localRef: '(delete)', localSha: ZERO, remoteRef: 'refs/heads/old', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
  assert.equal(d.gated.length, 0);
  assert.match(d.reason, /delet/i);
});

test('pre-push-gate — a ref with no new commits (local == remote) is not gated', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
  assert.equal(d.gated.length, 0);
  assert.match(d.reason, /no new commits/i);
});

test('pre-push-gate — sha comparison is case-insensitive', () => {
  const d = decidePushScope([{ localRef: 'refs/heads/main', localSha: A.toUpperCase(), remoteRef: 'refs/heads/main', remoteSha: A }]);
  assert.equal(d.shouldRun, false);
});

test('pre-push-gate — one gatable ref among skippable ones still gates', () => {
  const d = decidePushScope([
    { localRef: '(delete)', localSha: ZERO, remoteRef: 'refs/heads/old', remoteSha: A },
    { localRef: 'refs/heads/main', localSha: A, remoteRef: 'refs/heads/main', remoteSha: A },
    { localRef: 'refs/heads/feat', localSha: B, remoteRef: 'refs/heads/feat', remoteSha: ZERO },
  ]);
  assert.equal(d.shouldRun, true);
  assert.deepEqual(d.gated.map(r => r.localRef), ['refs/heads/feat']);
});

test('pre-push-gate — no refs at all means nothing to push, so nothing to gate', () => {
  const d = decidePushScope([]);
  assert.equal(d.shouldRun, false);
  assert.match(d.reason, /nothing to push/i);
});

// ------------------------------------------------------------ ordering
test('pre-push-gate — checks run cheapest-first: the guards and bundle integrity precede the suites', () => {
  // The two leading guards answer "is the thing I am about to spend two minutes
  // measuring actually the thing being pushed?", so they come before everything.
  // `ci-parity` sits between package-contents and test-suite deliberately: it
  // runs only the env-sensitive subset (~45 s) against the full suite's ~4 min,
  // so under cheapest-first it precedes the suite. It exists because on
  // 2026-08-19 eight assertions passed this gate and then failed in hosted CI —
  // no local step set CI=1, so no local step could see it.
  const ids = orderedCheckIds();
  assert.deepEqual(ids, [
    'worktree-matches-push', 'push-blast-radius',
    'bundle-integrity', 'bundle-matches-source', 'package-contents', 'ci-parity', 'test-suite', 'corpus-gate', 'self-scan-gate',
    'mutation-gate', 'protection-verdict-gate', 'provenance-accuracy-gate', 'layer-recall-gate', 'language-support-gate',
    'verification-conformance-static', 'release-closure-static',
  ]);
});

// Task 8 (Finding Provenance second-audit remediation). An independent PRD
// audit found bench:provenance-accuracy:check reachable from no gate at all,
// so its 12/13 known-origin-accuracy number could silently rot forever.
test('pre-push-gate — provenance-accuracy gate is present, cheap enough to sit before layer-recall', () => {
  const provenance = CHECKS.find(c => c.id === 'provenance-accuracy-gate');
  assert.ok(provenance, 'provenance-accuracy-gate must be a registered pre-push check');
  assert.equal(provenance.npmScript, 'bench:provenance-accuracy:check');
  // Measured this session: ~9s, well under layer-recall's ~11.5s.
  const ids = orderedCheckIds();
  assert.ok(ids.indexOf('mutation-gate') < ids.indexOf('provenance-accuracy-gate'),
    'mutation-gate (~0.85s) must run before provenance-accuracy-gate (~9s)');
  assert.ok(ids.indexOf('provenance-accuracy-gate') < ids.indexOf('layer-recall-gate'),
    'provenance-accuracy-gate (~9s) must run before layer-recall-gate (~11.5s)');
});

// M2 (Stage-0 audit, 2026). bench:mutation:check and bench:layer-recall:check
// were both built with both-direction verification recorded, but neither was
// reachable from pre-push, release-check, or any CI workflow — a repo-wide
// grep found the npm script names only in package.json and documentation.
// Both gates protected nothing that would actually stop a regressed push.
test('pre-push-gate — mutation and layer-recall gates are present, cheapest of the two first', () => {
  const mutation = CHECKS.find(c => c.id === 'mutation-gate');
  const layerRecall = CHECKS.find(c => c.id === 'layer-recall-gate');
  assert.ok(mutation, 'mutation-gate must be a registered pre-push check');
  assert.equal(mutation.npmScript, 'bench:mutation:check');
  assert.ok(layerRecall, 'layer-recall-gate must be a registered pre-push check');
  assert.equal(layerRecall.npmScript, 'bench:layer-recall:check');
  // Measured this session: mutation ~0.85s, layer-recall ~11.5s (forces deep
  // mode on all 210 corpus entries) — mutation goes first.
  const ids = orderedCheckIds();
  assert.ok(ids.indexOf('mutation-gate') < ids.indexOf('layer-recall-gate'),
    'the cheaper gate (mutation) must run before the pricier one (layer-recall)');
});

test('pre-push-gate — every check declares a title and a remedy', () => {
  for (const c of CHECKS) {
    assert.ok(c.title, `${c.id} has no title`);
    assert.ok(c.remedy, `${c.id} has no remedy`);
  }
});

test('pre-push-gate — the network-dependent publish checks are deliberately absent', () => {
  const ids = orderedCheckIds();
  for (const absent of ['dependency-currency', 'remote-ci-green', 'head-pushed']) {
    assert.ok(!ids.includes(absent), `${absent} must not run on push`);
  }
});

// ------------------------------------------------------------ outcomes
test('pre-push-gate — exit code 0 is the only pass', () => {
  assert.equal(evaluateCheckOutcome({ label: 'npm test', exitCode: 0 }).ok, true);
});

test('pre-push-gate — a non-zero exit fails and names the command', () => {
  const r = evaluateCheckOutcome({ label: 'npm test', exitCode: 1 });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /npm test/);
  assert.match(r.errors[0], /exited 1/);
});

test('pre-push-gate — a check that could not run is a FAILURE, never a skip', () => {
  const r = evaluateCheckOutcome({ label: 'npm run bench:self-scan:check', exitCode: null });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /could not be run/i);
  assert.match(r.errors[0], /not a passing gate/i);
});

test('pre-push-gate — a missing npm script surfaces as unrunnable-is-failure too', () => {
  const r = evaluateCheckOutcome({ label: 'npm run nope', exitCode: undefined });
  assert.equal(r.ok, false);
});

// ------------------------------------------------------------ activation
test('pre-push-gate — correct hooksPath is active, no warning', () => {
  const r = evaluateHookActivation({ configuredHooksPath: HOOKS_PATH });
  assert.equal(r.active, true);
  assert.equal(r.warnings.length, 0);
});

test('pre-push-gate — unset hooksPath warns loudly with the activation command', () => {
  const r = evaluateHookActivation({ configuredHooksPath: null });
  assert.equal(r.active, false);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /core\.hooksPath/);
  assert.match(r.warnings[0], new RegExp(HOOKS_PATH));
});

test('pre-push-gate — a hooksPath pointing elsewhere also warns', () => {
  const r = evaluateHookActivation({ configuredHooksPath: '.git/hooks' });
  assert.equal(r.active, false);
  assert.match(r.warnings[0], /\.git\/hooks/);
});

test('pre-push-gate — trailing whitespace on the configured path does not defeat detection', () => {
  const r = evaluateHookActivation({ configuredHooksPath: `${HOOKS_PATH}\n` });
  assert.equal(r.active, true);
});

// ------------------------------------------------------------ summary
test('pre-push-gate — all-pass summary is ok and states what was verified', () => {
  const s = summarize([
    { id: 'bundle-integrity', title: 'Bundle', result: { ok: true, errors: [] } },
    { id: 'test-suite', title: 'Tests', result: { ok: true, errors: [] } },
  ]);
  assert.equal(s.ok, true);
  assert.equal(s.failed.length, 0);
  assert.ok(s.lines.every(l => /^PASS/.test(l)));
});

test('pre-push-gate — a failure is reported with its remedy and the bypass escape hatch', () => {
  const s = summarize([
    { id: 'bundle-integrity', title: 'Bundle', result: { ok: true, errors: [] } },
    { id: 'test-suite', title: 'Tests', remedy: 'Run `npm test` and fix the failures.', result: { ok: false, errors: ['`npm test` exited 1.'] } },
  ]);
  assert.equal(s.ok, false);
  assert.deepEqual(s.failed.map(f => f.id), ['test-suite']);
  const text = s.lines.join('\n');
  assert.match(text, /FAIL {2}Tests/);
  assert.match(text, /Run `npm test` and fix the failures\./);
  assert.match(text, /--no-verify/);
});

// --- git context must not leak from the hook into the suites ------------------
//
// Git exports GIT_DIR into every hook. The gate spawns `npm test`, which
// inherited it, so every test that builds a temp repository and shells out to
// `git` operated on THIS repository instead of its fixture.
//
// The consequence was not a false failure. Two blocked pushes from a linked
// worktree ran the suite under the hook and the history-mining tests committed
// their fixtures into the real branch — ~30 commits that between them deleted
// 421 files and 90,282 lines from scanner/src, which then got pushed. From an
// ordinary clone GIT_DIR is the relative `.git` and stops resolving once a test
// chdirs away, which is why this went unseen for so long.

test('envWithoutGitContext strips every variable that could redirect a child git', () => {
  const out = envWithoutGitContext({
    GIT_DIR: '/repo/.git',
    GIT_WORK_TREE: '/repo',
    GIT_INDEX_FILE: '/repo/.git/index',
    GIT_OBJECT_DIRECTORY: '/repo/.git/objects',
    GIT_ALTERNATE_OBJECT_DIRECTORIES: '/other/objects',
    GIT_PREFIX: 'scanner/',
    GIT_COMMON_DIR: '/repo/.git',
  });
  assert.deepEqual(Object.keys(out), [], 'no git-context variable may survive');
});

test('envWithoutGitContext preserves everything a child actually needs', () => {
  // Over-scrubbing would break the spawn itself, failing the gate closed for a
  // different and even more confusing reason.
  const out = envWithoutGitContext({
    PATH: '/usr/bin', HOME: '/home/x', NODE_ENV: 'test',
    GIT_DIR: '/repo/.git', GIT_AUTHOR_NAME: 'keep me',
  });
  assert.equal(out.PATH, '/usr/bin');
  assert.equal(out.HOME, '/home/x');
  assert.equal(out.NODE_ENV, 'test');
  assert.equal(out.GIT_DIR, undefined);
  // GIT_AUTHOR_* cannot redirect which repository a command targets, so it is
  // deliberately kept: the list is a denylist of redirectors, not a blanket
  // "delete anything starting with GIT_".
  assert.equal(out.GIT_AUTHOR_NAME, 'keep me');
});

test('envWithoutGitContext does not mutate the source environment', () => {
  const source = { GIT_DIR: '/repo/.git', PATH: '/usr/bin' };
  envWithoutGitContext(source);
  assert.equal(source.GIT_DIR, '/repo/.git', 'process.env must not be modified in place');
});

// --- the gate must verify what it is PUSHING, not just what is on disk -------
//
// A run of this gate once passed all four checks in 184s on a branch whose
// committed tree was missing 421 files and 90,282 lines of scanner/src. The
// files still existed on disk as untracked, so every suite imported them and
// went green while the refs being uploaded did not contain them. These two
// checks exist so that cannot happen silently again; either one catches it.

test('worktree check fails when tracked files differ from HEAD', () => {
  const r = evaluateWorktreeMatchesPush(' M scanner/src/engine.js\nD  scanner/src/gone.js\n');
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /2 tracked file\(s\) differ/);
  assert.match(r.errors[0], /not in the commit being pushed/);
});

test('worktree check passes on a clean tree', () => {
  const r = evaluateWorktreeMatchesPush('');
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 0);
});

test('worktree check tolerates a few untracked files but says so', () => {
  const r = evaluateWorktreeMatchesPush('?? notes.md\n?? scratch.txt\n');
  assert.equal(r.ok, true);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /2 untracked/);
});

test('worktree check fails on a flood of untracked files — the incident signature', () => {
  // The real incident looked exactly like this: the history was rewritten
  // underneath the working tree, so the whole project read as untracked.
  const porcelain = Array.from({ length: 40 }, (_, i) => `?? src/file${i}.js`).join('\n');
  const r = evaluateWorktreeMatchesPush(porcelain);
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /40 untracked files/);
  assert.match(r.errors[0], /reflog/);
});

test('blast-radius check fails on a mass deletion, quoting both counts', () => {
  const r = evaluatePushBlastRadius({ filesDeleted: 421, filesInBase: 900, base: 'abc123def456' });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /421 tracked file/);
});

test('blast-radius check fails on a large FRACTION even under the absolute cap', () => {
  // 30 of 100 is only 30 files — under the 50-file cap — but a third of the
  // repository. The fraction rule is what catches a small project.
  const r = evaluatePushBlastRadius({ filesDeleted: 30, filesInBase: 100 });
  assert.equal(r.ok, false);
  assert.match(r.errors[0], /30\.0%/);
});

test('blast-radius check passes an ordinary deletion', () => {
  const r = evaluatePushBlastRadius({ filesDeleted: 3, filesInBase: 900 });
  assert.equal(r.ok, true);
});

test('blast-radius check warns rather than fails when there is no base to measure', () => {
  // A genuinely first push has no previous state. That is a real condition,
  // not a broken check, so it must not block — but it must be visible.
  const r = evaluatePushBlastRadius({ measured: false });
  assert.equal(r.ok, true);
  assert.match(r.warnings[0], /NOT measured/);
});

test('the two new guards run before the expensive suites', () => {
  const ids = orderedCheckIds();
  assert.equal(ids[0], 'worktree-matches-push');
  assert.equal(ids[1], 'push-blast-radius');
  assert.ok(ids.indexOf('test-suite') > ids.indexOf('push-blast-radius'),
    'a guard that runs after the suites cannot save the minutes it exists to save');
});

// =========================================================================
// Per-check verdict cache. Every test below drives the REAL buildScopedCache /
// executeChecks / computeScopedKey with injected facts and fake checks; the
// real gate is never run. Each rule is pinned in BOTH directions: the thing
// that must hit does, and the thing that must not, does not.
// =========================================================================
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { buildScopedCache, PURE_BENCHES } from '../../scripts/pre-push-gate.mjs';
import { executeChecks } from '../../scripts/gate-run-checks.mjs';
import {
  computeScopedKey, loadCache, scopedRecordId, cachingDisabled, digestScope, CACHE_FILE,
} from '../../scripts/gate-verdict-cache.mjs';
import { scopeFor, pathInScope } from '../../scripts/gate-check-scopes.mjs';
import { analyseTrace } from '../../scripts/gate-trace-reads.mjs';

const KEY = 'test-hmac-key';
const signer = (body) => crypto.createHmac('sha256', KEY).update(body).digest('hex');
const CLOCK = new Date('2026-10-07T12:00:00.000Z');
const NARROW = { all: false, usesHistory: false, writesRepo: false, include: ['scanner/', 'bench/x/'] };

function mkRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ppg-cache-'));
  const put = (rel, text) => { fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true }); fs.writeFileSync(path.join(dir, rel), text); };
  put('scanner/package.json', '{"name":"x"}');
  put('scanner/src/a.js', 'export const a = 1;\n');
  put('scanner/dist/agentic-security.mjs', 'bundle-v1');
  put('bench/x/run.js', 'run();\n');
  put('docs/notes.txt', 'unrelated\n');
  put('README.md', 'readme\n');
  return { dir, put };
}
function walkFiles(dir, base = dir, acc = []) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.name === '.agentic-security') continue;
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) walkFiles(abs, base, acc); else acc.push(path.relative(base, abs));
  }
  return acc.sort();
}
const FAKE = { id: 'fake-bench', title: 'Fake bench', npmScript: 'bench:fake' };
const PASS = { ok: true, errors: [], warnings: [] };
function cacheFor(dir, argv = [], extra = {}) {
  const inputs = { files: () => walkFiles(dir), headSha: 'h1', bundleSha: 'bundle1', python: 'py1', command: 'node fake.js', scope: () => NARROW, ...(extra.inputs || {}) };
  return buildScopedCache(argv, { repo: dir, env: extra.env || {}, signer, inputs, now: () => CLOCK });
}
/** Run the fake check through the real executor. `outcome` decides pass/fail; `calls` records real runs. */
async function gate(dir, { argv = [], extra = {}, outcome = PASS, hook = null } = {}) {
  const calls = [];
  const logs = [];
  const entries = await executeChecks({
    checks: [FAKE], scoped: cacheFor(dir, argv, extra), legacy: null, log: (l) => logs.push(l), now: () => CLOCK.getTime() + 60000,
    runCheck: async (c) => { calls.push(c.id); if (hook) hook(); return outcome; },
  });
  return { calls, logs, entries };
}

test('cache: a second run with every input unchanged is a HIT, announced loudly, and does not run the check', async () => {
  const { dir } = mkRepo();
  const first = await gate(dir);
  assert.deepEqual(first.calls, ['fake-bench']);
  assert.equal(first.entries[0].cached, undefined);
  const second = await gate(dir);
  assert.deepEqual(second.calls, [], 'the check must not run on a hit');
  assert.match(second.entries[0].cached, /^cached \(inputs unchanged since 2026-10-07T12:00:00\.000Z\)$/);
  assert.ok(second.logs.some((l) => /cached \(inputs unchanged since/.test(l)), 'the hit must be printed, not silent');
  assert.equal(second.entries[0].result.ok, true);
});

test('cache: touching a file without changing its bytes still hits (content, not mtime)', async () => {
  const { dir } = mkRepo();
  await gate(dir);
  const f = path.join(dir, 'scanner/src/a.js');
  fs.utimesSync(f, new Date(2030, 0, 1), new Date(2030, 0, 1));
  assert.deepEqual((await gate(dir)).calls, []);
});

test('cache: a change to an in-scope file invalidates, including a same-length edit', async () => {
  for (const [rel, text] of [['scanner/src/a.js', 'export const a = 2;\n'], ['bench/x/run.js', 'runZ();\n']]) {
    const { dir } = mkRepo();
    await gate(dir);
    fs.writeFileSync(path.join(dir, rel), text);
    assert.deepEqual((await gate(dir)).calls, ['fake-bench'], `${rel} changed, so the check must re-run`);
  }
});

test('cache: adding or deleting an in-scope file invalidates', async () => {
  const a = mkRepo();
  await gate(a.dir);
  a.put('scanner/src/new.js', 'x\n');
  assert.deepEqual((await gate(a.dir)).calls, ['fake-bench'], 'an added file is an input');
  const b = mkRepo();
  await gate(b.dir);
  fs.rmSync(path.join(b.dir, 'bench/x/run.js'));
  assert.deepEqual((await gate(b.dir)).calls, ['fake-bench'], 'a removed file is an input');
});

test('cache: a change OUTSIDE the declared scope does not invalidate (that is the point of scoping)', async () => {
  const { dir, put } = mkRepo();
  await gate(dir);
  put('docs/notes.txt', 'edited prose\n');
  put('README.md', 'edited\n');
  assert.deepEqual((await gate(dir)).calls, [], 'prose outside every scope must not cost a re-run');
});

test('cache: the bundle, node version, python version, command, environment and (for history readers) HEAD each invalidate', async () => {
  const cases = [
    ['bundle', { inputs: { bundleSha: 'bundle2' } }],
    ['node version', { inputs: { nodeVersion: 'v99.0.0' } }],
    ['python version', { inputs: { python: 'py2' } }],
    ['the check script / arguments', { inputs: { command: 'node fake.js --other' } }],
    ['AGENTIC_SECURITY_* environment', { env: { AGENTIC_SECURITY_DEEP: '1' } }],
    ['ambient CI variable', { env: { CI: 'true' } }],
  ];
  for (const [what, extra] of cases) {
    const { dir } = mkRepo();
    await gate(dir);
    assert.deepEqual((await gate(dir, { extra })).calls, ['fake-bench'], `a changed ${what} must invalidate`);
  }
  // HEAD matters only to a check whose scope says it reads history, and must NOT matter to one that does not.
  const hist = { inputs: { scope: () => ({ ...NARROW, usesHistory: true }) } };
  const h = mkRepo();
  await gate(h.dir, { extra: hist });
  assert.deepEqual((await gate(h.dir, { extra: { inputs: { ...hist.inputs, headSha: 'h2' } } })).calls, ['fake-bench'], 'HEAD changed for a history reader');
  const n = mkRepo();
  await gate(n.dir);
  assert.deepEqual((await gate(n.dir, { extra: { inputs: { headSha: 'h2' } } })).calls, [], 'HEAD changed for a content-only check: same bytes, still a hit');
});

test("cache: the gate's own code, the bundle and the engine are inputs of every cacheable check", () => {
  for (const c of CHECKS.filter((x) => x.npmScript)) {
    const sc = scopeFor(c.id);
    for (const f of ['scripts/pre-push-gate.mjs', 'scripts/gate-verdict-cache.mjs', 'scripts/gate-check-scopes.mjs', 'scripts/gate-run-checks.mjs', 'scanner/package.json', 'scanner/dist/agentic-security.mjs', 'scanner/src/engine.js']) {
      assert.ok(pathInScope(sc, f), `${c.id} must be invalidated by a change to ${f}`);
    }
  }
});

test('cache: a tampered, hand-edited or unsigned cache file is refused and the check runs', async () => {
  const mutate = [
    ['a record edited to look newer', (doc) => { doc.records[scopedRecordId('fake-bench')].at = '2026-10-07T12:30:00.000Z'; }],
    ['a record whose key was swapped', (doc) => { doc.records[scopedRecordId('fake-bench')].key = 'f'.repeat(64); }],
    ['a forged extra record', (doc) => { doc.records[scopedRecordId('other')] = { checkId: 'x', verdict: 'pass' }; }],
    ['the signature stripped', (doc) => { delete doc.signature; }],
  ];
  for (const [what, fn] of mutate) {
    const { dir } = mkRepo();
    await gate(dir);
    const p = path.join(dir, CACHE_FILE);
    const doc = JSON.parse(fs.readFileSync(p, 'utf8'));
    fn(doc);
    fs.writeFileSync(p, JSON.stringify(doc));
    const r = await gate(dir);
    assert.deepEqual(r.calls, ['fake-bench'], `${what}: a cache that does not verify must not be trusted`);
  }
  const { dir } = mkRepo();
  await gate(dir);
  fs.writeFileSync(path.join(dir, CACHE_FILE), '{not json');
  assert.deepEqual((await gate(dir)).calls, ['fake-bench'], 'unparseable cache runs the check');
});

test('cache: a cache signed with a different key is refused', async () => {
  const { dir } = mkRepo();
  await gate(dir);
  const other = (body) => crypto.createHmac('sha256', 'someone-elses-key').update(body).digest('hex');
  const ctx = buildScopedCache([], { repo: dir, env: {}, signer: other, inputs: { files: () => walkFiles(dir), headSha: 'h1', bundleSha: 'bundle1', python: 'py1', command: 'c', scope: () => NARROW } });
  assert.equal(ctx.rejected, 'signature mismatch');
  assert.deepEqual(ctx.records, {});
});

test('cache: a FAILING check is never cached, so a fix is picked up at once', async () => {
  const { dir } = mkRepo();
  const bad = { ok: false, errors: ['exited 1'], warnings: [] };
  assert.deepEqual((await gate(dir, { outcome: bad })).calls, ['fake-bench']);
  assert.deepEqual(loadCache(dir, { signer }).records, {}, 'nothing may be recorded for a failure');
  assert.deepEqual((await gate(dir, { outcome: bad })).calls, ['fake-bench'], 'it runs again');
  assert.deepEqual((await gate(dir)).calls, ['fake-bench'], 'and when it is fixed it runs and passes');
  assert.deepEqual((await gate(dir)).calls, [], 'only then does the pass hit');
});

test('cache: a check that passes but rewrites its own inputs is not cached', async () => {
  const { dir } = mkRepo();
  const r = await gate(dir, { hook: () => fs.writeFileSync(path.join(dir, 'scanner/src/a.js'), `mutated ${Math.random()}\n`) });
  assert.ok(r.logs.some((l) => /NOT cached/.test(l)));
  assert.deepEqual(loadCache(dir, { signer }).records, {});
});

test('cache: --no-cache, AGENTIC_SECURITY_GATE_NO_CACHE and hosted CI always run everything, even over a valid cache', async () => {
  const { dir } = mkRepo();
  await gate(dir);
  assert.deepEqual((await gate(dir)).calls, [], 'sanity: the cache is valid and would hit');
  assert.equal(cacheFor(dir, ['--no-cache']), null);
  assert.equal(cacheFor(dir, [], { env: { AGENTIC_SECURITY_GATE_NO_CACHE: '1' } }), null);
  assert.equal(cacheFor(dir, [], { env: { GITHUB_ACTIONS: 'true' } }), null);
  assert.equal(cachingDisabled([], {}), false);
  const calls = [];
  await executeChecks({ checks: [FAKE], scoped: cacheFor(dir, ['--no-cache']), log: () => {}, runCheck: async (c) => { calls.push(c.id); return PASS; } });
  assert.deepEqual(calls, ['fake-bench'], '--no-cache runs the check');
});

test('cache: a --no-cache run does not write a cache either', async () => {
  const { dir } = mkRepo();
  await executeChecks({ checks: [FAKE], scoped: cacheFor(dir, ['--no-cache']), log: () => {}, runCheck: async () => PASS });
  assert.equal(fs.existsSync(path.join(dir, CACHE_FILE)), false);
});

test('cache: an unreadable in-scope file yields NO key (run the check), never a partial digest', () => {
  if (process.getuid && process.getuid() === 0) return; // root reads anything; the property is untestable there
  const { dir } = mkRepo();
  const f = path.join(dir, 'scanner/src/a.js');
  fs.chmodSync(f, 0o000);
  try {
    const k = computeScopedKey({ check: FAKE, command: 'c', repo: dir, files: walkFiles(dir), headSha: 'h', bundleSha: 'b', python: 'p', scope: NARROW });
    assert.equal(k, null);
  } finally { fs.chmodSync(f, 0o644); }
  const again = computeScopedKey({ check: FAKE, command: 'c', repo: dir, files: walkFiles(dir), headSha: 'h', bundleSha: 'b', python: 'p', scope: NARROW });
  assert.ok(again && again.key, 'readable again, the key exists');
});

test('cache: a missing bundle or script text yields no key', () => {
  const { dir } = mkRepo();
  assert.equal(computeScopedKey({ check: FAKE, command: 'c', repo: dir, files: walkFiles(dir), headSha: 'h', bundleSha: null, python: 'p', scope: NARROW }), null);
  assert.equal(computeScopedKey({ check: FAKE, command: null, repo: dir, files: walkFiles(dir), headSha: 'h', bundleSha: 'b', python: 'p', scope: NARROW }), null);
});

test('cache: a symlink retargeted to different bytes invalidates', async () => {
  const { dir } = mkRepo();
  fs.writeFileSync(path.join(dir, 'bench/x/one.txt'), '1');
  fs.writeFileSync(path.join(dir, 'bench/x/two.txt'), '2');
  fs.symlinkSync('one.txt', path.join(dir, 'bench/x/link'));
  await gate(dir);
  fs.rmSync(path.join(dir, 'bench/x/link'));
  fs.symlinkSync('two.txt', path.join(dir, 'bench/x/link'));
  assert.deepEqual((await gate(dir)).calls, ['fake-bench']);
});

test('scopes: digests differ exactly when in-scope content differs', () => {
  const { dir, put } = mkRepo();
  const d0 = digestScope(dir, NARROW, { files: walkFiles(dir) });
  put('docs/notes.txt', 'changed');
  assert.equal(digestScope(dir, NARROW, { files: walkFiles(dir) }).digest, d0.digest);
  put('bench/x/run.js', 'changed');
  assert.notEqual(digestScope(dir, NARROW, { files: walkFiles(dir) }).digest, d0.digest);
});

// ----------------------------------------------------------- parallel groups
test('parallel: members of one group overlap in time; everything else stays serial', async () => {
  const mk = (id, g) => ({ id, title: id, npmScript: `s:${id}`, ...(g ? { parallelGroup: g } : {}) });
  let running = 0; let peak = 0;
  const order = [];
  const runCheck = async (c) => {
    order.push(`start:${c.id}`);
    running++; peak = Math.max(peak, running);
    await new Promise((r) => setTimeout(r, 25));
    running--; order.push(`end:${c.id}`);
    return PASS;
  };
  const entries = await executeChecks({ checks: [mk('a'), mk('b', 'G'), mk('c', 'G'), mk('d', 'G'), mk('e')], log: () => {}, runCheck });
  assert.deepEqual(entries.map((e) => e.id), ['a', 'b', 'c', 'd', 'e'], 'results come back in declared order');
  assert.equal(peak, 3, 'the three group members ran together, nothing else did');
  assert.ok(order.indexOf('end:a') < order.indexOf('start:b'), 'a finishes before the group starts');
  assert.ok(order.indexOf('end:d') < order.indexOf('start:e'), 'the group finishes before e starts');
});

test('parallel: a failure inside a group is reported, every member is reported, and later checks do not run', async () => {
  const mk = (id, g) => ({ id, title: id, npmScript: `s:${id}`, ...(g ? { parallelGroup: g } : {}) });
  const ran = [];
  const entries = await executeChecks({
    checks: [mk('b', 'G'), mk('c', 'G'), mk('z')], log: () => {},
    runCheck: async (c) => { ran.push(c.id); return c.id === 'c' ? { ok: false, errors: ['boom'], warnings: [] } : PASS; },
  });
  assert.deepEqual(ran.sort(), ['b', 'c']);
  assert.deepEqual(entries.map((e) => [e.id, e.result.ok]), [['b', true], ['c', false]]);
});

test('parallel: a check that throws is a failure, not a skip', async () => {
  const entries = await executeChecks({ checks: [{ id: 'q', title: 'q', npmScript: 's' }], log: () => {}, runCheck: async () => { throw new Error('spawn exploded'); } });
  assert.equal(entries[0].result.ok, false);
  assert.match(entries[0].result.errors[0], /spawn exploded/);
});

test('parallel: only checks traced as writing nothing inside the repository are grouped, and no big suite is', () => {
  const grouped = CHECKS.filter((c) => c.parallelGroup);
  assert.ok(grouped.length >= 2);
  for (const c of grouped) {
    assert.equal(c.parallelGroup, PURE_BENCHES);
    assert.equal(scopeFor(c.id).writesRepo, false, `${c.id} is in a parallel group without a recorded writesRepo:false`);
  }
  for (const id of ['test-suite', 'ci-parity', 'corpus-gate', 'self-scan-gate', 'layer-recall-gate']) {
    assert.ok(!CHECKS.find((c) => c.id === id).parallelGroup, `${id} writes scan state and must stay serial`);
  }
  // a group must be contiguous, or the executor would run its members apart
  const idx = grouped.map((c) => CHECKS.indexOf(c));
  assert.equal(idx[idx.length - 1] - idx[0], idx.length - 1, 'group members must be adjacent');
});

test('cache: the in-process guards are never cached', async () => {
  const calls = [];
  const guard = { id: 'worktree-matches-push', title: 'g' }; // no npmScript
  const { dir } = mkRepo();
  const scoped = cacheFor(dir);
  for (let i = 0; i < 2; i++) await executeChecks({ checks: [guard], scoped, log: () => {}, runCheck: async (c) => { calls.push(c.id); return PASS; } });
  assert.deepEqual(calls, ['worktree-matches-push', 'worktree-matches-push']);
  assert.deepEqual(loadCache(dir, { signer }).records, {});
});

// --------------------------------------------------------- trace analysis
test('trace analysis: a read outside the scope, VCS use on this repo, and a write inside it are each reported', () => {
  const repo = '/r';
  const lines = [
    { op: 'readFileSync', path: '/r/scanner/src/x.js', kind: 'fs' },
    { op: 'readFileSync', path: '/r/ide/secret.json', kind: 'fs' },
    { op: 'spawnSync', cmd: 'git', args: ['log'], cwd: '/r/scanner', kind: 'spawn' },
    { op: 'spawnSync', cmd: 'git', args: ['clone', 'x', 'y'], cwd: '/r/scanner', kind: 'spawn' },
    { op: 'writeFileSync', path: '/r/bench/mutation/out.json', kind: 'write' },
    { op: 'writeFileSync', path: '/tmp/elsewhere', kind: 'write' },
  ].map((o) => JSON.stringify(o));
  const a = analyseTrace(lines, scopeFor('mutation-gate'), repo);
  assert.deepEqual(a.outside, ['ide/secret.json']);
  assert.equal(a.repoGit.length, 1, 'clone builds a new repository and is not a read of this one');
  assert.deepEqual(a.writes, ['bench/mutation/out.json']);
  const clean = analyseTrace([JSON.stringify({ op: 'readFileSync', path: '/r/bench/mutation/runner.mjs', kind: 'fs' })], scopeFor('mutation-gate'), repo);
  assert.deepEqual(clean.outside, []);
});

// ------------------------------------------------- hidden scan state, ineligible checks
import { execFileSync } from 'node:child_process';
import { wipeIgnoredState } from '../../scripts/gate-verdict-cache.mjs';

test('cache: checks whose scan state was never traced are ineligible for the per-check cache and fall back to the whole-tree one', async () => {
  for (const id of ['test-suite', 'ci-parity', 'self-scan-gate']) {
    assert.equal(scopeFor(id).scoped, false, `${id} must not get a scoped key`);
  }
  assert.equal(scopeFor('a-check-nobody-traced').scoped, false, 'an unlisted check defaults to no scoped key');
  const { dir } = mkRepo();
  const calls = [];
  const ineligible = { id: 'test-suite', title: 't', npmScript: 'test' };
  const scoped = buildScopedCache([], { repo: dir, env: {}, signer, inputs: { files: () => walkFiles(dir), headSha: 'h', bundleSha: 'b', python: 'p', command: 'c' } });
  for (let i = 0; i < 2; i++) await executeChecks({ checks: [ineligible], scoped, log: () => {}, runCheck: async (c) => { calls.push(c.id); return PASS; } });
  assert.deepEqual(calls, ['test-suite', 'test-suite'], 'ineligible means it always runs under the scoped cache');
  assert.deepEqual(loadCache(dir, { signer }).records, {}, 'and nothing is recorded for it');
});

function mkGitRepo() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ppg-state-'));
  const env = { ...process.env };
  for (const k of ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE']) delete env[k];
  const git = (...a) => execFileSync('git', a, { cwd: dir, env, stdio: 'pipe' });
  git('init', '-q');
  fs.writeFileSync(path.join(dir, '.gitignore'), '.agentic-security/\n');
  fs.mkdirSync(path.join(dir, 'bench/cve-replay/e1/pre/.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'bench/cve-replay/e1/pre/.agentic-security/rules.yml'), 'disable: [x]\n');
  fs.writeFileSync(path.join(dir, 'bench/cve-replay/e1/pre/app.js'), 'x\n');
  fs.mkdirSync(path.join(dir, 'other/.agentic-security'), { recursive: true });
  fs.writeFileSync(path.join(dir, 'other/.agentic-security/keep.json'), '{}');
  return { dir, git };
}

test('cache: gitignored scan state under a cleanState root is removed before keying; sources and other roots are untouched', () => {
  const { dir } = mkGitRepo();
  const n = wipeIgnoredState(dir, ['bench/cve-replay/']);
  assert.equal(n, 1);
  assert.equal(fs.existsSync(path.join(dir, 'bench/cve-replay/e1/pre/.agentic-security')), false, 'stale rules override is gone');
  assert.equal(fs.existsSync(path.join(dir, 'bench/cve-replay/e1/pre/app.js')), true, 'sources survive');
  assert.equal(fs.existsSync(path.join(dir, 'other/.agentic-security/keep.json')), true, 'outside the root, state is not touched');
});

test('cache: a .agentic-security directory that is NOT ignored is never deleted', () => {
  const { dir, git } = mkGitRepo();
  fs.writeFileSync(path.join(dir, '.gitignore'), '');
  const n = wipeIgnoredState(dir, ['bench/cve-replay/']);
  assert.equal(n, 0, 'unignored content is real input and is left for the file digest to cover');
  assert.equal(fs.existsSync(path.join(dir, 'bench/cve-replay/e1/pre/.agentic-security/rules.yml')), true);
  void git;
});

test('cache: a stale rules override planted before a run cannot survive into a cached verdict', async () => {
  // The scenario the wipe exists for: a hand-written rules.yml in a corpus tree changes what the bench measures but is invisible to a
  // file listing. After the wipe it cannot be there at key time, so the same key can never describe two different measured states.
  const { dir } = mkGitRepo();
  const scope = { scoped: true, all: false, usesHistory: false, cleanState: ['bench/cve-replay/'], include: ['bench/cve-replay/'] };
  const listing = () => ['.gitignore', 'bench/cve-replay/e1/pre/app.js'];
  const ctx = buildScopedCache([], { repo: dir, env: {}, signer, inputs: { files: listing, headSha: 'h', bundleSha: 'b', python: 'p', command: 'c', scope: () => scope } });
  const k = ctx.keyFor({ id: 'corpus-gate', npmScript: 'x' });
  assert.ok(k && k.key);
  assert.equal(fs.existsSync(path.join(dir, 'bench/cve-replay/e1/pre/.agentic-security')), false);
});

test('trace analysis: scan state read outside a cleanState root, and writes outside it, fail verification', () => {
  const repo = '/r';
  const scope = { ...scopeFor('corpus-gate') };
  const ok = analyseTrace([
    { op: 'readFileSync', path: '/r/bench/cve-replay/e1/pre/.agentic-security/rules.yml', kind: 'fs' },
    { op: 'writeFileSync', path: '/r/bench/cve-replay/e1/pre/.agentic-security/last-scan.json', kind: 'write' },
  ].map((o) => JSON.stringify(o)), scope, repo);
  assert.deepEqual(ok.stateReads, []);
  assert.deepEqual(ok.writesOutside, []);
  const bad = analyseTrace([
    { op: 'readFileSync', path: '/r/.agentic-security/rules.yml', kind: 'fs' },
    { op: 'writeFileSync', path: '/r/docs/generated.md', kind: 'write' },
  ].map((o) => JSON.stringify(o)), scope, repo);
  assert.deepEqual(bad.stateReads, ['.agentic-security/rules.yml']);
  assert.deepEqual(bad.writesOutside, ['docs/generated.md']);
});

test('cache wiring: with NO injected bundle or python, the real facts are read and a key exists (a misnamed field made every key null once)', () => {
  const { dir } = mkRepo();
  // only the file listing and scope are injected; the bundle hash, python version and revision come from the real repository
  const ctx = buildScopedCache([], { repo: dir, env: {}, signer, inputs: { files: () => walkFiles(dir), command: 'c', scope: () => NARROW } });
  const k = ctx.keyFor(FAKE);
  assert.ok(k && /^[0-9a-f]{64}$/.test(k.key), 'a key must be producible from the real bundle and python');
});
