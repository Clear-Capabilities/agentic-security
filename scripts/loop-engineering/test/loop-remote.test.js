// Hosted-CI executor (lib/remote.mjs). `git` and `gh` are replaced by a fake that plays GitHub's side; what is under test is the
// controller's side of the bargain: what it asks for, and every way it must refuse to call a run verified.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { remotePreflight, runRemote } from '../lib/remote.mjs';
import { evaluateCriteria } from '../lib/verifier.mjs';

const SHA = 'a'.repeat(40);
const sha256 = (b) => createHash('sha256').update(b).digest('hex');
const REQ = { id: 'NIX-011', criteria: [{ id: 'NIX-011.AC01' }, { id: 'NIX-011.AC02' }] };
const WATCH = ['docs/**', 'scanner/**'];
const WATCH_JSON = JSON.stringify(WATCH);
const DIGEST = 'd'.repeat(64);
const CFG = { workflow: 'verify-remote.yml', target: 'nix', legs: ['nix'], timeoutSeconds: 60 };
const PASS_TAP = 'TAP version 13\nok 1 - [NIX-011.AC01] hostile evaluator behavior is contained\nok 2 - [NIX-011.AC02] the sandbox is probed\n1..2\n# tests 2\n# pass 2\n# fail 0\n# skipped 0\n# todo 0\n';

/** A fake GitHub. `art` shapes what the artifact contains; `opts` shapes the rest. */
function fake({ dirty = '', branches = `${SHA}\trefs/heads/main\n`, art = {}, conclusion = 'success', headSha = SHA, nonceVisible = true, tracked = true } = {}) {
  const calls = [];
  let nonce = null;
  const run = (cmd, args, o = {}) => {
    calls.push([cmd, ...args]);
    if (cmd === 'git') {
      if (args[0] === 'status') return dirty;
      if (args[0] === 'rev-parse') return `${SHA}\n`;
      if (args[0] === 'ls-remote') return branches;
      if (args[0] === 'ls-files') { if (!tracked) throw new Error('not tracked'); return '.github/workflows/verify-remote.yml\n'; }
    }
    if (cmd === 'gh') {
      if (args[0] === 'repo') return 'org/repo\n';
      if (args[0] === 'workflow') { nonce = args.find((a) => a.startsWith('nonce=')).slice(6); return ''; }
      if (args[0] === 'run' && args[1] === 'list') return JSON.stringify(nonceVisible ? [{ databaseId: 77, displayTitle: `verify NIX-011 ${nonce}`, headSha: SHA, createdAt: 'x', url: 'u' }] : []);
      if (args[0] === 'run' && args[1] === 'view') return JSON.stringify({ status: 'completed', conclusion, headSha, url: 'https://example/run/77' });
      if (args[0] === 'run' && args[1] === 'download') {
        const dest = args[args.indexOf('-D') + 1];
        const tap = art.tap ?? PASS_TAP;
        const leg = { name: 'nix', system: 'x86_64-linux', tap: 'nix.tap', tapSha256: art.tapSha256 ?? sha256(tap), exitCode: art.exitCode ?? 0, toolVersions: { nix: 'nix 2.24.10' } };
        const meta = { schema: 1, requirement: art.requirement ?? 'NIX-011', sha: art.sha ?? SHA, workflowSha: art.workflowSha ?? SHA, treeDigest: art.digest ?? DIGEST, watchSha256: art.watchSha256 ?? sha256(WATCH_JSON), legs: art.legs ?? [leg] };
        if (!art.noMeta) writeFileSync(join(dest, 'meta.json'), JSON.stringify(meta));
        if (!art.noTap) writeFileSync(join(dest, 'nix.tap'), tap);
        return '';
      }
      if (args[0] === 'api') return JSON.stringify({ artifacts: [{ name: 'verify-NIX-011', digest: 'sha256:abc' }] });
    }
    void o; return '';
  };
  return { run, calls };
}

async function go(f, extra = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'loop-remote-'));
  mkdirSync(join(dir, 'ev'), { recursive: true });
  try {
    let t = 0;
    const r = await runRemote({ repoRoot: dir, evidenceDir: join(dir, 'ev'), req: REQ, watch: WATCH, watchDigest: DIGEST, remoteCfg: CFG, evaluateCriteria, run: f.run, now: () => (t += 1000), pollMs: 1, ...extra });
    return { r, dir, files: r.files.map((x) => readFileSync(x.path).length) };
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

test('preflight: a dirty tree, an unpushed commit, an uncommitted workflow and an unusable gh each refuse, with the remedy', () => {
  const ok = remotePreflight({ repoRoot: '.', workflow: 'verify-remote.yml', run: fake().run });
  assert.equal(ok.ok, true); assert.equal(ok.sha, SHA); assert.equal(ok.branch, 'main'); assert.equal(ok.repo, 'org/repo');
  assert.match(remotePreflight({ repoRoot: '.', workflow: 'verify-remote.yml', run: fake({ dirty: ' M a.js\n' }).run }).reason, /uncommitted or untracked/);
  assert.match(remotePreflight({ repoRoot: '.', workflow: 'verify-remote.yml', run: fake({ branches: `${'b'.repeat(40)}\trefs/heads/main\n` }).run }).reason, /not the tip of any pushed branch/);
  assert.match(remotePreflight({ repoRoot: '.', workflow: 'verify-remote.yml', run: fake({ tracked: false }).run }).reason, /not committed/);
  const noGh = fake(); const orig = noGh.run;
  assert.match(remotePreflight({ repoRoot: '.', workflow: 'verify-remote.yml', run: (c, a, o) => { if (c === 'gh') throw new Error('gh: command not found'); return orig(c, a, o); } }).reason, /gh is not usable/);
});

test('a run on the right commit, over the same bytes, with every test passing, is verified, and the evidence says it ran remotely', async () => {
  const f = fake();
  const { r } = await go(f);
  assert.equal(r.status, 'ok', r.reason);
  assert.deepEqual(r.criteria.map((c) => c.state), ['pass', 'pass']);
  assert.equal(r.remote.runId, 77); assert.equal(r.remote.sha, SHA); assert.equal(r.remote.artifactDigest, 'sha256:abc'); assert.equal(r.remote.legs[0].name, 'nix');
  assert.match(r.limitations[0], /GitHub-hosted runner.*not on this host/);
  const dispatch = f.calls.find((c) => c[1] === 'workflow');
  assert.ok(dispatch.includes(`sha=${SHA}`) && dispatch.includes(`watch=${WATCH_JSON}`) && dispatch.includes('requirement=NIX-011') && dispatch.some((a) => a.startsWith('nonce=')), 'the dispatch pins the commit, the requirement, the watch set and a nonce');
});

test('it finds ITS run by nonce: no matching run means failure, never "the latest run"', async () => {
  const { r } = await go(fake({ nonceVisible: false }), { now: (() => { let t = 0; return () => (t += 120_000); })() });
  assert.equal(r.status, 'failed'); assert.match(r.reason, /no run carrying nonce/);
});

test('every way the runner\'s answer can be wrong fails closed', async () => {
  const cases = [
    ['the run concluded failure', { conclusion: 'failure' }, /concluded failure/],
    ['the run executed another commit', { headSha: 'c'.repeat(40) }, /executed cccccccccccc/],
    ['meta names another sha', { art: { sha: 'e'.repeat(40) } }, /tested eeeeeeeeeeee/],
    ['the workflow that ran is not the committed one', { art: { workflowSha: 'f'.repeat(40) } }, /workflow that ran/],
    ['the runner digested different bytes', { art: { digest: '9'.repeat(64) } }, /different bytes were tested/],
    ['the runner digested a different watch set', { art: { watchSha256: '1'.repeat(64) } }, /different set of watched files/],
    ['meta names another requirement', { art: { requirement: 'NIX-012' } }, /not NIX-011/],
    ['a declared leg is missing', { art: { legs: [] } }, /leg nix is missing/],
    ['the TAP does not match its recorded hash', { art: { tapSha256: '2'.repeat(64) } }, /does not match the hash/],
    ['the TAP file is missing', { art: { noTap: true } }, /TAP file nix.tap is missing/],
    ['meta.json is missing', { art: { noMeta: true } }, /meta.json is missing/],
  ];
  for (const [name, opts, re] of cases) {
    const { r } = await go(fake(opts));
    assert.notEqual(r.status, 'ok', name);
    assert.match(String(r.reason), re, name);
    assert.ok(r.criteria.every((c) => c.state === 'fail'), `${name}: no criterion may pass`);
  }
});

test('the TAP is judged exactly as a local run is: a failing, a skipped or an untagged criterion all fail', async () => {
  const failing = PASS_TAP.replace('ok 2 - [NIX-011.AC02]', 'not ok 2 - [NIX-011.AC02]').replace('# fail 0', '# fail 1').replace('# pass 2', '# pass 1');
  const a = (await go(fake({ art: { tap: failing, exitCode: 1 } }))).r;
  assert.equal(a.status, 'failed'); assert.equal(a.criteria.find((c) => c.id === 'NIX-011.AC02').state, 'fail'); assert.equal(a.criteria.find((c) => c.id === 'NIX-011.AC01').state, 'pass');
  const skipped = PASS_TAP.replace('ok 2 - [NIX-011.AC02] the sandbox is probed', 'ok 2 - [NIX-011.AC02] the sandbox is probed # SKIP').replace('# skipped 0', '# skipped 1');
  const b = (await go(fake({ art: { tap: skipped } }))).r;
  assert.equal(b.status, 'failed'); assert.equal(b.criteria.find((c) => c.id === 'NIX-011.AC02').state, 'fail');
  const untagged = PASS_TAP.replace('[NIX-011.AC02] ', '').replace('# tests 2', '# tests 2');
  const c = (await go(fake({ art: { tap: untagged } }))).r;
  assert.equal(c.status, 'failed'); assert.match(c.criteria.find((x) => x.id === 'NIX-011.AC02').reason, /no test is tagged/);
  const nonzero = (await go(fake({ art: { exitCode: 2 } }))).r;
  assert.equal(nonzero.status, 'failed', 'all tests pass but the suite exited non-zero');
});

test('every declared leg must pass: one passing leg and one failing leg is a failure', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'loop-remote-'));
  mkdirSync(join(dir, 'ev'), { recursive: true });
  try {
    const f = fake(); const base = f.run;
    const bad = PASS_TAP.replace('ok 1 - [NIX-011.AC01]', 'not ok 1 - [NIX-011.AC01]').replace('# fail 0', '# fail 1').replace('# pass 2', '# pass 1');
    const run = (c, a, o) => {
      if (c === 'gh' && a[0] === 'run' && a[1] === 'download') {
        const dest = a[a.indexOf('-D') + 1];
        writeFileSync(join(dest, 'x86.tap'), PASS_TAP); writeFileSync(join(dest, 'arm.tap'), bad);
        const legs = [{ name: 'x86_64-linux', tap: 'x86.tap', tapSha256: sha256(PASS_TAP), exitCode: 0 }, { name: 'aarch64-linux-emulated', tap: 'arm.tap', tapSha256: sha256(bad), exitCode: 1 }];
        writeFileSync(join(dest, 'meta.json'), JSON.stringify({ schema: 1, requirement: 'NIX-011', sha: SHA, workflowSha: SHA, treeDigest: DIGEST, watchSha256: sha256(WATCH_JSON), legs }));
        return '';
      }
      return base(c, a, o);
    };
    let t = 0;
    const r = await runRemote({ repoRoot: dir, evidenceDir: join(dir, 'ev'), req: REQ, watch: WATCH, watchDigest: DIGEST, remoteCfg: { ...CFG, legs: ['x86_64-linux', 'aarch64-linux-emulated'] }, evaluateCriteria, run, now: () => (t += 1000), pollMs: 1 });
    assert.equal(r.status, 'failed');
    assert.match(r.criteria.find((c) => c.id === 'NIX-011.AC01').reason, /leg aarch64-linux-emulated/);
    assert.equal(r.criteria.find((c) => c.id === 'NIX-011.AC02').state, 'pass');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('when remote verification is not possible the requirement is blocked, not failed and not passed', async () => {
  const { r } = await go(fake({ dirty: ' M a.js\n' }));
  assert.equal(r.status, 'unavailable'); assert.match(r.reason, /not possible/);
  assert.ok(r.criteria.every((c) => c.state === 'fail'));
});
