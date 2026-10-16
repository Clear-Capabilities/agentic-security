// E0-02: the measurement identity and the factual baseline.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { makeRoot, cleanup, REPO } from './helpers.js';
import { assertValidForRelease, configSnapshot, digestOfFiles, measurementIdentity } from '../../../scripts/engineering-excellence/lib/measurement-identity.mjs';
import { GATES, buildBaseline, renderMarkdown, runGate } from '../../../scripts/engineering-excellence/baseline.mjs';
import { withCleanWorktree } from '../../../scripts/engineering-excellence/lib/clean-worktree.mjs';

async function cleanRepo() {
  const { root, git } = await makeRoot();
  const dist = path.join(root, 'scanner', 'dist');
  fs.mkdirSync(dist, { recursive: true });
  const body = 'export const bundle = 1;\n';
  fs.writeFileSync(path.join(dist, 'agentic-security.mjs'), body);
  fs.writeFileSync(path.join(dist, 'agentic-security.mjs.sha256'), `${createHash('sha256').update(body).digest('hex')}  agentic-security.mjs\n`);
  fs.writeFileSync(path.join(root, 'scanner', 'package-lock.json'), '{}');
  fs.mkdirSync(path.join(root, 'bench'), { recursive: true });
  fs.writeFileSync(path.join(root, 'bench', 'corpus.json'), '[1,2,3]');
  git('add', '-A'); git('commit', '-q', '-m', 'bundle');
  return { root, git, body };
}

test('a clean tree with a bundle that matches its sidecar is a valid, trusted measurement identity', async () => {
  const { root } = await cleanRepo();
  try {
    const id = measurementIdentity(root, { corpus: { id: 'c', files: ['bench/corpus.json'] }, env: {} });
    assert.equal(id.measurementValid, true, id.invalidReasons.join(','));
    assert.equal(id.releaseTrust, 'trusted');
    assert.match(id.sourceCommit, /^[0-9a-f]{40}$/);
    assert.equal(id.sourceTreeClean, true);
    assert.equal(id.bundleSha256, id.bundleSidecarSha256);
    assert.equal(id.corpusId, 'c');
    assert.match(id.corpusSha256, /^[0-9a-f]{64}$/);
    assert.equal(assertValidForRelease(id), id);
    assert.ok(id.toolchain.node.startsWith('v'));
  } finally { cleanup(root); }
});

test('a dirty source tree is flagged untrusted_for_release and listed, never silently cleaned or stashed', async () => {
  const { root, git } = await cleanRepo();
  try {
    fs.writeFileSync(path.join(root, 'src.txt'), 'changed\n');
    fs.writeFileSync(path.join(root, 'new.txt'), 'untracked\n');
    const id = measurementIdentity(root, { env: {} });
    assert.equal(id.measurementValid, false);
    assert.equal(id.releaseTrust, 'untrusted_for_release');
    assert.ok(id.invalidReasons.includes('dirty_worktree'));
    assert.deepEqual(id.dirtyPaths.sort(), ['new.txt', 'src.txt']);
    assert.throws(() => assertValidForRelease(id), /untrusted_for_release.*dirty_worktree/);
    // the working tree was not touched
    assert.equal(fs.readFileSync(path.join(root, 'src.txt'), 'utf8'), 'changed\n');
    assert.equal(fs.existsSync(path.join(root, 'new.txt')), true);
    assert.equal(git === undefined, false);
  } finally { cleanup(root); }
});

test('the program\'s own bookkeeping files do not make the scanner source dirty, and the exclusion is counted', async () => {
  const { root } = await cleanRepo();
  try {
    const dir = path.join(root, 'scripts', 'engineering-excellence');
    fs.writeFileSync(path.join(dir, 'status.json'), '{"changed":true}');
    fs.mkdirSync(path.join(root, 'docs', 'engineering-excellence'), { recursive: true });
    fs.writeFileSync(path.join(root, 'docs', 'engineering-excellence', 'STATUS.md'), 'x');
    const id = measurementIdentity(root, { env: {} });
    assert.equal(id.sourceTreeClean, true);
    assert.equal(id.bookkeepingPathsIgnored, 2);
    assert.equal(id.measurementValid, true);
  } finally { cleanup(root); }
});

test('a missing bundle, a missing sidecar and a sidecar that disagrees each invalidate the measurement', async () => {
  const { root, body } = await cleanRepo();
  try {
    const bundle = path.join(root, 'scanner', 'dist', 'agentic-security.mjs');
    const reasons = () => measurementIdentity(root, { env: {} }).invalidReasons;
    fs.writeFileSync(`${bundle}.sha256`, `${'0'.repeat(64)}  agentic-security.mjs\n`);
    assert.ok(reasons().includes('bundle_sidecar_mismatch'));
    fs.rmSync(`${bundle}.sha256`);
    assert.ok(reasons().includes('bundle_sidecar_missing'));
    fs.rmSync(bundle);
    assert.ok(reasons().includes('bundle_missing'));
    void body;
  } finally { cleanup(root); }
});

test('an incomplete corpus invalidates the measurement and the corpus digest follows its content', async () => {
  const { root } = await cleanRepo();
  try {
    const a = measurementIdentity(root, { corpus: { id: 'c', files: ['bench/corpus.json'] }, env: {} });
    assert.ok(measurementIdentity(root, { corpus: { id: 'c', files: ['bench/corpus.json', 'bench/gone.json'] }, env: {} }).invalidReasons.includes('corpus_incomplete'));
    fs.writeFileSync(path.join(root, 'bench', 'corpus.json'), '[1,2,4]');
    const b = measurementIdentity(root, { corpus: { id: 'c', files: ['bench/corpus.json'] }, env: {} });
    assert.notEqual(a.corpusSha256, b.corpusSha256);
    assert.equal(digestOfFiles(root, ['bench/corpus.json']), b.corpusSha256);
  } finally { cleanup(root); }
});

test('the configuration snapshot never records a credential or an address and changes when a knob changes', () => {
  const env = { AGENTIC_SECURITY_LLM_ENDPOINT: 'https://llm.internal.example/v1?key=abc123', AGENTIC_SECURITY_HMAC_KEY: 'deadbeef', AGENTIC_SECURITY_DEEP: '1', PATH: '/bin' };
  const snap = configSnapshot(env);
  const text = JSON.stringify(snap);
  assert.equal(text.includes('abc123'), false);
  assert.equal(text.includes('deadbeef'), false);
  assert.equal(text.includes('llm.internal.example'), false);
  assert.equal(snap.modelEndpointMode, 'remote');
  assert.equal(snap.knobs.AGENTIC_SECURITY_DEEP, '1');
  assert.equal(snap.knobs.AGENTIC_SECURITY_HMAC_KEY, '<set>');
  assert.equal(configSnapshot({ AGENTIC_SECURITY_LLM_ENDPOINT: 'http://127.0.0.1:11434/v1' }).modelEndpointMode, 'loopback');
  assert.equal(configSnapshot({}).modelEndpointMode, 'none');
  assert.notEqual(JSON.stringify(configSnapshot({ AGENTIC_SECURITY_DEEP: '1' })), JSON.stringify(configSnapshot({ AGENTIC_SECURITY_DEEP: '0' })));
});

test('every baseline gate is an existing npm script, and the gate list has no duplicates', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8'));
  assert.equal(new Set(GATES.map((g) => g.id)).size, GATES.length);
  for (const g of GATES) {
    assert.deepEqual(g.argv.slice(0, 2), ['npm', 'run']);
    assert.ok(pkg.scripts[g.argv[2]], `${g.id}: npm script ${g.argv[2]} does not exist in scanner/package.json`);
    assert.ok(g.timeoutMs >= 60_000 && g.timeoutMs <= 3_600_000, `${g.id}: timeout is bounded`);
  }
});

test('a gate run is recorded with its exit code and log; a failing gate is failed and a hung one is blocked, never passed', async () => {
  const { root } = await cleanRepo();
  try {
    fs.mkdirSync(path.join(root, 'scanner'), { recursive: true });
    const gate = (id, code, timeoutMs) => ({ id, label: id, kind: 'regression', argv: [process.execPath, '-e', code], cwd: 'scanner', timeoutMs });
    const ok = await runGate(root, gate('ok', 'console.log("detection 5/5")', 30000));
    assert.equal(ok.status, 'passed');
    assert.match(ok.summaryTail, /detection 5\/5/);
    assert.ok(fs.existsSync(path.join(root, ok.log)));
    assert.match(ok.logSha256, /^[0-9a-f]{64}$/);
    const bad = await runGate(root, gate('bad', 'process.exit(3)', 30000));
    assert.equal(bad.status, 'failed');
    assert.equal(bad.exitCode, 3);
    const hung = await runGate(root, gate('hung', 'setInterval(()=>{},1000)', 2000));
    assert.equal(hung.status, 'blocked');
    assert.match(hung.reason, /timeout|wall/i);
    assert.equal(ok.measurementValid, true, 'the identity is taken before the run, on the clean fixture');
    assert.equal(ok.sourceCommit.length, 40);
  } finally { cleanup(root); }
});

test('the baseline reports gates that were not run as not_run and the independent population as unmeasured, with archived numbers labelled historical', () => {
  const b = buildBaseline(REPO);
  assert.equal(b.schemaVersion, 1);
  assert.equal(b.independentAccuracy.status, 'unmeasured');
  assert.match(b.independentAccuracy.reason, /No fresh run/);
  if (b.independentAccuracy.archived) {
    assert.match(b.independentAccuracy.archived.label, /HISTORICAL/);
    assert.equal(b.independentAccuracy.archived.engineVersion, '0.141.0');
  }
  assert.deepEqual(b.gates.map((g) => g.id), GATES.map((g) => g.id));
  for (const g of b.gates) assert.ok(['passed', 'failed', 'blocked', 'not_run'].includes(g.status), `${g.id}: ${g.status}`);
  assert.equal(b.corpora.cveReplay.role.includes('not an accuracy measurement'), true);
  const md = renderMarkdown(b);
  assert.match(md, /Release trust:/);
  assert.match(md, /Status: \*\*unmeasured\*\*/);
});

test('the committed baseline names a real commit and states its release trust', () => {
  const committed = JSON.parse(fs.readFileSync(path.join(REPO, 'docs', 'engineering-excellence', 'baseline.json'), 'utf8'));
  assert.match(committed.identity.sourceCommit, /^[0-9a-f]{40}$/);
  assert.ok(['trusted', 'untrusted_for_release'].includes(committed.identity.releaseTrust));
  assert.equal(committed.independentAccuracy.status, 'unmeasured');
  for (const g of committed.gates) {
    if (g.status === 'passed' || g.status === 'failed') {
      assert.equal(typeof g.exitCode, 'number', `${g.id} records an exit code`);
      assert.ok(g.log && g.logSha256, `${g.id} records its log`);
    }
  }
});

test('a measurement worktree is a clean checkout of one commit, the working tree is left alone, and the worktree is removed afterwards', async () => {
  const { root } = await cleanRepo();
  try {
    fs.mkdirSync(path.join(root, 'scanner', 'node_modules'), { recursive: true });
    fs.writeFileSync(path.join(root, 'src.txt'), 'uncommitted edit\n');
    fs.writeFileSync(path.join(root, 'scratch.txt'), 'untracked\n');
    let seen;
    await withCleanWorktree(root, ({ dir, commit, linked }) => {
      seen = { dir, commit, linked };
      assert.equal(fs.readFileSync(path.join(dir, 'src.txt'), 'utf8'), 'x\n', 'the committed content, not the edit');
      assert.equal(fs.existsSync(path.join(dir, 'scratch.txt')), false);
      assert.ok(fs.lstatSync(path.join(dir, 'scanner', 'node_modules')).isSymbolicLink(), 'generated, gitignored pieces are linked');
      const id = measurementIdentity(dir, { env: {} });
      assert.equal(id.sourceTreeClean, true);
      assert.equal(id.sourceCommit, commit);
    }, { parent: os_tmp() });
    assert.deepEqual(seen.linked, ['scanner/node_modules']);
    assert.equal(fs.existsSync(seen.dir), false, 'removed afterwards');
    assert.equal(fs.readFileSync(path.join(root, 'src.txt'), 'utf8'), 'uncommitted edit\n', 'the working tree was not touched');
    assert.equal(fs.existsSync(path.join(root, 'scratch.txt')), true);
    // the worktree is removed even when the measurement throws
    let dirSeen;
    await assert.rejects(withCleanWorktree(root, ({ dir }) => { dirSeen = dir; throw new Error('boom'); }, { parent: os_tmp() }), /boom/);
    assert.equal(fs.existsSync(dirSeen), false);
  } finally { cleanup(root); }
});

test('a gate run can be taken in a different tree from the one it is recorded against', async () => {
  const { root } = await cleanRepo();
  try {
    fs.mkdirSync(path.join(root, 'scanner'), { recursive: true });
    fs.writeFileSync(path.join(root, 'dirty.txt'), 'the working tree is dirty\n');
    const gate = { id: 'where', label: 'where', kind: 'regression', argv: [process.execPath, '-e', 'console.log(process.cwd())'], cwd: 'scanner', timeoutMs: 30000 };
    let measured;
    await withCleanWorktree(root, async ({ dir }) => { fs.mkdirSync(path.join(dir, 'scanner'), { recursive: true }); measured = await runGate(root, gate, { measureRoot: dir }); }, { parent: os_tmp() });
    assert.equal(measured.status, 'passed');
    assert.equal(measured.measurementValid, true, 'valid because it was measured in the clean worktree, not the dirty working tree');
    assert.match(measured.summaryTail, /-measure-/);
    assert.equal(measurementIdentity(root, { env: {} }).measurementValid, false, 'the working tree itself is dirty');
  } finally { cleanup(root); }
});

function os_tmp() { return fs.realpathSync(path.join(path.sep, 'tmp')); }
