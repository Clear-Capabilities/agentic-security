// LOOP-005: independent acceptance verifier and fresh evidence.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { MiniRepo, suiteSource, sleep } from './helpers.js';
import { loadManifest } from '../lib/manifest.mjs';
import { layout, evidenceKey } from '../lib/state.mjs';
import { TreeIndex } from '../lib/tree.mjs';
import { verifyRequirement } from '../lib/verifier.mjs';
import { assessAll, computeProgress } from '../lib/progress.mjs';
import { assessRequirement, checkEnvelope, sign, listEvidence } from '../lib/evidence.mjs';
import { runGateCommand } from '../lib/gates.mjs';

async function ctx(repo) {
  const i = await repo.init(); assert.equal(i.code, 0, i.stderr);
  const m = loadManifest(repo.root).manifest;
  const L = layout(repo.root, repo.runId());
  const tree = new TreeIndex(repo.root);
  const key = evidenceKey(repo.root);
  return { m, L, tree, key, base: { repoRoot: repo.root, L, manifest: m, tree, key, invoker: 'test' }, req: (id) => m.requirements.find((r) => r.id === id) };
}
const R1 = [{ id: 'HS-001', weight: 2, criteria: ['one', 'two'] }];

test('[LOOP-005.AC01] a forged "100% complete" worker message cannot earn verified status', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { workerMode: { default: 'claim-done' } });
  try {
    await repo.init();
    const s = await repo.cli(['start', '--background']);
    assert.equal(s.code, 0, s.stderr);
    const st = await repo.waitFor(async () => { const x = await repo.status(); return ['blocked', 'completed', 'crashed', 'failed'].includes(x.status) ? x : null; }, { timeoutMs: 60000 });
    assert.equal(st.status, 'blocked');
    assert.equal(st.verifiedPercent, 0);
    assert.equal(st.requirements[0].state, 'blocked');
    assert.match(readFileSync(repo.runPath('attempts', 'HS-001-01', 'stream.log'), 'utf8'), /100% complete/, 'the false claim was made');
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC01] hand-edited, fabricated, re-signed-with-wrong-key and field-tampered evidence is ignored', async () => {
  const repo = new MiniRepo(R1);
  try {
    const c = await ctx(repo);
    writeFileSync(repo.path('flag-HS-001'), 'x');
    const { evidence, file } = await verifyRequirement(c.base, c.req('HS-001'));
    assert.equal(evidence.result, 'pass');
    const good = () => assessRequirement(c.L, c.req('HS-001'), { key: c.key, manifest: c.m, tree: c.tree.build() });
    assert.equal(good().verified, true);
    // 1. flip a criterion to fail->pass style edit: change result without re-signing
    const forged = JSON.parse(readFileSync(file, 'utf8')); forged.criteria[0].state = 'fail'; forged.result = 'pass';
    writeFileSync(file, JSON.stringify(forged));
    assert.equal(good().verified, false, 'edited evidence fails its signature');
    assert.ok(good().rejected.length >= 1);
    // 2. tampered tree digest even with the field changed
    const t2 = JSON.parse(JSON.stringify(evidence)); t2.treeDigest = 'a'.repeat(64);
    writeFileSync(file, JSON.stringify(t2));
    assert.equal(checkEnvelope(t2, c.key).valid, false);
    // 3. fully fabricated envelope signed with the WRONG key
    const fake = JSON.parse(JSON.stringify(evidence)); fake.evidenceId = 'HS-001-000099'; fake.signature = sign(fake, 'not-the-key');
    writeFileSync(join(c.L.evidenceDir, 'HS-001', '000099.json'), JSON.stringify(fake));
    assert.equal(good().verified, false);
    // 4. junk file
    writeFileSync(join(c.L.evidenceDir, 'HS-001', '000100.json'), '{"result":"pass"}');
    assert.equal(good().verified, false);
    assert.equal(good().latest, null, 'no valid evidence remains');
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC01] stale or swapped logs are detected by hash', async () => {
  const repo = new MiniRepo(R1);
  try {
    const c = await ctx(repo);
    writeFileSync(repo.path('flag-HS-001'), 'x');
    const { evidence } = await verifyRequirement(c.base, c.req('HS-001'));
    assert.equal(checkEnvelope(evidence, c.key, { checkLogs: true }).valid, true);
    writeFileSync(evidence.logs.combined.path, 'ok 1 - [HS-001.AC01] everything passed\n');
    const r = checkEnvelope(evidence, c.key, { checkLogs: true });
    assert.equal(r.valid, false);
    assert.match(r.reasons.join(), /log hash mismatch/);
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC01] modified expected answers (the suite itself) make prior evidence stale', async () => {
  const repo = new MiniRepo(R1);
  try {
    const c = await ctx(repo);
    writeFileSync(repo.path('flag-HS-001'), 'x');
    await verifyRequirement(c.base, c.req('HS-001'));
    const a = () => assessRequirement(c.L, c.req('HS-001'), { key: c.key, manifest: c.m, tree: c.tree.build() });
    assert.equal(a().verified, true);
    writeFileSync(repo.path('t', 'suite-HS-001.test.js'), suiteSource('HS-001', ['HS-001.AC01', 'HS-001.AC02']) + '\n// weakened\n');
    const after = a();
    assert.equal(after.verified, false);
    assert.equal(after.stale, true);
    assert.match(after.staleReasons.join(), /source\/test files changed/);
  } finally { await repo.cleanup(); }
});

const BAD_SUITES = {
  'missing tests': { src: `import test from 'node:test';\ntest('[HS-001.AC01] only one tagged', () => {});\n`, reason: /criteria not passing: HS-001\.AC02/ },
  'untagged tests': { src: `import test from 'node:test';\ntest('passes but untagged', () => {});\n`, reason: /criteria not passing/ },
  'empty selection': { src: `// no tests at all\n`, reason: /zero tests|criteria not passing|exit code/ },
  'skipped tagged test': { src: `import test from 'node:test';\ntest('[HS-001.AC01] a', () => {});\ntest('[HS-001.AC02] b', { skip: true }, () => {});\n`, reason: /skipped|criteria not passing/ },
  'todo tagged test': { src: `import test from 'node:test';\ntest('[HS-001.AC01] a', () => {});\ntest('[HS-001.AC02] b', { todo: true }, () => {});\n`, reason: /skipped|criteria not passing/ },
  'failing tagged test': { src: `import test from 'node:test';\ntest('[HS-001.AC01] a', () => {});\ntest('[HS-001.AC02] b', () => { throw new Error('no'); });\n`, reason: /exit code 1|criteria not passing/ },
  'non-zero exit accepted by nobody': { src: `import test from 'node:test';\ntest('[HS-001.AC01] a', () => {});\ntest('[HS-001.AC02] b', () => {});\ntest('unrelated failure', () => { throw new Error('x'); });\n`, reason: /exit code 1/ },
  'process exit swallowing': { src: `import test from 'node:test';\ntest('[HS-001.AC01] a', () => {});\ntest('[HS-001.AC02] b', () => {});\nprocess.on('exit', () => { process.exitCode = 5; });\n`, reason: /exit code [1-9]/ },
};
for (const [name, { src, reason }] of Object.entries(BAD_SUITES)) {
  test(`[LOOP-005.AC01] ${name} fails closed`, async () => {
    const repo = new MiniRepo(R1, { suiteSources: { 'suite-HS-001': src } });
    try {
      const c = await ctx(repo);
      const { evidence } = await verifyRequirement(c.base, c.req('HS-001'));
      assert.equal(evidence.result, 'fail');
      assert.match(evidence.reason, reason);
      const p = computeProgress(c.m, assessAll({ L: c.L, manifest: c.m, tree: c.tree.build(), key: c.key }));
      assert.equal(p.verifiedPercent, 0);
    } finally { await repo.cleanup(); }
  });
}

test('[LOOP-005.AC01] a missing suite file and an unavailable required tool are typed, not passes', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 1, criteria: ['x'] }, { id: 'HS-002', weight: 1, criteria: ['y'], requiresTools: ['definitely-not-installed-xyz'] }]);
  try {
    const c = await ctx(repo);
    repo.read('t/suite-HS-001.test.js');
    writeFileSync(repo.path('t', 'suite-HS-001.test.js'), '');
    const { rmSync } = await import('node:fs'); rmSync(repo.path('t', 'suite-HS-001.test.js'));
    const a = await verifyRequirement(c.base, c.req('HS-001'));
    assert.equal(a.evidence.result, 'fail'); assert.match(a.evidence.reason, /do not exist yet/);
    const b = await verifyRequirement(c.base, c.req('HS-002'));
    assert.equal(b.evidence.result, 'blocked'); assert.equal(b.evidence.blocker.type, 'missing-tool');
    assert.equal(b.evidence.criteria.every((x) => x.state === 'fail'), true, 'a blocked requirement earns no points');
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC02] a relevant change invalidates impacted evidence; an unrelated change does not', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['a'] }, { id: 'HS-002', weight: 3, criteria: ['b'] }], { profile: { watch: { HS: ['t/**', 'flag-*'], NIX: ['t/**'] } } });
  try {
    const c = await ctx(repo);
    for (const id of ['HS-001', 'HS-002']) writeFileSync(repo.path('flag-' + id), 'x');
    for (const id of ['HS-001', 'HS-002']) await verifyRequirement(c.base, c.req(id));
    const rows = () => computeProgress(c.m, assessAll({ L: c.L, manifest: c.m, tree: c.tree.build(), key: c.key })).requirements;
    assert.deepEqual(rows().map((r) => r.state), ['verified', 'verified']);
    writeFileSync(repo.path('unrelated.txt'), 'noise');
    assert.deepEqual(rows().map((r) => r.state), ['verified', 'verified'], 'unwatched files do not invalidate');
    writeFileSync(repo.path('t', 'suite-HS-002.test.js'), readFileSync(repo.path('t', 'suite-HS-002.test.js'), 'utf8') + '\n// edit\n');
    const r2 = rows();
    assert.equal(r2.find((r) => r.id === 'HS-002').state, 'stale');
    assert.equal(r2.find((r) => r.id === 'HS-001').state, 'stale', 'both watch t/** so both are impacted');
    // changing the verifier or acceptance definition also invalidates (acceptance/PRD hashes are bound into evidence)
    const ev = listEvidence(c.L, 'HS-001').pop().ev;
    assert.ok(ev.manifest.requirementHash && ev.verifier.hash && ev.prdSha256 && ev.treeDigest);
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC02] a tree change DURING verification aborts the verdict', async () => {
  const mutating = `import test from 'node:test';\nimport fs from 'node:fs';\ntest('[HS-001.AC01] passes but mutates the tree', () => { fs.writeFileSync('flag-mutated', String(Date.now())); });\n`;
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['one'] }], { suiteSources: { 'suite-HS-001': mutating } });
  try {
    const c = await ctx(repo);
    const { evidence } = await verifyRequirement(c.base, c.req('HS-001'));
    assert.equal(evidence.result, 'fail');
    assert.match(evidence.reason, /source tree changed while the suite was running/);
    assert.equal(evidence.criteria[0].state, 'fail');
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC03] evidence records the actual command, exit, observations and artifact hashes; the numerator counts only fresh passes', async () => {
  const repo = new MiniRepo([{ id: 'HS-001', weight: 2, criteria: ['a', 'b'] }, { id: 'HS-002', weight: 3, criteria: ['c'] }]);
  try {
    const c = await ctx(repo);
    writeFileSync(repo.path('flag-HS-001'), 'x');
    const { evidence: e1 } = await verifyRequirement(c.base, c.req('HS-001'));
    const { evidence: e2 } = await verifyRequirement(c.base, c.req('HS-002'));
    assert.equal(e1.result, 'pass'); assert.equal(e2.result, 'fail');
    assert.deepEqual(e1.exec.argv.slice(0, 3), ['node', '--test', '--test-reporter=tap']);
    assert.equal(e1.exec.cwd, '.'); assert.equal(e1.exec.exitCode, 0); assert.equal(e1.exec.expectedExitCode, 0); assert.equal(e1.exec.outcome, 'exited');
    assert.ok(e1.exec.startedAt && e1.exec.endedAt);
    assert.equal(e1.counts.tests, 2); assert.equal(e1.counts.pass, 2); assert.equal(e1.counts.fail, 0);
    assert.equal(e1.criteria.length, 2);
    assert.ok(e1.criteria.every((x) => x.state === 'pass' && x.assertions[0].name.includes(`[${x.id}]`)), 'observed assertions are recorded per criterion');
    assert.match(e1.logs.combined.sha256, /^[0-9a-f]{64}$/);
    assert.match(e1.suiteFilesDigest, /^[0-9a-f]{64}$/); assert.match(e1.treeDigest, /^[0-9a-f]{64}$/);
    assert.equal(e1.environment.node, process.version);
    assert.equal(e2.exec.exitCode, 1); assert.equal(e2.criteria[0].state, 'fail');
    const p = computeProgress(c.m, assessAll({ L: c.L, manifest: c.m, tree: c.tree.build(), key: c.key }));
    assert.equal(p.verifiedWeight, 2); assert.equal(p.totalWeight, 5); assert.equal(p.verifiedPercent, 40);
    assert.equal(p.passedCriteria, 2, 'criteria count only from fresh evidence');
    assert.equal(readdirSync(join(c.L.evidenceDir, 'HS-001')).filter((f) => f.endsWith('.json')).length, 1);
  } finally { await repo.cleanup(); }
});

test('[LOOP-005.AC04] gate wrappers: success, expected severity exits, unexpected exits, timeouts and spawn failures', async () => {
  const run = (g) => runGateCommand({ id: 'g', cwd: '.', executable: process.execPath, timeoutSeconds: 10, ...g }, { repoRoot: process.cwd(), graceMs: 300 });
  // success
  assert.equal((await run({ args: ['-e', 'process.exit(0)'] })).ok, true);
  // deliberate failure
  const bad = await run({ args: ['-e', 'process.exit(1)'] });
  assert.equal(bad.ok, false); assert.match(bad.reason, /exit 1, expected 0/);
  // a scanner run over a vulnerable fixture is EXPECTED to exit with a severity code (here 1) and that is asserted explicitly
  assert.equal((await run({ args: ['-e', 'process.exit(1)'], expectedExitCodes: [1] })).ok, true);
  // ...and an unexpected zero (scanner found nothing in a vulnerable fixture) is a failure
  const missed = await run({ args: ['-e', 'process.exit(0)'], expectedExitCodes: [1] });
  assert.equal(missed.ok, false);
  // partial-scan outcome (exit 3) is not an accepted severity exit
  assert.equal((await run({ args: ['-e', 'process.exit(3)'], expectedExitCodes: [0, 1] })).ok, false);
  // timeout, signal and spawn failure never pass
  const to = await runGateCommand({ id: 'g', cwd: '.', executable: process.execPath, args: ['-e', 'setInterval(()=>{},1000)'], timeoutSeconds: 1 }, { repoRoot: process.cwd(), graceMs: 300 });
  assert.equal(to.ok, false); assert.equal(to.outcome, 'timeout-wall');
  assert.equal((await run({ args: ['-e', 'process.kill(process.pid,"SIGKILL")'], expectedExitCodes: [0, 1] })).ok, false);
  const nf = await runGateCommand({ id: 'g', cwd: '.', executable: '/no/such/binary', args: [], timeoutSeconds: 5 }, { repoRoot: process.cwd() });
  assert.equal(nf.ok, false); assert.equal(nf.outcome, 'spawn-failed');
  await sleep(10);
});
