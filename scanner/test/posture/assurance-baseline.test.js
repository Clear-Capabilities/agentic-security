// CORE-001: reproducible baseline capture and capability inventory.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  captureBaseline, evaluateBaseline, validateBaseline, assertSafeOutput, parsePorcelain, CAPABILITY_STATUSES,
} from '../../src/posture/assurance/baseline.js';
import { CAPABILITY_INVENTORY, RECOMMENDATION_MAPPINGS } from '../../src/posture/assurance/baseline-inventory.js';
import { digestOf } from '../../src/posture/assurance/identity.js';
import * as B from '../../src/posture/assurance/baseline.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '../../..');
const CLI = path.join(REPO, 'scripts', 'baseline-capture.mjs');

const sha = (b) => crypto.createHash('sha256').update(b).digest('hex');

function run(cwd, cmd, args) {
  const r = spawnSync(cmd, args, { cwd, encoding: 'utf8' });
  assert.equal(r.status, 0, `${cmd} ${args.join(' ')}: ${r.stderr}`);
  return r.stdout;
}

const FIXTURE_INVENTORY = [
  {
    id: 'cap-a', workstream: 2, title: 'Capability A', status: 'implemented', gap: null, prd: ['X-1'],
    source: ['scanner/src/cap_a.js'], entryPoints: [{ path: 'scanner/src/cap_a.js', symbol: 'aFn' }],
    evidence: [{ kind: 'test', path: 'scanner/test/a.test.js' }],
  },
  {
    id: 'cap-b', workstream: 3, title: 'Capability B', status: 'partial', gap: 'half done', prd: ['X-2'],
    source: ['scanner/src/cap_b.js'], entryPoints: [],
    evidence: [{ kind: 'test', path: 'scanner/test/b.test.js' }, { kind: 'artifact', path: 'bench/result.json' }],
  },
];
const FIXTURE_MAPPINGS = Array.from({ length: 7 }, (_, i) => ({
  n: i + 1, title: `rec ${i + 1}`, priority: 'P0', slice: `X-${i}`, extensionPoints: ['scanner/src/cap_a.js'],
}));

/** A real git repository shaped like the checkout, with two unrelated user changes already present. */
function makeFixture() {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-fx-')));
  const w = (rel, text) => { fs.mkdirSync(path.dirname(path.join(root, rel)), { recursive: true }); fs.writeFileSync(path.join(root, rel), text); };
  w('scanner/package.json', JSON.stringify({ name: 'fx', version: '1.2.3', bin: { fx: './bin/fx.js' }, scripts: { test: 'x', build: 'y' } }));
  w('scanner/src/cap_a.js', 'export function aFn() { return 1; }\n');
  w('scanner/src/cap_b.js', 'export function bFn() { return 2; }\n');
  w('scanner/test/a.test.js', '// a\n');
  w('scanner/test/b.test.js', '// b\n');
  w('bench/result.json', '{"ok":true}\n');
  w('scanner/dist/agentic-security.mjs', 'bundle-bytes\n');
  w('scanner/dist/agentic-security.mjs.sha256', `${sha('bundle-bytes\n')}  agentic-security.mjs\n`);
  w('commands/scan.md', '# scan\n');
  w('hooks/h.js', '// hook\n');
  w('docs/README.md', 'docs\n');
  run(root, 'git', ['init', '-q']);
  run(root, 'git', ['config', 'user.email', 't@example.com']);
  run(root, 'git', ['config', 'user.name', 't']);
  run(root, 'git', ['add', '-A']);
  run(root, 'git', ['commit', '-q', '-m', 'init']);
  // unrelated user work in progress, present BEFORE the baseline is captured
  w('notes/wip.txt', 'my private notes\n');
  w('docs/README.md', 'docs, edited by the user\n');
  return root;
}
const capture = (root, extra = {}) => captureBaseline({ root, inventory: FIXTURE_INVENTORY, mappings: FIXTURE_MAPPINGS, ...extra });
const cleanup = (root) => fs.rmSync(root, { recursive: true, force: true });

function treeDigest(root) {
  const lines = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((x, y) => x.name.localeCompare(y.name))) {
      if (e.name === '.git') continue;
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p); else lines.push(`${path.relative(root, p)}:${sha(fs.readFileSync(p))}`);
    }
  };
  walk(root);
  return sha(lines.join('\n'));
}

// ---------------------------------------------------------------- AC01

test('[CORE-001.AC01] the manifest records exact source and bundle digests, HEAD, dirty paths, versions, entry points and seven mappings', () => {
  const root = makeFixture();
  try {
    const m = capture(root);
    const head = run(root, 'git', ['rev-parse', 'HEAD']).trim();
    assert.deepEqual(m.repository.head, { status: 'known', value: head });
    assert.equal(m.repository.branch.status, 'known');
    // bundle digest is the real sha256 of the bundle bytes, and the sidecar agrees
    assert.equal(m.digests.bundle.value.digest, `sha256:${sha('bundle-bytes\n')}`);
    assert.equal(m.digests.bundle.value.sidecarMatches, true);
    // source digest is stable for an unchanged tree and moves with a one-byte edit
    assert.equal(capture(root).digests.source.value.digest, m.digests.source.value.digest);
    assert.ok(m.digests.source.value.fileCount >= 3);
    fs.appendFileSync(path.join(root, 'scanner/src/cap_b.js'), ' ');
    assert.notEqual(capture(root).digests.source.value.digest, m.digests.source.value.digest);
    // dirty paths are exact and carry bytes digests
    const dirty = Object.fromEntries(m.repository.dirtyPaths.value.map(d => [d.path, d]));
    assert.equal(dirty['notes/wip.txt'].change, 'untracked');
    assert.equal(dirty['notes/wip.txt'].digest, `sha256:${sha('my private notes\n')}`);
    assert.equal(dirty['docs/README.md'].change, 'modified');
    assert.deepEqual(Object.keys(dirty).sort(), ['docs/README.md', 'notes/wip.txt']);
    // versions and entry points
    assert.equal(m.versions.node.value, process.version);
    assert.equal(m.versions.scanner.value, '1.2.3');
    assert.equal(m.versions.git.status, 'known');
    assert.deepEqual(m.entryPoints.packageBin.value, { fx: './bin/fx.js' });
    assert.deepEqual(m.entryPoints.npmScripts.value, ['build', 'test']);
    assert.deepEqual(m.entryPoints.commands.value, ['scan.md']);
    assert.deepEqual(m.entryPoints.hooks.value, ['h.js']);
    // seven mappings, each extension point verified
    assert.equal(m.recommendationMappings.length, 7);
    assert.ok(m.recommendationMappings.every(r => r.extensionPoints.every(e => e.exists)));
    assert.deepEqual(validateBaseline(m), { ok: true, errors: [] });
    assert.deepEqual(m.problems, []);
  } finally { cleanup(root); }
});

test('[CORE-001.AC01] no unknown field is fabricated: absent facts are recorded as unknown with a reason and no value', () => {
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'baseline-nogit-')));
  try {
    fs.mkdirSync(path.join(root, 'scanner/src'), { recursive: true });
    fs.writeFileSync(path.join(root, 'scanner/src/cap_a.js'), 'export function aFn() {}\n');
    const failing = (cmd, args, opts) => ({ status: 127, stdout: '', stderr: 'not found' });
    const m = captureBaseline({ root, exec: failing, inventory: [], mappings: FIXTURE_MAPPINGS });
    for (const f of [m.repository.head, m.repository.branch, m.repository.dirtyPaths, m.digests.source, m.digests.bundle, m.versions.npm, m.versions.git, m.versions.python3, m.versions.scanner, m.entryPoints.packageBin, m.entryPoints.commands]) {
      assert.equal(f.status, 'unknown');
      assert.ok(f.reason && f.reason.length > 5);
      assert.ok(!('value' in f), 'an unknown fact must not carry a value');
    }
    assert.equal(m.versions.node.status, 'known', 'what is actually known is still recorded');
    assert.deepEqual(validateBaseline(m), { ok: true, errors: [] });
    // a hand-fabricated value on an unknown fact is rejected
    const forged = structuredClone(m); forged.repository.head = { status: 'unknown', reason: 'x', value: 'abc' };
    assert.equal(validateBaseline(forged).ok, false);
    // a tampered manifest no longer matches its id
    const real = makeFixture();
    try {
      const good = capture(real);
      const bad = structuredClone(good); bad.repository.head = { status: 'known', value: 'f'.repeat(40) };
      assert.ok(validateBaseline(bad).errors.some(e => /baselineId/.test(e)));
      const sixMappings = structuredClone(good); sixMappings.recommendationMappings.pop();
      assert.equal(validateBaseline(sixMappings).ok, false);
    } finally { cleanup(real); }
  } finally { cleanup(root); }
});

test('[CORE-001.AC01] the baseline id is clock-free: two captures at different times share an id', () => {
  const root = makeFixture();
  try {
    const a = capture(root, { now: () => '2020-01-01T00:00:00Z' });
    const b = capture(root, { now: () => '2031-12-31T23:59:59Z' });
    assert.equal(a.baselineId, b.baselineId);
    assert.notEqual(a.capturedAt, b.capturedAt);
  } finally { cleanup(root); }
});

test('[CORE-001.AC01] the schema constants and the digest scope are stated, and source roots are never inside the digest scope by accident', () => {
  assert.equal(B.BASELINE_SCHEMA, 'agentic-security/baseline-manifest');
  assert.equal(B.BASELINE_VERSION, '1.0.0');
  assert.deepEqual([...B.SOURCE_DIGEST_PATHS], ['scanner/src', 'scanner/bin', 'scanner/package.json', 'scanner/package-lock.json']);
  for (const r of ['scanner/src', 'scanner/bin', 'hooks', 'commands', 'agents', 'scripts']) assert.ok(B.SOURCE_ROOTS.includes(r), r);
  assert.ok(!B.SOURCE_ROOTS.includes('docs') && !B.SOURCE_ROOTS.includes('bench'), 'docs and bench are where a baseline may be written');
  const root = makeFixture();
  try {
    const m = capture(root);
    assert.equal(m.schema, B.BASELINE_SCHEMA);
    assert.equal(m.schemaVersion, B.BASELINE_VERSION);
    assert.deepEqual(m.digests.source.value.covers, [...B.SOURCE_DIGEST_PATHS]);
  } finally { cleanup(root); }
});

test('[CORE-001.AC01] porcelain parsing keeps renames and spaced names exact', () => {
  const out = ' M a b.js\0?? new.txt\0R  to.js\0from.js\0 D gone.js\0';
  assert.deepEqual(parsePorcelain(out).map(e => e.path), ['a b.js', 'new.txt', 'to.js', 'from.js', 'gone.js']);
});

// ---------------------------------------------------------------- AC02

test('[CORE-001.AC02] every capability of the real checkout has a status, an existing source path and an existing test or artifact', () => {
  const m = captureBaseline({ root: REPO });
  assert.deepEqual(m.problems, [], m.problems.join('\n'));
  assert.ok(m.capabilities.length >= 15);
  for (const c of m.capabilities) {
    assert.ok(CAPABILITY_STATUSES.includes(c.status), c.id);
    assert.ok(c.source.length > 0 && c.evidence.length > 0, c.id);
    assert.deepEqual(c.pathsMissing, [], `${c.id} cites a path that does not exist`);
    assert.ok(Object.values(c.sourceDigests).every(d => /^sha256:[0-9a-f]{64}$/.test(d)), c.id);
    assert.ok(Object.values(c.evidenceDigests).every(d => /^sha256:[0-9a-f]{64}$/.test(d)), c.id);
    for (const ep of c.entryPoints) assert.equal(ep.exported, true, `${c.id}: ${ep.symbol}`);
    assert.equal(c.status === 'implemented', c.gap === null, `${c.id}: only an implemented capability may omit its gap`);
  }
  // the four statuses are all in use, so the vocabulary is not decorative
  assert.deepEqual([...new Set(m.capabilities.map(c => c.status))].sort(), [...CAPABILITY_STATUSES].sort());
  assert.equal(m.recommendationMappings.length, 7);
  assert.ok(m.recommendationMappings.every(r => r.extensionPoints.every(e => e.exists)), 'every mapping extension point exists');
  assert.deepEqual(validateBaseline(m), { ok: true, errors: [] });
});

test('[CORE-001.AC02] PoC replay, runtime imports, model trust and fleet checkpoints are explicitly inventoried', () => {
  const cited = (needle) => CAPABILITY_INVENTORY.filter(c => c.source.some(p => p.endsWith(needle)));
  for (const needle of ['execution-proof.js', 'runtime-observation.js', 'model-trust.js', 'fleet.js', 'scan-checkpoint.js']) {
    assert.ok(cited(needle).length >= 1, `${needle} is not inventoried`);
  }
  assert.ok(cited('telemetry-ingest.js').length >= 1, 'telemetry imports');
  // every one of the seven workstreams has at least one entry
  const ws = new Set(CAPABILITY_INVENTORY.map(c => c.workstream));
  for (const n of [1, 2, 3, 4, 5, 6, 7]) assert.ok(ws.has(n), `workstream ${n} has no inventory entry`);
  assert.equal(RECOMMENDATION_MAPPINGS.length, 7);
});

test('[CORE-001.AC02] the inventory cannot over-claim: a missing path, a missing symbol, a bad status or a gapless partial is reported', () => {
  const root = makeFixture();
  try {
    const base = FIXTURE_INVENTORY[0];
    const bad = [
      { ...base, id: 'ghost-source', source: ['scanner/src/does_not_exist.js'] },
      { ...base, id: 'ghost-evidence', evidence: [{ kind: 'test', path: 'scanner/test/nope.test.js' }] },
      { ...base, id: 'ghost-symbol', entryPoints: [{ path: 'scanner/src/cap_a.js', symbol: 'notThere' }] },
      { ...base, id: 'bad-status', status: 'excellent' },
      { ...base, id: 'implemented-with-gap', gap: 'but actually broken' },
      { ...base, id: 'partial-without-gap', status: 'partial', gap: null },
      { ...base, id: 'no-evidence', evidence: [] },
    ];
    const m = captureBaseline({ root, inventory: bad, mappings: FIXTURE_MAPPINGS });
    const text = m.problems.join('\n');
    for (const id of ['ghost-source', 'ghost-evidence', 'ghost-symbol', 'bad-status', 'implemented-with-gap', 'partial-without-gap', 'no-evidence']) {
      assert.ok(text.includes(`'${id}'`), `${id} was not reported`);
    }
    assert.ok(m.capabilities.find(c => c.id === 'ghost-source').pathsMissing.includes('scanner/src/does_not_exist.js'));
    // a mapping whose extension point is missing is reported too
    const m2 = captureBaseline({ root, inventory: [], mappings: [{ ...FIXTURE_MAPPINGS[0], extensionPoints: ['nowhere/at/all.js'] }, ...FIXTURE_MAPPINGS.slice(1)] });
    assert.ok(m2.problems.some(p => /nowhere\/at\/all\.js/.test(p)));
  } finally { cleanup(root); }
});

// ---------------------------------------------------------------- AC03

test('[CORE-001.AC03] a changed checkout invalidates exactly the applicable evidence; unrelated user changes are retained and disclosed', () => {
  const root = makeFixture();
  try {
    const recorded = capture(root);
    const wipBefore = fs.readFileSync(path.join(root, 'notes/wip.txt'), 'utf8');

    // the checkout moves on: capability A's source changes, B's cited TEST changes, and the user adds an unrelated file
    fs.appendFileSync(path.join(root, 'scanner/src/cap_a.js'), '// changed\n');
    fs.appendFileSync(path.join(root, 'scanner/test/b.test.js'), '// changed\n');
    fs.mkdirSync(path.join(root, 'scratch'), { recursive: true });
    fs.writeFileSync(path.join(root, 'scratch/idea.md'), 'new unrelated user file\n');
    const current = capture(root);
    const verdict = evaluateBaseline(recorded, current);

    assert.deepEqual(verdict.invalidated.sort(), ['cap-a', 'cap-b']);
    assert.deepEqual(verdict.capabilities.find(c => c.id === 'cap-a').changedPaths, ['scanner/src/cap_a.js']);
    assert.deepEqual(verdict.capabilities.find(c => c.id === 'cap-b').changedPaths, ['scanner/test/b.test.js']);
    assert.equal(verdict.sourceChanged, true);
    assert.equal(verdict.bundleChanged, false);
    assert.equal(verdict.headChanged, false);

    const u = verdict.userChanges;
    assert.equal(u.comparable, true);
    assert.deepEqual(u.retained.map(x => [x.path, x.scope]).sort(), [['docs/README.md', 'unrelated'], ['notes/wip.txt', 'unrelated']]);
    assert.deepEqual(u.introduced.map(x => [x.path, x.scope]).sort(), [['scanner/src/cap_a.js', 'applicable'], ['scanner/test/b.test.js', 'applicable'], ['scratch/idea.md', 'unrelated']]);
    // the user's own files are untouched
    assert.equal(fs.readFileSync(path.join(root, 'notes/wip.txt'), 'utf8'), wipBefore);
    assert.equal(fs.readFileSync(path.join(root, 'docs/README.md'), 'utf8'), 'docs, edited by the user\n');
  } finally { cleanup(root); }
});

test('[CORE-001.AC03] unrelated changes alone invalidate nothing, in both directions', () => {
  const root = makeFixture();
  try {
    const recorded = capture(root);
    fs.writeFileSync(path.join(root, 'notes/wip.txt'), 'edited again\n');
    fs.writeFileSync(path.join(root, 'notes/more.txt'), 'x\n');
    const verdict = evaluateBaseline(recorded, capture(root));
    assert.deepEqual(verdict.invalidated, []);
    assert.deepEqual(verdict.valid.sort(), ['cap-a', 'cap-b']);
    assert.deepEqual(verdict.userChanges.changedSince.map(x => x.path), ['notes/wip.txt']);
    assert.deepEqual(verdict.userChanges.introduced.map(x => x.path), ['notes/more.txt']);
    assert.ok([...verdict.userChanges.changedSince, ...verdict.userChanges.introduced].every(x => x.scope === 'unrelated'));
    // reverting an applicable change restores validity: invalidation tracks bytes, not history
    fs.appendFileSync(path.join(root, 'scanner/src/cap_a.js'), 'x');
    assert.deepEqual(evaluateBaseline(recorded, capture(root)).invalidated, ['cap-a']);
    run(root, 'git', ['checkout', '--', 'scanner/src/cap_a.js']);
    assert.deepEqual(evaluateBaseline(recorded, capture(root)).invalidated, []);
    // a bundle change and a new commit are disclosed
    fs.writeFileSync(path.join(root, 'scanner/dist/agentic-security.mjs'), 'different\n');
    assert.equal(evaluateBaseline(recorded, capture(root)).bundleChanged, true);
    run(root, 'git', ['add', 'notes/wip.txt']);
    run(root, 'git', ['commit', '-q', '-m', 'second']);
    assert.equal(evaluateBaseline(recorded, capture(root)).headChanged, true);
    // a deleted cited file invalidates
    fs.rmSync(path.join(root, 'scanner/src/cap_b.js'));
    assert.ok(evaluateBaseline(recorded, capture(root)).invalidated.includes('cap-b'));
  } finally { cleanup(root); }
});

test('[CORE-001.AC03] capture never modifies the tree, in-process or through the CLI', () => {
  const root = makeFixture();
  try {
    const before = treeDigest(root);
    const statusBefore = run(root, 'git', ['status', '--porcelain=v1', '--untracked-files=all']);
    capture(root);
    assert.equal(treeDigest(root), before);
    const cli = spawnSync(process.execPath, [CLI, '--root', root, '--json'], { encoding: 'utf8' });
    assert.ok([0, 1].includes(cli.status), cli.stderr);
    assert.equal(treeDigest(root), before, 'the CLI changed the checkout');
    assert.equal(run(root, 'git', ['status', '--porcelain=v1', '--untracked-files=all']), statusBefore);
  } finally { cleanup(root); }
});

test('[CORE-001.AC03] output is refused inside source roots and over tracked files; allowed under docs, bench or outside', () => {
  const root = makeFixture();
  try {
    assert.equal(assertSafeOutput(root, path.join(root, 'scanner/src/baseline.json')).ok, false);
    assert.equal(assertSafeOutput(root, path.join(root, 'hooks/baseline.json')).ok, false);
    assert.equal(assertSafeOutput(root, path.join(root, 'docs/README.md')).ok, false, 'a tracked file');
    assert.equal(assertSafeOutput(root, path.join(root, 'docs/baseline.json')).ok, true);
    assert.equal(assertSafeOutput(root, path.join(root, 'bench/baseline.json')).ok, true);
    assert.equal(assertSafeOutput(root, path.join(os.tmpdir(), 'elsewhere.json')).ok, true);
    const refused = spawnSync(process.execPath, [CLI, '--root', root, '--out', path.join(root, 'scanner/src/baseline.json')], { encoding: 'utf8' });
    assert.equal(refused.status, 2);
    assert.ok(!fs.existsSync(path.join(root, 'scanner/src/baseline.json')));
    assert.equal(spawnSync(process.execPath, [CLI, '--bogus'], { encoding: 'utf8' }).status, 2);
  } finally { cleanup(root); }
});

test('[CORE-001.AC03] the CLI writes a valid manifest; --compare exits 0 when current, 1 once evidence is invalidated, 2 when the baseline is forged', () => {
  const recordedPath = path.join(os.tmpdir(), `bl-${process.pid}.json`);
  try {
    // the real checkout and the real inventory
    const wrote = spawnSync(process.execPath, [CLI, '--out', recordedPath], { encoding: 'utf8' });
    assert.equal(wrote.status, 0, wrote.stderr + wrote.stdout);
    const recorded = JSON.parse(fs.readFileSync(recordedPath, 'utf8'));
    assert.deepEqual(validateBaseline(recorded), { ok: true, errors: [] });
    const same = spawnSync(process.execPath, [CLI, '--compare', recordedPath], { encoding: 'utf8' });
    assert.equal(same.status, 0, same.stdout);
    assert.match(same.stdout, /0 invalidated/);

    // the recorded baseline cites a source digest that the checkout no longer has: a properly re-identified manifest, so it is valid but stale
    const stale = structuredClone(recorded);
    const cap = stale.capabilities[0];
    cap.sourceDigests[cap.source[0]] = `sha256:${'0'.repeat(64)}`;
    const { baselineId, capturedAt, ...rest } = stale;
    stale.baselineId = digestOf(rest);
    fs.writeFileSync(recordedPath, JSON.stringify(stale));
    const invalidated = spawnSync(process.execPath, [CLI, '--compare', recordedPath], { encoding: 'utf8' });
    assert.equal(invalidated.status, 1, invalidated.stdout);
    assert.match(invalidated.stdout, /1 invalidated \(poc-replay\)/);

    // a manifest edited without re-identifying it is refused outright
    const forged = structuredClone(recorded);
    forged.capabilities[0].sourceDigests[forged.capabilities[0].source[0]] = `sha256:${'0'.repeat(64)}`;
    fs.writeFileSync(recordedPath, JSON.stringify(forged));
    assert.equal(spawnSync(process.execPath, [CLI, '--compare', recordedPath], { encoding: 'utf8' }).status, 2);
  } finally { fs.rmSync(recordedPath, { force: true }); }
});
