// E7-02: finding-to-commit attribution is defensible: it follows renames, handles deep-layer findings, survives rebases and shallow clones, keeps
// uncommitted, ignored, generated and history-less findings apart from attributed ones, surfaces its failures, and reports both denominators.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { runScan } from '../../src/runScan.js';
import { setStateWritesEnabled } from '../../src/posture/state-dir.js';
import { ATTRIBUTION_CATEGORIES, ATTRIBUTION_TARGET, MIN_ELIGIBLE_FOR_RATE, attributionCoverage, inspectRepository } from '../../src/posture/provenance/coverage.js';
import { clearBlameCache } from '../../src/posture/provenance/git-evidence.js';
import { createGitFixture } from '../helpers/build-git-fixture.js';

setStateWritesEnabled(false);
const SAFE = "const express = require('express');\nconst app = express();\napp.get('/', (req, res) => res.send('ok'));\n";
const RUN = "const { exec } = require('child_process');\napp.get('/run', (req, res) => { exec('ls ' + req.query.d); res.end(); });\n";
const cmd = (scan) => (scan.findings || []).filter((f) => /Command Injection/i.test(f.vuln || ''));
const sh = (dir, ...a) => execFileSync('git', a, { cwd: dir, stdio: 'pipe', encoding: 'utf8' });
const scan = async (dir) => (await runScan(dir, { deep: true })).scan;

test('MULTI-AUTHOR: the origin is the commit that introduced the flaw, by its author, not a later commit by someone else that touched the file', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('app.js', SAFE + RUN); const intro = fx.commit('add run endpoint', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('app.js', SAFE + RUN + '// footer\n'); fx.commit('footer', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    fx.writeFile('app.js', '// header\n' + SAFE + RUN + '// footer\n'); fx.commit('header shifts every line down', { date: '2026-01-04T00:00:00Z', authorName: 'Dave' });
    const [f] = cmd(await scan(fx.root)); assert.ok(f, 'the flaw is found');
    const fp = f.findingProvenance;
    assert.equal(fp.status, 'complete'); assert.equal(fp.findingOrigin.commit, intro); assert.equal(fp.findingOrigin.authorName, 'Bob');
    assert.equal(fp.method, 'semantic-history-replay'); assert.ok(fp.findingOrigin.absentInParents.length >= 1, 'it was absent in the parent: the commit introduced it');
    assert.equal(fp.findingOrigin.committerDate.slice(0, 10), '2026-01-02');
  } finally { fx.cleanup(); }
});

test('KNOWN LIMIT, pinned: when a later commit edits the text of the vulnerable line itself, the finding is credited to that edit (its identity includes the line text)', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('app.js', SAFE + RUN); fx.commit('add run endpoint', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('app.js', (SAFE + RUN).replace('res.end();', 'res.end(); // done')); const edit = fx.commit('annotate the vulnerable line, flaw intact', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    const [f] = cmd(await scan(fx.root)); const fp = f.findingProvenance;
    assert.equal(fp.status, 'complete'); assert.equal(fp.findingOrigin.commit, edit, 'today the edit is credited; if this changes, change it on purpose');
    assert.notEqual(fp.confidence.level, 'unknown');
  } finally { fx.cleanup(); }
});

test('RENAMES AND MOVES: the origin survives a rename, a move into a directory, and both in sequence; the rename commit is never credited', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('app.js', SAFE + RUN); const intro = fx.commit('add run endpoint', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    sh(fx.root, 'mv', 'app.js', 'server.js'); fx.commit('rename', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    fs.mkdirSync(path.join(fx.root, 'src/api'), { recursive: true }); sh(fx.root, 'mv', 'server.js', 'src/api/server.js'); fx.commit('move into src/api', { date: '2026-01-04T00:00:00Z', authorName: 'Dave' });
    const [f] = cmd(await scan(fx.root)); assert.equal(f.file, 'src/api/server.js');
    assert.equal(f.findingProvenance.status, 'complete', JSON.stringify(f.findingProvenance.limitations));
    assert.equal(f.findingProvenance.findingOrigin.commit, intro); assert.equal(f.findingProvenance.findingOrigin.authorName, 'Bob');
  } finally { fx.cleanup(); }
});

test('REBASE: after history is rewritten the origin is the rewritten commit, with the same author, and the attribution is consistent', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    const main = sh(fx.root, 'rev-parse', '--abbrev-ref', 'HEAD').trim();
    sh(fx.root, 'checkout', '-q', '-b', 'feature');
    fx.writeFile('app.js', SAFE + RUN); const before = fx.commit('add run endpoint', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    sh(fx.root, 'checkout', '-q', main);
    fx.writeFile('README.md', 'docs\n'); fx.commit('docs on main', { date: '2026-01-03T00:00:00Z', authorName: 'Eve' });
    sh(fx.root, 'checkout', '-q', 'feature'); sh(fx.root, '-c', 'user.email=r@x.test', '-c', 'user.name=Rebaser', 'rebase', '-q', main);
    const after = sh(fx.root, 'rev-parse', 'HEAD').trim(); assert.notEqual(after, before, 'the commit was rewritten');
    const [f] = cmd(await scan(fx.root)); const fp = f.findingProvenance;
    assert.equal(fp.status, 'complete'); assert.equal(fp.findingOrigin.commit, after); assert.equal(fp.findingOrigin.authorName, 'Bob', 'the author survives the rebase; the committer does not take the credit');
    assert.notEqual(fp.findingOrigin.commit, before);
  } finally { fx.cleanup(); }
});

test('UNCOMMITTED: a line in the working tree that no commit has is reported as uncommitted, with no author or date invented', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('app.js', SAFE + RUN); // not committed
    const [f] = cmd(await scan(fx.root)); const fp = f.findingProvenance;
    assert.equal(fp.status, 'uncommitted'); assert.equal(fp.findingOrigin, null, 'no commit, so no origin');
    const cov = attributionCoverage([f], { root: fx.root });
    assert.equal(cov.categories.uncommitted, 1); assert.equal(cov.attributed, 1);
  } finally { fx.cleanup(); }
});

test('SHALLOW CLONE: a clone cut short is not claimed as complete, says why, and is classed as history-unavailable rather than as a pipeline failure', async () => {
  const fx = createGitFixture();
  const clone = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-02-shallow-'));
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('app.js', SAFE + RUN); fx.commit('add run endpoint', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    fx.writeFile('README.md', 'x\n'); fx.commit('readme', { date: '2026-01-03T00:00:00Z', authorName: 'Carol' });
    const dest = path.join(clone, 'c'); execFileSync('git', ['clone', '-q', '--depth', '1', `file://${fx.root}`, dest], { stdio: 'pipe' });
    assert.equal(sh(dest, 'rev-parse', '--is-shallow-repository').trim(), 'true');
    const [f] = cmd(await scan(dest)); const fp = f.findingProvenance;
    assert.notEqual(fp.status, 'complete', 'with one commit visible nothing can be shown to have been introduced');
    assert.ok(fp.limitations.length > 0 && fp.confidence.level !== 'high');
    assert.equal(fp.historyCoverage.shallow, true);
    const cov = attributionCoverage([f], { root: dest });
    assert.equal(cov.categories['ineligible:history-unavailable'], 1, JSON.stringify(cov.perFinding)); assert.equal(cov.eligible, 0);
  } finally { fx.cleanup(); fs.rmSync(clone, { recursive: true, force: true }); }
});

test('INELIGIBLE FILES are counted apart from attributed ones: ignored, generated, untracked and no repository', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-02-cov-'));
  try {
    sh(dir, 'init', '-q', '.'); sh(dir, 'config', 'user.email', 'a@b'); sh(dir, 'config', 'user.name', 'n');
    fs.writeFileSync(path.join(dir, '.gitignore'), 'ignored/\n'); fs.mkdirSync(path.join(dir, 'ignored')); fs.mkdirSync(path.join(dir, 'src/generated'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'src/real.js'), 'a\n'); fs.writeFileSync(path.join(dir, 'src/generated/x.js'), 'a\n'); fs.writeFileSync(path.join(dir, 'src/header.js'), '// Code generated by protoc. DO NOT EDIT.\n');
    sh(dir, 'add', '-A'); sh(dir, 'commit', '-qm', 'init');
    fs.writeFileSync(path.join(dir, 'ignored/i.js'), 'a\n'); fs.writeFileSync(path.join(dir, 'src/new.js'), 'a\n');
    const fnd = (file, status, extra = {}) => ({ id: file, file, findingProvenance: { status, limitations: ['x'], ...extra } });
    const findings = [fnd('src/real.js', 'complete'), fnd('src/real.js', 'partial'), fnd('src/real.js', 'budget_exhausted'), fnd('src/real.js', 'error'), fnd('src/real.js', 'not_available'), fnd('ignored/i.js', 'partial'), fnd('src/generated/x.js', 'partial'), fnd('src/header.js', 'partial'), fnd('src/new.js', 'partial'), fnd('src/real.js', 'uncommitted')];
    const cov = attributionCoverage(findings, { root: dir, readHeader: (f) => fs.readFileSync(path.join(dir, f), 'utf8').slice(0, 400) });
    assert.deepEqual(Object.keys(cov.categories), [...ATTRIBUTION_CATEGORIES]);
    assert.deepEqual(cov.categories, { attributed: 1, uncommitted: 1, 'ineligible:ignored': 1, 'ineligible:generated': 2, 'ineligible:untracked': 1, 'ineligible:history-unavailable': 0, 'eligible:budget_exhausted': 1, 'eligible:project-wide': 0, 'eligible:unconfirmed': 1, 'eligible:not_available': 1, 'eligible:error': 1 });
    assert.equal(cov.total, 10); assert.equal(cov.attributed, 2); assert.equal(cov.ineligible, 4); assert.equal(cov.eligibleUnattributed, 4); assert.equal(cov.eligible, 6);
    assert.equal(cov.attributed + cov.ineligible + cov.eligibleUnattributed, cov.total, 'every finding is in exactly one bucket');
    assert.equal(cov.overallRate, 0.2); assert.equal(cov.eligibleRate, 0.3333);
    assert.equal(cov.targetStatus, 'insufficient_eligible', 'six eligible findings are too few to call a rate met or missed'); assert.equal(cov.target, ATTRIBUTION_TARGET);
    assert.ok(cov.perFinding.every((p) => p.category && (p.category.startsWith('attributed') || p.category === 'uncommitted' || p.reason)), 'every non-attributed finding says why');
    // no repository at all
    const bare = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-02-norepo-'));
    try {
      const nr = attributionCoverage([fnd('a.js', 'not_available')], { root: bare });
      assert.equal(nr.categories['ineligible:history-unavailable'], 1); assert.match(nr.perFinding[0].reason, /not inside a git work tree/);
      assert.equal(inspectRepository(bare, ['a.js']).repo, false);
    } finally { fs.rmSync(bare, { recursive: true, force: true }); }
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('PROJECT-WIDE detectors are named as such, not lumped with ordinary unconfirmed findings', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-02-pw-'));
  try {
    sh(dir, 'init', '-q', '.'); sh(dir, 'config', 'user.email', 'a@b'); sh(dir, 'config', 'user.name', 'n'); fs.writeFileSync(path.join(dir, 'a.js'), 'a\n'); sh(dir, 'add', '-A'); sh(dir, 'commit', '-qm', 'i');
    const p = (parser, family) => ({ id: `${parser}`, file: 'a.js', parser, family, findingProvenance: { status: 'partial', limitations: ['x'] } });
    const cov = attributionCoverage([p('STATE-MACHINE', 'state-machine-bypass'), p('REGEX', 'spec-drift'), p('CONCURRENCY', 'concurrency-bug'), p('STRUCTURAL', 'xss'), p('LLM-STORED-PROMPT-XFILE', 'llm-prompt-injection')], { root: dir });
    assert.equal(cov.categories['eligible:project-wide'], 4); assert.equal(cov.categories['eligible:unconfirmed'], 1);
    assert.equal(cov.eligible, 5, 'they stay in the eligible denominator: they are a gap to close, not an exemption');
    assert.match(cov.perFinding[0].reason, /whole-project analysis/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('THE TARGET: met, not met and insufficient are different statements, and the rate is never a bare number', () => {
  const mk = (n, attributed) => Array.from({ length: n }, (_, i) => ({ id: `f${i}`, file: 'src/a.js', findingProvenance: { status: i < attributed ? 'complete' : 'partial', limitations: ['x'] } }));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ee-e7-02-t-'));
  try {
    sh(dir, 'init', '-q', '.'); sh(dir, 'config', 'user.email', 'a@b'); sh(dir, 'config', 'user.name', 'n'); fs.mkdirSync(path.join(dir, 'src')); fs.writeFileSync(path.join(dir, 'src/a.js'), 'a\n'); sh(dir, 'add', '-A'); sh(dir, 'commit', '-qm', 'i');
    assert.equal(attributionCoverage(mk(100, 96), { root: dir }).targetStatus, 'met'); assert.equal(attributionCoverage(mk(100, 94), { root: dir }).targetStatus, 'not_met');
    assert.equal(attributionCoverage(mk(MIN_ELIGIBLE_FOR_RATE - 1, MIN_ELIGIBLE_FOR_RATE - 1), { root: dir }).targetStatus, 'insufficient_eligible');
    const empty = attributionCoverage([], { root: dir }); assert.equal(empty.eligibleRate, null); assert.equal(empty.overallRate, null); assert.equal(empty.targetStatus, 'insufficient_eligible');
    assert.equal(attributionCoverage(null, { root: dir }).total, 0);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('ERRORS ARE SURFACED: a broken repository gives findings a status and a reason, never a thrown error or a silent blank', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('package.json', '{"name":"p"}'); fx.writeFile('app.js', SAFE + RUN); fx.commit('init', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fs.writeFileSync(path.join(fx.root, '.git', 'HEAD'), 'ref: refs/heads/does-not-exist\n');
    fs.writeFileSync(path.join(fx.root, '.git', 'index'), 'garbage');
    let s; await assert.doesNotReject(async () => { s = await scan(fx.root); });
    const f = cmd(s)[0]; assert.ok(f, 'the scan still finds the flaw');
    const fp = f.findingProvenance;
    assert.ok(fp && typeof fp.status === 'string', 'the finding carries a provenance status'); assert.notEqual(fp.status, 'complete');
    assert.ok(Array.isArray(fp.limitations) && fp.limitations.length > 0, `and a reason: ${JSON.stringify(fp)}`);
    const cov = attributionCoverage([f], { root: fx.root });
    assert.equal(cov.attributed, 0); assert.ok(cov.perFinding[0].reason, 'the coverage report names the reason');
  } finally { fx.cleanup(); }
});

test('PER-FILE BLAME gives the same answers as per-line blame and starts far fewer processes for a file with many findings', async () => {
  const fx = createGitFixture();
  try {
    fx.writeFile('f.js', Array.from({ length: 40 }, (_, i) => `// line ${i + 1}`).join('\n') + '\n'); const a = fx.commit('first', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });
    fx.writeFile('f.js', Array.from({ length: 40 }, (_, i) => (i % 2 ? `// edited ${i + 1}` : `// line ${i + 1}`)).join('\n') + '\n'); const b = fx.commit('edit odd lines', { date: '2026-01-02T00:00:00Z', authorName: 'Bob' });
    const { blameLine } = await import('../../src/posture/provenance/git-evidence.js');
    const perLine = []; for (let l = 1; l <= 40; l++) { clearBlameCache(); perLine.push(blameLine(fx.root, 'f.js', l)); }
    clearBlameCache();
    const cached = []; for (let l = 1; l <= 40; l++) cached.push(blameLine(fx.root, 'f.js', l));
    assert.deepEqual(cached, perLine, 'identical for every line');
    assert.equal(cached[0].commit, a); assert.equal(cached[1].commit, b); assert.equal(cached[1].authorName, 'Bob');
    // process count: the first question uses the single-line form, the rest are answered by one whole-file blame
    const cpMod = await import('node:child_process'); const real = cpMod.default.execFileSync; let blames = 0;
    cpMod.default.execFileSync = function (file, args) { if (file === 'git' && Array.isArray(args) && args.includes('blame')) blames++; return real.apply(this, arguments); };
    const { syncBuiltinESMExports } = await import('node:module'); syncBuiltinESMExports();
    try { clearBlameCache(); for (let l = 1; l <= 40; l++) blameLine(fx.root, 'f.js', l); } finally { cpMod.default.execFileSync = real; syncBuiltinESMExports(); }
    assert.ok(blames <= 2, `40 lines of one file cost ${blames} blame processes (it was 40)`);
    // a changed file is blamed again, not served stale
    fx.writeFile('f.js', 'new first line\n' + fs.readFileSync(path.join(fx.root, 'f.js'), 'utf8'));
    const live = blameLine(fx.root, 'f.js', 1); assert.equal(live.uncommitted, true, 'the working-tree change is seen');
  } finally { fx.cleanup(); clearBlameCache(); }
});
