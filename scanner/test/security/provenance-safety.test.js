// Cross-cutting safety and determinism guarantees for Finding Provenance
// (PRD Scenarios J and L, FR-PROV-024).
//
// This file adds no new production code — Tasks 1-17 already built every
// guarantee exercised here (coordinator.js's terminal-status + secret-safety
// discipline from Task 11, engine.js's runFullScan wiring from Task 15). A
// genuine failure below means a real bug in one of those modules, not a bug
// to paper over here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { createGitFixture } from '../helpers/build-git-fixture.js';
import { runFullScan } from '../../src/engine.js';

// A syntactically valid GitHub PAT — matches the engine's own
// `ghp_[0-9a-zA-Z]{36}` secret-detector pattern EXACTLY (36 chars after the
// prefix). This matters: predicate-replay.js's `replayAt` re-runs the FULL
// detector suite (secrets included) against every historical commit's blob
// content it considers, so a canary the secrets scanner would actually flag
// is what makes this test exercise the real risk — a canary that never gets
// detected as a secret would pass trivially without the dangerous data path
// (historical blob -> in-process re-scan -> discarded result) ever firing.
const CANARY_SECRET = 'ghp_' + 'CANARY'.repeat(6); // 36 chars after "ghp_"

function assertNoCanary(haystack, where) {
  assert.equal(String(haystack).includes(CANARY_SECRET), false, `canary leaked into ${where}`);
}

function walkFiles(dir) {
  const out = [];
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.name === '.git') continue;
    const full = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

// Reads every file under `dir` as text and asserts none of them contain the
// canary — deliberately walks the WHOLE `.agentic-security` state tree, not
// just the provenance cache subdirectory, so a leak into a sibling artifact
// (lifecycle.json, a lockfile, anything else statePath() might touch) is
// caught too, not just the one location the brief named.
function assertNoCanaryOnDisk(dir) {
  const files = walkFiles(dir);
  for (const f of files) {
    let content;
    try { content = fs.readFileSync(f, 'utf8'); } catch { continue; } // not text: not a text-leak channel
    assertNoCanary(content, `on-disk file ${path.relative(dir, f)}`);
  }
  return files;
}

// Monkey-patches stdout/stderr/console during `fn` and returns everything
// written, so a leak via a stray console.error/process.stderr.write in an
// error path is caught even though nothing else here would see it.
async function captureIO(fn) {
  const chunks = [];
  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);
  const origConsole = { log: console.log, warn: console.warn, error: console.error, info: console.info, debug: console.debug };
  process.stdout.write = (chunk, ...rest) => { chunks.push(String(chunk)); return origStdout(chunk, ...rest); };
  process.stderr.write = (chunk, ...rest) => { chunks.push(String(chunk)); return origStderr(chunk, ...rest); };
  for (const k of Object.keys(origConsole)) {
    console[k] = (...args) => { chunks.push(args.map(String).join(' ')); };
  }
  try {
    const result = await fn();
    return { result, captured: chunks.join('') };
  } finally {
    process.stdout.write = origStdout;
    process.stderr.write = origStderr;
    Object.assign(console, origConsole);
  }
}

// git status --porcelain lines for the disclosed, expected
// `.agentic-security/` state directory are filtered out before comparison.
// FR-PROV-024's guarantee is about the GIT repository (HEAD, the index,
// every TRACKED file's bytes) never moving — not about whether the
// provenance cache (an ordinary, disclosed, untracked artifact under
// `.agentic-security/`) gets written; that write is exercised and verified
// safe by Scenario J below. Filtering here, rather than asserting porcelain
// is byte-identical including that directory, avoids conflating "the scanner
// wrote its own state" (expected) with "the scanner touched the repository"
// (the actual thing FR-PROV-024 forbids).
function porcelainExcludingState(root) {
  const out = execFileSync('git', ['status', '--porcelain'], { cwd: root, encoding: 'utf8' });
  return out.split('\n').filter((line) => line.length > 3 && !line.slice(3).startsWith('.agentic-security')).join('\n');
}

test('Scenario J: a historical secret never appears in provenance output, cache, disk state, or diagnostic logs', async () => {
  const fx = createGitFixture();
  try {
    const withSecret = `function h(id) {\n  const token = "${CANARY_SECRET}";\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n`;
    const withoutSecret = `function h(id) {\n  const token = process.env.TOKEN;\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n`;

    fx.writeFile('server.js', withSecret);
    fx.commit('leak secret', { date: '2026-01-01T00:00:00Z' });
    fx.writeFile('server.js', withoutSecret);
    fx.commit('remove secret', { date: '2026-01-02T00:00:00Z' });

    // Sanity: the canary really is buried in git history, and really is
    // gone from HEAD — otherwise the rest of this test proves nothing.
    const historicalBlob = execFileSync('git', ['show', 'HEAD~1:server.js'], { cwd: fx.root, encoding: 'utf8' });
    assert.ok(historicalBlob.includes(CANARY_SECRET), 'fixture setup broken: canary not actually in git history');
    assert.ok(!withoutSecret.includes(CANARY_SECRET), 'fixture setup broken: canary still in HEAD content');

    const { result: scan, captured } = await captureIO(() =>
      runFullScan({ fileContents: { 'server.js': withoutSecret }, scanRoot: fx.root }, () => {}));

    // Sanity: the finding whose provenance we're computing actually exists
    // and its origin walk actually reached the commit holding the secret —
    // otherwise the coordinator never touched the risky historical blob and
    // the assertions below would be vacuous.
    const finding = (scan.findings || []).find((f) => f.file === 'server.js' && f.family === 'sql-injection');
    assert.ok(finding && finding.findingProvenance, 'expected a sql-injection finding with findingProvenance attached');
    assert.equal(finding.findingProvenance.status, 'complete',
      'expected the origin walk to fully resolve — otherwise it may never have reached the secret-bearing commit');
    assert.ok(finding.findingProvenance.historyCoverage.commitsConsidered >= 1,
      'origin walk must have actually considered history, or this test never exercised the risky path');

    // 1. The full scan result, serialized exactly as a consumer/report
    //    writer would see it — every finding, every annotator's output
    //    (including annotatorErrors, which carry raw exception messages).
    assertNoCanary(JSON.stringify(scan), 'the serialized scan result');

    // 2. Anything written to stdout/stderr/console while the scan ran.
    assertNoCanary(captured, 'diagnostic output (stdout/stderr/console)');

    // 3. Every file on disk under .agentic-security/ — not just the
    //    provenance cache subdirectory.
    const stateDir = path.join(fx.root, '.agentic-security');
    const cacheDir = path.join(stateDir, 'provenance', 'cache');
    assert.ok(fs.existsSync(cacheDir) && fs.readdirSync(cacheDir).length > 0,
      'sanity: the provenance cache must actually contain entries, or the disk check below is vacuous');
    const scannedFiles = assertNoCanaryOnDisk(stateDir);
    assert.ok(scannedFiles.length > 0, 'sanity: expected at least one file under .agentic-security/ to have been checked');
  } finally {
    fx.cleanup();
  }
});

test('FR-PROV-024: provenance analysis makes zero changes to the working tree', async () => {
  const fx = createGitFixture();
  try {
    const src = 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n';
    fx.writeFile('server.js', src);
    fx.commit('c1', { date: '2026-01-01T00:00:00Z' });

    const headBefore = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
    const porcelainBefore = porcelainExcludingState(fx.root);
    assert.equal(porcelainBefore, '', 'sanity: fixture must start with a clean tracked tree');
    const contentBefore = fs.readFileSync(path.join(fx.root, 'server.js'), 'utf8');

    const scan = await runFullScan({ fileContents: { 'server.js': src }, scanRoot: fx.root }, () => {});
    assert.ok((scan.findings || []).some((f) => f.family === 'sql-injection'),
      'sanity: fixture must actually produce a finding, or provenance never ran against real history');

    const headAfter = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: fx.root, encoding: 'utf8' }).trim();
    const porcelainAfter = porcelainExcludingState(fx.root);
    const contentAfter = fs.readFileSync(path.join(fx.root, 'server.js'), 'utf8');

    assert.equal(headAfter, headBefore, 'HEAD must not move');
    assert.equal(porcelainAfter, porcelainBefore, 'no tracked file may be added, modified, staged, or deleted');
    assert.equal(contentAfter, contentBefore, "the scanned file's on-disk bytes must be unchanged");
  } finally {
    fx.cleanup();
  }
});

test('Scenario L: two scans of the same HEAD produce byte-stable provenance (volatile fields excluded)', async () => {
  const fx = createGitFixture();
  try {
    const src = 'function h(id) {\n  db.query("SELECT * FROM t WHERE id = " + id);\n}\n';
    fx.writeFile('server.js', src);
    fx.commit('c1', { date: '2026-01-01T00:00:00Z', authorName: 'Alice' });

    const scan1 = await runFullScan({ fileContents: { 'server.js': src }, scanRoot: fx.root }, () => {});

    // Force genuine recomputation for the second scan rather than a cache
    // read: a cache hit trivially returns the exact same object reference
    // and would prove nothing about the RESOLVER's own determinism (git log
    // output ordering, the coordinator's concurrent scheduler, iteration
    // order over any Set/Map along the way).
    fs.rmSync(path.join(fx.root, '.agentic-security', 'provenance', 'cache'), { recursive: true, force: true });

    const scan2 = await runFullScan({ fileContents: { 'server.js': src }, scanRoot: fx.root }, () => {});

    const strip = (fp) => {
      if (!fp) return fp;
      const { firstObserved, ...rest } = fp;
      return rest;
    };
    const project = (scan) => (scan.findings || [])
      .map((f) => ({ stableId: f.stableId, provenance: strip(f.findingProvenance) }));

    const fp1 = project(scan1);
    const fp2 = project(scan2);

    assert.ok(fp1.length > 0, 'sanity: fixture must actually produce findings, or this test proves nothing');
    assert.ok(fp1.every((x) => x.provenance && x.provenance.status === 'complete'),
      'sanity: expected fully-resolved provenance so the deep comparison exercises real resolved fields, not two empty stubs');

    // A genuine deep comparison, not a loose/shallow one: assert.deepEqual
    // ignores key ORDER, so it alone wouldn't catch a subtle non-determinism
    // like a Map/Set iterating in a different order between the two runs and
    // producing an object with the same values but a different key order.
    // The JSON.stringify comparison catches that; deepEqual is kept alongside
    // it as the more readable failure message when values themselves differ.
    assert.equal(JSON.stringify(fp1), JSON.stringify(fp2),
      'findingProvenance must be byte-stable across two scans of the same HEAD (volatile fields excluded), including key order');
    assert.deepEqual(fp1, fp2);
  } finally {
    fx.cleanup();
  }
});
