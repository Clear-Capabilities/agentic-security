// Tests for bench/_lib/tree-integrity.mjs (STATE_SEAM_COMPLETION_PRD M3).
//
// This helper is what stands between the project and quoting a number measured
// over a corpus the run itself modified. A guard demonstrated only in the
// passing direction has not been demonstrated, so every assertion below is
// paired with the case that must FAIL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import * as os from 'node:os';
import { fileURLToPath } from 'node:url';
import {
  snapshotTree, diffSnapshots, assertTreeUnchanged, purgeScanState, formatDiff,
} from '../../bench/_lib/tree-integrity.mjs';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const HERE_BENCH = path.join(REPO_ROOT, 'bench');

/**
 * Scanning harnesses that write ON PURPOSE, with reasons.
 *
 * `autopilot` applies fixes and `enroll-proven-finding` writes corpus entries —
 * mutation IS the job in both cases, and they run against a project the user
 * explicitly pointed them at.
 *
 * `provenance/runner.mjs` is the one entry here that is a BENCH, so it needs
 * the sharper justification. This guard exists because a bench that mutates
 * the corpus it measures produces a number nobody should quote — but that
 * reasoning is about a TRACKED corpus (bench/cve-replay's trees, this repo's
 * own src/). The provenance bench's fixture is a different kind of thing: a
 * git repo built fresh in a private os.tmpdir() per iteration by
 * createGitFixture() and fs.rmSync'd by fx.cleanup() before the next one
 * starts. Nothing it writes is tracked, committed, or reused across a run,
 * so there is no corpus to contaminate.
 *
 * And it MUST write: the bench's warm-cache arm measures the cost of a scan
 * that hits `.agentic-security/provenance-cache/`, and that cache is itself
 * gated on state writes being enabled (see cache.js). Calling
 * disableStateWrites() here would silently turn the warm arm into a second
 * cold arm — the bench would still print a "warm" number, and it would be
 * wrong. Leaving writes on is also the more honest measurement: a real scan
 * writes last-scan.json and the cache too.
 *
 * If this bench is ever repointed at a tracked tree, remove this entry.
 */
const SCANNERS_THAT_WRITE_BY_DESIGN = new Set([
  'scripts/autopilot.mjs', 'scripts/enroll-proven-finding.mjs',
  'provenance/runner.mjs',
]);

async function tmpTree() {
  const d = await fsp.mkdtemp(path.join(os.tmpdir(), 'tree-integrity-'));
  await fsp.writeFile(path.join(d, 'a.js'), 'const a = 1;\n');
  await fsp.mkdir(path.join(d, 'sub'));
  await fsp.writeFile(path.join(d, 'sub', 'b.js'), 'const b = 2;\n');
  return d;
}

test('an untouched tree compares equal', async () => {
  const d = await tmpTree();
  try {
    assert.equal(diffSnapshots(snapshotTree(d), snapshotTree(d)).ok, true);
    assert.doesNotThrow(() => assertTreeUnchanged(snapshotTree(d), snapshotTree(d), 'x'));
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a planted file is detected — the assertion FAILS, proven not assumed', async () => {
  const d = await tmpTree();
  try {
    const before = snapshotTree(d);
    await fsp.mkdir(path.join(d, '.agentic-security'));
    await fsp.writeFile(path.join(d, '.agentic-security', 'threat-model.json'), '{"cwe":"CWE-89"}');
    const after = snapshotTree(d);

    const diff = diffSnapshots(before, after);
    assert.equal(diff.ok, false);
    assert.ok(diff.added.includes('.agentic-security/threat-model.json'));
    assert.throws(() => assertTreeUnchanged(before, after, 'corpus'), /was MODIFIED by the run/);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('an EMPTY directory is detected — git cannot see these, and that hid two writers', async () => {
  // Not a hypothetical. `sbom-history/` and `fix-history/` were being created
  // in scanned trees while `git status` reported clean, because git does not
  // track empty directories. Metadata-only or git-based comparison would repeat
  // that mistake, so directories are snapshotted explicitly.
  const d = await tmpTree();
  try {
    const before = snapshotTree(d);
    await fsp.mkdir(path.join(d, 'sbom-history'));
    const diff = diffSnapshots(before, snapshotTree(d));
    assert.equal(diff.ok, false, 'creating an empty directory is a mutation');
    assert.ok(diff.added.includes('sbom-history/'));
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a same-length rewrite is detected — content hashing, not size+mtime', async () => {
  // The artifact this exists to catch is a JSON state file rewritten by a
  // second run. Equal length inside one mtime tick is exactly that shape, and
  // is precisely what a cheaper metadata comparison would miss.
  const d = await tmpTree();
  try {
    const before = snapshotTree(d);
    await fsp.writeFile(path.join(d, 'a.js'), 'const a = 9;\n'); // same byte length
    const diff = diffSnapshots(before, snapshotTree(d));
    assert.equal(diff.ok, false);
    assert.deepEqual(diff.modified, ['a.js']);
    assert.deepEqual(diff.added, []);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('a removed file is reported as removed, not silently ignored', async () => {
  const d = await tmpTree();
  try {
    const before = snapshotTree(d);
    await fsp.rm(path.join(d, 'sub', 'b.js'));
    const diff = diffSnapshots(before, snapshotTree(d));
    assert.equal(diff.ok, false);
    assert.deepEqual(diff.removed, [path.join('sub', 'b.js')]);
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('purgeScanState removes state dirs at any depth and reports the count', async () => {
  const d = await tmpTree();
  try {
    await fsp.mkdir(path.join(d, '.agentic-security'));
    await fsp.writeFile(path.join(d, '.agentic-security', 'x.json'), '{}');
    await fsp.mkdir(path.join(d, 'sub', '.agentic-security'));
    await fsp.writeFile(path.join(d, 'sub', '.agentic-security', 'y.json'), '{}');

    const removed = purgeScanState(d);
    assert.equal(removed, 2, 'the count is returned so a caller cannot clean up in silence');
    assert.ok(!fs.existsSync(path.join(d, '.agentic-security')));
    assert.ok(!fs.existsSync(path.join(d, 'sub', '.agentic-security')));
    // Upstream source is untouched — a purge that ate the corpus would be worse
    // than the contamination it removes.
    assert.ok(fs.existsSync(path.join(d, 'a.js')));
    assert.ok(fs.existsSync(path.join(d, 'sub', 'b.js')));
  } finally { await fsp.rm(d, { recursive: true, force: true }); }
});

test('the failure message names the paths and truncates a mass change', () => {
  const before = new Map([['a', '1']]);
  const after = new Map([['a', '1'], ...Array.from({ length: 30 }, (_, i) => [`n${i}`, 'h'])]);
  const diff = diffSnapshots(before, after);
  const msg = formatDiff(diff);
  assert.match(msg, /ADDED \(30\)/);
  assert.match(msg, /and 18 more/, 'a 420-tree drift must stay readable');
});

// ── Every bench runner must disable state writes ────────────────────────────

test('no bench runner can scan without disabling state writes', () => {
  // A guard, not a convention. Before this landed, the self-scan harness alone
  // had created 298 stray `.agentic-security/` directories across this
  // repository — in docs/, commands/, .github/workflows/ — and the cve-replay
  // corpus held 420 more. Both were invisible because nothing asserted their
  // absence, and both are the exact failure `posture/state-dir.js` was written
  // to prevent years earlier.
  //
  // Scoped to runners that actually SCAN. A runner that never calls runScan
  // cannot litter, and demanding the call from it would be cargo cult.
  // bench/*/ AND scripts/. The first sweep covered only bench/, and six
  // scanning harnesses under scripts/ were still writing .agentic-security/
  // into fixture trees — found by looking for stray directories after a clean
  // run, not by the guard, which is why the guard now covers them.
  const files = [];
  for (const d of fs.readdirSync(HERE_BENCH, { withFileTypes: true })) {
    if (!d.isDirectory() || d.name === '_lib') continue;
    for (const f of fs.readdirSync(path.join(HERE_BENCH, d.name))) {
      if (/\.(mjs|js)$/.test(f)) files.push(['bench', `${d.name}/${f}`, path.join(HERE_BENCH, d.name, f)]);
    }
  }
  for (const f of fs.readdirSync(path.join(REPO_ROOT, 'scripts'))) {
    if (/\.(mjs|js)$/.test(f)) files.push(['scripts', `scripts/${f}`, path.join(REPO_ROOT, 'scripts', f)]);
  }

  const offenders = [];
  {
    for (const [, rel, abs] of files) {
      if (SCANNERS_THAT_WRITE_BY_DESIGN.has(rel)) continue;
      // Comments stripped FIRST. Without it, a commented-out call still reads
      // as wired — the guard's own negative case proved that, and it is the
      // third time comment-blindness has defeated a guard in this repository
      // (the state-seam ledger guard hit it twice). Line comments before block
      // comments, for the reason documented in test/no-stray-state.test.js.
      const src = fs.readFileSync(abs, 'utf8')
        .replace(/(^|[^:])\/\/.*$/gm, '$1').replace(/\/\*[\s\S]*?\*\//g, '');
      if (!/\brunScan\b/.test(src)) continue;          // does not scan — cannot litter
      // Must CALL it, not merely import it. An earlier version of this guard
      // tested for the identifier anywhere in the file and therefore passed a
      // module whose call had been commented out — the import alone satisfied
      // it. Found by running the guard's own negative case.
      if (/disableStateWrites\s*\(/.test(src)) continue;
      offenders.push(rel);
    }
  }
  assert.deepEqual(offenders, [],
    'These bench runners call runScan without disabling state writes, so they will\n' +
    'write .agentic-security/ into the corpus they are measuring. Import\n' +
    "disableStateWrites from bench/_lib/tree-integrity.mjs and await it in main().");
});
