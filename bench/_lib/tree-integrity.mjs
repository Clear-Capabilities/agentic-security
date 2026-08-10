// Byte-identity assertions for benchmark corpora (STATE_SEAM_COMPLETION_PRD M3).
//
// WHY THIS EXISTS
// ---------------
// A benchmark that mutates its own corpus is measuring something other than the
// code. This project has already paid for that lesson twice:
//
//   · bench/independent/ was scored against 220 trees polluted with the
//     engine's own output — 544 state files carrying CWE identifiers — so the
//     engine was partly grading its own prior conclusions. Every figure
//     measured that way had to be withdrawn.
//   · bench/cve-replay/ — the corpus behind the gate that runs on EVERY push
//     and behind the published scorecard — was measured at 420 contaminated
//     trees / 5,231 state files, accreting one new `sbom-history/<commit>.json`
//     per tree on every gate run, without bound.
//
// Both were invisible for weeks, because nothing ever asked the one question
// that would have exposed them: *is the corpus the same after the run as it was
// before?* That question is this module.
//
// WHY CONTENT HASHES AND NOT size+mtime
// -------------------------------------
// Cheaper metadata comparison is tempting and wrong here. A rewrite that
// preserves length lands inside one mtime tick often enough to matter, and the
// artifacts this is built to catch — a JSON state file rewritten by a second
// run — are exactly that shape. Hashing a 25 MB corpus costs well under a
// second against scans that take minutes.
//
// WHAT IT DELIBERATELY DOES NOT DO
// --------------------------------
// It does not clean up. Purging belongs to the runner, before its scans; this
// module only observes. A helper that quietly repaired the tree would hide the
// very drift it exists to report — and the corpus would go on being mutated,
// just invisibly.
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';

/** Directories never walked: enormous, and not part of the measured corpus. */
const SKIP_DIRS = new Set(['node_modules', '.git']);

/**
 * Content-hash every file under `dir`.
 *
 * Returns a Map of repo-relative path -> sha256. Unreadable files are recorded
 * with a sentinel rather than skipped: a file that becomes unreadable between
 * the two snapshots IS a change, and silently dropping it would report the tree
 * as unchanged.
 */
export function snapshotTree(dir) {
  const out = new Map();
  const walk = (d) => {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (SKIP_DIRS.has(e.name)) continue;
        // Directories are recorded too. An EMPTY directory is invisible to
        // `git status` (git does not track them) and was, measurably, how two
        // state-writing modules escaped detection: the tree read "clean" while
        // `sbom-history/` and `fix-history/` were being created in it.
        out.set(path.relative(dir, p) + '/', 'dir');
        walk(p);
        continue;
      }
      if (!e.isFile()) continue;
      let h;
      try { h = crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }
      catch { h = 'UNREADABLE'; }
      out.set(path.relative(dir, p), h);
    }
  };
  walk(dir);
  return out;
}

/**
 * Compare two snapshots. Returns `{ ok, added[], removed[], modified[] }`.
 *
 * Every category is reported separately because they mean different things: an
 * ADDED path is the engine littering, a MODIFIED one is the engine overwriting
 * the corpus it is being scored against, and a REMOVED one means a runner is
 * deleting upstream source.
 */
export function diffSnapshots(before, after) {
  const added = [], removed = [], modified = [];
  for (const [p, h] of after) {
    if (!before.has(p)) added.push(p);
    else if (before.get(p) !== h) modified.push(p);
  }
  for (const p of before.keys()) if (!after.has(p)) removed.push(p);
  added.sort(); removed.sort(); modified.sort();
  return { ok: !added.length && !removed.length && !modified.length, added, removed, modified };
}

/** Render a diff for a human, truncated so a mass change stays readable. */
export function formatDiff(diff, limit = 12) {
  const L = [];
  const section = (label, arr) => {
    if (!arr.length) return;
    L.push(`  ${label} (${arr.length}):`);
    for (const p of arr.slice(0, limit)) L.push(`    · ${p}`);
    if (arr.length > limit) L.push(`    … and ${arr.length - limit} more`);
  };
  section('ADDED', diff.added);
  section('MODIFIED', diff.modified);
  section('REMOVED', diff.removed);
  return L.join('\n');
}

/**
 * Assert a corpus is byte-identical across a run.
 *
 * Throws on drift. Benchmarks are measurements, not gates, so they generally
 * avoid failing a build — but this is not a measurement of the ENGINE, it is a
 * statement about whether the measurement itself is valid. A run over a mutated
 * corpus produces a number nobody should quote, and continuing silently would
 * hand back exactly that number.
 */
export function assertTreeUnchanged(before, after, label) {
  const diff = diffSnapshots(before, after);
  if (diff.ok) return diff;
  throw new Error(
    `${label}: the corpus was MODIFIED by the run — this measurement is not valid.\n` +
    formatDiff(diff) + '\n' +
    '  A benchmark that mutates its own corpus is measuring something other than\n' +
    '  the code. Scan with state writing disabled (setStateWritesEnabled(false) or\n' +
    '  AGENTIC_SECURITY_NO_STATE=1) and purge leftover state before the run.',
  );
}

/**
 * Turn state writing off for an in-process bench run, and prove it took effect.
 *
 * Both switches are set. The env var covers any child process a runner spawns;
 * the in-process call covers the common case where `runScan` is imported
 * directly. Setting only one leaves a whole class of runner unprotected, and
 * which class depends on an implementation detail of the runner — not something
 * a caller should have to know.
 */
export async function disableStateWrites() {
  process.env.AGENTIC_SECURITY_NO_STATE = '1';
  const { setStateWritesEnabled, stateWritesEnabled } =
    await import('../../scanner/src/posture/state-dir.js');
  setStateWritesEnabled(false);
  // Verified, not assumed: this module's whole purpose is to stop a benchmark
  // trusting an unchecked precondition.
  if (stateWritesEnabled()) {
    throw new Error('failed to disable state writes — refusing to run a benchmark that would mutate its corpus');
  }
}

/**
 * Remove `.agentic-security/` directories left inside a corpus by earlier runs.
 *
 * Purged BEFORE a run, never only after: purging afterwards still leaves a
 * window in which an interrupted run poisons the next one. Returns the number
 * of directories removed so a caller can report a non-zero count rather than
 * cleaning up in silence.
 *
 * POINT THIS AT A CORPUS, NEVER AT THE REPOSITORY. Not every
 * `.agentic-security/` is scan output: `scanner/test/fixtures/custom-rules/`
 * and `.../sca-suppression/` keep a **tracked, committed** `rules.yml` inside
 * one, because that is where the product reads rules from. A repo-wide sweep
 * deletes them and breaks the custom-rule and SCA-suppression tests — done
 * accidentally while implementing this module, caught by the suite, restored
 * from git. The caller chooses the directory precisely so this function never
 * has to guess which state is disposable.
 */
export function purgeScanState(dir, { maxDepth = 12 } = {}) {
  let removed = 0;
  const walk = (d, depth = 0) => {
    if (depth > maxDepth) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const p = path.join(d, e.name);
      if (e.name === '.agentic-security') {
        fs.rmSync(p, { recursive: true, force: true });
        removed++;
        continue;
      }
      if (SKIP_DIRS.has(e.name)) continue;
      walk(p, depth + 1);
    }
  };
  walk(dir);
  return removed;
}
