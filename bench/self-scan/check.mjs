#!/usr/bin/env node
// Self-scan precision gate.
//
// Phase 1 introduced six false high-severity findings on this repository's
// own code and they survived several task reviews before a human measured
// them by hand (see measure.mjs's header). This turns that measurement into
// a build gate: run measure.mjs fresh, diff it against the committed
// BASELINE.json, and fail the build on ANY drift.
//
// Per-FILE, not per-total: a finding disappearing from one file while a new
// one appears in another leaves the total unchanged but is exactly the kind
// of silent regression this gate exists to catch. Every file that gained or
// lost findings is named, with the before/after count and delta.
//
// Exit code contract (mirrors bench/cve-replay/runner.mjs's
// --check-baseline, for the same reason: a degraded environment must never
// be reported as a detection regression):
//   0  clean — fresh measurement matches BASELINE.json exactly, per file.
//   1  drift — a file's count changed, appeared, or disappeared. This is the
//      "your commit changed detection behavior" case.
//   2  could not measure — usage error, missing/unreadable baseline, the
//      measurement run itself threw, OR a preflight check failed (a target
//      directory the baseline expects is missing/unreadable, or a target the
//      baseline says has findings came back completely empty). NOT a drift
//      finding. The missing-path cases are certain environment faults — fix
//      the environment and re-run. The came-back-empty case is ambiguous:
//      it is equally the signature of every finding in that target genuinely
//      being fixed, and the remedy for that reading is `--update-baseline`,
//      not an environment fix. The message says so.
//
// The preflight exists because `measure.mjs` -> `runScan` does not throw on
// a missing target directory — it just returns { total: 0, byFile: {} } —
// so without it, a renamed-away `hooks/` looks identical to "every finding
// in hooks disappeared" and gets reported as drift (exit 1) instead of as
// the environment problem it actually is. This is the same failure mode the
// CVE-replay gate hit with a degraded Python parser: a missing capability
// silently looked like a detection regression until it got its own exit
// code. Same fix here.
//
// Usage:
//   node bench/self-scan/check.mjs                 # gate: exit 0/1/2
//   node bench/self-scan/check.mjs --update-baseline # regenerate BASELINE.json

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MEASURE = path.join(HERE, 'measure.mjs');
const BASELINE_PATH = path.join(HERE, 'BASELINE.json');

function currentCommit() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

function runMeasure() {
  const raw = execFileSync(process.execPath, [MEASURE, '--json'], {
    cwd: HERE,
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  return JSON.parse(raw);
}

// Diff two { total, byFile } shapes for a single target (or the polyglot
// block, which has byLanguage instead of byFile — the caller passes whichever
// key name applies). Returns an array of { file, before, after, delta }
// entries for every file that appeared, disappeared, or changed count.
function diffByFile(baseFile, nowFile) {
  const before = baseFile || {};
  const now = nowFile || {};
  const files = new Set([...Object.keys(before), ...Object.keys(now)]);
  const moved = [];
  for (const f of [...files].sort()) {
    const b = before[f] || 0;
    const n = now[f] || 0;
    if (b !== n) moved.push({ file: f, before: b, after: n, delta: n - b });
  }
  return moved;
}

function fail(code, msg) {
  console.error(msg);
  process.exit(code);
}

// Verify the environment can actually produce a meaningful measurement
// before trusting a diff against it. Returns null if everything checks out,
// or a human-readable message naming the specific problem otherwise.
//
// Two independent checks, because either alone can be fooled:
//   1. Every target directory the baseline knows about (plus the polyglot
//      fixture directory) must exist and be a readable directory. Catches a
//      renamed/deleted/relocated target outright. This one IS a certain
//      environment fault — a path the baseline names is simply not there.
//   2. Even if a directory exists, a target the baseline says has findings
//      must not come back with zero. Catches the case where the directory
//      is present but empty, unreadable in a way that doesn't throw, or
//      otherwise fails to produce the files the baseline expects — without
//      relying solely on the path check above. This one is AMBIGUOUS: the
//      identical signal is produced by someone genuinely fixing every finding
//      in a target, and telling them to go fix their environment leaves them
//      with a gate that can never go green. Reported as `kind: 'ambiguous'`
//      so the caller presents both readings and names `--update-baseline`.
//
// Returns null when everything checks out, otherwise
// `{ kind: 'environment' | 'ambiguous', msg }`.
function preflight(baseline, now) {
  const baseTargets = baseline.targets || {};
  for (const t of Object.keys(baseTargets)) {
    const dir = path.join(REPO, t);
    let st;
    try {
      st = fs.statSync(dir);
    } catch {
      return { kind: 'environment', msg: `target directory missing or unreadable: ${path.relative(process.cwd(), dir)} (baselined target "${t}")` };
    }
    if (!st.isDirectory()) {
      return { kind: 'environment', msg: `target path is not a directory: ${path.relative(process.cwd(), dir)} (baselined target "${t}")` };
    }
  }

  const polyDir = path.join(HERE, 'fixtures', 'polyglot');
  if (!fs.existsSync(polyDir) || !fs.statSync(polyDir).isDirectory()) {
    return { kind: 'environment', msg: `polyglot fixture directory missing or unreadable: ${path.relative(process.cwd(), polyDir)}` };
  }

  const nowTargets = now.targets || {};
  for (const t of Object.keys(baseTargets)) {
    const baseTotal = (baseTargets[t] && baseTargets[t].total) || 0;
    const nowTotal = (nowTargets[t] && nowTargets[t].total) || 0;
    if (baseTotal > 0 && nowTotal === 0) {
      return { kind: 'ambiguous', msg: `target "${t}" (${path.relative(process.cwd(), path.join(REPO, t))}) has a baseline of ${baseTotal} finding(s) but the fresh scan returned 0. Two things produce this signal and this gate cannot tell them apart:\n    (a) the target is missing/misconfigured, or the scan did not see the files the baseline was built from — check the path, the file list, and that the scan actually ran;\n    (b) every finding in that target was genuinely fixed — a real outcome, and the right one. If so this is not an error: re-run with \`--update-baseline\` to record the new zero, review the regenerated BASELINE.json, and commit it.\n    Confirm which by scanning the target directly before deciding.` };
    }
  }

  return null;
}

async function main() {
  const updateBaseline = process.argv.includes('--update-baseline');

  let now;
  try {
    now = runMeasure();
  } catch (e) {
    fail(2, `✗ could not measure — measure.mjs failed to run: ${e && e.message}\n  This is NOT a drift finding; fix the runner/environment and re-run.`);
    return;
  }

  if (updateBaseline) {
    const baseline = {
      generatedAt: new Date().toISOString(),
      commit: currentCommit(),
      targets: now.targets,
      polyglot: now.polyglot,
    };
    // Preserve any hand-written narrative notes across regenerations.
    if (fs.existsSync(BASELINE_PATH)) {
      try {
        const prev = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
        if (prev._notes) baseline._notes = prev._notes;
      } catch {
        // Unreadable previous baseline — proceed without carrying notes
        // forward rather than blocking the regeneration.
      }
    }
    fs.writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
    console.log(`✓ baseline updated → ${path.relative(process.cwd(), BASELINE_PATH)}`);
    for (const [t, v] of Object.entries(now.targets)) console.log(`  ${t}: ${v.total}`);
    console.log(`  polyglot: ${now.polyglot.total}`);
    return;
  }

  if (!fs.existsSync(BASELINE_PATH)) {
    fail(2, `✗ no baseline at ${path.relative(process.cwd(), BASELINE_PATH)} — run with --update-baseline first.`);
    return;
  }

  let baseline;
  try {
    baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, 'utf8'));
  } catch (e) {
    fail(2, `✗ could not measure — BASELINE.json is not valid JSON: ${e && e.message}`);
    return;
  }

  const problem = preflight(baseline, now);
  if (problem) {
    if (problem.kind === 'ambiguous') {
      fail(2, `✗ could not measure — cannot distinguish an environment problem from a genuine fix:\n  ${problem.msg}`);
    } else {
      fail(2, `✗ could not measure — environment problem, NOT drift: ${problem.msg}\n  Fix the environment (restore the missing path, check permissions) and re-run.`);
    }
    return;
  }

  const drift = [];

  const baseTargets = baseline.targets || {};
  const nowTargets = now.targets || {};
  const targetNames = new Set([...Object.keys(baseTargets), ...Object.keys(nowTargets)]);
  for (const t of [...targetNames].sort()) {
    const moved = diffByFile(baseTargets[t] && baseTargets[t].byFile, nowTargets[t] && nowTargets[t].byFile);
    for (const m of moved) drift.push({ target: t, ...m });
  }

  const polyMoved = diffByFile(baseline.polyglot && baseline.polyglot.byLanguage, now.polyglot && now.polyglot.byLanguage);
  for (const m of polyMoved) drift.push({ target: 'polyglot', ...m });

  console.log('Self-scan precision gate:');
  for (const t of [...targetNames].sort()) {
    const b = (baseTargets[t] && baseTargets[t].total) || 0;
    const n = (nowTargets[t] && nowTargets[t].total) || 0;
    console.log(`  ${t}: baseline=${b} now=${n}${b === n ? '' : '  ✗'}`);
  }
  console.log(`  polyglot: baseline=${(baseline.polyglot && baseline.polyglot.total) || 0} now=${(now.polyglot && now.polyglot.total) || 0}`);

  if (drift.length) {
    console.error(`\n✗ per-file drift detected (${drift.length} file(s)/language(s) moved):`);
    for (const d of drift) {
      const sign = d.delta > 0 ? '+' : '';
      console.error(`  · [${d.target}] ${d.file}: ${d.before} → ${d.after} (${sign}${d.delta})`);
    }
    console.error('\n✗ self-scan baseline drift — failing build. If intentional, run `npm run bench:self-scan:update-baseline` and review the diff before committing.');
    process.exit(1);
    return;
  }

  console.log('\n✓ no drift — per-file counts match BASELINE.json exactly');
}

main().catch(e => {
  console.error(`fatal: ${e && e.stack}`);
  process.exit(2);
});
