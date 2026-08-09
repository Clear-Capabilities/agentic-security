#!/usr/bin/env node
// Pre-push gate — everything that must be true before commits leave this
// machine, checked in one place, with a named remedy per failure.
//
// WHY THIS EXISTS
// ---------------
// There has long been a release gate (scripts/release-check.mjs, wired into
// `prepublishOnly`) that blocks a broken *publish*. Nothing blocked a broken
// *push*. So broken code reached the remote repeatedly and was discovered
// afterwards by hosted CI — minutes-to-hours later, by which point the bad
// commit is public, other clones have fetched it, and the fix is a second
// commit rather than an amend. This gate moves the same verification to the
// moment before anything is uploaded.
//
// DESIGN RULES, EACH ONE A WAY THIS KIND OF GATE SILENTLY FAILS
// -------------------------------------------------------------
//  1. AN UNRUNNABLE CHECK IS A FAILURE, NOT A SKIP. If a check cannot be
//     executed — npm script removed, spawn failed, binary missing — that is
//     reported as FAIL with the reason. This project has been bitten more
//     than once by "unverifiable" being quietly treated as "fine".
//  2. A HOOK NOBODY INSTALLED IS NOT A GATE. `core.hooksPath` is per-clone
//     local config; a fresh clone has it unset and the hook never runs, in
//     total silence. So activation is part of the existing setup step
//     (scanner/'s npm `prepare`, which runs on `npm install`), AND this
//     script warns loudly whenever it notices it is not active.
//  3. CHEAPEST FIRST. Bundle integrity is an in-process hash compare that
//     fails in milliseconds; it precedes the ~2 minutes of suites so the
//     commonest mistake ("edited src/, forgot to rebuild") costs no wait.
//  4. ONLY GATE WHAT IS BEING PUSHED. Refs come from stdin in git's
//     `<local ref> <local sha> <remote ref> <remote sha>` form. A delete
//     (all-zero local sha) and a ref with no new commits (local == remote)
//     are not gated — there is no new code in either.
//  5. BYPASS IS POSSIBLE BUT LOUD. `git push --no-verify` skips every hook;
//     that cannot be prevented and should not be. Instead the gate prints a
//     one-line verdict on success, so its ABSENCE from a push's output is
//     the visible signal that it was bypassed.
//
// WHAT IS DELIBERATELY EXCLUDED
// -----------------------------
// The network-dependent release checks — dependency currency (registry
// round-trips) and hosted-CI status — are NOT run here. They belong at
// publish time: they are slow, they are about the state of the world rather
// than the state of the code, and an offline developer must still be able to
// push. `npm run release:check` remains the full set.
//
// Usage:
//   node scripts/pre-push-gate.mjs                 # read refs from stdin
//   node scripts/pre-push-gate.mjs --force         # gate regardless of refs
//   node scripts/pre-push-gate.mjs --install-hook  # activate core.hooksPath
// Exit: 0 push may proceed / 1 at least one check failed or was unrunnable.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { runPackageContentsCheck } from './package-contents-check.mjs';
import { signLastScan } from '../scanner/src/posture/integrity.js';
import {
  gatherKeyParts, computeVerdictKey, loadCache, recordVerdict,
  evaluateCachedVerdict, renderProvenance, cachingDisabled,
} from './gate-verdict-cache.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..');
const SCANNER = path.join(REPO, 'scanner');

/** Repo-relative directory holding the committed hooks. */
export const HOOKS_PATH = '.githooks';

/** The escape hatch, named in exactly one place. */
export const BYPASS_HINT =
  'To push anyway (deliberately, accepting the risk): git push --no-verify';

// ---------------------------------------------------------------------------
// Check registry. Order is the execution order and the printed order, and it
// is cheapest-first on purpose. `remedy` is what a human should do.
// ---------------------------------------------------------------------------

export const CHECKS = [
  {
    id: 'worktree-matches-push',
    title: 'Working tree matches the commit being pushed',
    remedy: 'Commit or stash your changes so the suites run against the same ' +
      'tree you are pushing. Every check below tests the WORKING TREE; if it ' +
      'differs from the pushed commit, a green gate describes code you are ' +
      'not uploading.',
  },
  {
    id: 'push-blast-radius',
    title: 'Push does not delete an implausible number of tracked files',
    remedy: 'Inspect `git diff --stat <base>..HEAD`. If the deletion is real ' +
      'and intended, push with --no-verify and say so in the commit message. ' +
      'If it is not, your history has been rewritten by something you did not ' +
      'intend — check `git reflog` before doing anything else.',
  },
  {
    id: 'bundle-integrity',
    title: 'Built bundle matches its SHA-256 sidecar',
    remedy: 'Run `npm run build` in scanner/ and commit both ' +
      'dist/agentic-security.mjs and dist/agentic-security.mjs.sha256. ' +
      '(This is what catches "edited src/, forgot to rebuild".)',
  },
  {
    id: 'package-contents',
    title: 'Package contents match the committed expectation',
    remedy: 'Compare the printed diff against scanner/expected-package-manifest.json. Fix ' +
      '`files` in scanner/package.json or remove the stray path; only update the committed ' +
      'expectation file if the new shape is an intended, reviewed change to what ships.',
  },
  {
    id: 'test-suite',
    title: 'Full test suite passes',
    npmScript: 'test',
    remedy: 'Run `npm test` in scanner/ and fix the failures.',
  },
  {
    id: 'corpus-gate',
    title: 'CVE-replay corpus baseline holds',
    npmScript: 'bench:cve-replay:check',
    remedy: 'Run `npm run bench:cve-replay:check` in scanner/ and resolve the drift ' +
      '(fix the regression, or re-baseline only if the change is intended).',
  },
  {
    id: 'self-scan-gate',
    title: 'Self-scan precision baseline holds',
    npmScript: 'bench:self-scan:check',
    remedy: 'Run `npm run bench:self-scan:check` in scanner/ and fix the code that ' +
      'changed detection behaviour on this repository.',
  },
];

/** Ids in execution order — cheapest first. */
export function orderedCheckIds() {
  return CHECKS.map(c => c.id);
}

function result(errors = [], warnings = []) {
  return { ok: errors.length === 0, errors, warnings };
}

// ---------------------------------------------------------------------------
// Pure decision functions. No I/O — each takes already-gathered facts so the
// tests can exercise it on constructed inputs.
// ---------------------------------------------------------------------------

const ZERO_SHA = /^0+$/;

/**
 * THE GATE TESTS THE WORKING TREE. IT PUSHES REFS. THOSE ARE NOT THE SAME THING.
 *
 * This is not a hypothetical. A run of this gate once passed all four checks in
 * 184s on a branch whose committed tree was missing 421 files and 90,282 lines
 * of scanner/src — because those files still existed on disk as untracked, so
 * every suite imported them and went green while the refs being uploaded did
 * not contain them. The push succeeded and shipped a gutted tree.
 *
 * So: before spending minutes on suites, confirm the thing they are about to
 * measure is the thing being sent.
 *
 * Tracked modifications or deletions FAIL. A dirty tracked tree means the
 * verdict provably describes different content than the commit.
 *
 * Untracked files FAIL past a small threshold. A couple of scratch files are
 * ordinary; a large body of them means the suites may be exercising code that
 * is absent from the pushed commit, which is exactly the shape of the incident
 * above. Below the threshold they are reported as warnings so they stay visible
 * without becoming noise.
 *
 * `.gitignore`d paths never appear in `git status --porcelain` output, so
 * node_modules and generated state do not count toward anything here.
 */
export function evaluateWorktreeMatchesPush(porcelain, opts = {}) {
  const maxUntracked = Number.isInteger(opts.maxUntracked) ? opts.maxUntracked : 20;
  const lines = String(porcelain ?? '').split('\n').map(l => l.replace(/\s+$/, '')).filter(Boolean);

  const untracked = [];
  const trackedChanges = [];
  for (const line of lines) {
    if (line.startsWith('??')) untracked.push(line.slice(3));
    else trackedChanges.push(line);
  }

  const errors = [];
  const warnings = [];

  if (trackedChanges.length > 0) {
    const shown = trackedChanges.slice(0, 10).map(l => `      ${l}`).join('\n');
    errors.push(
      `${trackedChanges.length} tracked file(s) differ from HEAD, so the suites ` +
      'would test content that is not in the commit being pushed:\n' + shown +
      (trackedChanges.length > 10 ? `\n      … and ${trackedChanges.length - 10} more` : ''));
  }

  if (untracked.length > maxUntracked) {
    errors.push(
      `${untracked.length} untracked files are present (threshold ${maxUntracked}). ` +
      'The suites may be importing files that the pushed commit does not contain. ' +
      'This is the signature of a history that was rewritten underneath a working ' +
      'tree — check `git log --oneline -5` and `git reflog` before pushing.');
  } else if (untracked.length > 0) {
    warnings.push(`${untracked.length} untracked file(s) present (under the ${maxUntracked} threshold): ` +
      untracked.slice(0, 5).join(', ') + (untracked.length > 5 ? ', …' : ''));
  }

  return result(errors, warnings);
}

/**
 * A push that deletes most of the source tree is almost never intentional, and
 * it is exactly what a runaway process or a mis-resolved rebase produces. This
 * measures the refs being pushed rather than the working tree, so it is the one
 * check that cannot be fooled by files that exist only on disk.
 *
 * `measured: false` (no base commit to diff against — a genuinely first push)
 * passes with a warning rather than failing. That is a deliberate exception to
 * this file's unrunnable-is-a-failure rule: "there is no previous state" is a
 * real, legitimate state, not a broken check, and failing it would make the
 * first push of any new repository impossible.
 */
export function evaluatePushBlastRadius(input = {}) {
  const { measured = true, filesDeleted = 0, filesInBase = 0, base = null } = input;
  const maxDeleted = Number.isInteger(input.maxDeleted) ? input.maxDeleted : 50;
  const maxFraction = typeof input.maxFraction === 'number' ? input.maxFraction : 0.10;

  if (!measured) {
    return result([], ['no base commit to compare against, so deletion blast radius ' +
      'was NOT measured for this push (a brand-new branch with no shared ancestor).']);
  }

  const errors = [];
  const fraction = filesInBase > 0 ? filesDeleted / filesInBase : 0;
  const where = base ? ` vs ${String(base).slice(0, 12)}` : '';

  if (filesDeleted > maxDeleted) {
    errors.push(`this push deletes ${filesDeleted} tracked file(s)${where}, over the ` +
      `${maxDeleted}-file threshold.`);
  } else if (filesInBase > 0 && fraction > maxFraction) {
    errors.push(`this push deletes ${filesDeleted} of ${filesInBase} tracked file(s)${where} ` +
      `(${(fraction * 100).toFixed(1)}%), over the ${(maxFraction * 100).toFixed(0)}% threshold.`);
  }
  return result(errors);
}

/**
 * Parse the hook's stdin. Git writes one line per ref being pushed:
 *   <local ref> SP <local sha> SP <remote ref> SP <remote sha>
 * A line that does not have exactly those four fields is NOT dropped — it is
 * returned as malformed, because "I did not understand the input" must never
 * present itself as "there was nothing to check".
 */
export function parsePushRefs(stdin) {
  const refs = [];
  const malformed = [];
  for (const raw of String(stdin ?? '').split('\n')) {
    const line = raw.trim();
    if (!line) continue;
    const parts = line.split(/\s+/);
    if (parts.length !== 4) {
      malformed.push(line);
      continue;
    }
    const [localRef, localSha, remoteRef, remoteSha] = parts;
    refs.push({ localRef, localSha, remoteRef, remoteSha });
  }
  return { refs, malformed };
}

/**
 * Decide whether this push carries new code worth gating.
 *
 * Not gated:
 *   - an all-zero LOCAL sha: the ref is being deleted, no code is uploaded;
 *   - local sha == remote sha: the remote already has this exact commit.
 * Gated:
 *   - an all-zero REMOTE sha: a brand-new branch — every commit is new.
 */
export function decidePushScope(refs) {
  const list = Array.isArray(refs) ? refs : [];
  if (list.length === 0) {
    return { shouldRun: false, gated: [], reason: 'nothing to push — git supplied no refs' };
  }
  const gated = [];
  const skipped = [];
  for (const r of list) {
    const local = String(r.localSha || '').toLowerCase();
    const remote = String(r.remoteSha || '').toLowerCase();
    if (ZERO_SHA.test(local)) {
      skipped.push({ ref: r.remoteRef, why: 'ref is being deleted' });
      continue;
    }
    if (local === remote) {
      skipped.push({ ref: r.localRef, why: 'no new commits' });
      continue;
    }
    gated.push(r);
  }
  if (gated.length > 0) {
    return {
      shouldRun: true,
      gated,
      skipped,
      reason: `${gated.length} ref(s) carry new commits`,
    };
  }
  const why = skipped.map(s => s.why);
  const reason = why.includes('ref is being deleted') && !why.includes('no new commits')
    ? 'every ref is a deletion — no code is being uploaded'
    : why.includes('ref is being deleted')
      ? 'every ref is a deletion or has no new commits'
      : 'no new commits to push';
  return { shouldRun: false, gated: [], skipped, reason };
}

/**
 * A gated command is satisfied only by a literal exit code 0. Anything else —
 * including "we never got an exit code" — is a failure. See design rule 1.
 */
export function evaluateCheckOutcome({ label, exitCode }) {
  if (exitCode === 0) return result();
  if (exitCode === null || exitCode === undefined) {
    return result([`\`${label}\` could not be run at all (no exit status: missing script, ` +
      'spawn failure, or it was killed) — an unrunnable gate is not a passing gate.']);
  }
  return result([`\`${label}\` exited ${exitCode}.`]);
}

/** Bundle integrity: the built artifact must hash to what its sidecar claims. */
export function evaluateBundleIntegrity({ bundleSha256, sidecarSha256 }) {
  if (!bundleSha256) {
    return result(['dist/agentic-security.mjs is missing or unreadable — the built ' +
      'bundle cannot be verified.']);
  }
  if (!sidecarSha256) {
    return result(['dist/agentic-security.mjs.sha256 is missing or unreadable — the ' +
      'bundle hash cannot be verified.']);
  }
  if (bundleSha256 !== sidecarSha256) {
    return result([`bundle hash ${bundleSha256.slice(0, 12)}… does not match sidecar ` +
      `${sidecarSha256.slice(0, 12)}… — the bundle was not rebuilt (or not committed) ` +
      'after the last source change.']);
  }
  return result();
}

/**
 * Is the committed hook actually wired up in this clone? `core.hooksPath` is
 * local config: a fresh clone has it unset and every hook here is inert.
 */
export function evaluateHookActivation({ configuredHooksPath }) {
  const configured = configuredHooksPath == null ? null : String(configuredHooksPath).trim();
  if (configured === HOOKS_PATH) return { active: true, warnings: [] };
  const seen = configured ? `it is currently \`${configured}\`` : 'it is currently unset';
  return {
    active: false,
    warnings: [
      `This clone is NOT configured to run the committed hooks: core.hooksPath ` +
      `should be \`${HOOKS_PATH}\`, ${seen}. Nothing is gating your pushes. ` +
      `Fix it with: git config core.hooksPath ${HOOKS_PATH}  ` +
      `(or re-run \`npm install\` in scanner/, which does it for you).`,
    ],
  };
}

/** Render the per-check PASS/FAIL summary. */
export function summarize(entries) {
  const lines = [];
  const failed = [];
  for (const e of entries) {
    const r = e.result || {};
    lines.push(`${r.ok ? 'PASS' : 'FAIL'}  ${e.title}`);
    for (const w of r.warnings || []) lines.push(`      ! ${w}`);
    for (const err of r.errors || []) lines.push(`      x ${err}`);
    if (!r.ok) {
      failed.push(e);
      if (e.remedy) lines.push(`      -> Remedy: ${e.remedy}`);
    }
  }
  if (failed.length > 0) lines.push(`      ${BYPASS_HINT}`);
  return { ok: failed.length === 0, failed, lines };
}

// ---------------------------------------------------------------------------
// I/O layer. Gathers facts and hands them to the functions above; makes no
// pass/fail decision of its own.
// ---------------------------------------------------------------------------

function readBytesOrNull(absPath) {
  try {
    return fs.readFileSync(absPath);
  } catch {
    return null;
  }
}

function readTextOrNull(absPath) {
  try {
    return fs.readFileSync(absPath, 'utf8');
  } catch {
    return null;
  }
}

function run(cmd, args, opts = {}) {
  // Always argv-array, never a shell string.
  const r = spawnSync(cmd, args, { encoding: 'utf8', shell: false, ...opts });
  return { status: r.error ? null : r.status, stdout: r.stdout || '', stderr: r.stderr || '' };
}

function bundleHashes() {
  const bundle = readBytesOrNull(path.join(SCANNER, 'dist', 'agentic-security.mjs'));
  const sidecarRaw = readTextOrNull(path.join(SCANNER, 'dist', 'agentic-security.mjs.sha256'));
  return {
    bundleSha256: bundle ? crypto.createHash('sha256').update(bundle).digest('hex') : null,
    sidecarSha256: sidecarRaw ? (sidecarRaw.trim().split(/\s+/)[0] || null) : null,
  };
}

function configuredHooksPath() {
  const r = run('git', ['config', '--get', 'core.hooksPath'], { cwd: REPO });
  return r.status === 0 ? r.stdout : null;
}

// Git exports GIT_DIR and friends into every hook it runs, and a hook that
// spawns a test suite hands them straight down. Any test that builds a temp
// repository and shells out to `git` then operates on THIS repository instead
// of its own fixture.
//
// This is not theoretical and it is not merely a failed gate. Before this fix,
// two blocked pushes from a linked worktree ran the suite under the hook, and
// the history-mining tests committed their fixtures INTO the real branch: ~30
// commits ("chore: release 1..19", "fix XSS in parser", …) that between them
// deleted 421 files and 90,282 lines from scanner/src. The branch was then
// pushed carrying that gutted tree.
//
// It only bites from a linked worktree, which is why it went unnoticed. In an
// ordinary clone GIT_DIR is the relative string `.git`, which stops resolving
// the moment a test chdirs into its temp directory, so git falls back to normal
// discovery. In a worktree `git rev-parse --git-dir` is an ABSOLUTE path, so it
// resolves from anywhere. Isolated to GIT_DIR by re-running the suite with one
// variable set at a time.
//
// Scrub the whole redirecting family, not GIT_DIR alone: GIT_INDEX_FILE and
// GIT_WORK_TREE misdirect writes the same way, and GIT_OBJECT_DIRECTORY would
// send objects to the wrong store. GIT_AUTHOR_* is deliberately left alone —
// it cannot change which repository a command targets, so this is a denylist of
// redirectors, not a blanket GIT_ prefix match.
const GIT_ENV_TO_SCRUB = [
  'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_OBJECT_DIRECTORY',
  'GIT_ALTERNATE_OBJECT_DIRECTORIES', 'GIT_PREFIX', 'GIT_COMMON_DIR',
];

export function envWithoutGitContext(source = process.env) {
  const env = { ...source };
  for (const k of GIT_ENV_TO_SCRUB) delete env[k];
  return env;
}

function runNpmGate(script) {
  const label = `npm run ${script}`;
  process.stderr.write(`  running ${label} …\n`);
  const r = run('npm', ['run', script], { cwd: SCANNER, stdio: 'inherit', env: envWithoutGitContext() });
  return evaluateCheckOutcome({ label, exitCode: r.status });
}

// --- PRD R1: verdict cache -------------------------------------------------
//
// This gate is the PRODUCER. It runs the slow checks for real and records each
// PASS, so the release gate minutes later does not re-derive the same facts
// about the same commit. It reads the cache too — repeated pushes of an
// unchanged commit are common enough to be worth it — but the value is mostly
// downstream. See scripts/gate-verdict-cache.mjs for why this is safe.
function gateCacheContext(argv) {
  if (cachingDisabled(argv)) return { enabled: false, key: null, records: {} };
  const parts = gatherKeyParts({ repo: REPO });
  const key = computeVerdictKey(parts);
  // A null key means an input could not be read. That is "cannot cache", which
  // resolves to "run everything" — never to a shared or partial key.
  if (!key) return { enabled: false, key: null, records: {}, reason: 'one or more cache-key inputs unreadable' };
  const cache = loadCache(REPO, { signer: cacheSigner });
  return { enabled: true, key, commitSha: parts.commitSha, records: cache.records, rejected: cache.rejected };
}

// Sign with the existing per-install HMAC key rather than inventing a second
// mechanism — posture/integrity.js is the same primitive last-scan.json uses.
// An unsignable cache is an unverifiable cache, which loadCache discards, which
// means the checks simply run. Failing to sign can never produce a skipped check.
function cacheSigner(body) {
  try {
    return signLastScan(body);
  } catch {
    return null;
  }
}

/** `git status --porcelain` for the repo, or null when it cannot be read. */
function porcelainStatus() {
  const r = run('git', ['status', '--porcelain'], { cwd: REPO, env: envWithoutGitContext() });
  return r.status === 0 ? r.stdout : null;
}

/**
 * Resolve the commit to measure a push against: the remote's current tip when
 * it has one, otherwise the fork point from the default branch. Returns
 * `{ measured:false }` when neither exists.
 */
function pushBase(gatedRefs) {
  const ref = (gatedRefs || [])[0];
  if (!ref) return { measured: false };
  const remote = String(ref.remoteSha || '');
  if (remote && !ZERO_SHA.test(remote)) {
    const exists = run('git', ['cat-file', '-e', `${remote}^{commit}`], { cwd: REPO, env: envWithoutGitContext() });
    if (exists.status === 0) return { measured: true, base: remote };
  }
  for (const candidate of ['origin/main', 'origin/master', 'main', 'master']) {
    const mb = run('git', ['merge-base', candidate, ref.localSha], { cwd: REPO, env: envWithoutGitContext() });
    if (mb.status === 0 && mb.stdout.trim()) return { measured: true, base: mb.stdout.trim() };
  }
  return { measured: false };
}

/** Count tracked files deleted between `base` and `head`, and the base's size. */
function deletionStats(base, head) {
  const changed = run('git', ['diff', '--name-status', `${base}..${head}`], { cwd: REPO, env: envWithoutGitContext() });
  if (changed.status !== 0) return null;
  const filesDeleted = changed.stdout.split('\n').filter(l => /^D\s/.test(l)).length;
  const all = run('git', ['ls-tree', '-r', '--name-only', base], { cwd: REPO, env: envWithoutGitContext() });
  const filesInBase = all.status === 0 ? all.stdout.split('\n').filter(Boolean).length : 0;
  return { filesDeleted, filesInBase };
}

function readStdin() {
  try {
    // fd 0; returns '' when stdin is a tty with nothing piped.
    return fs.readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------
// Hook activation (also invoked by scanner/'s npm `prepare`).
// ---------------------------------------------------------------------------

/**
 * Point this clone's git at the committed hooks. ALWAYS exits 0: this runs
 * from `npm install`, and a setup convenience that can break a dependency
 * install is worse than one that prints a warning.
 */
function installHook() {
  const out = process.stderr;
  const inWorkTree = run('git', ['rev-parse', '--is-inside-work-tree'], { cwd: REPO });
  if (inWorkTree.status !== 0) {
    out.write('pre-push gate: not a git work tree — skipping hook activation.\n');
    return 0;
  }
  if (!fs.existsSync(path.join(REPO, HOOKS_PATH, 'pre-push'))) {
    out.write(`pre-push gate: ${HOOKS_PATH}/pre-push not found — skipping hook activation.\n`);
    return 0;
  }
  const set = run('git', ['config', 'core.hooksPath', HOOKS_PATH], { cwd: REPO });
  if (set.status !== 0) {
    out.write('pre-push gate: WARNING — could not set core.hooksPath. Your pushes are ' +
      `NOT gated. Run: git config core.hooksPath ${HOOKS_PATH}\n`);
    return 0;
  }
  const verify = evaluateHookActivation({ configuredHooksPath: configuredHooksPath() });
  if (!verify.active) {
    out.write(`pre-push gate: WARNING — ${verify.warnings[0]}\n`);
    return 0;
  }
  out.write(`pre-push gate: active (core.hooksPath=${HOOKS_PATH}). ` +
    'Pushes now run the gate; `git push --no-verify` bypasses it.\n');
  return 0;
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

export function main(argv = []) {
  const out = process.stderr;
  if (argv.includes('--install-hook')) return installHook();

  const force = argv.includes('--force');
  const started = Date.now();

  // Decide scope before spending any time.
  const { refs, malformed } = parsePushRefs(force ? '' : readStdin());
  if (malformed.length > 0) {
    // Rule 1 applied to the input itself: if we cannot read what is being
    // pushed, we gate everything rather than assume there is nothing to do.
    out.write('pre-push gate: could not parse these ref lines from git, ' +
      'so the full gate is being run:\n');
    for (const m of malformed) out.write(`  ${m}\n`);
  }
  const scope = force
    ? { shouldRun: true, gated: [], reason: '--force: gating regardless of refs' }
    : (malformed.length > 0
      ? { shouldRun: true, gated: [], reason: 'unparseable ref input — gating defensively' }
      : decidePushScope(refs));

  if (!scope.shouldRun) {
    out.write(`pre-push gate: nothing to verify (${scope.reason}). Push proceeds.\n`);
    return 0;
  }

  // Activation warning. This is the case where the script was run by hand;
  // when it runs FROM the hook, hooksPath is by definition set — but a
  // developer who invokes it directly should still be told.
  const activation = evaluateHookActivation({ configuredHooksPath: configuredHooksPath() });

  out.write(`\n${'='.repeat(64)}\n`);
  out.write(`Pre-push gate — ${scope.reason}\n`);
  for (const r of scope.gated || []) {
    out.write(`  ${r.localRef} ${String(r.localSha).slice(0, 12)} -> ${r.remoteRef}\n`);
  }
  for (const s of scope.skipped || []) out.write(`  (skipped ${s.ref}: ${s.why})\n`);
  out.write(`${'='.repeat(64)}\n`);

  const cacheCtx = gateCacheContext(argv);
  if (cacheCtx.rejected) {
    out.write(`  (verdict cache discarded: ${cacheCtx.rejected} — checks will run)\n`);
  }

  const entries = [];
  for (const check of CHECKS) {
    // Only the slow, deterministic-on-inputs checks are cacheable. The two
    // leading guards inspect the CURRENT working tree and refs, which are not
    // in the key, so caching them would be wrong; bundle-integrity and
    // package-contents are already sub-second.
    const cacheable = Boolean(check.npmScript);
    if (cacheable && cacheCtx.enabled) {
      const rec = cacheCtx.records[check.id];
      const verdict = evaluateCachedVerdict({ record: rec, key: cacheCtx.key, checkId: check.id });
      if (verdict.usable) {
        entries.push({ ...check, result: result(), cached: renderProvenance(rec) });
        continue;
      }
    }
    let r;
    if (check.id === 'worktree-matches-push') {
      const porcelain = porcelainStatus();
      // Cannot read status => cannot know what is being tested. Rule 1 applies.
      r = porcelain === null
        ? result(['`git status --porcelain` could not be read, so it is unknown whether ' +
          'the suites would test the same content as the pushed commit — an ' +
          'unverifiable gate is not a passing gate.'])
        : evaluateWorktreeMatchesPush(porcelain);
    } else if (check.id === 'push-blast-radius') {
      const b = pushBase(scope.gated);
      if (!b.measured) {
        r = evaluatePushBlastRadius({ measured: false });
      } else {
        const stats = deletionStats(b.base, 'HEAD');
        r = stats === null
          ? result([`could not diff HEAD against ${String(b.base).slice(0, 12)} to measure ` +
            'how much this push deletes — an unverifiable gate is not a passing gate.'])
          : evaluatePushBlastRadius({ ...stats, base: b.base });
      }
    } else if (check.id === 'bundle-integrity') {
      r = evaluateBundleIntegrity(bundleHashes());
    } else if (check.id === 'package-contents') {
      r = runPackageContentsCheck(REPO);
    } else {
      const startedCheck = Date.now();
      r = runNpmGate(check.npmScript);
      // Record the PASS so the release gate does not re-derive it minutes later.
      // Only a pass: a cached failure would strand a developer who has fixed it.
      if (r.ok && cacheCtx.enabled) {
        recordVerdict(REPO, {
          checkId: check.id, key: cacheCtx.key, commitSha: cacheCtx.commitSha,
          by: 'pre-push', durationMs: Date.now() - startedCheck,
        }, { signer: cacheSigner });
      }
    }
    entries.push({ ...check, result: r });
    if (!r.ok) break; // fastest-fail-first: no point burning minutes after a failure.
  }
  // Any check we never reached is reported, so the summary is never mistaken
  // for "everything passed".
  const ranIds = new Set(entries.map(e => e.id));
  const notRun = CHECKS.filter(c => !ranIds.has(c.id));

  const summary = summarize(entries);
  const elapsed = ((Date.now() - started) / 1000).toFixed(0);

  out.write(`\n${'='.repeat(64)}\n`);
  // A reused verdict states its provenance directly under its own PASS line. A
  // gate that silently skips work is indistinguishable from one that is not
  // running, so this is not optional decoration.
  const cachedById = new Map(entries.filter(e => e.cached).map(e => [e.title, e.cached]));
  for (const line of summary.lines) {
    out.write(`${line}\n`);
    for (const [title, prov] of cachedById) {
      if (line.includes(title)) out.write(`      ↳ ${prov}\n`);
    }
  }
  for (const c of notRun) out.write(`SKIP  ${c.title}  (an earlier check failed)\n`);
  out.write(`${'='.repeat(64)}\n`);

  for (const w of activation.warnings) out.write(`\nWARNING: ${w}\n`);

  if (!summary.ok) {
    out.write(`\npre-push gate FAILED in ${elapsed}s — push aborted. ` +
      `${summary.failed.length} check(s) failed: ` +
      `${summary.failed.map(f => f.id).join(', ')}\n`);
    return 1;
  }
  out.write(`\npre-push gate PASSED in ${elapsed}s — verified: ` +
    `${CHECKS.map(c => c.id).join(', ')}. ` +
    '(Network checks — dependency currency, hosted CI — run at publish time via ' +
    '`npm run release:check`.)\n');
  return 0;
}

// Only run when executed directly, so importing for tests has no side effects.
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exit(main(process.argv.slice(2)));
}
