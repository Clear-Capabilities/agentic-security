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
    id: 'bundle-integrity',
    title: 'Built bundle matches its SHA-256 sidecar',
    remedy: 'Run `npm run build` in scanner/ and commit both ' +
      'dist/agentic-security.mjs and dist/agentic-security.mjs.sha256. ' +
      '(This is what catches "edited src/, forgot to rebuild".)',
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

function runNpmGate(script) {
  const label = `npm run ${script}`;
  process.stderr.write(`  running ${label} …\n`);
  const r = run('npm', ['run', script], { cwd: SCANNER, stdio: 'inherit' });
  return evaluateCheckOutcome({ label, exitCode: r.status });
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

  const entries = [];
  for (const check of CHECKS) {
    const r = check.id === 'bundle-integrity'
      ? evaluateBundleIntegrity(bundleHashes())
      : runNpmGate(check.npmScript);
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
  for (const line of summary.lines) out.write(`${line}\n`);
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
