#!/usr/bin/env node
// Measure the scorecard on a CLEAN tree and commit it on its own (GA-01 evidence identity).
//
//   node scripts/scorecard-finalize.mjs [--no-commit] [--root <dir>]
//   npm run scorecard:finalize
//
// WHY THIS EXISTS. `release-prepare` used to regenerate the scorecard in the middle of the version bump, while every version file was
// uncommitted, so every release recorded `worktreeClean: false` by construction and the commit it named did not identify what was
// measured. The order is now: bump, commit the bump, then this script, which refuses a dirty tree, measures, re-renders the two pages
// derived from the scorecard (the GA programme status), and commits exactly those four files. The commit the scorecard names is then
// the tree that was measured, and the only difference between it and the commit that ships is the derived pages.
//
// `scorecardIdentity` is the check the release gate (`scorecard-identity` in release-check.mjs) applies to the committed result.
//
// Exit codes: 0 committed (or measured, with --no-commit), 1 the measurement is not clean or does not describe this version,
// 2 the tree was dirty before measuring or a step could not run.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** The files the scorecard command writes. A scorecard can never be clean with respect to its own output. */
export const SCORECARD_OUTPUTS = Object.freeze(['docs/SCORECARD.md', 'docs/scorecard.json']);
/** Those plus the GA programme pages rendered from them: the only files allowed to differ between the measured commit and the release. */
export const SCORECARD_DERIVED = Object.freeze([...SCORECARD_OUTPUTS, 'docs/ga-program/STATUS.md', 'docs/ga-program/status.json']);

/**
 * Does the committed scorecard identify the tree being released? Pure.
 * `changedSince` is `git diff --name-only <measured commit> HEAD`, or null when the measured commit is not in this history.
 */
export function scorecardIdentity({ scorecard, version, changedSince }) {
  const reasons = [];
  if (!scorecard) return { ok: false, reasons: ['docs/scorecard.json is missing or unreadable'] };
  const prov = scorecard.provenance || {}; const meas = scorecard.measurement || {};
  if (prov.worktreeClean !== true || meas.cleanMeasurement !== true) reasons.push('the scorecard was measured on a dirty worktree');
  const measured = meas.engineVersion || prov.engineVersion;
  if (measured !== version) reasons.push(`the scorecard describes engine ${measured}, the release is ${version}`);
  if (!/^[0-9a-f]{40}$/.test(String(prov.commit || ''))) reasons.push('the scorecard records no source commit');
  else if (changedSince === null) reasons.push(`the measured commit ${String(prov.commit).slice(0, 12)} is not in this history`);
  else {
    const extra = (changedSince || []).filter((f) => !SCORECARD_DERIVED.includes(f));
    if (extra.length) reasons.push(`changed since the measured commit ${String(prov.commit).slice(0, 12)}: ${extra.slice(0, 10).join(', ')}${extra.length > 10 ? ` and ${extra.length - 10} more` : ''}`);
  }
  return { ok: reasons.length === 0, reasons };
}

/** `git diff --name-only <commit> HEAD` in `repo`, or null when the commit is unknown here. */
export function changedSinceCommit(repo, commit) {
  if (!/^[0-9a-f]{40}$/.test(String(commit || ''))) return null;
  const known = spawnSync('git', ['cat-file', '-e', `${commit}^{commit}`], { cwd: repo });
  if (known.status !== 0) return null;
  const r = spawnSync('git', ['diff', '--name-only', commit, 'HEAD'], { cwd: repo, encoding: 'utf8' });
  return r.status === 0 ? r.stdout.split('\n').filter(Boolean) : null;
}

function dirtyPaths(repo) {
  const r = spawnSync('git', ['status', '--porcelain', '--', '.', ...SCORECARD_OUTPUTS.map((f) => `:(exclude)${f}`)], { cwd: repo, encoding: 'utf8' });
  if (r.status !== 0) return null;
  return r.stdout.split('\n').filter(Boolean).map((l) => l.slice(3));
}

function main(argv) {
  const ri = argv.indexOf('--root');
  const repo = path.resolve(ri >= 0 ? argv[ri + 1] : path.join(HERE, '..'));
  const out = (s) => process.stdout.write(`${s}\n`);
  const dirty = dirtyPaths(repo);
  if (dirty === null) { out('scorecard-finalize: not a git repository'); return 2; }
  if (dirty.length) {
    out(`scorecard-finalize: refusing to measure a dirty tree (commit or remove these first, the scorecard would not identify what it measured):\n${dirty.slice(0, 20).map((p) => `  ${p}`).join('\n')}`);
    return 2;
  }
  const step = (label, cmd, args, cwd) => {
    out(`▶ ${label}`);
    const r = spawnSync(cmd, args, { cwd, stdio: 'inherit' });
    if (r.status !== 0) { out(`scorecard-finalize: ${label} failed (exit ${r.status})`); return false; }
    return true;
  };
  if (!step('measure the scorecard', 'npm', ['run', '--silent', 'scorecard'], path.join(repo, 'scanner'))) return 2;
  if (!step('render the GA programme status', process.execPath, ['scripts/ga-program/ledger.mjs', '--render'], repo)) return 2;
  const version = JSON.parse(fs.readFileSync(path.join(repo, 'scanner', 'package.json'), 'utf8')).version;
  const scorecard = JSON.parse(fs.readFileSync(path.join(repo, 'docs', 'scorecard.json'), 'utf8'));
  const id = scorecardIdentity({ scorecard, version, changedSince: changedSinceCommit(repo, scorecard.provenance?.commit) });
  if (!id.ok) { out(`scorecard-finalize: the measurement does not identify this release:\n${id.reasons.map((r) => `  ${r}`).join('\n')}`); return 1; }
  const head = String(scorecard.provenance.commit).slice(0, 12);
  if (argv.includes('--no-commit')) { out(`scorecard measured cleanly at ${head}; not committed (--no-commit)`); return 0; }
  const add = spawnSync('git', ['add', '--', ...SCORECARD_DERIVED], { cwd: repo });
  if (add.status !== 0) { out('scorecard-finalize: git add failed'); return 2; }
  const staged = spawnSync('git', ['diff', '--cached', '--quiet'], { cwd: repo });
  if (staged.status === 0) { out(`scorecard already current for ${version} at ${head}; nothing to commit`); return 0; }
  const c = spawnSync('git', ['commit', '-q', '-m', `docs: scorecard for ${version}, clean measurement at ${head}`], { cwd: repo, stdio: 'inherit' });
  if (c.status !== 0) { out('scorecard-finalize: git commit failed'); return 2; }
  out(`scorecard for ${version} committed; it names ${head}, the tree it measured`);
  return 0;
}

if (import.meta.url === `file://${process.argv[1]}`) process.exit(main(process.argv.slice(2)));
