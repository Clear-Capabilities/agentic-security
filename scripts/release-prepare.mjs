#!/usr/bin/env node
// Release preparation: bring every generated release artifact up to date for the version in scanner/package.json, then run the
// cheap suites that fail late when one of them is stale. It exists because the same failures kept surfacing 16 to 40 minutes
// into the pre-push gate (an inventory naming the old version, a regression report, a pinned count, a docs table), each costing a
// full gate round trip.
//
//   node scripts/release-prepare.mjs                       regenerate artifacts, then run the verification suites
//   node scripts/release-prepare.mjs --version 0.176.0     first replace the current version string in the release files
//   node scripts/release-prepare.mjs --no-tests            regenerate only
//
// It writes files and runs tests. It never commits, pushes or publishes: review `git status`, commit, then `node scripts/ship.mjs`.
// A step that fails stops the run with its name, so a green finish means every regenerated artifact matches and the suites passed.
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SCANNER = join(ROOT, 'scanner');

/** Files that carry the release version string (the same set `release-check` compares for consistency). */
export const VERSION_FILES = [
  '.claude-plugin/marketplace.json', '.claude-plugin/plugin.json', 'CLAUDE.md', 'README.md', 'gemini-extension.json',
  'scanner/package.json', 'scanner/package-lock.json',
];

/** Replace every occurrence of `from` with `to` in the given files. Returns the count per file; a file with none is reported, never skipped silently. */
export function bumpVersion(root, from, to, files = VERSION_FILES) {
  if (!/^\d+\.\d+\.\d+$/.test(from) || !/^\d+\.\d+\.\d+$/.test(to)) throw new Error(`versions must be X.Y.Z (got ${from} -> ${to})`);
  const counts = {};
  for (const f of files) {
    const p = join(root, f);
    const text = readFileSync(p, 'utf8');
    counts[f] = text.split(from).length - 1;
    if (counts[f] > 0) writeFileSync(p, text.split(from).join(to));
  }
  return counts;
}

/** The ordered steps. `cwd` is relative to the repository root. */
export function planSteps({ tests = true } = {}) {
  const npm = (script) => ({ cmd: 'npm', args: ['run', '--silent', script], cwd: 'scanner' });
  const node = (script, ...args) => ({ cmd: process.execPath, args: [script, ...args], cwd: '.' });
  const steps = [
    { name: 'sync the scanner changelog', ...node('scripts/sync-scanner-changelog.mjs') },
    { name: 'build the bundle', ...npm('build') },
    { name: 'render the language docs', ...npm('docs:render-language') },
    { name: 'capture the language examples', ...npm('docs:capture-language') },
    { name: 'regenerate the assurance docs', ...npm('docs:assurance') },
    { name: 'regenerate the scorecard', ...npm('scorecard') },
    { name: 'record inventory test runs', ...node('scripts/engineering-excellence/inventory.mjs', '--verify') },
    { name: 'render the inventory', ...node('scripts/engineering-excellence/inventory.mjs', '--render') },
    { name: 'regenerate the evidence contracts', ...npm('ee:evidence-contracts') },
    { name: 'regenerate the regression report', ...node('scripts/engineering-excellence/regression-report.mjs') },
    { name: 'regenerate the final report', ...node('scripts/engineering-excellence/final-report.mjs') },
  ];
  if (tests) {
    const suite = (name, ...files) => ({ name, cmd: process.execPath, args: ['--test', ...files], cwd: 'scanner' });
    steps.push(
      suite('docs, registry and inventory suites', 'test/language/*.test.js', 'test/documentation/*.test.js', 'test/engineering-excellence/e0-01-inventory.test.js', 'test/engineering-excellence/e8-03-regression-report.test.js', 'test/engineering-excellence/e8-04-docs.test.js', 'test/engineering-excellence/e8-05-handoff.test.js', 'test/engineering-excellence/e8-06-release-decision.test.js'),
      suite('pinned registry counts', 'test/lineage/*.test.js'),
      { name: 'language docs are current', ...npm('docs:check-language') },
      { name: 'gate and ship logic', cmd: process.execPath, args: ['--test', 'test/pre-push-gate.test.js', 'test/release-check.test.js', 'test/ship.test.js'], cwd: 'scanner' },
    );
  }
  return steps;
}

function currentVersion() {
  return JSON.parse(readFileSync(join(SCANNER, 'package.json'), 'utf8')).version;
}

function main(argv) {
  const out = (s) => process.stdout.write(`${s}\n`);
  const vi = argv.indexOf('--version');
  if (vi !== -1) {
    const to = argv[vi + 1];
    const from = currentVersion();
    if (!to) { out('release-prepare: --version needs X.Y.Z'); return 2; }
    if (to === from) { out(`release-prepare: already at ${to}`); } else {
      const counts = bumpVersion(ROOT, from, to);
      const missed = Object.entries(counts).filter(([, n]) => n === 0).map(([f]) => f);
      out(`version ${from} -> ${to}: ${Object.entries(counts).map(([f, n]) => `${f} x${n}`).join(', ')}`);
      if (missed.length) { out(`release-prepare: these files did not contain ${from}, check them by hand: ${missed.join(', ')}`); return 1; }
      if (!existsSync(join(ROOT, 'CHANGELOG.md')) || !readFileSync(join(ROOT, 'CHANGELOG.md'), 'utf8').includes(`## ${to}`)) {
        out(`release-prepare: CHANGELOG.md has no "## ${to}" entry yet. Write it, then run this again without --version.`);
        return 1;
      }
    }
  }
  const started = Date.now();
  for (const step of planSteps({ tests: !argv.includes('--no-tests') })) {
    const t0 = Date.now();
    out(`▶ ${step.name}`);
    const r = spawnSync(step.cmd, step.args, { cwd: join(ROOT, step.cwd), stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
    const secs = ((Date.now() - t0) / 1000).toFixed(0);
    if (r.status !== 0) {
      const tail = `${r.stdout || ''}\n${r.stderr || ''}`.split('\n').filter((l) => /^(✖|not ok|Error|AssertionError)|fail [1-9]|stale|mismatch/i.test(l)).slice(0, 12).join('\n');
      out(`✗ ${step.name} failed after ${secs}s (exit ${r.status})\n${tail}`);
      return 1;
    }
    out(`✓ ${step.name} (${secs}s)`);
  }
  out(`release-prepare: done in ${((Date.now() - started) / 1000).toFixed(0)}s. Review \`git status\`, commit, then run \`node scripts/ship.mjs\`.`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exit(main(process.argv.slice(2)));
