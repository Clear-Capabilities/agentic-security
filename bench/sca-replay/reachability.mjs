#!/usr/bin/env node
// PRD F3.2 — reachability scored as its OWN claim, with its own error costs.
//
// "A vulnerable version is present" and "the vulnerable code is reachable" are
// different assertions, and their errors are not symmetric:
//
//   a false UNREACHABLE is a MISSED EXPLOIT — the finding is demoted to info
//     and a real vulnerability stops being shown;
//   a false REACHABLE is NOISE — someone reads a finding that did not matter.
//
// `summarizeReachability` already reports the demotion RATE. A rate is not an
// accuracy claim, and the first run of `bench/sca-replay` reported a demotion
// rate of 0 for every single entry — not because the analysis is cautious, but
// because that bench fetches lockfiles and the analysis had no source to walk.
// A number that is structurally zero looks like a measurement and is not one.
//
// ── The oracle, and exactly what it can adjudicate ───────────────────────────
//
// Ground truth here is IMPORT-LEVEL and computed by this file, from the
// project's own source, with a reader that shares no code with the engine:
//
//   imported     — some source file in the project imports/requires the package
//   not imported — no file does
//
// That is a NECESSARY condition for the vulnerable function to be reachable,
// not a sufficient one. So it adjudicates two of the three cases and says so:
//
//   engine says UNREACHABLE + package IS imported   → wrong, and expensively so
//   engine says REACHABLE   + package NOT imported  → noise
//   engine says REACHABLE   + package IS imported   → NOT ADJUDICATED. The
//     vulnerable function specifically may still be unused, and this oracle
//     cannot see that. Counted and reported separately rather than folded in
//     as a win.
//
// Reporting the unadjudicated bucket by name is the point. An oracle that
// quietly scored it as correct would report near-perfect accuracy for an
// analysis that had simply never demoted anything.

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { readManifest, entryDir, entryComplete } from './fetch.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', '..', 'scanner', 'bin', 'agentic-security.js');
const LABELS = path.join(HERE, 'labels.json');
const RESULT = path.join(HERE, 'RESULT-reachability.json');

// ─── The independent import reader ──────────────────────────────────────────

/** npm: require('x'), import … from 'x', import('x'). Scoped names kept whole. */
function npmImports(text) {
  const out = new Set();
  const add = (spec) => {
    if (!spec || spec.startsWith('.') || spec.startsWith('/')) return;   // relative
    const parts = spec.split('/');
    out.add(spec.startsWith('@') && parts.length >= 2 ? `${parts[0]}/${parts[1]}` : parts[0]);
  };
  for (const m of text.matchAll(/\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1]);
  for (const m of text.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) add(m[1]);
  for (const m of text.matchAll(/\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g)) add(m[1]);
  for (const m of text.matchAll(/^\s*import\s+['"]([^'"]+)['"]/gm)) add(m[1]);
  return out;
}

/** PyPI: import x[.y], from x[.y] import … — top-level module only. */
function pypiImports(text) {
  const out = new Set();
  for (const m of text.matchAll(/^\s*import\s+([A-Za-z_][\w.]*)/gm)) out.add(m[1].split('.')[0]);
  for (const m of text.matchAll(/^\s*from\s+([A-Za-z_][\w.]*)\s+import\b/gm)) out.add(m[1].split('.')[0]);
  return out;
}

// A distribution name is not always its import name. Only the cases this corpus
// actually contains are listed — inventing a general mapping table would be
// guessing, and a wrong entry here silently changes the verdict.
const PYPI_IMPORT_ALIASES = {
  'pyyaml': ['yaml'], 'beautifulsoup4': ['bs4'], 'pillow': ['PIL'],
  'python-dateutil': ['dateutil'], 'msgpack-python': ['msgpack'],
  'attrs': ['attr', 'attrs'], 'setuptools': ['setuptools', 'pkg_resources'],
  'typing-extensions': ['typing_extensions'], 'importlib-metadata': ['importlib_metadata'],
  'backports-functools-lru-cache': ['backports'], 'cachecontrol': ['cachecontrol'],
};

function importNamesFor(ecosystem, pkg) {
  const lower = pkg.toLowerCase();
  if (ecosystem === 'PyPI') {
    const alias = PYPI_IMPORT_ALIASES[lower];
    // PyPI normalises `-` and `_` interchangeably in distribution names.
    return new Set([...(alias || []), lower, lower.replace(/-/g, '_')]);
  }
  return new Set([pkg, lower]);
}

function collectImports(srcRoot, ecosystem) {
  const found = new Set();
  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (ecosystem === 'npm' && !/\.(?:js|jsx|mjs|cjs|ts|tsx)$/i.test(e.name)) continue;
      if (ecosystem === 'PyPI' && !/\.py$/i.test(e.name)) continue;
      let body;
      try { body = fs.readFileSync(p, 'utf8'); } catch { continue; }
      const names = ecosystem === 'npm' ? npmImports(body) : pypiImports(body);
      for (const n of names) found.add(n.toLowerCase());
    }
  };
  walk(srcRoot);
  return found;
}

// ─── The engine's claim ─────────────────────────────────────────────────────

async function scan(dir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'scan', dir, '--format', 'json'], {
      cwd: dir, stdio: ['ignore', 'pipe', 'pipe'], env: { ...process.env, NO_COLOR: '1' },
    });
    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', () => {
      try { resolve(JSON.parse(out)); }
      catch (e) { reject(new Error(`unparseable scan output (${e.message}); stderr: ${err.slice(-300)}`)); }
    });
  });
}

/**
 * The engine's reachability verdict for one SCA finding.
 *
 * `unknown` is a first-class answer and is never folded into `reachable`: an
 * analysis that declines to decide has made no claim, and scoring a declined
 * claim as correct is how a reachability feature reports 100% while doing
 * nothing.
 */
function verdictOf(f) {
  if (f.unreachable === true) return 'unreachable';
  if (f.functionReachable === 'unreachable') return 'unreachable';
  if (f.functionReachable === 'reachable' || f.reachable === true) return 'reachable';
  if (f.functionReachable === 'unknown' || f.functionReachable == null) return 'unknown';
  return 'unknown';
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

// Deterministic held-out split on the entry id, so nobody chose which entries
// are hard and the split survives the corpus growing.
function isHeldOut(id) {
  let h = 0;
  for (const ch of String(id)) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
  return (h % 5) === 0;
}

async function main() {
  const manifest = readManifest();
  const labels = JSON.parse(fs.readFileSync(LABELS, 'utf8'));
  const rows = [];
  const unscored = [];

  for (const e of manifest.entries) {
    if (!e.withSource) continue;
    const lab = labels.entries[e.id];
    if (!entryComplete(e) || !lab || lab.status !== 'OK') {
      unscored.push({ id: e.id, reason: 'not materialised or unlabelled' });
      continue;
    }
    const srcRoot = path.join(entryDir(e.id), 'src-tree');
    if (!fs.existsSync(srcRoot)) {
      // Never a miss. An entry whose source could not be fetched is excluded by
      // name, exactly as bench/independent excludes an unfetchable entry.
      unscored.push({ id: e.id, reason: 'source not fetched — reachability cannot be scored' });
      continue;
    }

    const imported = collectImports(srcRoot, e.ecosystem);

    // Scan the lockfiles AND the source together — that is the shape a real
    // project has, and the only one in which reachability analysis can run.
    const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), `sca-reach-${e.id}-`));
    let scanResult = null;
    try {
      for (const f of e.files) {
        const src = path.join(entryDir(e.id), f);
        const dst = path.join(tmp, f);
        await fsp.mkdir(path.dirname(dst), { recursive: true });
        await fsp.copyFile(src, dst);
      }
      await fsp.cp(srcRoot, tmp, { recursive: true });
      scanResult = await scan(tmp);
    } catch (err) {
      unscored.push({ id: e.id, reason: err.message });
      await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
      continue;
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
    }

    const vulnerable = new Set(lab.vulnerable.map((c) => `${c.name}`.toLowerCase()));
    const seen = new Set();
    for (const f of (scanResult.findings || [])) {
      if (f.type !== 'vulnerable_dep') continue;
      const pkg = String(f.package || f.name || '');
      if (!pkg) continue;
      const key = `${e.id}|${pkg.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      // Only packages the third-party label says are vulnerable. Scoring
      // reachability on a package that is not vulnerable measures nothing.
      if (!vulnerable.has(pkg.toLowerCase())) continue;

      const names = importNamesFor(e.ecosystem, pkg);
      const isImported = [...names].some((n) => imported.has(n));
      const verdict = verdictOf(f);

      let outcome;
      if (verdict === 'unreachable' && isImported) outcome = 'FALSE-UNREACHABLE';
      else if (verdict === 'reachable' && !isImported) outcome = 'FALSE-REACHABLE';
      else if (verdict === 'unreachable' && !isImported) outcome = 'CORRECT-UNREACHABLE';
      else if (verdict === 'reachable' && isImported) outcome = 'UNADJUDICATED-REACHABLE';
      else outcome = 'UNKNOWN-NO-CLAIM';

      rows.push({
        id: e.id, ecosystem: e.ecosystem, package: pkg,
        heldOut: isHeldOut(e.id), verdict, imported: isImported, outcome,
      });
    }
    process.stderr.write(`  ✓ ${e.id.padEnd(22)} ${imported.size} distinct imports, ` +
      `${rows.filter((r) => r.id === e.id).length} vulnerable deps adjudicated\n`);
  }

  const tally = (rs) => {
    const c = (o) => rs.filter((r) => r.outcome === o).length;
    const falseUnreachable = c('FALSE-UNREACHABLE');
    const falseReachable = c('FALSE-REACHABLE');
    const correctUnreachable = c('CORRECT-UNREACHABLE');
    const adjudicated = falseUnreachable + falseReachable + correctUnreachable;
    return {
      total: rs.length,
      // The number that matters most: a demotion that hid a real, imported
      // dependency.
      falseUnreachable: { n: falseUnreachable, d: adjudicated, pct: pct(falseUnreachable, adjudicated) },
      falseReachable: { n: falseReachable, d: adjudicated, pct: pct(falseReachable, adjudicated) },
      correctUnreachable: { n: correctUnreachable, d: adjudicated, pct: pct(correctUnreachable, adjudicated) },
      unadjudicatedReachable: c('UNADJUDICATED-REACHABLE'),
      noClaim: c('UNKNOWN-NO-CLAIM'),
      adjudicated,
    };
  };

  const result = {
    prd: 'F3.2',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    oracle: 'IMPORT-LEVEL, computed here from the project source by a reader sharing no code with the engine. ' +
      'A necessary condition for function reachability, not a sufficient one — see UNADJUDICATED-REACHABLE.',
    errorCosts: {
      falseUnreachable: 'a MISSED EXPLOIT — the finding is demoted and a real vulnerability stops being shown',
      falseReachable: 'noise — someone reads a finding that did not matter',
    },
    all: tally(rows),
    development: tally(rows.filter((r) => !r.heldOut)),
    heldOut: tally(rows.filter((r) => r.heldOut)),
    unscored, rows,
  };
  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (process.argv.includes('--json')) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }
  const line = (label, t) => process.stdout.write(
    `${label.padEnd(14)} adjudicated ${String(t.adjudicated).padStart(3)}  ` +
    `false-unreachable ${String(t.falseUnreachable.n).padStart(3)} (${t.falseUnreachable.pct ?? 'n/a'}%)  ` +
    `false-reachable ${String(t.falseReachable.n).padStart(3)} (${t.falseReachable.pct ?? 'n/a'}%)  ` +
    `correct-unreachable ${String(t.correctUnreachable.n).padStart(3)}\n`);

  process.stdout.write(`\nbench/sca-replay reachability — engine ${result.engineVersion}\n\n`);
  line('ALL', result.all);
  line('development', result.development);
  line('held-out', result.heldOut);
  process.stdout.write(`\nnot adjudicated by an import-level oracle: ${result.all.unadjudicatedReachable}` +
    `  (reported reachable AND imported — the vulnerable FUNCTION may still be unused)\n`);
  process.stdout.write(`no claim made by the engine (unknown): ${result.all.noClaim}\n`);
  if (unscored.length) process.stdout.write(`UNSCORED: ${unscored.map((u) => `${u.id} (${u.reason})`).join(', ')}\n`);
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main().catch((e) => { process.stderr.write(`reachability runner failed: ${e.stack}\n`); process.exit(1); });
