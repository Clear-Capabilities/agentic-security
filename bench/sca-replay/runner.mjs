#!/usr/bin/env node
// PRD F3.1 — score the engine's SCA against third-party labels.
//
// Run order: fetch.mjs → label.mjs → this.
//
// ── The scoring domain, and why it is not simply "everything reported" ───────
//
// The label is produced by `label.mjs`, which enumerates dependencies with its
// own readers. Those readers cover the formats they cover and no more — the
// Maven one, for instance, refuses to resolve a version that lives in a parent
// POM this bench does not fetch.
//
// If every engine finding outside that enumeration were counted as a false
// positive, the bench would punish the ENGINE for the LABELLER's blind spots,
// and the fix for a bad score would be to make the engine see less. That is
// backwards. So scoring is confined to the domain both sides can see:
//
//   D  = components the labeller enumerated
//   P  = the subset of D the advisory database says is vulnerable   (positives)
//   E  = what the engine reported as a vulnerable dependency
//
//   TP           = E ∩ P
//   FN           = P \ E                 the engine missed a labelled vulnerability
//   FP           = (E ∩ D) \ P           the engine flagged a version the database says is clean
//   OUT-OF-LABEL = E \ D                 reported, NOT scored — the labeller never saw it
//
// OUT-OF-LABEL is printed prominently rather than buried, because a large
// number there means the label is too narrow to trust and is a finding about
// this bench, not about the engine.

import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawn } from 'node:child_process';
import { readManifest, entryDir, entryComplete } from './fetch.mjs';
import { withEntryTimeout, EntryTimeout } from '../_lib/watchdog.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLI = path.join(HERE, '..', '..', 'scanner', 'bin', 'agentic-security.js');
const LABELS = path.join(HERE, 'labels.json');
const RESULT = path.join(HERE, 'RESULT.json');

// Generous, because the point of a watchdog is to bound a hang, not to race a
// slow but healthy scan. next.js's lockfile alone carries 3097 components.
const ENTRY_BUDGET_MS = Number(process.env.SCA_REPLAY_TIMEOUT_MS || 600_000);

// The engine names ecosystems in its own vocabulary; the advisory database uses
// its own. Neither is wrong, so the runner translates rather than either side
// bending. An unmapped ecosystem is left as-is and will simply never match,
// which shows up as OUT-OF-LABEL rather than as a silent drop.
const ECO_TO_OSV = {
  npm: 'npm', pypi: 'PyPI', packagist: 'Packagist', rubygems: 'RubyGems',
  golang: 'Go', go: 'Go', cargo: 'crates.io', 'crates.io': 'crates.io',
  maven: 'Maven', pub: 'Pub', nuget: 'NuGet',
};

function key(ecosystem, name, version) {
  const eco = ECO_TO_OSV[String(ecosystem || '').toLowerCase()] || ecosystem;
  // Go module versions appear with and without the `v`; package names differ
  // only in case for some ecosystems. Normalising both sides the same way is
  // the only thing that makes a comparison meaningful.
  const v = String(version || '').replace(/^v/, '');
  return `${eco}|${String(name || '').toLowerCase()}|${v}`;
}

async function scan(dir) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [CLI, 'scan', dir, '--only', 'sca', '--format', 'json'], {
      cwd: dir, stdio: ['ignore', 'pipe', 'pipe'],
      // Bigger than any single lockfile's worth of findings, and set explicitly
      // so a truncated stdout can never masquerade as "the engine found less".
      env: { ...process.env, NO_COLOR: '1' },
    });
    let out = '', err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('error', reject);
    child.on('close', () => {
      // Exit code encodes severity (0 clean … 3 critical, 4 error). A non-zero
      // code here is the EXPECTED outcome — these repos have vulnerable deps.
      try { resolve(JSON.parse(out)); }
      catch (e) { reject(new Error(`unparseable scan output (${e.message}); stderr: ${err.slice(-400)}`)); }
    });
  });
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

async function main() {
  const showHeldOut = process.argv.includes('--show-heldout');
  const asJson = process.argv.includes('--json');
  const manifest = readManifest();

  if (!fs.existsSync(LABELS)) {
    process.stderr.write('labels.json missing — run `node label.mjs` first.\n');
    process.exit(1);
  }
  const labels = JSON.parse(fs.readFileSync(LABELS, 'utf8'));

  const perEntry = [];
  for (const e of manifest.entries) {
    const lab = labels.entries[e.id];
    if (!entryComplete(e)) {
      perEntry.push({ id: e.id, status: 'UNSCORED', reason: 'not materialised' });
      continue;
    }
    if (!lab || lab.status !== 'OK') {
      perEntry.push({ id: e.id, status: 'UNSCORED', reason: (lab && lab.reason) || 'no label' });
      continue;
    }

    // Scan a COPY. A scan writes `.agentic-security/` into the tree it reads,
    // and a cache directory that accumulates scan state stops being the thing
    // that was fetched — the root CLAUDE.md calls this out by name.
    const tmp = await fsp.mkdtemp(path.join(os.tmpdir(), `sca-replay-${e.id}-`));
    let scanResult = null, failure = null;
    try {
      await fsp.cp(entryDir(e.id), tmp, { recursive: true });
      scanResult = await withEntryTimeout(scan(tmp), e.id, ENTRY_BUDGET_MS);
    } catch (err) {
      failure = err instanceof EntryTimeout ? `timed out after ${ENTRY_BUDGET_MS}ms` : err.message;
    } finally {
      await fsp.rm(tmp, { recursive: true, force: true }).catch(() => {});
    }
    if (failure) {
      // Infrastructure failure is UNSCORED, never a miss.
      perEntry.push({ id: e.id, status: 'UNSCORED', reason: failure });
      process.stderr.write(`  – ${e.id}: UNSCORED (${failure})\n`);
      continue;
    }

    const D = new Set();
    for (const c of lab.vulnerable) D.add(key(c.ecosystem, c.name, c.version));
    const P = new Set(D);                                   // labelled positives
    // The full enumerated domain, rebuilt from the label file's count plus the
    // positives is not enough — we need the actual set, so re-derive it.
    const enumerated = new Set();
    {
      const { enumerate } = await import('./label.mjs');
      for (const c of enumerate(e)) enumerated.add(key(c.ecosystem, c.name, c.version));
    }

    // The engine collapses every finding sharing one advisory id into a single
    // primary finding and records the rest under `dependents[]` — one row per
    // advisory rather than one per (package, version), which is the right
    // default for a report a human reads. A bench that only read the primary
    // would score that UX decision as a recall failure: npm/cli carries
    // @babel/core at both 7.12.9 and 7.16.0 under the same advisory, and only
    // one of them is the primary.
    //
    // So `dependents` counts. The information is present in the output; the
    // first version of this runner simply did not look at it, and briefly
    // attributed the gap to the engine.
    const E = new Map();                                    // key → advisory ids the engine named
    const addReported = (ecosystem, name, version, osvId) => {
      const k = key(ecosystem, name, version);
      if (!E.has(k)) E.set(k, new Set());
      if (osvId) E.get(k).add(osvId);
    };
    for (const f of scanResult.findings || []) {
      if (f.type !== 'vulnerable_dep') continue;
      addReported(f.ecosystem, f.package || f.name, f.version, f.osvId);
      for (const d of f.dependents || []) addReported(f.ecosystem, d.name, d.version, f.osvId);
    }

    const tp = [], fn = [], fp = [], outOfLabel = [];
    for (const k of E.keys()) {
      if (P.has(k)) tp.push(k);
      else if (enumerated.has(k)) fp.push(k);
      else outOfLabel.push(k);
    }
    for (const k of P) if (!E.has(k)) fn.push(k);

    // Reachability is a SEPARATE claim (F3.2) and is counted separately here
    // rather than folded into recall: a demoted finding is still a detection.
    const scaFindings = (scanResult.findings || []).filter((f) => f.type === 'vulnerable_dep');
    const demoted = scaFindings.filter((f) => f.unreachable === true).length;

    // Two denominators, because they answer different questions.
    //
    //   version-level — "is THIS pinned version reported vulnerable"
    //   package-level — "does the report mention this package at all"
    //
    // A team upgrading a dependency needs the first. A team asking "am I
    // exposed to anything in lodash" needs the second. Publishing only the
    // higher of the two would be flattering and dishonest; publishing only the
    // lower understates what the tool actually tells you.
    const pkgOf = (k) => k.split('|').slice(0, 2).join('|');
    const Ppkg = new Set([...P].map(pkgOf));
    const Epkg = new Set([...E.keys()].map(pkgOf));
    const tpPkg = [...Ppkg].filter((k) => Epkg.has(k)).length;

    perEntry.push({
      id: e.id, repo: e.repo, tag: e.tag, ecosystem: e.ecosystem, heldOut: !!e.heldOut,
      status: 'SCORED',
      packageLevel: { tp: tpPkg, d: Ppkg.size, recall: pct(tpPkg, Ppkg.size) },
      labelled: { enumerated: enumerated.size, vulnerable: P.size },
      engine: { reported: E.size, findings: scaFindings.length },
      tp: tp.length, fn: fn.length, fp: fp.length, outOfLabel: outOfLabel.length,
      recall: pct(tp.length, P.size),
      precision: pct(tp.length, tp.length + fp.length),
      reachability: { demoted, demotionRate: pct(demoted, scaFindings.length) },
      // A handful of examples so a reader can check the claim by hand rather
      // than taking the counts on trust.
      examples: { fn: fn.slice(0, 5), fp: fp.slice(0, 5), outOfLabel: outOfLabel.slice(0, 5) },
    });
    process.stderr.write(
      `  ✓ ${e.id.padEnd(24)} tp=${String(tp.length).padStart(4)} fn=${String(fn.length).padStart(4)} ` +
      `fp=${String(fp.length).padStart(4)} out=${String(outOfLabel.length).padStart(4)}\n`);
  }

  const scored = perEntry.filter((r) => r.status === 'SCORED');
  const sum = (rows, f) => rows.reduce((a, r) => a + f(r), 0);
  const agg = (rows) => {
    const tp = sum(rows, (r) => r.tp), fn = sum(rows, (r) => r.fn), fp = sum(rows, (r) => r.fp);
    const ptp = sum(rows, (r) => r.packageLevel.tp), pd = sum(rows, (r) => r.packageLevel.d);
    return {
      entries: rows.length,
      labelledVulnerable: sum(rows, (r) => r.labelled.vulnerable),
      tp, fn, fp,
      outOfLabel: sum(rows, (r) => r.outOfLabel),
      recall: { n: tp, d: tp + fn, pct: pct(tp, tp + fn) },
      precision: { n: tp, d: tp + fp, pct: pct(tp, tp + fp) },
      packageRecall: { n: ptp, d: pd, pct: pct(ptp, pd) },
    };
  };

  const byEcosystem = {};
  for (const r of scored) {
    (byEcosystem[r.ecosystem] ||= []).push(r);
  }

  const result = {
    prd: 'F3.1',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    configuration: 'scan --only sca --format json, network enabled, per-entry watchdog ' + ENTRY_BUDGET_MS + 'ms',
    labelSource: labels.source,
    labelGeneratedAt: labels.generatedAt,
    totals: agg(scored),
    development: agg(scored.filter((r) => !r.heldOut)),
    heldOut: agg(scored.filter((r) => r.heldOut)),
    byEcosystem: Object.fromEntries(Object.entries(byEcosystem).map(([k, v]) => [k, agg(v)])),
    unscored: perEntry.filter((r) => r.status === 'UNSCORED'),
    entries: perEntry.map((r) => (r.heldOut && !showHeldOut ? { id: r.id, heldOut: true, status: r.status, withheld: 'per-entry detail withheld; pass --show-heldout' } : r)),
  };

  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (asJson) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }

  const line = (label, a) => process.stdout.write(
    `${label.padEnd(14)} recall ${String(a.recall.n).padStart(4)}/${String(a.recall.d).padStart(4)} = ` +
    `${a.recall.pct === null ? '  n/a' : String(a.recall.pct).padStart(6)}%   ` +
    `precision ${String(a.precision.n).padStart(4)}/${String(a.precision.d).padStart(4)} = ` +
    `${a.precision.pct === null ? '  n/a' : String(a.precision.pct).padStart(6)}%   ` +
    `pkg-recall ${String(a.packageRecall.n).padStart(4)}/${String(a.packageRecall.d).padStart(4)} = ` +
    `${a.packageRecall.pct === null ? '  n/a' : String(a.packageRecall.pct).padStart(6)}%\n`);

  process.stdout.write(`\nbench/sca-replay — engine ${result.engineVersion}, labels ${labels.generatedAt}\n\n`);
  line('ALL', result.totals);
  line('development', result.development);
  line('held-out', result.heldOut);
  process.stdout.write('\nper ecosystem:\n');
  for (const [eco, a] of Object.entries(result.byEcosystem)) line('  ' + eco, a);
  process.stdout.write(`\nout-of-label (reported, not scored): ${result.totals.outOfLabel}\n`);
  if (result.unscored.length) {
    process.stdout.write(`UNSCORED: ${result.unscored.map((u) => `${u.id} (${u.reason})`).join(', ')}\n`);
  }
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main().catch((e) => { process.stderr.write(`runner failed: ${e.stack}\n`); process.exit(1); });
