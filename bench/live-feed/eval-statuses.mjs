// Re-evaluates one extracted project against the operator snapshot a live scan just wrote, and prints the per-package and per-advisory
// statuses the scan itself does not expose (the scan result carries findings only). Same code path the scan uses:
// analyzeLanguageSupplyChain -> analyzeHaskellSupply -> configuredAdvisoryDb (reads $XDG_CONFIG_HOME/agentic-security).
// Usage: node eval-statuses.mjs <scanner-root> <project-dir>   (XDG_CONFIG_HOME, AGENTIC_SECURITY_* come from the environment)
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

// This reads a tree and evaluates it; nothing here should write scan state into the project being measured.
await disableStateWrites();

const [scannerRoot, dir] = process.argv.slice(2);
const MANIFEST = /(?:^|\/)(?:[^/]+\.cabal|cabal\.project(?:\.[a-z]+)?|package\.yaml|stack\.yaml|stack\.yaml\.lock)$/;
const PLAN = /(?:^|\/)dist-newstyle\/cache\/plan\.json$/;
// The file set is the scan's own: runScan's readTree applies the same ignore rules (test directories, vendor, build output, size caps) that the
// scan applies, so the components evaluated here are the components the scan evaluated, not every .cabal file that happens to exist on disk.
const { readTree } = await import(pathToFileURL(join(scannerRoot, 'src/runScan.js')).href);
const tree = await readTree(dir, {});
const files = {};
for (const [rel, text] of Object.entries({ ...tree.fileContents, ...tree.depFileContents })) if ((MANIFEST.test(rel) || PLAN.test(rel)) && typeof text === 'string') files[rel] = text;

const { analyzeLanguageSupplyChain } = await import(pathToFileURL(join(scannerRoot, 'src/language/engine-pass.js')).href);
const { snapshotPath } = await import(pathToFileURL(join(scannerRoot, 'src/language/haskell-advisory-feed.js')).href);
const r = analyzeLanguageSupplyChain(files, { scanRoot: dir });
const hs = { statuses: [], components: [], gaps: [], supplyChain: [], feed: null, ...(r.haskell || {}) };

const comps = hs.components || [];
const byStatus = {};
for (const s of hs.statuses) byStatus[s.status] = (byStatus[s.status] || 0) + 1;
const perPkg = new Map();
for (const s of hs.statuses) { if (!perPkg.has(s.name)) perPkg.set(s.name, new Set()); perPkg.get(s.name).add(s.status); }
const pkgBucket = { 'no-advisories': 0, 'with-advisories': 0, 'feed-incomplete': 0, 'feed-stale': 0, 'feed-unavailable': 0 };
for (const [, set] of perPkg) {
  if (set.has('feed-incomplete')) pkgBucket['feed-incomplete']++;
  else if (set.has('feed-stale')) pkgBucket['feed-stale']++;
  else if (set.has('feed-unavailable')) pkgBucket['feed-unavailable']++;
  else if (set.size === 1 && set.has('no-advisories')) pkgBucket['no-advisories']++;
  else pkgBucket['with-advisories']++;
}
let snapshot = null;
try { const s = JSON.parse(readFileSync(snapshotPath(process.env), 'utf8')); snapshot = { generatedAt: s.generatedAt, records: s.records.length, covered: Object.keys(s.covered || {}).length, coveredNames: Object.keys(s.covered || {}) }; } catch { /* none */ }
const names = [...new Set(comps.map((c) => c.name))];
const coveredSet = new Set(snapshot ? snapshot.coveredNames : []);
const out = {
  manifests: Object.keys(files).filter((p) => MANIFEST.test(p)).length,
  plan: Object.keys(files).filter((p) => PLAN.test(p)),
  components: comps.length,
  uniquePackages: names.length,
  resolution: comps.reduce((m, c) => { const k = c.resolution || (c.transitive ? 'plan-transitive' : 'unknown'); m[k] = (m[k] || 0) + 1; return m; }, {}),
  resolvedVersions: comps.filter((c) => c.version).length,
  declaredOnly: comps.filter((c) => !c.version).length,
  statusRows: byStatus,
  packages: pkgBucket,
  uncoveredNames: names.filter((n) => !coveredSet.has(n)),
  feed: hs.feed,
  gaps: hs.gaps.map((g) => ({ kind: g.kind, detail: String(g.detail).slice(0, 400) })),
  resolvedSummary: r.resolved || null,
  snapshot: snapshot ? { generatedAt: snapshot.generatedAt, records: snapshot.records, covered: snapshot.covered } : null,
  findings: hs.supplyChain.filter((f) => f.type === 'vulnerable_dep').map((f) => ({
    name: f.name, version: f.version, declaredRange: f.declaredRange, osvId: f.osvId, ids: f.ids, matchStatus: f.matchStatus, matchReason: f.matchReason,
    resolution: f.resolution, fixedIn: f.fixedIn, unfixed: f.unfixed, ghcComponent: f.ghcComponent, summary: f.summary, file: f.file, line: f.line,
  })),
  rows: hs.statuses.filter((s) => s.advisory).map((s) => ({ name: s.name, version: s.version, declaredRange: s.declaredRange, advisory: s.advisory, status: s.status, reason: s.reason || null })),
};
process.stdout.write(JSON.stringify(out));
