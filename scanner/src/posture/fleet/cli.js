// `agentic-security fleet init|scan|status|resume|query`.
//
// Reuses the existing posture/fleet.js (runFleet: bounded concurrency, resumable checkpoint, per-repo isolation,
// honest rollup) for the scanning half — this module adds only the manifest-driven entry point and the
// cross-repository dependency graph (fleet-graph.js) that runFleet has no notion of.
import fs from 'node:fs';
import path from 'node:path';
import { loadFleetManifest, starterManifestYaml } from './fleet-manifest.js';
import { buildFleetDependencyGraph, blastRadius } from './fleet-graph.js';
import { runFleet, rollupFleet, renderFleetSummary } from '../fleet.js';
import { statePath, ensureStateDir, safeWriteState } from '../state-dir.js';

const GRAPH_FILE = 'fleet-graph.json';
const STATE_FILE = 'fleet-state.json';

function graphPath(root) { return statePath(root, GRAPH_FILE); }
function statePathFor(root) { return statePath(root, STATE_FILE); }

export async function cmdFleet(args, root) {
  const sub = args._[1];
  if (sub === 'init') return cmdInit(args, root);
  if (sub === 'scan') return cmdScan(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'resume') return cmdScan(args, root, { resumeOnly: true });
  if (sub === 'query') return cmdQuery(args, root);
  console.error('usage: fleet init | scan <manifest.yaml> | status <manifest.yaml> | resume <manifest.yaml> | query --depends-on <repo-id> [<manifest.yaml>]');
  return 4;
}

function manifestArg(args) {
  const m = args._[2];
  return m && !String(m).startsWith('--') ? m : 'fleet.yaml';
}

async function cmdInit(args, root) {
  const target = path.resolve(root, manifestArg(args) === 'fleet.yaml' ? 'fleet.yaml' : manifestArg(args));
  if (fs.existsSync(target) && !args.flags.force) { console.error(`${target} already exists. Pass --force to overwrite.`); return 4; }
  fs.writeFileSync(target, starterManifestYaml(args.flags.organization || 'example'));
  console.log(`Wrote ${target}. Edit it to list your repositories, then run: agentic-security fleet scan ${path.basename(target)}`);
  return 0;
}

async function cmdScan(args, root, { resumeOnly = false } = {}) {
  const manifestFile = path.resolve(root, manifestArg(args));
  const loaded = loadFleetManifest(manifestFile);
  if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
  const { manifest } = loaded;

  if (!ensureStateDir(root)) { console.error('No safe state directory for this project.'); return 4; }
  const prevRollupFile = statePath(root, 'fleet-rollup.json');
  let previous = null;
  try { previous = JSON.parse(fs.readFileSync(prevRollupFile, 'utf8')); } catch { /* first run */ }

  const { runScan: runScanFn } = await import('../../runScan.js');
  // runScanFn resolves to { scan, meta } already — runFleet's worker expects exactly that shape from runScan, so
  // this must NOT wrap `scan` a second time (an earlier draft did, and every repo silently reported 0 findings:
  // `_summarise` reads `scan.findings` defensively rather than throwing on the wrong shape).
  const runScan = (repoPath) => runScanFn(repoPath, { provenance: false });

  console.error(`[fleet] scanning ${manifest.repositories.length} repository(ies) for ${manifest.organization} (${manifest.workers} worker(s))...`);
  const result = await runFleet({
    repos: manifest.repositories.map((r) => r.id), concurrency: manifest.workers,
    stateFile: statePathFor(root), resume: true, previous,
    runScan: async (repoId) => runScan(manifest.repositories.find((r) => r.id === repoId).path),
    onProgress: (entry) => { console.error(`[fleet] ${entry.ok ? 'done' : 'FAILED'}: ${entry.repo}${entry.ok ? ` (${entry.total} finding(s))` : ` — ${entry.error}`}`); },
  });
  if (resumeOnly && result.skipped.length === manifest.repositories.length) console.error('[fleet] nothing to resume — every repository was already complete.');

  safeWriteState(prevRollupFile, JSON.stringify(result.rollup, null, 2));
  const graph = buildFleetDependencyGraph(manifest.repositories);
  safeWriteState(graphPath(root), JSON.stringify({ organization: manifest.organization, builtAt: new Date().toISOString(), ...graph }, null, 2));

  console.log(renderFleetSummary(result.rollup));
  console.log(`\nRepositories requested: ${manifest.repositories.length}`);
  console.log(`Complete: ${result.results.filter((r) => r.ok).length + result.skipped.length}`);
  console.log(`Failed: ${result.results.filter((r) => !r.ok).length}`);
  const anyFailed = result.results.some((r) => !r.ok);
  return anyFailed ? 1 : 0;
}

async function cmdStatus(args, root) {
  const f = statePath(root, 'fleet-rollup.json');
  if (!fs.existsSync(f)) { console.error('No fleet scan has been run yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const rollup = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (args.flags.json) console.log(JSON.stringify(rollup, null, 2));
  else console.log(renderFleetSummary(rollup));
  return 0;
}

async function cmdQuery(args, root) {
  const target = args.flags['depends-on'];
  if (!target) { console.error('usage: fleet query --depends-on <repo-id>'); return 4; }
  const f = graphPath(root);
  if (!fs.existsSync(f)) { console.error('No fleet dependency graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const graph = JSON.parse(fs.readFileSync(f, 'utf8'));
  if (!graph.nodes.some((n) => n.id === target)) { console.error(`${target} is not a repository in the last fleet scan.`); return 4; }
  const radius = blastRadius(graph, target);
  if (args.flags.json) { console.log(JSON.stringify({ target, blastRadius: radius }, null, 2)); return 0; }
  if (!radius.length) { console.log(`No fleet repository depends on ${target} (by declared package name).`); return 0; }
  console.log(`Repositories depending on ${target} (directly or transitively):`);
  for (const r of radius) console.log(`  ${r.id}  (depth ${r.depth}, via ${r.path.slice(1).join(' -> ')})`);
  return 0;
}
