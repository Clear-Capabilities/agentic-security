// `agentic-security fleet init|scan|status|resume|query|explore`.
//
// The scanning half is the job fabric: a manifest becomes one idempotent job per repository in a local SQLite store, workers lease
// them, every scan runs in a supervised child under a hard timeout, and `resume` continues a run after anything stops it. The
// per-repository entry and the roll-up are the existing `posture/fleet.js` ones (counts, owners, scan health, delta), so a fleet
// report reads as it always has, with the organization's health and the enterprise graph added on top.
//
// Exit codes: 0 the organization is GREEN, 1 it is not (a required repository has no result, or a result is partial), 4 usage.
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { loadFleetManifest, starterManifestYaml } from './fleet-manifest.js';
import { buildFleetDependencyGraph, blastRadius } from './fleet-graph.js';
import { rollupFleet, renderFleetSummary } from '../fleet.js';
import { statePath, ensureStateDir, safeWriteState } from '../state-dir.js';
import { createSqliteJobStore } from './job-store.js';
import { planRun, runJobs, loadArtifacts, reclaimDeadWorkers, childScan } from './job-runner.js';
import { computeOrgHealth, renderOrgHealth } from './org-health.js';
import { discoverEdges, splitDeclared } from './discover-edges.js';
import { buildEnterpriseGraph, finalizeGraph, validateEnterpriseGraph, attackPaths, vulnerableSet, componentBlastRadius, renderBlastRadius, INTERNET } from './enterprise-graph.js';

const GRAPH_FILE = 'fleet-graph.json';
const ENTERPRISE_FILE = path.join('fleet', 'enterprise-graph.json');
const DB_FILE = path.join('fleet', 'fleet.db');
const ROLLUP_FILE = 'fleet-rollup.json';
const sha = (s) => createHash('sha256').update(s).digest('hex');

const usage = () => { console.error('usage: fleet init | edges [--undeclared] | scan <manifest.yaml> [--workers N] [--retries N] [--timeout-seconds N | --timeout-ms N] [--no-cache] | status [run-id] | resume <run-id|manifest.yaml> [--retry-failed] | query (--depends-on <id> | --blast-radius <component> [--version v] | --internet-to <data-class> [--involving-vulnerable auth|<repo>] | "<question>") | explore [--out file.html]'); return 4; };
const isManifestArg = (s) => /\.ya?ml$/i.test(String(s ?? ''));
const manifestArg = (args) => { const m = args._[2]; return m && !String(m).startsWith('--') ? m : 'fleet.yaml'; };
const dbPath = (root) => statePath(root, DB_FILE);

export async function cmdFleet(args, root) {
  const sub = args._[1];
  if (sub === 'init') return cmdInit(args, root);
  if (sub === 'scan') return cmdScan(args, root);
  if (sub === 'status') return cmdStatus(args, root);
  if (sub === 'resume') return cmdResume(args, root);
  if (sub === 'query') return cmdQuery(args, root);
  if (sub === 'explore') return cmdExplore(args, root);
  if (sub === 'edges') return cmdEdges(args, root);
  return usage();
}

/** `fleet edges [--undeclared] [--json]`: every edge of the last enterprise graph with the evidence it rests on; --undeclared keeps the ones found only in code. */
async function cmdEdges(args, root) {
  const f = statePath(root, ENTERPRISE_FILE);
  if (!fs.existsSync(f)) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const g = JSON.parse(fs.readFileSync(f, 'utf8'));
  const edges = g.edges.filter((e) => e.type !== 'exposes' && (!args.flags.undeclared || e.discovered));
  if (args.flags.json) { console.log(JSON.stringify({ discovery: g.discovery ?? null, edges }, null, 2)); return 0; }
  if (!edges.length) { console.log(args.flags.undeclared ? 'No edge was found in code that the manifest does not declare.' : 'The graph has no edges.'); }
  for (const e of edges) {
    const where = e.evidence.filter((x) => x.source === 'discovered-code-literal').map((x) => `${x.file}:${x.line}`);
    console.log(`${e.from} -[${e.type}]-> ${e.to}  ${e.discovered ? 'FOUND ONLY IN CODE' : where.length ? 'declared, and seen in code' : 'declared'}${where.length ? `  (${where.join(', ')})` : ''}`);
  }
  if (g.discovery?.limitations) console.log(`\nLimits: ${g.discovery.limitations.join(' ')}`);
  else if (g.discovery?.note) console.log(`\nEdge discovery: ${g.discovery.note}.`);
  return 0;
}

async function cmdInit(args, root) {
  const target = path.resolve(root, manifestArg(args) === 'fleet.yaml' ? 'fleet.yaml' : manifestArg(args));
  if (fs.existsSync(target) && !args.flags.force) { console.error(`${target} already exists. Pass --force to overwrite.`); return 4; }
  fs.writeFileSync(target, starterManifestYaml(args.flags.organization || 'example'));
  console.log(`Wrote ${target}. Edit it to list your repositories, then run: agentic-security fleet scan ${path.basename(target)}`);
  return 0;
}

function overrides(manifest, args) {
  const m = { ...manifest };
  const num = (v, lo, hi) => { const n = Number(v); return Number.isInteger(n) && n >= lo && n <= hi ? n : null; };
  if (args.flags.workers !== undefined) { const n = num(args.flags.workers, 1, 32); if (n == null) return { error: '--workers must be an integer from 1 to 32' }; m.workers = n; }
  if (args.flags.retries !== undefined) { const n = num(args.flags.retries, 0, 5); if (n == null) return { error: '--retries must be an integer from 0 to 5' }; m.retries = n; }
  if (args.flags['timeout-ms'] !== undefined) { const n = num(args.flags['timeout-ms'], 50, 86400000); if (n == null) return { error: '--timeout-ms must be an integer from 50 to 86400000' }; m.perRepoTimeoutMs = n; }
  if (args.flags['timeout-seconds'] !== undefined) { const n = num(args.flags['timeout-seconds'], 1, 86400); if (n == null) return { error: '--timeout-seconds must be an integer from 1 to 86400' }; m.perRepoTimeoutMs = n * 1000; }
  return { manifest: m };
}

function entriesOf(artifacts, manifest) {
  return manifest.repositories.filter((r) => artifacts.has(r.id)).map((r) => ({ ...artifacts.get(r.id).entry, repo: r.id }));
}

async function finishRun({ args, root, store, runId, manifest, manifestFile, interrupted }) {
  const { artifacts, problems } = loadArtifacts({ store, runId, root });
  const jobs = store.listJobs(runId);
  const health = computeOrgHealth({ manifest, jobs });
  for (const p of problems) { const r = health.repositories.find((x) => x.id === p.repoId); if (r) { r.state = 'failed'; r.error = p.problem; } }
  if (problems.length) { health.counts.complete -= problems.filter((p) => health.repositories.find((x) => x.id === p.repoId)).length; health.counts.failed += problems.length; if (health.assurance !== 'red' && manifest.repositories.some((r) => r.required && problems.some((p) => p.repoId === r.id))) health.assurance = 'red'; health.reasons.push(`${problems.length} result(s) could not be verified: ${problems.map((p) => `${p.repoId} (${p.problem})`).join(', ')}`); }

  let previous = null;
  const rollupFile = statePath(root, ROLLUP_FILE);
  try { previous = JSON.parse(fs.readFileSync(rollupFile, 'utf8')); } catch { /* first run */ }
  const rollup = rollupFleet(entriesOf(artifacts, manifest).concat(health.repositories.filter((r) => !artifacts.has(r.id) && r.state !== 'complete' && r.state !== 'partial').map((r) => ({ repo: r.id, ok: false, error: r.error || r.state, total: null, bySeverity: null, ids: [], scannedAt: new Date().toISOString(), scanHealth: null, policyDrift: null, provenanceDebt: null, mttr: null }))), previous);
  safeWriteState(rollupFile, JSON.stringify(rollup, null, 2));

  const dep = buildFleetDependencyGraph(manifest.repositories);
  safeWriteState(statePath(root, GRAPH_FILE), JSON.stringify({ organization: manifest.organization, builtAt: new Date().toISOString(), ...dep }, null, 2));
  // edges the code implies; skipped with --no-discover. A failure here never fails the run: the graph is then declared-only and says so.
  let discovered = null; let discoveryNote = args.flags['no-discover'] ? 'skipped (--no-discover)' : null;
  if (!args.flags['no-discover']) { try { discovered = discoverEdges({ manifest }); } catch (e) { discoveryNote = `failed (${String(e.message).slice(0, 80)}); the graph holds declared edges only`; } }
  const split = discovered ? splitDeclared(discovered, manifest) : null;
  const graph = finalizeGraph(buildEnterpriseGraph({ manifest, dependencyGraph: dep, discovered }));
  const findingsByRepo = Object.fromEntries([...artifacts].map(([id, a]) => [id, a.findings ?? []]));
  safeWriteState(statePath(root, ENTERPRISE_FILE), JSON.stringify({ ...graph, runId, manifestFile, findingsByRepo, discovery: discovered ? { scanned: discovered.scanned, limitations: discovered.limitations, undeclared: split.undeclared.length, confirmed: split.confirmed.length } : { note: discoveryNote }, builtAt: new Date().toISOString() }));

  if (args.flags.json) console.log(JSON.stringify({ runId, health, rollup }, null, 2));
  else {
    console.log(renderFleetSummary(rollup));
    console.log(`\nRun: ${runId}\n${renderOrgHealth(health)}`);
    if (split) console.log(`\nEdges found in code: ${split.undeclared.length} not in the manifest, ${split.confirmed.length} matching a declared edge. ${split.undeclared.length ? 'List them with: agentic-security fleet edges --undeclared' : ''}`.trimEnd());
    else if (discoveryNote) console.log(`\nEdge discovery ${discoveryNote}.`);
    if (interrupted) console.log(`\nInterrupted. Continue with: agentic-security fleet resume ${runId}`);
    else if (health.counts.failed || health.counts.timedOut || health.counts.notRun) console.log(`\nRetry the failed and timed-out repositories with: agentic-security fleet resume ${runId} --retry-failed`);
  }
  return health.assurance === 'green' && !interrupted ? 0 : 1;
}

async function runAll({ args, root, store, runId, manifest, manifestFile }) {
  const ac = new AbortController(); const onSig = () => ac.abort(); process.once('SIGINT', onSig); process.once('SIGTERM', onSig);
  try {
    await runJobs({ manifest, store, runId, root, scan: childScan, signal: ac.signal, useCache: !args.flags['no-cache'], onEvent: (e) => {
      if (args.flags.json) return;
      if (e.type === 'done') console.error(`[fleet] done: ${e.repo}${e.cached ? ' (cached)' : ''}${e.status === 'partial' ? ' (partial)' : ''}`);
      else if (e.type === 'failed') console.error(`[fleet] ${e.timedOut ? 'TIMED OUT' : 'FAILED'}: ${e.repo} (${e.error})${e.next === 'queued' ? ', will retry' : ''}`);
      else if (e.type === 'fenced') console.error(`[fleet] ${e.repo}: result discarded, another worker holds the job`);
    } });
    return await finishRun({ args, root, store, runId, manifest, manifestFile, interrupted: ac.signal.aborted });
  } finally { process.off('SIGINT', onSig); process.off('SIGTERM', onSig); }
}

async function cmdScan(args, root) {
  const manifestFile = path.resolve(root, manifestArg(args));
  const loaded = loadFleetManifest(manifestFile);
  if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
  const o = overrides(loaded.manifest, args);
  if (o.error) { console.error(o.error); return 4; }
  const { manifest } = o;
  if (!ensureStateDir(root)) { console.error('No safe state directory for this project.'); return 4; }
  const store = await createSqliteJobStore({ file: dbPath(root) });
  try {
    const manifestHash = sha(fs.readFileSync(manifestFile));
    console.error(`[fleet] planning ${manifest.repositories.length} repository(ies) for ${manifest.organization} (${manifest.workers} worker(s), ${manifest.retries} retr${manifest.retries === 1 ? 'y' : 'ies'}, ${Math.round(manifest.perRepoTimeoutMs / 1000)}s per repository)...`);
    const plan = planRun({ manifest, manifestHash, store, meta: { manifestFile } });
    return await runAll({ args, root, store, runId: plan.runId, manifest, manifestFile });
  } finally { store.close(); }
}

async function cmdResume(args, root) {
  const target = String(args._[2] ?? '');
  if (!target) return usage();
  const dbFile = dbPath(root);
  if (!fs.existsSync(dbFile)) { console.error('No fleet run exists in this project. Start one with: agentic-security fleet scan <manifest.yaml>'); return 4; }
  const store = await createSqliteJobStore({ file: dbFile });
  try {
    let run;
    if (isManifestArg(target)) {
      const hash = sha(fs.readFileSync(path.resolve(root, target)));
      run = store.listRuns().find((r) => r.manifestHash === hash && store.listJobs(r.runId).some((j) => ['queued', 'leased'].includes(j.status)));
      if (!run) { console.error('Nothing to resume for that manifest: no run of it has unfinished work. Use `fleet resume <run-id> --retry-failed` to retry failed repositories.'); return 4; }
    } else run = store.getRun(target);
    if (!run) { console.error(`No run ${target}. Runs: ${store.listRuns().slice(0, 5).map((r) => r.runId).join(', ') || 'none'}`); return 4; }
    const full = store.getRun(run.runId);
    const manifestFile = path.resolve(root, args.flags.manifest ?? full.meta?.manifestFile ?? (isManifestArg(target) ? target : 'fleet.yaml'));
    const loaded = loadFleetManifest(manifestFile);
    if (!loaded.ok) { console.error(`Invalid fleet manifest: ${loaded.errors.join('; ')}`); return 4; }
    const hash = sha(fs.readFileSync(manifestFile));
    if (hash !== full.manifestHash) { console.error(`The manifest ${path.basename(manifestFile)} has changed since run ${full.runId} was planned. A resumed run must scan what it planned; start a new scan instead.`); return 4; }
    const o = overrides(loaded.manifest, args);
    if (o.error) { console.error(o.error); return 4; }
    const freed = reclaimDeadWorkers(store, full.runId) + store.reclaimExpired(full.runId, { now: Date.now() });
    const requeued = args.flags['retry-failed'] ? store.requeueTerminal(full.runId, ['failed', 'timed_out']) : 0;
    // a limit given on the command line applies to the work still to do, including the work just re-queued
    if (args.flags['timeout-ms'] !== undefined || args.flags['timeout-seconds'] !== undefined) store.retime(full.runId, o.manifest.perRepoTimeoutMs);
    const open = store.listJobs(full.runId).filter((j) => ['queued', 'leased'].includes(j.status)).length;
    console.error(`[fleet] resuming ${full.runId}: ${open} unfinished, ${freed} lease(s) recovered${requeued ? `, ${requeued} failed repository(ies) re-queued` : ''}; finished results are reused.`);
    return await runAll({ args, root, store, runId: full.runId, manifest: o.manifest, manifestFile });
  } finally { store.close(); }
}

async function cmdStatus(args, root) {
  const dbFile = dbPath(root);
  if (!fs.existsSync(dbFile)) {
    const f = statePath(root, ROLLUP_FILE);
    if (!fs.existsSync(f)) { console.error('No fleet scan has been run yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
    const rollup = JSON.parse(fs.readFileSync(f, 'utf8'));
    console.log(args.flags.json ? JSON.stringify(rollup, null, 2) : renderFleetSummary(rollup));
    return 0;
  }
  const store = await createSqliteJobStore({ file: dbFile });
  try {
    const arg = args._[2];
    const run = arg && !isManifestArg(arg) ? store.getRun(String(arg)) : store.listRuns()[0] && store.getRun(store.listRuns()[0].runId);
    if (!run) { console.error(arg && !isManifestArg(arg) ? `No run ${arg}.` : 'No fleet run exists yet.'); return 4; }
    const meta = run.meta ?? {};
    const manifest = loadFleetManifest(path.resolve(root, meta.manifestFile ?? 'fleet.yaml'));
    const jobs = store.listJobs(run.runId);
    const m = manifest.ok ? manifest.manifest : { repositories: jobs.map((j) => ({ id: j.repoId, required: j.required })) };
    const health = computeOrgHealth({ manifest: m, jobs });
    if (args.flags.json) { console.log(JSON.stringify({ runId: run.runId, health, jobs: jobs.map((j) => ({ repo: j.repoId, status: j.status, attempts: j.attempts, worker: j.worker, leaseExpiresAt: j.leaseExpiresAt, error: j.error })) }, null, 2)); return 0; }
    console.log(`Run: ${run.runId} (${run.organization})\n${renderOrgHealth(health)}`);
    const live = jobs.filter((j) => j.status === 'leased');
    if (live.length) console.log(`\nIn progress: ${live.map((j) => `${j.repoId} (attempt ${j.attempts}, lease until ${new Date(j.leaseExpiresAt).toISOString()})`).join(', ')}`);
    const f = statePath(root, ROLLUP_FILE);
    if (fs.existsSync(f)) console.log(`\n${renderFleetSummary(JSON.parse(fs.readFileSync(f, 'utf8')))}`);
    return 0;
  } finally { store.close(); }
}

// "Show every Internet-facing path to PCI data involving vulnerable authentication code" is recognised as a fixed shape and mapped
// to the structured query below. Anything else is refused with the flags to use; this is not a natural-language engine.
export function parseFleetQuestion(text) {
  const m = /^\s*show\s+every\s+internet-facing\s+path\s+to\s+([a-z][a-z0-9-]*)\s+data(?:\s+involving\s+vulnerable\s+([a-z][a-z0-9-]*)\s+(?:code|components?|librar(?:y|ies)))?\s*\.?\s*$/i.exec(String(text ?? ''));
  if (!m) return null;
  const word = m[2]?.toLowerCase() ?? null;
  return { toDataClass: m[1].toLowerCase(), involving: word ? { family: word === 'authentication' || word === 'authorization' ? 'auth' : word } : null };
}

function readEnterprise(root) {
  const f = statePath(root, ENTERPRISE_FILE);
  if (!fs.existsSync(f)) return null;
  try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; }
}

async function cmdQuery(args, root) {
  const flags = args.flags;
  const question = args._[2] && !isManifestArg(args._[2]) ? String(args._[2]) : null;
  const parsed = question ? parseFleetQuestion(question) : null;
  if (question && !parsed) { console.error(`Not a recognised question. This command answers one shape: "Show every Internet-facing path to <data class> data [involving vulnerable <authentication|family> code]". For anything else use --depends-on, --blast-radius, or --internet-to with --involving-vulnerable.`); return 4; }

  if (flags['depends-on']) {
    const f = statePath(root, GRAPH_FILE);
    if (!fs.existsSync(f)) { console.error('No fleet dependency graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
    const graph = JSON.parse(fs.readFileSync(f, 'utf8'));
    const target = String(flags['depends-on']);
    if (!graph.nodes.some((n) => n.id === target)) { console.error(`${target} is not a repository in the last fleet scan.`); return 4; }
    const radius = blastRadius(graph, target);
    if (flags.json) { console.log(JSON.stringify({ target, blastRadius: radius }, null, 2)); return 0; }
    if (!radius.length) { console.log(`No fleet repository depends on ${target} (by declared package name).`); return 0; }
    console.log(`Repositories depending on ${target} (directly or transitively):`);
    for (const r of radius) console.log(`  ${r.id}  (depth ${r.depth}, via ${r.path.slice(1).join(' -> ')})`);
    return 0;
  }

  const ent = readEnterprise(root);
  if (!ent) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const bad = validateEnterpriseGraph(ent);
  if (bad.length) { console.error(`The stored enterprise graph is inconsistent (${bad[0]}). Re-run the scan.`); return 1; }
  const findings = new Map(Object.entries(ent.findingsByRepo ?? {}));

  if (flags['blast-radius']) {
    const r = componentBlastRadius({ graph: ent, component: String(flags['blast-radius']), version: flags.version ? String(flags.version) : null });
    if (!r) { console.error(`${flags['blast-radius']} is not in the last fleet scan.`); return 4; }
    console.log(flags.json ? JSON.stringify(r, null, 2) : renderBlastRadius(r));
    return 0;
  }

  const toClass = parsed?.toDataClass ?? flags['internet-to'];
  if (toClass) {
    const sel = parsed?.involving ?? (flags['involving-vulnerable'] ? (/^[a-z][a-z0-9-]*$/.test(String(flags['involving-vulnerable'])) && ent.nodes.some((n) => n.id === flags['involving-vulnerable']) ? { repo: String(flags['involving-vulnerable']) } : { family: String(flags['involving-vulnerable']) }) : null);
    const involving = sel ? vulnerableSet({ graph: ent, findingsByRepo: findings, selector: sel }) : null;
    const res = attackPaths({ graph: ent, toDataClass: String(toClass).toLowerCase(), involving });
    if (flags.json) { console.log(JSON.stringify({ ...res, involving: involving ? { direct: [...involving.direct], all: [...involving.all], why: Object.fromEntries(involving.why) } : null }, null, 2)); return 0; }
    if (!res.targets.length) { console.log(`No node in the fleet manifest is marked as holding ${toClass} data, so there is nothing to reach.`); return 0; }
    if (!res.paths.length) console.log(`No Internet-facing path to ${toClass} data${involving ? ' involving that vulnerable code' : ''} was found in the declared graph.${res.truncated ? ' (search bound reached)' : ''}`);
    for (const p of res.paths) {
      console.log(p.nodes.map((n) => (n === INTERNET ? 'Internet' : n)).join(' -> '));
      if (p.discoveredEdges?.length) console.log(`    rests on edge(s) found only in code, not declared: ${p.discoveredEdges.join(', ')}`);
      if (p.involving.length) console.log(`    involves vulnerable code: ${p.involving.map((n) => `${n} (${involving.why.get(n)})`).join(', ')}`);
    }
    if (res.paths.length) console.log(`\n${res.paths.length} path(s). Reach edges are as declared in the fleet manifest, plus any marked above as found only in code.${res.truncated ? ' The search bound was reached; more may exist.' : ''}`);
    return 0;
  }
  return usage();
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
async function cmdExplore(args, root) {
  const ent = readEnterprise(root);
  if (!ent) { console.error('No enterprise graph yet. Run `agentic-security fleet scan <manifest.yaml>` first.'); return 4; }
  const rows = ent.edges.map((e) => `<tr><td>${esc(e.from)}</td><td>${esc(e.type)}${e.reach ? '' : ' (dependency)'}</td><td>${esc(e.to)}</td><td>${e.evidence.map((x) => esc(`${x.source}: ${x.repo ?? ''} ${x.field ?? x.declared ?? ''} ${x.value ?? x.spec ?? ''}`.trim())).join('<br>')}</td></tr>`).join('\n');
  const nodes = ent.nodes.map((n) => `<tr><td>${esc(n.id)}</td><td>${esc(n.type)}</td><td>${n.internetFacing ? 'yes' : ''}</td><td>${esc(n.environment ?? '')}</td><td>${esc(n.dataClasses.join(', '))}</td><td>${esc(n.trustZone ?? '')}</td></tr>`).join('\n');
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fleet graph</title><style>body{font:14px/1.5 system-ui,sans-serif;max-width:70rem;margin:2rem auto;padding:0 1rem}table{border-collapse:collapse;margin:.5rem 0 2rem;width:100%}td,th{border:1px solid #8884;padding:.25rem .6rem;text-align:left;vertical-align:top}</style></head><body><h1>${esc(ent.organization)} fleet graph</h1><p>Run ${esc(ent.runId)}. Reach edges are as declared in the fleet manifest; dependency edges come from package manifests. Every edge lists its evidence.</p><h2>Nodes</h2><table><tr><th>id</th><th>type</th><th>internet-facing</th><th>environment</th><th>data</th><th>trust zone</th></tr>${nodes}</table><h2>Edges</h2><table><tr><th>from</th><th>type</th><th>to</th><th>evidence</th></tr>${rows}</table></body></html>\n`;
  const out = path.resolve(root, String(args.flags.out ?? 'fleet-graph.html'));
  fs.writeFileSync(out, html);
  console.log(`Wrote ${out} (${ent.nodes.length} nodes, ${ent.edges.length} edges). A static page, no server.`);
  return 0;
}
