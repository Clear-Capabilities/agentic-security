//
// `agentic-security context <build|inspect|diff|review|status|eval|verify|export|cleanup>`
//
// Additive: no existing command changes. `build`, `inspect`, `diff`, `status`, `verify`, `export` and `cleanup` read
// the repository and write only DCI's own state, with no model and no network. `review` is the only subcommand that
// can reach a model, and only through the governed discovery caller (egress policy, redaction, local-only).
//
// Exit codes: 0 done; 1 bad arguments or a refused operation; 2 the input was too large to analyse; 3 (with
// `--strict`) the run finished but some eligible work has no verified result; 130 cancelled.
import * as path from 'node:path';
import * as fs from 'node:fs';
import { buildContext } from './build.js';
import { loadConfig } from './config.js';
import { persistBuild } from './persist.js';
import { readStoreJson, writeStoreJson, readManifest, readPackageText, verifyStoredBundle, cleanupStore, exportBundle, listStoredBundles, storeRoot } from './store.js';
import { diffManifestSets, cacheReport } from './diff.js';
import { readGitSnapshot, readSnapshot } from './files.js';
import { QUESTION_PACKS, packById } from './prompts/packs.js';
import { cleanForTerminal } from './canonical.js';
import { describeModel, resolveInvoker, buildReviewPrompt, redactPackageText, checkEgressForFiles } from './review.js';
import { planJobs, runQueue, exportBatch, importBatch, HARD_LIMITS } from './queue.js';
import { reviewsToCandidates, adjudicate } from './candidates.js';
import { capabilityMatrix } from './capabilities.js';
import { statePath } from '../posture/state-dir.js';

const flag = (a, k) => (a.flags[k] === undefined ? undefined : a.flags[k]);
const truthy = (v) => v === true || (typeof v === 'string' && v !== 'false' && v !== '0');
const num = (v) => (v === undefined || v === true ? undefined : Number(v));

/** Everything this command prints goes through here: repository-supplied names must not carry escape sequences to a terminal. */
function say(text) { console.log(cleanForTerminal(text)); }

function out(format, text, obj) {
  if (format === 'json') say(JSON.stringify(obj, null, 2));
  else if (format === 'jsonl') say(JSON.stringify(obj));
  else say(text);
}

function usage() {
  say([
    'Usage: agentic-security context <subcommand> [--root <dir>] [--format text|json|jsonl]',
    '',
    '  build     Resolve entry points and write one inspectable context bundle each (no model, no network)',
    '            [--entrypoints http,webhook,queue,cron,upload,cli] [--profile compact|standard|extended] [--max-tokens N] [--route <label|id>] [--no-write]',
    '  inspect   Show one bundle: --route <label|id> | --hash <contextHash>  [--show-context] [--package N]',
    '  diff      Routes added/removed/changed between two refs: --from <ref> [--to <ref>]  (omit --to for the working tree)',
    '  review    Focused one-call reviews over frozen bundles: --question <pack[,pack]> [--route x] [--local-only] [--allow-remote] [--concurrency N]',
    '            [--max-calls N] [--max-wall-seconds N] [--max-cost-usd N --cost-per-call-usd N] [--retry-failed] [--refute] [--strict]',
    '            [--dry-run] [--export-batch] [--import-batch <results.jsonl> --batch-id <id>]',
    '  status    Coverage so far: entry points, bundles, review jobs',
    '  eval      Frozen evaluation: --suite fixtures --baseline deterministic|hunt --variant dci [--format json]',
    '  verify    Re-check stored bundles against their hashes and the current source',
    '  export    One bundle as a single JSON document: --hash <contextHash>',
    '  cleanup   Remove unreferenced old bundles (blocked by a legal hold): [--older-than-days N] [--dry-run]',
    '',
    'Question packs: ' + QUESTION_PACKS.map(p => p.id).join(', '),
  ].join('\n'));
}

function entrypointFilter(arg) { return arg === undefined || arg === true ? undefined : String(arg); }

async function doBuild(root, args, { write = true } = {}) {
  const { config, problems } = loadConfig(root);
  if (flag(args, 'entrypoints')) config.entrypointKinds = String(flag(args, 'entrypoints')).split(',').map(s => s.trim()).filter(Boolean);
  if (flag(args, 'profile')) config.context.profile = String(flag(args, 'profile'));
  if (flag(args, 'max-tokens')) config.context.maxTokens = num(flag(args, 'max-tokens'));
  const events = [];
  const jsonl = flag(args, 'format') === 'jsonl';
  const built = await buildContext(root, { config, route: entrypointFilter(flag(args, 'route')), onEvent: (e) => { events.push(e); if (jsonl) say(JSON.stringify(e)); } });
  if (!built.ok) return { ok: false, built, config, problems };
  let persisted = null;
  if (write) persisted = persistBuild(root, built, config);
  return { ok: true, built, config, problems, persisted, events };
}

function routeTable(built) {
  const rows = [];
  for (const e of built.entrypoints) {
    const b = built.bundles.find(x => x.entrypoint.id === e.id);
    const m = b && b.manifest;
    rows.push(`  ${e.disposition.padEnd(18)} ${m ? m.context.integrity.padEnd(11) : '-'.padEnd(11)} ${e.label}  (${e.registrationSite.file}:${e.registrationSite.line})${e.resolutionReasons.length ? '  [' + e.resolutionReasons.join(', ') + ']' : ''}`);
  }
  return rows.join('\n');
}

async function cmdBuild(root, args, format) {
  const r = await doBuild(root, args, { write: !truthy(flag(args, 'no-write')) });
  if (!r.ok) {
    out(format, `context build: ${r.built.reason}${r.built.detail && r.built.detail.count ? ` (${r.built.detail.count} files, limit ${r.built.detail.limit})` : ''}`, { ok: false, reason: r.built.reason, detail: r.built.detail });
    return r.built.reason === 'too-many-files' ? 2 : 1;
  }
  const { built } = r;
  const s = built.summary;
  const obj = { ok: true, graph: { symbols: built.graph.symbols.length, edges: built.graph.edges.length, hash: built.graph.hash, source: built.semantic.source }, snapshotHash: built.snapshotHash, repository: built.repository, summary: s, semantic: built.semantic, configProblems: r.problems, persisted: r.persisted, skippedFiles: built.skipped.length };
  const text = [
    'Deterministic Context Intelligence: build',
    `  graph: ${built.graph.symbols.length} symbols, ${built.graph.edges.length} edges, ${built.graph.hash.slice(0, 12)}  (${built.semantic.source.join(' + ')})`,
    `  entry points found ${s.entrypointsFound}: resolved ${s.resolved}, partially resolved ${s.partial}, unresolved ${s.unresolved}, excluded by policy ${s.excluded}`,
    `  bundles built ${s.bundlesBuilt}: complete ${s.complete}, partial ${s.partialBundles}, unavailable ${s.unavailable}`,
    `  unresolved material calls: ${s.unresolvedEdges}   tokens (estimate, chars/4): ${s.tokens}`,
    built.skipped.length ? `  ${built.skipped.length} file(s) skipped (symlink, oversize or unreadable)` : null,
    built.semantic.status && built.semantic.status !== 'off' ? `  compiler metadata: ${built.semantic.status}${built.semantic.reason ? ` (${built.semantic.reason}${built.semantic.detail ? ': ' + built.semantic.detail : ''})` : ''}` : null,
    r.problems.length ? `  config notes: ${r.problems.join('; ')}` : null,
    r.persisted ? (r.persisted.ok ? `  written: ${r.persisted.written} bundle(s) under .agentic-security/context-intelligence/` : `  WRITE PROBLEMS: ${JSON.stringify(r.persisted.failures)}`) : '  (not written: --no-write)',
    '',
    routeTable(built),
    '',
    'A "complete" bundle means nothing unresolved, omitted, capped or split was found. It does not mean the route is safe.',
  ].filter(x => x !== null).join('\n');
  out(format, text, obj);
  return 0;
}

function findBundle(built, sel) {
  return built.bundles.find(b => b.entrypoint.id === sel) || built.bundles.find(b => b.entrypoint.label === sel) || built.bundles.find(b => b.entrypoint.label.includes(sel));
}

async function cmdInspect(root, args, format) {
  let manifest;
  let fileContents = null;
  if (flag(args, 'hash')) {
    const m = readManifest(root, String(flag(args, 'hash')));
    if (!m.ok) { out(format, `context inspect: ${m.code}`, { ok: false, reason: m.code }); return 1; }
    manifest = m.value;
  } else if (flag(args, 'route') && flag(args, 'route') !== true) {
    const idx = readStoreJson(root, 'index.json');
    const sel = String(flag(args, 'route'));
    let hash = null;
    if (idx.ok) {
      const hit = idx.value.entrypoints.find(e => e.entrypointId === sel) || idx.value.entrypoints.find(e => e.label === sel) || idx.value.entrypoints.find(e => e.label.includes(sel));
      if (hit) hash = hit.contextHash;
    }
    if (!hash) { out(format, `context inspect: no stored bundle for '${sel}'. Run \`context build\` first.`, { ok: false, reason: 'not-built' }); return 1; }
    const m = readManifest(root, hash);
    if (!m.ok) { out(format, `context inspect: ${m.code}`, { ok: false, reason: m.code }); return 1; }
    manifest = m.value;
  } else { out(format, 'context inspect: pass --route <label|id> or --hash <contextHash>', { ok: false, reason: 'missing-selector' }); return 1; }
  void fileContents;
  const pkgIdx = Number.isInteger(num(flag(args, 'package'))) ? num(flag(args, 'package')) : 1;
  const text = truthy(flag(args, 'show-context')) ? readPackageText(root, manifest, pkgIdx) : null;
  const obj = { ok: true, manifest, context: text && text.ok ? text.text : undefined };
  if (format === 'json' || format === 'jsonl') { out(format, '', obj); return 0; }
  const m = manifest;
  const lines = [
    `${m.entrypoint.method} ${m.entrypoint.path}  [${m.entrypoint.kind}]  ${m.entrypoint.registrationSite.file}:${m.entrypoint.registrationSite.line}`,
    `  context hash ${m.contextHash.slice(0, 16)}   integrity ${m.context.integrity}${m.context.integrityReasons.length ? ' (' + m.context.integrityReasons.join(', ') + ')' : ''}   entry point ${m.status.entrypoint}`,
    `  packages: ${m.context.packages.map(p => `${p.index}/${p.total} ~${p.tokensEstimated} tok${p.standalone ? '' : ' (not standalone)'}`).join(', ')}   tokenizer: ${m.context.tokenizer && m.context.tokenizer.name}`,
    `  handler: ${m.entrypoint.handlerSymbol || '(none)'}   auth scheme (${m.entrypoint.authScheme.basis}): ${m.entrypoint.authScheme.status}`,
    '  protection:',
    ...Object.entries(m.protection).map(([k, v]) => `    ${k.padEnd(20)} ${v.state.padEnd(26)} ${v.why}`),
    `  controls (${m.controls.length}):`,
    ...m.controls.slice(0, 12).map(c => `    ${c.kind.padEnd(20)} ${c.file}:${c.line}  ${c.evidence}/${c.basis}${c.rejectionSeen === false ? ' (no rejection seen)' : ''}`),
    `  sensitive operations (${m.sensitiveOperations.length}):`,
    ...m.sensitiveOperations.slice(0, 8).map(c => `    ${c.kind.padEnd(14)} ${c.file}:${c.line}`),
    `  unresolved material calls (${m.unknowns.filter(u => u.material).length}):`,
    ...m.unknowns.filter(u => u.material).slice(0, 10).map(u => `    ${u.site}  ${u.calleeName}  (${u.reason})`),
    `  omissions (${m.omissions.length}):`,
    ...m.omissions.slice(0, 8).map(o => `    ${o.symbolId || o.range}  ${o.reason}`),
    `  boundaries (calls into libraries, not first-party code): ${m.boundaries.length}`,
  ];
  if (text) lines.push('', text.ok ? text.text : `(context text unavailable: ${text.code})`);
  say(lines.join('\n'));
  return 0;
}

async function snapshotFor(root, ref, config) {
  if (ref === undefined || ref === true) return readSnapshot(root, { maxFiles: config.maxFiles });
  return readGitSnapshot(root, String(ref), { maxFiles: config.maxFiles });
}

async function cmdDiff(root, args, format) {
  const from = flag(args, 'from');
  if (!from || from === true) { out(format, 'context diff: --from <ref> is required', { ok: false, reason: 'missing-from' }); return 1; }
  const { config } = loadConfig(root);
  const a = await snapshotFor(root, from, config);
  const b = await snapshotFor(root, flag(args, 'to'), config);
  for (const [label, s] of [['--from', a], ['--to', b]]) {
    if (!s.ok) { out(format, `context diff: cannot read ${label}: ${s.reason}`, { ok: false, reason: s.reason, which: label }); return 1; }
  }
  const [ba, bb] = [await buildContext(root, { config, snapshot: a }), await buildContext(root, { config, snapshot: b })];
  if (!ba.ok || !bb.ok) { out(format, 'context diff: build failed', { ok: false, reason: (ba.ok ? bb : ba).reason }); return 1; }
  const d = diffManifestSets(ba.bundles.filter(x => x.manifest).map(x => x.manifest), bb.bundles.filter(x => x.manifest).map(x => x.manifest));
  const cache = cacheReport(root, bb.bundles.filter(x => x.manifest).map(x => x.manifest));
  const obj = { ok: true, from: { ref: String(from), commit: a.commit || null, snapshotHash: a.snapshotHash }, to: { ref: flag(args, 'to') === undefined ? 'working-tree' : String(flag(args, 'to')), commit: b.commit || null, snapshotHash: b.snapshotHash }, ...d, cache };
  const text = [
    `context diff ${obj.from.ref} -> ${obj.to.ref}`,
    `  routes: +${d.added.length} added, -${d.removed.length} removed, ${d.changed.length} changed, ${d.unchangedCount} unchanged`,
    ...d.added.map(r => `  + ${r.route}  (${r.file}, ${r.integrity})`),
    ...d.removed.map(r => `  - ${r.route}  (${r.file})`),
    ...d.changed.flatMap(c => [
      `  ~ ${c.route}  (${c.file})  integrity ${c.integrity.from} -> ${c.integrity.to}`,
      ...c.authControlChanges.added.map(x => `      + control ${x}`),
      ...c.authControlChanges.removed.map(x => `      - control ${x}`),
      ...c.newSensitiveOperations.map(x => `      + sensitive operation ${x}`),
      ...c.unknownEdgeChanges.added.map(x => `      + unresolved ${x}`),
      ...Object.entries(c.protectionChanges).map(([k, v]) => `      protection ${k}: ${v.from} -> ${v.to}`),
    ]),
    `  stored bundles reusable for the target: ${cache.hits} hit, ${cache.misses} miss (index ${cache.indexStatus}, ${cache.invalidated} invalidated, ${cache.newRoutes} new)`,
  ].join('\n');
  out(format, text, obj);
  return 0;
}

function statusSnapshot(root) {
  const idx = readStoreJson(root, 'index.json');
  const queuesDir = path.join(storeRoot(root), 'queues');
  const reviewsDir = path.join(storeRoot(root), 'reviews');
  const count = (d) => { try { return fs.readdirSync(d).filter(n => n.endsWith('.json')).length; } catch { return 0; } };
  const queues = [];
  try {
    for (const n of fs.readdirSync(queuesDir).filter(x => x.endsWith('.json')).sort()) {
      const q = readStoreJson(root, `queues/${n}`);
      if (q.ok) {
        const tally = {};
        for (const j of Object.values(q.value.jobs || {})) tally[j.state] = (tally[j.state] || 0) + 1;
        queues.push({ runId: q.value.runId, jobs: Object.keys(q.value.jobs || {}).length, states: tally });
      }
    }
  } catch { /* no queues yet */ }
  return { indexed: idx.ok, indexStatus: idx.ok ? 'ok' : idx.code, summary: idx.ok ? idx.value.summary : null, graph: idx.ok ? idx.value.graph : null, repository: idx.ok ? idx.value.repository : null, storedBundles: listStoredBundles(root).length, reviews: count(reviewsDir), queues };
}

async function cmdStatus(root, args, format) {
  const { config, problems } = loadConfig(root);
  const st = statusSnapshot(root);
  const obj = { ok: true, config: { enabled: config.enabled, entrypointKinds: config.entrypointKinds, semanticMetadata: config.semanticMetadata, context: config.context, review: config.review }, configProblems: problems, ...st, capabilities: capabilityMatrix() };
  const text = [
    'Deterministic Context Intelligence: status',
    st.indexed
      ? `  last build: ${st.summary.entrypointsFound} entry points (${st.summary.resolved} resolved, ${st.summary.partial} partial, ${st.summary.unresolved} unresolved, ${st.summary.excluded} excluded), bundles complete ${st.summary.complete} / partial ${st.summary.partialBundles} / unavailable ${st.summary.unavailable}`
      : `  no build recorded (${st.indexStatus}). Run \`context build\`.`,
    st.indexed ? `  commit ${st.repository.commit || '(no git)'}${st.repository.dirty ? ' + uncommitted changes' : ''}   graph ${st.graph.hash.slice(0, 12)}` : null,
    `  stored bundles: ${st.storedBundles}   verified review results: ${st.reviews}`,
    ...st.queues.map(q => `  review run ${q.runId.slice(0, 10)}: ${q.jobs} jobs ${JSON.stringify(q.states)}`),
    problems.length ? `  config notes: ${problems.join('; ')}` : null,
    `  DCI integration enabled: ${config.enabled} (the explicit \`context\` commands work either way)`,
  ].filter(x => x !== null).join('\n');
  out(format, text, obj);
  return 0;
}

async function cmdVerify(root, args, format) {
  const { config } = loadConfig(root);
  const snap = await readSnapshot(root, { maxFiles: config.maxFiles });
  if (!snap.ok) { out(format, `context verify: ${snap.reason}`, { ok: false, reason: snap.reason }); return 1; }
  const results = [];
  for (const h of listStoredBundles(root)) {
    const v = verifyStoredBundle(root, h, { fileContents: snap.fileContents });
    results.push({ contextHash: h, ok: v.ok, problems: v.problems });
  }
  const bad = results.filter(r => !r.ok);
  const obj = { ok: bad.length === 0, checked: results.length, mismatched: bad.length, results };
  out(format, `context verify: ${results.length} bundle(s) checked, ${bad.length} do not match the current source or their own hashes${bad.length ? '\n' + bad.slice(0, 20).map(b => `  ${b.contextHash.slice(0, 12)}: ${b.problems.slice(0, 3).join(', ')}`).join('\n') : ''}`, obj);
  return bad.length ? 1 : 0;
}

async function cmdExport(root, args, format) {
  const h = flag(args, 'hash');
  if (!h || h === true) { out(format, 'context export: --hash <contextHash> is required', { ok: false }); return 1; }
  const r = exportBundle(root, String(h));
  if (!r.ok) { out(format, `context export: refused (${r.problems.join(', ')})`, { ok: false, problems: r.problems }); return 1; }
  say(JSON.stringify(r.export, null, 2));
  return 0;
}

async function cmdCleanup(root, args, format) {
  const r = cleanupStore(root, { olderThanDays: Number.isFinite(num(flag(args, 'older-than-days'))) ? num(flag(args, 'older-than-days')) : 30, dryRun: truthy(flag(args, 'dry-run')) });
  const text = r.blockedByLegalHold
    ? `context cleanup: nothing removed, the context-intelligence artifact is under a legal hold (${r.blockedByLegalHold.owner}: ${r.blockedByLegalHold.reason})`
    : `context cleanup: ${r.removed.length} bundle(s) ${r.dryRun ? 'would be ' : ''}removed, ${r.kept.length} kept`;
  out(format, text, { ok: true, ...r });
  return 0;
}

// ---- review ------------------------------------------------------------------------------------------------------

function loadJobFrom(built, packs) {
  const byEp = new Map(built.bundles.map(b => [b.entrypoint.id, b]));
  const packMap = new Map(packs.map(p => [p.id, p]));
  return (job) => {
    const bundles = job.entrypointIds.map(id => byEp.get(id));
    if (bundles.some(b => !b || !b.manifest)) return { error: 'entry point no longer has a bundle' };
    const pack = packMap.get(job.packId);
    if (!pack) return { error: 'question pack unavailable' };
    for (let i = 0; i < bundles.length; i++) {
      if (bundles[i].manifest.contextHash !== job.contextHashes[i]) return { error: 'stale-context: the bundle changed since this job was planned' };
    }
    return {
      pack, entrypoints: bundles.map(b => b.entrypoint), manifests: bundles.map(b => b.manifest),
      packageTexts: bundles.map((b, i) => (b.pack.packages.find(p => p.index === job.packageIndexes[i]) || b.pack.packages[0]).text),
    };
  };
}

async function cmdReview(root, args, format) {
  const { config } = loadConfig(root);
  const provider = flag(args, 'provider');
  if (provider !== undefined && provider !== 'configured') { out(format, `context review: --provider only accepts 'configured' (the endpoint set through the existing LLM configuration); got '${provider}'`, { ok: false, reason: 'bad-provider' }); return 1; }
  const wanted = flag(args, 'question') && flag(args, 'question') !== true ? String(flag(args, 'question')).split(',').map(s => s.trim()).filter(Boolean) : config.review.questionPacks;
  const packs = wanted.map(packById);
  if (packs.some(p => !p)) { out(format, `context review: unknown question pack '${wanted[packs.findIndex(p => !p)]}'. Known: ${QUESTION_PACKS.map(p => p.id).join(', ')}`, { ok: false, reason: 'unknown-pack' }); return 1; }

  // --local-only is an explicit statement of intent: it is enforced by the existing egress policy, which denies any
  // non-loopback endpoint, and a denial skips the jobs. There is no fallback to another provider.
  if (truthy(flag(args, 'local-only'))) process.env.AGENTIC_SECURITY_EGRESS_MODE = 'local-only';

  const r = await doBuild(root, args, { write: true });
  if (!r.ok) { out(format, `context review: build failed (${r.built.reason})`, { ok: false, reason: r.built.reason }); return r.built.reason === 'too-many-files' ? 2 : 1; }
  const { built } = r;
  const model = describeModel({ allowRemote: truthy(flag(args, 'allow-remote')) || r.config.review.allowRemote === true });
  const { jobs, droppedByJobLimit } = planJobs({ bundles: built.bundles, packs, model, maxJobs: Math.min(HARD_LIMITS.maxJobs, num(flag(args, 'max-jobs')) || HARD_LIMITS.maxJobs) });
  const loadJob = loadJobFrom(built, packs);
  const ctxBase = { root: built.root, fileContents: built.fileContents, model };

  if (truthy(flag(args, 'dry-run'))) {
    const obj = { ok: true, dryRun: true, eligibleJobs: jobs.length, droppedByJobLimit, model: { provider: model.provider, model: model.model }, packs: packs.map(p => `${p.id}/${p.version}`) };
    out(format, `context review (dry run): ${jobs.length} job(s) would run over ${built.summary.bundlesBuilt} bundle(s); model ${model.provider || '(none configured)'}/${model.model || '-'}`, obj);
    return 0;
  }

  if (truthy(flag(args, 'export-batch'))) {
    const e = exportBatch(built.root, jobs, loadJob, { model, review: { buildReviewPrompt, redactPackageText, checkEgressForFiles } });
    if (!e.ok) { out(format, `context review: batch export failed (${e.code})`, e); return 1; }
    out(format, `context review: batch ${e.batchId} written (${e.requests} request(s), ${e.skipped.length} skipped by policy or error). Upload is the operator's step; import results with --import-batch <file> --batch-id ${e.batchId}.`, { ok: true, ...e });
    return 0;
  }

  if (flag(args, 'import-batch') && flag(args, 'import-batch') !== true) {
    const batchId = flag(args, 'batch-id');
    if (!batchId || batchId === true) { out(format, 'context review: --batch-id is required with --import-batch', { ok: false }); return 1; }
    let text;
    try { text = fs.readFileSync(path.resolve(String(flag(args, 'import-batch'))), 'utf8'); } catch { out(format, 'context review: cannot read the results file', { ok: false }); return 1; }
    const imp = importBatch(built.root, String(batchId), text, { jobs, loadJob, fileContents: built.fileContents });
    out(format, imp.ok ? `context review: imported ${imp.accepted} accepted, ${imp.declined} declined, ${imp.rejected.length} rejected, ${imp.duplicates} duplicate(s)` : `context review: ${imp.reason}`, imp);
    return imp.ok ? 0 : 1;
  }

  const invoker = resolveInvoker({ scanRoot: built.root });
  const ac = new AbortController();
  let interrupted = false;
  const onSig = () => { interrupted = true; ac.abort(); };
  process.on('SIGINT', onSig); process.on('SIGTERM', onSig);
  const jsonl = format === 'jsonl';
  let result;
  try {
    result = await runQueue(jobs, {
      ...ctxBase, invoker, loadJob, signal: ac.signal, retryFailed: truthy(flag(args, 'retry-failed')),
      onEvent: jsonl ? (e) => say(JSON.stringify(e)) : undefined,
      limits: {
        concurrency: num(flag(args, 'concurrency')) || config.review.concurrency,
        maxCalls: num(flag(args, 'max-calls')) || config.review.maxCalls,
        maxWallSeconds: num(flag(args, 'max-wall-seconds')) || config.review.maxWallSeconds,
        maxTokensPerJob: config.review.maxTokensPerJob,
        maxRetries: config.review.maxRetries,
        jobTimeoutMs: (num(flag(args, 'job-timeout-seconds')) || 120) * 1000,
        maxCostUsd: num(flag(args, 'max-cost-usd')) ?? config.review.maxCostUsd,
        costPerCallUsd: num(flag(args, 'cost-per-call-usd')),
      },
    });
  } finally { process.off('SIGINT', onSig); process.off('SIGTERM', onSig); }

  // verified results -> candidates -> the existing adjudication
  const records = [];
  for (const [, res] of result.results) {
    if (res.state === 'succeeded' && res.review) {
      const job = res.job;
      const lj = loadJob(job);
      if (lj.error) continue;
      records.push({ review: res.review, entrypoints: lj.entrypoints.map(e => ({ id: e.id, label: e.label })), pack: lj.pack });
    }
  }
  const candidates = reviewsToCandidates(records);
  let priorScan = null, triageFeedback = null;
  try { priorScan = JSON.parse(fs.readFileSync(statePath(built.root, 'last-scan.json'), 'utf8')); } catch { /* none */ }
  try { triageFeedback = JSON.parse(fs.readFileSync(statePath(built.root, 'triage-feedback.json'), 'utf8')); } catch { /* none */ }
  const { makeTaintProbe } = await import('../discovery/index.js');
  const adj = await adjudicate(candidates, { taintProbe: makeTaintProbe(built.ir.perFile, built.ir.callGraph), priorScan, triageFeedback, scanRoot: built.root, refute: truthy(flag(args, 'refute')) ? {} : null });

  const cov = result.coverage;
  const report = { ok: true, runId: result.runId, interrupted, model: { provider: model.provider, model: model.model }, buildSummary: built.summary, coverage: cov, candidates: candidates.length, findings: adj.findings.map(f => ({ id: f.id, severity: f.severity, file: f.file, line: f.line, vuln: f.vuln, cwe: f.cwe, confirmation: f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier, witnesses: f.contextIntelligence && f.contextIntelligence.witnessCount, contextIntelligence: f.contextIntelligence })), advisory: adj.advisory, refuted: adj.refuted, duplicates: adj.duplicates.length, suppressed: adj.suppressed.length };
  writeStoreJson(built.root, `reports/review-${result.runId}.json`, report);
  const text = [
    'Deterministic Context Intelligence: review',
    `  model: ${model.provider || '(none)'}/${model.model || '-'}   packs: ${packs.map(p => p.id).join(', ')}`,
    `  eligible ${cov.eligible} | attempted ${cov.attempted} | succeeded ${cov.succeeded} | partial ${cov.partial} | failed ${cov.failed} | timed out ${cov.timed_out} | skipped by policy ${cov.skipped_by_policy} | cancelled ${cov.cancelled}`,
    `  cached ${cov.cached}, resumed ${cov.resumed}, model calls ${cov.modelCalls}, wall ${Math.round(cov.wallMs / 1000)}s`,
    `  cost: ${cov.estimatedCostUsd === null ? 'not estimated (' + cov.costBasis + ')' : '$' + cov.estimatedCostUsd.toFixed(4) + ' (' + cov.costBasis + ')'}`,
    ...Object.entries(cov.reasons).slice(0, 8).map(([k, v]) => `  ! ${v}x ${k}`),
    cov.missingCoverage > 0 ? `  ${cov.missingCoverage} eligible job(s) have NO verified result. That is missing coverage, not a clean result.` : '  every eligible job has a verified result (that is coverage, not proof of safety)',
    cov.queueStateCorrupt ? '  note: the previous queue checkpoint failed its integrity check and was ignored' : null,
    '',
    adj.findings.length ? `${adj.findings.length} candidate finding(s) (advisory, unconfirmed unless stated; severity comes from the confirmation tier):` : 'No candidate findings survived verification.',
    ...adj.findings.map(f => `  [${f.severity}] ${f.file}:${f.line}  ${f.vuln}  confirmation=${(f.discovery && f.discovery.confirmation && f.discovery.confirmation.tier) || 'unknown'} routes=${f.contextIntelligence ? f.contextIntelligence.witnessCount : 1}`),
    adj.advisory.length ? `  ${adj.advisory.length} advisory-only hypothesis(es) not promoted to findings` : null,
  ].filter(x => x !== null).join('\n');
  out(format, text, report);
  if (interrupted) return 130;
  if (truthy(flag(args, 'strict')) && cov.missingCoverage > 0) return 3;
  return 0;
}

// ---- dispatch -----------------------------------------------------------------------------------------------------

export async function cmdContext(args) {
  const sub = args._[1];
  const root = path.resolve(flag(args, 'root') && flag(args, 'root') !== true ? String(flag(args, 'root')) : '.');
  const format = ['json', 'jsonl'].includes(flag(args, 'format')) ? flag(args, 'format') : 'text';
  switch (sub) {
    case 'build': return cmdBuild(root, args, format);
    case 'inspect': return cmdInspect(root, args, format);
    case 'diff': return cmdDiff(root, args, format);
    case 'review': return cmdReview(root, args, format);
    case 'status': return cmdStatus(root, args, format);
    case 'verify': return cmdVerify(root, args, format);
    case 'export': return cmdExport(root, args, format);
    case 'cleanup': return cmdCleanup(root, args, format);
    case 'eval': {
      const { cmdEval } = await import('./evaluation/index.js');
      return cmdEval(root, args, format);
    }
    default:
      usage();
      return sub === undefined ? 0 : 1;
  }
}

