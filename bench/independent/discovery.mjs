// The `deep+discovery` configuration of the independent measurement: after the deterministic deep scan of a tree, run the
// product's LLM candidate discovery (scanner/src/discovery, the engine behind `hunt`) over the same tree with a LOCAL Ollama
// model, and score the union of both finding sets with the unchanged scorer.
//
// WHAT THIS MUST NEVER DO
//   * Steer discovery with anything the benchmark knows. The advisory's files, CWE, changed lines and every other label stay
//     in runner.mjs; this module is handed a directory and the deterministic findings for it, nothing else. File selection,
//     focus areas, lenses, the call and candidate ceilings are the product's own defaults (`selectHuntFiles`, `runDiscovery`).
//     The one knob set here is the wall-clock budget, because a per-entry bound is a property of the measurement, and it is
//     recorded.
//   * Send code off this machine. The model is reached through the product's `ollama` preset, which refuses a non-loopback
//     host, and a preflight refuses an Ollama model served from a remote host (an Ollama "cloud" model answers on the loopback
//     port and forwards the prompt). Any inherited model configuration is removed for the duration of the call.
//   * Change the deterministic half. The preset is set only while discovery runs, so the deep scan of every tree sees exactly
//     the environment of the `deep` configuration (no model validator, no other model-backed pass).
//   * Write into the scanned tree. Discovery runs without a scan root (no cross-run memory), and the tree is content-hashed
//     before and after.
//   * Read an exhausted budget as a clean result. Every tree's coverage (calls, degraded runs, unparseable replies, the budget
//     and timeout state) travels with its row, and the report counts incomplete trees.
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { snapshotTree, assertTreeUnchanged } from '../_lib/tree-integrity.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const SRC = (rel) => path.join(REPO, 'scanner', 'src', rel);

export const DEFAULT_DISCOVERY_BUDGET_MIN = 10;
/** The longest one model call may run (the product's Ollama request timeout, never past the tree's budget). */
const callTimeoutMs = (budgetMs) => Math.min(300000, budgetMs);
/**
 * The hard stop sits one full model call plus a minute past the product's own wall-clock budget. The budget is checked
 * before each call, so a call started just before it is spent may run to its own timeout; stopping earlier would discard
 * everything the run produced (measured: a 4B thinking model took up to five minutes per call and a one-minute grace lost
 * the whole tree). The hard stop is for a call that never returns at all.
 */
const hardStopGraceMs = (budgetMs) => callTimeoutMs(budgetMs) + 60 * 1000;
/** Model configuration that must not leak into (or out of) the scoped discovery environment. */
const INHERITED_MODEL_VARS = /^AGENTIC_SECURITY_(LLM_|OLLAMA_)/;

/**
 * Parse the discovery options from argv. Returns null when `--discovery` is absent.
 *   --discovery                        enable
 *   --discovery-model=<ollama model>   default AGENTIC_SECURITY_BENCH_DISCOVERY_MODEL, else the product's default Ollama model
 *   --discovery-budget-min=<minutes>   per-tree wall clock, default 10
 */
export function discoveryOptionsFromArgv(argv, env = process.env, defaultModel = null) {
  if (!argv.includes('--discovery')) return null;
  const val = (k) => { const a = argv.find((x) => x.startsWith(`--${k}=`)); return a ? a.slice(k.length + 3) : null; };
  const model = val('discovery-model') || env.AGENTIC_SECURITY_BENCH_DISCOVERY_MODEL || defaultModel;
  if (!model) throw new Error('--discovery needs a model: pass --discovery-model=<installed Ollama model>');
  const minutes = val('discovery-budget-min') === null ? DEFAULT_DISCOVERY_BUDGET_MIN : Number(val('discovery-budget-min'));
  if (!Number.isFinite(minutes) || minutes <= 0) throw new Error(`--discovery-budget-min must be a positive number of minutes, got ${JSON.stringify(val('discovery-budget-min'))}`);
  const host = env.AGENTIC_SECURITY_BENCH_DISCOVERY_HOST || 'http://127.0.0.1:11434';
  return { model, budgetMs: Math.round(minutes * 60000), host };
}

/** The configuration string. A discovery run can never share a name (or a RESULT file) with a deterministic one. */
export function configurationName(deep, discovery) {
  return `${deep ? 'deep' : 'pattern-only'}${discovery ? '+discovery' : ''}`;
}

/** The file tag of a configuration (RESULT-<tag>.json, RESULT-chunk-<tag>-NNNNN.json). */
export function configurationTag(deep, discovery) {
  return `${deep ? 'deep' : 'pattern'}${discovery ? '-discovery' : ''}`;
}

/** The environment overrides discovery runs under: the loopback Ollama preset and nothing inherited. */
export function discoveryEnv(opts) {
  return {
    AGENTIC_SECURITY_LLM_PRESET: 'ollama',
    AGENTIC_SECURITY_LLM_MODEL: opts.model,
    AGENTIC_SECURITY_OLLAMA_HOST: opts.host,
    // one model call may not outlive the tree's budget
    AGENTIC_SECURITY_LLM_TIMEOUT_MS: String(callTimeoutMs(opts.budgetMs)),
    // belt and braces: a scan still settling in the background (a watchdog-abandoned entry) must not start validating
    AGENTIC_SECURITY_LLM_VALIDATE: '0',
  };
}

/** Run `fn` with `overrides` applied and every other model variable removed; restore the environment afterwards. */
export async function withScopedEnv(overrides, fn, env = process.env) {
  const saved = {};
  for (const k of Object.keys(env)) if (INHERITED_MODEL_VARS.test(k)) { saved[k] = env[k]; delete env[k]; }
  for (const [k, v] of Object.entries(overrides)) { if (!(k in saved)) saved[k] = env[k]; env[k] = v; }
  try { return await fn(); } finally {
    for (const k of Object.keys(env)) if (INHERITED_MODEL_VARS.test(k)) delete env[k];
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete env[k]; else env[k] = v; }
  }
}

/**
 * Refuse to start unless the model is local: a loopback host, the product's preset accepts it, and the model is installed
 * and not served from a remote host. Returns the identity recorded with the result.
 */
export async function preflightDiscovery(opts, { listModels = null, env = process.env } = {}) {
  const { isLoopbackUrl } = await import(SRC('llm-validator/local-endpoint.js'));
  if (!isLoopbackUrl(opts.host)) throw new Error(`discovery host ${opts.host} is not loopback; only a local model may read benchmark code`);
  const { resolveProvider } = await import(SRC('llm-validator/providers.js'));
  const scoped = { ...Object.fromEntries(Object.entries(env).filter(([k]) => !INHERITED_MODEL_VARS.test(k))), ...discoveryEnv(opts) };
  const resolved = resolveProvider({ role: 'hunt', env: scoped });
  if (!resolved.ok || resolved.config.provider !== 'ollama' || resolved.config.egress !== 'loopback-only') {
    throw new Error(`the ollama preset did not resolve to a loopback provider: ${resolved.reason || JSON.stringify(resolved.config?.egress)}`);
  }
  const list = listModels || (async () => (await import(SRC('llm-validator/ollama-provider.js'))).listOllamaModels({ host: opts.host }));
  const r = await list();
  if (!r.ok) throw new Error(`Ollama is not reachable at ${opts.host} (${r.code || 'error'}: ${r.reason || ''}); start it with \`ollama serve\``);
  const m = (r.models || []).find((x) => x.name === opts.model || x.name === `${opts.model}:latest`);
  if (!m) throw new Error(`model ${opts.model} is not installed in Ollama (installed: ${(r.models || []).map((x) => x.name).join(', ') || 'none'})`);
  if (m.remoteHost || /(?:^|[:-])cloud$/i.test(m.name)) throw new Error(`model ${m.name} is served from a remote host (${m.remoteHost || 'cloud tag'}); it would send benchmark code off this machine`);
  return {
    provider: 'ollama', modelEndpointMode: 'loopback', host: opts.host,
    model: m.name, modelDigest: m.digest || null, parameterSize: m.parameterSize || null, quantization: m.quantization || null,
    budgetMs: opts.budgetMs,
    selection: 'product defaults: selectHuntFiles, runDiscovery focus areas, all lenses, call and candidate ceilings; no label input',
  };
}

function summarise(report, extra) {
  const c = report?.coverage || {};
  const runs = report?.runs || [];
  return {
    ...extra,
    focusAreas: c.areasPlanned ?? 0,
    hunterRuns: runs.length,
    degradedRuns: c.degradedRuns ?? 0,
    unparseableRuns: runs.filter((r) => r.reason === 'hunter output was not parseable JSON').length,
    proposed: runs.reduce((n, r) => n + (r.candidateCount || 0), 0),
    citationsDiscarded: c.citationsDiscarded ?? 0,
    candidatesCapped: c.candidatesCapped ?? 0,
    confirmedByTier: c.confirmedByTier || null,
    panelsRun: c.panelsRun ?? 0,
    undecidedPanels: c.undecidedPanels ?? 0,
    refuted: (report?.refutedCandidates || []).length,
    duplicatesOfDeterministic: (report?.duplicates || []).length,
    fresh: (report?.fresh || []).length,
    // A fresh finding whose refutation panel cast no vote (an exhausted budget or a dead model) survived by default, not on
    // scrutiny; the product reports it all the same, and so does this measurement, but the count travels with the row.
    freshUnvetted: (report?.fresh || []).filter((f) => f?.discovery?.refutation?.undecided === true).length,
    freshByTier: (report?.fresh || []).reduce((o, f) => { const t = f?.discovery?.confirmation?.tier || 'unconfirmed'; o[t] = (o[t] || 0) + 1; return o; }, {}),
    llmCalls: c.llmCalls ?? 0,
    maxLlmCalls: c.maxLlmCalls ?? null,
    budgetExhausted: Boolean(c.budgetExhausted),
    reasons: (c.reasons || []).slice(0, 20),
  };
}

/**
 * Discovery over one tree. `deterministicFindings` play the role of the CLI's prior scan (a hunt never re-reports what the
 * rule engine found). Returns `{ findings, summary }`; `summary.complete` is false whenever any part of the product's own
 * pipeline did not run to the end (budget, hard stop, degraded runs, file cap).
 */
export async function discoverTree(dir, deterministicFindings, opts, { runDiscoveryImpl = null, now = Date.now, graceMs = null } = {}) {
  const startedAt = now();
  const discovery = await import(SRC('discovery/index.js'));
  const run = runDiscoveryImpl || discovery.runDiscovery;
  const before = snapshotTree(dir);
  const sel = await discovery.selectHuntFiles(dir);
  if (sel.overCap) {
    return { findings: [], summary: { complete: false, skipped: `over the product's ${sel.maxFiles}-file hunt cap (${sel.rels.length} files); the CLI refuses this scope`, filesSelected: sel.rels.length, durationMs: now() - startedAt } };
  }
  const { buildProjectIR } = await import(SRC('ir/index.js'));
  const { perFile, callGraph } = buildProjectIR(sel.fileContents);
  let timedOut = false;
  let report = null;
  let error = null;
  await withScopedEnv(discoveryEnv(opts), async () => {
    let timer;
    const hardStop = new Promise((resolve) => { timer = setTimeout(() => { timedOut = true; resolve(null); }, opts.budgetMs + (graceMs ?? hardStopGraceMs(opts.budgetMs))); });
    try {
      report = await Promise.race([
        run({ perFileIR: perFile, callGraph, fileContents: sel.fileContents, priorScan: { findings: deterministicFindings || [] }, triageFeedback: null },
          { maxWallMs: opts.budgetMs }),
        hardStop,
      ]);
    } catch (e) { error = e?.message || String(e); } finally { clearTimeout(timer); }
  });
  assertTreeUnchanged(before, snapshotTree(dir), `discovery over ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  const findings = (report?.fresh || []).filter((f) => !String(f.file || '').includes('.agentic-security'));
  const summary = summarise(report, { filesSelected: sel.rels.length, durationMs: now() - startedAt, timedOut, error });
  summary.complete = !timedOut && !error && !summary.budgetExhausted && summary.degradedRuns === 0 && summary.candidatesCapped === 0;
  return { findings, summary };
}

/** Report-level accounting over every row's discovery summaries. */
export function discoveryTotals(rows) {
  const trees = rows.flatMap((r) => (r.discovery ? [r.discovery.pre, r.discovery.post] : [])).filter(Boolean);
  const sum = (k) => trees.reduce((n, t) => n + (Number(t[k]) || 0), 0);
  return {
    trees: trees.length,
    incompleteTrees: trees.filter((t) => !t.complete).length,
    budgetExhaustedTrees: trees.filter((t) => t.budgetExhausted).length,
    timedOutTrees: trees.filter((t) => t.timedOut).length,
    entriesWithIncompleteDiscovery: rows.filter((r) => r.discovery && (!r.discovery.pre?.complete || !r.discovery.post?.complete)).length,
    hunterRuns: sum('hunterRuns'), unparseableRuns: sum('unparseableRuns'), degradedRuns: sum('degradedRuns'),
    proposed: sum('proposed'), refuted: sum('refuted'), fresh: sum('fresh'), freshUnvetted: sum('freshUnvetted'), llmCalls: sum('llmCalls'),
    filesSelected: sum('filesSelected'), durationMs: sum('durationMs'),
    meaning: 'an incomplete tree was scored with the findings discovery produced before it stopped; it is not a clean result',
  };
}
