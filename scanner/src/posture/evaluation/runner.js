// Reproducible evaluation runs and layer ablations (QA-003).
//
// A run executes the engine over the protocol's pinned targets and records, for
// every target and variant, the outcome (completed / timeout / error /
// unavailable / quarantined), its findings, timing, cost, failure reason and the
// hashes of what went in and what came out. Nothing is dropped: a target that
// timed out is a recorded outcome, and scoring (score.js) counts it as a MISS
// when a known positive sat behind it.
//
// Run identity covers everything that can change a result: protocol hash, engine
// and bundle, layer configuration, provider/model/settings/cache, budget, seed,
// replicate, split, and the digests of the targets themselves. Change any one and
// the id changes, so two runs are never confused or silently merged.
//
// The engine never sees labels: this module receives workspace directories only,
// stages them through custody.js (which audits and quarantines), and runs the
// scan in a child process under a scrubbed environment.

import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SCHEMA_VERSION } from '../assurance/schema-kit.js';
import { digestOf } from '../assurance/identity.js';
import { STATE_DIR_NAME } from '../state-dir.js';
import { validateProtocol } from './protocol.js';
import { stageWorkspace, engineEnvironment } from './custody.js';
import { RESULT_BEGIN, RESULT_END, LAYER_ENV } from './scan-child.js';

const RUN_SCHEMA = 'agentic-security/evaluation-run';
export const ABLATION_LAYERS = Object.freeze(Object.keys(LAYER_ENV));
const OUTCOME_STATUSES = Object.freeze(['completed', 'timeout', 'error', 'unavailable', 'quarantined']);
const SCAN_CHILD = path.join(path.dirname(fileURLToPath(import.meta.url)), 'scan-child.js');
const SKIP = new Set(['.git', STATE_DIR_NAME, 'node_modules']);

/** Content digest of a directory tree: sorted relative paths plus bytes. Symlinks are hashed by target, never followed. */
export function digestTree(dir, { maxFiles = 50000 } = {}) {
  const h = crypto.createHash('sha256');
  let n = 0;
  const walk = (d, rel) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const r = rel ? `${rel}/${e.name}` : e.name;
      const full = path.join(d, e.name);
      if (e.isSymbolicLink()) { h.update(`L:${r}:${fs.readlinkSync(full)}\n`); continue; }
      if (e.isDirectory()) { if (!SKIP.has(e.name)) walk(full, r); continue; }
      if (!e.isFile()) continue;
      if (++n > maxFiles) throw new Error(`digestTree: more than ${maxFiles} files`);
      h.update(`F:${r}:${fs.statSync(full).size}\n`);
      h.update(fs.readFileSync(full));
    }
  };
  walk(dir, '');
  return `sha256:${h.digest('hex')}`;
}

/** The digest a protocol pins for one target: both variants' trees. */
export function targetDigestOf({ pre, post }) { return digestOf({ pre: pre ?? null, post: post ?? null }); }

const keyOf = (o) => digestOf(o);

/** Everything that can change a run's results. Labels are deliberately absent: the engine never sees them. */
export function runIdentityMaterial({ protocol, config, budget, split, replicate = 0, targetDigests }) {
  return {
    protocolHash: protocol.protocolHash,
    engine: protocol.engine,
    config: {
      layer: config.layer, provider: config.provider ?? null, model: config.model ?? null,
      settings: config.settings ?? {}, cache: config.cache ?? { mode: 'none' }, seed: config.seed ?? null,
    },
    budget, split, replicate,
    targets: Object.fromEntries(Object.entries(targetDigests).sort(([a], [b]) => a.localeCompare(b))),
  };
}
export const runIdentity = (m) => `erun:${keyOf({ kind: 'evaluation-run', ...runIdentityMaterial(m) }).slice('sha256:'.length, 'sha256:'.length + 20)}`;
/** Same as the run id but with the replicate left out: the id of the experiment replicates belong to. */
const experimentIdentity = (m) => `eexp:${keyOf({ kind: 'evaluation-experiment', ...runIdentityMaterial({ ...m, replicate: 0 }) }).slice('sha256:'.length, 'sha256:'.length + 20)}`;

// ---------------------------------------------------------------- the default scan function

/**
 * Run one engine scan in a child process. The child is killed (whole process
 * group) when the timeout expires. Returns `{ findings }` or throws an Error whose
 * `code` is TIMEOUT, UNAVAILABLE or ERROR.
 */
export function defaultScanFn(workspaceDir, { layer, timeoutMs, env, diagnose = false, childPath = SCAN_CHILD }) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [childPath, workspaceDir, layer, ...(diagnose ? ['diagnose'] : [])], { env, cwd: workspaceDir, detached: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = ''; let err = ''; let done = false;
    const cap = 64 * 1024 * 1024;
    const fail = (code, message) => { if (done) return; done = true; clearTimeout(timer); const e = new Error(message); e.code = code; reject(e); };
    const timer = setTimeout(() => {
      try { process.kill(-child.pid, 'SIGKILL'); } catch { try { child.kill('SIGKILL'); } catch { /* gone */ } }
      fail('TIMEOUT', `no result within ${timeoutMs} ms`);
    }, timeoutMs);
    child.stdout.on('data', (b) => { if (out.length < cap) out += b; });
    child.stderr.on('data', (b) => { if (err.length < 65536) err += b; });
    child.on('error', (e) => fail('ERROR', e.message));
    child.on('close', (code) => {
      if (done) return;
      if (code === 3) return fail('UNAVAILABLE', err.trim().slice(0, 300) || 'layer unavailable');
      if (code !== 0) return fail('ERROR', `scan exited ${code}: ${err.trim().slice(-300)}`);
      const a = out.indexOf(RESULT_BEGIN); const b = out.indexOf(RESULT_END);
      if (a < 0 || b < a) return fail('ERROR', 'scan produced no result block');
      try { done = true; clearTimeout(timer); resolve(JSON.parse(out.slice(a + RESULT_BEGIN.length, b))); } catch (e) { done = false; fail('ERROR', `unreadable result: ${e.message}`); }
    });
  });
}

const sortFindings = (fs_) => [...fs_].sort((x, y) => `${x.file}|${x.line}|${x.family}|${x.cwe}|${x.id}`.localeCompare(`${y.file}|${y.line}|${y.family}|${y.cwe}|${y.id}`));

function emptyOutcome(targetId, variant, status, failureReason, extra = {}) {
  return { targetId, variant, status, findings: [], durationMs: 0, costUsd: null, costSource: 'unmeasured', failureReason, inputHash: null, outputHash: digestOf([]), cached: false, ...extra };
}

/**
 * Execute one configuration over the protocol's targets.
 *
 * @param {object}   o
 * @param {object}   o.protocol        a frozen, valid protocol
 * @param {object}   o.config          { layer, provider?, model?, settings?, cache?, seed? }
 * @param {Function} o.resolveTarget   (target, variant) => { dir } | { unavailable: reason }
 * @param {Function} [o.scanFn]        (workspace, { layer, timeoutMs, seed, env }) => { findings, costUsd? }
 * @param {string[]} [o.protectedTerms] terms that must not appear in an engine workspace
 * @param {'dev'|'sealed'|'all'} [o.split]
 * @param {boolean}  [o.allowSealed]   required to touch sealed targets (the custodian's call)
 * @param {Map}      [o.cache]         outcome cache, keyed by every semantically relevant input
 */
export async function runEvaluation(o) {
  const { protocol, config, resolveTarget, scanFn = defaultScanFn, protectedTerms = [], split = 'dev', allowSealed = false, cache = null, replicate = 0, workRoot, now = Date.now } = o;
  const v = validateProtocol(protocol);
  if (!v.ok) return { ok: false, errors: v.errors, run: null };
  if (!ABLATION_LAYERS.includes(config?.layer)) return { ok: false, errors: [{ code: 'UNKNOWN_ENUM', path: 'config.layer', message: `layer must be one of ${ABLATION_LAYERS.join(', ')}` }], run: null };
  if ((split === 'sealed' || split === 'all') && !allowSealed) {
    return { ok: false, errors: [{ code: 'SEALED_ACCESS', path: 'split', message: 'only the evaluation custodian may run the sealed split (allowSealed)' }], run: null };
  }
  const wanted = new Set(split === 'all' ? [...protocol.splits.dev, ...protocol.splits.sealed] : protocol.splits[split] || []);
  const targets = protocol.targets.filter((t) => wanted.has(t.id)).sort((a, b) => a.id.localeCompare(b.id));
  const budget = { perTargetTimeoutMs: protocol.limits.perTargetTimeoutMs, spendCeilingUsd: protocol.limits.spendCeilingUsd };
  const cfg = { ...config, seed: config.seed ?? null };

  const ownRoot = !workRoot;
  const root = workRoot || fs.mkdtempSync(path.join(os.tmpdir(), 'eval-run-'));
  const outcomes = []; const targetDigests = {};
  let spent = 0;
  try {
    for (const t of targets) {
      const variants = t.postCommit ? ['pre', 'post'] : ['pre'];
      const resolved = {}; const digests = {};
      for (const variant of variants) {
        const r = await resolveTarget(t, variant);
        resolved[variant] = r;
        if (r?.dir) { try { digests[variant] = digestTree(r.dir); } catch (e) { resolved[variant] = { unavailable: `digest failed: ${e.message}` }; } }
      }
      const allResolved = variants.every((vn) => resolved[vn]?.dir);
      const combined = allResolved ? targetDigestOf({ pre: digests.pre, post: digests.post ?? null }) : null;
      // `targetDigests` carries the pinned digest even when the tree is unavailable, so identity is stable.
      targetDigests[t.id] = combined || t.digest;
      for (const variant of variants) {
        const base = { targetId: t.id, variant };
        if (!resolved[variant]?.dir) { outcomes.push(emptyOutcome(t.id, variant, 'unavailable', resolved[variant]?.unavailable || 'target could not be resolved')); continue; }
        if (combined !== t.digest) { outcomes.push(emptyOutcome(t.id, variant, 'unavailable', 'target-digest-mismatch: the tree does not match the digest pinned in the protocol')); continue; }
        const inputHash = digestOf({ digest: digests[variant], layer: cfg.layer, budget, seed: cfg.seed, replicate, engine: protocol.engine, provider: cfg.provider ?? null, model: cfg.model ?? null, settings: cfg.settings ?? {}, cache: cfg.cache ?? { mode: 'none' } });
        if (cache && cfg.cache?.mode === 'enabled' && cache.has(inputHash)) { outcomes.push({ ...cache.get(inputHash), ...base, cached: true }); continue; }
        if (spent >= budget.spendCeilingUsd && budget.spendCeilingUsd > 0 && cfg.layer === 'model-assisted') {
          outcomes.push(emptyOutcome(t.id, variant, 'error', 'spend-ceiling-reached', { inputHash })); continue;
        }
        const staged = stageWorkspace({ srcDir: resolved[variant].dir, destDir: path.join(root, `${t.id}-${variant}`.replace(/[^\w.-]/g, '_')), terms: protectedTerms });
        if (!staged.ok) { outcomes.push(emptyOutcome(t.id, variant, 'quarantined', `leakage control: ${staged.leaks.map((l) => `${l.kind}${l.file ? `@${l.file}` : ''}`).join(', ')}`, { inputHash })); continue; }
        const env = engineEnvironment({ PATH: process.env.PATH, LANG: 'C', HOME: root, ...(cfg.layer === 'model-assisted' ? pickLlmEnv(process.env) : {}) });
        const t0 = now();
        try {
          const res = await scanFn(staged.destDir, { layer: cfg.layer, timeoutMs: budget.perTargetTimeoutMs, seed: cfg.seed, env });
          const findings = sortFindings(res?.findings || []);
          const cost = typeof res?.costUsd === 'number' ? res.costUsd : null;
          if (cost) spent += cost;
          const oc = { ...base, status: 'completed', findings, durationMs: now() - t0, costUsd: cost, costSource: cost === null ? 'unmeasured' : 'reported-by-scan', failureReason: null, inputHash, outputHash: digestOf(findings), cached: false };
          if (cache && cfg.cache?.mode === 'enabled') cache.set(inputHash, oc);
          outcomes.push(oc);
        } catch (e) {
          const status = e?.code === 'TIMEOUT' ? 'timeout' : e?.code === 'UNAVAILABLE' ? 'unavailable' : 'error';
          outcomes.push(emptyOutcome(t.id, variant, status, String(e?.message || e).slice(0, 400), { durationMs: now() - t0, inputHash }));
        } finally {
          fs.rmSync(staged.destDir, { recursive: true, force: true });
        }
      }
    }
  } finally {
    if (ownRoot) fs.rmSync(root, { recursive: true, force: true });
  }
  const material = { protocol, config: cfg, budget, split, replicate, targetDigests };
  const totals = Object.fromEntries(OUTCOME_STATUSES.map((s) => [s, outcomes.filter((x) => x.status === s).length]));
  const run = {
    schema: RUN_SCHEMA, schemaVersion: SCHEMA_VERSION,
    runId: runIdentity(material), experimentId: experimentIdentity(material),
    protocolHash: protocol.protocolHash, engine: protocol.engine, split, replicate,
    config: runIdentityMaterial(material).config, budget,
    targetSetDigest: digestOf(runIdentityMaterial(material).targets),
    sealedTargetIds: split === 'dev' ? [] : targets.filter((t) => protocol.splits.sealed.includes(t.id)).map((t) => t.id),
    outcomes, totals, totalCostUsd: outcomes.reduce((s, x) => s + (x.costUsd || 0), 0),
    rawHash: digestOf(outcomes.map((x) => ({ t: x.targetId, v: x.variant, s: x.status, o: x.outputHash }))),
  };
  return { ok: true, errors: [], run };
}

function pickLlmEnv(env) {
  const out = {};
  for (const [k, v] of Object.entries(env)) if (/^AGENTIC_SECURITY_LLM_/.test(k)) out[k] = v;
  return out;
}

/**
 * Replicates of one configuration. Deterministic layers must reproduce their
 * output hashes exactly; the model-assisted layer is stochastic and needs at
 * least three replicates with recorded seeds, or the result is invalid.
 */
export async function runReplicates({ n = 1, seedSupported = false, ...rest }) {
  const stochastic = rest.config?.layer === 'model-assisted';
  const runs = [];
  for (let i = 0; i < n; i++) {
    const config = { ...rest.config, seed: seedSupported ? (rest.config.seed ?? 0) + i : (rest.config.seed ?? null) };
    const r = await runEvaluation({ ...rest, config, replicate: i });
    if (!r.ok) return { ok: false, errors: r.errors, runs, valid: false, reasons: ['run rejected'] };
    runs.push(r.run);
  }
  const reasons = [];
  if (stochastic && n < 3) reasons.push(`a stochastic configuration needs at least 3 measured replicates, got ${n}`);
  if (stochastic && !seedSupported) reasons.push('seeds are not supported by this provider; replicate variance is recorded without a seed');
  const differing = [];
  if (n >= 2) {
    const first = runs[0];
    for (const o of first.outcomes) {
      const hashes = runs.map((r) => r.outcomes.find((x) => x.targetId === o.targetId && x.variant === o.variant)?.outputHash);
      if (new Set(hashes).size > 1) differing.push(`${o.targetId}/${o.variant}`);
    }
  }
  const determinism = n < 2 ? { checked: false, identical: null, differing: [] } : { checked: true, identical: differing.length === 0, differing };
  if (!stochastic && determinism.checked && !determinism.identical) reasons.push(`deterministic configuration produced different output across replicates: ${differing.join(', ')}`);
  return { ok: true, errors: [], runs, stochastic, determinism, valid: reasons.filter((x) => !x.startsWith('seeds are not supported')).length === 0, reasons };
}

/**
 * Run every layer over identical targets, matching policy and ceilings. Only the
 * layer differs between configurations; anything else that differs is refused.
 */
export async function runAblations({ layers = ABLATION_LAYERS, config = {}, ...rest }) {
  const runs = [];
  for (const layer of layers) {
    const r = await runEvaluation({ ...rest, config: { ...config, layer } });
    if (!r.ok) return { ok: false, errors: r.errors, runs };
    runs.push(r.run);
  }
  const cmp = assertAblationComparable(runs);
  return { ok: cmp.ok, errors: cmp.errors, runs, comparable: cmp.ok };
}

/** Ablations are comparable only if protocol, split, target set and budget are identical and only the layer differs. */
export function assertAblationComparable(runs) {
  const errors = [];
  const [a, ...others] = runs || [];
  if (!a) return { ok: false, errors: [{ code: 'MISSING_FIELD', path: 'runs', message: 'no runs to compare' }] };
  for (const r of others) {
    for (const [field, same] of [
      ['protocolHash', r.protocolHash === a.protocolHash], ['split', r.split === a.split],
      ['targetSetDigest', r.targetSetDigest === a.targetSetDigest], ['budget', digestOf(r.budget) === digestOf(a.budget)],
      ['config.provider', r.config.provider === a.config.provider], ['config.model', r.config.model === a.config.model],
      ['config.settings', digestOf(r.config.settings) === digestOf(a.config.settings)], ['config.cache', digestOf(r.config.cache) === digestOf(a.config.cache)],
    ]) if (!same) errors.push({ code: 'ABLATION_MISMATCH', path: field, message: `${r.config.layer} differs from ${a.config.layer} in ${field}; ablations may differ only in layer` });
    if (r.runId === a.runId) errors.push({ code: 'DUPLICATE_ID', path: 'runId', message: 'two ablations share a run identity' });
  }
  return { ok: errors.length === 0, errors };
}
