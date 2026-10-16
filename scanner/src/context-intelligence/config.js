//
// DCI configuration: `.agentic-security/context-intelligence.json`, operator-authored, never written by the scanner.
//
// `enabled` is false by default and means exactly one thing: DCI is not woven into any other command. The explicit
// `context ...` commands are the opt-in and always work; building and inspecting need no model and no network.
// A model call needs an explicit `context review`, a configured endpoint, and a pass through the egress policy.
// `review.enabled` is reserved for a future automatic integration and is not read by the explicit command.
import * as fs from 'node:fs';
import { statePath } from '../posture/state-dir.js';
import { PROFILES } from './packer.js';
import { ENTRYPOINT_KINDS } from './entrypoints.js';

export const CONFIG_SCHEMA_VERSION = 1;
export const CONFIG_FILE = 'context-intelligence.json';

export const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: CONFIG_SCHEMA_VERSION,
  enabled: false,
  entrypointKinds: ['http'],
  exclude: [],
  maxEntrypoints: 5000,
  maxFiles: 3000,
  semanticMetadata: { mode: 'off', haskellHieDir: null },
  context: { profile: 'standard', maxTokens: null, pruneLowValue: true, maxSymbols: 60, maxDepth: 12 },
  review: { enabled: false, allowRemote: false, questionPacks: ['authz-idor'], concurrency: 2, maxCalls: 100, maxWallSeconds: 900, maxCostUsd: null, maxTokensPerJob: 40000, maxRetries: 3 },
  replay: { contentAddressed: true, retention: 'inherit' },
});

const clamp = (v, lo, hi, d) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, Math.trunc(v))) : d);

/** Validate and normalise a parsed config object. Returns { config, problems }; unknown keys are reported, never silently kept. */
export function normalizeConfig(raw) {
  const problems = [];
  const r = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  const d = DEFAULT_CONFIG;
  if (raw !== undefined && raw !== null && r !== raw) problems.push('config-is-not-an-object');
  if (r.schemaVersion !== undefined && r.schemaVersion !== CONFIG_SCHEMA_VERSION) problems.push(`unsupported-schemaVersion:${r.schemaVersion}`);
  for (const k of Object.keys(r)) if (!Object.hasOwn(d, k)) problems.push(`unknown-key:${k}`);

  const kinds = Array.isArray(r.entrypointKinds) ? r.entrypointKinds.filter(k => ENTRYPOINT_KINDS.includes(k)) : d.entrypointKinds;
  if (Array.isArray(r.entrypointKinds) && kinds.length !== r.entrypointKinds.length) problems.push('unknown-entrypoint-kind');
  const sm = r.semanticMetadata && typeof r.semanticMetadata === 'object' ? r.semanticMetadata : {};
  const cx = r.context && typeof r.context === 'object' ? r.context : {};
  const rv = r.review && typeof r.review === 'object' ? r.review : {};
  const rp = r.replay && typeof r.replay === 'object' ? r.replay : {};
  const mode = ['off', 'import'].includes(sm.mode) ? sm.mode : 'off';
  if (sm.mode !== undefined && mode !== sm.mode) problems.push(`semanticMetadata.mode-not-supported:${sm.mode}`);

  const config = {
    schemaVersion: CONFIG_SCHEMA_VERSION,
    enabled: r.enabled === true,
    entrypointKinds: kinds.length ? [...new Set(kinds)] : d.entrypointKinds,
    exclude: Array.isArray(r.exclude) ? r.exclude.filter(x => typeof x === 'string' && x.length < 300).slice(0, 200) : [],
    maxEntrypoints: clamp(r.maxEntrypoints, 1, 50000, d.maxEntrypoints),
    maxFiles: clamp(r.maxFiles, 1, 20000, d.maxFiles),
    semanticMetadata: { mode, haskellHieDir: typeof sm.haskellHieDir === 'string' ? sm.haskellHieDir : null },
    context: {
      profile: Object.hasOwn(PROFILES, cx.profile) ? cx.profile : d.context.profile,
      maxTokens: Number.isFinite(cx.maxTokens) ? clamp(cx.maxTokens, 1000, 400000, null) : null,
      pruneLowValue: cx.pruneLowValue !== false,
      maxSymbols: clamp(cx.maxSymbols, 5, 400, d.context.maxSymbols),
      maxDepth: clamp(cx.maxDepth, 1, 40, d.context.maxDepth),
    },
    review: {
      enabled: rv.enabled === true,
      allowRemote: rv.allowRemote === true,
      questionPacks: Array.isArray(rv.questionPacks) && rv.questionPacks.length ? rv.questionPacks.filter(x => typeof x === 'string') : d.review.questionPacks,
      concurrency: clamp(rv.concurrency, 1, 16, d.review.concurrency),
      maxCalls: clamp(rv.maxCalls, 1, 5000, d.review.maxCalls),
      maxWallSeconds: clamp(rv.maxWallSeconds, 5, 86400, d.review.maxWallSeconds),
      maxCostUsd: Number.isFinite(rv.maxCostUsd) && rv.maxCostUsd >= 0 ? rv.maxCostUsd : null,
      maxTokensPerJob: clamp(rv.maxTokensPerJob, 1000, 400000, d.review.maxTokensPerJob),
      maxRetries: clamp(rv.maxRetries, 0, 3, d.review.maxRetries),
    },
    replay: { contentAddressed: rp.contentAddressed !== false, retention: typeof rp.retention === 'string' ? rp.retention : 'inherit' },
  };
  return { config, problems };
}

/** Load the config for a project. A missing file is the defaults; a malformed one is reported, and the defaults are used. */
export function loadConfig(root) {
  let raw = null;
  const problems = [];
  try {
    raw = JSON.parse(fs.readFileSync(statePath(root, CONFIG_FILE), 'utf8'));
  } catch (err) {
    if (err && err.code !== 'ENOENT') problems.push('config-unreadable-or-invalid-json');
  }
  const n = normalizeConfig(raw);
  return { config: n.config, problems: [...problems, ...n.problems] };
}
