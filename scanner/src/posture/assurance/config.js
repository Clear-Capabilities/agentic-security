// Unified configuration for the assurance features (CORE-004).
//
// Extends the configuration mechanism the scanner already has instead of adding
// a second one:
//   - environment variables, `AGENTIC_SECURITY_*` (docs/reference/configuration.md),
//     including the existing `AGENTIC_SECURITY_NO_<NAME>=1` kill-switch shape;
//   - a per-project YAML file under `.agentic-security/` read through
//     posture/state-dir.js and util/yaml.js, exactly as egress-policy.yml is.
//
// Precedence, highest first. A higher level always wins over a lower one, and the
// result says which level decided:
//   1. kill switch   AGENTIC_SECURITY_NO_ASSURANCE=1 (all) or AGENTIC_SECURITY_NO_<FEATURE>=1
//   2. overrides     explicit options from the caller (CLI flags)
//   3. environment   AGENTIC_SECURITY_ASSURANCE_<FEATURE>=1|0
//   4. project file  .agentic-security/assurance.yml
//   5. default       every new feature defaults to OFF
//
// Two rules that follow from the trust model:
//   - HIGH-RISK EXECUTION IS OPERATOR-ONLY. The project file lives inside the
//     scanned repository, which is hostile input. A project file can never switch
//     on a feature whose risk class is `high-risk-execution`; only the
//     environment or an explicit override can. The refusal is disclosed, not silent.
//   - INVALID CONFIGURATION FAILS CLOSED. An unknown feature, a non-boolean, or a
//     limit that is not a finite number within its ceiling leaves that feature
//     disabled and is reported in `errors`. It never falls through to a default
//     that is more permissive than what the operator wrote.
//
// A disabled feature is inert: nothing in this module touches the scan or report
// pipeline, so default behaviour is unchanged.

import * as fs from 'node:fs';
import { statePath } from '../state-dir.js';
import { load as loadYaml } from '../../util/yaml.js';

export const CONFIG_FILE = 'assurance.yml';
export const CONFIG_VERSION = 1;

export const RISK_CLASSES = Object.freeze(['passive', 'model-network', 'high-risk-execution']);

// Every new feature. `platforms` is the set where the feature is supported at all;
// off it the result is a typed `unsupported`, with the note disclosed.
export const FEATURES = Object.freeze({
  'verification-oracles': {
    risk: 'high-risk-execution', platforms: ['linux', 'darwin'],
    platformNote: 'runtime oracles run through the confinement sandbox; isolation-required checks are only advertised on Linux',
  },
  'patch-negative-verification': {
    risk: 'high-risk-execution', platforms: ['linux', 'darwin'],
    platformNote: 'replays the exploit against the original and the patched revision through the confinement sandbox, so it needs verification-oracles as well; an unproved isolation control blocks it',
  },
  'deployment-boundaries': { risk: 'passive', platforms: ['linux', 'darwin', 'win32'], platformNote: null },
  'invariant-scenarios': {
    risk: 'high-risk-execution', platforms: ['linux', 'darwin'],
    platformNote: 'stateful scenarios execute target code and need the confinement sandbox',
  },
  'capability-enforcement': {
    risk: 'high-risk-execution', platforms: ['linux'],
    platformNote: 'runner-level filesystem, network and process enforcement is only advertised on Linux; macOS can supervise but not enforce',
  },
  'model-routing': { risk: 'model-network', platforms: ['linux', 'darwin', 'win32'], platformNote: null },
  'portfolio-assurance': { risk: 'passive', platforms: ['linux', 'darwin', 'win32'], platformNote: null },
});

// Finite limits with hard ceilings. `enforcedBy` names the helper in THIS module
// that actually enforces it; `null` means this layer only carries the number for
// a runner to enforce, and the disclosure says so rather than claiming otherwise.
export const LIMITS = Object.freeze({
  timeoutMs: { default: 15_000, min: 1, max: 120_000, enforcedBy: 'withDeadline' },
  retries: { default: 2, min: 0, max: 5, enforcedBy: 'retryBounded' },
  maxOutputBytes: { default: 262_144, min: 1, max: 16 * 1024 * 1024, enforcedBy: 'capOutput' },
  maxRequestBytes: { default: 262_144, min: 1, max: 16 * 1024 * 1024, enforcedBy: 'guardedModelCall' },
  maxFileBytes: { default: 5 * 1024 * 1024, min: 1, max: 64 * 1024 * 1024, enforcedBy: 'readFileBounded' },
  maxMemoryMiB: { default: 6144, min: 64, max: 65_536, enforcedBy: null },
});

const FEATURE_IDS = Object.keys(FEATURES);
const envName = (id) => id.toUpperCase().replace(/-/g, '_');

function parseBool(raw) {
  if (raw === true || raw === '1' || raw === 'true') return true;
  if (raw === false || raw === '0' || raw === 'false') return false;
  return undefined;
}

function checkLimits(limits, where, errors) {
  const out = {};
  if (limits === undefined || limits === null) return out;
  if (typeof limits !== 'object' || Array.isArray(limits)) { errors.push({ code: 'invalid-config', path: where, message: 'limits must be a mapping' }); return null; }
  let bad = false;
  for (const [k, v] of Object.entries(limits)) {
    const spec = LIMITS[k];
    if (!spec) { errors.push({ code: 'invalid-config', path: `${where}.${k}`, message: `unknown limit '${k}'` }); bad = true; continue; }
    if (typeof v !== 'number' || !Number.isFinite(v) || !Number.isInteger(v)) { errors.push({ code: 'invalid-config', path: `${where}.${k}`, message: 'must be a finite integer' }); bad = true; continue; }
    if (v < spec.min || v > spec.max) { errors.push({ code: 'invalid-config', path: `${where}.${k}`, message: `must be between ${spec.min} and ${spec.max}` }); bad = true; continue; }
    out[k] = v;
  }
  return bad ? null : out;
}

function readProjectFile(scanRoot, readFile, errors) {
  let fp;
  try { fp = statePath(scanRoot, CONFIG_FILE); } catch { return null; }
  let raw;
  try { raw = readFile(fp); } catch { return null; } // absent file is the normal case
  let doc;
  try { doc = loadYaml(raw); } catch (e) {
    errors.push({ code: 'invalid-config', path: CONFIG_FILE, message: `not valid YAML: ${String(e.message).split('\n')[0]}` });
    return { broken: true };
  }
  if (doc === undefined) return { features: {}, limits: {} };
  if (typeof doc !== 'object' || Array.isArray(doc)) { errors.push({ code: 'invalid-config', path: CONFIG_FILE, message: 'must be a mapping' }); return { broken: true }; }
  for (const k of Object.keys(doc)) {
    if (!['version', 'features', 'limits'].includes(k)) errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.${k}`, message: `unknown key '${k}'` });
  }
  if (doc.version !== undefined && doc.version !== CONFIG_VERSION) {
    errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.version`, message: `unsupported version ${JSON.stringify(doc.version)} (supported: ${CONFIG_VERSION})` });
    return { broken: true };
  }
  return doc;
}

/**
 * Resolve the effective configuration.
 *
 * @param {object} [opts]
 * @param {string} [opts.scanRoot]
 * @param {object} [opts.env]       defaults to process.env
 * @param {object} [opts.overrides] `{ features: {id: bool}, limits: {...} }` from explicit flags
 * @param {string} [opts.platform]  defaults to process.platform
 * @param {(p:string)=>string} [opts.readFile]
 */
export function resolveAssuranceConfig({ scanRoot, env = process.env, overrides = {}, platform = process.platform, readFile = (p) => fs.readFileSync(p, 'utf8') } = {}) {
  const errors = [];
  const file = readProjectFile(scanRoot, readFile, errors);
  const fileOk = file && !file.broken ? file : null;
  const globalKill = env.AGENTIC_SECURITY_NO_ASSURANCE === '1';

  const fileFeatures = (fileOk && fileOk.features && typeof fileOk.features === 'object' && !Array.isArray(fileOk.features)) ? fileOk.features : {};
  if (fileOk && fileOk.features !== undefined && fileFeatures !== fileOk.features) errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.features`, message: 'must be a mapping' });
  for (const id of Object.keys(fileFeatures)) {
    if (!FEATURES[id]) errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.features.${id}`, message: `unknown feature '${id}'` });
  }

  const features = {};
  for (const id of FEATURE_IDS) {
    const spec = FEATURES[id];
    const entry = { id, risk: spec.risk, enabled: false, source: 'default', reason: 'default: off', killed: false, notes: [] };
    let invalid = false;

    // 5/4: project file
    const fe = fileFeatures[id];
    if (fe !== undefined) {
      if (typeof fe !== 'object' || fe === null || Array.isArray(fe)) { errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.features.${id}`, message: 'must be a mapping' }); invalid = true; }
      else {
        for (const k of Object.keys(fe)) if (!['enabled', 'limits'].includes(k)) { errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.features.${id}.${k}`, message: `unknown key '${k}'` }); invalid = true; }
        if (fe.enabled !== undefined) {
          const b = parseBool(fe.enabled);
          if (typeof fe.enabled !== 'boolean') { errors.push({ code: 'invalid-config', path: `${CONFIG_FILE}.features.${id}.enabled`, message: 'must be true or false' }); invalid = true; }
          else if (b && spec.risk === 'high-risk-execution') {
            entry.notes.push('project file requested enablement; refused: high-risk execution can only be enabled by the operator through the environment or an explicit option');
            entry.source = 'project-file-refused'; entry.reason = 'high-risk execution cannot be enabled by a project file';
          } else { entry.enabled = b; entry.source = 'project-file'; entry.reason = `project file sets enabled=${b}`; }
        }
      }
    }
    // 3: environment
    const rawEnv = env[`AGENTIC_SECURITY_ASSURANCE_${envName(id)}`];
    if (rawEnv !== undefined && rawEnv !== '') {
      const b = parseBool(rawEnv);
      if (b === undefined) { errors.push({ code: 'invalid-config', path: `AGENTIC_SECURITY_ASSURANCE_${envName(id)}`, message: `must be 1/true or 0/false, got ${JSON.stringify(rawEnv)}` }); invalid = true; }
      else { entry.enabled = b; entry.source = 'env'; entry.reason = `environment sets enabled=${b}`; }
    }
    // 2: explicit overrides
    const ov = overrides.features?.[id];
    if (ov !== undefined) {
      if (typeof ov !== 'boolean') { errors.push({ code: 'invalid-config', path: `overrides.features.${id}`, message: 'must be a boolean' }); invalid = true; }
      else { entry.enabled = ov; entry.source = 'override'; entry.reason = `explicit option sets enabled=${ov}`; }
    }
    // invalid configuration fails closed
    if (invalid) { entry.enabled = false; entry.source = 'invalid-config'; entry.reason = 'configuration for this feature is invalid; disabled'; }
    // 1: kill switch
    if (globalKill || env[`AGENTIC_SECURITY_NO_${envName(id)}`] === '1') {
      entry.enabled = false; entry.killed = true; entry.source = 'kill-switch';
      entry.reason = globalKill ? 'AGENTIC_SECURITY_NO_ASSURANCE=1' : `AGENTIC_SECURITY_NO_${envName(id)}=1`;
    }
    // platform disclosure
    const supported = spec.platforms.includes(platform);
    entry.platform = { supported, platform, note: spec.platformNote, supportedPlatforms: [...spec.platforms] };
    features[id] = entry;
  }

  // limits: file -> overrides, each validated; a bad level is dropped whole
  const limits = {};
  for (const [k, spec] of Object.entries(LIMITS)) limits[k] = { value: spec.default, source: 'default', enforcedBy: spec.enforcedBy };
  const apply = (obj, source, where) => {
    const ok = checkLimits(obj, where, errors);
    if (!ok) return;
    for (const [k, v] of Object.entries(ok)) limits[k] = { value: v, source, enforcedBy: LIMITS[k].enforcedBy };
  };
  if (fileOk) apply(fileOk.limits, 'project-file', `${CONFIG_FILE}.limits`);
  apply(overrides.limits, 'override', 'overrides.limits');

  return { version: CONFIG_VERSION, features, limits, errors, killSwitch: globalKill };
}

/** Plain numeric limits for a caller that only wants the numbers. */
export function limitValues(config) {
  return Object.fromEntries(Object.entries(config.limits).map(([k, v]) => [k, v.value]));
}

// ---------------------------------------------------------------- typed results

export const RESULT_STATUSES = Object.freeze(['ok', 'disabled', 'blocked', 'unsupported', 'degraded']);
export const RESULT_CODES = Object.freeze([
  'disabled', 'kill-switch', 'platform-unsupported', 'invalid-config', 'egress-denied', 'limit-exceeded', 'timeout',
  'missing-provider', 'missing-credential', 'missing-collector', 'missing-execution-backend', 'missing-dependency',
]);

export function typed(status, code, reason, extra = {}) {
  return { status, code, reason, ...extra };
}

/** The gate every new feature passes through. Never throws, never prompts, never reaches the network. */
export function featureStatus(config, id) {
  const f = config?.features?.[id];
  if (!f) return typed('blocked', 'invalid-config', `unknown feature '${id}'`);
  if (f.killed) return typed('blocked', 'kill-switch', f.reason, { feature: id });
  if (f.source === 'invalid-config') return typed('blocked', 'invalid-config', f.reason, { feature: id });
  if (!f.enabled) return typed('disabled', 'disabled', f.reason, { feature: id });
  if (!f.platform.supported) {
    return typed('unsupported', 'platform-unsupported', `${id} is not supported on ${f.platform.platform}${f.platform.note ? `: ${f.platform.note}` : ''}`, { feature: id, supportedPlatforms: f.platform.supportedPlatforms });
  }
  return typed('ok', null, f.reason, { feature: id });
}

const REQUIREMENT_KINDS = Object.freeze({
  provider: 'missing-provider',
  credential: 'missing-credential',
  collector: 'missing-collector',
  'execution-backend': 'missing-execution-backend',
  dependency: 'missing-dependency',
});

/** A credential requirement that only checks that an environment variable is set. Never prompts, never reads its value into a result. */
export function envPresent(name, env = process.env) {
  return () => typeof env[name] === 'string' && env[name].length > 0;
}

/**
 * Evaluate declared requirements. A missing REQUIRED one blocks; a missing
 * OPTIONAL one degrades. A probe that throws counts as missing. No requirement is
 * ever satisfied by a fallback, a prompt or a cloud default.
 *
 * requirements: [{ kind, name, optional?, present: () => boolean }]
 */
export function evaluateRequirements(requirements = []) {
  const missingRequired = [];
  const missingOptional = [];
  for (const r of requirements) {
    let present = false;
    try { present = !!r.present(); } catch { present = false; }
    if (present) continue;
    const item = { kind: r.kind, name: r.name, code: REQUIREMENT_KINDS[r.kind] || 'missing-dependency' };
    (r.optional ? missingOptional : missingRequired).push(item);
  }
  return { missingRequired, missingOptional };
}

/**
 * Run `fn` only when the feature is enabled, supported here and its required
 * dependencies are present. Returns a typed result either way; `fn` is never
 * called otherwise. Optional gaps yield `degraded` and `fn` receives them so it
 * can skip that part of its work.
 */
export async function runFeature(config, id, { requirements = [] } = {}, fn) {
  const gate = featureStatus(config, id);
  if (gate.status !== 'ok') return gate;
  const { missingRequired, missingOptional } = evaluateRequirements(requirements);
  if (missingRequired.length) {
    const first = missingRequired[0];
    return typed('blocked', first.code, `${id} needs ${first.kind} '${first.name}', which is not available`, { feature: id, missing: missingRequired });
  }
  const value = await fn({ limits: limitValues(config), missingOptional });
  if (missingOptional.length) return typed('degraded', missingOptional[0].code, `${id} ran without optional ${missingOptional.map(m => `${m.kind} '${m.name}'`).join(', ')}`, { feature: id, missing: missingOptional, value });
  return typed('ok', null, gate.reason, { feature: id, value });
}

/** Operator-readable disclosure of every feature, its state and its platform support. */
export function describeAssuranceConfig(config) {
  return {
    killSwitch: config.killSwitch,
    features: Object.values(config.features).map(f => ({
      id: f.id, risk: f.risk, enabled: f.enabled, source: f.source, reason: f.reason,
      platformSupported: f.platform.supported, platformNote: f.platform.supported ? null : f.platform.note, notes: f.notes,
    })),
    limits: Object.fromEntries(Object.entries(config.limits).map(([k, v]) => [k, { value: v.value, source: v.source, enforced: v.enforcedBy ? `by ${v.enforcedBy}` : 'not enforced by this layer (carried for the runner)' }])),
    errors: config.errors,
  };
}
