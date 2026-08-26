// Central egress policy (assurance-hardening PRD FR-601).
//
// Every outbound call this codebase makes to an LLM provider must be
// evaluated HERE before its prompt is constructed and before any network
// client touches the endpoint. A denied call must produce no network
// request and a machine-readable decision object — never a silent no-op
// and never a request that fires anyway with the decision merely logged
// after the fact.
//
// SCOPE (this is FR-601 only, not the fuller FR-602-607 cluster):
//   - A real allow/deny decision, evaluated before prompt construction.
//   - `mode: deny` / `mode: local-only` / provider allow-deny lists as the
//     concrete denial conditions this cycle implements, because FR-601's
//     acceptance criterion ("a denied call results in no network request")
//     requires at least one genuine, testable deny path to exist.
//   - Deliberately NOT in scope here: redaction of the outbound payload
//     (FR-603, already partially done by llm-validator/redact.js for its
//     own path only), and persistent per-call audit records (FR-604). Each
//     remains separate, tracked future work.
//   - FR-602 (provider/model/role/region/repository/path/data-class/
//     max-context constraints) IS in scope as of the FR-602 cycle — see the
//     dimension loop and the path/token checks in evaluateEgress below.
//     Each new dimension is evaluated ONLY when the caller supplies the
//     corresponding ctx value AND the config restricts that dimension —
//     a caller with no opinion on, say, region is never blocked by a
//     region rule it has no way to satisfy or violate. This mirrors the
//     provider dimension's own pre-existing shape (deniedX/allowedX list
//     membership) for model/role/region/repository/data-class; path uses
//     glob matching (util/glob.js's matchesAnyGlob, already used elsewhere
//     in this codebase for ignore-pattern matching) since a single literal
//     string is the wrong shape for a file path constraint; max-context
//     is a numeric cap on an ESTIMATED token count the caller computes
//     itself (evaluateEgress runs before prompt construction, so it has
//     no prompt to measure — the caller must estimate from what it is
//     about to build).
//   - FR-605 (unambiguous local-only mode, anti-URL-smuggling) IS in scope
//     as of the FR-605 cycle: `mode: local-only` here calls the same
//     literal-only `isLoopbackUrl` check `local-endpoint.js` uses for its
//     own preset, and every real HTTP-calling caller in the codebase
//     (llm-validator, discovery/llm-invoke's single- AND consensus-endpoint
//     paths, adversary-agent's own default path, flow-narration,
//     sca/llm-function-extract) routes through this function before
//     dialing out — verified by tracing every reference to
//     AGENTIC_SECURITY_LLM_ENDPOINT in the codebase, not assumed. The one
//     real gap found and closed in that pass: discovery/llm-invoke.js's
//     multi-endpoint consensus mode used to construct its caller with NO
//     egress check at all, so a `mode: local-only` policy was silently
//     bypassable by setting AGENTIC_SECURITY_LLM_ENDPOINTS instead of the
//     single-endpoint var. Fixed there, not here — see that file's own
//     comment on `makeConsensusInvoke`.
//   - FR-607 (approved-provider metadata for regulated profiles) IS in
//     scope as of the FR-607 cycle: `regulatedProfile.requireApprovedProviders`
//     is a no-op unless configured; once set, every provider must have a
//     matching `approvedProviders[provider]` entry carrying a non-empty
//     value for each required attribute (default: dpaStatus, baaStatus,
//     retentionPolicy) or the call is denied. Organizational/contractual
//     facts, never inferred — same discipline
//     dataflow/privacy-governance.js's GOVERNANCE_FIELDS already
//     established for RoPA/DPIA.
//
// DEFAULT BEHAVIOR. No config file and no env override => 'allow'. This
// preserves the existing default-on UX for every LLM-backed feature in this
// codebase (discovery, validation, adversary-agent, etc.) — FR-601 asks for
// a policy DECISION on every call, not a policy that silently disables
// functionality nobody configured it to disable.

import * as fs from 'node:fs';
import { load as loadYaml } from '../util/yaml.js';
import { statePath } from '../posture/state-dir.js';
import { isLoopbackUrl } from '../llm-validator/local-endpoint.js';
import { matchesAnyGlob } from '../util/glob.js';

// FR-602: the list-membership dimensions, keyed by ctx field name to the
// config's allow/deny list PAIR name. `provider` (FR-601) already used
// this exact shape as allowedProviders/deniedProviders; the rest are new.
const LIST_DIMENSIONS = [
  { ctxKey: 'model', allowKey: 'allowedModels', denyKey: 'deniedModels' },
  { ctxKey: 'role', allowKey: 'allowedRoles', denyKey: 'deniedRoles' },
  { ctxKey: 'region', allowKey: 'allowedRegions', denyKey: 'deniedRegions' },
  { ctxKey: 'repository', allowKey: 'allowedRepositories', denyKey: 'deniedRepositories' },
  { ctxKey: 'dataClass', allowKey: 'allowedDataClasses', denyKey: 'deniedDataClasses' },
];

const POLICY_FILE = 'egress-policy.yml';

// FR-607: when a regulated profile requires approved-provider metadata, an
// approvedProviders[provider] entry must carry a non-empty value for each
// of these attributes unless the operator names a different set via
// regulatedProfile.requiredAttributes. DPA (Data Processing Agreement) and
// BAA (Business Associate Agreement, HIPAA) are organizational/contractual
// facts — not derivable from code, same "state it, never infer it"
// discipline dataflow/privacy-governance.js's GOVERNANCE_FIELDS already
// established for RoPA/DPIA fields.
const DEFAULT_REQUIRED_PROVIDER_ATTRIBUTES = ['dpaStatus', 'baaStatus', 'retentionPolicy'];

// FR-603 (egress/redact.js) reads the same egress-policy.yml file for its
// own keys (proprietaryPaths, customerDataPatterns, redactPii) — one
// operator-facing config surface for the whole egress epic rather than a
// second file. Exported (not `_`-prefixed like the rest of this module's
// internals) for that reuse; still not part of the public evaluateEgress
// API surface.
export function loadPolicyConfig(scanRoot) {
  let fp;
  try { fp = statePath(scanRoot, POLICY_FILE); } catch { return null; }
  // Read first, check second — an existsSync-then-readFileSync pair is a
  // check-then-use race (the file can vanish between the two calls); this
  // codebase's convention (apply-fix-service.js's readVerifiedScan) is to
  // let the read fail and classify ENOENT rather than pre-check existence.
  let raw;
  try {
    raw = fs.readFileSync(fp, 'utf8');
  } catch (e) {
    return null; // ENOENT (no config file) or any other read failure — same fallback either way
  }
  try {
    const doc = loadYaml(raw);
    return (doc && typeof doc === 'object' && !Array.isArray(doc)) ? doc : null;
  } catch { return null; }
}

/** Best-effort, purely informational provider label from the endpoint host. */
function _providerOf(endpoint) {
  let u;
  try { u = new URL(String(endpoint)); } catch { return 'unknown'; }
  if (isLoopbackUrl(endpoint)) return 'local';
  const h = u.hostname.toLowerCase();
  if (h.includes('anthropic')) return 'anthropic';
  if (h.includes('openai')) return 'openai';
  if (h.includes('googleapis') || h.includes('generativelanguage')) return 'google';
  return h || 'unknown';
}

/**
 * Evaluate whether an outbound LLM call is permitted. Call sites MUST check
 * `.allowed` before building the prompt for that call and before invoking
 * any fetch/HTTP client against `ctx.endpoint`.
 *
 * @param {object} ctx
 * @param {string} [ctx.scanRoot] - project root, for reading
 *   `.agentic-security/egress-policy.yml`; a missing/unreadable root is
 *   treated the same as no config file (falls back to 'allow').
 * @param {string} ctx.purpose - short, stable id of the call site (e.g.
 *   'discovery-hunter', 'llm-validator', 'adversary-agent') — never
 *   free text, so a decision is comparable across runs and never carries
 *   source content.
 * @param {string} ctx.endpoint - the URL that would be called. Required —
 *   a caller with no configured endpoint should never reach this function
 *   at all (every call site already has its own pre-existing "is anything
 *   configured" check upstream of prompt construction).
 * @param {string} [ctx.model] - FR-602: the model id the caller intends to
 *   use, if known. Evaluated against allowedModels/deniedModels only when
 *   supplied.
 * @param {string} [ctx.role] - FR-602: which ROLE this call serves (the
 *   same closed vocabulary llm-validator/providers.js's ROLES uses, but
 *   this function does not require membership in it — a caller in a
 *   different subsystem may have its own role names). Evaluated against
 *   allowedRoles/deniedRoles only when supplied.
 * @param {string} [ctx.region] - FR-602: a data-residency/provider region
 *   identifier, if the caller knows one. This codebase does not derive a
 *   region for any provider today; it is purely caller-supplied and
 *   evaluated against allowedRegions/deniedRegions only when supplied.
 * @param {string} [ctx.repository] - FR-602: a repository identifier for
 *   the current scan (e.g. a git remote or a stable project label), if the
 *   caller knows one. Evaluated against allowedRepositories/
 *   deniedRepositories only when supplied.
 * @param {string} [ctx.path] - FR-602: a '/'-separated relative path
 *   representative of the content in this call (e.g. the finding's source
 *   file), if applicable. Evaluated by glob against allowedPaths/
 *   deniedPaths only when supplied.
 * @param {string} [ctx.dataClass] - FR-602: a regulated-data-class label
 *   (e.g. from dataflow/privacy-taxonomy.js's taxonomy) present in the
 *   content this call would send, if the caller has classified it.
 *   Evaluated against allowedDataClasses/deniedDataClasses only when
 *   supplied.
 * @param {number} [ctx.contextTokens] - FR-602: the caller's OWN estimate
 *   of the prompt's token size (this function runs before prompt
 *   construction, so it cannot measure one itself). Compared against
 *   `maxContextTokens` in config only when both are present.
 * @returns {{allowed:boolean, decision:'allow'|'deny', reason:string|null,
 *   provider:string, policySource:'default'|'env'|'config', purpose:string}}
 *   Sanitized — carries no prompt/source content, only metadata, so it is
 *   always safe to log or attach to a report as-is (PRD walkthrough
 *   scenario 7: "records a sanitized decision without retaining source").
 */
export function evaluateEgress(ctx = {}) {
  const {
    scanRoot, purpose = 'unknown', endpoint,
    model = null, role = null, region = null, repository = null,
    path: filePath = null, dataClass = null, contextTokens = null,
  } = ctx;

  if (!endpoint || typeof endpoint !== 'string') {
    return { allowed: false, decision: 'deny', reason: 'no endpoint provided to evaluateEgress', provider: 'unknown', policySource: 'default', purpose };
  }

  const provider = _providerOf(endpoint);

  // Blunt, ops-friendly kill switch — same shape as the existing
  // AGENTIC_SECURITY_LLM_VALIDATE=0 precedent in llm-validator/index.js.
  if (process.env.AGENTIC_SECURITY_EGRESS_DENY === '1') {
    return { allowed: false, decision: 'deny', reason: "AGENTIC_SECURITY_EGRESS_DENY=1 is set", provider, policySource: 'env', purpose };
  }

  const envMode = process.env.AGENTIC_SECURITY_EGRESS_MODE;
  const cfg = loadPolicyConfig(scanRoot);
  const mode = envMode || (cfg && cfg.mode) || 'allow';
  const policySource = envMode ? 'env' : ((cfg && cfg.mode) ? 'config' : 'default');

  if (mode === 'deny') {
    return { allowed: false, decision: 'deny', reason: "egress mode is 'deny'", provider, policySource, purpose };
  }

  if (mode === 'local-only' && !isLoopbackUrl(endpoint)) {
    return {
      allowed: false, decision: 'deny',
      reason: `egress mode is 'local-only' and the endpoint is not a loopback address`,
      provider, policySource, purpose,
    };
  }

  const deniedProviders = (cfg && Array.isArray(cfg.deniedProviders)) ? cfg.deniedProviders : [];
  if (deniedProviders.includes(provider)) {
    return { allowed: false, decision: 'deny', reason: `provider '${provider}' is in deniedProviders`, provider, policySource: 'config', purpose };
  }

  const allowedProviders = (cfg && Array.isArray(cfg.allowedProviders)) ? cfg.allowedProviders : null;
  if (allowedProviders && !allowedProviders.includes(provider)) {
    return { allowed: false, decision: 'deny', reason: `provider '${provider}' is not in allowedProviders`, provider, policySource: 'config', purpose };
  }

  // FR-602: the remaining list-membership dimensions (model/role/region/
  // repository/dataClass), each a no-op unless BOTH the caller supplied a
  // value AND the config restricts that specific dimension.
  const ctxValues = { model, role, region, repository, dataClass };
  for (const { ctxKey, allowKey, denyKey } of LIST_DIMENSIONS) {
    const value = ctxValues[ctxKey];
    if (value == null) continue;
    const deniedList = (cfg && Array.isArray(cfg[denyKey])) ? cfg[denyKey] : [];
    if (deniedList.includes(value)) {
      return { allowed: false, decision: 'deny', reason: `${ctxKey} '${value}' is in ${denyKey}`, provider, policySource: 'config', purpose };
    }
    const allowedList = (cfg && Array.isArray(cfg[allowKey])) ? cfg[allowKey] : null;
    if (allowedList && !allowedList.includes(value)) {
      return { allowed: false, decision: 'deny', reason: `${ctxKey} '${value}' is not in ${allowKey}`, provider, policySource: 'config', purpose };
    }
  }

  // FR-602: path is glob-matched, not list-membership — a single literal
  // string is the wrong shape for a file path constraint.
  if (filePath != null) {
    const deniedPaths = (cfg && Array.isArray(cfg.deniedPaths)) ? cfg.deniedPaths : [];
    if (matchesAnyGlob(filePath, deniedPaths)) {
      return { allowed: false, decision: 'deny', reason: `path '${filePath}' matches a deniedPaths pattern`, provider, policySource: 'config', purpose };
    }
    const allowedPaths = (cfg && Array.isArray(cfg.allowedPaths)) ? cfg.allowedPaths : null;
    if (allowedPaths && !matchesAnyGlob(filePath, allowedPaths)) {
      return { allowed: false, decision: 'deny', reason: `path '${filePath}' does not match any allowedPaths pattern`, provider, policySource: 'config', purpose };
    }
  }

  // FR-602: max-context is a numeric cap, evaluated only when the caller
  // supplied its own token estimate AND the config sets a cap.
  if (typeof contextTokens === 'number' && cfg && typeof cfg.maxContextTokens === 'number') {
    if (contextTokens > cfg.maxContextTokens) {
      return {
        allowed: false, decision: 'deny',
        reason: `estimated context (${contextTokens} tokens) exceeds maxContextTokens (${cfg.maxContextTokens})`,
        provider, policySource: 'config', purpose,
      };
    }
  }

  // FR-607: a regulated profile can require APPROVED-PROVIDER metadata
  // (DPA/BAA status, retention policy) before a provider is usable at all —
  // a no-op unless the operator opts in via regulatedProfile.requireApproved
  // Providers, same "restricts nothing until configured" default every
  // other dimension above follows.
  const regulatedProfile = (cfg && typeof cfg.regulatedProfile === 'object' && cfg.regulatedProfile) ? cfg.regulatedProfile : null;
  let approvedProviderMetadata = null;
  if (regulatedProfile && regulatedProfile.requireApprovedProviders) {
    const requiredAttributes = (Array.isArray(regulatedProfile.requiredAttributes) && regulatedProfile.requiredAttributes.length)
      ? regulatedProfile.requiredAttributes
      : DEFAULT_REQUIRED_PROVIDER_ATTRIBUTES;
    const approvedProviders = (cfg && typeof cfg.approvedProviders === 'object' && cfg.approvedProviders) ? cfg.approvedProviders : {};
    const entry = approvedProviders[provider];
    if (!entry || typeof entry !== 'object') {
      return {
        allowed: false, decision: 'deny',
        reason: `provider '${provider}' has no approved-provider metadata configured, and this profile requires one (regulatedProfile.requireApprovedProviders)`,
        provider, policySource: 'config', purpose,
      };
    }
    const missing = requiredAttributes.filter((attr) => {
      const v = entry[attr];
      return !(typeof v === 'string' && v.length > 0 && v !== 'none' && v !== 'not_signed');
    });
    if (missing.length) {
      return {
        allowed: false, decision: 'deny',
        reason: `provider '${provider}' is missing required approved-provider attribute(s): ${missing.join(', ')}`,
        provider, policySource: 'config', purpose,
      };
    }
    approvedProviderMetadata = entry;
  }

  return {
    allowed: true, decision: 'allow', reason: null, provider, policySource, purpose,
    ...(approvedProviderMetadata ? { approvedProviderMetadata } : {}),
  };
}

export const _internals = { loadPolicyConfig, _providerOf, POLICY_FILE, DEFAULT_REQUIRED_PROVIDER_ATTRIBUTES };
