// R12 (PRD §5) — deterministic SCA decision-first verdict.
//
// Turns the enrichment signals already on each `vulnerable_dep` finding
// (compositeRiskTier, kev, epss, reachabilityTier, mitigationVerdict,
// fixedVersions, policy suppression/freeze) into ONE verdict from a closed enum,
// so the default SCA output is a decision ("fix these 5, auto-merge these 40,
// ignore these 255 — here's why") rather than a CVE dump.
//
// This codifies the ordered procedure documented for the `sca-triager` agent so
// it runs without an LLM. The agent remains for nuanced/uncertain cases; this
// gives every dep a defensible default verdict deterministically.
//
// Verdict enum (must match the agent + downstream /fix --sca):
//   AUTO_MERGE_PATCH · WAIT_FOR_PATCH · MANUAL_REVIEW · ACCEPT_RISK · WONT_FIX

import { BUILD_TRUST_TYPE } from '../language/contracts.js';

export const SCA_VERDICTS = ['AUTO_MERGE_PATCH', 'WAIT_FOR_PATCH', 'MANUAL_REVIEW', 'ACCEPT_RISK', 'WONT_FIX'];

const REACHABLE_TIERS = new Set(['route-reachable-via-function', 'function-reachable', 'import-reachable']);
const UNREACHABLE_TIERS = new Set(['unreachable', 'build-only', 'manifest-only', 'transitive-only']);

// Parse a version into {major,minor,patch}. Tolerates leading 'v', ranges, and
// pre-release/build suffixes. Returns null when no leading numeric core exists.
export function parseVersion(v) {
  if (v == null) return null;
  const m = String(v).match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!m) return null;
  return { major: +m[1], minor: m[2] != null ? +m[2] : 0, patch: m[3] != null ? +m[3] : 0 };
}

// Classify the smallest bump from `current` to `fixed`: 'patch' | 'minor' |
// 'major' | 'none' (fixed <= current) | 'unknown' (unparseable).
export function bumpKind(current, fixed) {
  const c = parseVersion(current);
  const f = parseVersion(fixed);
  if (!c || !f) return 'unknown';
  if (f.major > c.major) return 'major';
  if (f.major < c.major) return 'none';
  if (f.minor > c.minor) return 'minor';
  if (f.minor < c.minor) return 'none';
  if (f.patch > c.patch) return 'patch';
  return 'none';
}

function isReachable(sc) {
  // Default to "reachable" when the tier is unknown — fail toward review, not
  // toward auto-accept (never silently ACCEPT_RISK something we couldn't place).
  if (sc.reachabilityTier == null) return true;
  return REACHABLE_TIERS.has(sc.reachabilityTier);
}

/**
 * Compute the verdict for one vulnerable_dep finding. Pure. Returns
 * { verdict, reason, expiryDays? }. Follows the documented ordered procedure;
 * the first matching rule wins.
 */
export function computeScaVerdict(sc, opts = {}) {
  const testsDetected = !!opts.testsDetected;
  const tier = sc.reachabilityTier;
  const fixed = Array.isArray(sc.fixedVersions) ? sc.fixedVersions.filter(Boolean) : [];
  const riskTier = sc.compositeRiskTier;
  const bump = fixed.length ? bumpKind(sc.version, fixed[0]) : null;

  // 1. Already suppressed by policy (accept-risk match) → pass-through.
  if (sc.suppressed || sc.suppressionReason) {
    return { verdict: 'ACCEPT_RISK', reason: sc.suppressionReason || 'matched existing accept-risk in sca-policy.yml' };
  }
  // 1b. Nix build-trust policy findings have no advisory, fixed version or upgrade
  // path: the remedy is a configuration or pin change, which is always a human call.
  if (sc.type === BUILD_TRUST_TYPE) {
    return { verdict: 'MANUAL_REVIEW', reason: `${sc.rule}: ${sc.remediation || 'review the Nix build-trust setting'}` };
  }
  // 2. No fixed version exists → nothing to upgrade yet.
  if (!fixed.length) {
    return { verdict: 'WAIT_FOR_PATCH', reason: `no fixed version published${sc.osvId ? ` for ${sc.osvId}` : ''}` };
  }
  // 3. KEV-listed AND reachable → urgent. Same-major fix auto-merges; else review.
  if ((sc.kev || sc.kevListed) && isReachable(sc)) {
    if (bump === 'patch' || bump === 'minor') {
      return { verdict: 'AUTO_MERGE_PATCH', reason: `KEV-listed and reachable; ${bump} bump to ${fixed[0]}` };
    }
    return { verdict: 'MANUAL_REVIEW', reason: 'KEV-listed but fix requires a major-version bump' };
  }
  // 4. Environment-mitigated in prod → accept with re-evaluation window.
  if (sc.mitigationVerdict === 'mitigated-in-prod') {
    return { verdict: 'ACCEPT_RISK', reason: 'mitigated in production (WAF / network policy / auth gate)', expiryDays: 90 };
  }
  // 5. Unreachable (in prod or by tier) → accept; low real exposure.
  if (sc.mitigationVerdict === 'unreachable-in-prod' || (tier && UNREACHABLE_TIERS.has(tier))) {
    return { verdict: 'ACCEPT_RISK', reason: `not reachable (${sc.mitigationVerdict || tier})`, expiryDays: 180 };
  }
  // 6. Major-version freeze policy → human decision.
  if (sc.majorVersionFrozen) {
    return { verdict: 'MANUAL_REVIEW', reason: 'package is on the major-version-freeze list' };
  }
  // 7. Fix requires a major bump → breaking-change review.
  if (bump === 'major') {
    return { verdict: 'MANUAL_REVIEW', reason: `fix requires a major-version bump (${sc.version} → ${fixed[0]}); review breaking changes` };
  }
  // 8. Patch-only bump at high/critical risk → safe auto-merge.
  if (bump === 'patch' && (riskTier === 'high' || riskTier === 'critical')) {
    return { verdict: 'AUTO_MERGE_PATCH', reason: `patch bump to ${fixed[0]} at ${riskTier} risk` };
  }
  // 9. EPSS says exploited-now + reachable + same-major → urgency overrides minor/patch distinction.
  if ((sc.exploitedNow || (typeof sc.epssPercentile === 'number' && sc.epssPercentile >= 0.95)) && isReachable(sc) && (bump === 'patch' || bump === 'minor')) {
    return { verdict: 'AUTO_MERGE_PATCH', reason: `high EPSS (exploited in the wild) and reachable; ${bump} bump to ${fixed[0]}` };
  }
  // 10. Minor bump at critical risk WITH tests present → auto-merge (tests catch breakage).
  if (bump === 'minor' && riskTier === 'critical' && testsDetected) {
    return { verdict: 'AUTO_MERGE_PATCH', reason: `minor bump to ${fixed[0]} at critical risk; project has tests` };
  }
  // 11. Anything else (minor bump at non-critical risk, 'none', unclear) → human.
  return { verdict: 'MANUAL_REVIEW', reason: bump === 'none' ? 'no upgrade path resolves the advisory; review manually' : `${bump || 'unclear'} bump — defer to human triage` };
}

/**
 * Annotate every vulnerable_dep in supplyChain with `scaVerdict` +
 * `scaVerdictReason` (+ `scaVerdictExpiryDays` when applicable). Mutates and
 * returns supplyChain. Returns a per-verdict count map on `supplyChain._scaVerdictCounts`.
 */
export function annotateScaVerdicts(supplyChain, opts = {}) {
  if (!Array.isArray(supplyChain)) return supplyChain;
  const counts = { AUTO_MERGE_PATCH: 0, WAIT_FOR_PATCH: 0, MANUAL_REVIEW: 0, ACCEPT_RISK: 0, WONT_FIX: 0 };
  for (const sc of supplyChain) {
    if (!sc || (sc.type !== 'vulnerable_dep' && sc.type !== BUILD_TRUST_TYPE)) continue;
    const { verdict, reason, expiryDays } = computeScaVerdict(sc, opts);
    sc.scaVerdict = verdict;
    sc.scaVerdictReason = reason;
    if (expiryDays) sc.scaVerdictExpiryDays = expiryDays;
    if (counts[verdict] != null) counts[verdict]++;
  }
  try {
    Object.defineProperty(supplyChain, '_scaVerdictCounts', { value: counts, enumerable: false, configurable: true });
  } catch { /* frozen array — ignore */ }
  return supplyChain;
}
