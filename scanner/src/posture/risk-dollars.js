// Risk-in-dollars — expected value of exploitation per finding.
//
// Combines three signals into an EV estimate:
//
//   P(exploited)   from EPSS score on the finding's CVE if present,
//                  else from family-level base rate
//   Impact($)      from crown-jewel mapping (data class) and industry
//                  breach-cost averages
//   Discount       reachability tier (route-reachable > function-reachable
//                  > unknown > unreachable)
//
// EV per finding = P × Impact × Discount × ConfidenceWeight
//
// Industry breach-cost figures used here are sourced from publicly
// reported aggregates (Ponemon Cost of a Data Breach Report — IBM/Verizon
// methodology is widely cited but the figures are reported in the public
// summary; we use rounded estimates as defaults that users can override
// via .agentic-security/risk-config.yml).
//
// Disclaimer: this is an order-of-magnitude estimate for prioritization.
// It is NOT an actuarial or insurance assessment.
//
// FR-803/FR-805 (assurance-hardening PRD): the single `ev` number above is
// only ever the BASE scenario. Every finding also gets `range` (low/base/
// high spanning conservative/base/severe), `scenarios` (all three, named),
// `assumptions` (which table entry and which tier produced each factor),
// and `modelVersion` — so a reader can trace any dollar figure back to
// exactly the inputs and methodology version that produced it, and compare
// scenarios without any of this ever touching `finding.severity`.

import * as fs from 'node:fs';
import * as path from 'node:path';


import { statePath } from './state-dir.js';
// Base rates per family (annual probability of at-least-one exploit given
// an exposed instance). Rough industry estimates; tune via config.
const FAMILY_BASE_PROB = {
  'sqli': 0.18, 'sql-injection': 0.18,
  'xss': 0.12, 'mutation-xss': 0.10,
  'command-injection': 0.16,
  'code-injection': 0.20,
  'deserialization': 0.15,
  'auth-missing': 0.25,
  'authz': 0.18, 'idor': 0.15,
  'csrf': 0.07,
  'ssrf': 0.10, 'ssrf-cloud-metadata': 0.22,
  'xxe': 0.08,
  'open-redirect': 0.05,
  'path-traversal': 0.10,
  'crypto-weak-cipher': 0.04, 'crypto-weak-hash': 0.03,
  'crypto-tls-no-verify': 0.10, 'crypto-tls-version': 0.05,
  'crypto-jwt-none': 0.20, 'crypto-jwt-key-confusion': 0.18,
  'hardcoded-secret': 0.30,
  'vulnerable-dependency': 0.08,
  'dependency-confusion': 0.06,
  'iam-overpermissive': 0.10,
  'k8s-rbac-cluster-admin': 0.12,
  'k8s-pod-security-privileged': 0.10,
  'prompt-injection': 0.20,
  'agent-tool-exec': 0.25,
  'reentrancy': 0.30,
  'signature-replay': 0.15,
  'eth-sign-used': 0.30,
  'unlimited-approval': 0.18,
};

// Default impact (USD) per crown-jewel / data-class tier.
const IMPACT_USD = {
  'PII':           250_000,
  'PHI':           400_000,
  'PCI':           500_000,
  'Confidential':  150_000,
  'crown-jewel':   300_000,
  'default':        50_000,
};

const REACH_DISCOUNT = {
  'reachable-public':                1.0,
  'public-unauthed':                 1.0,
  'route-reachable':                 0.9,
  'route-reachable-via-function':    0.7,
  'function-reachable':              0.5,
  'unknown':                         0.3,
  'unreachable':                     0.05,
  'function-reachable-but-not-route':0.4,
};

// Tiny YAML — parses the two flat "section:\n  key: number" blocks
// (impactUSD, familyBaseProb) plus four top-level flat scalar keys (FR-802's
// organization-specific inputs, added below). Deliberately line-based rather
// than one multi-line regex: a single regex here
// (`(?:\s+\w+\s*:\s*\d+\s*\n?)+`) looked correct but had a real, silent bug
// — `\s*` before the optional trailing `\n?` greedily consumed the NEXT
// line's leading indentation too, so the repeated group's `+` quantifier
// only ever matched ONE entry before its required leading `\s+` failed to
// find any whitespace left to consume. A risk-config.yml with more than one
// impactUSD entry silently kept only the first — found while adding
// familyBaseProb support (which inherited the identical bug) and testing
// it with more than one entry, per this session's standing rule of testing
// multi-entry cases, not just the single-entry case a hand-rolled parser's
// own author tends to reach for first.
//
// FR-802: `organizationScale`, `industry`, `recordCount`, `controlStrength`
// are free-form top-level scalars (not sections) — an operator states them
// directly, e.g. `industry: healthcare`. `recordCount` is parsed as an
// integer; a non-numeric value is treated as not configured (never silently
// coerced to NaN, which `!= null` would otherwise count as "present").
const FLAT_SCALAR_KEYS = ['organizationScale', 'industry', 'recordCount', 'controlStrength'];

function _loadConfig(scanRoot) {
  const fp = statePath(scanRoot, 'risk-config.yml');
  if (!fs.existsSync(fp)) return null;
  try {
    const body = fs.readFileSync(fp, 'utf8');
    const cfg = {};
    let section = null;
    for (const line of body.split(/\r?\n/)) {
      const sectionMatch = line.match(/^(impactUSD|familyBaseProb)\s*:\s*$/);
      if (sectionMatch) { section = sectionMatch[1]; continue; }
      const flatMatch = !section && line.match(/^([A-Za-z][\w-]*)\s*:\s*(\S.*?)\s*$/);
      if (flatMatch && FLAT_SCALAR_KEYS.includes(flatMatch[1])) {
        if (flatMatch[1] === 'recordCount') {
          const n = parseInt(flatMatch[2], 10);
          if (Number.isFinite(n)) cfg.recordCount = n;
        } else {
          cfg[flatMatch[1]] = flatMatch[2];
        }
        continue;
      }
      if (!section) continue;
      const entryMatch = line.match(/^[ \t]+([\w-]+)\s*:\s*([\d.]+)\s*$/);
      if (entryMatch) {
        if (!cfg[section]) cfg[section] = {};
        cfg[section][entryMatch[1]] = section === 'impactUSD' ? parseInt(entryMatch[2], 10) : parseFloat(entryMatch[2]);
      } else if (line.trim() !== '') {
        section = null; // a non-indented, non-blank line ends the current section
      }
    }
    return cfg;
  } catch { return null; }
}

// FR-801/FR-802: every dollar estimate is a SCENARIO by default — generic,
// industry-wide probability/impact tables, not this organization's actual
// exposure. `ORG_SPECIFIC_DIMENSIONS` is the full set of tunable knobs this
// module recognizes (includes `familyBaseProb`, a bonus calibration input
// that isn't one of FR-802's five named inputs). The stronger claim FR-802
// gates — "likely organizational loss" — requires ALL FIVE of its literally
// named inputs (scale, industry, record count, control strength, impact),
// tracked separately as `REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS` so that
// configuring `familyBaseProb` alone (or any subset of the five) can never
// unlock that label — only 'scenario_partially_configured', same as before.
const ORG_SPECIFIC_DIMENSIONS = ['impactUSD', 'familyBaseProb', 'organizationScale', 'industry', 'recordCount', 'controlStrength'];
const REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS = ['impactUSD', 'organizationScale', 'industry', 'recordCount', 'controlStrength'];

function _scenarioDisclosure(cfg) {
  const configured = ORG_SPECIFIC_DIMENSIONS.filter(d => cfg && cfg[d] != null);
  const unconfigured = ORG_SPECIFIC_DIMENSIONS.filter(d => !configured.includes(d));
  const requiredMissing = REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS.filter(d => !(cfg && cfg[d] != null));

  let status, message;
  if (requiredMissing.length === 0) {
    status = 'scenario_organization_specific';
    message = `All organization-specific inputs are configured (${REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS.join(', ')}) — this estimate reflects a likely organizational loss for your organization, not a generic industry scenario.`;
  } else if (configured.length > 0) {
    status = 'scenario_partially_configured';
    message = `Uses organization-configured values for: ${configured.join(', ')}. Still missing for a likely-organizational-loss estimate: ${requiredMissing.join(', ')}. This is NOT a likely-organizational-loss estimate.`;
  } else {
    status = 'scenario_default';
    message = 'Uses generic industry-wide scenario defaults. No organization-specific inputs are configured (see .agentic-security/risk-config.yml) — this is NOT a likely-organizational-loss estimate.';
  }

  return {
    status,
    configuredInputs: configured,
    unconfiguredInputs: unconfigured,
    requiredForOrganizationSpecificLoss: REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS,
    missingRequiredInputs: requiredMissing,
    message,
  };
}

function _baseProb(family, cfg) {
  if (!family) return 0.05;
  const overrides = cfg && cfg.familyBaseProb;
  if (overrides) {
    const hit = overrides[family] ?? overrides[String(family).toLowerCase()];
    if (typeof hit === 'number') return hit;
  }
  return FAMILY_BASE_PROB[family] || FAMILY_BASE_PROB[String(family).toLowerCase()] || 0.05;
}

// FR-803: split out from _impactFor so an assumption can name WHICH tier
// produced the number, not just the number itself.
function _impactTierOf(finding) {
  const dc = Array.isArray(finding.dataClasses) ? finding.dataClasses : [];
  if (dc.includes('PHI')) return 'PHI';
  if (dc.includes('PCI')) return 'PCI';
  if (dc.includes('PII')) return 'PII';
  if (dc.includes('Confidential')) return 'Confidential';
  if (finding.threatModel?.crownJewel) return 'crown-jewel';
  return 'default';
}

function _impactFor(finding, cfg) {
  const table = cfg && cfg.impactUSD ? { ...IMPACT_USD, ...cfg.impactUSD } : IMPACT_USD;
  return table[_impactTierOf(finding)];
}

// SCA entries carry reachabilityTier/routeReachable (engine.js's SCA
// reachability pass); SAST findings never do — they carry relevanceTier/
// entrypointReachable instead (posture/relevance.js). Without this
// fallback, _reachDiscount always read 'unknown' (0.3) for every SAST
// finding, regardless of whether it was actually route-reachable.
function _relevanceTierToReachTier(relevanceTier) {
  switch (relevanceTier) {
    case 'direct':      return 'route-reachable';
    case 'indirect':    return 'function-reachable';
    case 'unreachable': return 'unreachable';
    default:            return null;
  }
}

// FR-803: split out from _reachDiscount so an assumption can name the tier.
function _reachTierOf(finding) {
  return finding.reachabilityTier
    || (finding.routeReachable && 'route-reachable')
    || _relevanceTierToReachTier(finding.relevanceTier)
    || 'unknown';
}

function _reachDiscount(finding) {
  return REACH_DISCOUNT[_reachTierOf(finding)] || 0.3;
}

function _epssProb(finding) {
  if (typeof finding.epssScore === 'number') return finding.epssScore;
  if (typeof finding.epss === 'number') return finding.epss;
  return null;
}

// FR-803: names WHERE the probability number came from, for the assumptions
// list — not just the value.
function _probSource(finding, cfg) {
  if (_epssProb(finding) != null) return 'EPSS score (finding-specific)';
  const overrides = cfg && cfg.familyBaseProb;
  if (overrides && (overrides[finding.family] != null || overrides[String(finding.family).toLowerCase()] != null)) {
    return 'operator-configured familyBaseProb override';
  }
  return 'built-in industry base-rate table';
}

// Bump ONLY when the EV formula or a table's underlying MEANING changes
// (e.g. re-deriving FAMILY_BASE_PROB from a new source) — never for an
// additive field on the output shape, which stays backward compatible.
export const RISK_MODEL_VERSION = '1.0.0';

// FR-805: scenario multipliers apply only to the two GENERIC assumption
// inputs — probability-of-exploit and impact-per-incident — that FR-801
// already discloses as industry-wide defaults. Reachability discount and
// confidence weight are both measured facts about THIS finding in THIS
// scan, not assumptions with real-world spread, so they stay fixed across
// scenarios rather than being perturbed for effect.
const SCENARIO_MULTIPLIERS = {
  conservative: { prob: 0.5, impact: 0.6 },
  base: { prob: 1.0, impact: 1.0 },
  severe: { prob: 1.75, impact: 1.5 },
};

/**
 * Compute EV per finding. Mutates the finding in place: adds
 * .riskDollars = { ev, prob, impact, discount, confidenceWeight,
 *   scenarioStatus, range: {low, base, high}, scenarios: {conservative,
 *   base, severe}, assumptions: [...], modelVersion, confidence }.
 */
export function annotateRiskDollars(scanRoot, findings) {
  const disclosure = _scenarioDisclosure(_loadConfig(scanRoot));
  if (!Array.isArray(findings) || findings.length === 0) return { total: 0, sumEv: 0, scenario: disclosure };
  const cfg = _loadConfig(scanRoot);
  let sumEv = 0;
  let critEv = 0, highEv = 0;
  for (const f of findings) {
    const epss = _epssProb(f);
    const prob = epss != null ? epss : _baseProb(f.family, cfg);
    const impactTier = _impactTierOf(f);
    const impact = _impactFor(f, cfg);
    const reachTier = _reachTierOf(f);
    const discount = REACH_DISCOUNT[reachTier] || 0.3;
    // FR-804 (assurance-hardening PRD): this used to be
    // `Math.max(0.4, f.confidence || 0.8)` — TWO stacked bugs. First, `||`
    // treats a real confidence of 0 (a legitimate, very-low value) as falsy
    // and silently substitutes 0.8, the HIGH default — a genuinely
    // near-zero-confidence finding got the same dollar weight as a
    // near-certain one. Second, the unconditional `Math.max(0.4, ...)`
    // floor inflated every OTHER low-confidence finding (0.05, 0.1, ...) up
    // to 0.4 regardless, which is exactly "an artificially high confidence
    // without an explicit reason" FR-804 names. Fixed: use the finding's
    // real confidence whenever it is genuinely present (including 0), with
    // no floor; 0.8 remains the default ONLY when confidence is absent
    // (not a number at all), which is a "we don't know" default, not an
    // inflation of a known low value.
    const confidenceWeight = typeof f.confidence === 'number' ? f.confidence : 0.8;

    // FR-805: three named scenarios, sharing the SAME discount/confidence —
    // only the two generic inputs (prob, impact) are perturbed. `ev` (base
    // scenario) is unchanged from before this cycle, since base's
    // multipliers are 1.0/1.0.
    const scenarios = {};
    for (const [name, mult] of Object.entries(SCENARIO_MULTIPLIERS)) {
      const scenarioProb = Math.min(1, prob * mult.prob);
      const scenarioImpact = Math.round(impact * mult.impact);
      scenarios[name] = Math.round(scenarioProb * scenarioImpact * discount * confidenceWeight);
    }
    const ev = scenarios.base;

    // FR-803: every dollar value traces to its own assumptions and a model
    // version — not just a bare number.
    const assumptions = [
      `probability of exploit: ${Number(prob.toFixed(3))} (source: ${_probSource(f, cfg)})`,
      `impact estimate: ${fmtUsd(impact)} (tier: ${impactTier}, ${cfg?.impactUSD?.[impactTier] != null ? 'operator-configured' : 'built-in default'})`,
      `reachability discount: ${discount} (tier: ${reachTier})`,
      `confidence weight: ${Number(confidenceWeight.toFixed(2))} (${typeof f.confidence === 'number' ? 'measured from this scan' : 'unknown — defaulted'})`,
    ];
    // FR-803: a distinct confidence indicator on the estimate itself — not
    // the per-finding confidenceWeight multiplier, but a coarse tier
    // reflecting how much of this number is organization-specific vs.
    // generic-default, folded with the finding's own detection confidence.
    const confidence = disclosure.status === 'scenario_organization_specific' && confidenceWeight >= 0.7
      ? 'high'
      : (disclosure.status === 'scenario_default' || confidenceWeight < 0.4 ? 'low' : 'medium');

    f.riskDollars = {
      ev, prob: Number(prob.toFixed(3)), impact, discount,
      confidenceWeight: Number(confidenceWeight.toFixed(2)),
      scenarioStatus: disclosure.status,
      range: { low: scenarios.conservative, base: scenarios.base, high: scenarios.severe },
      scenarios,
      assumptions,
      modelVersion: RISK_MODEL_VERSION,
      confidence,
    };
    sumEv += ev;
    if (f.severity === 'critical') critEv += ev;
    else if (f.severity === 'high') highEv += ev;
  }
  return { total: findings.length, sumEv, critEv, highEv, scenario: disclosure };
}

/**
 * Format a USD figure for display.
 */
export function fmtUsd(n) {
  if (typeof n !== 'number' || !isFinite(n)) return '$?';
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}k`;
  return `$${n}`;
}

export const _internals = {
  FAMILY_BASE_PROB, IMPACT_USD, REACH_DISCOUNT, ORG_SPECIFIC_DIMENSIONS,
  REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS, SCENARIO_MULTIPLIERS,
  _baseProb, _impactFor, _impactTierOf, _reachDiscount, _reachTierOf,
  _probSource, _loadConfig, _scenarioDisclosure,
};
