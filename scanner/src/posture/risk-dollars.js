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
// EV per finding = P × Impact × Discount × ConfidenceFloor
//
// Industry breach-cost figures used here are sourced from publicly
// reported aggregates (Ponemon Cost of a Data Breach Report — IBM/Verizon
// methodology is widely cited but the figures are reported in the public
// summary; we use rounded estimates as defaults that users can override
// via .agentic-security/risk-config.yml).
//
// Disclaimer: this is an order-of-magnitude estimate for prioritization.
// It is NOT an actuarial or insurance assessment.

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

function _loadConfig(scanRoot) {
  const fp = statePath(scanRoot, 'risk-config.yml');
  if (!fs.existsSync(fp)) return null;
  try {
    const body = fs.readFileSync(fp, 'utf8');
    // Tiny YAML — look for impactUSD / familyBaseProb overrides
    const cfg = {};
    const impactMatch = body.match(/^impactUSD\s*:\s*\n((?:\s+\w+\s*:\s*\d+\s*\n?)+)/m);
    if (impactMatch) {
      cfg.impactUSD = {};
      for (const m of impactMatch[1].matchAll(/(\w+)\s*:\s*(\d+)/g)) cfg.impactUSD[m[1]] = parseInt(m[2], 10);
    }
    return cfg;
  } catch { return null; }
}

function _baseProb(family) {
  if (!family) return 0.05;
  return FAMILY_BASE_PROB[family] || FAMILY_BASE_PROB[String(family).toLowerCase()] || 0.05;
}

function _impactFor(finding, cfg) {
  const table = cfg && cfg.impactUSD ? { ...IMPACT_USD, ...cfg.impactUSD } : IMPACT_USD;
  const dc = Array.isArray(finding.dataClasses) ? finding.dataClasses : [];
  if (dc.includes('PHI')) return table.PHI;
  if (dc.includes('PCI')) return table.PCI;
  if (dc.includes('PII')) return table.PII;
  if (dc.includes('Confidential')) return table.Confidential;
  if (finding.threatModel?.crownJewel) return table['crown-jewel'];
  return table.default;
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

function _reachDiscount(finding) {
  const tier = finding.reachabilityTier
    || (finding.routeReachable && 'route-reachable')
    || _relevanceTierToReachTier(finding.relevanceTier)
    || 'unknown';
  return REACH_DISCOUNT[tier] || 0.3;
}

function _epssProb(finding) {
  if (typeof finding.epssScore === 'number') return finding.epssScore;
  if (typeof finding.epss === 'number') return finding.epss;
  return null;
}

/**
 * Compute EV per finding. Mutates the finding in place: adds
 * .riskDollars = { ev, prob, impact, discount }.
 */
export function annotateRiskDollars(scanRoot, findings) {
  if (!Array.isArray(findings) || findings.length === 0) return { total: 0, sumEv: 0 };
  const cfg = _loadConfig(scanRoot);
  let sumEv = 0;
  let critEv = 0, highEv = 0;
  for (const f of findings) {
    const epss = _epssProb(f);
    const prob = epss != null ? epss : _baseProb(f.family);
    const impact = _impactFor(f, cfg);
    const discount = _reachDiscount(f);
    const confidenceFloor = Math.max(0.4, f.confidence || 0.8);
    const ev = Math.round(prob * impact * discount * confidenceFloor);
    f.riskDollars = { ev, prob: Number(prob.toFixed(3)), impact, discount, confidenceFloor: Number(confidenceFloor.toFixed(2)) };
    sumEv += ev;
    if (f.severity === 'critical') critEv += ev;
    else if (f.severity === 'high') highEv += ev;
  }
  return { total: findings.length, sumEv, critEv, highEv };
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

export const _internals = { FAMILY_BASE_PROB, IMPACT_USD, REACH_DISCOUNT, _baseProb, _impactFor, _reachDiscount };
