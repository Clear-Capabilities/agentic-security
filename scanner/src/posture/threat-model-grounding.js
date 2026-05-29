// Threat-model-grounded prioritization.
//
// Reads project documentation (CLAUDE.md + docs/THREAT-MODEL.md + AGENTS.md)
// to extract the project's stated threat model and applies it to finding
// prioritization:
//
//   - **Crown jewels** — file globs listed under "## Crown jewels" or
//     "## Sensitive surfaces" boost severity by one tier when a finding
//     lands there.
//   - **Out-of-scope** — file globs under "## Out of scope" or "## Not in
//     threat model" demote findings to low.
//   - **Compliance regime** — declared under "## Compliance" (e.g.
//     SOC2 / HIPAA / GDPR) adds compliance-tag fields to findings in
//     matching families (PII → HIPAA/GDPR; auth → SOC2 CC6.1; etc.).
//   - **Stated attacker** — "## Attacker model" / "## Threat actor"
//     section sets f.attackerProfile = 'script-kiddie' | 'apt' | 'insider'
//     for use in downstream prioritization.
//
// Opt-out: AGENTIC_SECURITY_NO_THREAT_MODEL_GROUNDING=1

import * as fs from 'node:fs';
import * as path from 'node:path';

const DOC_PATHS = [
  'CLAUDE.md',
  'docs/THREAT-MODEL.md',
  'docs/threat-model.md',
  'docs/THREATMODEL.md',
  'THREAT-MODEL.md',
  '.agentic-security/AGENTS.md',
];

function _readDoc(scanRoot, rel) {
  try { return fs.readFileSync(path.join(scanRoot, rel), 'utf8'); } catch { return ''; }
}

function _allDocs(scanRoot) {
  return DOC_PATHS.map(p => _readDoc(scanRoot, p)).join('\n\n');
}

function _extractPathsFromSection(body, sectionRegex) {
  const sec = body.match(sectionRegex);
  if (!sec) return [];
  const paths = [];
  // Match `path/like/this/**`, "path/like", or list-item paths.
  const re = /[`"]([\w./*?\-]+)[`"]|^\s*-\s+([\w./*?\-]+)/gm;
  let m;
  while ((m = re.exec(sec[0]))) {
    const p = m[1] || m[2];
    if (p && /[\/.]/.test(p)) paths.push(p);
  }
  return Array.from(new Set(paths));
}

function _extractCompliance(body) {
  const sec = body.match(/^#{1,3}\s+Compliance[\s\S]*?(?=\n#{1,3}\s|$(?![\s\S]))/im);
  if (!sec) return [];
  const found = new Set();
  const re = /\b(SOC2|HIPAA|PCI[- ]DSS|GDPR|CCPA|FedRAMP|ISO[- ]?27001|NIST(?:[- ]?(?:CSF|800-53|AI 600-1))?|EU AI Act|OWASP (?:ASVS|LLM Top 10))\b/gi;
  let m;
  while ((m = re.exec(sec[0]))) found.add(m[1].toUpperCase().replace(/\s+/g, '-'));
  return Array.from(found);
}

function _extractAttacker(body) {
  const sec = body.match(/^#{1,3}\s+(?:Attacker model|Threat actor|Adversary)[\s\S]*?(?=\n#{1,3}\s|$(?![\s\S]))/im);
  if (!sec) return null;
  const txt = sec[0].toLowerCase();
  if (/\bapt\b|nation[- ]?state|sophisticated/.test(txt)) return 'apt';
  if (/\binsider\b|employee|disgruntled/.test(txt)) return 'insider';
  if (/script[- ]?kiddie|automated|opportunistic/.test(txt)) return 'script-kiddie';
  return 'general';
}

function _globMatch(pattern, p) {
  const norm = String(p).replace(/\\/g, '/');
  const re = new RegExp(
    '^' + String(pattern).replace(/\\/g, '/')
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/\*\*/g, '###DSTAR###')
      .replace(/\*/g, '[^/]*')
      .replace(/###DSTAR###/g, '.*')
    + '$',
  );
  return re.test(norm);
}

const SEVERITY_RANK = ['info', 'low', 'medium', 'high', 'critical'];

function _bumpSeverity(sev) {
  const i = SEVERITY_RANK.indexOf(sev);
  if (i < 0 || i >= SEVERITY_RANK.length - 1) return sev;
  return SEVERITY_RANK[i + 1];
}

const FAMILY_TO_REGIME = {
  'pii-exposure': ['HIPAA', 'GDPR'],
  'training-data-pii': ['GDPR'],
  'auth-missing': ['SOC2'],
  'authz': ['SOC2'],
  'idor': ['SOC2'],
  'crypto-weak-cipher': ['PCI-DSS', 'FedRAMP'],
  'crypto-tls-no-verify': ['PCI-DSS'],
  'hardcoded-secret': ['SOC2', 'PCI-DSS'],
  'k8s-rbac-cluster-admin': ['SOC2'],
  'aws-public-s3': ['SOC2', 'GDPR'],
};

/**
 * Read project threat model from documentation. Cached per-scan-root via
 * a module-level WeakMap-like... actually just pure read each time, since
 * scan-time overhead is tiny.
 */
export function loadThreatModel(scanRoot) {
  if (process.env.AGENTIC_SECURITY_NO_THREAT_MODEL_GROUNDING === '1') {
    return { crownJewels: [], outOfScope: [], compliance: [], attacker: null };
  }
  const body = _allDocs(scanRoot);
  return {
    crownJewels:   _extractPathsFromSection(body, /^#{1,3}\s+(?:Crown jewels|Sensitive surfaces?)[\s\S]*?(?=\n#{1,3}\s|$(?![\s\S]))/im),
    outOfScope:    _extractPathsFromSection(body, /^#{1,3}\s+(?:Out of scope|Not in threat model)[\s\S]*?(?=\n#{1,3}\s|$(?![\s\S]))/im),
    compliance:    _extractCompliance(body),
    attacker:      _extractAttacker(body),
  };
}

/**
 * Annotator: applies the project's threat model to each finding.
 */
export function applyThreatModel(scanRoot, findings) {
  if (process.env.AGENTIC_SECURITY_NO_THREAT_MODEL_GROUNDING === '1') return { applied: 0 };
  if (!Array.isArray(findings) || findings.length === 0) return { applied: 0 };
  const tm = loadThreatModel(scanRoot);
  if (!tm.crownJewels.length && !tm.outOfScope.length && !tm.compliance.length && !tm.attacker) {
    return { applied: 0, reason: 'no-threat-model-found' };
  }
  let applied = 0;
  for (const f of findings) {
    const rel = f.file ? (path.isAbsolute(f.file) ? path.relative(scanRoot, f.file) : f.file) : '';

    // Out-of-scope demotion wins over crown-jewel promotion.
    if (rel && tm.outOfScope.some(g => _globMatch(g, rel))) {
      f.threatModel = { ...(f.threatModel || {}), outOfScope: true };
      f.severity = 'low';
      applied++;
      continue;
    }
    if (rel && tm.crownJewels.some(g => _globMatch(g, rel))) {
      f.threatModel = { ...(f.threatModel || {}), crownJewel: true };
      f.severity = _bumpSeverity(f.severity || 'medium');
      applied++;
    }
    // Compliance regime tagging based on family.
    const regimes = FAMILY_TO_REGIME[f.family];
    if (regimes && tm.compliance.length) {
      const matched = regimes.filter(r => tm.compliance.includes(r));
      if (matched.length) {
        f.threatModel = { ...(f.threatModel || {}), compliance: matched };
        applied++;
      }
    }
    if (tm.attacker) {
      f.threatModel = { ...(f.threatModel || {}), attacker: tm.attacker };
    }
  }
  return { applied, total: findings.length, threatModel: tm };
}

export const _internals = { _extractPathsFromSection, _extractCompliance, _extractAttacker, _bumpSeverity, _globMatch };
