// 0.8.0 Feat-10: License policy enforcement — allow/deny/review per SPDX license expression.
//
// Reads .agentic-security/license-policy.yml (allow / deny / review-required) and
// emits findings of kind 'license' for components whose license violates the policy.
//
// Policy file shape:
//   allow:   ['MIT', 'Apache-2.0', 'BSD-3-Clause', 'BSD-2-Clause', 'ISC', '0BSD']
//   deny:    ['GPL-3.0', 'GPL-2.0', 'AGPL-3.0', 'AGPL-1.0', 'SSPL-1.0']
//   review:  ['LGPL-2.1', 'LGPL-3.0', 'MPL-2.0']
//   unknown: 'review'   # 'deny' | 'allow' | 'review' — what to do with components missing a license
//
// Default policy (when no file exists) is permissive: nothing fires unless the
// user opts in by creating the policy file.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';

import { statePath } from './state-dir.js';
const DEFAULT_POLICY = {
  allow: [],
  deny: [],
  review: [],
  unknown: 'allow',
};

export function loadLicensePolicy(scanRoot) {
  if (!scanRoot) return null;
  for (const name of ['license-policy.yml', 'license-policy.yaml', 'license-policy.json']) {
    const p = statePath(scanRoot, name);
    if (!fs.existsSync(p)) continue;
    try {
      const raw = fs.readFileSync(p, 'utf8');
      const doc = name.endsWith('.json') ? JSON.parse(raw) : yaml.load(raw);
      return _normalize(doc);
    } catch (e) {
      return { _error: `Failed to parse ${p}: ${e.message}` };
    }
  }
  return null;
}

function _normalize(doc) {
  return {
    allow:   Array.isArray(doc?.allow)   ? doc.allow.map(_norm)   : [],
    deny:    Array.isArray(doc?.deny)    ? doc.deny.map(_norm)    : [],
    review:  Array.isArray(doc?.review)  ? doc.review.map(_norm)  : [],
    unknown: ['allow','deny','review'].includes(doc?.unknown) ? doc.unknown : 'allow',
  };
}

function _norm(s) { return String(s||'').trim().toUpperCase(); }

// Classify a single license string against the policy.
// Returns one of: 'allow' | 'deny' | 'review' | 'unknown'.
export function classifyLicense(license, policy) {
  policy = policy || DEFAULT_POLICY;
  if (!license || !license.trim()) return policy.unknown || 'allow';
  const norm = _norm(license);
  // SPDX expressions can be compound: "(MIT OR Apache-2.0)"; treat as deny if ANY
  // compound atom is denied; otherwise allow if any allowed atom matches.
  const atoms = norm.replace(/[()]/g, '').split(/\s+(?:OR|AND)\s+/i).map(s=>s.trim()).filter(Boolean);
  if (atoms.length > 1) {
    if (atoms.some(a => policy.deny.includes(a))) return 'deny';
    if (atoms.some(a => policy.review.includes(a))) return 'review';
    if (atoms.some(a => policy.allow.includes(a))) return 'allow';
    return policy.unknown || 'allow';
  }
  if (policy.deny.includes(norm))   return 'deny';
  if (policy.review.includes(norm)) return 'review';
  if (policy.allow.includes(norm))  return 'allow';
  return policy.unknown || 'allow';
}

// Run the policy against scan.components and emit findings of kind 'license'.
export function evaluateLicensePolicy(components, policy) {
  if (!policy) return [];
  if (policy._error) return [{
    id: 'license-policy:error',
    kind: 'license', severity: 'low',
    vuln: 'License policy file failed to parse',
    file: '.agentic-security/license-policy.yml', line: 0,
    snippet: policy._error,
  }];
  const findings = [];
  for (const c of components || []) {
    const verdict = classifyLicense(c.license || '', policy);
    if (verdict === 'allow') continue;
    const sev = verdict === 'deny' ? 'high' : 'low';
    const lic = c.license || '(none)';
    findings.push({
      id: `license-policy:${c.ecosystem}:${c.name}@${c.version}:${verdict}`,
      kind: 'license', severity: sev,
      vuln: verdict === 'deny'
        ? `Denied license: ${lic} in ${c.name}@${c.version}`
        : verdict === 'review'
          ? `License requires review: ${lic} in ${c.name}@${c.version}`
          : `Component without declared license: ${c.name}@${c.version}`,
      file: c.filePath || 'package.json', line: 0,
      snippet: `${c.ecosystem}:${c.name}@${c.version} — license ${lic}`,
      fix: verdict === 'deny'
        ? 'Replace this dependency with a license-compatible alternative, or move it under .agentic-security/license-policy.yml `review:` if your legal team approves a one-off exception.'
        : verdict === 'review'
          ? 'Have legal/license review confirm this license is compatible with your distribution model. Add it to `allow:` or `deny:` once decided.'
          : 'Confirm this dependency\'s actual license (check the upstream repo). Many `unknown` cases are misconfigured registry metadata for an otherwise-permissive license.',
      package: c.name, version: c.version, ecosystem: c.ecosystem, license: c.license || null,
    });
  }
  return findings;
}
