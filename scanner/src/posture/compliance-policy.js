// Compliance-as-code DSL — Recommendation #9 of the world-class+2 plan.
//
// Customers declare their compliance policy in
// .agentic-security/compliance.policy.yml. The scanner reads the policy,
// runs verification (each rule is a deterministic check against scanner
// findings + config files + state) and emits a structured JSON-LD
// evidence file consumable by Vanta / Drata / SecureFrame / auditors.
//
// DSL shape:
//
//   framework: "SOC2 Type II"
//   controls:
//     CC6.1:
//       title: "Logical access controls"
//       requires:
//         - finding-family: "auth-missing"
//           must-be: zero
//         - file-exists: ".github/dependabot.yml"
//         - documented: ".agentic-security/auth-policy.md"
//       evidence:
//         - "Scanner finds 0 auth-missing findings on the current release"
//         - "Dependency-update automation present"
//     CC7.2:
//       title: "Security incident response"
//       requires:
//         - file-exists: "INCIDENT-PLAN.md"
//
// Verifier primitives in v1:
//   finding-family: <name>     must-be: zero | min: <n> | max: <n>
//   file-exists: <relative-path>
//   documented: <relative-path>  (alias for file-exists)
//   env-var-set: <name>
//   sca-policy-has-entry: <type>  (e.g. accept-risk, sla)
//
// Output:
//   .agentic-security/compliance-evidence.json — JSON-LD compliant
//     structured artifact
//   .agentic-security/compliance-evidence.md — human-readable summary

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

const POLICY_FILE = 'compliance.policy.yml';

export function loadPolicy(scanRoot) {
  const fp = path.join(scanRoot, '.agentic-security', POLICY_FILE);
  if (!fs.existsSync(fp)) return null;
  try {
    const raw = fs.readFileSync(fp, 'utf8');
    const doc = yaml.load(raw);
    return _normalize(doc);
  } catch (e) {
    return { _error: `Failed to parse ${fp}: ${e.message}` };
  }
}

function _normalize(doc) {
  if (!doc) return null;
  return {
    framework: doc.framework || 'Custom',
    version: doc.version || '1.0',
    controls: Object.entries(doc.controls || {}).map(([id, c]) => ({
      id,
      title: c.title || id,
      requires: Array.isArray(c.requires) ? c.requires : [],
      evidence: Array.isArray(c.evidence) ? c.evidence : [],
      not_applicable: !!c['not-applicable'],
    })),
  };
}

/**
 * Run a single primitive check against the scanner state.
 *   { passed, reason }
 */
function _runCheck(check, ctx) {
  if (check['finding-family']) {
    const family = check['finding-family'];
    const matching = (ctx.findings || []).filter(f => f.family === family);
    if (check['must-be'] === 'zero') {
      if (matching.length === 0) return { passed: true, reason: '0 findings' };
      return { passed: false, reason: `${matching.length} findings in family '${family}'` };
    }
    if (typeof check.min === 'number') {
      if (matching.length >= check.min) return { passed: true, reason: `${matching.length} ≥ ${check.min}` };
      return { passed: false, reason: `${matching.length} < ${check.min}` };
    }
    if (typeof check.max === 'number') {
      if (matching.length <= check.max) return { passed: true, reason: `${matching.length} ≤ ${check.max}` };
      return { passed: false, reason: `${matching.length} > ${check.max}` };
    }
    return { passed: false, reason: 'finding-family check has no must-be/min/max' };
  }
  if (check['file-exists'] || check['documented']) {
    const rel = check['file-exists'] || check['documented'];
    const fp = path.join(ctx.scanRoot, rel);
    if (fs.existsSync(fp)) return { passed: true, reason: `${rel} exists` };
    return { passed: false, reason: `${rel} not found` };
  }
  if (check['env-var-set']) {
    const name = check['env-var-set'];
    if (process.env[name]) return { passed: true, reason: `$${name} set` };
    return { passed: false, reason: `$${name} not set` };
  }
  if (check['sca-policy-has-entry']) {
    const type = check['sca-policy-has-entry'];
    const policyPath = path.join(ctx.scanRoot, '.agentic-security', 'sca-policy.yml');
    if (!fs.existsSync(policyPath)) return { passed: false, reason: 'sca-policy.yml not found' };
    try {
      const policy = yaml.load(fs.readFileSync(policyPath, 'utf8'));
      if (type === 'accept-risk' && Array.isArray(policy['accept-risk']) && policy['accept-risk'].length) {
        return { passed: true, reason: `${policy['accept-risk'].length} accept-risk entries` };
      }
      if (type === 'sla' && policy.sla && Object.keys(policy.sla).length) {
        return { passed: true, reason: `${Object.keys(policy.sla).length} SLA buckets defined` };
      }
      return { passed: false, reason: `no ${type} entries in sca-policy.yml` };
    } catch (e) {
      return { passed: false, reason: 'sca-policy.yml parse error: ' + e.message };
    }
  }
  return { passed: false, reason: 'unknown check primitive' };
}

/**
 * Run all controls in the policy and emit a verification report.
 */
export function verifyPolicy(policy, ctx) {
  if (!policy || !policy.controls) return { controls: [], status: 'no-policy' };
  const results = [];
  for (const control of policy.controls) {
    if (control.not_applicable) {
      results.push({ ...control, status: 'not-applicable', checks: [] });
      continue;
    }
    const checkResults = control.requires.map(c => ({ check: c, result: _runCheck(c, ctx) }));
    const allPassed = checkResults.every(r => r.result.passed);
    results.push({
      ...control,
      status: allPassed ? 'compliant' : 'non-compliant',
      checks: checkResults,
    });
  }
  const summary = {
    total: results.length,
    compliant: results.filter(r => r.status === 'compliant').length,
    nonCompliant: results.filter(r => r.status === 'non-compliant').length,
    notApplicable: results.filter(r => r.status === 'not-applicable').length,
  };
  return { framework: policy.framework, version: policy.version, controls: results, summary };
}

/**
 * Emit JSON-LD compliance evidence (the Vanta/Drata-shape artifact).
 */
export function emitEvidenceJsonLd(report, scanRoot) {
  if (!report) return null;
  const jsonld = {
    '@context': {
      '@vocab': 'https://agentic-security.io/compliance/v1/',
      'schema': 'https://schema.org/',
    },
    '@type': 'ComplianceEvidence',
    framework: report.framework,
    version: report.version,
    generatedAt: new Date().toISOString(),
    summary: report.summary,
    controls: report.controls.map(c => ({
      '@type': 'Control',
      id: c.id, title: c.title, status: c.status,
      checks: c.checks.map(ck => ({
        '@type': 'Check',
        rule: ck.check,
        passed: ck.result.passed,
        reason: ck.result.reason,
      })),
      narrative_evidence: c.evidence || [],
    })),
  };
  try {
    fs.mkdirSync(path.join(scanRoot, '.agentic-security'), { recursive: true });
    fs.writeFileSync(path.join(scanRoot, '.agentic-security', 'compliance-evidence.json'), JSON.stringify(jsonld, null, 2));
  } catch {}
  return jsonld;
}

/**
 * Emit a human-readable markdown summary.
 */
export function emitEvidenceMarkdown(report, scanRoot) {
  const lines = [];
  lines.push(`# Compliance evidence — ${report.framework}`);
  lines.push('');
  lines.push(`Generated by agentic-security on ${new Date().toISOString().slice(0,10)}.`);
  lines.push('');
  lines.push(`Compliant: **${report.summary.compliant}** / Non-compliant: **${report.summary.nonCompliant}** / Not applicable: **${report.summary.notApplicable}** of ${report.summary.total} controls.`);
  lines.push('');
  for (const c of report.controls) {
    lines.push(`## ${c.id} — ${c.title}  (${c.status})`);
    for (const ck of c.checks) {
      const mark = ck.result.passed ? '✓' : '✗';
      lines.push(`- ${mark} \`${JSON.stringify(ck.check)}\` — ${ck.result.reason}`);
    }
    if (c.evidence && c.evidence.length) {
      lines.push('');
      lines.push('**Narrative evidence:**');
      for (const e of c.evidence) lines.push(`- ${e}`);
    }
    lines.push('');
  }
  try {
    fs.writeFileSync(path.join(scanRoot, '.agentic-security', 'compliance-evidence.md'), lines.join('\n'));
  } catch {}
  return lines.join('\n');
}

export const _internals = { _normalize, _runCheck };
