// Rule pack overrides (R9). Pro users edit .agentic-security/rules.yml to:
//   - severityOverrides: per-rule severity remap
//   - disable: list of rule vuln strings or rule IDs to skip entirely
//   - custom: user-defined regex rules (with vuln/severity/cwe/fix metadata)
//   - version: pin to a specific scanner version for reproducibility
//
// Engine integration: scanner consults this module after producing findings.
// `applyOverrides(findings, scanRoot)` returns a filtered/remapped list.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

const OVERRIDES_PATH = '.agentic-security/rules.yml';

function _path(scanRoot) {
  return path.join(scanRoot || process.cwd(), OVERRIDES_PATH);
}

export function loadOverrides(scanRoot) {
  const fp = _path(scanRoot);
  if (!fs.existsSync(fp)) return {};
  try {
    const raw = yaml.load(fs.readFileSync(fp, 'utf8')) || {};
    return {
      version: raw.version || null,
      severityOverrides: raw.severityOverrides || {},
      disable: Array.isArray(raw.disable) ? raw.disable : [],
      custom: Array.isArray(raw.custom) ? raw.custom : [],
      ignorePaths: Array.isArray(raw.ignorePaths) ? raw.ignorePaths : [],
    };
  } catch (_) { return {}; }
}

// Validate the user's rules.yml. Returns { ok, errors[] }.
export function validateOverrides(scanRoot) {
  const errors = [];
  const o = loadOverrides(scanRoot);
  if (o.severityOverrides) {
    for (const [vuln, sev] of Object.entries(o.severityOverrides)) {
      if (!['critical', 'high', 'medium', 'low', 'info'].includes(sev)) {
        errors.push(`severityOverrides["${vuln}"]: invalid severity "${sev}"`);
      }
    }
  }
  if (o.custom) {
    for (let i = 0; i < o.custom.length; i++) {
      const c = o.custom[i];
      if (!c.id) errors.push(`custom[${i}]: missing id`);
      if (!c.regex) errors.push(`custom[${i}]: missing regex`);
      else { try { new RegExp(c.regex); } catch (e) { errors.push(`custom[${i}]: bad regex: ${e.message}`); } }
      if (!c.vuln) errors.push(`custom[${i}]: missing vuln`);
      if (!c.severity) errors.push(`custom[${i}]: missing severity`);
    }
  }
  return { ok: errors.length === 0, errors };
}

// Apply severity overrides + disable filter to a finding list.
export function applyOverrides(findings, scanRoot) {
  const o = loadOverrides(scanRoot);
  if (!o || (!o.severityOverrides && !o.disable?.length)) return findings;
  const disable = new Set(o.disable || []);
  const sevMap = o.severityOverrides || {};
  return findings
    .filter(f => !disable.has(f.vuln) && !disable.has(f.id))
    .map(f => sevMap[f.vuln] ? { ...f, severity: sevMap[f.vuln] } : f);
}

// Run user-defined custom regex rules against a file. Returns custom findings.
export function runCustomRules(filePath, fileContent, scanRoot) {
  const o = loadOverrides(scanRoot);
  if (!o.custom || !o.custom.length) return [];
  const lines = fileContent.split('\n');
  const out = [];
  for (const rule of o.custom) {
    let re;
    try { re = new RegExp(rule.regex, rule.flags || 'g'); }
    catch (_) { continue; }
    let m;
    while ((m = re.exec(fileContent)) !== null) {
      const lineNum = fileContent.substring(0, m.index).split('\n').length;
      out.push({
        id: `custom:${rule.id}:${filePath}:${lineNum}`,
        vuln: rule.vuln,
        severity: rule.severity,
        cwe: rule.cwe || '',
        stride: rule.stride || '',
        file: filePath,
        line: lineNum,
        snippet: lines[lineNum - 1]?.trim() || m[0],
        fix: rule.fix || '',
        description: rule.description || '',
        custom: true,
        parser: 'CUSTOM_RULE',
      });
      if (!re.global) break;
    }
  }
  return out;
}
