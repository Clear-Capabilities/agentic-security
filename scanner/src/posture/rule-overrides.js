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
import { verifyLastScan } from './integrity.js';
import { statePath } from './state-dir.js';

function _path(scanRoot) {
  return statePath(scanRoot, 'rules.yml');
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

// Premortem #4 — gate disable: entries on a sibling signature or explicit
// opt-out. `disable:` silently suppresses rules; without a guard, a PR that
// adds `disable: [cmd-injection-nodejs]` ships and the scanner stops firing
// on that family. By default we now REFUSE to honor `disable:` unless:
//   1. .agentic-security/rules.yml.sig exists and verifies the file body
//      with the same HMAC key the rest of the engine uses, OR
//   2. AGENTIC_SECURITY_RULES_UNSIGNED=1 is set (developer escape hatch —
//      this should NEVER be set in CI for an outside contribution).
// `severityOverrides`, `custom`, and `ignorePaths` remain in effect either
// way: they don't reduce coverage, they only add or remap.
function _disableAllowed(scanRoot) {
  if (process.env.AGENTIC_SECURITY_RULES_UNSIGNED === '1') return { ok: true, reason: 'unsigned-opt-in' };
  const fp = _path(scanRoot);
  if (!fs.existsSync(fp)) return { ok: true, reason: 'no-rules-file' };
  let body;
  try { body = fs.readFileSync(fp, 'utf8'); }
  catch { return { ok: false, reason: 'rules-unreadable' }; }
  const sigPath = fp + '.sig';
  if (!fs.existsSync(sigPath)) return { ok: false, reason: 'no-signature' };
  const ok = verifyLastScan(body, sigPath);
  return { ok: ok === true, reason: ok === true ? 'signed' : 'bad-signature' };
}

// Apply severity overrides + disable filter to a finding list.
// Harness-engineering note (post-derived): validate the overrides file BEFORE
// honoring any of it. If the YAML has a malformed severity, a broken custom
// regex, or any other syntax error, refuse the entire file and surface the
// reason on stderr. The previous shape "load, ignore broken entries, apply
// the rest" is exactly the silent-failure mode the post warns against.
export function applyOverrides(findings, scanRoot) {
  const o = loadOverrides(scanRoot);
  if (!o || (!o.severityOverrides && !o.disable?.length)) return findings;
  const v = validateOverrides(scanRoot);
  if (!v.ok) {
    if (!globalThis.__as_overrides_warned) {
      globalThis.__as_overrides_warned = true;
      try {
        process.stderr.write(`agentic-security: ignoring .agentic-security/rules.yml — validation failed:\n`);
        for (const e of v.errors) process.stderr.write(`  · ${e}\n`);
        process.stderr.write(`  Fix the errors above, or remove rules.yml. Findings will be returned unfiltered.\n`);
      } catch {}
    }
    return findings;
  }
  let disable;
  if (o.disable?.length) {
    const gate = _disableAllowed(scanRoot);
    if (gate.ok) {
      disable = new Set(o.disable);
    } else {
      // Refused. Surface the reason on stderr once per process so operators
      // who *meant* to disable a rule see why it didn't take.
      if (!globalThis.__as_disable_warned) {
        globalThis.__as_disable_warned = true;
        try {
          process.stderr.write(`agentic-security: ignoring 'disable:' in rules.yml — ${gate.reason}. Sign rules.yml with \`agentic-security rules sign\` or set AGENTIC_SECURITY_RULES_UNSIGNED=1 to opt in.\n`);
        } catch {}
      }
      disable = new Set();
    }
  } else {
    disable = new Set();
  }
  const sevMap = o.severityOverrides || {};
  return findings
    .filter(f => !disable.has(f.vuln) && !disable.has(f.id))
    .map(f => sevMap[f.vuln] ? { ...f, severity: sevMap[f.vuln] } : f);
}

// Cache: compiled custom rules per scanRoot. Validated at first call;
// subsequent calls for the same scan reuse the compiled regexes.
const _compiledCustomRules = new Map();   // scanRoot → { compiled[], errors[] }

function _compileCustomRules(scanRoot) {
  if (_compiledCustomRules.has(scanRoot)) return _compiledCustomRules.get(scanRoot);
  const o = loadOverrides(scanRoot);
  const result = { compiled: [], errors: [] };
  if (!o.custom || !o.custom.length) {
    _compiledCustomRules.set(scanRoot, result);
    return result;
  }
  for (let i = 0; i < o.custom.length; i++) {
    const rule = o.custom[i];
    if (!rule.id) { result.errors.push(`custom[${i}]: missing id`); continue; }
    if (!rule.regex) { result.errors.push(`custom[${i}] (${rule.id}): missing regex`); continue; }
    if (!rule.vuln) { result.errors.push(`custom[${i}] (${rule.id}): missing vuln`); continue; }
    if (!rule.severity) { result.errors.push(`custom[${i}] (${rule.id}): missing severity`); continue; }
    try {
      const re = new RegExp(rule.regex, rule.flags || 'g');
      result.compiled.push({ rule, re });
    } catch (e) {
      result.errors.push(`custom[${i}] (${rule.id}): bad regex: ${e.message}`);
    }
  }
  _compiledCustomRules.set(scanRoot, result);
  return result;
}

// Run user-defined custom regex rules against a file. Returns custom findings.
//
// Harness-engineering note (post-derived): rules are compiled and validated
// at first invocation per scan; if ANY rule fails to compile, that rule is
// excluded AND surfaced via stderr — never silently skipped per-call.
export function runCustomRules(filePath, fileContent, scanRoot) {
  const { compiled, errors } = _compileCustomRules(scanRoot);
  if (errors.length && !globalThis.__as_custom_rules_warned) {
    globalThis.__as_custom_rules_warned = true;
    try {
      process.stderr.write(`agentic-security: ${errors.length} custom rule(s) in .agentic-security/rules.yml failed to compile and were skipped:\n`);
      for (const e of errors) process.stderr.write(`  · ${e}\n`);
    } catch {}
  }
  if (!compiled.length) return [];
  const lines = fileContent.split('\n');
  const out = [];
  for (const { rule, re } of compiled) {
    re.lastIndex = 0;   // each file starts fresh for global regexes
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
