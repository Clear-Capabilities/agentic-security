// FR-PROD-1 — WAF rule-set ingest.
//
// Read a WAF rule set (Cloudflare custom rules JSON, AWS WAF JSON, ModSecurity
// `.conf`, or a normalized YAML) from one of the conventional locations:
//
//   .agentic-security/waf-rules.{json,yml,yaml,conf}
//   waf/rules.json
//   cloudflare-rules.json
//   aws-waf.json
//
// Build a list of `BlockRule { id, pattern, families }` where `families` is the
// set of attack families this rule unambiguously blocks. Conservative under-
// approximation: a finding is demoted to `mitigated-by-waf` only when its
// family appears in some rule's families AND the rule does not depend on
// runtime context the scanner cannot evaluate (e.g., per-customer rate
// thresholds).
//
// The format is intentionally narrow because vendor WAF rule semantics differ.
// We support these inputs:
//
//  Normalized YAML / JSON (recommended):
//    rules:
//      - id: cf-1
//        pattern: 'SQLi attempt'
//        families: ['sql-injection']
//      - id: cf-2
//        pattern: 'XSS reflected'
//        families: ['xss']
//
//  Cloudflare custom-rule export (best-effort):
//    [{ "id": "...", "expression": "...", "action": "block" }, ...]
//    Family is inferred from the expression text via SIGNAL_PATTERNS.
//
//  AWS WAF list-rules JSON: same expression-based heuristic.

import * as fs from 'node:fs';
import * as path from 'node:path';

const CANDIDATE_PATHS = [
  '.agentic-security/waf-rules.json',
  '.agentic-security/waf-rules.yml',
  '.agentic-security/waf-rules.yaml',
  '.agentic-security/waf-rules.conf',
  'waf/rules.json',
  'cloudflare-rules.json',
  'aws-waf.json',
];

const SIGNAL_PATTERNS = [
  [/sqli|sql.injection|union.+select/i, 'sql-injection'],
  [/xss|cross.site|<script|javascript:/i, 'xss'],
  [/ssrf|169\.254\.169\.254|metadata.google|localhost.+request/i, 'ssrf'],
  [/path.traversal|\.\.\//, 'path-traversal'],
  [/command.injection|shell.injection|\$\(|system\(|exec\(/i, 'command-injection'],
  [/xxe|external.entity|!ENTITY/i, 'xxe'],
  [/csrf|cross.site request/i, 'csrf'],
  [/open.redirect|url.redirect/i, 'open-redirect'],
  [/log4shell|log4j|jndi/i, 'jndi'],
  [/deserialization|gadget chain/i, 'unsafe-deserialization'],
  [/rate.?limit|rate.limit/i, 'unbounded-llm'],
  [/prompt.injection|jailbreak/i, 'prompt-injection'],
];

function inferFamilyFromExpression(expr) {
  if (!expr || typeof expr !== 'string') return [];
  const fams = new Set();
  for (const [re, fam] of SIGNAL_PATTERNS) {
    if (re.test(expr)) fams.add(fam);
  }
  return [...fams];
}

function parseNormalized(obj) {
  const rules = Array.isArray(obj.rules) ? obj.rules : [];
  return rules.map((r) => ({
    id: r.id || r.name || 'unnamed',
    pattern: r.pattern || r.description || '',
    families: Array.isArray(r.families) ? r.families : inferFamilyFromExpression(r.pattern || ''),
    vendor: r.vendor || 'normalized',
  }));
}

function parseCloudflare(arr) {
  return arr.filter(r => r && (r.action === 'block' || r.action === 'managed_challenge')).map((r) => ({
    id: r.id || r.ref || 'cf-' + Math.random().toString(36).slice(2, 8),
    pattern: r.description || r.expression || '',
    families: inferFamilyFromExpression(r.expression || r.description || ''),
    vendor: 'cloudflare',
  }));
}

function parseAwsWaf(obj) {
  const rules = obj.Rules || obj.rules || [];
  return rules.map((r) => ({
    id: r.Name || r.name || 'aws-' + Math.random().toString(36).slice(2, 8),
    pattern: JSON.stringify(r.Statement || r.statement || {}).slice(0, 200),
    families: inferFamilyFromExpression(JSON.stringify(r.Statement || r.statement || {})),
    vendor: 'aws-waf',
  })).filter(r => r.families.length > 0);
}

function parseYamlLike(text) {
  // Tiny YAML subset parser — enough for our recommended shape. NOT a real
  // YAML parser. Falls back to JSON.parse on failure.
  try { return JSON.parse(text); } catch {}
  const rules = [];
  let current = null;
  for (const raw of text.split(/\n/)) {
    const ln = raw.replace(/#.*$/, '').replace(/\s+$/, '');
    if (!ln.trim()) continue;
    const dashMatch = /^\s*-\s+(\w+):\s*(.*)$/.exec(ln);
    const kvMatch = /^\s+(\w+):\s*(.*)$/.exec(ln);
    if (dashMatch) {
      if (current) rules.push(current);
      current = {};
      current[dashMatch[1]] = parseScalar(dashMatch[2]);
    } else if (kvMatch && current) {
      current[kvMatch[1]] = parseScalar(kvMatch[2]);
    }
  }
  if (current) rules.push(current);
  return { rules };
}

function parseScalar(s) {
  s = s.trim();
  if (s === '' || s === '~' || s === 'null') return null;
  if (/^\[.*\]$/.test(s)) {
    return s.slice(1, -1).split(',').map(t => t.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean);
  }
  return s.replace(/^['"]|['"]$/g, '');
}

export function loadWafRules(scanRoot) {
  const root = scanRoot || process.cwd();
  for (const rel of CANDIDATE_PATHS) {
    const fp = path.join(root, rel);
    if (!fs.existsSync(fp)) continue;
    let text;
    try { text = fs.readFileSync(fp, 'utf8'); } catch { continue; }
    try {
      const trimmed = text.trim();
      if (trimmed.startsWith('[')) {
        return parseCloudflare(JSON.parse(trimmed));
      }
      if (trimmed.startsWith('{')) {
        const obj = JSON.parse(trimmed);
        if (obj.Rules || obj.rules?.[0]?.Statement) return parseAwsWaf(obj);
        if (obj.rules) return parseNormalized(obj);
      }
      // YAML-like
      const parsed = parseYamlLike(text);
      if (parsed && parsed.rules) return parseNormalized(parsed);
    } catch {
      // Fall through to next candidate.
    }
  }
  return [];
}

function familyOf(f) {
  if (f.family) return String(f.family).toLowerCase();
  const v = (f.vuln || '').toLowerCase();
  if (/sql.*injection/.test(v)) return 'sql-injection';
  if (/command.*injection/.test(v)) return 'command-injection';
  if (/xss|cross.site/.test(v)) return 'xss';
  if (/ssrf/.test(v)) return 'ssrf';
  if (/path.travers/.test(v)) return 'path-traversal';
  if (/xxe/.test(v)) return 'xxe';
  if (/csrf/.test(v)) return 'csrf';
  if (/jndi|log4shell/.test(v)) return 'jndi';
  if (/deserial/.test(v)) return 'unsafe-deserialization';
  if (/open.redirect/.test(v)) return 'open-redirect';
  if (/prompt injection/.test(v)) return 'prompt-injection';
  if (/max_tokens|unbounded/.test(v)) return 'unbounded-llm';
  return 'unknown';
}

export function annotateWafMitigation(findings, scanRoot) {
  if (!Array.isArray(findings)) return { findings, rules: [] };
  const rules = loadWafRules(scanRoot);
  if (!rules.length) return { findings, rules };
  const byFamily = new Map();
  for (const r of rules) {
    for (const fam of r.families) {
      if (!byFamily.has(fam)) byFamily.set(fam, []);
      byFamily.get(fam).push(r);
    }
  }
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fam = familyOf(f);
    if (!byFamily.has(fam)) continue;
    const matched = byFamily.get(fam);
    f.mitigatedByWaf = true;
    f.wafRuleId = matched.map(r => `${r.vendor}:${r.id}`).join(',');
    f.wafMatchedFamilies = [fam];
  }
  return { findings, rules };
}
