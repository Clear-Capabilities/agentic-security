// Side-by-side compare runner framework (v0.74).
//
// Generic framework for running a user-supplied scanner alongside
// agentic-security on the same codebase and producing a comparison
// card. We DO NOT ship configs for specific competitors — the
// framework is bring-your-own-tool. The user provides:
//
//   - the other tool's invocation (an argv array)
//   - a JSON path / regex that pulls findings out of its output
//   - the field names that map to {file, line, severity, vuln, cwe}
//
// The framework runs both, normalizes both to a common shape, and
// renders a Markdown comparison: overlap, agentic-security-only,
// other-only, severity disagreement.
//
// Usage:
//   agentic-security compare \\
//     --with "other-cli scan . --json" \\
//     --field-file "path" --field-line "lineNumber" \\
//     --field-severity "level" --field-vuln "ruleId" \\
//     --out compare.md
//
// The framework has zero knowledge of which "other tool" is running —
// users supply config that maps the other tool's output shape to ours.

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import { runFullScan } from './engine.js';

const SEVERITY_NORMALIZE = {
  critical: 'critical', crit: 'critical', error: 'critical', '5': 'critical',
  high:     'high',     warning: 'high',  warn: 'high',     '4': 'high',
  medium:   'medium',   mid: 'medium',                       '3': 'medium',
  low:      'low',      info: 'low',                         '2': 'low',
  note:     'info',     none: 'info',                        '1': 'info',
};

function _normalizeSeverity(s) {
  if (!s) return 'info';
  return SEVERITY_NORMALIZE[String(s).toLowerCase()] || 'info';
}

/**
 * Run the other tool with the given argv, parse its output as JSON,
 * extract findings via the field map.
 *
 *   argv: ['other-cli', 'scan', '.', '--json']
 *   fieldMap: { file: 'path', line: 'lineNumber', severity: 'level', vuln: 'ruleId', cwe: 'cwe' }
 *   rootArrayPath: 'results' (optional — JSONPath-lite into the response)
 */
export function runOtherTool(argv, { fieldMap, rootArrayPath, timeoutMs = 120_000 } = {}) {
  if (!Array.isArray(argv) || argv.length === 0) {
    return { ok: false, reason: 'no-argv', findings: [] };
  }
  const r = spawnSync(argv[0], argv.slice(1), { encoding: 'utf8', timeout: timeoutMs });
  if (r.error && r.error.code === 'ENOENT') {
    return { ok: false, reason: 'binary-missing', findings: [] };
  }
  if (r.status === null) {
    return { ok: false, reason: 'timed-out', findings: [] };
  }
  let parsed;
  try { parsed = JSON.parse(r.stdout || '{}'); }
  catch { return { ok: false, reason: 'json-parse-failed', findings: [] }; }
  let arr = parsed;
  if (rootArrayPath) {
    for (const k of rootArrayPath.split('.')) arr = arr ? arr[k] : null;
  }
  if (!Array.isArray(arr)) arr = [];
  const findings = arr.map(item => ({
    file: _get(item, fieldMap?.file || 'file'),
    line: Number(_get(item, fieldMap?.line || 'line')) || 0,
    severity: _normalizeSeverity(_get(item, fieldMap?.severity || 'severity')),
    vuln: String(_get(item, fieldMap?.vuln || 'vuln') || ''),
    cwe: _get(item, fieldMap?.cwe || 'cwe') || null,
    _other: true,
  })).filter(f => f.file);
  return { ok: true, findings, exitCode: r.status };
}

function _get(obj, path) {
  if (!obj || !path) return null;
  let cur = obj;
  for (const k of String(path).split('.')) {
    cur = cur ? cur[k] : null;
    if (cur == null) return null;
  }
  return cur;
}

/**
 * Compare two finding lists. Overlap is detected by (file, line, ±2)
 * regardless of CWE — different tools sometimes assign different CWEs
 * to the same shape.
 *
 * Returns:
 *   {
 *     overlap:        [{ ours, theirs }],          # both flagged same site
 *     oursOnly:       Finding[],                   # we found, they missed
 *     theirsOnly:     Finding[],                   # they found, we missed
 *     severityShift:  [{ ours, theirs, oursSev, theirsSev }],
 *   }
 */
export function compareFindings(ours, theirs) {
  const oursByLoc = new Map();
  for (const f of (ours || [])) {
    if (!f.file) continue;
    const key = `${f.file}:${f.line}`;
    if (!oursByLoc.has(key)) oursByLoc.set(key, []);
    oursByLoc.get(key).push(f);
  }
  const overlap = [];
  const severityShift = [];
  const theirsOnly = [];
  const matchedOurs = new Set();
  for (const t of (theirs || [])) {
    let matched = null;
    for (let d = -2; d <= 2; d++) {
      const key = `${t.file}:${t.line + d}`;
      const candidates = oursByLoc.get(key);
      if (candidates && candidates.length) { matched = candidates[0]; break; }
    }
    if (matched) {
      overlap.push({ ours: matched, theirs: t });
      matchedOurs.add(matched);
      if (matched.severity !== t.severity) {
        severityShift.push({ ours: matched, theirs: t, oursSev: matched.severity, theirsSev: t.severity });
      }
    } else {
      theirsOnly.push(t);
    }
  }
  const oursOnly = (ours || []).filter(f => !matchedOurs.has(f));
  return { overlap, oursOnly, theirsOnly, severityShift };
}

/**
 * Render the comparison as a Markdown card. Tool names are user-supplied
 * (per the no-competitor-names policy — the framework doesn't ship any
 * built-in adapter for specific competitors).
 */
export function renderComparison(comparison, { ourName = 'agentic-security', otherName = 'other-tool' } = {}) {
  const c = comparison || { overlap: [], oursOnly: [], theirsOnly: [], severityShift: [] };
  const lines = [];
  lines.push(`# Comparison: ${ourName} vs. ${otherName}`);
  lines.push('');
  lines.push(`| Metric | ${ourName} | ${otherName} |`);
  lines.push('|--------|------:|------:|');
  lines.push(`| Findings | ${c.overlap.length + c.oursOnly.length} | ${c.overlap.length + c.theirsOnly.length} |`);
  lines.push(`| Overlap  | ${c.overlap.length} | ${c.overlap.length} |`);
  lines.push(`| Unique   | ${c.oursOnly.length} | ${c.theirsOnly.length} |`);
  lines.push(`| Severity disagreement | ${c.severityShift.length} | — |`);
  lines.push('');
  if (c.oursOnly.length) {
    lines.push(`### ${c.oursOnly.length} findings only ${ourName} caught`);
    lines.push('');
    for (const f of c.oursOnly.slice(0, 10)) {
      lines.push(`- **${f.severity}** \`${f.file}:${f.line}\` — ${f.vuln} ${f.cwe ? `(${f.cwe})` : ''}`);
    }
    if (c.oursOnly.length > 10) lines.push(`- … +${c.oursOnly.length - 10} more`);
    lines.push('');
  }
  if (c.theirsOnly.length) {
    lines.push(`### ${c.theirsOnly.length} findings only ${otherName} caught`);
    lines.push('');
    for (const f of c.theirsOnly.slice(0, 10)) {
      lines.push(`- **${f.severity}** \`${f.file}:${f.line}\` — ${f.vuln} ${f.cwe ? `(${f.cwe})` : ''}`);
    }
    if (c.theirsOnly.length > 10) lines.push(`- … +${c.theirsOnly.length - 10} more`);
    lines.push('');
  }
  if (c.severityShift.length) {
    lines.push(`### ${c.severityShift.length} severity disagreements`);
    lines.push('');
    for (const s of c.severityShift.slice(0, 10)) {
      lines.push(`- \`${s.ours.file}:${s.ours.line}\` — ${ourName}: **${s.oursSev}**, ${otherName}: **${s.theirsSev}**`);
    }
    lines.push('');
  }
  if (c.overlap.length && !c.oursOnly.length && !c.theirsOnly.length) {
    lines.push('Perfect overlap — both tools agree on every finding.');
  }
  return lines.join('\n');
}

/**
 * Full pipeline: run agentic-security in-memory + run the other tool +
 * compare + render.
 */
export async function runComparison({ scanRoot, fileContents, otherArgv, otherFieldMap, otherRootArrayPath, ourName, otherName }) {
  // `provenance:false` — a comparison snapshot run against a caller-supplied
  // file set, used only to line up findings against another tool's output. It
  // must not resolve git provenance (nothing here asks for it) and must not
  // reach updateLifecycle, which would read this partial set as the project's
  // current open findings and remediate everything absent from it.
  const ourScan = await runFullScan({ fileContents, scanRoot, provenance: false }, () => {});
  const ours = (ourScan.findings || []).map(f => ({
    file: f.file, line: f.line || 0,
    severity: _normalizeSeverity(f.severity),
    vuln: f.vuln, cwe: f.cwe || null,
  }));
  const other = runOtherTool(otherArgv, { fieldMap: otherFieldMap, rootArrayPath: otherRootArrayPath });
  const comparison = compareFindings(ours, other.findings);
  const md = renderComparison(comparison, { ourName, otherName });
  return { ours, theirs: other.findings, comparison, markdown: md, otherStatus: other };
}

export const _internal = { _normalizeSeverity, _get };
