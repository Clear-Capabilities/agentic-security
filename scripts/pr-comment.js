#!/usr/bin/env node
// Standalone PR-comment generator. Reads agentic-security scan JSON, writes
// a Markdown summary suitable for posting via `gh pr comment`.
//
// Usage:
//   node scripts/pr-comment.js <path-to-scan.json> [--baseline <path>]
//   gh pr comment <PR#> --body-file comment.md
//
// Optional second argument is a baseline scan to diff against. When present,
// the comment includes a grade delta and a "since baseline" diff line.
'use strict';
const fs = require('fs');

const argv = process.argv.slice(2);
const scanPath = argv.find(a => !a.startsWith('--')) || '.agentic-security/last-scan.json';
const blIdx = argv.indexOf('--baseline');
const baselinePath = blIdx >= 0 ? argv[blIdx + 1] : null;

function loadScan(p) {
  try { return JSON.parse(fs.readFileSync(p, 'utf8')); } catch { return null; }
}

function counts(scan) {
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of (scan?.findings || [])) sev[f.severity] = (sev[f.severity] || 0) + 1;
  for (const s of (scan?.supplyChain || []).filter(s => s.type === 'vulnerable_dep')) {
    sev[s.severity || 'high'] = (sev[s.severity || 'high'] || 0) + 1;
  }
  return sev;
}

function computeGrade(scan) {
  const c = counts(scan);
  const kev = [...(scan?.findings || []), ...(scan?.supplyChain || [])].filter(f => f.kev === true).length;
  if (c.critical > 10 || (c.critical > 5 && kev > 0)) return 'F';
  if (c.critical >= 6) return 'D';
  if (kev > 0) return 'D';
  if (c.critical >= 3) return 'C-';
  if (c.critical >= 1) return 'C';
  if (c.high > 10) return 'B-';
  if (c.high >= 3) return 'B';
  if (c.high > 0) return 'A-';
  if (c.medium > 0) return 'A';
  return 'A+';
}

function badgeUrl(grade) {
  const colors = { 'A+': 'brightgreen', 'A': 'brightgreen', 'A-': 'green', 'B': 'green', 'B-': 'yellowgreen', 'C': 'yellow', 'C-': 'orange', 'D': 'orange', 'F': 'red' };
  const params = new URLSearchParams({
    label: 'agentic-security',
    message: grade,
    color: colors[grade] || 'lightgrey',
    logo: 'shield',
    logoColor: 'white',
  });
  return 'https://img.shields.io/static/v1?' + params.toString();
}

function gradeDeltaLine(prev, now) {
  if (!prev || prev === now) return null;
  const RANK = { 'F': 0, 'D': 1, 'C-': 2, 'C': 3, 'B-': 4, 'B': 5, 'A-': 6, 'A': 7, 'A+': 8 };
  const direction = (RANK[now] ?? 0) > (RANK[prev] ?? 0) ? '📈 up' : '📉 down';
  return `Grade ${direction}: **${prev}** → **${now}**`;
}

const scan = loadScan(scanPath);
if (!scan) { process.stderr.write(`Could not load scan at ${scanPath}\n`); process.exit(1); }
const baseline = baselinePath ? loadScan(baselinePath) : null;

const sev = counts(scan);
const grade = computeGrade(scan);
const baselineGrade = baseline ? computeGrade(baseline) : null;
const baselineSev = baseline ? counts(baseline) : null;
const top = (scan.findings || []).filter(f => ['critical','high'].includes(f.severity)).slice(0, 10);
const repo = 'https://github.com/clearcapabilities/agentic-security';

const lines = [];
// Header — badge + grade delta
lines.push(`<a href="${repo}"><img alt="agentic-security: ${grade}" src="${badgeUrl(grade)}" /></a>`);
lines.push('');
lines.push('## agentic-security scan');
lines.push('');
const delta = gradeDeltaLine(baselineGrade, grade);
if (delta) {
  lines.push(delta);
  lines.push('');
}

lines.push('| Critical | High | Medium | Low | Info |');
lines.push('|---:|---:|---:|---:|---:|');
if (baselineSev) {
  // Show delta in each column when baseline available
  const fmt = (now, was) => {
    if (now === was) return String(now);
    const d = now - was;
    return `${now} (${d > 0 ? '+' : ''}${d})`;
  };
  lines.push(`| ${fmt(sev.critical, baselineSev.critical)} | ${fmt(sev.high, baselineSev.high)} | ${fmt(sev.medium, baselineSev.medium)} | ${fmt(sev.low, baselineSev.low)} | ${fmt(sev.info, baselineSev.info)} |`);
} else {
  lines.push(`| ${sev.critical} | ${sev.high} | ${sev.medium} | ${sev.low} | ${sev.info} |`);
}
lines.push('');
lines.push(top.length ? '### Top critical/high findings' : '_No critical or high findings._');
lines.push('');
for (const f of top) {
  lines.push(`- **[${f.severity.toUpperCase()}]** \`${f.file}:${f.line}\` — ${f.vuln}${f.cwe ? ` (${f.cwe})` : ''}`);
}
lines.push('');
lines.push(`<sub>Powered by <a href="${repo}">agentic-security</a> · run \`/security-grade\` locally for the full picture.</sub>`);
lines.push('');
process.stdout.write(lines.join('\n'));
