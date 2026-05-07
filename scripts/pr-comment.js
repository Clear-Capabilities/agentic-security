#!/usr/bin/env node
// Standalone PR-comment generator. Reads agentic-security JSON output from a path,
// writes a Markdown summary suitable for posting via gh pr comment.
//
// Usage:
//   node scripts/pr-comment.js <path-to-scan.json> > comment.md
//   gh pr comment <PR#> --body-file comment.md
'use strict';
const fs = require('fs');
const r = JSON.parse(fs.readFileSync(process.argv[2] || '.agentic-security/last-scan.json', 'utf8'));
const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
for (const f of r.findings) sev[f.severity] = (sev[f.severity] || 0) + 1;
const top = r.findings.filter(f => ['critical','high'].includes(f.severity)).slice(0, 10);
process.stdout.write([
  '## agentic-security scan',
  '',
  '| Critical | High | Medium | Low | Info |',
  '|---:|---:|---:|---:|---:|',
  `| ${sev.critical} | ${sev.high} | ${sev.medium} | ${sev.low} | ${sev.info} |`,
  '',
  top.length ? '### Top critical/high findings' : '_No critical or high findings._',
  '',
  ...top.map(f => `- **[${f.severity.toUpperCase()}]** \`${f.file}:${f.line}\` — ${f.vuln}${f.cwe ? ` (${f.cwe})` : ''}`),
  '',
].join('\n'));
