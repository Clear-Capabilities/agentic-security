#!/usr/bin/env node
// FR-SDLC-10 — Differential scanner CLI.
//
// Run two versions of the scanner against the same target and emit the
// delta. Use cases:
//   1. PR-time regression detection — catch when an upgrade of the scanner
//      itself loses or adds findings on a stable codebase.
//   2. Migration confidence — let a customer dry-run a scanner upgrade
//      before bumping their pinned version.
//
// Usage:
//   agentic-security-diff --baseline ./dist/agentic-security.mjs \
//                         --candidate ./dist/agentic-security.mjs.next \
//                         [--root .]
//
// Both `--baseline` and `--candidate` paths must point to runnable scanner
// bundles. The CLI invokes each via child_process with `--format json` and
// computes the diff on the resulting findings list (keyed by `stableId`
// when present, else by `(file, line, family)`).

import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import * as fs from 'node:fs';

function parseArgs(argv) {
  const opts = { root: '.', baseline: null, candidate: null, format: 'cli' };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--baseline') opts.baseline = argv[++i];
    else if (a === '--candidate') opts.candidate = argv[++i];
    else if (a === '--root') opts.root = argv[++i];
    else if (a === '--format') opts.format = argv[++i];
    else if (a === '--help' || a === '-h') opts.help = true;
  }
  return opts;
}

function runScan(binPath, root) {
  if (!fs.existsSync(binPath)) {
    return { error: `binary not found: ${binPath}`, findings: [] };
  }
  const res = spawnSync(process.execPath, [binPath, 'scan', root, '--format', 'json'], {
    encoding: 'utf8',
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  if (res.status !== 0 && !res.stdout) {
    return { error: `scanner exited ${res.status}: ${(res.stderr || '').slice(0, 200)}`, findings: [] };
  }
  try {
    const data = JSON.parse(res.stdout);
    const findings = Array.isArray(data) ? data : (data.findings || []);
    return { findings };
  } catch (e) {
    return { error: `failed to parse JSON: ${e.message}`, findings: [] };
  }
}

function keyOf(f) {
  if (f.stableId) return `sid:${f.stableId}`;
  return `pos:${f.file}:${f.line}:${f.family || f.vuln || '?'}`;
}

function diff(baseline, candidate) {
  const byKey = (arr) => {
    const m = new Map();
    for (const f of arr) m.set(keyOf(f), f);
    return m;
  };
  const a = byKey(baseline);
  const b = byKey(candidate);
  const added = [], removed = [], changed = [];
  for (const [k, f] of b) {
    if (!a.has(k)) added.push(f);
    else {
      const prev = a.get(k);
      if (prev.severity !== f.severity || prev.vuln !== f.vuln) changed.push({ before: prev, after: f });
    }
  }
  for (const [k, f] of a) if (!b.has(k)) removed.push(f);
  return { added, removed, changed };
}

function summarize(d) {
  const lines = [];
  lines.push('# Differential scan report');
  lines.push('');
  lines.push(`Added:    ${d.added.length}`);
  lines.push(`Removed:  ${d.removed.length}`);
  lines.push(`Changed:  ${d.changed.length}`);
  lines.push('');
  if (d.added.length) {
    lines.push('## Added (candidate found, baseline did not)');
    for (const f of d.added.slice(0, 25)) lines.push(`  + [${f.severity}] ${f.vuln || ''} at ${f.file}:${f.line}`);
    if (d.added.length > 25) lines.push(`  + ... ${d.added.length - 25} more`);
    lines.push('');
  }
  if (d.removed.length) {
    lines.push('## Removed (baseline found, candidate did not)');
    for (const f of d.removed.slice(0, 25)) lines.push(`  - [${f.severity}] ${f.vuln || ''} at ${f.file}:${f.line}`);
    if (d.removed.length > 25) lines.push(`  - ... ${d.removed.length - 25} more`);
    lines.push('');
  }
  if (d.changed.length) {
    lines.push('## Changed (same finding, different severity or wording)');
    for (const c of d.changed.slice(0, 15)) {
      lines.push(`  ~ [${c.before.severity}→${c.after.severity}] ${c.after.file}:${c.after.line}`);
    }
    lines.push('');
  }
  return lines.join('\n');
}

function main() {
  const opts = parseArgs(process.argv);
  if (opts.help || !opts.baseline || !opts.candidate) {
    console.log('Usage: agentic-security-diff --baseline <bin> --candidate <bin> [--root .] [--format cli|json]');
    process.exit(opts.help ? 0 : 1);
  }
  const root = path.resolve(opts.root);
  const baseline = runScan(opts.baseline, root);
  const candidate = runScan(opts.candidate, root);
  if (baseline.error) { console.error('baseline:', baseline.error); process.exit(2); }
  if (candidate.error) { console.error('candidate:', candidate.error); process.exit(2); }
  const d = diff(baseline.findings, candidate.findings);
  if (opts.format === 'json') {
    process.stdout.write(JSON.stringify(d, null, 2));
  } else {
    process.stdout.write(summarize(d));
  }
  // Exit 0 if no delta, 1 if delta, 2 if errors (already exited above).
  const hasDelta = d.added.length || d.removed.length || d.changed.length;
  process.exit(hasDelta ? 1 : 0);
}

main();
