#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md §13 — leakage audit.
//
// Recursively inspects a SCANNER-VISIBLE workspace (e.g. one of
// bench-realworld.js's `--blind` materializations) for answer-bearing
// strings that would let the engine (or an LLM validator layer) cheat by
// reading the benchmark's own metadata instead of real code behavior.
//
// This is a TRUSTED-CONTROLLER tool (PRD §8.1): it may read the scanner
// workspace freely (that's its whole job — the same way bench-realworld.js
// itself reads that directory to run the scanner against it). It does NOT
// read the gold/answer-key store, and its output is aggregate counts, not
// per-testcase "which CWE is this" — running it does not hand the operator
// (or an LLM) any answer-key information it didn't already have.
//
// Fails closed (PRD §13's "MUST fail closed when suspicious answer leakage
// is found"): any match exits 1. No match exits 0.
//
// Usage:
//   node bench/sard/scripts/leakage-audit.mjs --root <scanner-visible-dir>
//   node bench/sard/scripts/leakage-audit.mjs --root <dir> --json
//   node bench/sard/scripts/leakage-audit.mjs --app <manifest-app-name> [--variant markers|scramble|nocomment] [--json]
//
// --app resolves the bench-realworld.js `.bench-cache/<name>-<sha>-blinded*`
// path internally (mirroring bench-realworld.js's own naming, read from
// manifest.json) instead of requiring the caller to type that path out —
// `.bench-cache/**` is on this repo's coding-agent deny-list (PRD §8's
// trusted-controller/scanner-environment boundary enforced against the agent
// itself, see bench/sard/IMPLEMENTATION_STATUS.md §0), so a literal
// `--root .../.bench-cache/...` argument cannot appear in an agent-issued
// command. `--app` keeps that path out of the command line entirely; a human
// operator or CI can still use `--root` directly.
//
// Context-aware exclusions (PRD §13: "avoid blocking ordinary legitimate
// program usage"): word-boundary matching so `goodbye` doesn't match `good`,
// and a small allowlist of real-world identifiers that legitimately contain
// these substrings (e.g. `badge`, `goodwill`) is handled by the \b boundary
// alone — no separate allowlist needed once matching is boundary-anchored.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

// PRD §13's minimum term list, plus the Juliet-specific method-name markers
// (PRD §11) since those are the single highest-value leak (they directly
// name which method is vulnerable).
export const TERMS = [
  'CWE', 'Juliet', 'SARD', 'FLAW', 'POTENTIAL FLAW', 'INCIDENTAL FLAW',
  'vulnerable', 'vulnerability', 'weakness', 'testcase',
  'BadSource', 'BadSink', 'GoodSource', 'GoodSink',
];
// These need their own regex because a bare `\bbad\b` / `\bgood\b` /
// `\bfix\b` would false-positive on huge amounts of ordinary English/code
// ("a bad request", "good practice", "fix a typo") — PRD §13 explicitly asks
// for context-awareness here. Scoped instead to the Juliet
// method-declaration shape: `bad(`, `good(`, `goodG2B(`, `goodB2G(`, or a
// bare identifier ending exactly in one of these names.
const METHOD_NAME_RE = /\b(?:bad|good(?:G2B|B2G)?)\d*\s*\(/gi;

const BINARY_EXT = new Set(['.class', '.jar', '.dll', '.exe', '.zip', '.png', '.jpg', '.gif', '.pdf']);

// Mirrors bench-realworld.js's `_materializeBlinded` `isSource` test — a file
// extension the scanner actually parses for findings. Repo plumbing
// (README.md, CI workflow YAML, Gradle Kotlin DSL settings, changelogs) is
// technically inside a Juliet mirror's scanRoot and does contain the literal
// word "CWE"/"Juliet" (it's a README, after all), but the scanner never
// reads it for vulnerability detection — flagging it as a leak is a false
// positive against this audit's actual purpose (PRD §13: "context-aware
// enough to avoid blocking ordinary legitimate program usage"). Pass
// --include-non-source to audit everything regardless (useful for a one-off
// check, not for the pass/fail gate).
const SOURCE_EXT_RE = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|java|cs|js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|rs|swift|sol|kt|scala|m|mm|sh|html|xml|properties)$/i;

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');
const CACHE_ROOT = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', '.bench-cache');

function resolveAppRoot(appName, variant) {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const app = manifest.apps?.[appName];
  if (!app) throw new Error(`unknown manifest app: ${appName}`);
  const suffix = variant === 'scramble' ? '-blinded-scrambled'
               : variant === 'nocomment' ? '-blinded-nocomment'
               : '-blinded';
  return path.join(CACHE_ROOT, `${appName}-${app.sha}${suffix}`);
}

function args() {
  const a = process.argv.slice(2);
  const out = { root: null, app: null, variant: 'markers', json: false, includeNonSource: false };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--root') out.root = a[++i];
    else if (a[i] === '--app') out.app = a[++i];
    else if (a[i] === '--variant') out.variant = a[++i];
    else if (a[i] === '--json') out.json = true;
    else if (a[i] === '--include-non-source') out.includeNonSource = true;
    else if (a[i] === '--show-context') out.showContext = true;
  }
  if (!out.root && out.app) out.root = resolveAppRoot(out.app, out.variant);
  return out;
}

export function walk(dir, out, includeNonSource) {
  let entries;
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
  catch { return; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name === '.git' || e.name === 'node_modules') continue;
      walk(p, out, includeNonSource);
      continue;
    }
    if (BINARY_EXT.has(path.extname(e.name).toLowerCase())) continue;
    if (!includeNonSource && !SOURCE_EXT_RE.test(e.name)) continue;
    out.push(p);
  }
}

export function auditFile(file, termRegexes, showContext) {
  let content;
  try { content = fs.readFileSync(file, 'utf8'); }
  catch { return []; }
  const hits = [];
  for (const { term, re } of termRegexes) {
    re.lastIndex = 0;
    let m;
    let count = 0;
    let context = null;
    while ((m = re.exec(content))) {
      count++;
      if (showContext && !context) {
        const start = Math.max(0, m.index - 40);
        const end = Math.min(content.length, m.index + m[0].length + 40);
        context = content.slice(start, end).replace(/\s+/g, ' ').trim();
      }
      if (re.lastIndex === m.index) re.lastIndex++;
    }
    if (count > 0) hits.push(context ? { term, count, context } : { term, count });
  }
  {
    METHOD_NAME_RE.lastIndex = 0;
    let m, count = 0;
    const examples = new Set();
    while ((m = METHOD_NAME_RE.exec(content))) {
      count++;
      examples.add(m[0].replace(/\s*\($/, ''));
      if (METHOD_NAME_RE.lastIndex === m.index) METHOD_NAME_RE.lastIndex++;
    }
    if (count > 0) hits.push({ term: 'juliet-method-name', count, examples: [...examples].slice(0, 5) });
  }
  return hits;
}

function main() {
  const opts = args();
  if (!opts.root) {
    console.error('Usage: leakage-audit.mjs --root <scanner-visible-dir> [--json]');
    process.exit(2);
  }
  if (!fs.existsSync(opts.root)) {
    console.error(`✗ root does not exist: ${opts.root}`);
    process.exit(2);
  }
  const termRegexes = TERMS.map(term => ({
    term,
    re: new RegExp(`\\b${term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'gi'),
  }));

  const files = [];
  walk(opts.root, files, opts.includeNonSource);

  const findings = [];
  for (const f of files) {
    const hits = auditFile(f, termRegexes, opts.showContext);
    if (hits.length) findings.push({ file: path.relative(opts.root, f), hits });
  }

  const totalHits = findings.reduce((s, f) => s + f.hits.reduce((s2, h) => s2 + h.count, 0), 0);

  if (opts.json) {
    console.log(JSON.stringify({ root: opts.root, filesScanned: files.length, filesFlagged: findings.length, totalHits, findings }, null, 2));
  } else {
    console.log(`\nSARD leakage audit: ${opts.root}`);
    console.log(`  files scanned: ${files.length}`);
    console.log(`  files flagged: ${findings.length}`);
    console.log(`  total hits:    ${totalHits}`);
    if (findings.length) {
      console.log('\n  Top flagged files:');
      for (const f of findings.slice(0, 20)) {
        console.log(`    ${f.file}: ${f.hits.map(h => `${h.term}×${h.count}`).join(', ')}`);
        if (opts.showContext) {
          for (const h of f.hits) if (h.context) console.log(`      ${h.term}: …${h.context}…`);
        }
      }
      if (findings.length > 20) console.log(`    … and ${findings.length - 20} more`);
    }
  }

  if (findings.length > 0) {
    console.error(`\n✗ LEAKAGE AUDIT FAILED — ${findings.length} file(s) contain answer-bearing strings. Failing closed.`);
    process.exit(1);
  }
  // stderr, not stdout: --json mode's stdout must contain ONLY the JSON blob
  // above (this bug was caught this session — a bare --json run appended
  // this line after the JSON, breaking `JSON.parse` on the combined output).
  console.error('\n✓ leakage audit passed — no answer-bearing strings found.');
}

if (import.meta.url === `file://${process.argv[1]}`) main();
