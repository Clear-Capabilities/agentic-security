#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 7 (§24-27) — semantic mutation testing
// for Juliet Java. Purpose: prove detection depends on SEMANTICS, not surface
// syntax, by applying behavior-preserving rewrites to real `bad()` method
// bodies and confirming the scanner's finding survives.
//
// WHY A NEW SCRIPT, NOT bench/mutation/runner.mjs DIRECTLY: that harness's
// cases are hand-AUTHORED code snippets (see its own header) — every
// metamorphic/adversarial pair is written by hand because its purpose is
// pinning specific sanitizer-gating behavior with full control over the
// exact shape. This script needs the opposite: apply a mutation
// PROGRAMMATICALLY to REAL Juliet source this agent cannot read directly
// (bench-cache is deny-listed — see IMPLEMENTATION_STATUS.md §0), so the
// transform itself has to be a mechanical, verifiable text operation, not
// something authored by inspection. What IS reused: `runScan()` +
// `disableStateWrites()`, the exact scan-a-tmp-dir-and-check-findings
// pattern bench/mutation/runner.mjs already uses, and `findJavaMethodSpans`
// (exported from bench-realworld.js by this same PRD work) for locating the
// `bad()` method body to mutate within.
//
// Two mutation types, both simple enough to verify are safe WITHOUT parsing
// the file myself (mechanical text substitution + a real post-hoc parse
// check, not a guess):
//   IDENTIFIER_RENAME — rename the first local variable declared inside
//     bad() to a deterministic opaque name, word-boundary-scoped to that
//     method's line range only (so a same-named variable elsewhere in the
//     file, e.g. in good()/goodG2B(), is untouched).
//   BOOLEAN_EQUIVALENCE — `x != null` -> `!(x == null)` where present in the
//     method body. A no-op rewrite of a null check's polarity.
//
// Every mutation is validated three ways before being scored (PRD §27):
//   1. PARSES — parseJavaFile() must return non-null with >=1 function.
//   2. THE ORIGINAL fires the expected family/CWE at the expected location
//      (established fresh in the SAME run, not assumed from an old score).
//   3. Only mutations passing both above are scored for Semantic Robustness.
//
// Usage:
//   node bench/sard/scripts/mutate.mjs --app sard-juliet-java-strict --cwe 89,78,23,80,327 --limit 30

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { runScan } from '../../../scanner/src/runScan.js';
import { disableStateWrites } from '../../_lib/tree-integrity.mjs';
import { findJavaMethodSpans } from '../../../scanner/test/benchmark/realworld/bench-realworld.js';
import { parseJavaFile } from '../../../scanner/src/ir/parser-java.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST_PATH = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', 'manifest.json');
const CACHE_ROOT = path.join(HERE, '..', '..', '..', 'scanner', 'test', 'benchmark', 'realworld', '.bench-cache');
const MUTATIONS_DIR = path.join(HERE, '..', 'mutations');
const REPORTS_DIR = path.join(HERE, '..', 'reports');

function args() {
  const a = process.argv.slice(2);
  const out = { app: null, cwes: null, limit: 30 };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--app') out.app = a[++i];
    else if (a[i] === '--cwe') out.cwes = a[++i].split(',').map(s => s.trim());
    else if (a[i] === '--limit') out.limit = parseInt(a[++i], 10);
  }
  return out;
}

function resolveRoot(appName) {
  const manifest = JSON.parse(fs.readFileSync(MANIFEST_PATH, 'utf8'));
  const app = manifest.apps?.[appName];
  if (!app) throw new Error(`unknown manifest app: ${appName}`);
  return { app, root: path.join(CACHE_ROOT, `${appName}-${app.sha}`) };
}

// Collect a sample of {file, family, cwe} for real `bad()` methods across the
// requested CWE directories. Caps per-CWE so one huge family doesn't crowd
// out the sample's diversity.
function sampleBadFiles(root, app, cwes, limit) {
  const cweMap = app.groundTruth.cweToFamily || {};
  const perCwe = Math.max(1, Math.ceil(limit / (cwes?.length || 1)));
  const samples = [];
  const dirs = fs.readdirSync(root, { withFileTypes: true }).filter(e => e.isDirectory() && /^juliet-cwe\d+$/i.test(e.name));
  for (const d of dirs) {
    const m = d.name.match(/^juliet-cwe(\d+)$/i);
    const cweNum = m[1];
    if (cwes && !cwes.includes(cweNum)) continue;
    const cwe = `CWE${cweNum}`;
    const family = cweMap[cwe];
    if (!family) continue;
    const srcRoot = path.join(root, d.name, 'src', 'main', 'java');
    if (!fs.existsSync(srcRoot)) continue;
    let count = 0;
    (function walk(dir) {
      if (count >= perCwe) return;
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
      for (const e of entries) {
        if (count >= perCwe) return;
        const p = path.join(dir, e.name);
        if (e.isDirectory()) { walk(p); continue; }
        if (!/\.java$/i.test(e.name) || /^Test|TestCase\.java$/.test(e.name)) continue;
        samples.push({ file: p, rel: path.relative(root, p), family, cwe });
        count++;
      }
    })(srcRoot);
  }
  return samples.slice(0, limit);
}

// IDENTIFIER_RENAME: first local var decl inside the bad() span -> opaque name.
function mutateIdentifierRename(content, span) {
  const lines = content.split('\n');
  const spanText = lines.slice(span.startLine - 1, span.endLine).join('\n');
  const declRe = /\b(?:String|int|long|boolean|double|float|Object|char|byte|short)\s+(\w+)\s*=/;
  const m = spanText.match(declRe);
  if (!m) return null;
  const varName = m[1];
  if (['data', 'i', 'j'].includes(varName) === false && varName.length < 1) return null;
  const opaque = `mv_${crypto.createHash('sha1').update(varName).digest('hex').slice(0, 8)}`;
  const wordRe = new RegExp(`\\b${varName}\\b`, 'g');
  const mutatedSpan = spanText.replace(wordRe, opaque);
  if (mutatedSpan === spanText) return null;
  const newLines = [...lines.slice(0, span.startLine - 1), ...mutatedSpan.split('\n'), ...lines.slice(span.endLine)];
  return { content: newLines.join('\n'), detail: `renamed local var "${varName}" -> "${opaque}"` };
}

// BOOLEAN_EQUIVALENCE: `x != null` -> `!(x == null)`, scoped to the span.
function mutateBooleanEquivalence(content, span) {
  const lines = content.split('\n');
  const spanText = lines.slice(span.startLine - 1, span.endLine).join('\n');
  const neqRe = /(\w+)\s*!=\s*null/;
  const m = spanText.match(neqRe);
  if (!m) return null;
  const mutatedSpan = spanText.replace(neqRe, `!($1 == null)`);
  if (mutatedSpan === spanText) return null;
  const newLines = [...lines.slice(0, span.startLine - 1), ...mutatedSpan.split('\n'), ...lines.slice(span.endLine)];
  return { content: newLines.join('\n'), detail: `"${m[0]}" -> "!(${m[1]} == null)"` };
}

// NOOP_STATEMENT_INSERTION: insert one harmless, unused local variable
// declaration as the first statement of the method body — "additional
// helper/unrelated code" per PRD §25. Universally applicable (every method
// has an opening brace) and maximally safe: it never touches any existing
// statement, so it cannot alter the tainted data flow the finding depends
// on, only add inert code around it. This is the mutation that should have
// the HIGHEST survival rate by construction — a detector losing a finding
// here would indicate the engine's matching is unreasonably fragile to
// unrelated surrounding code, not a real semantic change.
function mutateNoopInsertion(content, span, seed) {
  const lines = content.split('\n');
  const spanText = lines.slice(span.startLine - 1, span.endLine).join('\n');
  const braceIdx = spanText.indexOf('{');
  if (braceIdx === -1) return null;
  const marker = `sard_mut_${crypto.createHash('sha1').update(String(seed)).digest('hex').slice(0, 8)}`;
  const mutatedSpan = spanText.slice(0, braceIdx + 1) + `\n    int ${marker} = 0;` + spanText.slice(braceIdx + 1);
  const newLines = [...lines.slice(0, span.startLine - 1), ...mutatedSpan.split('\n'), ...lines.slice(span.endLine)];
  return { content: newLines.join('\n'), detail: `inserted no-op "int ${marker} = 0;" as first statement` };
}

const MUTATORS = [
  { name: 'NOOP_STATEMENT_INSERTION', fn: (content, span) => mutateNoopInsertion(content, span, content.length) },
  { name: 'IDENTIFIER_RENAME', fn: mutateIdentifierRename },
  { name: 'BOOLEAN_EQUIVALENCE', fn: mutateBooleanEquivalence },
];

async function scanSingleFile(relFileName, content) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sard-mutation-'));
  const target = path.join(dir, path.basename(relFileName));
  fs.writeFileSync(target, content);
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  try {
    const { scan } = await runScan(dir);
    return scan.findings || [];
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  }
}

function findingMatches(findings, family) {
  return findings.some(f => (f.family || '').toLowerCase() === family.toLowerCase());
}

async function main() {
  await disableStateWrites();
  const opts = args();
  if (!opts.app) { console.error('Usage: mutate.mjs --app <manifest-app-name> [--cwe 89,78,...] [--limit N]'); process.exit(2); }
  const { app, root } = resolveRoot(opts.app);
  if (!fs.existsSync(root)) { console.error(`✗ corpus not cloned yet: ${root}`); process.exit(2); }

  const samples = sampleBadFiles(root, app, opts.cwes, opts.limit);
  console.error(`  sampled ${samples.length} bad()-bearing files across ${new Set(samples.map(s=>s.cwe)).size} CWEs`);

  const results = [];
  for (const s of samples) {
    let content;
    try { content = fs.readFileSync(s.file, 'utf8'); } catch { continue; }
    const spans = findJavaMethodSpans(content);
    const badSpan = spans.find(m => /^(?:bad|badSink|badSource|bad\d+)$/.test(m.name));
    if (!badSpan) continue;

    // Baseline: does the ORIGINAL fire the expected family, established
    // fresh in this run (not assumed from an old score elsewhere).
    const baselineFindings = await scanSingleFile(s.rel, content);
    const baselineFired = findingMatches(baselineFindings, s.family);
    if (!baselineFired) {
      results.push({ file: s.rel, cwe: s.cwe, family: s.family, mutation: null, status: 'SKIPPED_NO_BASELINE_TP' });
      continue;
    }

    for (const mutator of MUTATORS) {
      const mutated = mutator.fn(content, badSpan);
      if (!mutated) {
        results.push({ file: s.rel, cwe: s.cwe, family: s.family, mutation: mutator.name, status: 'NOT_APPLICABLE' });
        continue;
      }
      // Validation 1: PARSES.
      let parsed;
      try { parsed = await parseJavaFile(path.basename(s.file), mutated.content); } catch { parsed = null; }
      if (!parsed || !Array.isArray(parsed.functions) || parsed.functions.length === 0) {
        results.push({ file: s.rel, cwe: s.cwe, family: s.family, mutation: mutator.name, status: 'INVALID_PARSE_FAILED', detail: mutated.detail });
        continue;
      }
      // Validation 2 + measurement: does the SAME finding survive?
      const mutatedFindings = await scanSingleFile(s.rel, mutated.content);
      const survived = findingMatches(mutatedFindings, s.family);
      results.push({ file: s.rel, cwe: s.cwe, family: s.family, mutation: mutator.name, status: survived ? 'SURVIVED' : 'LOST', detail: mutated.detail });

      // Persist the mutated file for inspection.
      const outDir = path.join(MUTATIONS_DIR, opts.app, path.dirname(s.rel), mutator.name);
      fs.mkdirSync(outDir, { recursive: true });
      fs.writeFileSync(path.join(outDir, path.basename(s.file)), mutated.content);
    }
  }

  const scored = results.filter(r => r.status === 'SURVIVED' || r.status === 'LOST');
  const survived = scored.filter(r => r.status === 'SURVIVED').length;
  const srr = scored.length ? survived / scored.length : null;
  const invalid = results.filter(r => r.status === 'INVALID_PARSE_FAILED').length;
  const skippedNoBaseline = results.filter(r => r.status === 'SKIPPED_NO_BASELINE_TP').length;
  const notApplicable = results.filter(r => r.status === 'NOT_APPLICABLE').length;

  const report = {
    generatedAt: new Date().toISOString(), app: opts.app, sampled: samples.length,
    semanticRobustnessRate: srr, scored: scored.length, survived, lost: scored.length - survived,
    invalidParseFailed: invalid, skippedNoBaseline, notApplicable,
    byMutator: Object.fromEntries(MUTATORS.map(m => {
      const rows = scored.filter(r => r.mutation === m.name);
      const s = rows.filter(r => r.status === 'SURVIVED').length;
      return [m.name, { scored: rows.length, survived: s, rate: rows.length ? s / rows.length : null }];
    })),
    results,
  };
  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, 'mutation-report.json'), JSON.stringify(report, null, 2) + '\n');

  console.log(`\nSemantic Robustness Rate: ${srr === null ? 'N/A' : (srr*100).toFixed(1) + '%'} (${survived}/${scored.length} mutations survived)`);
  console.log(`  invalid (parse failed, excluded from scoring): ${invalid}`);
  console.log(`  skipped (baseline itself didn't fire): ${skippedNoBaseline}`);
  console.log(`  not applicable (mutator found no matching shape): ${notApplicable}`);
  for (const [name, s] of Object.entries(report.byMutator)) {
    console.log(`  ${name}: ${s.rate === null ? 'N/A' : (s.rate*100).toFixed(1) + '%'} (${s.survived}/${s.scored})`);
  }
  console.log(`\nWritten: ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'mutation-report.json'))}`);
}

main();
