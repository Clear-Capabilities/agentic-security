#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 5 (§21-22) — error clustering + prioritization.
//
// SCOPE NOTE, stated up front rather than implied: PRD §21 wants FNs/FPs
// classified into a 23-category structural taxonomy (INTERPROCEDURAL_FLOW,
// FIELD_FLOW, ALIAS_TRACKING, ...). Doing that with real confidence requires
// reading the actual vulnerable source to see WHY the engine missed it —
// which this agent cannot do (bench/sard-juliet-java/** and
// scanner/test/benchmark/realworld/.bench-cache/** are both on the
// coding-agent deny-list; see bench/sard/IMPLEMENTATION_STATUS.md §0). What
// this script CAN do without violating that boundary: every fn/fp entry's
// `file` field is a plain path STRING already present in bench-realworld.js's
// own JSON output (not raw source content), and Juliet's own file-naming
// convention encodes real structural information in that string — the same
// convention `split.mjs`'s `familyKeyFor` already uses for template-family
// grouping. Clustering by that string is a genuine, evidence-based signal;
// forcing it into the PRD's exact 23-label vocabulary without being able to
// verify the underlying mechanism would be presenting a guess as a
// diagnosis. So this script reports real clusters ranked by FN/FP volume
// (satisfying §22's actual deliverable — "rank causes by potential F1
// improvement" — using real counts) and separately applies ONLY the small
// number of naming-convention mappings this session has direct, verified
// evidence for (documented per-mapping below), rather than guessing at all 23.
//
// Usage:
//   node bench/sard/scripts/analyze-errors.mjs --input <bench-realworld.js --json output>
//
// Writes bench/sard/reports/error-clusters.{json,md} (gitignored, local-only
// per bench/README.md's policy, same as every other report this subsystem
// produces).

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPORTS_DIR = path.join(HERE, '..', 'reports');

function readInput() {
  const idx = process.argv.indexOf('--input');
  if (idx !== -1 && process.argv[idx + 1]) return fs.readFileSync(process.argv[idx + 1], 'utf8');
  try { return fs.readFileSync(0, 'utf8'); } catch (e) { throw new Error(`no --input file and stdin unreadable: ${e.message}`); }
}

// Mirrors split.mjs's familyKeyFor: strip the trailing Juliet flow-variant
// suffix. What's left is the descriptor Juliet's OWN generator assigned to
// this specific source/sink/propagation combination.
function familyKeyFor(basename) {
  return basename.replace(/\.(java|cs)$/i, '').replace(/_\d{2}[ab]?$/i, '');
}

// The CWE<N>_<Description>__ prefix names the vulnerability category itself
// (already captured by `cwe`/`family` elsewhere) — strip it so the cluster
// key reflects the SOURCE/PROPAGATION/SINK descriptor specifically, which is
// the part that varies within one CWE and is what actually explains why one
// flow variant is caught and a structurally-different one isn't.
function descriptorFor(basename) {
  const key = familyKeyFor(basename);
  const m = key.match(/^CWE\d+_[^_]*(?:_[^_]*)*?__(.+)$/);
  return m ? m[1] : key;
}

// Naming-convention mappings this session has DIRECT VERIFIED EVIDENCE for
// (not guessed): the multi-file paired-variant suffix (_NNa/_NNb) is
// mechanically confirmed by split.mjs's own regex and Juliet's documented
// generation methodology to mean "the tainted value crosses a file/class
// boundary between the two halves" — that's INTERPROCEDURAL_FLOW /
// MULTI_FILE_FLOW by definition of what the suffix means, not a guess about
// unseen source content. Everything else stays as an unlabeled descriptor
// cluster rather than a forced categorization.
function taxonomyHintFor(relPath) {
  if (/_\d{2}[ab]\.(java|cs)$/i.test(relPath)) return 'MULTI_FILE_FLOW / INTERPROCEDURAL_FLOW (paired _NNa/_NNb variant — confirmed by suffix convention, not inferred from content)';
  return null;
}

function clusterBy(entries, keyFn) {
  const clusters = new Map();
  for (const e of entries) {
    const base = path.basename(e.file || '');
    if (!base) continue;
    const key = keyFn(base);
    if (!clusters.has(key)) clusters.set(key, []);
    clusters.get(key).push(e);
  }
  return clusters;
}

function main() {
  const raw = readInput();
  const parsed = JSON.parse(raw);
  const results = parsed.results || (Array.isArray(parsed) ? parsed : [parsed]);

  const report = { generatedAt: new Date().toISOString(), apps: [] };
  const mdLines = ['# SARD error clusters (Phase 5)', '', 'See this script\'s header for scope — descriptor clusters are evidence-based (filename strings already present in scan output); the PRD\'s full 23-category taxonomy needs source-content access this agent does not have.', ''];

  for (const r of results) {
    const fnClusters = clusterBy(r.fns || [], descriptorFor);
    const fpClusters = clusterBy(r.fps || [], descriptorFor);

    const fnRanked = [...fnClusters.entries()].map(([key, entries]) => ({
      descriptor: key,
      count: entries.length,
      cwes: [...new Set(entries.map(e => e.cwe).filter(Boolean))],
      taxonomyHint: taxonomyHintFor(entries[0]?.file || ''),
      sampleFiles: entries.slice(0, 2).map(e => e.file),
    })).sort((a, b) => b.count - a.count);

    const fpRanked = [...fpClusters.entries()].map(([key, entries]) => ({
      descriptor: key,
      count: entries.length,
      families: [...new Set(entries.map(e => e.family).filter(Boolean))],
      sampleFiles: entries.slice(0, 2).map(e => e.file),
    })).sort((a, b) => b.count - a.count);

    const multiFileFnCount = (r.fns || []).filter(e => /_\d{2}[ab]\.(java|cs)$/i.test(e.file || '')).length;

    report.apps.push({ name: r.name, fnClusterCount: fnRanked.length, fpClusterCount: fpRanked.length, topFn: fnRanked.slice(0, 25), topFp: fpRanked.slice(0, 25), multiFileFnCount });

    mdLines.push(`## ${r.name}`, '');
    mdLines.push(`${(r.fns || []).length} FNs across ${fnRanked.length} descriptor clusters. ${(r.fps || []).length} FPs across ${fpRanked.length} descriptor clusters.`);
    mdLines.push(`${multiFileFnCount} FNs (${((multiFileFnCount / Math.max((r.fns||[]).length,1)) * 100).toFixed(1)}%) are paired multi-file variants — confirmed MULTI_FILE_FLOW/INTERPROCEDURAL_FLOW by suffix convention.`, '');
    mdLines.push('### Top false-negative clusters (ranked by potential recall gain)', '');
    mdLines.push('| Descriptor | FN count | CWE(s) | Taxonomy hint |', '|---|---|---|---|');
    for (const c of fnRanked.slice(0, 20)) mdLines.push(`| ${c.descriptor} | ${c.count} | ${c.cwes.join(', ')} | ${c.taxonomyHint || '—'} |`);
    mdLines.push('');
    mdLines.push('### Top false-positive clusters (ranked by potential precision gain)', '');
    mdLines.push('| Descriptor | FP count | Family(ies) |', '|---|---|---|');
    for (const c of fpRanked.slice(0, 20)) mdLines.push(`| ${c.descriptor} | ${c.count} | ${c.families.join(', ')} |`);
    mdLines.push('');
  }

  fs.mkdirSync(REPORTS_DIR, { recursive: true });
  fs.writeFileSync(path.join(REPORTS_DIR, 'error-clusters.json'), JSON.stringify(report, null, 2) + '\n');
  fs.writeFileSync(path.join(REPORTS_DIR, 'error-clusters.md'), mdLines.join('\n') + '\n');
  for (const app of report.apps) {
    console.log(`${app.name}: ${app.fnClusterCount} FN clusters, ${app.fpClusterCount} FP clusters, ${app.multiFileFnCount} multi-file-variant FNs`);
    console.log(`  top FN: ${app.topFn[0]?.descriptor} (${app.topFn[0]?.count})`);
    console.log(`  top FP: ${app.topFp[0]?.descriptor} (${app.topFp[0]?.count})`);
  }
  console.log(`\nWritten: ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'error-clusters.json'))}, ${path.relative(process.cwd(), path.join(REPORTS_DIR, 'error-clusters.md'))}`);
}

main();
