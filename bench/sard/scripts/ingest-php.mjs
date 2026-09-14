#!/usr/bin/env node
// SARD_AGENTIC_SECURITY_PRD.md Phase 1/2 — PHP SARD ingestion (genuinely new;
// no existing PHP Juliet/SARD harness exists in this repo — see
// bench/sard/IMPLEMENTATION_STATUS.md §0). Source: the SARD PHP Vulnerability
// Test Suite (Stivalet & Delaitre, NIST SARD test-suite #103), pinned in
// bench/sard/dataset-lock.json.
//
// Archive layout (verified this session by direct inspection — this script
// IS the trusted controller, PRD §8.1, so reading the raw corpus to build
// ground truth is its job, same as bench-realworld.js's buildJulietExpected
// already does for Java/C#):
//   <numericId>-v1.0.0/manifest.sarif   — SARIF 2.1.0 ground truth:
//       properties.state: "good" | "bad"
//       results[].ruleId: "CWE-<N>"        (only present when state=bad)
//       results[].locations[].physicalLocation.region.startLine
//   <numericId>-v1.0.0/src/<CWE-and-descriptor-bearing-filename>.php
//
// This script:
//   1. Parses manifest.sarif per case (trusted read).
//   2. Assigns an OPAQUE case id (sha256 of the numeric id, truncated) so the
//      original SARD id — which anyone can look up at samate.nist.gov/SARD to
//      see the raw answer — never reaches the scanner-visible workspace.
//   3. Neutralizes the PHP source (strips all comments, preserving line
//      count so SARIF line numbers still line up; renames the generator
//      template's literal `$tainted` variable — a real, confirmed leak, see
//      IMPLEMENTATION_STATUS.md — to a neutral name) into
//      bench/sard/workspace/php/<caseId>/src.php.
//   4. Writes gold labels to bench/sard/gold/php.json — NEVER copied into
//      workspace/. Gold entries carry the opaque caseId, not the original
//      numeric id, in the field a downstream scorer would join on, but DO
//      retain originalId themselves (gold/ is the trusted-only store).
//
// Bounded by --limit for this session's actual run (the full corpus is
// 42,212 cases; each requires 2 subprocess extractions, so an unbounded run
// is a multi-minute-plus operation — run without --limit for a real full
// ingestion later). Idempotent: skips a case whose workspace dir already
// exists, so a bounded run can be extended incrementally without redoing
// earlier work (PRD's "resumable" requirement, applied at the granularity
// this script actually needs).
//
// Usage:
//   node bench/sard/scripts/ingest-php.mjs --limit 200
//   node bench/sard/scripts/ingest-php.mjs            # full corpus (slow)

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { bucketFor } from './split.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SARD_ROOT = path.resolve(HERE, '..');
const ZIP_PATH = path.join(SARD_ROOT, 'raw', 'php-vulnerability-test-suite.zip');
const WORKSPACE_ROOT = path.join(SARD_ROOT, 'workspace', 'php');
const GOLD_PATH = path.join(SARD_ROOT, 'gold', 'php.json');

// CWE -> family. Reuses the same family taxonomy strings as
// scanner/test/benchmark/realworld/manifest.json's Juliet cweToFamily maps
// (cross-corpus comparability) rather than inventing a parallel one, per
// this repo's reuse-over-duplication convention. Only CWEs this corpus's own
// SARIF `results[].ruleId` actually names need an entry (unmapped CWEs are
// still ingested with family=null — never silently dropped).
const CWE_TO_FAMILY = {
  'CWE-22': 'path-traversal', 'CWE-23': 'path-traversal', 'CWE-36': 'path-traversal',
  'CWE-78': 'command-injection',
  'CWE-79': 'xss', 'CWE-80': 'xss', 'CWE-81': 'xss', 'CWE-83': 'xss',
  'CWE-89': 'sql-injection',
  'CWE-90': 'ldap-injection',
  // CWE-91: this corpus's own taxonomy calls it "XML/XPath injection", and
  // the scanner's real family for CWE-91 (posture/finding-defaults.js
  // _CWE_FAMILY, and the php-domxpath-query catalog sink) is
  // 'xpath-injection', not 'code-injection' — a real family-name mismatch
  // fixed here (adversarial-premortem-style bug: a good-looking mapping that
  // silently made this whole CWE unscoreable by family comparison).
  'CWE-91': 'xpath-injection',
  'CWE-94': 'code-injection',
  'CWE-95': 'code-injection', // eval injection
  'CWE-98': 'code-injection', // PHP remote file inclusion — matches finding-defaults.js's CWE-98 entry
  'CWE-601': 'open-redirect',
  'CWE-643': 'xpath-injection',
  'CWE-862': 'missing-authz',
};

function args() {
  const a = process.argv.slice(2);
  const out = { limit: null };
  for (let i = 0; i < a.length; i++) {
    if (a[i] === '--limit') out.limit = parseInt(a[++i], 10);
  }
  return out;
}

function listCaseIds() {
  const names = execFileSync('unzip', ['-Z1', ZIP_PATH], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }).split('\n');
  const ids = new Set();
  for (const n of names) {
    const m = n.match(/^(\d+)-v1\.0\.0\/manifest\.sarif$/);
    if (m) ids.add(m[1]);
  }
  return [...ids].sort();
}

function extractText(entryPath) {
  return execFileSync('unzip', ['-p', ZIP_PATH, entryPath], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
}

function opaqueCaseId(numericId) {
  return 'case_' + crypto.createHash('sha256').update(String(numericId)).digest('hex').slice(0, 10);
}

// Adversarial-premortem remediation (SARD_80_F1_SCANNER_PRD.md review, Round 1
// finding F1.2): PHP had no train/dev/test split at all — split.mjs's
// familyKeyFor only strips Juliet's `.java`/`.cs` extension + `_NN[ab]` flow-
// variant suffix, and score-php.mjs never consumed a split even if one
// existed. Every PHP number reported anywhere in this ledger to date was
// fit-and-report on the same undivided sample.
//
// This corpus (Stivalet & Delaitre, SARD PHP Vulnerability Test Suite) does
// NOT use Juliet's `_NN[ab]` numbered-variant convention — confirmed by
// direct inspection of all 42,212 case filenames (`unzip -l`, this session):
// every descriptor filename is unique, and the numeric directory ID carries
// no structural meaning of its own. Its actual near-duplicate axis is
// different: the filename is
// `CWE_<N>__<source>__<sanitizer>__<sink-descriptor>[-<encoding>][_<quote-style>].php`,
// and the SAME (CWE, source, sanitizer, sink) combination recurs across
// several cases differing ONLY in cosmetic surface syntax — a trailing
// `_simple_quote`/`_double_quote` suffix, or which literal printf format
// specifier (`%s`/`%d`/`%u`/...) the sink descriptor names. Verified
// empirically (not guessed): stripping exactly those two cosmetic axes
// collapses the corpus's 42,212 unique filenames into 35,588 family keys,
// with real multi-member families (e.g. 5 members per {CWE, source,
// sanitizer, sink} combination — one per format-specifier/quote-style
// permutation actually generated). Leaving either axis unstripped would
// split near-identical surface variants of the same underlying vulnerability
// across train/dev/test, exactly the leakage this exists to prevent.
export function phpFamilyKeyFor(descriptorFilename) {
  return String(descriptorFilename)
    .replace(/\.php$/i, '')
    .replace(/_simple_quote$/i, '')
    .replace(/_double_quote$/i, '')
    .replace(/-sprintf_%[a-zA-Z]$/i, '-sprintf');
}

// Same seed/algorithm split.mjs uses for Java/C# (imported bucketFor, not
// reimplemented) — one shared split concept across all three languages
// rather than a parallel, potentially-inconsistent PHP-only notion of it.
export const PHP_SPLIT_SEED = 'sard-split-v1';

// Strip PHP comments (// # and /* */), preserving newline count so SARIF
// line numbers still index correctly into the neutralized file — the same
// "preserve line mapping where practical" requirement bench-realworld.js's
// _materializeBlinded already honors for Java/C#. String-literal-aware so a
// `//` or `#` inside a quoted string isn't mistaken for a comment start.
function stripPhpComments(src) {
  let out = '';
  let i = 0;
  const n = src.length;
  let inSingle = false, inDouble = false;
  while (i < n) {
    const ch = src[i], next = src[i + 1];
    if (inSingle) {
      out += ch;
      if (ch === '\\') { out += src[i + 1] || ''; i += 2; continue; }
      if (ch === "'") inSingle = false;
      i++; continue;
    }
    if (inDouble) {
      out += ch;
      if (ch === '\\') { out += src[i + 1] || ''; i += 2; continue; }
      if (ch === '"') inDouble = false;
      i++; continue;
    }
    if (ch === "'") { inSingle = true; out += ch; i++; continue; }
    if (ch === '"') { inDouble = true; out += ch; i++; continue; }
    if (ch === '/' && next === '*') {
      const end = src.indexOf('*/', i + 2);
      const block = end === -1 ? src.slice(i) : src.slice(i, end + 2);
      out += block.replace(/[^\n]/g, ' ');
      i += block.length;
      continue;
    }
    if ((ch === '/' && next === '/') || ch === '#') {
      let end = src.indexOf('\n', i);
      if (end === -1) end = n;
      out += ' '.repeat(end - i);
      i = end;
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

// Adversarial-review finding (SARD_AGENTIC_SECURITY_PRD.md premortem, Round
// 1, F3): the original version of this function renamed exactly one
// hardcoded variable name (`$tainted`, confirmed leaking this session — see
// IMPLEMENTATION_STATUS.md) and nothing else — a single ad hoc point-fix
// discovered by iterating against the audit, not a designed protection, and
// structurally far weaker than bench-realworld.js's `_blindTransform`
// (general, hash-based, case-insensitive rules covering numbered flow
// variants and PascalCase forms for Java/C#). Generalized to the same
// DESIGN PATTERN here — general, hash-based, defense-in-depth rules rather
// than one hardcoded name — even though a real run of the (now-strengthened,
// see leakage-audit.mjs's `cwe-number` check) leakage audit against the
// materialized workspace found ZERO hits across all 5000 already-ingested
// cases either way (this corpus's own generator, Stivalet & Delaitre's SARD
// PHP Vulnerability Test Suite, does not appear to use Juliet's bad()/good()
// naming convention at all). This closes the STRUCTURAL gap (no general
// mechanism existed) rather than a currently-observed leak.
//
// Word-boundary-anchored throughout so a legitimate identifier that merely
// CONTAINS one of these substrings (`$taintedFoo`, `badge`, `goodwill`) is
// left alone — better to under-rename and let leakage-audit.mjs catch a
// residual than to risk a broken rename corrupting valid PHP.
function neutralizeIdentifiers(src) {
  return src
    // The one confirmed leak this session found, kept for backward
    // compatibility with already-ingested cases (the hash-based rule below
    // would ALSO catch `$tainted`, but renaming it identically both ways
    // means re-ingesting doesn't change already-committed gold/workspace
    // content for cases that only ever had this one variable name).
    .replace(/\$tainted\b/g, '$value')
    // General Juliet-style bad/good identifiers, defense-in-depth for a
    // future generator variant or corpus update — mirrors
    // bench-realworld.js's `_blindTransform` hash-based rule shape (case-
    // insensitive, numbered-flow-variant-aware) so the two pipelines share
    // one protection design rather than PHP staying a special case.
    .replace(/\$?\bbad(?:sink|source)?\d*\b/gi, (m) => (m[0] === '$' ? '$' : '') + `op0_${crypto.createHash('sha1').update(m.replace(/^\$/, '').toLowerCase()).digest('hex').slice(0, 6)}`)
    .replace(/\$?\bgood(?:g2b|b2g)?(?:sink|source)?\d*\b/gi, (m) => (m[0] === '$' ? '$' : '') + `op1_${crypto.createHash('sha1').update(m.replace(/^\$/, '').toLowerCase()).digest('hex').slice(0, 6)}`)
    // A CWE-and-descriptor tail fused directly onto an identifier (the same
    // shape bench-realworld.js's own CWE-tag rule closes for Java/C#).
    .replace(/\bCWE\d+_[A-Za-z0-9_]+\b/g, (m) => `case_${crypto.createHash('sha1').update(m).digest('hex').slice(0, 8)}`)
    // A bare CWE+digits reference with no trailing descriptor (a string
    // literal or log message, say) — the exact shape leakage-audit.mjs's
    // new `cwe-number` check exists to catch independently if this rule
    // ever misses a variant.
    .replace(/\bCWE[\s_-]?\d+\b/gi, (m) => `ref_${crypto.createHash('sha1').update(m.toUpperCase()).digest('hex').slice(0, 6)}`)
    .replace(/\bjuliet\b/gi, 'app')
    .replace(/\btestcases?\b/gi, 'code');
}

function main() {
  const opts = args();
  if (!fs.existsSync(ZIP_PATH)) {
    console.error(`✗ ${path.relative(process.cwd(), ZIP_PATH)} not found — run the download step first (see dataset-lock.json for the source URL).`);
    process.exit(2);
  }
  fs.mkdirSync(WORKSPACE_ROOT, { recursive: true });
  fs.mkdirSync(path.dirname(GOLD_PATH), { recursive: true });

  let ids = listCaseIds();
  if (opts.limit) ids = ids.slice(0, opts.limit);

  const gold = fs.existsSync(GOLD_PATH) ? JSON.parse(fs.readFileSync(GOLD_PATH, 'utf8')) : [];
  const goldByCase = new Map(gold.map(g => [g.caseId, g]));

  let ingested = 0, skipped = 0, malformed = 0;
  for (const numericId of ids) {
    const caseId = opaqueCaseId(numericId);
    const caseDir = path.join(WORKSPACE_ROOT, caseId);
    if (fs.existsSync(caseDir) && goldByCase.has(caseId)) { skipped++; continue; }

    let manifest;
    try {
      manifest = JSON.parse(extractText(`${numericId}-v1.0.0/manifest.sarif`));
    } catch (e) { malformed++; console.error(`  ⚠ ${numericId}: manifest.sarif parse failed (${e.message})`); continue; }

    const run = manifest.runs?.[0];
    const state = run?.properties?.state;
    const artifactUri = run?.artifacts?.[0]?.location?.uri;
    if (!state || !artifactUri) { malformed++; console.error(`  ⚠ ${numericId}: missing state or artifact URI`); continue; }

    let srcText;
    try { srcText = extractText(`${numericId}-v1.0.0/${artifactUri}`); }
    catch (e) { malformed++; console.error(`  ⚠ ${numericId}: source extraction failed (${e.message})`); continue; }

    const result = run.results?.[0];
    const cwe = result?.ruleId || null; // e.g. "CWE-90"; null for a "good" case
    const line = result?.locations?.[0]?.physicalLocation?.region?.startLine ?? null;
    const family = cwe ? (CWE_TO_FAMILY[cwe] || null) : null;
    // Split assignment happens HERE, at ingest time, while the real
    // descriptor filename (artifactUri's basename) is still in hand — it is
    // never written to gold.json itself (only the opaque caseId is), so the
    // split key can't leak the original filename downstream. See
    // phpFamilyKeyFor's header comment for why this corpus needs a different
    // family-key shape than Java/C#'s Juliet-suffix stripping.
    const templateFamily = phpFamilyKeyFor(path.basename(artifactUri));
    const split = bucketFor(PHP_SPLIT_SEED, templateFamily);

    const neutralized = neutralizeIdentifiers(stripPhpComments(srcText));
    fs.mkdirSync(caseDir, { recursive: true });
    fs.writeFileSync(path.join(caseDir, 'src.php'), neutralized);

    const entry = { caseId, state, cwe, family, file: 'src.php', line, originalId: numericId, split };
    goldByCase.set(caseId, entry);
    ingested++;
  }

  const finalGold = [...goldByCase.values()].sort((a, b) => a.caseId.localeCompare(b.caseId));
  fs.writeFileSync(GOLD_PATH, JSON.stringify(finalGold, null, 2) + '\n');

  console.log(`\nPHP SARD ingestion: ${ingested} ingested, ${skipped} already present (skipped), ${malformed} malformed.`);
  console.log(`Gold store: ${finalGold.length} total entries → ${path.relative(process.cwd(), GOLD_PATH)}`);
  console.log(`Workspace:  ${path.relative(process.cwd(), WORKSPACE_ROOT)}`);
  const splitCounts = { train: 0, dev: 0, test: 0 };
  for (const g of finalGold) if (g.split) splitCounts[g.split]++;
  const noSplit = finalGold.length - (splitCounts.train + splitCounts.dev + splitCounts.test);
  console.log(`Split (family-keyed, seed=${PHP_SPLIT_SEED}): train=${splitCounts.train} dev=${splitCounts.dev} test=${splitCounts.test}` +
    (noSplit ? `  ⚠ ${noSplit} entries carry no split field (ingested by an older script version — re-ingest to backfill)` : ''));
  const badCount = finalGold.filter(g => g.state === 'bad').length;
  const unmappedCwe = finalGold.filter(g => g.state === 'bad' && g.cwe && !g.family);
  console.log(`  state=bad: ${badCount}, state=good: ${finalGold.length - badCount}`);
  if (unmappedCwe.length) {
    const cwes = [...new Set(unmappedCwe.map(g => g.cwe))].sort();
    console.log(`  ⚠ ${unmappedCwe.length} bad cases have a CWE not in CWE_TO_FAMILY: ${cwes.join(', ')} — extend the map above, not silently dropped.`);
  }
}

if (import.meta.url === `file://${process.argv[1]}`) main();
