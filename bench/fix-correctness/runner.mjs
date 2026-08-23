#!/usr/bin/env node
// PRD F6.3 — fix correctness, against the fix the maintainers actually shipped.
//
// ── The ground truth nobody was using ───────────────────────────────────────
//
// For every entry in `bench/independent` the upstream FIX COMMIT is known, and
// the corpus already materialises both sides of it: `pre/` is the vulnerable
// revision, `post/` is the maintainers' fix. That makes it a rare thing — a
// genuinely third-party ground truth for REMEDIATION, not just for detection —
// and until now nothing read it.
//
// ── What is compared ────────────────────────────────────────────────────────
//
// Semantic equivalence between two patches is undecidable in general and
// hand-waving about it would be worse than no bench, so this measures three
// specific, checkable things and reports them separately:
//
//   1. SYNTHESIS COVERAGE — of the real findings the engine gets right on real
//      code, for how many can it produce a fix at all? This is F6.5's honest
//      failure rate, measured on third-party code instead of fixtures.
//   2. LOCATION AGREEMENT — does our patch change the same lines the
//      maintainers changed? A fix in the right class at the wrong place is not
//      a fix.
//   3. APPROACH AGREEMENT — classify both diffs into a remediation category
//      (parameterize, encode, validate, replace-api, add-guard, remove-code)
//      and compare. Coarse on purpose: a category is checkable, and "is this
//      semantically the same fix" is not.
//
// A fix that DELETES the vulnerable code satisfies "the finding disappeared"
// and is almost never what upstream did. `remove-code` is therefore a category
// in its own right and is reported, never folded into agreement.

import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import { withEntryTimeout, EntryTimeout } from '../_lib/watchdog.mjs';
import { disableStateWrites } from '../_lib/tree-integrity.mjs';

// Everything that can touch the scanner is imported DYNAMICALLY, after
// disableStateWrites() has run.
//
// Static imports are hoisted and evaluated before any of this module's body,
// so a top-level `import` of the engine puts its module graph in place while
// state writing is still enabled — and the first scan then writes
// .agentic-security/ into the corpus, which the tree-integrity guard correctly
// refuses to score. Every entry came back UNSCORED and the bench reported a
// confident 0/0. The ordering is load-bearing, not stylistic.
let synthesizeDeterministicPatch, scanDirRaw, purgeScanState,
  findMatchingFindings, isLocalized, changedLineRanges, isHeldOut;

async function loadEngine() {
  await disableStateWrites();
  ({ synthesizeDeterministicPatch } = await import('../../scanner/src/posture/deterministic-fix.js'));
  ({ scanDirRaw, purgeScanState, findMatchingFindings, isLocalized, changedLineRanges, isHeldOut } =
    await import('../independent/runner.mjs'));
}

const HERE = path.dirname(fileURLToPath(import.meta.url));
const INDEPENDENT = path.join(HERE, '..', 'independent');
const CACHE = path.join(INDEPENDENT, 'cache');
const RESULT = path.join(HERE, 'RESULT.json');
const ENTRY_BUDGET_MS = Number(process.env.FIX_CORRECTNESS_TIMEOUT_MS || 600_000);

// Remediation categories, matched against the ADDED lines of a diff. Ordered:
// the first match wins, and the order runs from most specific to least, so a
// change that both parameterises a query and adds a guard is called what it
// primarily is.
const CATEGORIES = [
  ['parameterize', /\?\s*[,)]|\$\d|:\w+\s*[,)]|prepare\s*\(|bindParam|bind_param|placeholder|execute\s*\(\s*\w+\s*,/i],
  ['encode', /escape|htmlspecialchars|encodeURI|sanitiz|quote|htmlEncode|template\.HTML|CGI\.escape/i],
  ['validate', /\bvalid|\bcheck|allowlist|whitelist|\bin_array|\bincludes\(|\bhas\(|regexp?\.|match\(|instanceof|isinstance/i],
  ['replace-api', /\bexecFile|\bspawn\(|subprocess\.run|shlex|iofs\.ValidPath|filepath\.Clean|os\.path\.realpath|createHash\(['"`]sha256|rejectUnauthorized:\s*true|verify\s*=\s*True/i],
  ['add-guard', /\bassert\w*\s*\(|\bif\s*\(|\bunless\b|\braise\b|\bthrow\b|\breturn\s+(?:false|nil|error|res\.status)|abort\(|forbidden|unauthoriz/i],
  // ReDoS fixes almost never add a check — they rewrite the pattern so it stops
  // backtracking. Without its own category every one of them landed in `other`,
  // which made the taxonomy look useless when it was merely incomplete.
  ['rewrite-pattern', /\/\^?\[|RegExp\(|\bre\.compile|\bregexp?\b/i],
];

function categorise(addedLines) {
  const text = addedLines.join('\n');
  if (!text.trim()) return 'remove-code';
  for (const [name, re] of CATEGORIES) if (re.test(text)) return name;
  return 'other';
}

// The lines upstream ADDED, and the line ranges they touched.
//
// `changedLineRanges` takes PATHS, not contents — it shells out to `diff`. The
// first version of this passed the file bodies, `fs.existsSync` on a 40 KB
// string returned false, and every range came back null, so `isLocalized` was
// false for everything and the bench silently scored zero localized true
// positives. A helper that returns null on bad input rather than throwing is
// exactly the shape that produces a confident wrong answer.
function upstreamDiff(prePath, postPath) {
  const pre = fs.readFileSync(prePath, 'utf8'), post = fs.readFileSync(postPath, 'utf8');
  const preSet = new Set(pre.split('\n').map((l) => l.trim()).filter(Boolean));
  const added = post.split('\n').filter((l) => l.trim() && !preSet.has(l.trim()));
  const ranges = changedLineRanges(prePath, postPath);
  return { added, ranges: ranges || [], pre, post };
}

// The lines OUR patch adds, relative to the file it was synthesized from.
function ourDiff(before, after) {
  const beforeSet = new Set(before.split('\n').map((l) => l.trim()).filter(Boolean));
  const afterLines = after.split('\n');
  const added = afterLines.filter((l) => l.trim() && !beforeSet.has(l.trim()));
  const changed = [];
  const b = before.split('\n');
  for (let i = 0; i < Math.max(b.length, afterLines.length); i++) {
    if (b[i] !== afterLines[i]) changed.push(i + 1);
  }
  return { added, changedLines: changed };
}

function pct(n, d) { return d === 0 ? null : Number(((n / d) * 100).toFixed(2)); }

async function main() {
  await loadEngine();
  const manifest = JSON.parse(fs.readFileSync(path.join(INDEPENDENT, 'manifest.json'), 'utf8'));
  const limit = Number(process.env.FIX_CORRECTNESS_LIMIT || 0);
  const entries = limit ? manifest.entries.slice(0, limit) : manifest.entries;

  const rows = [];
  let scanned = 0, unscored = 0;

  for (const e of entries) {
    const dir = path.join(CACHE, e.id);
    const preDir = path.join(dir, 'pre'), postDir = path.join(dir, 'post');
    if (!fs.existsSync(preDir) || !fs.existsSync(postDir)) { unscored++; continue; }

    purgeScanState(preDir);
    let findings;
    try {
      // scanDirRaw returns { findings, suppressions } — a wrapper, not an
      // array. Unwrapped explicitly rather than destructured inline so the
      // shape is visible at the call site.
      ({ findings } = await withEntryTimeout(scanDirRaw(preDir), e.id, ENTRY_BUDGET_MS));
    } catch (err) {
      // Infrastructure failure is UNSCORED, never a miss — bench/independent's
      // doctrine, inherited.
      unscored++;
      process.stderr.write(`  – ${e.id}: UNSCORED (${err instanceof EntryTimeout ? 'timeout' : err.message})\n`);
      continue;
    }
    scanned++;

    // Only findings the engine got RIGHT count. Measuring fix synthesis on a
    // false positive would measure how well we remediate things that are not
    // there.
    const matching = findMatchingFindings(findings, e.cwe, e.files);
    if (!matching.length) continue;

    for (const f of matching) {
      const rel = String(f.file || '').replace(/\\/g, '/');
      const advisoryFile = e.files.find((x) => rel.endsWith(x));
      if (!advisoryFile) continue;

      const prePath = path.join(preDir, advisoryFile);
      const postPath = path.join(postDir, advisoryFile);
      if (!fs.existsSync(prePath) || !fs.existsSync(postPath)) continue;
      const up = upstreamDiff(prePath, postPath);
      const preBody = up.pre;
      if (!isLocalized(f.line, up.ranges)) continue;   // localized TPs only

      const row = {
        id: e.id, cwe: e.cwe, language: e.language, file: advisoryFile,
        heldOut: isHeldOut(e.id),
        upstreamCategory: categorise(up.added),
        upstreamHunks: up.ranges.length,
        synthesized: false, source: null,
        locationAgreement: null, categoryAgreement: null, ourCategory: null,
      };

      // Two synthesis paths, both shipped: the deterministic whole-file
      // rewriter, and the replacement the detector attached to the finding.
      let after = null;
      const det = synthesizeDeterministicPatch({ ...f, file: advisoryFile }, preBody);
      if (det && det.patch && det.patch[advisoryFile]) {
        after = det.patch[advisoryFile];
        row.source = `deterministic:${det.ruleId}`;
      } else if (f.fix && typeof f.fix.replacement === 'string' && f.fix.replacement) {
        const lines = preBody.split('\n');
        if (Number.isInteger(f.line) && f.line >= 1 && f.line <= lines.length) {
          lines[f.line - 1] = f.fix.replacement;
          after = lines.join('\n');
          row.source = 'finding-replacement';
        }
      }

      if (after && after !== preBody) {
        row.synthesized = true;
        const ours = ourDiff(preBody, after);
        row.ourCategory = categorise(ours.added);
        row.locationAgreement = ours.changedLines.some((ln) => isLocalized(ln, up.ranges));
        row.categoryAgreement = row.ourCategory === row.upstreamCategory;
      }
      rows.push(row);
      process.stderr.write(
        `  ${row.synthesized ? '✓' : '·'} ${e.id.padEnd(24)} ${String(e.cwe).padEnd(9)} ` +
        `${row.synthesized ? `${row.source} → ${row.ourCategory} (upstream ${row.upstreamCategory})` : `no fix synthesized (upstream ${row.upstreamCategory})`}\n`);
    }
  }

  const synth = rows.filter((r) => r.synthesized);
  const byUpstreamCategory = {};
  for (const r of rows) {
    const b = (byUpstreamCategory[r.upstreamCategory] ||= { d: 0, synthesized: 0 });
    b.d++;
    if (r.synthesized) b.synthesized++;
  }

  const result = {
    prd: 'F6.3',
    generatedAt: new Date().toISOString(),
    engineVersion: JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'scanner', 'package.json'), 'utf8')).version,
    groundTruth: 'the upstream fix commit for each bench/independent entry — third-party, not authored here',
    population: {
      entriesScanned: scanned, entriesUnscored: unscored,
      // Both counts, because one entry can carry several localized findings —
      // one advisory here contributes five, and a per-finding rate alone would
      // read as five independent data points when it is one codebase.
      localizedTruePositives: rows.length,
      entriesWithALocalizedTruePositive: new Set(rows.map((r) => r.id)).size,
    },
    synthesisCoverage: { n: synth.length, d: rows.length, pct: pct(synth.length, rows.length) },
    locationAgreement: {
      n: synth.filter((r) => r.locationAgreement).length, d: synth.length,
      pct: pct(synth.filter((r) => r.locationAgreement).length, synth.length),
    },
    approachAgreement: {
      n: synth.filter((r) => r.categoryAgreement).length, d: synth.length,
      pct: pct(synth.filter((r) => r.categoryAgreement).length, synth.length),
    },
    heldOut: {
      localizedTruePositives: rows.filter((r) => r.heldOut).length,
      synthesized: rows.filter((r) => r.heldOut && r.synthesized).length,
    },
    upstreamRemediationMix: byUpstreamCategory,
    rows,
  };
  fs.writeFileSync(RESULT, JSON.stringify(result, null, 2) + '\n');

  if (process.argv.includes('--json')) { process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return; }
  process.stdout.write(`\nbench/fix-correctness — engine ${result.engineVersion}\n\n`);
  process.stdout.write(`entries scanned            ${scanned} (${unscored} unscored)\n`);
  process.stdout.write(`localized true positives   ${rows.length}\n`);
  process.stdout.write(`fix synthesized            ${result.synthesisCoverage.n}/${result.synthesisCoverage.d} = ${result.synthesisCoverage.pct}%\n`);
  process.stdout.write(`  location agreement       ${result.locationAgreement.n}/${result.locationAgreement.d} = ${result.locationAgreement.pct}%\n`);
  process.stdout.write(`  approach agreement       ${result.approachAgreement.n}/${result.approachAgreement.d} = ${result.approachAgreement.pct}%\n`);
  process.stdout.write('\nwhat the maintainers actually did, across these findings:\n');
  for (const [cat, b] of Object.entries(byUpstreamCategory).sort((a, c) => c[1].d - a[1].d)) {
    process.stdout.write(`  ${cat.padEnd(16)} ${String(b.d).padStart(3)} findings, we synthesize a fix for ${b.synthesized}\n`);
  }
  process.stdout.write(`\nwrote ${path.relative(process.cwd(), RESULT)}\n`);
}

main().catch((e) => { process.stderr.write(`runner failed: ${e.stack}\n`); process.exit(1); });
