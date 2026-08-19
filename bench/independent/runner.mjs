#!/usr/bin/env node
// Score the engine against the independent population.
//
// This is an ACCURACY MEASUREMENT, not a gate. It does not fail a build, it does
// not have a baseline, and it must never grow one: a number you are not allowed
// to move is a number you will start tuning towards.
//
// Per entry, over the CWE the advisory assigned:
//   TP  a matching finding in pre/   (vulnerable version)
//   FN  no matching finding in pre/
//   FP  a matching finding in post/  (fixed version)
//   TN  no matching finding in post/
//
// MATCHING IS CWE-ONLY. Scoring on this engine's own vuln titles or families
// would grade it against vocabulary it chose itself. CWE is the one identifier
// the advisory and the engine both speak, and it is the same choice
// posture/comparison.js makes for the same reason.
//
// AN UNFETCHABLE OR UNSCANNABLE ENTRY IS UNSCORED. It is excluded from every
// denominator and reported by name — never counted as a miss. Counting an
// infrastructure failure as a detection failure silently blames the engine for
// the network, which is exactly the reasoning error the corpus gate's
// "unrunnable is not a pass" rule exists to prevent, pointed the other way.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { entryDir, entryComplete } from './fetch.mjs';

import { snapshotTree, assertTreeUnchanged, disableStateWrites } from '../_lib/tree-integrity.mjs';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(HERE, '..', '..');
const MANIFEST = path.join(HERE, 'manifest.json');

/** Below this, a rate is noise. Reported, but labelled unreliable. */
export const MIN_RELIABLE_N = 10;

/**
 * T0.1 — how far from a changed line a finding may sit and still count as
 * being ABOUT that change. A fix often adds a guard a line or two above the
 * sink it protects, so an exact-line requirement would be too strict; a wide
 * window would re-admit the coincidences this metric exists to exclude.
 * Deliberately small, and every widening must be justified with data.
 */
export const LOCALIZATION_WINDOW = 3;

/**
 * T0.5 — CWE parent edges (child -> parents), deliberately CONSERVATIVE.
 *
 * WHY THIS EXISTS. The engine and the advisory can describe the same bug at
 * different depths of MITRE's tree: the engine reports CWE-94 (Code
 * Injection) where an advisory labelled CWE-95 (Eval Injection, its child).
 * Scoring those as a miss measures vocabulary, not detection.
 *
 * WHY IT IS SHORT. Every edge added here can only ever ADMIT more matches, so
 * a generous table manufactures recall — the exact failure this benchmark
 * exists to avoid. Only well-established, unambiguous ChildOf relationships
 * that bear on classes this engine actually reports are listed. When in
 * doubt, leave the edge out and take the miss.
 *
 * Applied SYMMETRICALLY (an engine finding more specific OR more general than
 * the label both count) and only alongside T0.1's localization tightening —
 * loosening the CWE axis while the location axis stayed loose would inflate
 * the number in exactly the direction this PRD refuses.
 */
export const CWE_PARENT = {
  'CWE-95': ['CWE-94'], 'CWE-94': ['CWE-74'],
  'CWE-78': ['CWE-77'], 'CWE-77': ['CWE-74'],
  'CWE-89': ['CWE-74'], 'CWE-79': ['CWE-74'],
  'CWE-113': ['CWE-93'], 'CWE-93': ['CWE-74'],
  'CWE-23': ['CWE-22'], 'CWE-36': ['CWE-22'],
  'CWE-338': ['CWE-330'], 'CWE-331': ['CWE-330'],
  'CWE-328': ['CWE-327'],
  'CWE-259': ['CWE-798'],
  'CWE-862': ['CWE-285'], 'CWE-863': ['CWE-285'], 'CWE-285': ['CWE-284'],
  'CWE-639': ['CWE-863'],
  'CWE-611': ['CWE-610'], 'CWE-601': ['CWE-610'],
  'CWE-1333': ['CWE-407'],
};

/** Transitive ancestors of a CWE, per the conservative table above. */
export function cweAncestors(cwe) {
  const out = new Set();
  const walk = (c, depth = 0) => {
    if (depth > 8) return; // cycle/pathology guard
    for (const p of (CWE_PARENT[c] || [])) { if (!out.has(p)) { out.add(p); walk(p, depth + 1); } }
  };
  walk(String(cwe || '').toUpperCase().trim());
  return out;
}

/**
 * Does a finding's CWE satisfy an advisory's labelled CWE? Exact match, or an
 * ancestor relationship in EITHER direction (see CWE_PARENT's rationale).
 */
export function cweSatisfies(foundCwe, wantedCwe) {
  const found = String(foundCwe || '').toUpperCase().trim();
  const want = String(wantedCwe || '').toUpperCase().trim();
  if (!/^CWE-\d+$/.test(found) || !/^CWE-\d+$/.test(want)) return false;
  if (found === want) return true;
  return cweAncestors(found).has(want) || cweAncestors(want).has(found);
}

/**
 * Findings matching the labelled CWE, restricted to the advisory's files.
 * `hierarchy` opts into the CWE_PARENT relation; OFF by default so the
 * historical exact-match contract (and its tests) is unchanged.
 */
export function findMatchingFindings(findings, cwe, files = null, { hierarchy = false } = {}) {
  const want = String(cwe || '').toUpperCase().trim();
  if (!/^CWE-\d+$/.test(want)) return [];
  const scoped = localiseToAdvisory(findings, files);
  return scoped.filter(f => hierarchy
    ? cweSatisfies(f.cwe, want)
    : String(f.cwe || '').toUpperCase().trim() === want);
}

/** Does any finding carry the labelled CWE? Normalised, exact on the number. */
export function matchesCwe(findings, cwe, files = null, opts = {}) {
  return findMatchingFindings(findings, cwe, files, opts).length > 0;
}

/**
 * T0.1 — is a finding's line inside (or within `window` lines of) any range
 * the fix commit actually changed?
 *
 * This is the whole point of the localized metric. A finding that carries the
 * right CWE in the right FILE but sits 200 lines from the code the fix
 * touched is not a detection of that vulnerability; measured on the 2026-08-17
 * population, 17 of 21 "true positives" were exactly that.
 */
export function isLocalized(line, ranges, window = LOCALIZATION_WINDOW) {
  const n = Number(line);
  if (!Number.isFinite(n) || n <= 0) return false;      // no line ⇒ cannot localize
  if (!Array.isArray(ranges) || ranges.length === 0) return false;
  return ranges.some(([a, b]) => n >= a - window && n <= b + window);
}

/**
 * Line ranges (1-based, inclusive, on the PRE side) that differ between the
 * vulnerable and fixed copies of one file. Shells out to `diff -u0`, matching
 * this directory's existing practice of using system tools (tar/git/gh).
 * Returns [] for an identical file and null when the comparison can't be made
 * (missing side, or no usable diff) — the caller must distinguish those.
 */
export function changedLineRanges(preFile, postFile) {
  if (!fs.existsSync(preFile) || !fs.existsSync(postFile)) return null;
  const r = cp.spawnSync('diff', ['-u0', preFile, postFile], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  // diff exits 0 (identical) or 1 (differences); >1 is a real failure.
  if (r.error || typeof r.status !== 'number' || r.status > 1) return null;
  const ranges = [];
  for (const m of String(r.stdout || '').matchAll(/^@@ -(\d+)(?:,(\d+))? /gm)) {
    const start = parseInt(m[1], 10);
    const len = m[2] === undefined ? 1 : parseInt(m[2], 10);
    // len===0 is unified diff's notation for a PURE INSERTION (`-82,0`) — the
    // most common shape a security fix takes (add a check, delete nothing).
    // Dropping it entirely, rather than anchoring a point range at `start`,
    // meant no finding could ever localize against an insertion-only fix —
    // found via GHSA-2364-jh4q-m9vm, whose fix inserts one line and nothing
    // else, so every one of its 8 hunks but one was silently excluded.
    ranges.push(len > 0 ? [start, start + len - 1] : [start, start]);
  }
  return ranges;
}

/**
 * Line ranges on the POST side that the fix produced — the `+P,Q` half of each
 * unified-diff hunk header, mirroring changedLineRanges' pre-side `-N,M`.
 *
 * Needed because `survivedFix` asked "does ANY matching finding remain in the
 * advisory's files", which is a different claim from the one the metric
 * reports ("localized TPs that correctly disappear once the vulnerability is
 * fixed"). A file with several vulnerable sites where the fix addresses only
 * some — GHSA-chm3-vqcf-52rx patches 5 handlers and leaves other unscoped ones
 * untouched, GHSA-q939-rpr3-3284 guards 2 of 4 sinks — always reported
 * "survived", even when the detector went silent on every site the fix
 * actually changed. Scoping to the post-side changed lines asks whether the
 * finding still fires on the code the fix PRODUCED.
 */
export function changedLineRangesPost(preFile, postFile) {
  if (!fs.existsSync(preFile) || !fs.existsSync(postFile)) return null;
  const r = cp.spawnSync('diff', ['-u0', preFile, postFile], { encoding: 'utf8', maxBuffer: 32 * 1024 * 1024 });
  if (r.error || typeof r.status !== 'number' || r.status > 1) return null;
  const ranges = [];
  for (const m of String(r.stdout || '').matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? /gm)) {
    const start = parseInt(m[1], 10);
    const len = m[2] === undefined ? 1 : parseInt(m[2], 10);
    // len===0 is a pure DELETION — anchor a point range, same as the
    // pure-insertion case on the pre side.
    ranges.push(len > 0 ? [start, start + len - 1] : [start, start]);
  }
  return ranges;
}

/**
 * T0.7 — deterministic held-out slice.
 *
 * Detection work must not be tuned against every entry it is scored on, the
 * same reason posture/holdout-eval.js exists for calibration. Membership is a
 * pure function of the entry id, so the split is stable across runs, machines
 * and population growth — no stored state to drift, and a newly mined entry
 * lands on a fixed side rather than reshuffling everything.
 */
export function isHeldOut(id, fraction = 0.2) {
  let h = 2166136261 >>> 0;                    // FNV-1a
  for (const ch of String(id)) { h ^= ch.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; }
  return (h % 1000) / 1000 < fraction;
}

/**
 * Restrict findings to the files the advisory's fix commit touched.
 *
 * WHY, WITH THE NUMBER THAT FORCED IT. Package-scope materialisation (N1) gave
 * the taint engine the callers it needs, and recall rose 12.5% -> 32.5%. It also
 * widened what counts as a false positive to the whole package: an entry could
 * score FP because the same CWE appeared ANYWHERE in the scanned tree. Measured
 * on the 110-entry run, several `post/` scopes contained over 1700 findings, so
 * "a CWE-862 exists somewhere in 1735 findings" was being recorded as a false
 * positive against one advisory about one file.
 *
 * That is not a precision defect, it is a scoping error in the benchmark, and
 * leaving it in place would have invited exactly the wrong response — tuning
 * detectors to suppress real findings in unrelated code in order to move a
 * number.
 *
 * SYMMETRIC ON PURPOSE. The restriction applies to `pre` and `post` alike.
 * Scoring the vulnerable side generously and the fixed side strictly would
 * inflate both recall and precision, which is the shape of a benchmark built to
 * flatter. Context still does its job — the engine reads the whole package to
 * resolve the flow — but the CLAIM is anchored to the files the advisory is
 * actually about.
 *
 * `files = null` disables the restriction, which is what the unit tests use.
 */
export function localiseToAdvisory(findings, files) {
  if (!Array.isArray(files) || files.length === 0) return findings || [];
  const wanted = new Set(files.map(f => String(f)));
  return (findings || []).filter(f => {
    const file = String(f.file || '');
    // Findings carry paths relative to the scanned root, which is the scope
    // directory — so compare by suffix rather than demanding an exact match.
    for (const w of wanted) {
      if (file === w || file.endsWith('/' + w) || w.endsWith('/' + file) || w.endsWith(file)) return true;
    }
    return false;
  });
}

/** Precision/recall/F1 from raw counts, each carrying its {n, d}. */
export function scoreCounts({ tp, fp, fn, tn }) {
  const rate = (n, d) => ({ n, d, value: d > 0 ? n / d : null });
  const precision = rate(tp, tp + fp);
  const recall = rate(tp, tp + fn);
  const f1 = (precision.value !== null && recall.value !== null && (precision.value + recall.value) > 0)
    ? (2 * precision.value * recall.value) / (precision.value + recall.value)
    : null;
  return { tp, fp, fn, tn, precision, recall, f1, scored: tp + fn };
}

function pct(r) {
  if (!r || r.value === null) return 'n/a';
  return `${(r.value * 100).toFixed(1)}% (${r.n}/${r.d})`;
}

/**
 * Remove any scan state the engine wrote INTO a tree it scanned.
 *
 * THIS IS AN INTEGRITY CONTROL, NOT TIDINESS. A scan writes
 * `.agentic-security/` into its own root — threat-model.json,
 * exploit-bundles.json, scan-history.json — and those files CONTAIN CWE
 * IDENTIFIERS from the previous run. Audited on this population: 220 polluted
 * trees, 544 state files carrying `CWE-` strings.
 *
 * Left in place, the second scan of a tree reads the first scan's conclusions as
 * if they were source code. That is the benchmark grading the engine on its own
 * previous output — the precise definition of cheating, arrived at by accident
 * rather than intent, which is the only way it ever shows up in practice.
 *
 * Purged BEFORE every scan, so each measurement sees exactly the upstream files
 * and nothing this project produced. Purging only afterwards would still leave a
 * window where an interrupted run poisons the next one.
 */
export function purgeScanState(dir) {
  let removed = 0;
  const walk = (d, depth = 0) => {
    if (depth > 12) return;
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (!e.isDirectory()) continue;
      const p = path.join(d, e.name);
      if (e.name === '.agentic-security') { fs.rmSync(p, { recursive: true, force: true }); removed++; continue; }
      if (e.name === 'node_modules' || e.name === '.git') continue;
      walk(p, depth + 1);
    }
  };
  walk(dir);
  return removed;
}

export async function scanDirRaw(dir) {
  // Pristine input, every time. See purgeScanState.
  purgeScanState(dir);
  // Snapshot AFTER the purge: the purge is a deliberate removal, so including
  // it would guarantee a spurious "corpus changed" on every entry. What is
  // being asserted is that the SCAN adds nothing, which is the claim that
  // matters. (STATE_SEAM_COMPLETION_PRD M3)
  const before = snapshotTree(dir);
  const { runScan } = await import(path.join(REPO, 'scanner', 'src', 'runScan.js'));
  const { scan } = await runScan(dir);
  const { normalizeFindings } = await import(path.join(REPO, 'scanner', 'src', 'report', 'index.js'));
  const findings = normalizeFindings(scan) || [];
  assertTreeUnchanged(before, snapshotTree(dir), `independent entry ${path.basename(path.dirname(dir))}/${path.basename(dir)}`);
  // Defence in depth: even with a pristine input, refuse to score a finding
  // whose path is inside our own state directory. A single guard that can be
  // bypassed by a mid-run write is not a guard.
  return {
    findings: findings.filter(f => !String(f.file || '').includes('.agentic-security')),
    suppressions: scan.suppressions || [],
  };
}

async function scanDir(dir) {
  return (await scanDirRaw(dir)).findings;
}

async function main() {
  // STATE_SEAM_COMPLETION_PRD M3 — see scanDir for the per-entry assertion.
  await disableStateWrites();
  const manifest = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));
  const asJson = process.argv.includes('--json');
  // T0.3 — the deep engine is a CONFIGURATION of this measurement, not a
  // separate script. Before this flag existed, runner.mjs called runScan()
  // with no options and runScan() does not default deep:true (only the CLI
  // wrapper sets AGENTIC_SECURITY_DEEP), so every independent-population
  // figure this project ever published was pattern-only — the taint engine
  // was never once exercised by the benchmark built to measure it.
  const deep = process.argv.includes('--deep');
  if (deep) process.env.AGENTIC_SECURITY_DEEP = '1';
  const configuration = deep ? 'deep' : 'pattern-only';

  const perEntry = [];
  const unscored = [];

  // Per-entry progress, to STDERR so `--json` stdout stays machine-parseable.
  //
  // Without this the runner is completely opaque: it buffers the whole report
  // and writes it at the end, so a 110-minute deep run looks identical at
  // minute 5 and minute 105 — no way to tell "working" from "wedged", and a
  // run killed at 95% leaves nothing at all. Rate and ETA come from measured
  // elapsed time rather than a fixed estimate, because deep mode is ~2x
  // slower than pattern-only and any hardcoded guess is wrong for one of them.
  //
  // Quiet when stderr is not a TTY (CI logs, `2>file`) unless the caller asks
  // via AGENTIC_SECURITY_BENCH_PROGRESS=1, so redirected runs stay clean.
  const total = manifest.entries.length;
  const showProgress = process.env.AGENTIC_SECURITY_BENCH_PROGRESS === '1'
    || (process.stderr.isTTY && process.env.AGENTIC_SECURITY_BENCH_PROGRESS !== '0');
  const startedAt = Date.now();
  let seen = 0;
  const progress = (id, note = '') => {
    if (!showProgress) return;
    seen++;
    const elapsed = (Date.now() - startedAt) / 1000;
    const rate = seen / Math.max(elapsed, 0.001);
    const etaS = rate > 0 ? Math.round((total - seen) / rate) : 0;
    const mmss = (t) => `${Math.floor(t / 60)}m${String(Math.round(t % 60)).padStart(2, '0')}s`;
    const pct = String(Math.round((seen / total) * 100)).padStart(3);
    process.stderr.write(
      `[${String(seen).padStart(String(total).length)}/${total}] ${pct}% `
      + `elapsed ${mmss(elapsed)} eta ${mmss(etaS)}  ${id}${note ? ' — ' + note : ''}\n`);
  };

  for (const e of manifest.entries) {
    if (!entryComplete(e)) {
      progress(e.id, 'skipped: not fetched');
      unscored.push({ id: e.id, reason: 'not fetched — run `npm run bench:independent:fetch`' });
      continue;
    }
    const dir = entryDir(e.id);

    // T0.6 — an entry whose vulnerable file is not in the materialised tree
    // cannot be detected by any engine, so counting it as a detection failure
    // blames the scanner for the sampling. Measured on this population: the
    // file is sometimes DELETED by the fix commit, or dropped by mine.mjs's
    // 5-file cap on a squashed commit. Same doctrine as the existing
    // "unfetchable is UNSCORED, never a miss" rule.
    const missing = (e.files || []).filter(rel => !fs.existsSync(path.join(dir, 'pre', rel)));
    if ((e.files || []).length > 0 && missing.length === (e.files || []).length) {
      progress(e.id, 'unscored: advisory files absent');
      unscored.push({ id: e.id, reason: `advisory file(s) absent from the materialised pre/ tree: ${missing.join(', ')}` });
      continue;
    }

    let preFindings, postFindings;
    try {
      preFindings = await scanDir(path.join(dir, 'pre'));
      postFindings = await scanDir(path.join(dir, 'post'));
    } catch (err) {
      progress(e.id, `unscored: scan failed — ${err.message}`);
      unscored.push({ id: e.id, reason: `scan failed: ${err.message}` });
      continue;
    }

    // ── file-scoped (the historical rule; retained as a diagnostic) ────────
    const hitPre = matchesCwe(preFindings, e.cwe, e.files);
    const hitPost = matchesCwe(postFindings, e.cwe, e.files);
    // Same verdict with the advisory-file restriction OFF. See `wide` below.
    const hitPreWide = matchesCwe(preFindings, e.cwe, null);
    const hitPostWide = matchesCwe(postFindings, e.cwe, null);

    // ── T0.1 localized (THE CLAIM) ────────────────────────────────────────
    // Credit only when a matching finding sits on code the fix actually
    // changed. Hierarchy matching (T0.5) is enabled here and only here: it
    // may only ever accompany this tightening, never precede it.
    const rangesByFile = new Map();
    for (const rel of (e.files || [])) {
      rangesByFile.set(rel, changedLineRanges(path.join(dir, 'pre', rel), path.join(dir, 'post', rel)));
    }
    const relOf = (f) => (e.files || []).find(rel => rel.endsWith(String(f.file || '')) || String(f.file || '').endsWith(rel)) || f.file;
    const localizedMatches = findMatchingFindings(preFindings, e.cwe, e.files, { hierarchy: true })
      .filter(f => isLocalized(f.line, rangesByFile.get(relOf(f))));
    const hitPreLocal = localizedMatches.length > 0;
    // T0.2 — did the SAME finding go away once the bug was fixed? A finding
    // that survives its own fix has reported the presence of an API, not the
    // presence of a vulnerability.
    // Scoped to the lines the fix PRODUCED, not the whole file — see
    // changedLineRangesPost. `postMatchesAnywhere` is retained alongside so the
    // stricter and looser readings stay distinguishable in the report.
    const postRangesByFile = new Map();
    for (const rel of (e.files || [])) {
      postRangesByFile.set(rel, changedLineRangesPost(path.join(dir, 'pre', rel), path.join(dir, 'post', rel)));
    }
    const postMatchesAnywhere = findMatchingFindings(postFindings, e.cwe, e.files, { hierarchy: true });
    const postMatches = postMatchesAnywhere
      .filter(f => isLocalized(f.line, postRangesByFile.get(relOf(f))));
    const survivedFix = hitPreLocal && postMatches.length > 0;
    const survivedFixWide = hitPreLocal && postMatchesAnywhere.length > 0;
    // T0.4 — which analysis layer actually produced the credited finding.
    const matchedParser = hitPreLocal ? (localizedMatches[0].parser || 'unknown') : null;

    perEntry.push({
      id: e.id, cwe: e.cwe, language: e.language, repo: e.repo,
      heldOut: isHeldOut(e.id),
      tp: hitPre ? 1 : 0, fn: hitPre ? 0 : 1,
      fp: hitPost ? 1 : 0, tn: hitPost ? 0 : 1,
      tpWide: hitPreWide ? 1 : 0, fnWide: hitPreWide ? 0 : 1,
      fpWide: hitPostWide ? 1 : 0, tnWide: hitPostWide ? 0 : 1,
      tpLocal: hitPreLocal ? 1 : 0, fnLocal: hitPreLocal ? 0 : 1,
      fpLocal: (hitPost && !hitPreLocal) ? 1 : 0, tnLocal: (hitPost && !hitPreLocal) ? 0 : 1,
      survivedFix: survivedFix ? 1 : 0,
      survivedFixWide: survivedFixWide ? 1 : 0,
      matchedParser,
      matchedLine: hitPreLocal ? (localizedMatches[0].line ?? null) : null,
      preFindings: preFindings.length, postFindings: postFindings.length,
    });
    progress(e.id, hitPreLocal ? `localized TP (${matchedParser})` : (hitPre ? 'file-scoped only' : 'miss'));
  }

  const sum = (rows) => rows.reduce((a, r) => ({
    tp: a.tp + r.tp, fp: a.fp + r.fp, fn: a.fn + r.fn, tn: a.tn + r.tn,
  }), { tp: 0, fp: 0, fn: 0, tn: 0 });

  const overall = scoreCounts(sum(perEntry));
  // The SAME scans scored without the advisory-file restriction.
  //
  // WHY THIS IS REPORTED RATHER THAN CHOSEN BETWEEN. Two corrections landed
  // together — purging scan state (an accuracy correction: the engine had been
  // partly grading its own prior output) and localiseToAdvisory (a strictness
  // correction in the HARNESS). Recall fell sharply across the pair. Attributing
  // that fall to the engine when it belongs to the benchmark's scope would be the
  // same reasoning error as the contamination, pointed the other way.
  //
  // `overall` is the number this project quotes: it is the defensible claim,
  // because it asks whether the engine flagged the file the advisory is about.
  // `wide` asks only whether the CWE appeared ANYWHERE in the package, which over
  // scopes holding hundreds of findings is close to a lookup of "does this
  // codebase contain this bug class at all" — a question with a much easier yes.
  // The GAP between them is the diagnostic: it is how much of the engine's
  // apparent recall comes from finding the right thing versus from finding
  // something of the right kind somewhere.
  const wide = scoreCounts(sum(perEntry.map(r => ({
    tp: r.tpWide, fp: r.fpWide, fn: r.fnWide, tn: r.tnWide,
  }))));

  // T0.1 — THE CLAIM. Credit only where a matching finding landed on code the
  // fix actually changed. Measured 2026-08-17, this is the difference between
  // 6.67% (file-scoped) and 1.3% (localized): 17 of 21 apparent true positives
  // were right-CWE-right-file-wrong-code coincidences.
  const localizedOf = (rows) => scoreCounts(sum(rows.map(r => ({
    tp: r.tpLocal, fp: r.fpLocal, fn: r.fnLocal, tn: r.tnLocal,
  }))));
  const localized = localizedOf(perEntry);

  // T0.2 — of the localized true positives, how many correctly went SILENT on
  // the fixed code? A finding that survives its own fix has detected an API,
  // not a vulnerability. Reported with its denominator, never as a bare rate.
  const localTps = perEntry.filter(r => r.tpLocal === 1);
  const survived = localTps.filter(r => r.survivedFix === 1).length;
  const fixDiscrimination = {
    n: localTps.length - survived, d: localTps.length,
    value: localTps.length ? (localTps.length - survived) / localTps.length : null,
    meaning: 'localized TPs whose finding disappears from the lines the fix produced',
  };
  // The previous, looser reading, kept so the definition change is auditable
  // rather than a silent improvement: ANY matching finding remaining anywhere
  // in the advisory's files counts as survival. It understates a detector that
  // correctly silenced every site the fix touched while still reporting other,
  // genuinely unfixed sites in the same file.
  const survivedWide = localTps.filter(r => r.survivedFixWide === 1).length;
  const fixDiscriminationFileScoped = {
    n: localTps.length - survivedWide, d: localTps.length,
    value: localTps.length ? (localTps.length - survivedWide) / localTps.length : null,
    meaning: 'localized TPs with NO matching finding anywhere in the advisory files afterwards',
  };

  // T0.4 — which layer earned each localized true positive. This is the
  // standing answer to "what does the deep engine actually contribute",
  // rather than a question that needs a special investigation each time.
  const byLayer = {};
  for (const r of localTps) byLayer[r.matchedParser || 'unknown'] = (byLayer[r.matchedParser || 'unknown'] || 0) + 1;

  // T0.7 — the held-out slice is scored separately and must never be tuned
  // against. Same doctrine as posture/holdout-eval.js for calibration.
  const heldOutRows = perEntry.filter(r => r.heldOut);
  const devRows = perEntry.filter(r => !r.heldOut);

  const group = (key) => {
    const out = {};
    for (const r of perEntry) {
      const k = r[key] || '(unknown)';
      (out[k] ||= []).push(r);
    }
    return Object.fromEntries(Object.entries(out).sort(([a], [b]) => (a < b ? -1 : 1))
      .map(([k, rows]) => [k, { entries: rows.length, ...scoreCounts(sum(rows)) }]));
  };

  // Self-describing: the previous RESULT.json had to be hand-assembled from
  // stdout, which is how it came to carry a stale measuredAt/engineVersion
  // while claiming to be current. A report states its own provenance.
  let engineVersion = null;
  try { engineVersion = JSON.parse(fs.readFileSync(path.join(REPO, 'scanner', 'package.json'), 'utf8')).version; } catch { /* leave null */ }

  const report = {
    schema: 'agentic-security/independent-population-result@2',
    source: 'bench/independent/runner.mjs',
    measuredAt: new Date().toISOString().slice(0, 10),
    engineVersion,
    configuration,
    population: {
      totalEntries: manifest.entries.length,
      scoredEntries: perEntry.length,
      unscored,
      labelSources: [...new Set(manifest.entries.map(e => e.labelSource))],
    },
    reliable: perEntry.length >= MIN_RELIABLE_N,
    // Per-entry rows, so a false positive can be OPENED rather than counted.
    // Aggregates say precision is 50%; only these say which advisory produced
    // the finding in `post/`, which is the difference between "18 defects" and
    // "18 rows that need classifying". Plan R-4 depends on this existing.
    perEntry,
    // THE CLAIM (T0.1). Everything below it is diagnostic.
    localized: { ...localized, meaning: 'matching finding landed on code the fix actually changed (±' + LOCALIZATION_WINDOW + ' lines)' },
    fixDiscrimination,
    fixDiscriminationFileScoped,
    byLayer,
    heldOut: {
      meaning: 'never tune against these; scored separately (T0.7)',
      entries: heldOutRows.length,
      localized: localizedOf(heldOutRows),
    },
    development: {
      entries: devRows.length,
      localized: localizedOf(devRows),
    },
    overall,
    // Diagnostic only — NOT this project's headline. See the comment on `wide`.
    wide: { ...wide, meaning: 'same scans, advisory-file restriction OFF' },
    byLanguage: group('language'),
    byCwe: group('cwe'),
  };

  if (asJson) { process.stdout.write(JSON.stringify(report, null, 2) + '\n'); return 0; }

  const out = process.stdout;
  out.write('\nIndependent evaluation population\n');
  out.write(`  labels from: ${report.population.labelSources.join(', ')}\n`);
  out.write(`  scored ${perEntry.length} of ${manifest.entries.length} entries\n`);
  if (!report.reliable) {
    out.write(`\n  ⚠ n=${perEntry.length} is below ${MIN_RELIABLE_N}. These rates are NOT reliable.\n` +
      '    They are printed so the instrument can be seen working, not so the\n' +
      '    numbers can be quoted. Grow the population before drawing a conclusion.\n');
  }
  out.write(`  configuration: ${configuration}` + (deep ? '' : '  (pass --deep to measure the taint engine)') + '\n');

  out.write('\n  ── LOCALIZED (the claim) — the finding landed on code the fix changed ──\n');
  out.write('    precision  ' + pct(localized.precision) + '\n');
  out.write('    recall     ' + pct(localized.recall) + '\n');
  out.write('    F1         ' + (localized.f1 === null ? 'n/a' : localized.f1.toFixed(3)) + '\n');
  out.write('    fix-discrimination ' + pct(fixDiscrimination) +
            '  (localized TPs that go silent once fixed)\n');
  if (Object.keys(byLayer).length) {
    out.write('    by layer   ' + Object.entries(byLayer).sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${k}=${n}`).join('  ') + '\n');
  }
  out.write(`    held-out   ${pct(report.heldOut.localized.recall)} recall over ${report.heldOut.entries} entries (never tuned against)\n`);

  out.write('\n  ── FILE-SCOPED (diagnostic) — right CWE somewhere in the advisory files ──\n');
  out.write('    precision  ' + pct(overall.precision) + '\n');
  out.write('    recall     ' + pct(overall.recall) + '\n');
  out.write('    F1         ' + (overall.f1 === null ? 'n/a' : overall.f1.toFixed(3)) + '\n');
  out.write(`    raw        TP=${overall.tp} FP=${overall.fp} FN=${overall.fn} TN=${overall.tn}\n`);
  out.write('    The gap against LOCALIZED is how much apparent recall comes from a\n' +
            '    finding that carries the right CWE in the right file while describing\n' +
            '    different code. Measured 2026-08-17: 17 of 21 file-scoped TPs.\n');

  out.write('\n  same scans, advisory-file restriction OFF (diagnostic, NOT the claim):\n');
  out.write('    precision  ' + pct(wide.precision) + '\n');
  out.write('    recall     ' + pct(wide.recall) + '\n');
  out.write('    The gap against the figures above is how much apparent recall comes\n' +
            '    from flagging the right FILE versus flagging the right CWE somewhere\n' +
            '    in the package. Quote the restricted numbers; read this one to know\n' +
            '    whether a change moved the engine or moved the benchmark.\n');

  out.write('\n  by language\n');
  for (const [k, v] of Object.entries(report.byLanguage)) {
    out.write(`    ${k.padEnd(12)} n=${String(v.entries).padStart(3)}  precision ${pct(v.precision)}  recall ${pct(v.recall)}\n`);
  }
  out.write('\n  by CWE\n');
  for (const [k, v] of Object.entries(report.byCwe)) {
    out.write(`    ${k.padEnd(12)} n=${String(v.entries).padStart(3)}  recall ${pct(v.recall)}\n`);
  }
  if (unscored.length) {
    out.write(`\n  UNSCORED (${unscored.length}) — excluded from every denominator, never counted as misses:\n`);
    for (const u of unscored) out.write(`    · ${u.id}: ${u.reason}\n`);
  }
  out.write('\n  This is a measurement, not a gate. It has no baseline and must not grow one.\n\n');
  return 0;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().then(c => process.exit(c)).catch(e => {
    process.stderr.write(`independent runner failed: ${e.message}\n`); process.exit(1);
  });
}
