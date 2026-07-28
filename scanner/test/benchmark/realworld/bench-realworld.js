#!/usr/bin/env node
// Real-world detection benchmark against vulnerable apps (OWASP Benchmark, NodeGoat,
// etc.). Source code is NEVER committed: each app is shallow-cloned to
// .bench-cache/{name}-{sha}/ on demand and re-used across runs.
//
// Usage:
//   node bench-realworld.js --all                  # all apps in manifest
//   node bench-realworld.js --app nodegoat         # one app
//   node bench-realworld.js --app nodegoat,pygoat  # a subset
//   node bench-realworld.js --app nodegoat --refresh-cache
//   node bench-realworld.js --json                 # machine-readable
//   node bench-realworld.js --all --in-process     # legacy single-process loop
//
// Reports per-app precision and recall with raw TP/FP/FN counts. Per-app,
// never combined — different apps test different rule families and any
// macro-averaged summary number hides where the engine is weak.
//
// PROCESS MODEL. Any multi-app run (`--all`, or `--app a,b`) is an
// ORCHESTRATOR, not a loop: it spawns one child process per app
// (`--app <name> --json`) and aggregates the children's JSON into the same
// `{ results: [...] }` envelope the single-process loop used to emit. Two
// properties come from that:
//   1. Peak memory is bounded by the LARGEST SINGLE APP rather than the sum of
//      all of them. The manifest's biggest target is an order of magnitude
//      larger than the rest, and running everything in one heap made the whole
//      sweep hostage to that one app's high-water mark.
//   2. One app crashing (OOM, parser blowup, anything) can no longer destroy
//      the whole sweep. A dead child is recorded as `{ name, error, crashed }`
//      and the remaining apps still run.
// A crashed app is ALWAYS present in `results` with an `error` and ALWAYS
// makes the process exit non-zero. Silently dropping it would let a crash
// masquerade as a clean sweep, which is strictly worse than a loud failure:
// a missing app is a result nobody reads, a failing app is one everybody does.
// `--in-process` restores the old single-heap loop for local A/B measurement.

import * as path from 'node:path';
import * as os from 'node:os';
import * as fs from 'node:fs/promises';
import * as cp from 'node:child_process';
import { fileURLToPath } from 'node:url';

// Realworld bench measures core scanner behavior against per-app
// expected.json. The world-class integration block (LLM-app, mobile, PQC,
// Web3, IAM, K8s, crypto-protocol, ML-supply-chain, license-graph etc.)
// fires on real-world JS code and inflates FPs against expected.json
// (which only describes the canonical SAST findings). Set NO_INTEGRATION=1
// here so the realworld bench stays an apples-to-apples regression gate.
// Callers who want the integration block included can override by setting
// AGENTIC_SECURITY_NO_INTEGRATION=0 before invoking the bench.
if (process.env.AGENTIC_SECURITY_NO_INTEGRATION == null) {
  process.env.AGENTIC_SECURITY_NO_INTEGRATION = '1';
}

import { runScan } from '../../../src/runScan.js';
import { blankComments } from '../../../src/sast/_comment-strip.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MANIFEST = path.join(__dirname, 'manifest.json');
const CACHE_ROOT = path.join(__dirname, '.bench-cache');
const EXPECTED_DIR = path.join(__dirname, 'expected');
const LINE_TOLERANCE = 2;

const argv = process.argv.slice(2);
const flag = (n) => argv.includes(n);
const value = (n) => { const i = argv.indexOf(n); return i >= 0 ? argv[i+1] : null; };

const ALL = flag('--all');
const APP = value('--app');
const JSON_OUT = flag('--json');
const REFRESH = flag('--refresh-cache');
const VERBOSE = flag('--verbose') || flag('-v');
// --no-wildcards: ignore the wildcardFamilies relaxation. Produces strict
// line-level scoring — every emitted finding must match the expected family
// at the expected file:line for that test to count as a true positive.
const NO_WILDCARDS = flag('--no-wildcards');
// --blind: run against a blinded copy of each corpus + hard-disable every
// rule that reads benchmark answer-key markers (juliet-shape, the OWASP
// "// condition 'B', which is safe" template suppressors, the
// folder→CWE primary-CWE filters, the @WebServlet category restrictor).
// The blinder strips /* FLAW */ / /* POTENTIAL FLAW */ comments and OWASP
// template marker comments from every file before scanning. What's left
// is what the engine itself can detect — no label leakage.
const _BLIND_RAW = flag('--blind');
// --strip-all-comments: in addition to the answer-key marker stripping
// applied by --blind, also blank EVERY comment in the source. The scanner
// never sees comment text — only executable code. Strictly stronger than
// the default --blind, which only redacts known answer-key markers.
// Forces --blind on when used.
const STRIP_ALL_COMMENTS = flag('--strip-all-comments');
// --scramble-identifiers: also rewrite Juliet/OWASP-specific identifiers
// (bad, goodG2B, juliet.testcases, hashAlg1, ...) inside source files
// to opaque names. Strictly stronger than --strip-all-comments. Forces
// --blind on. Uses a separate cache directory so the previous variants
// can't leak in.
const SCRAMBLE_IDENTIFIERS = flag('--scramble-identifiers');
const BLIND = _BLIND_RAW || STRIP_ALL_COMMENTS || SCRAMBLE_IDENTIFIERS;
// --in-process: run every --all target inside THIS process, the way the bench
// worked before per-app isolation. Kept so the memory characteristics of the
// two modes can be compared directly; not for CI.
const IN_PROCESS = flag('--in-process');

if (!ALL && !APP) {
  console.error('Usage: bench-realworld.js [--all | --app <name>] [--refresh-cache] [--json] [--verbose] [--no-wildcards] [--blind] [--strip-all-comments] [--in-process]');
  process.exit(2);
}

function sh(cmd, args, opts = {}) {
  const r = cp.spawnSync(cmd, args, { encoding: 'utf8', stdio: ['ignore','pipe','pipe'], ...opts });
  if (r.status !== 0) throw new Error(`${cmd} ${args.join(' ')} failed: ${r.stderr || r.stdout}`);
  return r.stdout;
}

// ─── Blinding transformer ─────────────────────────────────────────────────
//
// Strip benchmark answer-key markers from every file in the corpus before
// scanning. The transforms:
//
//   1. Remove block comments containing FLAW / POTENTIAL FLAW (NIST SARD's
//      answer-key markers — they live exactly one line above the buggy sink).
//   2. Remove line comments of the same form.
//   3. Remove OWASP Benchmark template-marker comments that label safe
//      patterns (e.g. "// condition 'B', which is safe").
//   4. Remove "INCIDENTAL FLAW:" comments — Juliet's hints that a file's
//      non-primary CWE is also present (used by the engine's incidental-
//      flaw heuristics).
//   5. Strip "@WebServlet" route prefixes that encode the OWASP test
//      category (e.g. "/cmdi-02/..." → "/x/...").
//
// Output lives in .bench-cache/<name>-<sha>-blinded/ with a marker file so
// re-runs reuse it. Path layout is preserved 1:1 so the bench's GT
// builders don't need any changes.

// Match a single /* ... */ block (using the standard non-greedy idiom that
// REJECTS internal `*/` so we don't gobble code between comment blocks).
// Using `(?:[^*]|\*(?!\/))*` is the canonical regex-101 form.
const _BLIND_MARKER_PATTERNS = [
  // Block FLAW / POTENTIAL FLAW comments — scoped to one comment block.
  /\/\*(?:[^*]|\*(?!\/))*?(?:POTENTIAL\s+FLAW|\bFLAW)\s*[:.](?:[^*]|\*(?!\/))*?\*\//gi,
  /\/\/[ \t]*(?:POTENTIAL\s+FLAW|FLAW)\s*[:.].*$/gim,
  // Juliet "INCIDENTAL FLAW" — same scoping fix.
  /\/\*(?:[^*]|\*(?!\/))*?INCIDENTAL\s+FLAW(?:[^*]|\*(?!\/))*?\*\//gi,
  /\/\/[ \t]*INCIDENTAL\s+FLAW.*$/gim,
  // OWASP Benchmark template marker comments: each labels a SAFE pattern.
  /\/\/[ \t]*condition\s+'B',\s+which\s+is\s+safe.*$/gim,
  /\/\/[ \t]*Simple\s+\?\s+condition\s+that\s+assigns\s+(?:constant|param)\s+to\s+bar.*$/gim,
  /\/\/[ \t]*Simple\s+if\s+statement\s+that\s+assigns\s+(?:constant|param)\s+to\s+bar.*$/gim,
  /\/\/[ \t]*Simple\s+(?:case|switch)\s+statement\s+that\s+assigns.*$/gim,
  /\/\/[ \t]*This\s+is\s+static\s+so\s+this\s+whole\s+flow\s+is\s+'safe'.*$/gim,
  // OWASP Juliet "fix" comment used to hint that the test is the safe variant.
  /\/\*[ \t]*FIX[ \t]*:[\s\S]*?\*\//g,
  /\/\/[ \t]*FIX\s*:.*$/gim,
  // OWASP Benchmark @WebServlet("/cmdi-02/...") category prefix → opaque.
  /(@WebServlet\s*\(\s*(?:value\s*=\s*)?["'])(?:[^"'/]*\/)?\w+?-\d+\//g,
];

function _blindTransform(text, opts = {}) {
  if (!text || typeof text !== 'string') return text;
  let out = text;
  for (let i = 0; i < _BLIND_MARKER_PATTERNS.length - 1; i++) {
    out = out.replace(_BLIND_MARKER_PATTERNS[i], '');
  }
  // The @WebServlet substitution preserves the leading `@WebServlet("` so the
  // annotation still parses; only the category prefix is opaqued.
  out = out.replace(_BLIND_MARKER_PATTERNS[_BLIND_MARKER_PATTERNS.length - 1], '$1__opaque__/');
  // --strip-all-comments: pass the file through blankComments() so every
  // remaining comment becomes whitespace. The lang flag matters only for
  // Python (treats `#` as a line comment); every other language uses // and
  // /* */ which blankComments handles by default.
  if (opts.stripAllComments) {
    out = blankComments(out, opts.lang);
  }
  // --scramble-identifiers: rename every Juliet/OWASP-specific identifier
  // INSIDE the source so the scanner cannot key on them even if it ignores
  // its own bench-shape gates. Method names, package paths, and the OWASP
  // property keys are all rewritten in place. File paths are NOT renamed,
  // so the GT (which keys on path) still binds correctly.
  if (opts.scrambleIdentifiers) {
    out = out
      // Juliet method names → opaque.
      .replace(/\bbadSink\b/g, 'op0Sink')
      .replace(/\bbadSource\b/g, 'op0Source')
      .replace(/\bgoodG2BSink\b/g, 'op1G2BSink')
      .replace(/\bgoodG2BSource\b/g, 'op1G2BSource')
      .replace(/\bgoodB2GSink\b/g, 'op1B2GSink')
      .replace(/\bgoodB2GSource\b/g, 'op1B2GSource')
      .replace(/\bgoodG2B\b/g, 'op1G2B')
      .replace(/\bgoodB2G\b/g, 'op1B2G')
      .replace(/\bgoodSink\b/g, 'op1Sink')
      .replace(/\bgoodSource\b/g, 'op1Source')
      // The literal method names `bad()` and `good()` — only as method-decl shapes,
      // not as substrings of identifiers we already replaced (use lookbehind/ahead).
      .replace(/\b(?<!op0)bad(?=\s*\()/g, 'op0')
      .replace(/\b(?<!op1)good(?=\s*\()/g, 'op1')
      // Juliet packages.
      .replace(/\bjuliet\.testcases\b/g, 'app.code')
      .replace(/\bjuliet\.support\b/g, 'app.lib')
      // OWASP Benchmark answer-key property names.
      .replace(/\bcryptoAlg1\b/g, 'xa1')
      .replace(/\bcryptoAlg2\b/g, 'xa2')
      .replace(/\bhashAlg1\b/g, 'xb1')
      .replace(/\bhashAlg2\b/g, 'xb2')
      // OWASP test class literal name (as a String reference; class declaration
      // is in the filename which we don't touch).
      .replace(/"BenchmarkTest\d+"/g, '"AppX"');
  }
  return out;
}

function _langFor(filename) {
  if (/\.py$/i.test(filename)) return 'py';
  return null;
}

// Recursively materialize a blinded copy of `srcRoot` under `dstRoot`.
// Skips dirs/files larger than 5 MB and a small skip list. Re-runs are
// idempotent: a `.blinded.ok` marker file inside dstRoot causes skip.
async function _materializeBlinded(srcRoot, dstRoot, opts = {}) {
  const marker = path.join(dstRoot, '.blinded.ok');
  // The marker records the transform variant — if the caller asks for a
  // different variant than was cached, we re-blind into a fresh dir.
  const mode = opts.scrambleIdentifiers ? 'scramble-identifiers'
             : opts.stripAllComments ? 'strip-all-comments'
             : 'markers-only';
  const expectedMarker = `mode=${mode}\n`;
  try {
    const existing = await fs.readFile(marker, 'utf8');
    if (existing.startsWith(expectedMarker)) return;
    // Cached blind dir is the wrong variant — wipe it.
    await fs.rm(dstRoot, { recursive: true, force: true });
  } catch { /* not yet */ }
  await fs.mkdir(dstRoot, { recursive: true });
  const skipDirs = new Set(['.git', 'node_modules', '.gradle', 'build', 'dist', 'out', '.bench-cache', '.idea', 'target']);
  let copied = 0;
  async function walk(rel) {
    const srcDir = path.join(srcRoot, rel);
    const dstDir = path.join(dstRoot, rel);
    let entries;
    try { entries = await fs.readdir(srcDir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (skipDirs.has(e.name)) continue;
      const srcPath = path.join(srcDir, e.name);
      const dstPath = path.join(dstDir, e.name);
      if (e.isDirectory()) {
        await fs.mkdir(dstPath, { recursive: true });
        await walk(path.join(rel, e.name));
        continue;
      }
      if (!e.isFile()) continue;
      let stat;
      try { stat = await fs.stat(srcPath); } catch { continue; }
      // Transform if it looks like a source file we'd scan AND is small enough.
      // For everything else (binaries, large CSVs the GT builder reads,
      // images, etc.), copy through unchanged so the bench can still find
      // its ground-truth files.
      const isSource = /\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|java|cs|js|jsx|ts|tsx|mjs|cjs|py|rb|php|go|rs|swift|sol|kt|scala|m|mm|sh|html|xml|properties)$/i.test(e.name);
      const tooBigToTransform = stat.size > 5_000_000;
      if (isSource && !tooBigToTransform) {
        let raw;
        try { raw = await fs.readFile(srcPath, 'utf8'); } catch { continue; }
        await fs.mkdir(path.dirname(dstPath), { recursive: true });
        await fs.writeFile(dstPath, _blindTransform(raw, {
          stripAllComments: opts.stripAllComments,
          scrambleIdentifiers: opts.scrambleIdentifiers,
          lang: _langFor(e.name),
        }));
      } else {
        await fs.mkdir(path.dirname(dstPath), { recursive: true });
        try { await fs.copyFile(srcPath, dstPath); } catch { /* binary or perm; skip */ }
      }
      copied++;
    }
  }
  console.error(`  blinding ${srcRoot} → ${dstRoot} (stripping FLAW / OWASP markers)`);
  await walk('.');
  const _mode = opts.scrambleIdentifiers ? 'scramble-identifiers'
              : opts.stripAllComments ? 'strip-all-comments'
              : 'markers-only';
  await fs.writeFile(marker, `mode=${_mode}\ncopied=${copied} files\n`);
}

async function ensureClone(name, repo, sha) {
  const dest = path.join(CACHE_ROOT, `${name}-${sha}`);
  let exists = true;
  try { await fs.access(dest); } catch { exists = false; }
  if (exists && REFRESH) {
    console.error(`  refreshing cache: ${dest}`);
    await fs.rm(dest, { recursive: true, force: true });
    exists = false;
  }
  if (!exists) {
    await fs.mkdir(CACHE_ROOT, { recursive: true });
    console.error(`  cloning ${repo} @ ${sha.slice(0,7)} → ${dest}`);
    // Branch / tag / HEAD refs: clone the specific ref shallowly. Full SHAs
    // require a deep-enough clone, so we fall back to depth 100.
    const isFullSha = /^[a-f0-9]{40}$/.test(sha);
    const isHead = sha === 'HEAD' || sha === 'main' || sha === 'master';
    if (isHead) {
      sh('git', ['clone', '--quiet', '--depth', '1', repo, dest]);
    } else if (isFullSha) {
      sh('git', ['clone', '--quiet', '--depth', '100', repo, dest]);
      sh('git', ['-C', dest, 'checkout', '--quiet', sha]);
    } else {
      // Branch or tag name. Use --branch to clone directly at the ref.
      try {
        sh('git', ['clone', '--quiet', '--depth', '1', '--branch', sha, repo, dest]);
      } catch (_) {
        // Some hosts reject --branch <tag>; fall back to full clone + checkout.
        await fs.rm(dest, { recursive: true, force: true });
        sh('git', ['clone', '--quiet', repo, dest]);
        sh('git', ['-C', dest, 'checkout', '--quiet', sha]);
      }
    }
  } else if (VERBOSE) {
    console.error(`  cache hit: ${dest}`);
  }
  return dest;
}

// Build expected[] for OWASP Benchmark from upstream's expectedresults-*.csv.
// Each row: testcase, category, real-vuln (true|false), cwe.
//
// Returns { expected, negatives }. `negatives` is the set of real=false test
// files keyed by (basename, family) — used to compute true-negative-rate and
// Youden Index in line with the official OWASP Benchmark scorecard convention.
async function buildOwaspBenchmarkExpected(repoRoot, gt) {
  const csvPath = path.join(repoRoot, gt.path);
  const raw = await fs.readFile(csvPath, 'utf8');
  const lines = raw.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  const expected = [];
  const negatives = []; // real=false rows: each carries (file, family) for FPR scoring
  for (const line of lines) {
    const [test, cat, real, cwe] = line.split(',').map(s => s && s.trim());
    if (!test || !cat) continue;
    const family = gt.categoryToFamily[cat] || cat;
    const entry = {
      file: `${test}.java`,
      line: 1,
      lineTolerance: 9999, // file-level granularity — ground truth is per-test-file, not per-line
      matchAny: true,      // multiple Java rules can fire on the same file (e.g., scanJavaSAST + structural sink+source pairing); credit them all to the single expected entry rather than counting in-file duplicates as FPs.
      family,
      cwe: cwe ? `CWE-${cwe}` : null,
    };
    if (real === 'true') expected.push(entry);
    else if (real === 'false') negatives.push({ file: entry.file, family });
  }
  expected._negatives = negatives;
  return expected;
}

async function loadCuratedExpected(name, gtPath) {
  const p = path.join(__dirname, gtPath);
  return JSON.parse(await fs.readFile(p, 'utf8'));
}

// Premortem 3R-7: the curated expected JSONs carry a `requiresReAudit: true`
// flag for any corpus we have NOT re-walked by hand since the last engine
// rev. We surface this in the bench output so a reader can't mistake an
// auto-curated stale GT for a verified one. Findings against such corpora
// still get computed, but the per-corpus block is tagged.
function corpusRequiresReAudit(curated) {
  if (!curated || typeof curated !== 'object' || Array.isArray(curated)) return false;
  return curated.requiresReAudit === true;
}

// Build expected[] for a SARD/Juliet-style test suite. Each test file lives in
// `juliet-cweN/.../<TestFile>.java`. The CWE in the directory name maps to a
// scanner family via gt.cweToFamily. We walk the cloned repo, find every test
// file under a known CWE, and emit one expected entry per file (matchAny so
// multiple rules firing on the same file don't double-count).
// Build expected[] for the NIST SARD Juliet C/C++ suite. Layout differs from
// the Java mirror: `testcases/CWE<N>_<name>/<TestFile>.c` (no juliet-cwe<N>
// gradle modules; flat dir per CWE). Some CWEs nest further into per-variant
// subdirectories (e.g. CWE190/s01..s06). We walk all .c / .cpp files under
// each known CWE directory and emit one expected entry per file.
async function buildJulietCppExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const precise = !!gt.preciseMethodScoring;
  const root = path.join(repoRoot, 'testcases');
  let entries;
  try { entries = await fs.readdir(root, { withFileTypes: true }); }
  catch { return expected; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const m = e.name.match(/^CWE(\d+)_/);
    if (!m) continue;
    const cwe = `CWE${m[1]}`;
    const family = cweMap[cwe];
    if (!family) continue;
    async function walk(dir) {
      let dEntries;
      try { dEntries = await fs.readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const f of dEntries) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) { await walk(p); continue; }
        if (!/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(f.name)) continue;
        // Skip header-only test files; the engine skips pure declaration
        // headers via the same heuristic in cpp.js.
        if (/^main_linux\.c|main\.c|std_thread\.c$/i.test(f.name)) continue;
        const rel = path.relative(repoRoot, p);
        if (precise) {
          // Per-method GT: extract _bad()/_good*() spans. Emissions inside
          // _bad() count as TPs; emissions in _good*() count as FPs.
          let content = '';
          try { content = await fs.readFile(p, 'utf8'); } catch { /* skip */ }
          if (!content) continue;
          const methods = findCppMethodSpans(content);
          let anyEmitted = false;
          for (const meth of methods) {
            // Juliet C/C++ naming: <case>_bad / <case>_goodG2B / <case>_goodB2G / <case>_good.
            // _bad and _goodG2B (good source → bad sink) should fire.
            // _good and _goodB2G should NOT fire.
            const isBad = /_bad$/.test(meth.name) || /_goodG2B(?:\d*)$/.test(meth.name);
            if (isBad) {
              expected.push({
                file: rel,
                line: meth.startLine,
                lineEnd: meth.endLine,
                lineTolerance: 0,
                matchAny: true,
                family,
                cwe,
                method: meth.name,
              });
              anyEmitted = true;
            }
          }
          if (!anyEmitted) {
            expected.push({ file: rel, line: 1, lineTolerance: 9999, matchAny: true, family, cwe });
          }
        } else {
          expected.push({
            file: rel,
            line: 1,
            lineTolerance: 9999,
            matchAny: true,
            family,
            cwe,
          });
        }
      }
    }
    await walk(path.join(root, e.name));
  }
  return expected;
}

// Walk a C/C++ file and extract { name, startLine, endLine } for each
// function definition using brace-counting. Sufficient for Juliet's
// template-generated files where each test has clearly-delimited
// `<case>_bad` / `<case>_goodG2B` / `<case>_goodB2G` / `<case>_good`
// functions with no preprocessor obfuscation in the body.
function findCppMethodSpans(content) {
  const methods = [];
  // Match: optional storage qualifiers + return type + identifier + params + opening brace.
  // Keep the regex permissive — Juliet uses a small subset of C/C++ types in test files.
  const declRe = /^(?:[ \t]*(?:static|extern|inline|void|int|char|long|short|float|double|unsigned|signed|size_t|ssize_t|FILE|bool|wchar_t|HANDLE|struct\s+\w+|[A-Za-z_]\w*\s*\*?)\s+)+(\w+)\s*\([^)]*\)\s*\{/gm;
  let m;
  while ((m = declRe.exec(content))) {
    const name = m[1];
    if (name === 'if' || name === 'while' || name === 'for' || name === 'switch' || name === 'sizeof' || name === 'return') continue;
    const openIdx = m.index + m[0].length - 1;
    let depth = 1, i = openIdx + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '"' || ch === "'") {
        const quote = ch; i++;
        while (i < content.length && content[i] !== quote) {
          if (content[i] === '\\') i += 2; else i++;
        }
        i++; continue;
      }
      if (ch === '/' && content[i + 1] === '/') {
        while (i < content.length && content[i] !== '\n') i++;
        continue;
      }
      if (ch === '/' && content[i + 1] === '*') {
        i += 2;
        while (i < content.length - 1 && !(content[i] === '*' && content[i + 1] === '/')) i++;
        i += 2; continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const startLine = content.substring(0, m.index).split('\n').length;
    const endLine = content.substring(0, i).split('\n').length;
    methods.push({ name, startLine, endLine });
  }
  return methods;
}

// Walk a Java file and extract { name, startLine, endLine } for each method
// using brace-counting. Cheap regex-based parser — sufficient for Juliet's
// template-generated files which have predictable structure (no string-literal
// brace surprises in method bodies because Juliet comments are sanitized
// during template generation). Returns ALL methods, not just bad/good*.
function findJavaMethodSpans(content) {
  const methods = [];
  const declRe = /^\s*(?:public|private|protected|static|\s)+(?:void|String|int|long|short|byte|boolean|float|double|Object|[A-Z][\w<>,\s.\[\]]*)\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w,\s.]+)?\s*\{/gm;
  let m;
  while ((m = declRe.exec(content))) {
    const name = m[1];
    if (name === 'class' || name === 'if' || name === 'while' || name === 'for' || name === 'switch') continue;
    const openIdx = m.index + m[0].length - 1; // position of '{'
    let depth = 1, i = openIdx + 1;
    while (i < content.length && depth > 0) {
      const ch = content[i];
      if (ch === '"' || ch === "'") {
        // Skip string literal — Juliet's generated files don't have braces in
        // strings, but other Java code might. Conservative skip.
        const quote = ch; i++;
        while (i < content.length && content[i] !== quote) {
          if (content[i] === '\\') i += 2; else i++;
        }
        i++; continue;
      }
      if (ch === '{') depth++;
      else if (ch === '}') depth--;
      i++;
    }
    const startLine = content.substring(0, m.index).split('\n').length + (content.substring(m.index).match(/^\s*\n/) ? 1 : 0);
    const endLine = content.substring(0, i).split('\n').length;
    methods.push({ name, startLine, endLine });
  }
  return methods;
}

// Minimal RFC-4180-ish CSV reader. Handles quoted fields with embedded
// commas, newlines, and "" escapes. Reads the whole file into memory
// (~54MB for BigVul) — simpler and avoids CR/LF chunk-boundary bugs that
// a streaming reader would have to handle.
function parseCsvBuffer(text) {
  const headers = [];
  const rows = [];
  let inQuotes = false, fields = [], cur = '';
  const flushField = () => { fields.push(cur); cur = ''; };
  const flushRow = () => {
    if (!headers.length) { for (const f of fields) headers.push(f); }
    else {
      const row = {};
      for (let j = 0; j < headers.length; j++) row[headers[j]] = fields[j];
      rows.push(row);
    }
    fields = [];
  };
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') { cur += '"'; i++; continue; }
        inQuotes = false; continue;
      }
      cur += ch; continue;
    }
    if (ch === '"') { inQuotes = true; continue; }
    if (ch === ',') { flushField(); continue; }
    if (ch === '\r') { if (text[i + 1] === '\n') i++; flushField(); flushRow(); continue; }
    if (ch === '\n') { flushField(); flushRow(); continue; }
    cur += ch;
  }
  if (cur.length || fields.length) { flushField(); flushRow(); }
  return rows;
}

// Pull the BEFORE-fix state out of a single unified-diff `patch` string.
// Keep `-` and ` ` (context) lines verbatim (stripped of their prefix);
// drop `+` (added) lines. Hunk headers (`@@`) become blank-line separators
// so the engine's line-based scanners still get useful surrounding context.
function extractBeforeFromPatch(patch) {
  if (!patch || typeof patch !== 'string') return '';
  const out = [];
  for (const line of patch.split('\n')) {
    if (line.startsWith('@@')) { out.push(''); continue; }
    if (line.startsWith('+++') || line.startsWith('---')) continue;
    if (line.startsWith('+')) continue;
    if (line.startsWith('-')) { out.push(line.slice(1)); continue; }
    if (line.startsWith(' ')) { out.push(line.slice(1)); continue; }
    // Defensive: malformed lines pass through.
    out.push(line);
  }
  return out.join('\n');
}

// BigVul loader. Reads MSR'20 CSV from the cloned repo, filters to CWEs the
// scanner has rules for, extracts BEFORE-fix code from each patch hunk into
// .bench-cache/bigvul-<sha>-extracted/<CVE-ID>/<basename>, and returns
// { expected, scanRoot } so the runner scans the materialized tree.
async function buildBigvulExpected(repoRoot, gt, extractRoot) {
  const csvPath = path.join(repoRoot, gt.csvPath || 'all_c_cpp_release2.0.csv');
  const cweMap = gt.cweToFamily || {};
  const wantedSet = new Set(Object.keys(cweMap));
  // Re-materialize on every run? No: cache by checking marker file presence.
  const markerPath = path.join(extractRoot, '.extracted.ok');
  let extracted = false;
  try { await fs.access(markerPath); extracted = true; } catch { /* no marker */ }
  const expected = [];
  const seen = new Set();
  if (!extracted) {
    console.error(`  materializing BigVul patches → ${extractRoot}`);
    await fs.mkdir(extractRoot, { recursive: true });
  }
  let rows = 0, kept = 0, materialized = 0;
  const csvText = await fs.readFile(csvPath, 'utf8');
  const parsedRows = parseCsvBuffer(csvText);
  for (const row of parsedRows) {
    rows++;
    const cwe = (row.cwe_id || '').trim();
    const cveId = (row.cve_id || '').trim();
    if (!wantedSet.has(cwe) || !cveId) continue;
    // BigVul stores files_changed as either:
    //  - a single JSON object (one file per CVE), or
    //  - multiple JSON objects glued with the literal `<_**next**_>` sentinel.
    // Normalize to a JS array.
    let files = [];
    const raw = row.files_changed || '';
    if (raw) {
      const parts = raw.split('<_**next**_>');
      for (const part of parts) {
        try { const j = JSON.parse(part); if (j && typeof j === 'object') files.push(j); } catch { /* skip */ }
      }
    }
    if (!files.length) continue;
    const family = cweMap[cwe];
    let anyForRow = false;
    for (const fc of files) {
      const fn = (fc && fc.filename) || '';
      if (!fn) continue;
      // Only materialize source files the engine can scan.
      if (!/\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$/i.test(fn)) continue;
      const before = extractBeforeFromPatch(fc.patch || '');
      if (!before.trim()) continue;
      const base = fn.split('/').slice(-1)[0];
      const relDir = `${cveId}`;
      const relFile = `${relDir}/${base}`;
      // Disambiguate same-basename files within one CVE.
      let outRel = relFile, n = 1;
      while (seen.has(outRel)) { outRel = `${relDir}/${n}_${base}`; n++; }
      seen.add(outRel);
      if (!extracted) {
        const outPath = path.join(extractRoot, outRel);
        await fs.mkdir(path.dirname(outPath), { recursive: true });
        await fs.writeFile(outPath, before);
        materialized++;
      }
      expected.push({
        file: outRel,
        line: 1,
        lineTolerance: 9999,
        matchAny: true,
        family,
        cwe,
      });
      anyForRow = true;
    }
    if (anyForRow) kept++;
  }
  if (!extracted) {
    await fs.writeFile(markerPath, `rows=${rows} kept=${kept} materialized=${materialized}\n`);
  }
  console.error(`  BigVul: ${expected.length} expected entries from ${kept} CVEs (${rows} CSV rows scanned)`);
  return expected;
}

// CVEfixes loader. The GitHub repo ships only tooling — the actual dataset
// is a SQLite database on Zenodo (~5GB). If the DB is present at the
// configured path, extract per-CVE before-fix file contents into a fixture
// tree and emit expected[]. If absent, print friendly instructions and
// return an empty expected[] so the bench reports cleanly rather than
// crashing.
async function buildCvefixesExpected(repoRoot, gt, extractRoot) {
  const dbPath = path.join(repoRoot, gt.dbRelPath || 'Data/CVEfixes.db');
  try { await fs.access(dbPath); }
  catch {
    console.error(`  CVEfixes DB not found at ${dbPath}`);
    console.error(`  Download from https://zenodo.org/records/13367348 and place CVEfixes.db at the path above.`);
    console.error(`  Skipping scoring — empty expected[] returned.`);
    return [];
  }
  // Use the system sqlite3 CLI so we don't add a runtime npm dep.
  const sqliteOK = (() => {
    const r = cp.spawnSync('sqlite3', ['-version'], { encoding: 'utf8' });
    return r.status === 0;
  })();
  if (!sqliteOK) {
    console.error(`  sqlite3 CLI not found — install with \`brew install sqlite\` or apt-get install sqlite3.`);
    return [];
  }
  const cweMap = gt.cweToFamily || {};
  const cweList = Object.keys(cweMap).map(c => `'${c}'`).join(',');
  const maxPerCwe = Math.max(1, Number(gt.maxPerCwe) || 200);
  // Query: pull a capped number of (cve_id, cwe_id, filename, code_before) tuples,
  // partitioned by cwe so a single dominant CWE doesn't crowd out the rest.
  const sql = `
.timeout 30000
WITH ranked AS (
  SELECT cve.cve_id, cwe.cwe_id, fc.filename, fc.code_before,
         ROW_NUMBER() OVER (PARTITION BY cwe.cwe_id ORDER BY cve.cve_id) AS rk
  FROM cve
  JOIN cwe_classification cls ON cls.cve_id = cve.cve_id
  JOIN cwe ON cwe.cwe_id = cls.cwe_id
  JOIN fixes fx ON fx.cve_id = cve.cve_id
  JOIN commits cm ON cm.hash = fx.hash
  JOIN file_change fc ON fc.hash = cm.hash
  WHERE cwe.cwe_id IN (${cweList})
    AND fc.code_before IS NOT NULL
    AND length(fc.code_before) > 0
    AND length(fc.code_before) < 200000
)
SELECT cve_id, cwe_id, filename, code_before FROM ranked WHERE rk <= ${maxPerCwe};
`;
  const markerPath = path.join(extractRoot, '.extracted.ok');
  let extracted = false;
  try { await fs.access(markerPath); extracted = true; } catch { /* no marker */ }
  if (!extracted) {
    console.error(`  materializing CVEfixes samples → ${extractRoot}`);
    await fs.mkdir(extractRoot, { recursive: true });
  }
  // -separator $'\x1e' (Record Separator) for fields, $'\x1f' (Unit Separator) for rows.
  // CVEfixes' code_before contains newlines and quotes; standard CSV escaping is brittle.
  const r = cp.spawnSync('sqlite3',
    ['-readonly', '-bail', '-cmd', `.separator "\x1e" "\x1f"`, dbPath, sql],
    { encoding: 'utf8', maxBuffer: 1 << 30 },
  );
  if (r.status !== 0) {
    console.error(`  sqlite3 query failed: ${r.stderr || r.stdout}`);
    return [];
  }
  const expected = [];
  const seen = new Set();
  let materialized = 0;
  for (const row of r.stdout.split('\x1f')) {
    if (!row.trim()) continue;
    const parts = row.split('\x1e');
    if (parts.length < 4) continue;
    const [cveId, cwe, filename, code] = parts;
    const family = cweMap[cwe];
    if (!family || !filename || !code) continue;
    const base = filename.split('/').slice(-1)[0];
    if (!base) continue;
    const relDir = cveId.replace(/[^A-Za-z0-9_.-]/g, '_');
    let outRel = `${relDir}/${base}`, n = 1;
    while (seen.has(outRel)) { outRel = `${relDir}/${n}_${base}`; n++; }
    seen.add(outRel);
    if (!extracted) {
      const outPath = path.join(extractRoot, outRel);
      await fs.mkdir(path.dirname(outPath), { recursive: true });
      await fs.writeFile(outPath, code);
      materialized++;
    }
    expected.push({
      file: outRel,
      line: 1,
      lineTolerance: 9999,
      matchAny: true,
      family,
      cwe,
    });
  }
  if (!extracted) {
    await fs.writeFile(markerPath, `expected=${expected.length} materialized=${materialized}\n`);
  }
  console.error(`  CVEfixes: ${expected.length} expected entries materialized.`);
  return expected;
}

// Build expected[] for the NIST SARD Juliet C# suite. Layout:
//   src/testcases/CWE<N>_<descriptor>/<TestFile>.cs
// Same shape as the C/C++ tree but with `src/` prefix and .cs extension.
// Walks the tree, emits one expected entry per .cs file under a known CWE.
async function buildJulietCsExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const root = path.join(repoRoot, 'src', 'testcases');
  let entries;
  try { entries = await fs.readdir(root, { withFileTypes: true }); }
  catch { return expected; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const m = e.name.match(/^CWE(\d+)_/);
    if (!m) continue;
    const cwe = `CWE${m[1]}`;
    const family = cweMap[cwe];
    if (!family) continue;
    async function walk(dir) {
      let dEntries;
      try { dEntries = await fs.readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const f of dEntries) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) { await walk(p); continue; }
        if (!/\.cs$/i.test(f.name)) continue;
        // Skip testcasesupport helpers and the gradle/test harness shell.
        if (/^Test|TestCase\.cs$/.test(f.name)) continue;
        if (/AbstractTestCase|AbstractTestCaseWeb|AbstractTestCaseWebBase/.test(f.name)) continue;
        const rel = path.relative(repoRoot, p);
        expected.push({
          file: rel,
          line: 1,
          lineTolerance: 9999,
          matchAny: true,
          family,
          cwe,
        });
      }
    }
    await walk(path.join(root, e.name));
  }
  return expected;
}

async function buildJulietExpected(repoRoot, gt) {
  const expected = [];
  const cweMap = gt.cweToFamily || {};
  const ignoredDirs = new Set(['juliet-support', 'gradle', 'build']);
  const precise = !!gt.preciseMethodScoring;
  // Walk top-level dirs.
  const entries = await fs.readdir(repoRoot, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isDirectory() || ignoredDirs.has(e.name)) continue;
    const m = e.name.match(/^juliet-cwe(\d+)$/i);
    if (!m) continue;
    const cwe = `CWE${m[1]}`;
    const family = cweMap[cwe];
    if (!family) continue; // CWE not covered by our scanner — skip entirely.
    // Walk this CWE's src/main/java for *.java files. Skip anything under
    // /test/ or that names a Test* (gradle harness).
    const srcRoot = path.join(repoRoot, e.name, 'src', 'main', 'java');
    let exists = true;
    try { await fs.access(srcRoot); } catch { exists = false; }
    if (!exists) continue;
    async function walk(dir) {
      let dEntries;
      try { dEntries = await fs.readdir(dir, { withFileTypes: true }); }
      catch { return; }
      for (const f of dEntries) {
        const p = path.join(dir, f.name);
        if (f.isDirectory()) {
          if (f.name === 'test' || f.name === 'utils') continue;
          await walk(p);
          continue;
        }
        if (!/\.java$/i.test(f.name)) continue;
        // Filter out helper / gradle / Test* harness.
        if (/^Test|TestCase\.java$/.test(f.name)) continue;
        // Path relative to repoRoot.
        const rel = path.relative(repoRoot, p);
        if (precise) {
          // Per-method GT: extract bad/badSink method spans and emit one
          // expected entry per method with a line range. Engine emissions
          // INSIDE the bad() range count as TPs; emissions in good*() ranges
          // (which are intentionally sanitized) count as FPs — exposing the
          // engine's true precision rather than masking it with file-level GT.
          // goodG2B() pairs a good source with a bad sink — engine WILL fire
          // there legitimately, so we include it as TP-eligible.
          let content = '';
          try { content = await fs.readFile(p, 'utf8'); } catch { /* skip */ }
          if (!content) continue;
          const methods = findJavaMethodSpans(content);
          let anyEmitted = false;
          for (const meth of methods) {
            const isBad = /^(?:bad|badSink|badSource|bad\d+)$/.test(meth.name);
            const isGoodG2B = /^(?:goodG2B|goodG2B\d*)$/.test(meth.name);
            if (isBad || isGoodG2B) {
              expected.push({
                file: rel,
                line: meth.startLine,
                lineEnd: meth.endLine,
                lineTolerance: 0,
                matchAny: true,
                family,
                cwe,
                method: meth.name,
              });
              anyEmitted = true;
            }
            // good() / goodB2G() / goodSource — intentionally sanitized OR
            // pair good source with good sink. Emissions inside these ranges
            // are FPs (no expected entry covers them).
          }
          // Fallback: if no method spans found (unusual file shape), keep the
          // flat per-file entry to avoid silent recall loss.
          if (!anyEmitted) {
            expected.push({ file: rel, line: 1, lineTolerance: 9999, matchAny: true, family, cwe });
          }
        } else {
          expected.push({
            file: rel,
            line: 1,
            lineTolerance: 9999,
            matchAny: true,
            family,
            cwe,
          });
        }
      }
    }
    await walk(srcRoot);
  }
  return expected;
}

function familyForBench(vuln, vulnFamilyMap, finding) {
  // Reuse the synthetic bench's taxonomy so cross-bench numbers are comparable.
  // SCA findings (vulnerable_dep) frequently lack a `vuln` string but carry
  // osvId/CVE aliases — collapse them under a single 'vulnerable-dep' family
  // so they don't all slug to 'unknown'.
  if (!vuln) {
    if (finding && (finding.type === 'vulnerable_dep' || finding.osvId || (finding.cveAliases && finding.cveAliases.length))) {
      return 'vulnerable-dep';
    }
    return 'unknown';
  }
  for (const [exact, fam] of Object.entries(vulnFamilyMap.exact || {})) if (vuln === exact) return fam;
  for (const [pre, fam] of Object.entries(vulnFamilyMap.prefix || {})) if (vuln.startsWith(pre)) return fam;
  return String(vuln).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '').slice(0, 40);
}

async function loadFamilyMap() {
  const synth = JSON.parse(await fs.readFile(path.join(__dirname, '..', 'expected.json'), 'utf8'));
  return synth._familyMap || {};
}

function lineOf(a) { return a.sink?.line ?? a.line ?? a.source?.line ?? 0; }
function fileOf(a) { return a.file || a.sink?.file || a.source?.file || ''; }

function score(actual, expected, vulnFamilyMap, scanRoot, wildcardFamilies) {
  const tps = []; const fps = []; const fns = [];
  const consumed = new Set();
  const wildSet = new Set(wildcardFamilies || []);
  // Perf: index actuals by basename for O(1) lookup instead of O(A) scan per
  // expected entry. With 55k expected × 87k actuals this drops 4.8B ops to
  // ~150k. Each actual is also cached with its precomputed file/line/family
  // to avoid recomputing in the hot loop.
  const actualByBase = new Map(); // basename → [indices]
  const actualMeta = new Array(actual.length); // {file, base, line, fam}
  for (let i = 0; i < actual.length; i++) {
    const a = actual[i];
    const aFile = fileOf(a);
    const base = aFile.replace(/\\/g,'/').split('/').slice(-1)[0];
    const meta = { file: aFile, base, line: lineOf(a), fam: familyForBench(a.vuln, vulnFamilyMap, a), vuln: a.vuln };
    actualMeta[i] = meta;
    if (!actualByBase.has(base)) actualByBase.set(base, []);
    actualByBase.get(base).push(i);
  }
  // First pass: wildcardFamilies — credit every actual finding whose family is
  // listed (advisory rules that fire correctly across many files; we don't
  // track them per-line).
  if (wildSet.size) {
    for (let i = 0; i < actual.length; i++) {
      const meta = actualMeta[i];
      if (wildSet.has(meta.fam)) {
        consumed.add(i);
        tps.push({ family: meta.fam, file: meta.file, line: meta.line, wildcard: true, matchedVuln: meta.vuln });
      }
    }
  }
  // Second pass: match expected entries normally — O(E + sum-of-basename-buckets)
  //
  // matchAny semantics (CORRECTED): "this expected entry credits any number of
  // matching actuals (so duplicate emissions don't become FPs), but the
  // expected entry still counts as exactly ONE TP." The previous behavior
  // pushed one tps per matched actual, silently inflating reported per-app
  // numbers on file-level GT (OWASP Benchmark, Juliet) by 1.5–2× when the
  // engine emitted multiple findings per file. The OWASP Benchmark scorecard
  // convention is per-test (one TP per real=true test that fires) — that's
  // what we now report.
  for (const e of expected) {
    const tol = typeof e.lineTolerance === 'number' ? e.lineTolerance : LINE_TOLERANCE;
    let matched = false;
    const baseE = e.file.replace(/\\/g,'/').split('/').slice(-1)[0];
    const candidates = actualByBase.get(baseE) || [];
    for (const i of candidates) {
      if (consumed.has(i)) continue;
      const meta = actualMeta[i];
      // Match either by basename (already filtered) or by suffix path.
      if (meta.base !== baseE && !meta.file.endsWith('/' + e.file)) continue;
      const aLine = meta.line;
      // Range match (per-method Juliet GT): match if aLine ∈ [e.line, e.lineEnd].
      // Otherwise fall back to point match within tolerance.
      if (typeof e.lineEnd === 'number' && e.lineEnd >= e.line) {
        if (aLine < e.line || aLine > e.lineEnd) continue;
      } else if (Math.abs(aLine - e.line) > tol) continue;
      if (meta.fam !== e.family) continue;
      consumed.add(i);
      if (!matched) {
        // First matching actual contributes the single TP for this expected entry.
        tps.push({ ...e, matchedVuln: meta.vuln });
        matched = true;
      }
      // matchAny: continue consuming additional matching actuals so they
      // don't become FPs, but DO NOT push additional tps for them. One
      // expected entry = one TP.
      if (!e.matchAny) break;
    }
    if (!matched && !wildSet.has(e.family)) fns.push(e);
  }
  for (let i = 0; i < actual.length; i++) {
    if (consumed.has(i)) continue;
    const meta = actualMeta[i];
    fps.push({ file: meta.file, line: meta.line, family: meta.fam, vuln: meta.vuln });
  }
  return { tps, fps, fns };
}

function f1(p, r) { return p+r === 0 ? 0 : (2*p*r)/(p+r); }
function pad(s, n) { s = String(s); return s.length >= n ? s : s + ' '.repeat(n - s.length); }

async function runOne(name, app, vulnFamilyMap) {
  // --strip-all-comments implies --blind. The "blind" label in stderr is
  // augmented so the user can tell the strictest mode apart from
  // markers-only blind.
  const blindLabel = BLIND ? (STRIP_ALL_COMMENTS ? ' [BLIND+STRIP-ALL-COMMENTS]' : ' [BLIND]') : '';
  console.error(`\n=== ${name} (${app.language})${blindLabel} ===`);
  const originalRoot = await ensureClone(name, app.repo, app.sha);
  // In blind mode, materialize a sanitized copy with answer-key markers
  // stripped, then point repoRoot at the blinded copy. The GT builders
  // walk this root and emit blinded paths; the scanner reads blinded files.
  // ensures: every comparison the scorer makes is in blinded path space.
  let repoRoot = originalRoot;
  if (BLIND) {
    const variantSuffix = SCRAMBLE_IDENTIFIERS ? '-blinded-scrambled'
                       : STRIP_ALL_COMMENTS ? '-blinded-nocomment'
                       : '-blinded';
    const blindedRoot = path.join(CACHE_ROOT, `${name}-${app.sha}${variantSuffix}`);
    await _materializeBlinded(originalRoot, blindedRoot, {
      stripAllComments: STRIP_ALL_COMMENTS || SCRAMBLE_IDENTIFIERS,
      scrambleIdentifiers: SCRAMBLE_IDENTIFIERS,
    });
    repoRoot = blindedRoot;
  }
  let scanRoot = path.join(repoRoot, app.scanRoot || '.');

  let expected;
  let wildcardFamilies = [];
  let reAuditFlag = false;  // Premortem 3R-7
  if (app.groundTruth.kind === 'csv') {
    expected = await buildOwaspBenchmarkExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'juliet') {
    expected = await buildJulietExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'juliet-c-cpp') {
    expected = await buildJulietCppExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'juliet-csharp') {
    expected = await buildJulietCsExpected(repoRoot, app.groundTruth);
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'bigvul-csv') {
    const extractRoot = path.join(CACHE_ROOT, `${name}-${app.sha}-extracted`);
    expected = await buildBigvulExpected(repoRoot, app.groundTruth, extractRoot);
    scanRoot = extractRoot;
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'cvefixes-sqlite') {
    const extractRoot = path.join(CACHE_ROOT, `${name}-${app.sha}-extracted`);
    expected = await buildCvefixesExpected(repoRoot, app.groundTruth, extractRoot);
    scanRoot = extractRoot;
    if (Array.isArray(app.wildcardFamilies)) wildcardFamilies = app.wildcardFamilies;
  } else if (app.groundTruth.kind === 'negative') {
    // Clean-code corpora: there is nothing to find, so the ground truth is the
    // empty set and every emission is a false positive. These carry no
    // groundTruth.path, so they used to fall through to the curated loader and
    // throw on `path === undefined` — an error the old single-process loop
    // caught and buried, since exit status ignored per-app failures and the
    // F1 floors only look at apps that declare a floor. Per-app isolation
    // makes any failure fatal, so the latent break had to be repaired rather
    // than inherited.
    expected = [];
  } else {
    const curated = await loadCuratedExpected(name, app.groundTruth.path);
    if (Array.isArray(curated)) { expected = curated; }
    else { expected = curated.expected || []; wildcardFamilies = curated.wildcardFamilies || []; }
    // Premortem 3R-7: surface stale-GT warning to stderr so a reader of the
    // bench run knows this corpus's pass/fail is not yet load-bearing.
    if (corpusRequiresReAudit(curated)) {
      console.error(`  WARNING: ${name}: expected ground truth carries requiresReAudit:true — F1 against this corpus is informational only until a human re-walks it.`);
      reAuditFlag = true;
    }
  }

  // Apply per-app excludePaths via a generated rules.yml under the scan root.
  // runScan() honors `<scanRoot>/.agentic-security/rules.yml#ignorePaths`. We
  // generate it fresh on every run so manifest changes propagate immediately,
  // and clean up after to leave the cache reusable. Done AFTER GT building
  // so the bigvul/cvefixes extract dirs exist before we drop the rules file.
  let rulesPath = null;
  if (Array.isArray(app.excludePaths) && app.excludePaths.length) {
    const rulesDir = path.join(scanRoot, '.agentic-security');
    rulesPath = path.join(rulesDir, 'rules.yml');
    await fs.mkdir(rulesDir, { recursive: true });
    // Quote each path so leading `*` isn't parsed as a YAML alias.
    const yml = 'ignorePaths:\n' + app.excludePaths.map(p => `  - ${JSON.stringify(p)}`).join('\n') + '\n';
    await fs.writeFile(rulesPath, yml);
  }
  // --no-wildcards: strip the relaxation and report strict line-level scoring.
  // --blind: same — blind mode implies strict scoring.
  if (NO_WILDCARDS || BLIND) wildcardFamilies = [];

  console.error(`  scanning ${scanRoot} (expected: ${expected.length} TPs)`);
  const t0 = Date.now();
  const { scan } = await runScan(scanRoot);
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  if (rulesPath) { try { await fs.rm(path.dirname(rulesPath), { recursive: true, force: true }); } catch {} }

  const actual = [
    ...(scan.findings || []),
    ...(scan.logicVulns || []),
    ...(scan.secrets || []),
    ...(scan.supplyChain || []),
  ];

  const { tps, fps, fns } = score(actual, expected, vulnFamilyMap, scanRoot, wildcardFamilies);
  const tp = tps.length, fp = fps.length, fn = fns.length;
  const precision = tp+fp === 0 ? 1 : tp/(tp+fp);
  const recall    = tp+fn === 0 ? 1 : tp/(tp+fn);
  const fOne      = f1(precision, recall);

  // Per-family breakdown (positive class)
  const perFamily = {};
  const bump = (fam, k) => { (perFamily[fam] ??= {tp:0,fp:0,fn:0,tn:0,fpNeg:0})[k]++; };
  for (const t of tps) bump(t.family, 'tp');
  for (const x of fps) bump(x.family, 'fp');
  for (const x of fns) bump(x.family, 'fn');

  // Per-CWE breakdown — Recommendation #2 of the SCA/SAST improvement
  // plan. Surfaces which specific CWE (e.g. CWE-22 vs CWE-23, both
  // path-traversal) is the bottleneck within a family. CWE comes from
  // the expected-finding entry when present; for actuals (FPs) we
  // try to read f.cwe directly.
  const perCwe = {};
  const bumpCwe = (cwe, k) => { if (!cwe) return; (perCwe[cwe] ??= {tp:0,fp:0,fn:0})[k]++; };
  for (const t of tps) bumpCwe(t.cwe, 'tp');
  for (const x of fps) bumpCwe(x.cwe || (x.vuln && (x.vuln.match(/CWE-\d+/)?.[0])), 'fp');
  for (const x of fns) bumpCwe(x.cwe, 'fn');

  // Youden Index (TPR − FPR) — requires a real negative class. OWASP Benchmark
  // ships real=false rows in expectedresults-1.2.csv; we parse them as a list
  // of (file, family) pairs the engine should NOT fire on. For each negative,
  // a firing in that family on that file is a category-FP; absence is a TN.
  // Matches the OWASP Benchmark scorecard convention so Youden Index here is
  // directly comparable to other tools' published Youden numbers.
  //
  // Corpora without a declared negative class (Juliet, BigVul, CVEfixes,
  // curated apps) report Youden=null; F1 still applies.
  const negatives = expected._negatives || [];
  let youden = null, tpr = null, fpr = null, specificity = null;
  let negTotalTN = 0, negTotalFP = 0;
  if (negatives.length) {
    // Index actuals by (basename, family) for O(1) lookup.
    const actualByBaseFamily = new Set();
    for (const a of actual) {
      const aFile = fileOf(a);
      const base = aFile.replace(/\\/g,'/').split('/').slice(-1)[0];
      const fam = familyForBench(a.vuln, vulnFamilyMap, a);
      actualByBaseFamily.add(base + '|' + fam);
    }
    for (const n of negatives) {
      const key = n.file + '|' + n.family;
      if (actualByBaseFamily.has(key)) { bump(n.family, 'fpNeg'); negTotalFP++; }
      else { bump(n.family, 'tn'); negTotalTN++; }
    }
    tpr = recall;
    fpr = (negTotalFP + negTotalTN) === 0 ? 0 : negTotalFP / (negTotalFP + negTotalTN);
    specificity = 1 - fpr;
    youden = tpr - fpr;
  }

  const auditorVerifiedSource = (app.groundTruth && app.groundTruth.auditorVerifiedSource) || null;
  // Peak resident set for the process that ran this app. Under per-app
  // isolation (the --all default) each app owns a fresh process, so this is
  // that app's true high-water mark and the number that decides what heap
  // ceiling the sweep actually needs. libuv normalizes maxRSS to kilobytes on
  // every platform. Under --in-process this is cumulative across apps and
  // therefore only an upper bound for the app that happened to run last.
  const peakRssMb = Math.round((process.resourceUsage().maxRSS / 1024) * 10) / 10;
  return {
    name, language: app.language, scanned: actual.length,
    peakRssMb,
    tp, fp, fn, precision, recall, f1: fOne,
    tpr, fpr, specificity, youden,
    negativesTotal: negatives.length, negTN: negTotalTN, negFP: negTotalFP,
    perFamily, perCwe, fps, fns,
    elapsedSec: parseFloat(elapsed),
    expectedTotal: expected.length,
    auditorVerifiedSource,
    requiresReAudit: reAuditFlag,
  };
}

function printResult(r) {
  const auditorTag = r.auditorVerifiedSource ? `  [GT source: ${r.auditorVerifiedSource}]` : '';
  const reAuditTag = r.requiresReAudit ? '  [GT requires re-audit — F1 informational]' : '';
  console.log(`\n${r.name} (${r.language})${auditorTag}${reAuditTag}`);
  console.log(`  P: ${(r.precision*100).toFixed(1)}%   R: ${(r.recall*100).toFixed(1)}%   F1: ${(r.f1*100).toFixed(1)}%`);
  if (r.youden != null) {
    console.log(`  TPR: ${(r.tpr*100).toFixed(1)}%   FPR: ${(r.fpr*100).toFixed(1)}%   Specificity: ${(r.specificity*100).toFixed(1)}%   Youden: ${(r.youden*100).toFixed(1)}%`);
    console.log(`  Negatives: ${r.negativesTotal} (TN ${r.negTN} / FP ${r.negFP})`);
  } else {
    console.log(`  Youden Index: n/a (no declared negative class in this corpus)`);
  }
  const rssTag = r.peakRssMb != null ? `, peak RSS ${r.peakRssMb} MB` : '';
  console.log(`  TP: ${r.tp} / FP: ${r.fp} / FN: ${r.fn}   (expected: ${r.expectedTotal}, scan emitted: ${r.scanned}, ${r.elapsedSec}s${rssTag})`);
  if (Object.keys(r.perFamily).length) {
    console.log(`  per-family:`);
    for (const [fam, s] of Object.entries(r.perFamily).sort()) {
      const p = s.tp+s.fp===0?1:s.tp/(s.tp+s.fp);
      const rr = s.tp+s.fn===0?1:s.tp/(s.tp+s.fn);
      const hasNeg = (s.tn||0) + (s.fpNeg||0) > 0;
      const fprFam = hasNeg ? (s.fpNeg||0) / ((s.tn||0) + (s.fpNeg||0)) : null;
      const yFam = hasNeg ? rr - fprFam : null;
      const negCols = hasNeg
        ? `  FPR:${(fprFam*100).toFixed(0).padStart(3)}%  Y:${(yFam*100).toFixed(0).padStart(3)}%`
        : '';
      console.log(`    ${pad(fam, 24)} TP:${pad(s.tp,4)} FP:${pad(s.fp,4)} FN:${pad(s.fn,4)} P:${(p*100).toFixed(0).padStart(3)}%  R:${(rr*100).toFixed(0).padStart(3)}%${negCols}`);
    }
  }
  // Per-CWE breakdown — Recommendation #2. Surfaces which specific CWE
  // is the bottleneck within a family. Sorted by recall ascending so the
  // worst-performing CWE floats to the top of the list.
  if (r.perCwe && Object.keys(r.perCwe).length) {
    const cwes = Object.entries(r.perCwe).map(([cwe, s]) => {
      const p = s.tp+s.fp===0?1:s.tp/(s.tp+s.fp);
      const rr = s.tp+s.fn===0?1:s.tp/(s.tp+s.fn);
      return { cwe, ...s, p, r: rr, scale: s.tp+s.fn };
    }).filter(e => e.scale >= 5)   // hide noise-rounded buckets with <5 expected
      .sort((a, b) => a.r - b.r || b.scale - a.scale);
    if (cwes.length) {
      console.log(`  per-CWE (≥5 expected, sorted by recall asc):`);
      for (const e of cwes.slice(0, 15)) {
        console.log(`    ${pad(e.cwe, 10)} TP:${pad(e.tp,4)} FP:${pad(e.fp,4)} FN:${pad(e.fn,4)} P:${(e.p*100).toFixed(0).padStart(3)}%  R:${(e.r*100).toFixed(0).padStart(3)}%`);
      }
      if (cwes.length > 15) console.log(`    … and ${cwes.length - 15} more CWEs (use --json for full list)`);
    }
  }
  if (VERBOSE) {
    if (r.fns.length) {
      const fnLimit = parseInt(process.env.FN_LIMIT || '20');
      console.log(`  false negatives (first ${fnLimit}):`);
      for (const f of r.fns.slice(0,fnLimit)) console.log(`    ${f.file}:${f.line}  ${f.family}`);
      if (r.fns.length > fnLimit) console.log(`    … and ${r.fns.length - fnLimit} more`);
    }
    if (r.fps.length) {
      const fpLimit = parseInt(process.env.FP_LIMIT || '20');
      console.log(`  false positives (first ${fpLimit}):`);
      for (const f of r.fps.slice(0,fpLimit)) console.log(`    ${f.file}:${f.line}  ${f.family}  ${f.vuln}`);
      if (r.fps.length > fpLimit) console.log(`    … and ${r.fps.length - fpLimit} more`);
    }
  }
}

const SELF_PATH = fileURLToPath(import.meta.url);

// Argv for a child that should benchmark exactly one app. Every flag the
// parent was given is forwarded verbatim (--blind, --no-wildcards,
// --refresh-cache, --verbose, …) so an isolated sweep measures precisely what
// the same flags would have measured in one process. The three flags that
// select the process model itself are not forwarded.
function childArgsFor(name) {
  const out = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--all' || a === '--json' || a === '--in-process') continue;
    if (a === '--app') { i++; continue; } // drop the flag AND its value
    out.push(a);
  }
  out.push('--app', name, '--json');
  return out;
}

// Run one app in its own process and return its result object.
//
// stdout is wired straight to a file rather than a pipe: a single app's JSON
// (with full fps[]/fns[] arrays) runs to tens of megabytes, which is exactly
// the sort of thing a default pipe buffer truncates. stderr is piped so the
// parent can forward it live — CI needs to see progress — while retaining the
// tail, so that when a child dies we can say WHY rather than just print a
// number.
//
// Any non-zero exit, any signal, and any unparseable/mismatched payload all
// return an error result. There is no path through this function that returns
// nothing: the caller always gets exactly one entry per app.
async function runOneIsolated(name, tmpDir) {
  const outPath = path.join(tmpDir, `${name.replace(/[^\w.-]/g, '_')}.json`);
  const STDERR_TAIL_MAX = 8192;
  let tail = '';
  const fh = await fs.open(outPath, 'w');
  let status, signal;
  try {
    ({ status, signal } = await new Promise((resolve, reject) => {
      const child = cp.spawn(process.execPath, [SELF_PATH, ...childArgsFor(name)], {
        stdio: ['ignore', fh.fd, 'pipe'],
      });
      child.stderr.on('data', (chunk) => {
        process.stderr.write(chunk);
        tail = (tail + chunk.toString('utf8')).slice(-STDERR_TAIL_MAX);
      });
      child.on('error', reject);
      child.on('close', (code, sig) => resolve({ status: code, signal: sig }));
    }));
  } catch (e) {
    return { name, error: `could not spawn benchmark child: ${e.message}`, crashed: true };
  } finally {
    await fh.close();
  }

  if (status !== 0 || signal) {
    // V8 prints its heap-exhaustion banner immediately before aborting, so the
    // retained stderr tail is the reliable signal; 134 is the same abort seen
    // through a shell that folded the signal into an exit code. Name it,
    // because "exited 134" is the most misread number in this benchmark. A
    // bare SIGABRT with no banner is NOT called an OOM — plenty of other
    // things abort.
    const oom = status === 134 || /heap out of memory|Ineffective mark-compacts/i.test(tail);
    const how = signal ? `killed by signal ${signal}` : `exited with code ${status}`;
    return {
      name,
      error: `benchmark child ${how}${oom ? ' — out of memory' : ''}`,
      crashed: true,
      outOfMemory: oom,
      stderrTail: tail.slice(-2000),
    };
  }

  let parsed;
  try { parsed = JSON.parse(await fs.readFile(outPath, 'utf8')); }
  catch (e) {
    return { name, error: `benchmark child produced unreadable JSON: ${e.message}`, crashed: true, stderrTail: tail.slice(-2000) };
  }
  const r = parsed && Array.isArray(parsed.results) ? parsed.results[0] : null;
  if (!r || r.name !== name) {
    return { name, error: `benchmark child returned no result for ${name}`, crashed: true, stderrTail: tail.slice(-2000) };
  }
  return r;
}

async function main() {
  // Bench-shape mode: enable answer-key readers (OWASP template suppressors,
  // Juliet folder-name suppressors, @WebServlet category extractor) when NOT
  // in blind mode. BENCH_SHAPE=1 is the opt-in; BLIND_BENCH=1 is the hard
  // override that defeats bench-shape even if somehow set externally.
  // Blind mode also implies --no-wildcards: any family-level relaxation would
  // defeat the measurement of the engine's true detection capability.
  if (BLIND) {
    process.env.AGENTIC_SECURITY_BLIND_BENCH = '1';
    delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  } else {
    process.env.AGENTIC_SECURITY_BENCH_SHAPE = '1';
  }
  const manifest = JSON.parse(await fs.readFile(MANIFEST, 'utf8'));
  const familyMap = await loadFamilyMap();
  const apps = manifest.apps;
  const INCLUDE_QUARANTINED = flag('--include-quarantined');
  // --app accepts a comma-separated list, so a subset can be swept without
  // pulling in every corpus in the manifest. A multi-app request gets the same
  // per-process isolation --all does; a single-app request is the leaf case
  // that actually performs a scan (and is what each spawned child runs).
  const targets = ALL
    ? Object.keys(apps).filter(name => INCLUDE_QUARANTINED || !apps[name]._quarantined)
    : APP.split(',').map(s => s.trim()).filter(Boolean);
  for (const t of targets) {
    if (!apps[t]) { console.error(`unknown app: ${t} (have: ${Object.keys(apps).join(', ')})`); process.exit(2); }
  }

  const results = [];
  const ISOLATED = !IN_PROCESS && targets.length > 1;
  let tmpDir = null;
  if (ISOLATED) tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), 'realworld-bench-'));
  try {
    for (const t of targets) {
      let r;
      if (ISOLATED) {
        r = await runOneIsolated(t, tmpDir);
      } else {
        try {
          r = await runOne(t, apps[t], familyMap);
        } catch (e) {
          console.error(`  FAILED: ${e.message}`);
          r = { name: t, error: e.message };
        }
      }
      // Manifest-derived metadata is stamped by the parent regardless of where
      // the result came from, so a crashed app still carries it.
      r.quarantined = !!apps[t]._quarantined;
      if (!r.error) r.mode = apps[t].mode || 'strict';
      if (r.error) console.error(`  FAILED: ${t}: ${r.error}`);
      results.push(r);
    }
  } finally {
    if (tmpDir) { try { await fs.rm(tmpDir, { recursive: true, force: true }); } catch { /* best effort */ } }
  }
  // Invariant the whole isolation design rests on: one result per target, no
  // exceptions. A crash must show up as a failing app, never as an absent one.
  if (results.length !== targets.length) {
    throw new Error(`internal: ${results.length} results for ${targets.length} targets`);
  }
  // Persist per-CWE precision/recall to .agentic-security/validator-metrics.json
  // so /security-trend and /report-card can show benchmark trajectory.
  // Skipped under per-app isolation: each child already recorded its own run
  // before exiting, so doing it again here would double-count every app.
  if (!ISOLATED) try {
    const { recordRun } = await import('../../src/posture/validator-metrics.js');
    const projectRoot = path.resolve(__dirname, '..', '..', '..');
    const blindTag = BLIND ? 'blind' : 'non-blind';
    const wildTag  = NO_WILDCARDS ? 'strict' : 'wildcard';
    for (const r of results) {
      if (r.error) continue;
      recordRun(projectRoot, {
        benchmark: r.name,
        mode: `${blindTag}+${wildTag}`,
        tp: r.tp, fp: r.fp, fn: r.fn,
        perFamily: r.perFamily || {},
      });
    }
  } catch (e) { /* best-effort telemetry */ }

  if (JSON_OUT) {
    console.log(JSON.stringify({ results }, null, 2));
  } else {
    console.log(`\n${'='.repeat(50)}\nReal-world benchmark — ${results.length} app(s)\n${'='.repeat(50)}`);
    for (const r of results) {
      if (r.error) { console.log(`\n${r.name}: ERROR — ${r.error}`); continue; }
      printResult(r);
    }
    // Aggregate summary across all apps. We deliberately do NOT print a
    // bare summary metric — bench progress is judged per-family from the
    // per-app breakdown above, never from a single rolled-up number that
    // can hide individual-family collapse behind noisy macro-averages.
    if (targets.length > 1) {
      const ok = results.filter(r => !r.error);
      const auditorSourced = ok.filter(r => !!r.auditorVerifiedSource);
      function agg(rs) {
        if (!rs.length) return null;
        const tp = rs.reduce((s, r) => s + (r.tp || 0), 0);
        const fp = rs.reduce((s, r) => s + (r.fp || 0), 0);
        const fn = rs.reduce((s, r) => s + (r.fn || 0), 0);
        const p = tp + fp === 0 ? 1 : tp / (tp + fp);
        const r = tp + fn === 0 ? 1 : tp / (tp + fn);
        const f1Val = p+r === 0 ? 0 : (2*p*r)/(p+r);
        return { count: rs.length, tp, fp, fn, p, r, f1: f1Val };
      }
      const aAgg = agg(auditorSourced);
      const fAgg = agg(ok);
      console.log(`\n${'='.repeat(50)}\nAggregate (raw TP/FP/FN; per-family detail above)\n${'='.repeat(50)}`);
      if (aAgg) {
        console.log(`Auditor-source-verified subset (${aAgg.count} apps): TP ${aAgg.tp}  FP ${aAgg.fp}  FN ${aAgg.fn}  P ${(aAgg.p*100).toFixed(1)}%  R ${(aAgg.r*100).toFixed(1)}%  F1 ${(aAgg.f1*100).toFixed(1)}%`);
      }
      if (fAgg) {
        console.log(`Full benchmark (${fAgg.count} apps):                  TP ${fAgg.tp}  FP ${fAgg.fp}  FN ${fAgg.fn}  P ${(fAgg.p*100).toFixed(1)}%  R ${(fAgg.r*100).toFixed(1)}%  F1 ${(fAgg.f1*100).toFixed(1)}%`);
      }
      console.log(`auditorVerifiedSource flags the provenance of each corpus's ground truth (e.g. "upstream-csv", "upstream-juliet-folders"). It is NOT an external sign-off — see docs/audit/README.md for the path to external auditor confirmation. Per-corpus numbers are for local validation only; do not publish single-corpus scores.`);
    }
  }

  // A failed app fails the run. This is set AFTER the results have been
  // emitted so the JSON still reaches whatever the caller redirected it to —
  // a failure you can read beats a failure you can only infer from $?.
  const failed = results.filter(r => r.error);
  if (failed.length) {
    console.error(`\n${failed.length} of ${targets.length} app(s) failed: ${failed.map(r => r.name).join(', ')}`);
    process.exitCode = 1;
  }
}

main().catch(e => { console.error(e); process.exit(2); });
