// Independent-label isolation guard (assurance-hardening PRD FR-903).
//
// "Keep independent labels isolated from detector development | Detection
// code and prompts cannot access labels or expected-answer files during
// scan execution." Same spirit as artifact-registry-completeness.test.js
// and egress-policy-completeness.test.js: an isolation property nobody is
// forced to keep current is a snapshot, not a control.
//
// Survey (D-0014 method) found this codebase's architecture already keeps
// this property TRUE by construction — scanner/src/'s actual scan/detection
// path (engine.js, dataflow/, discovery/'s LLM prompts, every sast/*
// detector) never reads a labels/expected-answer FILE. The one place
// source-embedded answer-key MARKERS are read at all is sast/bench-shape/
// (and its co-located Java/C++ bench-extras siblings) — a documented,
// already-tested, opt-in-only, blind-mode-stripped exception for a
// DIFFERENT thing (marker comments injected by NIST SARD / OWASP Benchmark
// / Juliet INTO their own test files), not a separate labels FILE this
// requirement is about. See java-bench-shape-opt-in.test.js and
// juliet-path-filter-gate.test.js for that mechanism's own direct-execution
// proof (off by default, works under explicit opt-in).
//
// This file adds the structural guard so that fact stays true: it scans
// scanner/src/ for a reference to any known label / expected-answer
// artifact and fails if a NEW, unreviewed one appears — the same shape a
// future detector or LLM-prompt-building module could introduce by reading
// bench/cve-replay/corpus-baseline.json (the CVE-replay ground truth),
// bench/independent/RESULT.json (the independent-population labels), or a
// calibration holdout label set, to "know the answer" for a scan it is
// about to run.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(HERE, '..', 'src');

// Basenames / path fragments that name a labels or expected-answer
// artifact. Deliberately narrow and literal (not "answer" or "label" as
// bare words, which would false-positive on ordinary prose throughout this
// codebase) — each one is a real, specific file this repo's benchmarking
// infrastructure uses to carry ground truth.
const LABEL_ARTIFACT_PATTERNS = [
  'corpus-baseline.json',   // bench/cve-replay's ground truth (pre:TP post:TN per entry)
  'RESULT.json',            // bench/independent's scored labels
  'calibration-holdout',    // bench/calibration-holdout/labels.jsonl
  'labels.jsonl',           // the generic held-out label format holdout-eval.js reads
];

// Each entry is a real, reviewed exception with the reason it is safe —
// adding a name here is a reviewable decision, not a way to silence this
// guard. Both were confirmed, by direct inspection, to reference the
// filename ONLY as a string-literal LABEL in reporting output (a `source:`
// field value, a human-facing follow-up instruction) — never as an
// argument to a file-read call, and never consulted by anything that
// influences what a detector finds or how an LLM prompt is built.
const EXCLUDED_FILES = new Map([
  ['posture/accuracy-scorecard.js', 'reporting-only: cites bench/cve-replay/corpus-baseline.json and bench/independent/RESULT.json as `source:` label strings describing where COMMITTED data (already read by the impure driver script, scripts/scorecard.mjs, and handed in as a function parameter) came from — never reads either file itself, never used to derive a rate'],
  ['posture/corpus-enroll.js', 'prose only: names corpus-baseline.json inside a human-facing follow-up instruction string ("run `npm run bench:cve-replay:update-baseline` and commit the regenerated corpus-baseline.json") — not a read'],
]);

function walk(dir, out = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, out);
    else if (entry.name.endsWith('.js')) out.push(full);
  }
  return out;
}

test('FR-903: no detection code outside the reviewed exceptions references a labels/expected-answer artifact', () => {
  const files = walk(SRC);
  const offenders = [];
  for (const abs of files) {
    const rel = path.relative(SRC, abs).split(path.sep).join('/');
    if (EXCLUDED_FILES.has(rel)) continue;
    const text = fs.readFileSync(abs, 'utf8');
    for (const pattern of LABEL_ARTIFACT_PATTERNS) {
      if (text.includes(pattern)) offenders.push(`${rel}: references "${pattern}"`);
    }
  }
  assert.deepEqual(offenders, [],
    `detection code referencing a labels/expected-answer artifact outside the reviewed EXCLUDED_FILES list:\n${offenders.join('\n')}`);
});

test('FR-903 sanity: the scan actually walked a non-trivial number of files (the pattern list is not silently matching nothing)', () => {
  const files = walk(SRC);
  assert.ok(files.length > 200, `expected src/ to contain well over 200 .js files, found ${files.length} — the walk may be broken`);
});

test('FR-903 sanity: each reviewed exception genuinely matches at least one pattern (a stale, no-longer-matching entry should be removed, not left silently unused)', () => {
  for (const [rel] of EXCLUDED_FILES) {
    const abs = path.join(SRC, rel);
    const text = fs.readFileSync(abs, 'utf8');
    const matches = LABEL_ARTIFACT_PATTERNS.filter((p) => text.includes(p));
    assert.ok(matches.length > 0, `${rel} is listed as a reviewed exception but no longer matches any LABEL_ARTIFACT_PATTERNS entry — remove it from EXCLUDED_FILES`);
  }
});

// ── The known, gated, DIFFERENT exception: source-embedded answer-key
//    markers (bench-shape). Direct-execution proof this is off by default
//    and does not leak into an ordinary scan — the java-bench-shape-opt-in
//    and juliet-path-filter-gate suites already cover the mechanism's own
//    on/off behavior in depth; this is the narrower, FR-903-specific claim:
//    a project with NO opt-in set gets zero bench-shape-derived findings
//    even when its source happens to contain a marker-shaped comment. ──

test('FR-903: bench-shape (source-embedded marker) code paths are OFF by default — a marker-shaped comment does not affect an ordinary scan', async () => {
  const os = await import('node:os');
  const { runScan } = await import('../src/runScan.js');
  delete process.env.AGENTIC_SECURITY_BENCH_SHAPE;
  delete process.env.AGENTIC_SECURITY_BLIND_BENCH;
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-label-isolation-'));
  try {
    fs.writeFileSync(path.join(dir, 'App.java'), [
      '@WebServlet("/sqli-00/BenchmarkTest00001")',
      'public class BenchmarkTest00001 {',
      '  public void doIt(String s) {',
      '    /* POTENTIAL FLAW: this line intentionally does something dangerous */',
      '    System.out.println(s);',
      '  }',
      '}',
    ].join('\n'));
    const { scan } = await runScan(dir);
    // The bare presence of OWASP/SARD-shaped marker comments must not, on
    // its own, produce a finding attributable to answer-key leakage — real
    // findings from this fixture (if any) would come from genuine pattern
    // detection on the code itself, not from reading the marker/category.
    const answerKeyDerived = (scan.findings || []).filter((f) => /sqli-00|BenchmarkTest00001 category/i.test(f.description || ''));
    assert.equal(answerKeyDerived.length, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
