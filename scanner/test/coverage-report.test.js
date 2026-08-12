import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import {
  langOfFile,
  computeAnalysisTiers,
  countUnmodeledSinkCandidates,
  summarizeCoverage,
  IR_TAINT_LANGS,
} from '../src/posture/coverage-report.js';
import { runScan } from '../src/runScan.js';

test('langOfFile maps extensions to languages', () => {
  assert.equal(langOfFile('a/b.ts'), 'ts');
  assert.equal(langOfFile('main.rs'), 'rs');
  assert.equal(langOfFile('C.sol'), 'sol');
  assert.equal(langOfFile('x.unknownext'), null);
});

test('computeAnalysisTiers splits IR-taint vs pattern-only languages', () => {
  const t = computeAnalysisTiers(['a.js', 'b.js', 'c.py', 'd.rs', 'e.sol']);
  assert.deepEqual(t.irTaint, { js: 2, py: 1 });
  assert.deepEqual(t.patternOnly, { rs: 1, sol: 1 });
  // Sanity: the IR set is the source of truth for the split.
  assert.ok(IR_TAINT_LANGS.has('go') && !IR_TAINT_LANGS.has('rs'));
});

test('countUnmodeledSinkCandidates flags danger tokens with no finding on the line', () => {
  const fc = {
    'a.js': "const x = 1;\neval(userInput);\nchild_process.execSync(cmd);\n",
  };
  // Line 2 (eval) is already covered by a finding → not a candidate.
  const findings = [{ file: 'a.js', line: 2 }];
  const r = countUnmodeledSinkCandidates(fc, findings);
  // eval(line2) covered; execSync(line3) uncovered → 1 candidate.
  assert.equal(r.count, 1);
  assert.equal(r.examples[0].line, 3);
  assert.match(r.examples[0].token, /child_process/);
});

test('countUnmodeledSinkCandidates caps examples but keeps the full count', () => {
  const lines = Array.from({ length: 30 }, () => 'eval(x)').join('\n');
  const r = countUnmodeledSinkCandidates({ 'f.js': lines }, [], { cap: 5 });
  assert.equal(r.count, 30);
  assert.equal(r.examples.length, 5);
});

test('summarizeCoverage surfaces pattern-only languages and skips', () => {
  const meta = {
    filesScanned: 10, filesSkipped: 1, filesDenseSkipped: 2, filesTimedOut: 0,
    analysisTier: computeAnalysisTiers(['a.js', 'b.rs']),
    unmodeledSinkCandidates: { count: 3, examples: [] },
  };
  const s = summarizeCoverage(meta);
  assert.match(s, /skipped=3/);            // 1 + 2
  assert.match(s, /ir-taint=\[js\]/);
  assert.match(s, /pattern-only=\[rs\]/);
  assert.match(s, /unmodeled-sink-candidates=3/);
});

// S7 (Stage 2 measurement-completeness audit): scan._scanMeta.filesScanned
// used to be `files.length` — the CANDIDATE list before the per-file loop's
// size/density skip checks run — not the count of files actually analyzed
// (Object.keys(fc), the same set computeAnalysisTiers reads one line above
// in engine.js). A skipped file was counted in BOTH filesScanned and
// filesSkipped, so "scanned=N skipped=M" implied N+M files were seen when
// only N-of-those-candidates were actually analyzed.
test('_scanMeta.filesScanned excludes files skipped for size, matching the files actually analyzed', async () => {
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'agsec-coverage-'));
  try {
    await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"coverage-test"}');
    await fsp.writeFile(path.join(dir, 'normal.js'), 'const x = eval(require("fs").readFileSync(0));\n');
    // Engine skips any file over 10KB whose average line length exceeds 400
    // chars (engine.js's per-file loop, _filesDenseSkipped++) — a minified-
    // bundle heuristic. One very long line comfortably clears both bars.
    await fsp.writeFile(path.join(dir, 'dense.js'), 'const x = 1;' + 'a'.repeat(15_000) + ';\n');
    const { scan } = await runScan(dir, { network: false });
    assert.ok(scan._scanMeta.filesDenseSkipped >= 1, `expected the dense file to be skipped, got: ${JSON.stringify(scan._scanMeta)}`);
    assert.equal(scan._scanMeta.filesScanned, Object.keys(scan.fc || {}).length,
      'filesScanned must equal the number of files actually analyzed (fc), not the pre-skip candidate count');
  } finally { await fsp.rm(dir, { recursive: true, force: true }); }
});
