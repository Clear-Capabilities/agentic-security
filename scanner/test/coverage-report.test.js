import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  langOfFile,
  computeAnalysisTiers,
  countUnmodeledSinkCandidates,
  summarizeCoverage,
  IR_TAINT_LANGS,
} from '../src/posture/coverage-report.js';

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
