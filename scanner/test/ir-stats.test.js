// Tests for the IR-stats instrumentation (proof-corpus Phase 0).

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  languageOfFile,
  collectIrStats,
  irStatsTarget,
  writeIrStats,
} from '../src/ir/ir-stats.js';

test('languageOfFile: maps the dispatched extensions', () => {
  assert.equal(languageOfFile('a/b.js'), 'javascript');
  assert.equal(languageOfFile('a/b.tsx'), 'javascript');
  assert.equal(languageOfFile('a/b.mjs'), 'javascript');
  assert.equal(languageOfFile('a/b.py'), 'python');
  assert.equal(languageOfFile('a/b.java'), 'java');
  assert.equal(languageOfFile('a/b.cs'), 'csharp');
  assert.equal(languageOfFile('a/b.kt'), 'kotlin');
  assert.equal(languageOfFile('a/b.go'), 'go');
  assert.equal(languageOfFile('a/b.php'), 'php');
  assert.equal(languageOfFile('a/b.phtml'), 'php');
  assert.equal(languageOfFile('a/b.rb'), 'ruby');
});

test('languageOfFile: C/C++ is in the map so the pre-parser baseline is measurable', () => {
  assert.equal(languageOfFile('a/b.cpp'), 'cpp');
  assert.equal(languageOfFile('a/b.h'), 'cpp');
  assert.equal(languageOfFile('a/b.c'), 'cpp');
});

test('languageOfFile: unknown extensions and bad input return null', () => {
  assert.equal(languageOfFile('a/b.txt'), null);
  assert.equal(languageOfFile('README'), null);
  assert.equal(languageOfFile(null), null);
  assert.equal(languageOfFile(42), null);
});

test('collectIrStats: counts in-scope vs parsed per language', () => {
  const fileContents = {
    'a.js': 'x', 'b.js': 'y', 'c.py': 'z', 'd.txt': 'ignored',
  };
  const perFile = {
    'a.js': { file: 'a.js', functions: [{ qid: 'a.js::f@1#aa' }, { qid: 'a.js::g@5#bb' }] },
    'c.py': { file: 'c.py', functions: [{ qid: 'c.py::h@1#cc' }] },
  };
  const stats = collectIrStats(fileContents, perFile, null);
  assert.equal(stats.languages.javascript.inScope, 2);
  assert.equal(stats.languages.javascript.parsed, 1);
  assert.equal(stats.languages.javascript.functions, 2);
  assert.deepEqual(stats.languages.javascript.failures, ['b.js']);
  assert.equal(stats.languages.python.inScope, 1);
  assert.equal(stats.languages.python.parsed, 1);
  assert.equal(stats.totals.inScope, 3);
  assert.equal(stats.totals.parsed, 2);
  assert.equal(stats.totals.functions, 3);
  assert.ok(!('txt' in stats.languages), 'unknown extensions are not tracked');
});

test('collectIrStats: a file with an empty function list counts as parsed+functionless, not a failure', () => {
  const stats = collectIrStats(
    { 'a.js': 'x' },
    { 'a.js': { file: 'a.js', functions: [] } },
    null,
  );
  assert.equal(stats.languages.javascript.parsed, 1);
  assert.equal(stats.languages.javascript.functionless, 1);
  assert.deepEqual(stats.languages.javascript.failures, []);
});

test('collectIrStats: distinguishes an IR record with no functions from no IR record at all', () => {
  const fileContents = { 'a.js': 'x', 'b.js': 'y' };
  const perFile = {
    // a.js parsed successfully but declares no functions (e.g. a constants module).
    'a.js': { file: 'a.js', functions: [] },
    // b.js has no entry at all — the parser produced nothing for it.
  };
  const stats = collectIrStats(fileContents, perFile, null);
  assert.equal(stats.languages.javascript.inScope, 2);
  assert.equal(stats.languages.javascript.parsed, 1, 'a.js counts as parsed despite zero functions');
  assert.equal(stats.languages.javascript.functionless, 1, 'a.js is the functionless one');
  assert.deepEqual(stats.languages.javascript.failures, ['b.js'], 'only the file with no IR record is a failure');
});

test('collectIrStats: summarises call-graph size and resolution', () => {
  const callGraph = {
    functions: new Map([['q1', {}], ['q2', {}]]),
    edges: [
      { caller: 'q1', callee: 'q2' },
      { caller: 'q1', callee: null },
      { caller: 'q2', callee: 'q1' },
    ],
  };
  const stats = collectIrStats({ 'a.js': 'x' }, {}, callGraph);
  assert.equal(stats.callGraph.functions, 2);
  assert.equal(stats.callGraph.edges, 3);
  assert.equal(stats.callGraph.resolvedEdges, 2);
  assert.equal(stats.callGraph.unresolvedEdges, 1);
});

test('collectIrStats: failures are capped and sorted for determinism', () => {
  const fileContents = {};
  for (let i = 0; i < 250; i++) fileContents[`f${String(i).padStart(3, '0')}.js`] = 'x';
  const stats = collectIrStats(fileContents, {}, null);
  assert.equal(stats.languages.javascript.inScope, 250);
  assert.equal(stats.languages.javascript.parsed, 0);
  assert.equal(stats.languages.javascript.failures.length, 200, 'failure list is capped at 200');
  assert.equal(stats.languages.javascript.failures[0], 'f000.js', 'failures are sorted');
});

test('collectIrStats: tolerates null and undefined inputs', () => {
  const stats = collectIrStats(null, null, null);
  assert.equal(stats.totals.inScope, 0);
  assert.equal(stats.callGraph.functions, 0);
});

test('irStatsTarget: reads the env var, empty means off', () => {
  const prev = process.env.AGENTIC_SECURITY_IR_STATS;
  try {
    delete process.env.AGENTIC_SECURITY_IR_STATS;
    assert.equal(irStatsTarget(), null);
    process.env.AGENTIC_SECURITY_IR_STATS = '';
    assert.equal(irStatsTarget(), null);
    process.env.AGENTIC_SECURITY_IR_STATS = '/tmp/x.json';
    assert.equal(irStatsTarget(), '/tmp/x.json');
  } finally {
    if (prev === undefined) delete process.env.AGENTIC_SECURITY_IR_STATS;
    else process.env.AGENTIC_SECURITY_IR_STATS = prev;
  }
});

test('writeIrStats: writes sorted, timestamp-free JSON and creates parent dirs', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'irstats-'));
  const target = path.join(dir, 'nested', 'stats.json');
  const stats = collectIrStats({ 'a.js': 'x' }, {}, null);
  writeIrStats(target, stats);
  const raw = fs.readFileSync(target, 'utf8');
  assert.ok(!/\d{4}-\d{2}-\d{2}T/.test(raw), 'sidecar must contain no timestamp');
  const parsed = JSON.parse(raw);
  assert.equal(parsed.languages.javascript.inScope, 1);
  writeIrStats(target, stats);
  assert.equal(fs.readFileSync(target, 'utf8'), raw, 'two writes of equal stats are byte-identical');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── per-file parse-failure observability (ir/index.js) ──────────────────────
// The per-file try/catch in buildProjectIR is load-bearing (one RangeError
// must not abort IR for the whole project) but, bare, it made a systematic
// parser failure look identical to "this language isn't in the tree". These
// cover the counter and the env-gated stderr line that fix that.

test('irParseFailures: counts per-file parse failures by language', async () => {
  const m = await import('../src/ir/index.js');
  m._resetIrParseFailures();
  assert.deepEqual(m.irParseFailures(), { count: 0, byLanguage: {}, firstError: null });

  m._noteParseFailure('a/b.cs', new RangeError('Maximum call stack size exceeded'));
  m._noteParseFailure('a/c.cs', new RangeError('Maximum call stack size exceeded'));
  m._noteParseFailure('a/d.cpp', new Error('boom'));

  const f = m.irParseFailures();
  assert.equal(f.count, 3);
  assert.deepEqual(f.byLanguage, { cs: 2, cpp: 1 });
  assert.equal(f.firstError.file, 'a/b.cs');
  assert.match(f.firstError.message, /call stack/);
  m._resetIrParseFailures();
  assert.equal(m.irParseFailures().count, 0);
});

test('irParseFailures: stderr line is silent by default and emitted under AGENTIC_SECURITY_IR_PARSE_DEBUG=1', () => {
  const script = `
    import { _noteParseFailure } from ${JSON.stringify(path.resolve('src/ir/index.js'))};
    _noteParseFailure('x/y.cs', new RangeError('Maximum call stack size exceeded'));
  `;
  const run = (env) => spawnSync(process.execPath, ['--input-type=module', '-e', script], {
    encoding: 'utf8', env: { ...process.env, ...env },
  });

  const quiet = run({ AGENTIC_SECURITY_IR_PARSE_DEBUG: '' });
  assert.equal(quiet.status, 0, quiet.stderr);
  assert.equal(quiet.stderr.trim(), '', 'must stay silent unless explicitly enabled');

  const loud = run({ AGENTIC_SECURITY_IR_PARSE_DEBUG: '1' });
  assert.equal(loud.status, 0, loud.stderr);
  assert.match(loud.stderr, /\[ir\] parse failed \(cs\): x\/y\.cs: RangeError: Maximum call stack size exceeded/);
});
