// Next-gen taint capability #5 — SMT path-feasibility rebuild.
//
// The pre-existing `exploit-prover.js`'s `smtLiteInfeasibilityCheck` had
// correct METACHARACTER tables and a correct Z3-loading skeleton, but was
// fed `finding.trace`/`finding.chain` — which, confirmed by direct code
// reading of `dataflow/engine.js`, is a list of SOURCES reaching the sink
// (via `_sourcesReachingExpr`), never a sequential source-to-sink PATH with
// real sanitizer-call steps. Its own pre-existing unit tests only ever
// exercised a HAND-FABRICATED `chain: [{callee: 'htmlspecialchars'}]` shape
// the real engine never produces, so the mechanism was never actually
// exercised by real data before this rebuild. A SEPARATE, parallel
// mechanism (`smt-feasibility.js`) had the identical class of defect.
//
// This rebuild:
//   1. Fixed `backward.js`'s `sliceBackward` to trace THROUGH a call-shaped
//      assign RHS (previously a dead end — `accessPathOf` returns null for
//      a call expression) — recognizing a recognized sanitizer call as a
//      real `'sanitize'` step carrying a PROVEN output-regex source when
//      one is known.
//   2. Fixed `dataflow/engine.js`'s own finding-normalization allowlist,
//      which was silently dropping `argIndex` before `annotateBackwardSlices`
//      ever saw it (the same bug class its own comments already document
//      TWICE for `_funcQid`/`callee`) — without it, EVERY real finding's
//      backward slice degraded to an unmatchable `arg[undefined]`
//      placeholder, making the whole mechanism a structural no-op
//      regardless of any flag.
//   3. Fixed the still-more-common case where the tainted sink argument is
//      a COMPOUND expression (string concatenation) rather than a bare
//      identifier — `accessPathOf` alone can't handle it, so
//      `annotateBackwardSlices` now falls back to `engine.js`'s own
//      `_collectExprVars` tree-walker to find the real free variable.
//   4. Rebuilt `smtLiteInfeasibilityCheck` to consume the now-real
//      `finding.backwardSlice`, trusting a sanitizer step ONLY when its
//      output regex is proven (`string-domain.js`'s hand-vetted
//      `safeSanitizerOutputRegex`, deliberately narrower than the broad,
//      name-collision-prone 706-entry sink/sanitizer catalog), and
//      REFUSING to conclude anything across an opaque, unmodeled call
//      between a trusted sanitizer and the sink — the single most
//      safety-critical property of this whole rebuild.
//   5. Made `AGENTIC_SECURITY_SYMEXEC=1` self-sufficient: it now also runs
//      the backward-slice pass, rather than silently degrading to
//      uselessness unless an operator ALSO independently knew to set the
//      unrelated `AGENTIC_SECURITY_BACKWARD_SLICE=1` flag.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runScan } from '../src/runScan.js';
import { parseJsFile } from '../src/ir/parser-js.js';
import { sliceBackward } from '../src/dataflow/backward.js';
import { smtLiteInfeasibilityCheck, _internal } from '../src/dataflow/exploit-prover.js';
import { safeSanitizerOutputRegex } from '../src/dataflow/string-domain.js';

function mkTmp(name, files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `as-smt-${name}-`));
  for (const [rel, content] of Object.entries(files)) {
    const fp = path.join(dir, rel);
    fs.mkdirSync(path.dirname(fp), { recursive: true });
    fs.writeFileSync(fp, content);
  }
  return dir;
}

// ─── safeSanitizerOutputRegex ───────────────────────────────────────────

test('safeSanitizerOutputRegex: excludes toString (too ambiguous to trust for a sound proof)', () => {
  assert.equal(safeSanitizerOutputRegex('toString'), null);
  assert.equal(safeSanitizerOutputRegex('buf.toString'), null);
});

test('safeSanitizerOutputRegex: returns the real regex for an unambiguous builtin', () => {
  const r = safeSanitizerOutputRegex('parseInt');
  assert.ok(r instanceof RegExp);
  assert.ok(r.test('42'));
  assert.ok(!r.test("1' OR '1'='1"));
});

test('safeSanitizerOutputRegex: returns null for an unrecognized name', () => {
  assert.equal(safeSanitizerOutputRegex('myRandomHelper'), null);
});

// ─── sliceBackward: tracing through a call-shaped assign RHS ────────────

test('sliceBackward: a recognized sanitizer call is a real "sanitize" step with a proven output regex', () => {
  const src = `const { exec } = require('child_process');
module.exports = (req, res) => {
  const clean = encodeURIComponent(req.query.cmd);
  exec(clean);
};`;
  const ir = parseJsFile('app.js', src);
  const fn = ir.functions.find((f) => f.name === 'exports');
  const sinkNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call' && n.line === 4);
  const slice = sliceBackward(fn, sinkNode, 'clean');
  const sanitizeStep = slice.find((s) => s.kind === 'sanitize');
  assert.ok(sanitizeStep, 'expected a sanitize step in the slice');
  assert.equal(sanitizeStep.callee, 'encodeURIComponent');
  assert.ok(sanitizeStep.outputRegexSource, 'expected a proven output regex source');
});

test('sliceBackward: an unrecognized call is a generic "call" step with NO output regex (must not guess)', () => {
  const src = `const { exec } = require('child_process');
function mysteryHelper(s) { return s; }
module.exports = (req, res) => {
  const clean = mysteryHelper(req.query.cmd);
  exec(clean);
};`;
  const ir = parseJsFile('app.js', src);
  const fn = ir.functions.find((f) => f.name === 'exports');
  const sinkNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call' && n.line === 5);
  const slice = sliceBackward(fn, sinkNode, 'clean');
  const callStep = slice.find((s) => s.kind === 'call');
  assert.ok(callStep, 'expected a generic call step');
  assert.equal(callStep.callee, 'mysteryHelper');
  assert.equal(callStep.outputRegexSource, null);
});

test('sliceBackward: continues tracing into the call argument (previously a dead end)', () => {
  const src = `const { exec } = require('child_process');
module.exports = (req, res) => {
  const raw = req.query.cmd;
  const clean = encodeURIComponent(raw);
  exec(clean);
};`;
  const ir = parseJsFile('app.js', src);
  const fn = ir.functions.find((f) => f.name === 'exports');
  const sinkNode = Object.values(fn.cfg.nodes).find((n) => n.kind === 'call' && n.line === 5);
  const slice = sliceBackward(fn, sinkNode, 'clean');
  assert.ok(slice.some((s) => s.kind === 'source' && s.label === 'req.query.cmd'),
    `expected the slice to continue all the way to the real source. Slice: ${JSON.stringify(slice)}`);
});

// ─── smtLiteInfeasibilityCheck: the safety-critical logic ───────────────

test('smtLiteInfeasibilityCheck: a proven sanitizer excluding all metachars demotes to infeasible', () => {
  const backwardSlice = [
    { kind: 'sanitize', callee: 'parseInt', outputRegexSource: '^-?\\d+$', outputRegexFlags: '' },
    { kind: 'assign', to: 'id' },
    { kind: 'sink' },
  ];
  const r = smtLiteInfeasibilityCheck({ cwe: 'CWE-89', backwardSlice });
  assert.equal(r.feasible, false);
  assert.match(r.reason, /sanitizer-excludes-metacharacters:parseInt/);
});

test('smtLiteInfeasibilityCheck: NO sanitizer on the path stays feasible (unknown)', () => {
  const backwardSlice = [
    { kind: 'source', label: 'req.query.id' },
    { kind: 'assign', to: 'id' },
    { kind: 'sink' },
  ];
  const r = smtLiteInfeasibilityCheck({ cwe: 'CWE-89', backwardSlice });
  assert.equal(r.feasible, 'unknown');
});

test('smtLiteInfeasibilityCheck: SAFETY-CRITICAL — an opaque call AFTER a real sanitizer refuses to conclude infeasible', () => {
  const backwardSlice = [
    { kind: 'sanitize', callee: 'parseInt', outputRegexSource: '^-?\\d+$', outputRegexFlags: '' },
    { kind: 'assign', to: 'id' },
    { kind: 'call', callee: 'mutate', outputRegexSource: null },
    { kind: 'assign', to: 'evil' },
    { kind: 'sink' },
  ];
  const r = smtLiteInfeasibilityCheck({ cwe: 'CWE-89', backwardSlice });
  assert.notEqual(r.feasible, false,
    'an opaque, unmodeled call between a real sanitizer and the sink must NEVER be trusted through -- it could reintroduce or bypass the sanitizer\'s effect');
  assert.match(r.reason, /opaque-call-on-path:mutate/);
});

test('smtLiteInfeasibilityCheck: a sanitizer whose output regex does NOT exclude the family\'s metachars stays feasible', () => {
  // encodeURIComponent's own regex explicitly permits an apostrophe (RFC
  // 3986 unreserved character) -- it must NOT prove SQLi/XSS infeasible.
  const backwardSlice = [
    { kind: 'sanitize', callee: 'encodeURIComponent', outputRegexSource: safeSanitizerOutputRegex('encodeURIComponent').source, outputRegexFlags: '' },
    { kind: 'assign', to: 'clean' },
    { kind: 'sink' },
  ];
  const r = smtLiteInfeasibilityCheck({ cwe: 'CWE-89', backwardSlice });
  assert.equal(r.feasible, 'unknown',
    'encodeURIComponent permits a literal apostrophe through unescaped -- must not falsely prove SQLi infeasible');
});

test('smtLiteInfeasibilityCheck: a catalog-name-only sanitizer match with no proven output regex refuses (never guesses)', () => {
  // A project-local function merely NAMED like a known sanitizer (matched
  // by backward.js's broad catalog lookup for explainability) but with no
  // entry in the small, hand-vetted safeSanitizerOutputRegex table.
  const backwardSlice = [
    { kind: 'sanitize', callee: 'sanitize', sanitizerId: 'js-dompurify', outputRegexSource: null },
    { kind: 'assign', to: 'clean' },
    { kind: 'sink' },
  ];
  const r = smtLiteInfeasibilityCheck({ cwe: 'CWE-89', backwardSlice });
  assert.equal(r.feasible, 'unknown');
  assert.match(r.reason, /sanitizer-without-proven-output-shape/);
});

test('smtLiteInfeasibilityCheck: falls back to trace/chain when no backwardSlice is present (backward compat)', () => {
  const r = smtLiteInfeasibilityCheck({
    cwe: 'CWE-79',
    trace: [{ sourceLabel: 'req.body' }],
    chain: [{ callee: 'htmlspecialchars' }],
  });
  assert.equal(r.feasible, false);
});

// ─── End-to-end: the real pipeline, via runScan ─────────────────────────

test('end-to-end: AGENTIC_SECURITY_SYMEXEC=1 alone (no separate BACKWARD_SLICE flag) proves a numeric-coerced SQLi finding infeasible', async () => {
  const dir = mkTmp('e2e-fire', {
    'src/app.js': `const db = require('db');
module.exports = (req, res) => {
  const id = parseInt(req.query.id);
  db.query('SELECT * FROM t WHERE id=' + id);
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_SYMEXEC = '1';
  try {
    const { scan } = await runScan(dir);
    const f = (scan.findings || []).find((x) => x.parser === 'IR-TAINT' && /SQL Injection/i.test(x.vuln || ''));
    assert.ok(f, 'expected a SQL injection finding to exist (feasible or not)');
    assert.equal(f._provenUnreachable, true,
      `expected the numeric-coerced flow to be proven unreachable. Finding: ${JSON.stringify({ severity: f.severity, backwardSlice: f.backwardSlice })}`);
    assert.equal(f.severity, 'low', 'a proven-unreachable finding must be demoted, never removed');
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    delete process.env.AGENTIC_SECURITY_SYMEXEC;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('end-to-end precision: a genuinely unsanitized flow is NOT proven infeasible', async () => {
  const dir = mkTmp('e2e-clean', {
    'src/app.js': `const db = require('db');
module.exports = (req, res) => {
  const id = req.query.id;
  db.query('SELECT * FROM t WHERE id=' + id);
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_SYMEXEC = '1';
  try {
    const { scan } = await runScan(dir);
    const f = (scan.findings || []).find((x) => x.parser === 'IR-TAINT' && /SQL Injection/i.test(x.vuln || ''));
    assert.ok(f, 'expected a SQL injection finding');
    assert.notEqual(f._provenUnreachable, true);
    assert.equal(f.severity, 'high');
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    delete process.env.AGENTIC_SECURITY_SYMEXEC;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('end-to-end SAFETY-CRITICAL: an opaque helper call after a real sanitizer is NOT proven infeasible', async () => {
  const dir = mkTmp('e2e-opaque', {
    'src/app.js': `const db = require('db');
function mutate(s) { return s + "-suffix"; }
module.exports = (req, res) => {
  const id = parseInt(req.query.id);
  const evil = mutate(id);
  db.query('SELECT * FROM t WHERE id=' + evil);
};
`,
  });
  process.env.AGENTIC_SECURITY_DEEP = '1';
  process.env.AGENTIC_SECURITY_DEEP_IN_CI = '1';
  process.env.AGENTIC_SECURITY_SYMEXEC = '1';
  try {
    const { scan } = await runScan(dir);
    const f = (scan.findings || []).find((x) => x.parser === 'IR-TAINT' && /SQL Injection/i.test(x.vuln || ''));
    assert.ok(f, 'expected a SQL injection finding');
    assert.notEqual(f._provenUnreachable, true,
      'an opaque call downstream of a real sanitizer must never be trusted through to a false safety proof');
  } finally {
    delete process.env.AGENTIC_SECURITY_DEEP;
    delete process.env.AGENTIC_SECURITY_DEEP_IN_CI;
    delete process.env.AGENTIC_SECURITY_SYMEXEC;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
