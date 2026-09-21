// Sanity tests for the 9 world-class roadmap modules. Verifies each is
// importable, exposes its documented public API, and behaves correctly
// on small fixtures. Does NOT verify end-to-end network behavior (Z3
// solver, Rekor lookups, etc.) — those are integration-test concerns.

import { test } from 'node:test';
import assert from 'node:assert/strict';

// ── Item 1: Universal IR ───────────────────────────────────────────────────

test('universal-ir: detectLanguage maps extensions correctly', async () => {
  const { detectLanguage } = await import('../src/ir/universal-ir.js');
  assert.equal(detectLanguage('/path/x.java'), 'java');
  assert.equal(detectLanguage('/path/x.cs'),   'csharp');
  assert.equal(detectLanguage('/path/x.cpp'),  'cpp');
  assert.equal(detectLanguage('/path/x.py'),   'python');
  assert.equal(detectLanguage('/path/x.rs'),   'rust');
  assert.equal(detectLanguage('/path/x.go'),   'go');
  assert.equal(detectLanguage('/path/x.sol'),  'solidity');
  assert.equal(detectLanguage('/path/x.unknown-ext'), null);
});

test('universal-ir: buildUniversalIR returns null when tree-sitter unavailable', async () => {
  const { buildUniversalIR } = await import('../src/ir/universal-ir.js');
  // tree-sitter is not installed in this repo by design — verify the
  // graceful-fallback contract.
  const ir = await buildUniversalIR('test.java', 'class Foo { void bar() {} }');
  assert.equal(ir, null);
});

test('universal-ir: queryIR returns matches against a synthetic IR', async () => {
  const { queryIR } = await import('../src/ir/universal-ir.js');
  const synthIr = {
    calls: [
      { callee: 'ExecuteReader', receiver: 'cmd', args: [], line: 10 },
      { callee: 'getUser',        receiver: 'svc', args: [], line: 20 },
    ],
    assignments: [
      { target: 'cmd', isMember: true, memberPath: 'CommandText', rhsText: 'x', line: 5 },
    ],
    functions: [{ name: 'doStuff' }],
    classes: [{ name: 'Repo' }],
    imports: [{ module: 'foo' }],
  };
  const m1 = queryIR(synthIr, { node: 'call', name: 'ExecuteReader' });
  assert.equal(m1.length, 1);
  const m2 = queryIR(synthIr, { node: 'assign', targetGlob: 'cmd.CommandText' });
  assert.equal(m2.length, 1);
  const m3 = queryIR(synthIr, { node: 'class', nameGlob: 'R*' });
  assert.equal(m3.length, 1);
});

// ── Item 2: IFDS-precise ───────────────────────────────────────────────────

test('ifds-precise: RefinedSummaryCache stores per-entry-state summaries', async () => {
  const { RefinedSummaryCache } = await import('../src/dataflow/ifds-precise.js');
  const cache = new RefinedSummaryCache(null);
  const s1 = { returnTainted: true };
  const s2 = { returnTainted: false };
  cache.store('fn1', new Set(['arg0']), s1);
  cache.store('fn1', new Set(['arg1']), s2);
  assert.equal(cache.get('fn1', new Set(['arg0'])), s1);
  assert.equal(cache.get('fn1', new Set(['arg1'])), s2);
});

test('ifds-precise: backwardSlice returns source-first ordered trace', async () => {
  const { backwardSlice } = await import('../src/dataflow/ifds-precise.js');
  const finding = {
    file: 'a.js', line: 50,
    sink: {
      file: 'a.js', line: 50, snippet: 'sink(x)',
      predecessor: {
        file: 'a.js', line: 40, snippet: 'x = y + 1',
        predecessor: {
          file: 'a.js', line: 10, snippet: 'y = req.query.x',
        },
      },
    },
  };
  const slice = backwardSlice(null, finding);
  assert.equal(slice[0].line, 10);  // source first
  assert.equal(slice.at(-1).line, 50);  // sink last
});

// ── Item 3: SMT path feasibility — RETIRED ──────────────────────────────────
//
// `dataflow/smt-feasibility.js` (opt-in `AGENTIC_SECURITY_SMT_FEASIBILITY=1`)
// has been removed. Its predicate encoder read `f.chain`/`f.taintPath` as a
// sequential source-to-sink path, but those fields are actually a flat list
// of SOURCES reaching the sink (`_sourcesReachingExpr`) — never a real path
// — so its SMT-LIB output never modeled anything genuine, confirmed by
// direct code reading rather than by any test here (its own tests only ever
// fed it hand-fabricated predicate objects, never real finding data). It
// also mutated `f.severity` directly on an 'unsat' verdict, violating this
// codebase's recall-preserving-demotion convention (`dataflow/CLAUDE.md`).
// Superseded by `dataflow/exploit-prover.js`'s `proveExploits`, which
// consumes the real `backward.js`-built `finding.backwardSlice` — see
// `test/smt-path-feasibility.test.js` for its coverage.

// ── Item 4: Cross-repo / cross-service taint ────────────────────────────────

test('cross-service-taint: loads graph from yaml', async () => {
  const { loadServiceGraph, _internals } = await import('../src/dataflow/cross-service-taint.js');
  // Use the normalizer directly with synthetic doc (loader requires file).
  const doc = {
    services: {
      payments: { repo: 'github.com/x/payments', exposes: [{ route: 'POST /charges', taints: ['amount'] }] },
      ledger:   { consumes: [{ source: 'events.charge_created', fields: ['amount'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'kafka', topic: 'events.charge_created' }],
  };
  const norm = _internals._normalizeGraph(doc);
  assert.equal(Object.keys(norm.services).length, 2);
  assert.equal(norm.edges[0].via, 'kafka');
});

// The second sanity test here originally fed `{ snippet: 'process(amount)' }`
// — a shape no real detector produces (real findings carry `source.label`,
// never a bare `snippet`; see `test/cross-service-taint.test.js`'s own
// header for the full rebuild writeup). Fixed to use the real finding
// shape so this stays a genuine sanity check, not a false confirmation.
test('cross-service-taint: annotateCrossServiceFindings bumps severity', async () => {
  const { annotateCrossServiceFindings, _internals } = await import('../src/dataflow/cross-service-taint.js');
  const graph = _internals._normalizeGraph({
    services: {
      payments: { exposes: [{ route: 'POST /charges', taints: ['amount'] }] },
      ledger:   { consumes: [{ source: 'events.charge_created', fields: ['amount'] }] },
    },
    edges: [{ from: 'payments', to: 'ledger', via: 'kafka', topic: 'events.charge_created' }],
  });
  const findings = [{ severity: 'medium', source: { label: 'amount' } }];
  const r = annotateCrossServiceFindings(findings, graph, graph.services.ledger);
  assert.equal(r.annotated, 1);
  assert.equal(findings[0].crossService.from, 'payments');
  assert.equal(findings[0].severity, 'high'); // bumped one tier
});

// ── Item 5: Runtime correlation ────────────────────────────────────────────

test('runtime-correlation: returns unknown when no trace file present', async () => {
  const { annotateRuntimeCorrelation } = await import('../src/posture/runtime-correlation.js');
  const findings = [{ file: 'a.js', line: 10, severity: 'high' }];
  const r = await annotateRuntimeCorrelation('/tmp/no-such-dir', findings);
  assert.equal(r.unknown, 1);
  assert.equal(findings[0].runtimeObserved, 'unknown');
});

// ── Item 6: Exploit bundle ─────────────────────────────────────────────────

test('exploit-bundle: generateBundle emits a 4-piece bundle for SQLi', async () => {
  const { generateBundle } = await import('../src/posture/exploit-bundle.js');
  const finding = {
    family: 'sql-injection', cwe: 'CWE-89',
    file: 'app/api/search.js', line: 42,
    _inRoute: { path: '/api/search' }, _sourceParam: 'id',
  };
  const bundle = generateBundle(finding);
  assert.equal(bundle.family, 'sql-injection');
  assert.match(bundle.pocs.curl, /UNION(\s|%20)SELECT/);
  assert.match(bundle.tests.jest, /SQL [Ii]njection/);
  assert.match(bundle.tests.pytest, /sql_injection_rejected/);
  assert.match(bundle.remediation.summary, /[Pp]arameterize/);
});

test('exploit-bundle: emits stub for unknown family', async () => {
  const { generateBundle } = await import('../src/posture/exploit-bundle.js');
  const bundle = generateBundle({ family: 'unknown', file: 'x.c', line: 1 });
  assert.equal(bundle.stub, true);
});

// ── Item 7: Sigstore + SLSA ────────────────────────────────────────────────

test('sigstore-verify: returns no-digest when component has no hash', async () => {
  const { verifyComponent } = await import('../src/sca/sigstore-verify.js');
  process.env.AGENTIC_SECURITY_OFFLINE = '1';
  try {
    const r = await verifyComponent({ ecosystem: 'npm', name: 'lodash', version: '4.17.20' });
    assert.equal(r.state, 'unknown');
    assert.equal(r.reason, 'no-locally-recorded-digest');
  } finally {
    delete process.env.AGENTIC_SECURITY_OFFLINE;
  }
});

test('sigstore-verify: annotateProvenance no-ops without opt-in flag', async () => {
  const { annotateProvenance } = await import('../src/sca/sigstore-verify.js');
  // AGENTIC_SECURITY_SIGSTORE not set
  const r = await annotateProvenance([{ type: 'vulnerable_dep' }], [{ name: 'x' }]);
  assert.equal(r.skipped, true);
});

// ── Item 8: Triage learning ────────────────────────────────────────────────

test('triage-learning: recordTriageDecision + applyLearnedCalibration roundtrip', async () => {
  const { promises: fsp } = await import('node:fs');
  const path = await import('node:path');
  const os = await import('node:os');
  const dir = await fsp.mkdtemp(path.join(os.tmpdir(), 'tl-'));
  await fsp.mkdir(path.join(dir, '.agentic-security'), { recursive: true });
  await fsp.writeFile(path.join(dir, 'package.json'), '{"name":"t"}');

  const { recordTriageDecision, applyLearnedCalibration, loadCalibration } = await import('../src/posture/triage-learning.js');
  const finding = { family: 'hardcoded-secret', file: 'src/auth/x.js', vuln: 'Hardcoded Secret', confidence: 0.85 };
  // Record 10 false positives.
  for (let i = 0; i < 10; i++) recordTriageDecision(dir, finding, 'false-positive');
  // A fresh finding of the same shape gets its confidence demoted.
  const fresh = { ...finding };
  const r = applyLearnedCalibration(dir, [fresh]);
  assert.equal(r.adjusted, 1);
  assert.ok(fresh.confidence < 0.85, `expected confidence < 0.85, got ${fresh.confidence}`);
  await fsp.rm(dir, { recursive: true, force: true });
});

// ── Item 9: Privacy data flow ──────────────────────────────────────────────

test('privacy-taint: classifyField buckets PII / PHI / PCI / FIN', async () => {
  const { classifyField } = await import('../src/dataflow/privacy-taint.js');
  assert.deepEqual(classifyField('email'), ['PII']);
  assert.deepEqual(classifyField('credit_card_number'), ['PCI']);
  assert.deepEqual(classifyField('diagnosis'), ['PHI']);
  assert.deepEqual(classifyField('salary'), ['FIN']);
  assert.deepEqual(classifyField('not_personal_data'), []);
});

test('privacy-taint: classifySink identifies log/response/etc.', async () => {
  const { classifySink } = await import('../src/dataflow/privacy-taint.js');
  assert.equal(classifySink('console.log'), 'log');
  assert.equal(classifySink('res.send'), 'response');
  assert.equal(classifySink('fetch'), 'outboundHttp');
  assert.equal(classifySink('unrelated.method'), null);
});

test('privacy-taint: annotatePrivacyTaint emits a finding when PII flows to log', async () => {
  const { annotatePrivacyTaint } = await import('../src/dataflow/privacy-taint.js');
  const perFileIR = new Map();
  perFileIR.set('a.js', {
    _content: 'const email = req.body.email;\nconsole.log(email);\n',
    decls: [{ name: 'email', line: 1 }],
    calls: [{ callee: 'log', receiver: 'console', fullPath: 'console.log', args: [{ text: 'email' }], line: 2 }],
  });
  const r = annotatePrivacyTaint(perFileIR);
  assert.equal(r.findings.length, 1);
  assert.equal(r.findings[0].family, 'pii-exposure');
  assert.deepEqual(r.findings[0].piiClass, ['PII']);
  assert.equal(r.findings[0].sinkKind, 'log');
});

test('privacy-taint: emitDpiaArtifact produces markdown', async () => {
  const { emitDpiaArtifact } = await import('../src/dataflow/privacy-taint.js');
  const md = emitDpiaArtifact(
    [{ file: 'a.js', line: 1, name: 'email', classes: ['PII'], declaredType: 'string' }],
    [{ severity: 'medium', file: 'a.js', line: 2, piiClass: ['PII'], sinkKind: 'log', vuln: 'PII → log' }],
  );
  assert.match(md, /^# Data Protection Impact Assessment/);
  assert.match(md, /GDPR Art\. 35/);
});
