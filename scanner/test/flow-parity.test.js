// R3 — deep-engine flow parity for additional languages.
// Go + Kotlin now track interprocedural/intra taint through the deep engine
// (via call-source recognition + string-callee matching + Go concat lowering).
// PHP/Ruby/C# remain on the structural detectors (their parsers don't yet lower
// concat into the IR) — tracked as the R3 remainder.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runDeepAnalysis } from '../src/dataflow/index.js';
import { buildProjectIR } from '../src/ir/index.js';

function irTaint(file, code) {
  const { perFile, callGraph } = buildProjectIR({ [file]: code });
  return runDeepAnalysis(perFile, callGraph, {}).filter((f) => f.parser === 'IR-TAINT');
}

test('Go: FormValue → db.Query string-concat is flagged by the deep engine', () => {
  const f = irTaint('h.go', 'package main\nfunc h(w http.ResponseWriter, r *http.Request){\n q := r.FormValue("id")\n db.Query("SELECT " + q)\n}');
  assert.ok(f.length >= 1, `expected a Go IR-TAINT finding, got ${f.length}`);
  assert.ok(f.some((x) => /SQL Injection/i.test(x.vuln)));
});

test('Go precision: a literal query and a parameterized query do NOT fire', () => {
  assert.equal(irTaint('h.go', 'package main\nfunc h(){\n db.Query("SELECT * FROM users")\n}').length, 0);
  assert.equal(irTaint('h.go', 'package main\nfunc h(w http.ResponseWriter, r *http.Request){\n q := r.FormValue("id")\n db.Query("SELECT WHERE id=$1", q)\n}').length, 0);
});

test('Kotlin: request param → executeQuery string-concat is flagged', () => {
  const f = irTaint('h.kt', 'fun h(){ val q = request.getParameter("id"); stmt.executeQuery("SELECT " + q) }');
  assert.ok(f.length >= 1, `expected a Kotlin IR-TAINT finding, got ${f.length}`);
});

test('matchSource resolves CALL-shaped sources (regression guard for the matcher fix)', async () => {
  const { matchSource, matchSinkOrSanitizer } = await import('../src/dataflow/catalog.js');
  // Go-style call source (callee as a dotted string) is recognized.
  assert.ok(matchSource({ kind: 'call', callee: 'r.FormValue', args: [] }), 'r.FormValue() should be a source');
  // String-callee sink (Go) is recognized.
  assert.ok(matchSinkOrSanitizer('db.Query'), 'db.Query (string callee) should match a sink');
  // Member sources still work unchanged.
  assert.ok(matchSource({ kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'query' }), 'req.query member source intact');
});
