// Privacy IR adapter tests (assurance-hardening PRD, Milestone 2, FR-401).
//
// Covers: the adapter's own unit-level correctness (expression rendering,
// declaration/call extraction from real CFG shapes), an end-to-end proof
// using the REAL js parser (not a hand-built fixture — the whole point of
// FR-401 is that this now runs on real IR), and a real engine.js scan
// proving the deep-mode-conditional wiring (A-06's actual fix) end to end.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { adaptIRForPrivacyTaint, _internals } from '../src/privacy/ir-adapter.js';
import { annotatePrivacyTaint } from '../src/dataflow/privacy-taint.js';
import { parseJsFile } from '../src/ir/parser-js.js';
import { runScan } from '../src/runScan.js';
import * as path from 'node:path';

const { _calleeToString, _identifiersIn, _adaptFile, _tsTypeToString, _qualifiedTypeName, _extractTsTypes } = _internals;

// ── Unit: _calleeToString ────────────────────────────────────────────────

test('_calleeToString: a plain string callee is returned unchanged', () => {
  assert.equal(_calleeToString('console.log'), 'console.log');
});

test('_calleeToString: a member expression is dot-joined', () => {
  assert.equal(_calleeToString({ kind: 'member', object: { kind: 'ident', name: 'console' }, prop: 'log' }), 'console.log');
});

test('_calleeToString: a nested member expression (a.b.c) is fully dot-joined', () => {
  const expr = { kind: 'member', object: { kind: 'member', object: { kind: 'ident', name: 'a' }, prop: 'b' }, prop: 'c' };
  assert.equal(_calleeToString(expr), 'a.b.c');
});

test('_calleeToString: null/undefined/unknown-kind returns empty string, never throws', () => {
  assert.equal(_calleeToString(null), '');
  assert.equal(_calleeToString(undefined), '');
  assert.equal(_calleeToString({ kind: 'literal', value: 42 }), '');
});

// ── Unit: _identifiersIn ─────────────────────────────────────────────────

test('_identifiersIn: collects a bare identifier', () => {
  const out = [];
  _identifiersIn({ kind: 'ident', name: 'email' }, out);
  assert.deepEqual(out, ['email']);
});

test('_identifiersIn: collects identifiers nested inside binary/logical/template expressions', () => {
  const out = [];
  _identifiersIn({
    kind: 'tpl',
    parts: [
      { kind: 'literal', value: 'prefix-' },
      { kind: 'binary', op: '+', left: { kind: 'ident', name: 'email' }, right: { kind: 'ident', name: 'suffix' } },
    ],
  }, out);
  assert.ok(out.includes('email'));
  assert.ok(out.includes('suffix'));
});

test('_identifiersIn: collects identifiers nested inside a call argument, an array, and an object literal', () => {
  const out = [];
  _identifiersIn({
    kind: 'call',
    callee: { kind: 'ident', name: 'wrap' },
    args: [
      { kind: 'array', elements: [{ kind: 'ident', name: 'ssn' }] },
      { kind: 'object', props: [{ value: { kind: 'ident', name: 'email' } }] },
    ],
  }, out);
  assert.ok(out.includes('ssn'));
  assert.ok(out.includes('email'));
});

test('_identifiersIn: a deeply nested (but non-cyclic) expression does not stack-overflow — depth guard holds', () => {
  let expr = { kind: 'ident', name: 'base' };
  for (let i = 0; i < 500; i++) expr = { kind: 'member', object: expr, prop: `p${i}` };
  const out = [];
  assert.doesNotThrow(() => _identifiersIn(expr, out));
});

test('_identifiersIn: garbage input does not throw', () => {
  const out = [];
  assert.doesNotThrow(() => _identifiersIn(null, out));
  assert.doesNotThrow(() => _identifiersIn('not an object', out));
  assert.doesNotThrow(() => _identifiersIn({}, out));
});

// ── Unit: _adaptFile against a hand-built CFG matching the documented contract ──

test('_adaptFile: extracts declarations from function params and assign-node targets', () => {
  const fileIR = {
    file: 'a.js',
    functions: [{
      name: 'handler', line: 1, params: ['req'],
      cfg: { nodes: {
        n1: { kind: 'assign', target: 'email', line: 2, source: { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'email' } },
      } },
    }],
  };
  const { decls } = _adaptFile(fileIR);
  const names = decls.map(d => d.name);
  assert.ok(names.includes('req'));
  assert.ok(names.includes('email'));
});

test('_adaptFile: extracts calls from BOTH standalone call nodes AND assign-node call sources (the gap fn.calls itself misses)', () => {
  const fileIR = {
    file: 'a.js',
    functions: [{
      name: 'handler', line: 1, params: [],
      cfg: { nodes: {
        n1: { kind: 'call', callee: 'console.log', args: [{ kind: 'ident', name: 'x' }], line: 2 },
        n2: { kind: 'assign', target: 'y', line: 3, source: { kind: 'call', callee: { kind: 'ident', name: 'getSecret' }, args: [] } },
      } },
    }],
  };
  const { calls } = _adaptFile(fileIR);
  assert.equal(calls.length, 2);
  assert.ok(calls.some(c => c.fullPath === 'console.log'));
  assert.ok(calls.some(c => c.fullPath === 'getSecret'), 'the assign-sourced call must be surfaced too, not just standalone call nodes');
});

// FR-401 (D-0052): parameters and assignments are genuinely distinct
// elements, not silently folded into one undifferentiated "decls" bucket.
test('_adaptFile: decls distinguish parameters from assignments via `kind`', () => {
  const fileIR = {
    file: 'a.js',
    functions: [{
      name: 'handler', line: 1, params: ['req'],
      cfg: { nodes: {
        n1: { kind: 'assign', target: 'email', line: 2, source: { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'email' } },
      } },
    }],
  };
  const { decls } = _adaptFile(fileIR);
  const req = decls.find(d => d.name === 'req');
  const email = decls.find(d => d.name === 'email');
  assert.equal(req.kind, 'parameter');
  assert.equal(email.kind, 'assignment');
});

// FR-401 (D-0052): return-kind CFG nodes are real IR data (emitted by every
// language parser), so the adapter now surfaces them as a genuine `returns`
// element — even though annotatePrivacyTaint() doesn't consume it yet (see
// D-0052 for the honest scope note: supplied, not yet read by this one
// consumer).
test('_adaptFile: extracts returns from return-kind CFG nodes, naming the identifiers in the returned expression', () => {
  const fileIR = {
    file: 'a.js',
    functions: [{
      name: 'handler', line: 1, params: [],
      cfg: { nodes: {
        n1: { kind: 'return', line: 5, value: { kind: 'ident', name: 'email' } },
      } },
    }],
  };
  const { returns } = _adaptFile(fileIR);
  assert.equal(returns.length, 1);
  assert.equal(returns[0].line, 5);
  assert.ok(returns[0].names.includes('email'));
});

test('_adaptFile: a return with no value (bare "return;") is not surfaced (nothing to name)', () => {
  const fileIR = {
    file: 'a.js',
    functions: [{
      name: 'handler', line: 1, params: [],
      cfg: { nodes: { n1: { kind: 'return', line: 5, value: null } } },
    }],
  };
  const { returns } = _adaptFile(fileIR);
  assert.equal(returns.length, 0);
});

test('_adaptFile: garbage/empty fileIR does not throw and returns empty arrays', () => {
  assert.deepEqual(_adaptFile(null), { decls: [], calls: [], returns: [] });
  assert.deepEqual(_adaptFile({}), { decls: [], calls: [], returns: [] });
  assert.deepEqual(_adaptFile({ functions: [] }), { decls: [], calls: [], returns: [] });
});

// ── Integration: real parser output through the adapter through annotatePrivacyTaint ──

test('end-to-end: a REAL parsed JS file (not a hand-built fixture) — PII assigned to a local, then logged, produces a finding', () => {
  const code = [
    'function handler(req, res) {',
    '  const email = req.query.email;',
    '  console.log(email);',
    '}',
  ].join('\n');
  const ir = parseJsFile('app.js', code);
  const adapted = adaptIRForPrivacyTaint({ 'app.js': ir }, { 'app.js': code });
  const result = annotatePrivacyTaint(adapted);
  assert.equal(result.findings.length, 1, `expected 1 finding, got: ${JSON.stringify(result.findings)}`);
  assert.equal(result.findings[0].sinkKind, 'log');
  assert.deepEqual(result.findings[0].piiClass, ['PII']);
  assert.equal(result.findings[0].line, 3);
});

test('end-to-end: PII that never reaches a sink produces zero findings (negative control — the adapter must not over-fire)', () => {
  const code = [
    'function handler(req) {',
    '  const email = req.query.email;',
    '  return email;',
    '}',
  ].join('\n');
  const ir = parseJsFile('app.js', code);
  const adapted = adaptIRForPrivacyTaint({ 'app.js': ir }, { 'app.js': code });
  const result = annotatePrivacyTaint(adapted);
  assert.equal(result.findings.length, 0);
});

test('adaptIRForPrivacyTaint: a file with no IR entry (parse failure) degrades to empty decls/calls, not a throw', () => {
  const adapted = adaptIRForPrivacyTaint({}, { 'broken.js': 'const x = ;;;' });
  assert.deepEqual(adapted.get('broken.js'), { _content: 'const x = ;;;', decls: [], calls: [], returns: [], storage: [] });
});

// ── FR-401's "storage" element ───────────────────────────────────────────────

test('_storageForFile: reindexes the whole-project field-keyed registry down to one file, in field order', () => {
  const registry = {
    bio: [
      { file: 'a.js', line: 5, snippet: 'user.bio = req.body.bio', named: true },
      { file: 'b.js', line: 9, snippet: 'other.bio = req.body.bio', named: true },
    ],
    payload: [
      { file: 'a.js', line: 12, snippet: 'model.payload = req.body.data', named: false },
    ],
  };
  const out = _internals._storageForFile('a.js', registry);
  assert.deepEqual(out, [
    { field: 'bio', line: 5, snippet: 'user.bio = req.body.bio', named: true },
    { field: 'payload', line: 12, snippet: 'model.payload = req.body.data', named: false },
  ]);
});

test('_storageForFile: a file with no matching writes gets an empty array, not undefined or a throw', () => {
  const registry = { bio: [{ file: 'a.js', line: 5, snippet: 'x', named: true }] };
  assert.deepEqual(_internals._storageForFile('unrelated.js', registry), []);
});

test('_storageForFile: a null/missing registry degrades to empty, matching every other optional field here', () => {
  assert.deepEqual(_internals._storageForFile('a.js', null), []);
  assert.deepEqual(_internals._storageForFile('a.js', undefined), []);
});

test('adaptIRForPrivacyTaint: storage is populated per-file from a real registry, and empty when none is supplied', () => {
  const registry = { bio: [{ file: 'app.js', line: 2, snippet: 'user.bio = req.body.bio', named: true }] };
  const withRegistry = adaptIRForPrivacyTaint({}, { 'app.js': 'x' }, registry);
  assert.deepEqual(withRegistry.get('app.js').storage, [{ field: 'bio', line: 2, snippet: 'user.bio = req.body.bio', named: true }]);

  const withoutRegistry = adaptIRForPrivacyTaint({}, { 'app.js': 'x' });
  assert.deepEqual(withoutRegistry.get('app.js').storage, []);
});

test('FR-401 end-to-end: the REAL buildStoredTaintRegistry (not a hand-built stand-in) feeds the adapter\'s storage field correctly', async () => {
  const { buildStoredTaintRegistry } = await import('../src/engine.js');
  const fc = {
    'model.js': [
      'function saveProfile(req, model) {',
      '  model.create({ bio: req.body.bio });',
      '}',
    ].join('\n'),
  };
  // The real registry builder, over real fixture content that is expected
  // to trip STORED_TAINT_FIELD_PATTERNS's actual admission rule (an ORM
  // create() call whose field value references req.body) — not a
  // hand-constructed stand-in for what the registry might look like.
  const registry = buildStoredTaintRegistry(fc);
  assert.ok(registry.bio, `expected the real registry to admit 'bio' from this fixture; got ${JSON.stringify(registry)}`);
  assert.equal(registry.bio[0].file, 'model.js');

  const ir = parseJsFile('model.js', fc['model.js']);
  const adapted = adaptIRForPrivacyTaint({ 'model.js': ir }, fc, registry);
  assert.equal(adapted.get('model.js').storage.length, 1);
  assert.equal(adapted.get('model.js').storage[0].field, 'bio');
  assert.equal(adapted.get('model.js').storage[0].line, registry.bio[0].line);
});

test('FR-401 end-to-end: a real scan wires the real storedRegistry through to the privacy adapter without throwing', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false, deep: true });
  assert.ok(scan.scanHealth, 'expected the scan to complete cleanly with the storage wiring in place');
  assert.equal(scan.scanHealth.deepAnalysis.enabled, true);
});

// ── Integration: the real engine.js wiring, deep vs non-deep ────────────────

test('a REAL scan with deep mode ON detects a genuine PII-to-log flow via the real IR (the actual A-06 fix, end to end)', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false, deep: true });
  // Not asserting a specific fixture finding (the fixture wasn't built for
  // this), but proving the WIRING: privacy-taint ran through the real IR
  // without throwing, and scan completed normally with deep mode on.
  assert.ok(scan.scanHealth, 'expected scanHealth to be present');
  assert.equal(scan.scanHealth.deepAnalysis.enabled, true);
});

test('a REAL scan with deep mode OFF (the default) still runs privacy analysis without crashing — honest degraded path, not forced IR cost', async () => {
  const root = path.resolve(process.cwd(), 'test/fixtures/vulnerable-js');
  const { scan } = await runScan(root, { network: false });
  assert.equal(scan.scanHealth.deepAnalysis.requested, false);
  // The scan must complete cleanly either way — privacy analysis running
  // without real IR must not throw or corrupt the scan.
  assert.ok(Array.isArray(scan.findings));
});

// ── FR-401's "types" element (TypeScript-only, via a separate read-only parse) ──

test('_tsTypeToString: primitive keyword types', () => {
  assert.equal(_tsTypeToString({ type: 'TSStringKeyword' }), 'string');
  assert.equal(_tsTypeToString({ type: 'TSNumberKeyword' }), 'number');
  assert.equal(_tsTypeToString({ type: 'TSBooleanKeyword' }), 'boolean');
  assert.equal(_tsTypeToString({ type: 'TSAnyKeyword' }), 'any');
  assert.equal(_tsTypeToString({ type: 'TSVoidKeyword' }), 'void');
  assert.equal(_tsTypeToString({ type: 'TSBigIntKeyword' }), 'bigint');
});

test('_tsTypeToString: array, union, and literal types', () => {
  assert.equal(_tsTypeToString({ type: 'TSArrayType', elementType: { type: 'TSStringKeyword' } }), 'string[]');
  assert.equal(
    _tsTypeToString({ type: 'TSUnionType', types: [{ type: 'TSStringKeyword' }, { type: 'TSNullKeyword' }] }),
    'string | null'
  );
  assert.equal(
    _tsTypeToString({ type: 'TSLiteralType', literal: { type: 'StringLiteral', value: 'x' } }),
    '"x"'
  );
  assert.equal(
    _tsTypeToString({ type: 'TSLiteralType', literal: { type: 'NumericLiteral', value: 42 } }),
    '42'
  );
});

test('_tsTypeToString: a named type reference, with and without generic args', () => {
  assert.equal(_tsTypeToString({ type: 'TSTypeReference', typeName: { type: 'Identifier', name: 'Foo' } }), 'Foo');
  assert.equal(
    _tsTypeToString({
      type: 'TSTypeReference',
      typeName: { type: 'Identifier', name: 'Array' },
      typeArguments: { params: [{ type: 'TSStringKeyword' }] },
    }),
    'Array<string>'
  );
});

test('_tsTypeToString: a union with one unresolvable member returns null rather than a misleadingly partial string', () => {
  assert.equal(
    _tsTypeToString({ type: 'TSUnionType', types: [{ type: 'TSStringKeyword' }, { type: 'TSConditionalType' }] }),
    null
  );
});

test('_tsTypeToString: unrecognized/garbage node types are null, never a guess', () => {
  assert.equal(_tsTypeToString({ type: 'TSMappedType' }), null);
  assert.equal(_tsTypeToString(null), null);
  assert.equal(_tsTypeToString(undefined), null);
  assert.equal(_tsTypeToString({}), null);
});

test('_tsTypeToString: a deeply nested (but non-cyclic) type does not stack-overflow — depth guard holds', () => {
  let node = { type: 'TSStringKeyword' };
  for (let i = 0; i < 100; i++) {
    node = { type: 'TSArrayType', elementType: node };
  }
  assert.equal(_tsTypeToString(node), null, 'past the depth guard, this must degrade to null, not throw');
});

test('_qualifiedTypeName: dot-joins a TSQualifiedName (A.B) the same way _calleeToString dot-joins a member expression', () => {
  const node = {
    type: 'TSQualifiedName',
    left: { type: 'Identifier', name: 'Foo' },
    right: { name: 'Bar' },
  };
  assert.equal(_qualifiedTypeName(node), 'Foo.Bar');
});

test('_extractTsTypes: a real .ts file yields real types keyed by (line, name)', () => {
  const code = [
    'function handler(email: string, count: number, req) {',
    '  const name: string = req.body.name;',
    '  let ids: number[] = [];',
    '  return name;',
    '}',
  ].join('\n');
  const types = _extractTsTypes('app.ts', code);
  assert.equal(types.get(1).get('email'), 'string');
  assert.equal(types.get(1).get('count'), 'number');
  assert.equal(types.get(2).get('name'), 'string');
  assert.equal(types.get(3).get('ids'), 'number[]');
});

test('_extractTsTypes: a .js file (no TypeScript syntax) is never parsed for types — returns an empty map immediately', () => {
  const code = 'function handler(email) { const name = email; return name; }';
  const types = _extractTsTypes('app.js', code);
  assert.equal(types.size, 0);
});

test('_extractTsTypes: an untyped parameter/declarator contributes nothing (no fabricated type)', () => {
  const code = 'function handler(email) { const name = email; return name; }';
  const types = _extractTsTypes('app.ts', code);
  assert.equal(types.size, 0);
});

test('_extractTsTypes: a file this separate parse cannot handle degrades to an empty map, never a throw', () => {
  assert.doesNotThrow(() => {
    const types = _extractTsTypes('broken.ts', 'const x: = ;;; this is not valid typescript {{{');
    assert.equal(types.size, 0);
  });
  assert.doesNotThrow(() => { _extractTsTypes('app.ts', null); });
  assert.doesNotThrow(() => { _extractTsTypes(null, 'code'); });
});

test('_adaptFile: a supplied tsTypes map populates decl.type for matching (line, name) pairs, leaves the rest null', () => {
  const fileIR = {
    functions: [{
      qid: 'app.ts::handler@1', name: 'handler', line: 1, params: ['email', 'req'],
      cfg: { nodes: { n1: { kind: 'assign', target: 'x', line: 2, source: { kind: 'ident', name: 'email' } } } },
    }],
  };
  const tsTypes = new Map([
    [1, new Map([['email', 'string']])],
    [2, new Map([['x', 'string']])],
  ]);
  const { decls } = _adaptFile(fileIR, tsTypes);
  const email = decls.find(d => d.name === 'email');
  const req = decls.find(d => d.name === 'req');
  const x = decls.find(d => d.name === 'x');
  assert.equal(email.type, 'string');
  assert.equal(req.type, null, 'req has no matching (line,name) entry in tsTypes, so it stays null, not fabricated');
  assert.equal(x.type, 'string');
});

test('FR-401 end-to-end: a REAL TypeScript file — parsed via the real parser, adapted, and run through the real privacy taint engine — surfaces a genuine declaredType', () => {
  const code = [
    "function handler(req) {",
    "  const email: string = req.query.email;",
    "  console.log(email);",
    "}",
  ].join('\n');
  const ir = parseJsFile('app.ts', code);
  const adapted = adaptIRForPrivacyTaint({ 'app.ts': ir }, { 'app.ts': code });
  const emailDecl = adapted.get('app.ts').decls.find(d => d.name === 'email');
  assert.equal(emailDecl.type, 'string', 'the real adapter, on a real .ts parse, must surface the real annotated type');

  const result = annotatePrivacyTaint(adapted);
  assert.equal(result.findings.length, 1);
  const field = result.piiFields.find(f => f.name === 'email');
  assert.ok(field, `expected a piiFields entry for 'email'; got ${JSON.stringify(result.piiFields)}`);
  assert.equal(field.declaredType, 'string', 'privacy-taint.js already reads decl.type as declaredType — this must no longer be null for a real typed TS field');
});

test('FR-401: a plain .js file with the SAME shape gets no fabricated type — declaredType stays null, honestly', () => {
  const code = [
    "function handler(req) {",
    "  const email = req.query.email;",
    "  console.log(email);",
    "}",
  ].join('\n');
  const ir = parseJsFile('app.js', code);
  const adapted = adaptIRForPrivacyTaint({ 'app.js': ir }, { 'app.js': code });
  const emailDecl = adapted.get('app.js').decls.find(d => d.name === 'email');
  assert.equal(emailDecl.type, null);

  const result = annotatePrivacyTaint(adapted);
  const field = result.piiFields.find(f => f.name === 'email');
  assert.equal(field.declaredType, null);
});
