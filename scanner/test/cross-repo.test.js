// v0.73 — cross-repo OpenAPI federation tests.

import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildFederatedGraph, federatedFindings, _internal } from '../src/dataflow/cross-repo.js';

const PRODUCER_SPEC = {
  repo: 'acme/auth-svc',
  specPath: 'openapi.yaml',
  specContent: `
openapi: "3.0.0"
info: { title: auth-svc, version: 1.0 }
paths:
  /users/{id}:
    get:
      operationId: getUser
      responses:
        '200':
          content:
            application/json:
              schema:
                type: object
                properties:
                  id:    { type: string }
                  email: { type: string }
                  bio:   { type: string }
`,
};

const CONSUMER_SPEC = {
  repo: 'acme/billing-svc',
  specPath: 'openapi.json',
  specContent: JSON.stringify({
    openapi: '3.0.0',
    info: { title: 'billing-svc', version: '1.0' },
    paths: {
      '/users/{id}': {
        get: {
          operationId: 'fetchUser',
          requestBody: {
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    email: { type: 'string' },
                    bio:   { type: 'string' },
                    plan:  { type: 'string' },
                  },
                },
              },
            },
          },
          responses: { '200': {} },
        },
      },
    },
  }),
};

test('_parseSpec: handles YAML + JSON contents', () => {
  const yamlDoc = _internal._parseSpec(PRODUCER_SPEC);
  assert.ok(yamlDoc);
  assert.ok(yamlDoc.paths['/users/{id}']);
  const jsonDoc = _internal._parseSpec(CONSUMER_SPEC);
  assert.ok(jsonDoc);
  assert.ok(jsonDoc.paths['/users/{id}']);
});

test('_endpointsFor: extracts response + request field paths', () => {
  const doc = _internal._parseSpec(PRODUCER_SPEC);
  const eps = _internal._endpointsFor(doc);
  assert.equal(eps.length, 1);
  assert.equal(eps[0].method, 'get');
  assert.deepEqual(eps[0].responseFields.sort(), ['bio', 'email', 'id']);
});

test('_leafPathsOf: recurses through nested object schemas', () => {
  const schema = {
    type: 'object',
    properties: {
      user: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          tags: { type: 'array', items: { type: 'string' } },
        },
      },
      total: { type: 'integer' },
    },
  };
  const paths = _internal._leafPathsOf(schema);
  assert.ok(paths.includes('user.name'));
  assert.ok(paths.some(p => p.startsWith('user.tags')));
  assert.ok(paths.includes('total'));
});

test('buildFederatedGraph: producer + consumer with shared fields produce an edge', () => {
  const graph = buildFederatedGraph([PRODUCER_SPEC, CONSUMER_SPEC]);
  assert.ok(graph.federatedEdges.length >= 1);
  const e = graph.federatedEdges[0];
  // Either direction is acceptable for v1 — we emit both producer→consumer
  // and consumer→producer edges.
  const repos = new Set([e.from.repo, e.to.repo]);
  assert.ok(repos.has('acme/auth-svc'));
  assert.ok(repos.has('acme/billing-svc'));
  assert.ok(e.sharedFields.length > 0);
  // The shared fields should include email + bio.
  assert.ok(e.sharedFields.some(f => ['email', 'bio'].includes(f)));
});

test('buildFederatedGraph: single-repo input produces no federated edges', () => {
  const graph = buildFederatedGraph([PRODUCER_SPEC]);
  assert.equal(graph.federatedEdges.length, 0);
});

test('buildFederatedGraph: repos with non-overlapping fields produce no edge', () => {
  const a = { repo: 'a', specPath: 'a.yaml', specContent: `
openapi: "3.0.0"
info: { title: a, version: 1 }
paths:
  /x:
    get:
      responses:
        '200': { content: { application/json: { schema: { type: object, properties: { foo: { type: string } } } } } }
` };
  const b = { repo: 'b', specPath: 'b.yaml', specContent: `
openapi: "3.0.0"
info: { title: b, version: 1 }
paths:
  /x:
    get:
      requestBody: { content: { application/json: { schema: { type: object, properties: { bar: { type: string } } } } } }
      responses: { '200': {} }
` };
  const graph = buildFederatedGraph([a, b]);
  // Same path, but no overlapping fields → no edge.
  assert.equal(graph.federatedEdges.length, 0);
});

test('federatedFindings: emits one finding per edge with cross-repo metadata', () => {
  const graph = buildFederatedGraph([PRODUCER_SPEC, CONSUMER_SPEC]);
  const findings = federatedFindings(graph);
  assert.ok(findings.length >= 1);
  for (const f of findings) {
    assert.equal(f.parser, 'CROSS-REPO');
    assert.equal(f.family, 'cross-repo-taint');
    assert.equal(f.cwe, 'CWE-829');
    assert.ok(f.crossRepo);
    assert.ok(Array.isArray(f.crossRepo.sharedFields));
    assert.ok(f.trace.length === 2);
    assert.equal(f.trace[0].kind, 'producer');
    assert.equal(f.trace[1].kind, 'consumer');
  }
});

test('federatedFindings: empty graph yields empty array', () => {
  assert.deepEqual(federatedFindings(null), []);
  assert.deepEqual(federatedFindings({ federatedEdges: [] }), []);
});
