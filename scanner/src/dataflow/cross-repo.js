// Cross-repo taint via service contracts (v0.73).
//
// Most SAST tools are repo-bound: scan service A, scan service B
// separately, never connect the dots. Real attacks chain across repos —
// service A's response field flows through service B's request handler
// into B's SQL query.
//
// This module is the federation layer. Given a collection of OpenAPI /
// gRPC specs from multiple repos, it:
//
//   1. Parses each spec, extracts endpoints + their response shapes
//   2. Resolves which endpoints are CONSUMED across the set (one repo's
//      client call → another repo's server route)
//   3. Emits cross-service findings tagged with both producer + consumer
//      repo identities + the federated path
//
// v1 scope: OpenAPI only (the cross-lang-openapi.js module already
// handles intra-repo flow; this is the inter-repo lift). gRPC + GraphQL
// federation are deferred — the gRPC posture module exists but its
// schema-extraction layer needs cross-repo alignment first.
//
// Each input is a `{ repo, specPath, specContent }` triple. The repo
// name is the GitHub slug ('owner/name'); specPath is relative within
// that repo; specContent is the raw YAML/JSON.

import * as yaml from 'js-yaml';

const METHODS = ['get', 'post', 'put', 'patch', 'delete', 'head', 'options'];

function _parseSpec(spec) {
  if (!spec || typeof spec.specContent !== 'string') return null;
  try {
    const doc = /\.json$/i.test(spec.specPath || '')
      ? JSON.parse(spec.specContent)
      : yaml.load(spec.specContent);
    if (!doc || !doc.paths) return null;
    return doc;
  } catch { return null; }
}

function _endpointsFor(doc) {
  if (!doc || !doc.paths) return [];
  const out = [];
  for (const [p, methods] of Object.entries(doc.paths)) {
    for (const m of Object.keys(methods)) {
      if (!METHODS.includes(m.toLowerCase())) continue;
      const op = methods[m];
      out.push({
        method: m.toLowerCase(),
        path: p,
        responseFields: _responseFields(op),
        requestFields: _requestFields(op),
        operationId: op.operationId,
        summary: op.summary || op.description || '',
      });
    }
  }
  return out;
}

// Extract leaf field paths from an OpenAPI schema. Recursively walks
// `properties` returning dotted access paths ('user.email', 'items.0.name').
function _leafPathsOf(schema, prefix = '', depth = 0) {
  if (!schema || depth > 6) return [];
  if (schema.properties) {
    const out = [];
    for (const [k, v] of Object.entries(schema.properties)) {
      const p = prefix ? `${prefix}.${k}` : k;
      out.push(...(_leafPathsOf(v, p, depth + 1) || [p]));
    }
    return out;
  }
  if (schema.type === 'array' && schema.items) {
    return _leafPathsOf(schema.items, prefix ? `${prefix}[]` : '[]', depth + 1);
  }
  return prefix ? [prefix] : [];
}

function _responseFields(op) {
  if (!op || !op.responses) return [];
  const out = [];
  for (const [code, resp] of Object.entries(op.responses)) {
    if (!/^2/.test(code) && code !== 'default') continue;
    const content = resp.content || {};
    for (const mt of Object.values(content)) {
      if (mt.schema) out.push(..._leafPathsOf(mt.schema));
    }
  }
  return [...new Set(out)];
}

function _requestFields(op) {
  if (!op) return [];
  const out = [];
  if (op.requestBody && op.requestBody.content) {
    for (const mt of Object.values(op.requestBody.content)) {
      if (mt.schema) out.push(..._leafPathsOf(mt.schema));
    }
  }
  if (Array.isArray(op.parameters)) {
    for (const p of op.parameters) if (p && p.name) out.push(p.name);
  }
  return [...new Set(out)];
}

/**
 * Build the federated endpoint graph across a set of specs.
 *
 * Input:
 *   specs: Array<{ repo: 'owner/name', specPath, specContent }>
 *
 * Output:
 *   {
 *     producers: Map<'METHOD PATH', { repo, endpoint }[]>,
 *     consumers: Map<'METHOD PATH', { repo, endpoint }[]>,
 *     federatedEdges: [
 *       {
 *         from: { repo, method, path, fields: string[] },
 *         to:   { repo, method, path, fields: string[] },
 *         sharedFields: string[],
 *       }
 *     ]
 *   }
 *
 * A producer is anyone who DEFINES an endpoint (responses field). A
 * consumer is anyone who DECLARES a client dependency on that endpoint
 * via an `x-consumes` extension OR a matching `operationId` in a
 * `dependsOn` block. v1 uses a simpler heuristic: every pair of specs
 * containing the same `(method, path)` is an edge — the assumption is
 * that distinct repos publishing the same path means one consumes from
 * the other.
 */
export function buildFederatedGraph(specs) {
  const producers = new Map();    // 'GET /users/:id' → endpoints[]
  for (const spec of (specs || [])) {
    const doc = _parseSpec(spec);
    if (!doc) continue;
    for (const ep of _endpointsFor(doc)) {
      const key = `${ep.method.toUpperCase()} ${ep.path}`;
      if (!producers.has(key)) producers.set(key, []);
      producers.get(key).push({ repo: spec.repo, endpoint: ep });
    }
  }
  // Federated edges: every pair of repos publishing the same (method, path)
  // is treated as a producer→consumer edge. The producer side is the spec
  // that declares the response shape; the consumer the one that declares
  // a matching request.
  const federatedEdges = [];
  for (const [key, entries] of producers) {
    if (entries.length < 2) continue;
    for (let i = 0; i < entries.length; i++) {
      for (let j = 0; j < entries.length; j++) {
        if (i === j) continue;
        const from = entries[i];
        const to   = entries[j];
        // Heuristic: if `from` declares responseFields and `to` declares
        // requestFields with overlap, an edge exists.
        const shared = from.endpoint.responseFields.filter(f =>
          to.endpoint.requestFields.includes(f));
        if (shared.length === 0) continue;
        federatedEdges.push({
          from: {
            repo: from.repo, method: from.endpoint.method, path: from.endpoint.path,
            fields: from.endpoint.responseFields,
          },
          to: {
            repo: to.repo, method: to.endpoint.method, path: to.endpoint.path,
            fields: to.endpoint.requestFields,
          },
          sharedFields: shared,
        });
      }
    }
  }
  return { producers, federatedEdges };
}

/**
 * Render a list of cross-service findings from the federated graph. Each
 * edge becomes one finding tagged `family: 'cross-repo-taint'` with both
 * repos + the shared fields in the trace.
 */
export function federatedFindings(graph) {
  if (!graph || !Array.isArray(graph.federatedEdges)) return [];
  const findings = [];
  for (const edge of graph.federatedEdges) {
    findings.push({
      id: `cross-repo:${edge.from.repo}:${edge.from.method}:${edge.from.path}->${edge.to.repo}`,
      file: `(cross-repo: ${edge.from.repo})`,
      line: 0,
      vuln: `Cross-service data flow: ${edge.from.repo} → ${edge.to.repo}`,
      severity: 'medium',
      cwe: 'CWE-829',                 // Inclusion of Functionality from Untrusted Control Sphere
      family: 'cross-repo-taint',
      parser: 'CROSS-REPO',
      confidence: 0.65,
      description:
        `${edge.from.repo} declares the endpoint ${edge.from.method.toUpperCase()} ${edge.from.path} ` +
        `whose response carries ${edge.sharedFields.join(', ')}. ` +
        `${edge.to.repo} consumes the same endpoint and feeds those fields into its request shape. ` +
        `Any taint in the producer's response surfaces in the consumer's input — sanitization MUST happen at the consumer boundary.`,
      remediation:
        'Add a contract-test fixture in the consumer that asserts each shared field passes its sanitizer at request-handler entry. ' +
        'If the producer is third-party, treat the response as untrusted: validate length/charset before downstream use.',
      trace: [
        { kind: 'producer', label: `${edge.from.repo}: ${edge.from.method} ${edge.from.path}`, line: 0 },
        { kind: 'consumer', label: `${edge.to.repo}: ${edge.to.method} ${edge.to.path}`, line: 0 },
      ],
      crossRepo: {
        from: edge.from.repo,
        to: edge.to.repo,
        sharedFields: edge.sharedFields,
      },
    });
  }
  return findings;
}

export const _internal = { _parseSpec, _endpointsFor, _leafPathsOf, _responseFields, _requestFields };
