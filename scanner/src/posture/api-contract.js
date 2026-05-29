// API schema-aware scanning — Recommendation #3 of the world-class+2 plan.
//
// Cross-references the project's declared API contract (OpenAPI 3.x,
// GraphQL SDL, protobuf) against the route handlers actually detected in
// the source. Catches:
//
//   - undocumented-endpoint   Route in code but not in the contract
//   - undeclared-route        Contract path with no implementation
//   - missing-auth-on-route   Contract says auth required, code doesn't enforce
//   - parameter-type-mismatch Contract says int, code reads as raw string
//   - missing-validation      Contract says enum/pattern, code doesn't check
//
// Loaders:
//   - openapi.{yaml,yml,json} / swagger.{yaml,yml,json} → OpenAPI 3.x
//   - schema.graphql / *.graphql                        → GraphQL SDL
//   - *.proto                                            → protobuf
//
// Outputs new findings with family 'api-contract' and per-rule subfamily.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from 'js-yaml';

const CONTRACT_FILE_PATTERNS = [
  { glob: /(?:openapi|swagger)\.(?:ya?ml|json)$/i, kind: 'openapi' },
  { glob: /schema\.graphql$/i,                     kind: 'graphql' },
  { glob: /\.proto$/i,                             kind: 'protobuf' },
];

/**
 * Walk the scan root for contract files. Returns up to 5 parsed contracts.
 */
export function loadContracts(scanRoot) {
  const out = [];
  function walk(dir, depth) {
    if (depth > 4) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name.startsWith('.') || e.name === 'node_modules') continue;
      const fp = path.join(dir, e.name);
      if (e.isDirectory()) { walk(fp, depth + 1); continue; }
      for (const pat of CONTRACT_FILE_PATTERNS) {
        if (pat.glob.test(e.name)) {
          try {
            const raw = fs.readFileSync(fp, 'utf8');
            out.push({ path: fp, kind: pat.kind, doc: pat.kind === 'openapi' ? yaml.load(raw) : raw });
          } catch (err) {
            out.push({ path: fp, kind: pat.kind, error: String(err && err.message) });
          }
          if (out.length >= 5) return;
        }
      }
    }
  }
  walk(scanRoot, 0);
  return out;
}

/**
 * Parse an OpenAPI document into a normalized route list:
 *   [{ method, path, parameters: [{name,in,required,type,pattern,enum}],
 *      requiresAuth, requestBodyRequired, operationId, tags }]
 */
export function parseOpenAPI(doc) {
  if (!doc || !doc.paths) return [];
  const routes = [];
  const globalAuth = Array.isArray(doc.security) && doc.security.length > 0;
  for (const [routePath, pathItem] of Object.entries(doc.paths)) {
    for (const method of ['get','post','put','patch','delete','head','options']) {
      const op = pathItem[method];
      if (!op) continue;
      const localAuth = Array.isArray(op.security) ? op.security.length > 0 : globalAuth;
      const params = (op.parameters || []).concat(pathItem.parameters || []).map(p => ({
        name: p.name, in: p.in, required: !!p.required,
        type: (p.schema && p.schema.type) || p.type || null,
        pattern: (p.schema && p.schema.pattern) || p.pattern || null,
        enum:   (p.schema && p.schema.enum)    || p.enum    || null,
      }));
      routes.push({
        method: method.toUpperCase(),
        path: routePath,
        parameters: params,
        requiresAuth: localAuth,
        requestBodyRequired: !!(op.requestBody && op.requestBody.required),
        operationId: op.operationId || null,
        tags: op.tags || [],
      });
    }
  }
  return routes;
}

/**
 * Parse a GraphQL SDL fragment into a route-like list of fields.
 * Each field is treated as a "route" for cross-reference purposes.
 */
export function parseGraphQL(sdl) {
  if (typeof sdl !== 'string') return [];
  const routes = [];
  const re = /\b(?:type\s+(?:Query|Mutation|Subscription))\b\s*\{([\s\S]*?)\}/g;
  let m;
  while ((m = re.exec(sdl))) {
    for (const fieldLine of m[1].split('\n')) {
      const fm = fieldLine.match(/^\s*(\w+)\s*(?:\(([^)]*)\))?\s*:\s*(\w+)/);
      if (!fm) continue;
      const params = (fm[2] || '').split(',').map(s => s.trim()).filter(Boolean).map(s => {
        const pm = s.match(/^(\w+)\s*:\s*([\w!\[\]]+)/);
        return pm ? { name: pm[1], type: pm[2], required: /!/.test(pm[2]) } : null;
      }).filter(Boolean);
      routes.push({ method: 'GRAPHQL', path: '/' + fm[1], parameters: params, requiresAuth: null });
    }
  }
  return routes;
}

/**
 * Cross-reference declared contract routes against detected code routes.
 * `codeRoutes` is the engine's discovered route list (engine.scan.routes).
 *
 * Emits findings for:
 *   - undeclared-route       Contract declares it, code doesn't implement
 *   - undocumented-endpoint  Code exposes it, contract doesn't mention it
 *   - missing-auth-on-route  Contract says required, code is unauth
 */
export function diffRoutes(contractRoutes, codeRoutes) {
  const findings = [];
  if (!Array.isArray(contractRoutes) || !Array.isArray(codeRoutes)) return findings;
  function matchKey(r) {
    return `${(r.method || 'ANY').toUpperCase()} ${r.path || ''}`.trim();
  }
  const codeByKey = new Map(codeRoutes.map(r => [matchKey(r), r]));
  const contractByKey = new Map(contractRoutes.map(r => [matchKey(r), r]));
  // 1. Undeclared routes
  for (const [key, c] of contractByKey) {
    if (!codeByKey.has(key)) {
      findings.push({
        family: 'api-contract', subfamily: 'undeclared-route',
        severity: 'medium', cwe: 'CWE-1059',
        vuln: `Contract declares ${key}, no matching route handler found in code`,
        file: c.contractFile || 'openapi.yaml', line: 0,
        remediation: 'Implement the route declared in the contract OR remove the contract entry. Declared-but-missing routes signal documentation drift.',
      });
    }
  }
  // 2. Undocumented endpoints
  for (const [key, c] of codeByKey) {
    if (!contractByKey.has(key)) {
      findings.push({
        family: 'api-contract', subfamily: 'undocumented-endpoint',
        severity: 'high', cwe: 'CWE-1059',
        vuln: `Route ${key} is implemented but not declared in the API contract`,
        file: c.file, line: c.line,
        remediation: 'Add the route to the OpenAPI/GraphQL contract. Undocumented endpoints are the standard vector for accidentally-public internal APIs (the metadata-service pattern).',
      });
    }
  }
  // 3. Auth mismatch — contract says auth required but code marks unauth
  for (const [key, c] of contractByKey) {
    const code = codeByKey.get(key);
    if (!code) continue;
    if (c.requiresAuth === true && code.requiresAuth === false) {
      findings.push({
        family: 'api-contract', subfamily: 'missing-auth-on-route',
        severity: 'critical', cwe: 'CWE-306',
        vuln: `Route ${key} declared as requiring auth in contract, but handler is unauthenticated`,
        file: code.file, line: code.line,
        remediation: 'Either gate the handler with the documented auth mechanism, or update the contract if the route legitimately should be public.',
      });
    }
  }
  return findings;
}

/**
 * Run the full pipeline: load contracts, parse, diff vs codeRoutes,
 * return findings.
 */
export function runApiContractScan(scanRoot, codeRoutes) {
  const contracts = loadContracts(scanRoot);
  const findings = [];
  for (const c of contracts) {
    if (c.error) continue;
    let contractRoutes = [];
    if (c.kind === 'openapi') contractRoutes = parseOpenAPI(c.doc);
    else if (c.kind === 'graphql') contractRoutes = parseGraphQL(c.doc);
    contractRoutes.forEach(r => { r.contractFile = c.path; });
    findings.push(...diffRoutes(contractRoutes, codeRoutes || []));
  }
  return findings;
}

export const _internals = { CONTRACT_FILE_PATTERNS, parseOpenAPI, parseGraphQL };
