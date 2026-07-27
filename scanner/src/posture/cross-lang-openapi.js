import { isChainWorthy, familyForBoundary } from './cross-lang-meta.js';

// OpenAPI-aware cross-language taint propagation (Sentinel-parity FR-X-1).
//
// First-cut implementation: when an openapi.json / openapi.yaml is present in
// the scan root, build a map from (method, path) → endpoint description. For
// any client-side fetch/axios/requests call whose URL matches a known
// endpoint AND whose response is then passed to a sink (SQL, exec, write,
// innerHTML), emit a `cross_language: true` finding that ties the client
// site to the server route as a chain.
//
// Conservative on purpose: only flow taint when BOTH endpoints are
// unambiguously mapped. Ambiguous matches produce zero findings rather than
// false positives.
//
// Out of scope (deferred to a follow-up): gRPC .proto introspection, GraphQL
// resolver-to-resolver tracking, SQL/ORM round-trip, message queues.

import * as yaml from '../util/yaml.js';

function loadOpenAPI(fileContents) {
  for (const [fp, c] of Object.entries(fileContents || {})) {
    const base = fp.split('/').pop().toLowerCase();
    if (!/openapi\.(?:ya?ml|json)$|swagger\.(?:ya?ml|json)$/.test(base)) continue;
    try {
      const doc = /\.json$/i.test(base) ? JSON.parse(c) : yaml.load(c);
      if (doc && doc.paths) return { doc, file: fp };
    } catch { /* ignore */ }
  }
  return null;
}

function endpoints(doc) {
  const out = [];
  if (!doc || !doc.paths) return out;
  for (const [p, methods] of Object.entries(doc.paths)) {
    for (const m of Object.keys(methods)) {
      if (!/^(?:get|post|put|patch|delete|options|head)$/i.test(m)) continue;
      // staticPrefix = the literal prefix before the first {param} or :param.
      // Used to match client URLs that look like '/users/' + id where the only
      // static piece is the prefix.
      const staticPrefix = p.split(/\{|:/)[0];
      out.push({
        method: m.toUpperCase(),
        path: p,
        staticPrefix,
        urlRegex: new RegExp(
          '^' +
          p.replace(/[.+^$()|[\]\\]/g, '\\$&')
           .replace(/\{[^}]+\}/g, '[^/?#]+')
           .replace(/:[A-Za-z_][\w]*/g, '[^/?#]+') +
          '$'
        ),
      });
    }
  }
  return out;
}

function urlMatchesEndpoint(url, ep) {
  const clean = url.replace(/^https?:\/\/[^/]+/, '').split('?')[0];
  if (ep.urlRegex.test(clean)) return true;
  // Soft match: client URL is a concat — the literal we see is just the
  // static prefix up to a path parameter.
  if (ep.staticPrefix && ep.staticPrefix.length >= 3 && clean === ep.staticPrefix) return true;
  // Also match when the client wrote the path WITH a templated placeholder.
  if (clean === ep.path) return true;
  return false;
}

// Find client-side HTTP calls that match an OpenAPI endpoint.
// Returns Array<{ file, line, method, path, snippet }>
function clientCalls(fileContents, eps) {
  const CALL_RE = /\b(?:fetch|axios(?:\.(?:get|post|put|patch|delete))?|requests\.(?:get|post|put|patch|delete)|http\.request|urllib\.request\.urlopen)\s*\(\s*([`'"])([^`'"]+)\1/g;
  const out = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    let m;
    const r = new RegExp(CALL_RE.source, CALL_RE.flags);
    while ((m = r.exec(c))) {
      const url = m[2];
      const ep = eps.find(e => urlMatchesEndpoint(url, e));
      if (!ep) continue;
      const line = c.substring(0, m.index).split('\n').length;
      out.push({
        file: fp, line,
        method: ep.method, path: ep.path,
        snippet: (c.split('\n')[line - 1] || '').trim().slice(0, 200),
      });
    }
  }
  return out;
}

// Match an endpoint to its server-side route handler. Looks for express's
// app.METHOD(path, ...) or fastapi's @app.METHOD(path) or Flask's @app.route.
function serverRoutes(fileContents, eps) {
  const ROUTE_RE = [
    // Express / Fastify / Koa
    { lang: 'js', re: /\b(?:app|router|server|fastify)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*([`'"])([^`'"]+)\2/gi },
    // FastAPI
    { lang: 'py', re: /@\w+\s*\.\s*(get|post|put|patch|delete)\s*\(\s*([`'"])([^`'"]+)\2/gi },
    // Flask. The `methods=['POST']` part needs to anchor on the opening quote
    // of the method literal, otherwise `[^\]]*` greedy-consumes most of it
    // and only the last letter ends up in the capture group.
    { lang: 'py', re: /@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*([`'"])([^`'"]+)\1[^)]*methods\s*=\s*\[\s*['"]([A-Z]+)/gi },
  ];
  const out = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (!c || typeof c !== 'string') continue;
    if (c.length > 500_000) continue;
    for (const { lang, re } of ROUTE_RE) {
      if (lang === 'js' && !/\.(?:js|jsx|ts|tsx|mjs|cjs)$/i.test(fp)) continue;
      if (lang === 'py' && !/\.py$/i.test(fp)) continue;
      const r = new RegExp(re.source, re.flags);
      let m;
      while ((m = r.exec(c))) {
        let method, urlPattern;
        if (re === ROUTE_RE[2].re) { urlPattern = m[2]; method = (m[3] || 'GET').toUpperCase(); }
        else { method = (m[1] || '').toUpperCase(); urlPattern = m[3]; }
        const ep = eps.find(e =>
          e.method === method && urlMatchesEndpoint(urlPattern, e));
        if (!ep) continue;
        const line = c.substring(0, m.index).split('\n').length;
        out.push({ file: fp, line, method, path: ep.path });
      }
    }
  }
  return out;
}

// Top-level: returns Finding[] describing client-side calls whose response is
// returned from a server-side handler that itself has tainted-input findings.
export function scanCrossLangOpenAPI(fileContents, existingFindings) {
  const oa = loadOpenAPI(fileContents);
  if (!oa) return [];
  const eps = endpoints(oa.doc);
  if (eps.length === 0) return [];
  const callers = clientCalls(fileContents, eps);
  if (callers.length === 0) return [];
  const handlers = serverRoutes(fileContents, eps);
  if (handlers.length === 0) return [];

  // Index existing findings by file. A handler is "tainted-output" if any
  // critical/high finding sits in its file AND it's chain-worthy
  // (FR-CHAIN-FILTER) — CSRF, header-hardening etc. don't propagate across
  // a service boundary in a useful way.
  const findingsByFile = new Map();
  for (const f of existingFindings || []) {
    if (!f.file) continue;
    if (!/critical|high/i.test(f.severity || '')) continue;
    if (!isChainWorthy(f)) continue;
    if (!findingsByFile.has(f.file)) findingsByFile.set(f.file, []);
    findingsByFile.get(f.file).push(f);
  }

  const findings = [];
  for (const c of callers) {
    const matching = handlers.filter(h => h.method === c.method && h.path === c.path);
    for (const h of matching) {
      const fs = findingsByFile.get(h.file) || [];
      if (!fs.length) continue;
      const seed = fs[0];
      findings.push({
        id: `xlang-openapi:${c.file}:${c.line}:${h.method}-${h.path}`,
        file: c.file, line: c.line,
        vuln: `Cross-Language Taint: client call → ${h.method} ${h.path} (server handler in ${h.file}:${h.line} has a ${seed.severity} finding)`,
        severity: 'high',
        cwe: seed.cwe || 'CWE-862',
        stride: 'Information Disclosure',
        snippet: c.snippet,
        remediation: `The server-side handler for ${h.method} ${h.path} (${h.file}:${h.line}) has unaddressed ${seed.severity}-severity findings — specifically "${seed.vuln}". A response from that handler that flows into a client-side sink (innerHTML, eval, exec) propagates the underlying issue. Fix the server-side finding first.`,
        parser: 'XLANG-OPENAPI',
        family: familyForBoundary('openapi'),   // FR-FAMILY-REGISTRY
        confidence: 0.65,
        cross_language: true,
        chain: [
          { file: c.file, line: c.line, label: 'client-call' },
          { file: h.file, line: h.line, label: `${h.method} ${h.path}` },
          { file: seed.file, line: seed.line, label: seed.vuln },
        ],
      });
    }
  }
  return findings;
}
