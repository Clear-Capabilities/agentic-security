// FR-PROD-2 — Production telemetry ingest.
//
// Build a route → request-count map from a customer-supplied telemetry
// digest. The customer-side shim is responsible for producing the digest
// (no PII; counts and rates only). Expected format at
// `.agentic-security/telemetry.json`:
//
//   {
//     "windowDays": 30,
//     "routes": {
//       "GET /api/health":      { "count": 42000, "lastSeen": "2026-05-17T..." },
//       "POST /admin/users":    { "count": 0,     "lastSeen": null },
//       "POST /api/webhooks":   { "count": 8800,  "lastSeen": "2026-05-18T..." }
//     }
//   }
//
// Findings whose location matches a route with 0 requests over the window
// get `coldPath: true` and a confidence dampener — likely the code path is
// behind a flag or dead. Findings on hot paths (>1k req/30d) get
// `hotPath: true` and a small priority bump.
//
// We deliberately do NOT call Sentry/Datadog APIs from this module. The
// customer-side shim is in PRD as a separate workstream because cross-vendor
// API access in the scanner has too many privacy and auth-token concerns.

import * as fs from 'node:fs';
import * as path from 'node:path';

const CANDIDATE_PATHS = [
  '.agentic-security/telemetry.json',
  '.agentic-security/prod-telemetry.json',
];

const HOT_THRESHOLD = 1000;     // requests / window — promotes to hot
const COLD_THRESHOLD = 0;       // exactly zero requests → cold

export function loadTelemetry(scanRoot) {
  const root = scanRoot || process.cwd();
  for (const rel of CANDIDATE_PATHS) {
    const fp = path.join(root, rel);
    if (!fs.existsSync(fp)) continue;
    try {
      const data = JSON.parse(fs.readFileSync(fp, 'utf8'));
      if (data && typeof data === 'object' && data.routes) return data;
    } catch {}
  }
  return null;
}

// Heuristic: extract a route-shape signal from a finding's file path or
// content. Returns null when no route is inferable.
function routeShapeFor(f) {
  const fp = String(f.file || '');
  const inferred = [];
  // Next.js / SvelteKit / Remix style.
  let m;
  if ((m = /\/(?:app|pages|routes)\/(.+?)(?:\/route\.[a-z]+|\.[a-z]+)$/i.exec(fp))) {
    let r = '/' + m[1].replace(/\/(?:index|page|route)$/i, '');
    r = r.replace(/\[([^\]]+)\]/g, ':$1');
    inferred.push('* ' + r);
  }
  // Express / FastAPI / Flask: search the file snippet for app.METHOD('/path', ...)
  if (f.snippet && typeof f.snippet === 'string') {
    const sm = /app\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/i.exec(f.snippet);
    if (sm) inferred.push(`${sm[1].toUpperCase()} ${sm[2]}`);
  }
  return inferred.length ? inferred : null;
}

// Match a finding's inferred routes against the telemetry route map.
// Telemetry routes are like "GET /api/health"; finding routes may have
// `:param` placeholders. Use a permissive parameter-equivalence match.
function findRouteEntry(routes, candidates) {
  if (!routes || !candidates) return null;
  const norm = (s) => s.replace(/:\w+|\{\w+\}/g, '_PARAM_').trim();
  for (const c of candidates) {
    const cn = norm(c);
    for (const [route, info] of Object.entries(routes)) {
      if (norm(route) === cn) return info;
      // method-agnostic match for cases where the finding only knows the path
      const cmStar = cn.startsWith('* ');
      if (cmStar) {
        const cpath = cn.slice(2);
        if (norm(route).endsWith(' ' + cpath)) return info;
      }
    }
  }
  return null;
}

export function annotateTelemetry(findings, scanRoot) {
  if (!Array.isArray(findings)) return findings;
  const telem = loadTelemetry(scanRoot);
  if (!telem) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const candidates = routeShapeFor(f);
    if (!candidates) continue;
    const entry = findRouteEntry(telem.routes, candidates);
    if (!entry) continue;
    f.prodRequestCount = entry.count || 0;
    f.prodLastSeen = entry.lastSeen || null;
    if ((entry.count || 0) <= COLD_THRESHOLD) {
      f.coldPath = true;
      if (typeof f.confidence === 'number') f.confidence = Math.max(0, f.confidence - 0.08);
    } else if ((entry.count || 0) >= HOT_THRESHOLD) {
      f.hotPath = true;
      if (typeof f.confidence === 'number') f.confidence = Math.min(1, f.confidence + 0.05);
    }
  }
  return findings;
}
