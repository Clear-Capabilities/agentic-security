// FR-PROD-3 — Auth / RBAC posture import.
//
// Read a normalized auth-posture digest from `.agentic-security/auth-posture.json`
// or `auth-posture.yml`. The digest lists each route and the auth mechanism
// (if any) that gates it. A finding on a route that's gated by a known-good
// auth mechanism gets demoted to `mitigated-by-auth`.
//
// Recommended format:
//
//   {
//     "provider": "clerk",
//     "routes": {
//       "POST /api/users":         { "auth": "session+csrf",  "claims": ["user"] },
//       "POST /admin/users":       { "auth": "session+admin", "claims": ["admin"] },
//       "POST /api/webhooks":      { "auth": "stripe-signature" },
//       "GET  /api/public/status": { "auth": "none" }
//     }
//   }
//
// We treat the following `auth` values as KNOWN-GOOD mitigators:
//   session+csrf, session+admin, session+claim, jwt+verify, oauth+pkce,
//   stripe-signature, github-signature, svix-signature, clerk-session,
//   nextauth-session, okta-session, mtls
//
// Anything else (`none`, `unknown`, custom names) is treated as ungated.

import * as fs from 'node:fs';
import * as path from 'node:path';

const KNOWN_GOOD = new Set([
  'session+csrf', 'session+admin', 'session+claim', 'session',
  'jwt+verify', 'oauth+pkce', 'mtls',
  'stripe-signature', 'github-signature', 'svix-signature', 'clerk-webhook-signature',
  'clerk-session', 'nextauth-session', 'okta-session', 'auth0-session',
  'workos-session', 'lucia-session',
]);

const FAMILIES_GATEABLE_BY_AUTH = new Set([
  'idor', 'missing-authz', 'broken-auth', 'mass-assignment', 'csrf',
  'webhook-no-signature',
]);

const CANDIDATE_PATHS = [
  '.agentic-security/auth-posture.json',
  '.agentic-security/auth-posture.yml',
  '.agentic-security/auth-posture.yaml',
];

export function loadAuthPosture(scanRoot) {
  const root = scanRoot || process.cwd();
  for (const rel of CANDIDATE_PATHS) {
    const fp = path.join(root, rel);
    if (!fs.existsSync(fp)) continue;
    try {
      const text = fs.readFileSync(fp, 'utf8');
      const trimmed = text.trim();
      if (trimmed.startsWith('{')) return JSON.parse(trimmed);
      // YAML-lite: only the structure we recommend
      const out = { routes: {} };
      let currentRoute = null;
      for (const raw of text.split(/\n/)) {
        const ln = raw.replace(/#.*$/, '');
        const routeM = /^\s+"?([A-Z]+\s+\/[^"\s]+)"?\s*:\s*$/.exec(ln);
        if (routeM) { currentRoute = routeM[1]; out.routes[currentRoute] = {}; continue; }
        const kvM = /^\s+(\w+):\s*['"]?([^'"\s][^'"]*)['"]?\s*$/.exec(ln);
        if (kvM && currentRoute) out.routes[currentRoute][kvM[1]] = kvM[2];
      }
      if (Object.keys(out.routes).length) return out;
    } catch {}
  }
  return null;
}

function routeShapeFor(f) {
  const fp = String(f.file || '');
  const out = [];
  let m;
  if ((m = /\/(?:app|pages|routes)\/(.+?)(?:\/route\.[a-z]+|\.[a-z]+)$/i.exec(fp))) {
    let r = '/' + m[1].replace(/\/(?:index|page|route)$/i, '');
    r = r.replace(/\[([^\]]+)\]/g, ':$1');
    out.push('* ' + r);
  }
  if (f.snippet) {
    const sm = /app\.(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/i.exec(f.snippet);
    if (sm) out.push(`${sm[1].toUpperCase()} ${sm[2]}`);
  }
  return out;
}

function familyOf(f) {
  if (f.family) return String(f.family).toLowerCase();
  const v = (f.vuln || '').toLowerCase();
  if (/idor/.test(v)) return 'idor';
  if (/missing.auth/.test(v)) return 'missing-authz';
  if (/broken.auth|jwt|session/.test(v)) return 'broken-auth';
  if (/mass.assignment/.test(v)) return 'mass-assignment';
  if (/csrf/.test(v)) return 'csrf';
  if (/webhook.*sign/.test(v)) return 'webhook-no-signature';
  return null;
}

function matchRoute(routes, candidates) {
  if (!routes || !candidates) return null;
  const norm = (s) => s.replace(/:\w+|\{\w+\}/g, '_PARAM_').trim();
  for (const c of candidates) {
    const cn = norm(c);
    for (const [route, info] of Object.entries(routes)) {
      if (norm(route) === cn) return { route, info };
      if (cn.startsWith('* ') && norm(route).endsWith(' ' + cn.slice(2))) return { route, info };
    }
  }
  return null;
}

export function annotateAuthMitigation(findings, scanRoot) {
  if (!Array.isArray(findings)) return findings;
  const posture = loadAuthPosture(scanRoot);
  if (!posture || !posture.routes) return findings;
  for (const f of findings) {
    if (!f || typeof f !== 'object') continue;
    const fam = familyOf(f);
    if (!fam || !FAMILIES_GATEABLE_BY_AUTH.has(fam)) continue;
    const candidates = routeShapeFor(f);
    if (!candidates.length) continue;
    const matched = matchRoute(posture.routes, candidates);
    if (!matched) continue;
    const auth = matched.info?.auth || '';
    if (KNOWN_GOOD.has(auth)) {
      f.mitigatedByAuth = true;
      f.authMechanism = auth;
      f.authMatchedRoute = matched.route;
    }
  }
  return findings;
}
