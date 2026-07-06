// R19 (PRD §5) — OWASP API Top 10: Broken Object/Function Level Authorization.
//
// The data-layer IDOR detector (engine.js) catches `findById(req.params.id)`
// without an ownership clause. This complements it at the ROUTE-INVENTORY
// layer, where the highest-signal tell is INCONSISTENCY: a route registered in
// a file whose siblings are authenticated, but which itself has no auth.
//
//   BFLA (API5): a state-changing route (POST/PUT/PATCH/DELETE) with no auth
//                while sibling routes in the same file do enforce it.
//   BOLA (API1): a route taking an object identifier (:id / {id} / <id>) with
//                no auth, so object-level ownership cannot be enforced.
//
// Precision: we only fire inside files that DO authenticate some routes (an
// authenticated API surface) — a fully-public API isn't flagged, and the
// inconsistency is what makes a missing check a likely bug rather than intent.

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const ID_PARAM = /\/(?::\w*(?:id|key|uuid|guid|slug)\w*|\{\w*(?:id|key|uuid|guid|slug)\w*\}|<\w*(?:id|key|uuid|guid|slug)\w*>)/i;

function mk(r, kind, api, cwe, why) {
  return {
    id: `api-authz:${kind}:${r.file}:${r.line}`,
    severity: 'high',
    file: r.file,
    line: r.line || 0,
    vuln: `Broken ${kind === 'BOLA' ? 'Object' : 'Function'} Level Authorization (${api})`,
    cwe,
    family: 'broken-access-control',
    parser: 'API-AUTHZ',
    description: why,
    remediation: kind === 'BOLA'
      ? 'Authenticate the route and verify the caller owns the referenced object (scope the lookup by req.user.id / tenantId), don\'t trust the id from the request alone.'
      : 'Apply the same authentication/authorization middleware the sibling routes use; state-changing endpoints must enforce a role/permission check.',
  };
}

// #9 — CWE-306 missing authentication for a state-changing route.
function mk306(r) {
  return {
    id: `api-authz:missing-auth:${r.file}:${r.line}`,
    severity: 'high',
    file: r.file,
    line: r.line || 0,
    vuln: `Missing authentication for a state-changing route (${r.method} ${r.path})`,
    cwe: '306',
    family: 'broken-access-control',
    parser: 'API-AUTHZ',
    subfamily: 'missing-auth',
    description: `${r.method} ${r.path} performs a destructive/state-changing operation with no authentication, while other routes in this app DO enforce it — so auth-detection demonstrably works here. An unauthenticated ${r.method} lets anyone invoke it (delete/modify another user's data).`,
    remediation: 'Require authentication on this route (the same middleware/guard the app uses elsewhere) and, for object routes, verify the caller owns the target object.',
  };
}

/**
 * Cross-route analysis over the aggregated route inventory (aR).
 * Pure: takes routes[], returns Finding[].
 */
export function scanApiBrokenAuthz(routes) {
  if (!Array.isArray(routes) || routes.length < 2) return [];
  const byFile = new Map();
  for (const r of routes) {
    if (!r || r.path === '(file-based)' || !r.file) continue;
    if (!byFile.has(r.file)) byFile.set(r.file, []);
    byFile.get(r.file).push(r);
  }
  const findings = [];
  const seen = new Set();
  const push = (f) => { const k = `${f.file}:${f.line}`; if (seen.has(k)) return; seen.add(k); findings.push(f); };
  for (const group of byFile.values()) {
    if (group.length < 2) continue;
    const authed = group.filter((r) => r.hasAuth).length;
    // Only an authenticated API surface — at least one protected sibling, but
    // not all (otherwise there's no inconsistency to flag).
    if (authed < 1 || authed === group.length) continue;
    for (const r of group) {
      if (r.hasAuth) continue;
      const idParam = ID_PARAM.test(r.path || '');
      if (idParam) {
        push(mk(r, 'BOLA', 'API1', '639',
          `${r.method} ${r.path} takes an object identifier but enforces no authorization, while ${authed}/${group.length} sibling routes do. Object-level ownership cannot be enforced — an attacker can substitute another user's id.`));
      } else if (STATE_CHANGING.has(r.method)) {
        push(mk(r, 'BFLA', 'API5', '285',
          `${r.method} ${r.path} is a state-changing route with no authorization, while ${authed}/${group.length} sibling routes in this file enforce it — a likely missing function-level access check.`));
      }
    }
  }

  // #9 — CWE-306 app-level pass. If the app authenticates SOME route (so our
  // auth-detection works for it), a destructive route left unauthenticated is a
  // missing-auth bug even when its file-local siblings are also public (the
  // in-file inconsistency rule above cannot see that case). Scoped to DELETE and
  // id-taking PUT/PATCH — the least-ambiguous "should never be public" shapes —
  // so intentionally-public POSTs (login / signup / webhooks) don't false-fire.
  // `push` dedupes by file:line, so a route already flagged BFLA/BOLA above is
  // not double-reported here.
  const appHasAuth = routes.some((r) => r && r.hasAuth);
  if (appHasAuth) {
    for (const r of routes) {
      if (!r || r.hasAuth || !r.file || r.path === '(file-based)') continue;
      const destructive = r.method === 'DELETE'
        || ((r.method === 'PUT' || r.method === 'PATCH') && ID_PARAM.test(r.path || ''));
      if (destructive) push(mk306(r));
    }
  }

  return findings;
}
