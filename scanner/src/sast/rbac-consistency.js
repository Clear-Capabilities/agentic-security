// R21 (PRD §5) — RBAC role-tier authorization model.
//
// R19 (api-authz.js) flags missing AUTHENTICATION among authenticated siblings.
// This goes one level deeper to AUTHORIZATION TIER: it extracts the role/
// permission a route requires (from middleware/annotations near the handler) and
// flags two broken-access-control shapes the route inventory alone can't see:
//   1. A state-changing route that enforces NO role while sibling routes on the
//      same resource DO  → missing function-level authorization (BFLA).
//   2. A state-changing route gated at a STRICTLY LOWER tier than a read sibling
//      → privilege tier inversion (delete allowed below the tier that can read).
//
// Pure cross-route analysis (routes + file contents). Precision-first: fires
// only on inconsistency within a resource group that uses roles at all.

// Inline role checks — on the route's OWN registration line (middleware args).
const INLINE_PATTERNS = [
  /\b(?:requireRole|hasRole|hasAnyRole|checkRole|ensureRole|restrictTo|requireScope|hasAuthority|hasPermission|requirePermission)\s*\(\s*\[?\s*['"]([A-Za-z0-9_.:-]+)['"]/i,
  /\brole\s*(?:===?|==)\s*['"]([A-Za-z0-9_.:-]+)['"]/i,
];
// Decorator/attribute role checks — on the line(s) directly ABOVE the handler.
const DECORATOR_PATTERNS = [
  /@(?:PreAuthorize|Secured|RolesAllowed)\s*\(\s*[^)]*['"]([A-Za-z0-9_.:-]+)['"]/i,
  /\[Authorize\s*\(\s*Roles\s*=\s*"([A-Za-z0-9_.,:-]+)"/i,
  /@(?:roles_required|permission_required)\s*\(\s*['"]([A-Za-z0-9_.:-]+)['"]/i,
];

// Coarse tier ranking (higher = more privileged). Unknown roles → tier 1 (mid).
function tierOf(role) {
  const r = String(role || '').toLowerCase();
  if (/\b(super.?admin|root|owner|sysadmin)\b/.test(r) || r === 'superadmin') return 3;
  if (/\b(admin|administrator|manager|staff|moderator|mod)\b/.test(r)) return 2;
  if (/\b(user|member|authenticated|customer|editor|contributor)\b/.test(r)) return 1;
  if (/\b(guest|public|anon|anonymous|viewer|reader)\b/.test(r)) return 0;
  return 1;
}

const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

function roleOf(route, fileContents) {
  const content = fileContents[route.file];
  if (typeof content !== 'string') return { hasRole: false, role: null };
  const lines = content.split('\n');
  const idx = (route.line || 1) - 1;
  // 1. Inline middleware / role check on the route's OWN line (don't look at
  //    siblings — that would leak an adjacent route's role into this one).
  const own = lines[idx] || '';
  for (const re of INLINE_PATTERNS) { const m = own.match(re); if (m) return { hasRole: true, role: m[1] }; }
  // 2. Stacked decorators/attributes directly ABOVE the handler; stop at the
  //    first non-decorator line so we never cross into the previous route.
  for (let j = idx - 1; j >= 0 && j >= idx - 4; j--) {
    const l = (lines[j] || '').trim();
    if (!l) continue;
    if (/^@\w|^\[Authorize/i.test(l)) {
      for (const re of DECORATOR_PATTERNS) { const m = l.match(re); if (m) return { hasRole: true, role: m[1] }; }
      continue; // an unrecognized decorator — keep scanning the stack upward
    }
    break; // hit a non-decorator line → stop
  }
  return { hasRole: false, role: null };
}

// Resource key: path with dynamic segments collapsed (so /users and /users/:id
// group together as one resource).
function resourceKey(p) {
  return String(p || '').split('/').map((s) => (/^(:|\{|<|\d)/.test(s) ? '*' : s)).join('/').replace(/\/\*$/, '') || '/';
}

function mk(route, kind, cwe, why) {
  return {
    id: `rbac:${kind}:${route.file}:${route.line}`,
    severity: 'high',
    file: route.file, line: route.line || 0,
    vuln: kind === 'inversion'
      ? 'Authorization tier inversion (state-change allowed below the read tier)'
      : 'Missing role-based authorization on a state-changing route',
    cwe, family: 'broken-access-control', parser: 'RBAC',
    description: why,
    remediation: 'Enforce a role/permission check on the route at least as strong as its sibling routes; gate state-changing actions at the appropriate privilege tier.',
  };
}

export function scanRbacConsistency(routes, fileContents) {
  if (!Array.isArray(routes) || routes.length < 2) return [];
  const groups = new Map();
  for (const r of routes) {
    if (!r || r.path === '(file-based)' || !r.path) continue;
    const key = `${r.file}::${resourceKey(r.path)}`;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push({ ...r, ...roleOf(r, fileContents) });
  }
  const findings = [];
  const seen = new Set();
  const push = (f) => { const k = `${f.file}:${f.line}`; if (!seen.has(k)) { seen.add(k); findings.push(f); } };
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    const roled = group.filter((r) => r.hasRole);
    if (!roled.length) continue; // resource doesn't use roles at all → not our signal
    const maxReadTier = Math.max(...group.filter((r) => !STATE_CHANGING.has(r.method) && r.hasRole).map((r) => tierOf(r.role)), -1);
    for (const r of group) {
      if (!STATE_CHANGING.has(r.method)) continue;
      if (!r.hasRole) {
        push(mk(r, 'missing', '285',
          `${r.method} ${r.path} enforces no role check, while ${roled.length} sibling route(s) on this resource require one — a state-changing action left at a lower authorization tier (BFLA).`));
      } else if (maxReadTier >= 0 && tierOf(r.role) < maxReadTier) {
        push(mk(r, 'inversion', '269',
          `${r.method} ${r.path} requires role "${r.role}" (tier ${tierOf(r.role)}), but reading this resource requires a higher tier (${maxReadTier}). A lower-privileged user can mutate what they may not even read.`));
      }
    }
  }
  return findings;
}

export const _internals = { tierOf, resourceKey };
