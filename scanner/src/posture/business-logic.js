// Business-logic analysis (FR-LOGIC-1, FR-LOGIC-2, FR-LOGIC-7).
//
// Pillar 4 of the next-gen PRD. Today the engine has structural attack-chain
// synthesis (FR-LOGIC-4) and TOCTOU regex (FR-LOGIC-3 partial). This module
// adds three more:
//
//   FR-LOGIC-1 AuthZ matrix:
//     Per route, infer (auth-required, ownership-checked, role-required).
//     Flag routes whose state contradicts other routes on the same resource.
//
//   FR-LOGIC-2 State-machine extraction:
//     Find fields named `status` / `state` / `phase` with literal-string-set
//     values. Flag direct writes to that field with values outside the set.
//
//   FR-LOGIC-7 Negative-test-gap:
//     Route handlers with happy-path tests but no test for the unauthorized
//     case. Heuristic: check the test-files corpus for any test asserting
//     a 401 / 403 status against the route's path.

import { inferredInvariant } from './invariants/lifecycle.js';

const JS_TS_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_RE    = /\.py$/i;

function _lineOf(raw, idx) { return raw.substring(0, idx).split('\n').length; }

// ─── FR-LOGIC-1 AuthZ matrix ───────────────────────────────────────────────

const ROUTE_DEFINITION_PATTERNS = [
  // Express / Fastify
  { re: /\b(?:app|router|server)\s*\.\s*(get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]\s*,\s*([^)]*)\)/g, lang: 'js' },
  // Flask
  { re: /@(?:app|bp|blueprint)\s*\.\s*route\s*\(\s*['"]([^'"]+)['"][^)]*methods\s*=\s*\[\s*['"]([A-Z]+)['"]/g, lang: 'py' },
];

const AUTH_HINTS = [
  /req\.user\b/, /req\.auth\b/, /request\.user\b/,
  /requireAuth|isAuthenticated|@login_required|@requires_auth|@jwt_required/,
  /authorize|authMiddleware|verifyJWT|jwt\.verify\b/,
];
const OWNERSHIP_HINTS = [
  /owner|ownerId|user_id\s*=\s*request|req\.user\.id|userId\s*:\s*req\.user/i,
  /\.owner\s*===\s*req\.user|\.userId\s*===\s*req\.user/,
];
const ROLE_HINTS = [
  /requireRole|hasRole|isAdmin|@admin_required|@has_permission|user\.role|user\.is_staff/,
];

function _matchesAnyRe(arr, text) { return arr.some(re => re.test(text)); }

function extractAuthZMatrix(fileContents) {
  const routes = [];   // {file, line, method, path, authRequired, ownershipChecked, roleRequired}
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (typeof c !== 'string' || c.length === 0 || c.length > 500_000) continue;
    if (!JS_TS_RE.test(fp) && !PY_RE.test(fp)) continue;
    for (const { re, lang } of ROUTE_DEFINITION_PATTERNS) {
      if (lang === 'js' && !JS_TS_RE.test(fp)) continue;
      if (lang === 'py' && !PY_RE.test(fp))    continue;
      const r = new RegExp(re.source, re.flags);
      let m;
      while ((m = r.exec(c))) {
        const method = (m[1] || '').toUpperCase();
        const routePath = m[2];
        const line = _lineOf(c, m.index);
        // Inspect the handler body — take ±20 lines as a coarse window.
        const lines = c.split('\n');
        const window = lines.slice(Math.max(0, line - 1), line + 25).join(' ');
        routes.push({
          file: fp, line, method, path: routePath,
          authRequired:     _matchesAnyRe(AUTH_HINTS, window),
          ownershipChecked: _matchesAnyRe(OWNERSHIP_HINTS, window),
          roleRequired:     _matchesAnyRe(ROLE_HINTS, window),
        });
      }
    }
  }
  return routes;
}

function emitAuthZMatrixFindings(matrix) {
  if (!matrix.length) return [];
  // Group by resource path stem (first two path segments) and flag if some
  // routes on the same resource require auth and some don't.
  const byResource = new Map();
  for (const r of matrix) {
    const stem = (r.path || '').split('/').slice(0, 3).join('/');
    if (!byResource.has(stem)) byResource.set(stem, []);
    byResource.get(stem).push(r);
  }
  const findings = [];
  // IDOR check fires per route regardless of sibling-count — flatten matrix
  // and evaluate each route independently.
  for (const r of matrix) {
    const isMutation = /^(POST|PUT|PATCH|DELETE)$/.test(r.method);
    const hasIdParam = /[/:]\:?(?:id|userId|userid|user_id|\{[^}]+\})/.test(r.path);
    if (isMutation && hasIdParam && !r.ownershipChecked && !r.roleRequired) {
      findings.push({
        id: `authz-matrix-idor:${r.file}:${r.line}:${r.method}-${r.path}`,
        file: r.file, line: r.line,
        vuln: `Potential IDOR (AuthZ matrix): ${r.method} ${r.path} mutates by id without ownership/role check in the same handler`,
        severity: 'high',
        cwe: 'CWE-639',
        family: 'idor',
        stride: 'Elevation of Privilege',
        parser: 'AUTHZ-MATRIX',
        confidence: 0.55,
        snippet: `${r.method} ${r.path}`,
        remediation: 'Verify the authenticated user owns the resource being mutated, e.g. `Item.findOne({ _id: req.params.id, owner: req.user.id })` (Mongoose), or compare `obj.user_id == request.user.id` (Django). Reject with 403 when the check fails.',
      });
    }
  }
  for (const [stem, routes] of byResource) {
    if (routes.length < 2) continue;
    const hasAuth   = routes.filter(r => r.authRequired);
    const noAuth    = routes.filter(r => !r.authRequired);
    if (hasAuth.length > 0 && noAuth.length > 0) {
      // Inconsistency: same resource has both protected and unprotected routes.
      for (const r of noAuth) {
        findings.push({
          id: `authz-matrix:${r.file}:${r.line}:${r.method}-${r.path}`,
          file: r.file, line: r.line,
          vuln: `AuthZ inconsistency: ${r.method} ${r.path} has no auth check, but sibling routes on ${stem} require auth`,
          severity: 'high',
          cwe: 'CWE-285',
          family: 'authz-matrix-inconsistency',
          stride: 'Elevation of Privilege',
          parser: 'AUTHZ-MATRIX',
          confidence: 0.65,
          snippet: `${r.method} ${r.path}`,
          remediation: `Some routes under ${stem} call requireAuth / @login_required / verify JWT, others (including this one) do not. Either add the same auth guard here, or document why this route is intentionally public (and consider a per-route allowlist).`,
        });
      }
    }
  }
  return findings;
}

// ─── FR-LOGIC-2 State machine extraction ──────────────────────────────────

function collectStateSets(fileContents) {
  // Find sites where a literal set of statuses appears (e.g.
  // `STATUSES = ['pending', 'approved', 'rejected']` or an enum-like in TS).
  const stateSets = [];   // [{file, line, name, values: Set<string>, ordered: string[]}]
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (typeof c !== 'string' || !JS_TS_RE.test(fp)) continue;
    const re = /\b(STATUSES|STATES|PHASES|ALLOWED_STATUSES|[A-Z_]+_STATUSES)\s*=\s*\[\s*((?:['"][^'"]+['"]\s*,?\s*){2,})\]/g;
    let m;
    while ((m = re.exec(c))) {
      const values = [...m[2].matchAll(/['"]([^'"]+)['"]/g)].map(x => x[1]);
      stateSets.push({ file: fp, line: _lineOf(c, m.index), name: m[1], values: new Set(values), ordered: values });
    }
  }
  return stateSets;
}

function extractStateMachine(fileContents) {
  // Then look for direct writes like `.status = "<not in set>"` and flag.
  const stateSets = collectStateSets(fileContents);
  if (!stateSets.length) return [];
  const findings = [];
  for (const [fp, c] of Object.entries(fileContents || {})) {
    if (typeof c !== 'string' || !JS_TS_RE.test(fp)) continue;
    const writeRe = /\.\s*(?:status|state|phase)\s*=\s*['"]([^'"]+)['"]/g;
    let m;
    while ((m = writeRe.exec(c))) {
      const value = m[1];
      const validSet = stateSets.find(s => s.values.size > 0);
      if (!validSet) continue;
      if (validSet.values.has(value)) continue;
      const line = _lineOf(c, m.index);
      findings.push({
        id: `state-machine:${fp}:${line}:${value}`,
        file: fp, line,
        vuln: `State-machine bypass: write '${value}' not in declared set ${[...validSet.values].join(',')}`,
        severity: 'medium',
        cwe: 'CWE-841',
        family: 'state-machine-bypass',
        stride: 'Tampering',
        parser: 'STATE-MACHINE',
        confidence: 0.5,
        snippet: m[0].slice(0, 200),
        remediation: `The statuses recognized by your system appear to be {${[...validSet.values].join(', ')}}. This write sets a different value ('${value}'). If the new value is legitimate, add it to the set; otherwise treat the write as a state-machine bypass and reject it.`,
      });
    }
  }
  return findings;
}

// ─── FR-LOGIC-7 Negative-test-gap ─────────────────────────────────────────

function findNegativeTestGaps(fileContents, matrix) {
  // Heuristic: for each authenticated route, check if any test file in the
  // project references the route's path AND asserts 401/403/Forbidden. If
  // not, emit a "missing negative test" finding.
  if (!matrix || !matrix.length) return [];
  const testFiles = Object.entries(fileContents || {})
    .filter(([fp, c]) => /(?:^|\/)(?:tests?|__tests__|specs?)\//i.test(fp) && typeof c === 'string')
    .map(([fp, c]) => ({ fp, content: c }));
  if (!testFiles.length) return [];
  const findings = [];
  for (const r of matrix) {
    if (!r.authRequired) continue;
    // Convert Express `:param` and Flask `<param>` placeholders to a wildcard
    // so we match test invocations with concrete values like `/users/1`.
    const pathPattern = r.path
      .replace(/[/\\^$*+?.()|[\]{}]/g, '\\$&')
      .replace(/:\w+/g, '[^/?#]+')
      .replace(/<\w+>/g, '[^/?#]+');
    const re = new RegExp(pathPattern);
    // Look for any test file referencing this path AND asserting 401/403.
    const negTest = testFiles.find(t =>
      re.test(t.content) &&
      /(?:expect\s*\([^)]*\)\.[a-zA-Z]+\([^)]*40[13]|status_code\s*==\s*40[13]|\.status\s*=\s*=\s*40[13])/.test(t.content)
    );
    if (negTest) continue;
    findings.push({
      id: `negative-test-gap:${r.file}:${r.line}:${r.method}-${r.path}`,
      file: r.file, line: r.line,
      vuln: `Negative-test gap: ${r.method} ${r.path} has an auth check but no test asserting 401/403 for the unauthorized case`,
      severity: 'low',
      cwe: 'CWE-1059',
      family: 'negative-test-gap',
      stride: 'Repudiation',
      parser: 'NEG-TEST-GAP',
      confidence: 0.55,
      snippet: `${r.method} ${r.path} — has auth guard, no failing-case test in repo`,
      remediation: 'Add an authorization test: invoke this endpoint without a session / with a different user\'s token, and assert the response is 401 or 403. Tests of this shape catch regressions where the auth guard gets accidentally removed.',
    });
  }
  return findings;
}

// ─── Public API ────────────────────────────────────────────────────────────

export function scanBusinessLogic(fileContents) {
  if (!fileContents || typeof fileContents !== 'object') return [];
  const matrix = extractAuthZMatrix(fileContents);
  const out = [];
  out.push(...emitAuthZMatrixFindings(matrix));
  out.push(...extractStateMachine(fileContents));
  out.push(...findNegativeTestGaps(fileContents, matrix));
  return out;
}

// For tests + the no-dead-modules check.
// X-402: a declared status list read as an inferred workflow contract. The declared order is the only evidence for the allowed
// transitions (each value to the next), which is a guess a reviewer must confirm, so the proposal carries a high uncertainty and is
// advisory until approved in the signed ledger.
export function mineWorkflowInvariants(fileContents) {
  const out = [];
  for (const set of collectStateSets(fileContents)) {
    const states = set.ordered.filter((v) => /^[A-Za-z0-9_.:/-]{1,64}$/.test(v));
    if (states.length < 2) continue;
    const allowed = states.slice(0, -1).map((from, i) => ({ from, to: states[i + 1] }));
    const inv = inferredInvariant({ class: 'workflow-order', source: 'state-machine', evidence: { file: set.file, line: set.line, set: set.name }, uncertainty: 0.7, action: 'advance', allowed: allowed.slice(0, 16) });
    if (inv) out.push(inv);
  }
  return out;
}

export const _internals = { extractAuthZMatrix, extractStateMachine, findNegativeTestGaps };
