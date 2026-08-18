// PRD Theme 5 (T5.1–T5.4) — business-logic authorization.
//
// The largest single family in the evidence table: 19 of the 96 root-caused
// real-world misses. Not injection, not missing authentication — the caller IS
// authenticated, and the handler simply never checks that the object it is
// about to read or mutate belongs to them.
//
// Why the existing rules miss these (each verified against the real entries):
//   - api-authz.js works at ROUTE-INVENTORY granularity, comparing which
//     routes carry auth middleware. These handlers all have auth.
//   - authz.js's multi-tenant rule requires a literal ORM `where: {...}`
//     clause in the same file. The real code forwards the id to a service
//     layer (`identityManager.getCustomer(customerId)`), or uses TypeORM's
//     `findOneBy`, neither of which matches.
//   - business-logic.js's id heuristic recognises only `id`/`userId`; the real
//     parameters are `credentialId`, `subscriptionId`, `chatflowId`.
//
// Four sub-rules, one per shape found in the evidence:
//   T5.1 ownership-missing  — a request-supplied object id reaches a lookup or
//        mutation and nothing in the handler compares the result (or the
//        query) against an identity derived from the authenticated principal.
//   T5.2 tenant-scope-missing — a lookup by primary key in a codebase that
//        elsewhere always scopes by workspace/org/tenant.
//   T5.3 branch-inconsistent-authz — one branch of a handler checks
//        permission and a sibling branch performs the same action without it.
//   T5.4 lifecycle-gate-missing — a state-changing action on a resource that
//        carries a status/archived/deleted field, with no check of it.
//
// Every sub-rule names the control its advisory's fix added, and goes silent
// when that control is present.
import { blankComments } from './_comment-strip.js';

const SRC_RE = /\.(?:js|jsx|ts|tsx|mjs|cjs|py)$/i;

/** A handler that receives a request. */
const HANDLER_RE =
  /\b(?:async\s{1,4})?(?:function\s{1,4})?(\w{1,60})\s{0,4}\([^)]{0,300}\b(?:req|request|ctx|event)\b[^)]{0,300}\)\s{0,4}(?:=>\s{0,4})?\{/g;

/**
 * An object identifier read off the request — ANY *Id name, not just `id`.
 *
 * Three surface forms, all seen in the real entries. The DESTRUCTURING form is
 * what the code this rule was designed from actually uses
 * (`const { customerId } = req.query`), and the first version of this rule
 * matched only member access — which is why it returned zero findings on its
 * own target entry.
 */
const REQ_ID_RE =
  /\b(?:req|request|ctx)\s{0,2}\.\s{0,2}(?:params|query|body|args)\s{0,2}(?:\.\s{0,2}(\w{0,40}[iI]d)\b|\[\s*['"](\w{0,40}[iI]d)['"]\s*\])/g;
const REQ_ID_DESTRUCTURE_RE =
  /(?:const|let|var)\s{1,4}\{([^}]{0,200})\}\s{0,4}=\s{0,4}(?:await\s{1,4})?(?:req|request|ctx)\s{0,2}\.\s{0,2}(?:params|query|body|args)\b/g;

/**
 * The id is HANDED TO something that acts on it.
 *
 * A fixed ORM verb list was the second reason this rule missed its own target:
 * the real sink is `identityManager.getCustomerWithDefaultSource(customerId)`,
 * a domain method that matches no generic vocabulary. Any receiver-qualified
 * call taking the id counts, EXCEPT the response/logging/control shapes below —
 * echoing an id back to the caller is not acting on the object it names.
 */
const NON_ACTING_RECEIVER_RE = /^(?:res|response|reply|ctx|console|logger|log|next|JSON|Number|String|Boolean|parseInt|Array|Object)$/i;
/** Index of the acting call within `body`, or -1. Line attribution needs the
 * SINK, not the handler's opening brace — GHSA-2364's fix lands 8 lines into
 * the body, well outside the ±3 localization window a handler-line finding
 * would need to land in. */
function _usesIdAt(body, id) {
  const esc = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(`\\b(\\w{1,60})\\s{0,4}\\.\\s{0,4}\\w{1,60}\\s{0,4}\\([^)]{0,200}\\b${esc}\\b`, 'g');
  let m;
  while ((m = re.exec(body))) if (!NON_ACTING_RECEIVER_RE.test(m[1])) return m.index;
  return -1;
}
function _usesId(body, id) { return _usesIdAt(body, id) !== -1; }

/** Evidence the caller's identity constrains the operation. */
const OWNERSHIP_RE = new RegExp([
  // Compared against the principal.
  '\\b(?:req|request|ctx)\\s{0,2}\\.\\s{0,2}(?:user|auth|principal|session)\\b',
  '\\b(?:current_?user|currentUser|authUser|viewer|me)\\b',
  // Or the query itself is scoped.
  '\\b(?:user_?id|owner_?id|userId|ownerId|createdBy|author_?id)\\s{0,4}[:=]',
].join('|'), 'i');

/** Tenant dimension — the T5.2 control. */
const TENANT_RE = /\b(?:workspace_?id|workspaceId|org_?id|orgId|organization_?id|tenant_?id|tenantId|account_?id|accountId)\b/i;

/** An explicit authorization call — T5.3's control. */
const PERMISSION_CALL_RE =
  /\b(?:has_?permission|hasPermission|check_?permission|checkPermission|checkAnyPermission|require_?permission|can\w{0,20}|authorize\w{0,10}|assert\w{0,20}(?:Access|Permission)|verify\w{0,20}Access)\s{0,4}\(/i;

/** Lifecycle fields whose state should gate a mutation — T5.4. */
const LIFECYCLE_FIELD_RE = /\b(?:status|state|archived|is_?archived|deleted|is_?deleted|active|is_?active|expired|published|revoked)\b/i;
const STATE_CHANGE_RE = /\.(?:update|delete|remove|destroy|save|redeem|activate|apply|execute|publish)\s{0,4}\(/;

const _lineOf = (raw, i) => raw.slice(0, i).split('\n').length;

/** Body of a handler, by brace matching from its opening `{`. */
function _bodyFrom(code, openIdx) {
  let depth = 0;
  for (let i = openIdx; i < code.length && i < openIdx + 20000; i++) {
    const ch = code[i];
    if (ch === '{') depth++;
    else if (ch === '}') { depth--; if (depth === 0) return code.slice(openIdx, i + 1); }
  }
  return code.slice(openIdx, openIdx + 4000);
}

function mk(file, line, sub, cwe, vuln, description, remediation, checkedFor) {
  return {
    id: `ownership-authz:${sub}:${file}:${line}`,
    file, line, vuln,
    severity: 'high',
    cwe,
    family: 'broken-access-control',
    subfamily: sub,
    parser: 'OWNERSHIP-AUTHZ',
    confidence: 0.5,
    description, remediation, checkedFor,
  };
}

export function scanOwnershipAuthz(file, raw) {
  if (!raw || typeof raw !== 'string' || raw.length > 500_000) return [];
  if (!SRC_RE.test(file)) return [];
  if (!/\b(?:req|request|ctx)\b/.test(raw)) return [];          // cheap relevance gate
  const code = blankComments(raw, /\.py$/i.test(file) ? 'py' : null);

  // Does this FILE establish a tenant convention at all? T5.2 only means
  // something where the codebase demonstrably scopes by tenant elsewhere.
  const fileUsesTenant = TENANT_RE.test(code);

  const out = [];
  const seen = new Set();
  const push = (f) => { const k = `${f.subfamily}:${f.line}`; if (!seen.has(k)) { seen.add(k); out.push(f); } };

  HANDLER_RE.lastIndex = 0;
  let h;
  while ((h = HANDLER_RE.exec(code))) {
    const name = h[1];
    const openIdx = code.indexOf('{', h.index + h[0].length - 1);
    if (openIdx === -1) continue;
    const body = _bodyFrom(code, openIdx);
    const line = _lineOf(code, h.index);

    REQ_ID_RE.lastIndex = 0;
    REQ_ID_DESTRUCTURE_RE.lastIndex = 0;
    const ids = [...body.matchAll(REQ_ID_RE)].map(m => m[1] || m[2]).filter(Boolean);
    for (const d of body.matchAll(REQ_ID_DESTRUCTURE_RE)) {
      for (const part of String(d[1]).split(',')) {
        const nm = part.split(':').pop().trim();
        if (/^\w{0,40}[iI]d$/.test(nm)) ids.push(nm);
      }
    }
    // Aliases: `const x = req.params.credentialId` then `repo.findOneBy({id: x})`.
    // The rewrite keyed on the id NAME appearing at the call, which the old
    // verb-list check handled implicitly; without this an aliased id is missed.
    const names = [...ids];
    for (const id of ids) {
      const esc = id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      for (const a of body.matchAll(new RegExp(`(?:const|let|var)\\s{1,4}(\\w{1,60})\\s{0,4}=[^\\n]{0,80}\\b${esc}\\b`, 'g'))) names.push(a[1]);
    }
    // Attribute the finding to where the id is actually USED, not the handler
    // declaration — a fix inserted mid-body would otherwise sit well outside
    // any localization window keyed to the finding's line.
    let sinkIdx = -1;
    for (const n of names) {
      const idx = _usesIdAt(body, n);
      if (idx !== -1) { sinkIdx = idx; break; }
    }
    const touchesObject = sinkIdx !== -1;
    const sinkLine = touchesObject ? _lineOf(code, openIdx + sinkIdx) : line;

    // T5.1 — an object id from the request reaches a lookup/mutation and
    // nothing ties the operation to the authenticated principal. TENANT_RE is
    // checked too, not just OWNERSHIP_RE: GHSA-r745-8hwv-h473's /authorize
    // handler scopes its lookup by `workspaceId` (from
    // getActiveWorkspaceIdForRequest(req)) with no per-user ownership
    // predicate at all — workspace/tenant scoping IS an ownership check at a
    // coarser grain, and a rule that can't see that flags well-guarded
    // multi-tenant code as vulnerable. The sibling /refresh handler in the
    // same file, which has neither, still fires correctly.
    if (ids.length && touchesObject && !OWNERSHIP_RE.test(body) && !TENANT_RE.test(body)) {
      push(mk(file, sinkLine, 'ownership-missing', 'CWE-639',
        `${name}() looks up or mutates by request-supplied '${ids[0]}' with no ownership check`,
        `The object identifier '${ids[0]}' comes straight from the request and is used to read or change a record, `
        + 'but nothing in this handler compares that record — or constrains the query — against the authenticated '
        + 'caller. Authentication alone does not help here: any logged-in user can substitute another user\'s id. '
        + 'This is the shape route-level authz rules cannot see, because the route IS authenticated.',
        'Scope the lookup by the caller (add the principal\'s id to the query), or fetch first and compare the '
        + 'record\'s owner against the authenticated user before acting on it.',
        'a comparison against req.user/current_user, or an owner/tenant predicate in the query'));
    }

    // T5.2 — tenant-scoped codebase, unscoped lookup.
    // An explicit ownership assertion IS scoping. Without this, T5.2 simply
    // takes over from T5.1 the moment the maintainer's fix lands, and the
    // entry never discriminates — observed on GHSA-2364's post/ revision,
    // where assertStripeIdMatchesSession(id, req.user...) silenced T5.1 and
    // T5.2 immediately fired in its place.
    if (fileUsesTenant && ids.length && touchesObject && !TENANT_RE.test(body) && !OWNERSHIP_RE.test(body)) {
      push(mk(file, sinkLine, 'tenant-scope-missing', 'CWE-863',
        `${name}() queries by id without the workspace/tenant scope this file uses elsewhere`,
        'Other code in this file constrains queries by a workspace/organization/tenant dimension; this handler '
        + 'looks up by primary key alone. In a multi-tenant system that returns records belonging to other '
        + 'tenants whenever an id can be guessed or enumerated.',
        'Add the tenant dimension to the query, the same way the neighbouring handlers do.',
        'a workspace/org/tenant predicate inside this handler, given the file uses one elsewhere'));
    }

    // T5.3 — one branch authorizes, a sibling performs the same action bare.
    if (PERMISSION_CALL_RE.test(body)) {
      const branches = body.split(/\belse\b|\belif\b/);
      if (branches.length > 1) {
        const guarded = branches.filter(b => PERMISSION_CALL_RE.test(b)).length;
        const acting = branches.filter(b => STATE_CHANGE_RE.test(b)).length;
        if (guarded < acting) {
          push(mk(file, line, 'branch-inconsistent-authz', 'CWE-862',
            `${name}() checks permission on one branch but acts without it on another`,
            'This handler performs an authorization check in one branch and performs the same class of '
            + 'state-changing action in a sibling branch that has no such check. Whichever path skips the check '
            + 'is reachable by choosing the input that selects it.',
            'Hoist the authorization check above the branch so every path is covered, or repeat it on each '
            + 'acting branch.',
            'a permission call on every branch that performs a state-changing action'));
        }
      }
    }

    // T5.4 — mutate a resource whose lifecycle state is never consulted.
    if (STATE_CHANGE_RE.test(body) && LIFECYCLE_FIELD_RE.test(code) && !LIFECYCLE_FIELD_RE.test(body)) {
      push(mk(file, line, 'lifecycle-gate-missing', 'CWE-863',
        `${name}() acts on a resource without checking its lifecycle state`,
        'This handler performs a state-changing action on a record whose type carries a lifecycle field '
        + '(status/archived/deleted/expired — used elsewhere in this file) without consulting it. An archived, '
        + 'revoked or already-consumed record can therefore still be acted on.',
        'Check the resource\'s lifecycle state before acting, and reject the request when it is not in a state '
        + 'that permits the action.',
        'a status/archived/deleted check inside this handler, given the file uses one elsewhere'));
    }
  }
  return out;
}

export const _internals = { REQ_ID_RE, REQ_ID_DESTRUCTURE_RE, _usesId, _usesIdAt, OWNERSHIP_RE, TENANT_RE, PERMISSION_CALL_RE, LIFECYCLE_FIELD_RE };
