// Dual suppression schemas (R4).
//   - vibecoder:  .agentic-security/accepted.json  (soft, 30-day, auto-reminder)
//   - pro:        .agentic-security/suppressions.yml (audit-grade: reason +
//                  reviewer + expiry + rule-version pin)
// One function `applySuppressions(findings, scanRoot, profile)` filters in
// place. Loaders accept malformed input gracefully (skip bad entries, log).
//
// FR-1004 (assurance-hardening PRD): "exception owner, reason, scope,
// compensating control, and expiry." The pro schema already had reason
// (`reason`) and expiry (`expires_at`); `owner`, `scope`, and
// `compensating_control` are added here as required fields on the SAME
// entry, validated by the SAME `validateProSuppression` gate that already
// enforces the two-person rule. This is a deliberate tightening: an
// existing suppressions.yml entry written before this field set was
// required will now fail validation and REOPEN its finding, same as any
// other invalid pro suppression already does — an operator must add the
// three new fields to keep the exception honored. `owner` is who is
// accountable for eventually resolving or renewing the exception (may or
// may not be the same person as `reviewer`); `scope` is a short,
// human-readable statement of what the exception covers (this module's
// matching remains per-finding — `scope` documents intent, it does not
// widen what gets suppressed); `compensating_control` is the specific
// alternative mitigation that justifies leaving the underlying finding
// unfixed (a required field, not inferred from `reason` — "we'll fix it
// later" is a reason, not a compensating control, and conflating the two
// was the actual gap this PRD item exists to close).
//
// "Expired exceptions automatically reopen findings or fail the gate":
// `applySuppressions` already returns an expired suppression's finding to
// the KEPT (open) set rather than the suppressed set (see the `exp < now`
// branch below) — an expired exception was always self-reopening by
// construction, this was just never covered by a test until FR-1004.
// Reopening feeds the existing severity-based CI gate (`--fail-on`)
// exactly like any other open finding; no second, parallel expiry-gate
// mechanism is needed or built here.

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as yaml from '../util/yaml.js';
import { statePath, safeWriteState } from './state-dir.js';
import { loadApproverRegistry, verifyApprover, requiredRolesFor } from '../fix/approver-registry.js';

const MS_PER_DAY = 86400000;
const SOFT_TTL_DAYS = 30;

function _now() { return Date.now(); }
function _dateOnly(iso) {
  // Accept full ISO or YYYY-MM-DD.
  try { return new Date(iso).getTime(); } catch (_) { return NaN; }
}

export function loadSoftAccepted(scanRoot) {
  const fp = statePath(scanRoot, 'accepted.json');
  if (!fs.existsSync(fp)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(raw.accepted) ? raw.accepted : [];
  } catch (_) { return []; }
}

export function saveSoftAccepted(scanRoot, items) {
  const fp = statePath(scanRoot, 'accepted.json');
  safeWriteState(fp, JSON.stringify({ accepted: items }, null, 2));
}

export function addSoftAcceptance(scanRoot, finding, reason) {
  const items = loadSoftAccepted(scanRoot);
  const expires = new Date(_now() + SOFT_TTL_DAYS * MS_PER_DAY).toISOString().slice(0, 10);
  items.push({
    id: finding.id || `${finding.file}:${finding.line}:${finding.vuln}`,
    file: finding.file,
    line: finding.line,
    vuln: finding.vuln,
    reason: reason || 'vibecoded for now',
    accepted_at: new Date().toISOString().slice(0, 10),
    expires_at: expires,
  });
  saveSoftAccepted(scanRoot, items);
  return expires;
}

export function loadProSuppressions(scanRoot) {
  const fp = statePath(scanRoot, 'suppressions.yml');
  if (!fs.existsSync(fp)) return [];
  try {
    const parsed = yaml.load(fs.readFileSync(fp, 'utf8'));
    return Array.isArray(parsed) ? parsed : (parsed?.suppressions || []);
  } catch (_) { return []; }
}

// Validate one entry. Returns { ok, errors }.
//
// FR-1002: "bind approvals, EXCEPTIONS, AND SUPPRESSIONS to verified
// identities and roles... anonymous or unauthorized high-risk exceptions
// fail policy." A pro suppression's `justification_signed_by` is exactly
// such an exception-approval identity, but until this fix it was pure
// self-reported free text -- FR-307/FR-1002's registry existed and was
// wired into apply_fix, but never consulted here. `opts.registry` is
// optional and NO-OP when absent (loadApproverRegistry(scanRoot) returns
// null until an operator opts in, matching every other gate in this
// registry), so an existing project with no registry file sees zero
// behavior change. `opts.requiredRoles` lets the caller scope role
// requirements to the SUPPRESSED FINDING's own family/category, the same
// way FR-307 scopes them to a change's material-change category.
export function validateProSuppression(entry, opts = {}) {
  const errors = [];
  for (const k of ['finding_id', 'file', 'reason', 'justification_signed_by', 'reviewer', 'expires_at', 'owner', 'scope', 'compensating_control']) {
    if (!entry[k] || (typeof entry[k] === 'string' && !entry[k].trim())) errors.push(`missing: ${k}`);
  }
  if (entry.justification_signed_by && entry.reviewer && entry.justification_signed_by === entry.reviewer) {
    errors.push('justification_signed_by must differ from reviewer (two-person rule)');
  }
  if (entry.justification_signed_by && opts.registry !== undefined) {
    const v = verifyApprover(opts.registry, entry.justification_signed_by, opts.requiredRoles || []);
    if (!v.verified) errors.push(`justification_signed_by not authorized: ${v.reason}`);
  }
  if (entry.expires_at) {
    const t = _dateOnly(entry.expires_at);
    if (!Number.isFinite(t)) errors.push('expires_at must be ISO date');
    else if (t < _now()) errors.push('expires_at is in the past');
  }
  if (entry.severity === 'critical' && !entry._accept_critical) {
    errors.push('cannot suppress critical without --accept-critical flag at suppress time');
  }
  return { ok: errors.length === 0, errors };
}

export function applySuppressions(findings, scanRoot, profile) {
  const isVib = (profile?.profile || 'vibecoder') === 'vibecoder';
  const isPro = (profile?.profile) === 'pro';
  const items = isPro ? loadProSuppressions(scanRoot) : loadSoftAccepted(scanRoot);
  if (!items.length) return findings;

  // FR-1002: loaded once per call, not per entry — a missing registry file
  // (the common, not-opted-in case) makes verifyApprover() a no-op below,
  // exactly like every other gate built on this registry.
  const approverRegistry = isPro ? loadApproverRegistry(scanRoot) : null;

  const now = _now();
  const kept = [];
  const suppressed = [];

  for (const f of findings) {
    const fid = f.id || `${f.file}:${f.line}:${f.vuln}`;
    let matched = null;
    for (const s of items) {
      const matchId = s.id || s.finding_id;
      if (matchId && matchId === fid) { matched = s; break; }
      // Also match by (file, line, vuln) tuple.
      if (s.file === f.file && s.line === f.line && s.vuln === f.vuln) { matched = s; break; }
    }
    if (matched) {
      // Has it expired?
      const exp = _dateOnly(matched.expires_at || matched.expires || '');
      if (Number.isFinite(exp) && exp < now) {
        kept.push({ ...f, _suppressionExpired: true });
        continue;
      }
      // Pro: validate the entry still passes
      if (isPro) {
        // Same registry/category shape FR-307 already uses for high-impact
        // fixes: an operator opts a finding family into role-gating via
        // requiredRolesByCategory, keyed by that family's name.
        const requiredRoles = requiredRolesFor(approverRegistry, [f.family].filter(Boolean));
        const v = validateProSuppression({ ...matched, severity: f.severity }, { registry: approverRegistry, requiredRoles });
        if (!v.ok) { kept.push({ ...f, _suppressionInvalid: v.errors }); continue; }
      }
      suppressed.push({ ...f, _suppressed: matched });
      continue;
    }
    kept.push(f);
  }

  if (process.env.DEBUG_SUPPRESSIONS) {
    console.error(`[suppressions] ${suppressed.length} suppressed, ${kept.length} kept`);
  }
  return kept;
}

// Return suppressions that have expired so callers can remind the user.
export function expiredSoftAcceptances(scanRoot) {
  const items = loadSoftAccepted(scanRoot);
  const now = _now();
  return items.filter(s => {
    const exp = _dateOnly(s.expires_at);
    return Number.isFinite(exp) && exp < now;
  });
}
