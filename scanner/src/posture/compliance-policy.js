// Compliance-as-code DSL — Recommendation #9 of the world-class+2 plan.
//
// Customers declare their compliance policy in
// .agentic-security/compliance.policy.yml. The scanner reads the policy,
// runs verification (each rule is a deterministic check against scanner
// findings + config files + state) and emits a structured JSON-LD
// evidence file consumable by Vanta / Drata / SecureFrame / auditors.
//
// DSL shape:
//
//   framework: "SOC2 Type II"
//   controls:
//     CC6.1:
//       title: "Logical access controls"
//       requires:
//         - finding-family: "auth-missing"
//           must-be: zero
//         - file-exists: ".github/dependabot.yml"
//         - documented: ".agentic-security/auth-policy.md"
//       evidence:
//         - "Scanner finds 0 auth-missing findings on the current release"
//         - "Dependency-update automation present"
//     CC7.2:
//       title: "Security incident response"
//       requires:
//         - file-exists: "INCIDENT-PLAN.md"
//
// Verifier primitives in v1:
//   finding-family: <name>     must-be: zero | min: <n> | max: <n>
//   file-exists: <relative-path>
//   documented: <relative-path>  (alias for file-exists)
//   file-contains: <relative-path>   pattern: <regex>
//     FR-503: for a control that demands the file's CONTENT prove something,
//     not just its existence — "mere artifact existence... is insufficient
//     unless the mapping explicitly defines it." file-exists remains valid
//     for controls that genuinely only need a document to exist.
//   env-var-set: <name>
//   sca-policy-has-entry: <type>  (e.g. accept-risk, sla)
//
// FR-504/FR-506 (assurance-hardening PRD) — optional, per-control fields,
// all additive (a control naming none of these is unaffected):
//   owner: <string>                 — who is accountable for this control
//   reviewer: <string>               — who last reviewed the evidence
//   reviewed-at: <ISO date>          — when it was last reviewed
//   review-interval-days: <number>   — opts into staleness: once
//                                      reviewed-at + this interval has
//                                      passed, status becomes `stale`
//   not-applicable: true             — legacy bare exception, never expires
//   not-applicable:                  — structured exception; an EXPIRED one
//     reason: "..."                    reopens the control as status `gap`
//     owner: "..."                     rather than silently staying
//     expires-at: <ISO date>           not-applicable
//
// Every verification also computes `evidenceDigest` (FR-504) — a sha256 of
// {repository, commit, scope, engine, ruleset, analyzerHealth,
// mappingVersion, controls[{id,status}]} — so changing any bound input is a
// checkable property, not an assertion.
//
// Output:
//   .agentic-security/compliance-evidence.json — JSON-LD compliant
//     structured artifact
//   .agentic-security/compliance-evidence.md — human-readable summary

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { hardenGitArgs, hardenGitEnv } from '../util/git-hardening.js';
import * as yaml from '../util/yaml.js';
import { statePath, safeWriteState, STATE_DIR_NAME } from './state-dir.js';
import { SCANNER_VERSION } from './version.js';
import { EVIDENCE_GRADE_DISCLAIMER, EVIDENCE_GRADE_DISCLAIMER_SHORT } from './evidence-grade-wording.js';
import { loadSigningKeyIfConfigured, signComplianceEvidence } from './compliance-evidence-signing.js';
import { maybeEncryptForWrite } from './encryption-provider.js';

const POLICY_FILE = 'compliance.policy.yml';

// FR-508: "export evidence in a stable API suitable for external GRC
// ingestion | exported records retain source references, status
// semantics, and schema version." The JSON-LD shape itself has been
// additive-only since it was introduced (every field this session has
// added — evidenceDigest, owner/reviewer/staleReason/gapReason, signature —
// was optional and backward-compatible), which IS the stability guarantee;
// this constant is what lets a consumer verify that claim programmatically
// instead of taking it on faith. Bump when — and only when — an existing
// field's MEANING changes incompatibly (a genuinely additive field does
// not require a bump, matching every semver-adjacent convention in this
// codebase: new optional fields are not breaking changes).
export const EVIDENCE_SCHEMA_VERSION = 1;

// FR-508: "status semantics" — a GRC tool ingesting this artifact should
// not have to reverse-engineer what each status string means from this
// codebase's own source; the definitions travel WITH the document.
export const STATUS_SEMANTICS = {
  compliant: 'Every check for this control passed against the current scan.',
  'non-compliant': 'At least one check for this control failed against the current scan.',
  'not-applicable': 'The control is explicitly excepted by the policy mapping (not-applicable) and was not evaluated.',
  stale: 'The control passed its checks, but its evidence exceeded an operator-configured review interval (FR-506) and has not been re-reviewed.',
  gap: 'A previously-recorded not-applicable exception has expired (FR-506); the control has neither a fresh exception nor a fresh evaluation.',
};

export function loadPolicy(scanRoot) {
  const fp = statePath(scanRoot, POLICY_FILE);
  if (!fs.existsSync(fp)) return null;
  try {
    const raw = fs.readFileSync(fp, 'utf8');
    const doc = yaml.load(raw);
    return _normalize(doc);
  } catch (e) {
    return { _error: `Failed to parse ${fp}: ${e.message}` };
  }
}

// FR-506: `not-applicable` accepts either the legacy bare `true` (kept
// working forever — many existing compliance policy YAMLs use this shape,
// and a bare exception with no expiry is a valid, if less accountable,
// choice) or a structured exception object `{reason, owner, expires_at}`.
// Only the structured shape can expire; a bare `true` never does, matching
// this session's own "no expiry configured = never expires" convention
// (D-0025's suppression exceptions, the waiver-file pattern).
function _normalizeNotApplicable(raw) {
  if (!raw) return null;
  if (raw === true) return { legacy: true };
  if (typeof raw === 'object') {
    return {
      legacy: false,
      reason: raw.reason || null,
      owner: raw.owner || null,
      expires_at: raw['expires-at'] || raw.expires_at || null,
    };
  }
  return null;
}

function _normalize(doc) {
  if (!doc) return null;
  return {
    framework: doc.framework || 'Custom',
    version: doc.version || '1.0',
    controls: Object.entries(doc.controls || {}).map(([id, c]) => ({
      id,
      title: c.title || id,
      requires: Array.isArray(c.requires) ? c.requires : [],
      evidence: Array.isArray(c.evidence) ? c.evidence : [],
      not_applicable: _normalizeNotApplicable(c['not-applicable']),
      // FR-506: freshness + accountability metadata. All optional and
      // additive — a control naming neither owner/reviewer nor a review
      // interval is completely unaffected (no-op, matching every other
      // gate this session has built).
      owner: c.owner || null,
      reviewer: c.reviewer || null,
      reviewed_at: c['reviewed-at'] || c.reviewed_at || null,
      review_interval_days: typeof c['review-interval-days'] === 'number' ? c['review-interval-days']
        : (typeof c.review_interval_days === 'number' ? c.review_interval_days : null),
    })),
  };
}

/**
 * FR-506: is this control's evidence stale? Only meaningful when the
 * mapping author opted in via `review-interval-days` — a control with none
 * set is never stale, by construction (there is no baseline to be stale
 * relative to). `reviewed_at` missing while an interval IS set counts as
 * "never reviewed," which is at least as stale as a review that happened
 * on day zero — not a free pass.
 */
function _staleness(control, now) {
  if (!Number.isFinite(control.review_interval_days)) return { stale: false };
  const reviewedAt = control.reviewed_at ? Date.parse(control.reviewed_at) : NaN;
  const baseline = Number.isFinite(reviewedAt) ? reviewedAt : 0; // never-reviewed => already maximally stale
  const ageMs = now - baseline;
  const staleAfterMs = control.review_interval_days * 24 * 3600 * 1000;
  if (ageMs > staleAfterMs) {
    return { stale: true, reason: control.reviewed_at ? `last reviewed ${control.reviewed_at}, exceeds ${control.review_interval_days}-day interval` : `never reviewed (review-interval-days: ${control.review_interval_days} requires an initial reviewed-at)` };
  }
  return { stale: false };
}

/**
 * FR-506: has this control's not-applicable EXCEPTION expired? A bare-`true`
 * exception (legacy shape) never expires. An expired structured exception
 * reopens the control as a GAP (unevidenced), not silently back to
 * whatever `requires` would have said — an operator who marked something
 * not-applicable never ran the underlying checks, so there is no fresh
 * compliant/non-compliant verdict to fall back to.
 */
function _exceptionExpired(notApplicable, now) {
  if (!notApplicable || notApplicable.legacy) return false;
  if (!notApplicable.expires_at) return false;
  const exp = Date.parse(notApplicable.expires_at);
  return Number.isFinite(exp) && exp < now;
}

/**
 * Run a single primitive check against the scanner state.
 *   { passed, reason }
 */
function _runCheck(check, ctx) {
  if (check['finding-family']) {
    const family = check['finding-family'];
    const matching = (ctx.findings || []).filter(f => f.family === family);
    if (check['must-be'] === 'zero') {
      if (matching.length === 0) return { passed: true, reason: '0 findings' };
      return { passed: false, reason: `${matching.length} findings in family '${family}'` };
    }
    if (typeof check.min === 'number') {
      if (matching.length >= check.min) return { passed: true, reason: `${matching.length} ≥ ${check.min}` };
      return { passed: false, reason: `${matching.length} < ${check.min}` };
    }
    if (typeof check.max === 'number') {
      if (matching.length <= check.max) return { passed: true, reason: `${matching.length} ≤ ${check.max}` };
      return { passed: false, reason: `${matching.length} > ${check.max}` };
    }
    return { passed: false, reason: 'finding-family check has no must-be/min/max' };
  }
  if (check['file-exists'] || check['documented']) {
    const rel = check['file-exists'] || check['documented'];
    const fp = path.join(ctx.scanRoot, rel);
    if (fs.existsSync(fp)) return { passed: true, reason: `${rel} exists` };
    return { passed: false, reason: `${rel} not found` };
  }
  // FR-503: "mere artifact existence... is insufficient UNLESS the mapping
  // explicitly defines it." `file-exists` remains legitimate for controls
  // that genuinely only need "is there a policy document" — this is a NEW,
  // separate primitive a mapping author opts into for a control that
  // demands the file's CONTENT prove something (e.g. a workflow file that
  // must actually configure dependency automation, not merely exist under
  // that name with an empty body). Read-first-in-try/catch (D-0012) — no
  // existsSync-then-readFileSync, unlike the sibling file-exists check
  // above (pre-existing code, not touched here).
  if (check['file-contains']) {
    const rel = check['file-contains'];
    const fp = path.join(ctx.scanRoot, rel);
    let content;
    try { content = fs.readFileSync(fp, 'utf8'); }
    catch { return { passed: false, reason: `${rel} not found` }; }
    const patternStr = check.pattern;
    if (!patternStr) return { passed: false, reason: 'file-contains check has no pattern' };
    let re;
    try { re = new RegExp(patternStr, 'i'); }
    catch (e) { return { passed: false, reason: `file-contains pattern is not a valid regex: ${e.message}` }; }
    if (re.test(content)) return { passed: true, reason: `${rel} exists and matches required pattern` };
    return { passed: false, reason: `${rel} exists but does not match required pattern (mere existence is not enough for this control)` };
  }
  if (check['env-var-set']) {
    const name = check['env-var-set'];
    if (process.env[name]) return { passed: true, reason: `$${name} set` };
    return { passed: false, reason: `$${name} not set` };
  }
  if (check['sca-policy-has-entry']) {
    const type = check['sca-policy-has-entry'];
    const policyPath = statePath(ctx.scanRoot, 'sca-policy.yml');
    // FR-503 self-scan finding, fixed in passing: this was an
    // existsSync-then-readFileSync TOCTOU (D-0012's own named
    // anti-pattern) — read first, treat ENOENT as "not found" inside the
    // same catch that already handles a parse error, rather than a
    // separate pre-check with a window between it and the read.
    let raw;
    try { raw = fs.readFileSync(policyPath, 'utf8'); }
    catch { return { passed: false, reason: 'sca-policy.yml not found' }; }
    try {
      const policy = yaml.load(raw);
      if (type === 'accept-risk' && Array.isArray(policy['accept-risk']) && policy['accept-risk'].length) {
        return { passed: true, reason: `${policy['accept-risk'].length} accept-risk entries` };
      }
      if (type === 'sla' && policy.sla && Object.keys(policy.sla).length) {
        return { passed: true, reason: `${Object.keys(policy.sla).length} SLA buckets defined` };
      }
      return { passed: false, reason: `no ${type} entries in sca-policy.yml` };
    } catch (e) {
      return { passed: false, reason: 'sca-policy.yml parse error: ' + e.message };
    }
  }
  return { passed: false, reason: 'unknown check primitive' };
}

/**
 * Run all controls in the policy and emit a verification report.
 */
export function verifyPolicy(policy, ctx) {
  // CMP-5: loadPolicy() reports a parse failure as { _error }, which has no
  // `.controls` — the same shape as "no policy file at all". Distinguishing
  // them matters: a customer who typo'd their YAML deserves a loud error,
  // not a report that silently treats their (unparsed) policy as having no
  // controls to check.
  if (policy && policy._error) return { controls: [], status: 'error', error: policy._error };
  if (!policy || !policy.controls) return { controls: [], status: 'no-policy' };
  // CMP-5: a finding-family check must see every channel a real scan
  // produces (findings=SAST, secrets, logicVulns, supplyChain=SCA) — the
  // caller (engine.js) hands last-scan.json's own channel split through
  // ctx, so a control checking family:hardcoded-secret or
  // family:vulnerable-dep isn't blind to 3 of the engine's 4 finding types.
  // Family defaults mirror report/index.js's normalizeFindings so the two
  // modules can't drift apart on what family an untagged finding belongs to.
  ctx = {
    ...ctx,
    findings: [
      ...(ctx.findings || []),
      ...(ctx.secrets || []).map(s => ({ ...s, family: s.family || 'hardcoded-secret' })),
      ...(ctx.logicVulns || []),
      ...(ctx.supplyChain || []).map(sc => ({ ...sc, family: sc.family || 'vulnerable-dep' })),
    ],
  };
  const now = Date.now();
  const results = [];
  for (const control of policy.controls) {
    if (control.not_applicable) {
      // FR-506: an EXPIRED structured exception reopens the control as a
      // gap — nobody re-affirmed the exception, and the underlying checks
      // were never run, so there is no fresher verdict to report instead.
      if (_exceptionExpired(control.not_applicable, now)) {
        results.push({
          ...control, status: 'gap', checks: [],
          gapReason: `not-applicable exception expired on ${control.not_applicable.expires_at} — re-affirm or re-evaluate this control`,
        });
        continue;
      }
      results.push({ ...control, status: 'not-applicable', checks: [] });
      continue;
    }
    const checkResults = control.requires.map(c => ({ check: c, result: _runCheck(c, ctx) }));
    const allPassed = checkResults.every(r => r.result.passed);
    // FR-506: staleness is checked AFTER the real verdict, and can only ever
    // downgrade a `compliant` reading — a control already reporting
    // non-compliant findings does not need a second, redundant caveat that
    // its (already-failing) evidence is also old.
    const staleness = allPassed ? _staleness(control, now) : { stale: false };
    results.push({
      ...control,
      status: staleness.stale ? 'stale' : (allPassed ? 'compliant' : 'non-compliant'),
      ...(staleness.stale ? { staleReason: staleness.reason } : {}),
      checks: checkResults,
    });
  }
  const summary = {
    total: results.length,
    compliant: results.filter(r => r.status === 'compliant').length,
    nonCompliant: results.filter(r => r.status === 'non-compliant').length,
    notApplicable: results.filter(r => r.status === 'not-applicable').length,
    // FR-506: reported at the top level, not buried inside individual
    // controls — a summary that only says "compliant: 40" while 5 of those
    // are actually stale evidence, or 3 gaps hide behind expired
    // exceptions, is exactly the false-assurance shape this PRD exists to
    // close.
    stale: results.filter(r => r.status === 'stale').length,
    gap: results.filter(r => r.status === 'gap').length,
  };
  // FR-504: bind this conclusion to the inputs that could change it —
  // repository, commit, scope (framework+version), engine, ruleset,
  // analyzer health, and mapping version — so "changing any bound input
  // produces a new evidence digest" is a real, checkable property rather
  // than an assertion. Deliberately mirrors attestation.js's own
  // allowlist-then-sorted-JSON-then-sha256 shape rather than inventing a
  // fourth canonicalisation scheme in this codebase (see D-0026's lesson,
  // applied here even though this isn't a SIGNED bundle — the same
  // "unambiguous, reproducible digest of a defined field set" discipline
  // still applies).
  const evidenceDigest = computeEvidenceDigest({
    repository: ctx.repository ?? null,
    commit: ctx.commit ?? _currentCommit(ctx.scanRoot),
    scope: `${policy.framework}@${policy.version}`,
    engine: SCANNER_VERSION,
    ruleset: ctx.rulesetVersion ?? null,
    analyzerHealth: ctx.scanHealth?.status ?? null,
    mappingVersion: policy.version,
    controls: results.map(r => ({ id: r.id, status: r.status })),
  });
  return { framework: policy.framework, version: policy.version, controls: results, summary, evidenceDigest };
}

// `scanRoot` is the scanned project's repository, not this project's own
// trusted checkout — hardened per FR-PROV-024 / the second Finding
// Provenance PRD audit sweep (found missing here by a follow-up review that
// grepped for `child_process` usage beyond just `execFileSync('git'` call
// sites). `rev-parse HEAD` was VERIFIED not to itself trigger
// `core.fsmonitor`/a hook, so this is not a second live RCE — but the
// shell-string `execSync` form was gratuitous risk with no upside (no
// caller-controlled input to interpolate), and left this call outside the
// config/env hardening every other git call in this codebase now has.
function _currentCommit(scanRoot) {
  if (!scanRoot) return null;
  try {
    return execFileSync('git', hardenGitArgs(['rev-parse', 'HEAD']), { cwd: scanRoot, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'], env: hardenGitEnv() }).trim();
  } catch { return null; } // not a git repo, or git unavailable — not an error condition
}

/**
 * FR-504: the signed field set — an allowlist, exactly as attestation.js
 * and evidence-bundle.js canonicalise. A field not named here is not bound,
 * so a future addition to the evidence report cannot silently join or
 * leave the digest's scope.
 */
export function computeEvidenceDigest(fields) {
  const bound = {
    repository: fields.repository ?? null,
    commit: fields.commit ?? null,
    scope: fields.scope ?? null,
    engine: fields.engine ?? null,
    ruleset: fields.ruleset ?? null,
    analyzerHealth: fields.analyzerHealth ?? null,
    mappingVersion: fields.mappingVersion ?? null,
    controls: [...(fields.controls || [])].sort((a, b) => String(a.id).localeCompare(String(b.id))),
  };
  return crypto.createHash('sha256').update(_canonicalJson(bound), 'utf8').digest('hex');
}

// Deterministic JSON — keys sorted at every level, arrays order-preserving.
// Same algorithm as evidence-bundle.js's canonicalJson (duplicated rather
// than imported for the same reason policy-bundle.js gave: a pure,
// three-line function, and importing it would couple this module's digest
// format to a sibling module's internals for no real benefit).
function _canonicalJson(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value ?? null);
  if (Array.isArray(value)) return `[${value.map(_canonicalJson).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${_canonicalJson(value[k])}`).join(',')}}`;
}

/**
 * Emit JSON-LD compliance evidence (the Vanta/Drata-shape artifact).
 */
export function emitEvidenceJsonLd(report, scanRoot) {
  if (!report) return null;
  const jsonld = {
    '@context': {
      '@vocab': 'https://agentic-security.io/compliance/v1/',
      'schema': 'https://schema.org/',
    },
    '@type': 'ComplianceEvidence',
    // FR-508: schema version and status semantics travel WITH the
    // document — a consumer does not need to know this codebase's own
    // source to interpret either. policySource names exactly which
    // mapping file produced this export (the one per-export "source
    // reference" that is not already implicit in each control's own
    // `checks[].rule`, which already carries the raw check definition).
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    statusSemantics: STATUS_SEMANTICS,
    policySource: `${STATE_DIR_NAME}/${POLICY_FILE}`,
    framework: report.framework,
    version: report.version,
    generatedAt: new Date().toISOString(),
    // CMP-5 / FR-507: this artifact is fed to GRC tooling (Vanta/Drata/
    // SecureFrame) and auditors largely unread by a human — the same reason
    // auditor-walkthrough.js's narrative carries this disclaimer verbatim.
    // Without it here, a machine-consumed "ComplianceEvidence" document reads
    // as an attestation, not a scanner's automated observation. Sourced from
    // evidence-grade-wording.js — see that module's header for why this text
    // names all three assurance tiers explicitly, not just "not certified."
    disclaimer: EVIDENCE_GRADE_DISCLAIMER,
    provenance: { engineVersion: SCANNER_VERSION },
    // FR-504: "changing any bound input produces a new evidence digest."
    // Present only when verifyPolicy actually computed one (every real
    // caller does; a hand-built report in a test predating this field
    // simply omits it, rather than this function fabricating one from
    // partial information).
    ...(report.evidenceDigest ? { evidenceDigest: report.evidenceDigest } : {}),
    summary: report.summary,
    controls: report.controls.map(c => ({
      '@type': 'Control',
      id: c.id, title: c.title, status: c.status,
      // FR-506: present only when set — an owner-less, reviewer-less
      // control (the overwhelming majority, for any policy predating this
      // field) does not gain fabricated accountability metadata.
      ...(c.owner ? { owner: c.owner } : {}),
      ...(c.reviewer ? { reviewer: c.reviewer } : {}),
      ...(c.staleReason ? { staleReason: c.staleReason } : {}),
      ...(c.gapReason ? { gapReason: c.gapReason } : {}),
      checks: c.checks.map(ck => ({
        '@type': 'Check',
        rule: ck.check,
        passed: ck.result.passed,
        reason: ck.result.reason,
      })),
      narrative_evidence: c.evidence || [],
    })),
  };
  // FR-505: "sign evidence manifests WHEN SIGNING IS CONFIGURED" — a no-op
  // when the operator has not already set up a signing key (the common
  // case), so an ordinary scan's behavior is unchanged unless an operator
  // opted in. loadSigningKeyIfConfigured only ever READS an existing key,
  // never generates one — see that function's own header for why emitting
  // compliance evidence (an automatic, routine side effect of every scan)
  // must not silently create key material the way an explicit `attest`
  // command legitimately does.
  let signed = jsonld;
  const signingKey = loadSigningKeyIfConfigured();
  if (signingKey) signed = signComplianceEvidence(jsonld, signingKey.privateKeyPem);
  // Through the seam — see the note in pqc-migration-plan.js. The report is
  // still returned when writing is off; only the artifact is withheld.
  // FR-705: this artifact is marked confidential in artifact-registry.js.
  // maybeEncryptForWrite is a safe no-op when encryption isn't configured
  // (the overwhelming default case) and encrypts the JSON body when it is.
  // The fail-closed half of FR-705's acceptance criterion lives HERE: when
  // encryption is required but unavailable, the write is skipped entirely
  // — never a plaintext fallback — and an operator is told why, rather
  // than silently persisting unencrypted sensitive compliance evidence.
  const gated = maybeEncryptForWrite(scanRoot, 'compliance-evidence.json', JSON.stringify(signed, null, 2));
  if (!gated.ok) {
    // Always visible, not debug-gated: a required control silently not
    // being met is exactly the kind of thing FR-705 exists to surface,
    // not hide behind an opt-in verbosity flag.
    process.stderr.write(`[agentic-security] compliance-evidence.json NOT written: ${gated.reason}\n`);
  } else {
    safeWriteState(statePath(scanRoot, 'compliance-evidence.json'), gated.content);
  }
  return signed;
}

/**
 * Emit a human-readable markdown summary.
 */
export function emitEvidenceMarkdown(report, scanRoot) {
  const lines = [];
  lines.push(`# Compliance evidence — ${report.framework}`);
  lines.push('');
  lines.push(`Generated by agentic-security (engine ${SCANNER_VERSION}) on ${new Date().toISOString().slice(0,10)}.`);
  lines.push('');
  lines.push(`> ${EVIDENCE_GRADE_DISCLAIMER_SHORT}`);
  lines.push('');
  if (report.evidenceDigest) {
    lines.push(`Evidence digest (FR-504 — repository, commit, scope, engine, ruleset, analyzer health, and mapping version bound): \`${report.evidenceDigest}\``);
    lines.push('');
  }
  lines.push(`Compliant: **${report.summary.compliant}** / Non-compliant: **${report.summary.nonCompliant}** / Not applicable: **${report.summary.notApplicable}**` +
    `${report.summary.stale ? ` / Stale: **${report.summary.stale}**` : ''}${report.summary.gap ? ` / Gap: **${report.summary.gap}**` : ''} of ${report.summary.total} controls.`);
  lines.push('');
  for (const c of report.controls) {
    lines.push(`## ${c.id} — ${c.title}  (${c.status})`);
    if (c.owner) lines.push(`- owner: ${c.owner}`);
    if (c.reviewer) lines.push(`- reviewer: ${c.reviewer}`);
    if (c.staleReason) lines.push(`- ⚠ stale: ${c.staleReason}`);
    if (c.gapReason) lines.push(`- ⚠ gap: ${c.gapReason}`);
    for (const ck of c.checks) {
      const mark = ck.result.passed ? '✓' : '✗';
      lines.push(`- ${mark} \`${JSON.stringify(ck.check)}\` — ${ck.result.reason}`);
    }
    if (c.evidence && c.evidence.length) {
      lines.push('');
      lines.push('**Narrative evidence:**');
      for (const e of c.evidence) lines.push(`- ${e}`);
    }
    lines.push('');
  }
  // FR-705: same fail-closed gate as emitEvidenceJsonLd above.
  const rendered = lines.join('\n');
  const gated = maybeEncryptForWrite(scanRoot, 'compliance-evidence.md', rendered);
  if (!gated.ok) {
    process.stderr.write(`[agentic-security] compliance-evidence.md NOT written: ${gated.reason}\n`);
  } else {
    safeWriteState(statePath(scanRoot, 'compliance-evidence.md'), gated.content);
  }
  return rendered;
}

export const _internals = { _normalize, _runCheck, _staleness, _exceptionExpired, _currentCommit };
