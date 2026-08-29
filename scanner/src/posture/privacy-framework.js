// NIST Privacy Framework 1.1 — assessment + remediation planning.
//
// The bundled control set (`compliance-frameworks/nist-privacy-1-1.json`) is
// rendered by `auditor-walkthrough.js` like every other framework. This module
// adds the half a walkthrough cannot give you: a gap becomes a FINDING carrying
// a concrete remediation, so it flows through the same triage and `/fix` path
// as any other finding rather than sitting in a narrative nobody actions.
//
// THE INTEGRITY RULE THIS MODULE EXISTS TO ENFORCE
// -----------------------------------------------
// NIST ships a `Code Testable?` rating per control — yes / partial / no. On the
// 104 controls: 23 yes, 33 partial, **48 no**.
//
// That rating says whether a control COULD be assessed from source code. It does
// NOT say this engine assesses it. Conflating the two is how a compliance tool
// starts reporting governance controls — "the organization's privacy values are
// communicated" — as PASSED because no scanner rule fired against them. Silence
// is not evidence, and a clean report over 48 controls nobody measured is worse
// than no report: it is a false assurance that someone will hand to an auditor.
//
// So every control lands in exactly one of four buckets, and the bucket is
// always stated:
//
//   satisfied     mapped to a real engine signal, and that signal is clean
//   gap           mapped to a real engine signal, and that signal is dirty
//                 → this is the only bucket that produces a finding
//   engine-gap    NIST rates it code-testable, but this engine has no signal
//                 → disclosed BY NAME, never counted as satisfied
//   manual        NIST rates it not code-testable (governance, policy, process)
//                 → out of scope for any scanner, stated as such
//
// `engine-gap` is the bucket that keeps this honest. It is the difference
// between "we checked and it is fine" and "nobody checked", and it is reported
// with the same prominence as a failure because to a reader relying on the
// output they are the same thing.

import { loadFramework, evaluateFramework } from './auditor-walkthrough.js';
import { statePath, safeWriteState } from './state-dir.js';
import { EVIDENCE_GRADE_DISCLAIMER_SHORT } from './evidence-grade-wording.js';
import { PROVENANCE_COMPLIANCE_DISCLAIMER } from './provenance/schema.js';

export const PRIVACY_FRAMEWORK_ID = 'nist-privacy-1-1';

/** Bucket names, in report order (worst first). */
export const BUCKETS = Object.freeze(['gap', 'engine-gap', 'manual', 'satisfied']);

/**
 * Remediation per control family. Deliberately ACTIONABLE — a command or a
 * concrete artifact — rather than a restatement of the control text, which is
 * what a compliance report usually offers and what makes them ignorable.
 *
 * Keyed by the control-id prefix so a new control in an existing category
 * inherits sensible guidance instead of silently getting none.
 */
const REMEDIATION = [
  [/^PR\.DS-P1$/, 'Encrypt data at rest with an AEAD cipher. Replace ECB mode and static IVs; run `/fix --family crypto-weak-cipher` to apply the deterministic swaps.'],
  [/^PR\.DS-P2$/, 'Enforce TLS 1.2+ and stop disabling certificate verification. `/fix --family crypto-tls-no-verify` patches the verify-off call sites.'],
  [/^PR\.AA-P1$/, 'Remove hardcoded credentials and add authentication to unauthenticated routes. `/fix --rotate-secret` handles the secrets; auth gaps need a route-level decision.'],
  [/^PR\.AA-P4$/, 'Sign and verify identity assertions with a modern algorithm — no `none` alg, no weak-hash HMAC.'],
  [/^PR\.AA-05$/, 'Add object-level authorization on endpoints that read or mutate personal data. Review the IDOR and authz findings individually; these are not safely auto-patchable.'],
  [/^PR\.PS-P1$/, 'Tighten IaC: drop privileged pod security contexts and over-permissive IAM policies.'],
  [/^PR\.PS-P2$/, 'Upgrade dependencies carrying known advisories. `/fix --sca` proposes the version bumps.'],
  [/^PR\.PS-P4$/, 'Resolve dependency-confusion exposure by pinning internal scopes to your private registry.'],
  [/^PR\.IR-P1$/, 'Restrict network and cluster access — no cluster-admin bindings, no wildcard IAM.'],
  [/^PR\.DS-P8$/, 'Record an SBOM snapshot per release so dependency substitution is detectable.'],
  [/^CT\.DP-P/, 'Reduce what is observable: minimise PII reaching logs, responses, and third parties; de-identify where the data action does not need identity.'],
  [/^CT\.DM-P6$/, 'Transmit over TLS with a standard, current cipher suite.'],
  [/^CT\.DM-P9$/, 'Retain scan history and the MCP audit log so data-processing activity is reviewable.'],
  [/^CT\.DM-P10$/, 'Keep fix history so the technical measures you applied are demonstrably tested, not asserted.'],
  [/^CT\.PO-P/, 'Declare the policy in `.agentic-security/compliance.policy.yml` so it is verified on every scan rather than remembered.'],
  [/^CM\.AW-P4$/, 'Preserve the audit log — it is the record of disclosure this control asks for.'],
  [/^CM\.AW-P6$/, 'Keep SBOM snapshots and signed scan state so provenance and lineage survive review.'],
  [/^ID\.IM-P/, 'Produce the inventory artifacts: run a scan so the SBOM, threat model, and PII field map exist and are current.'],
  [/^ID\.RA-P3$/, 'Triage the PII-exposure findings — each is a problematic data action this control asks you to identify.'],
  [/^ID\.BE-P3$/, 'Generate the threat model so priority systems and their requirements are recorded.'],
  [/^GV\.PO-P2$/, 'Commit a compliance policy file so privacy expectations are enforced in CI, not just documented.'],
];

/** The remediation for a control, or null when none is defined. */
export function remediationFor(controlId) {
  for (const [re, text] of REMEDIATION) if (re.test(controlId)) return text;
  return null;
}

/**
 * Bucket one evaluated control.
 *
 * `evaluateFramework` returns 'present' | 'partial' | 'manual'. That vocabulary
 * cannot distinguish "no mapping because it is a governance control" from "no
 * mapping because we never built the check" — which is exactly the distinction
 * that decides whether a reader should worry. `codeTestable` supplies it.
 */
export function bucketOf(result, { assessable = true } = {}) {
  const c = result.control || {};
  const mapped = Array.isArray(c.mapsTo) && c.mapsTo.length > 0;
  if (mapped) {
    // VACUOUS SATISFACTION GUARD. `evaluateFramework` clears a `family:`
    // mapping when no findings of that family are open — which is also true of
    // a scan that examined nothing at all. Without this, pointing the tool at
    // an empty directory reports privacy controls as SATISFIED, on the strength
    // of having looked at zero files. That is the same false assurance the
    // manual bucket exists to prevent, arriving by a different route, and it
    // was caught by this module's own test rather than in review.
    if (!assessable) return 'engine-gap';
    return result.status === 'present' ? 'satisfied' : 'gap';
  }
  return String(c.codeTestable || 'no').toLowerCase() === 'no' ? 'manual' : 'engine-gap';
}

/** Severity for a gap. Privacy controls are graded by what the gap exposes. */
function severityFor(controlId) {
  if (/^PR\.(DS|AA)/.test(controlId)) return 'high';   // encryption, identity, access
  if (/^CT\.DP/.test(controlId)) return 'medium';      // data minimisation
  return 'low';
}

/**
 * Assess a scan against NIST Privacy Framework 1.1.
 *
 * Returns `{ frameworkId, controls[], summary, findings[] }`. Never throws:
 * posture modules degrade to a null result rather than failing a scan.
 */
// FR-405 (assurance-hardening PRD): controls whose ENTIRE mapping depends on
// privacy-taint's signal — a "clean" (present) result from a NON-IR-backed
// run (deep mode off, the default path) is not real evidence for these
// specifically, even when the scan otherwise examined real files and is
// `assessable` for every other control. Deliberately conservative: a control
// with an ADDITIONAL, independent mapping (e.g. CT.DP-P1's `family:data-
// exposure` alongside `family:pii-exposure`) is left alone, because that
// other signal may still be real and this module cannot attribute which
// specific mapping produced a "present" verdict. Confirmed by direct
// execution against this exact framework file that CT.DP-P4/CT.DP-P5 (both
// codeTestable:'yes', both mapped ONLY to `module:privacy-taint`) currently
// read `satisfied` from a run with zero real IR-backed analysis — see
// decisions.md for the reproduction.
function _isPurelyPrivacyTaintDependent(control) {
  const mapsTo = Array.isArray(control?.mapsTo) ? control.mapsTo : [];
  return mapsTo.length > 0 && mapsTo.every(m => m === 'module:privacy-taint' || m === 'family:pii-exposure');
}

export function assessPrivacyFramework(scanRoot, scan, opts = {}) {
  const fw = loadFramework(scanRoot, PRIVACY_FRAMEWORK_ID);
  if (!fw) return null;

  let evaluation;
  try { evaluation = evaluateFramework(scanRoot, fw, scan || {}); } catch { return null; }

  // Did the scan actually examine anything? A clean signal from a run that read
  // no files is not evidence — see the guard in bucketOf.
  const filesScanned = Number(scan && (scan.filesScanned ?? scan._scanMeta?.filesScanned)) || 0;
  const assessable = filesScanned > 0
    || (Array.isArray(scan?.findings) && scan.findings.length > 0)
    || (Array.isArray(scan?.components) && scan.components.length > 0);
  // `null` (never ran) and `false` (ran but degraded) are both "not real
  // IR-backed evidence" for the gate below; only `true` clears it.
  const privacyIrBacked = scan?.privacyIrBacked === true;

  const controls = [];
  const findings = [];
  const summary = { gap: 0, 'engine-gap': 0, manual: 0, satisfied: 0, total: 0 };

  for (const r of evaluation) {
    const c = r.control || {};
    const privacyTaintGated = !privacyIrBacked && _isPurelyPrivacyTaintDependent(c);
    const controlAssessable = assessable && !privacyTaintGated;
    const bucket = bucketOf(r, { assessable: controlAssessable });
    summary[bucket] += 1;
    summary.total += 1;

    const row = {
      id: c.id,
      function: c.function || null,
      category: c.category || null,
      summary: c.summary || '',
      codeTestable: c.codeTestable || 'no',
      bucket,
      observations: r.observations || [],
    };
    if (bucket === 'engine-gap') {
      // Named, not counted as a pass. See the header.
      row.disclosure = privacyTaintGated
        ? 'This control depends entirely on privacy-taint\'s signal, which ran without a real IR this scan (deep mode off, or an unsupported language) — a "no findings" result in that mode is not real evidence. NOT assessed.'
        : (Array.isArray(c.mapsTo) && c.mapsTo.length && !assessable)
          ? 'This control is mapped, but the scan examined no files — a clean signal from a run that read nothing is not evidence. NOT assessed.'
          : `NIST rates this control code-testable (${row.codeTestable}), but this engine has no signal for it. It was NOT assessed.`;
    }
    if (bucket === 'manual') {
      row.disclosure = 'NIST rates this control not code-testable — it is a governance, policy, or process control and is outside any scanner\'s reach.';
    }
    controls.push(row);

    if (bucket !== 'gap') continue;
    const remediation = remediationFor(c.id)
      || 'Review the observations for this control and close the underlying findings.';
    findings.push({
      id: `privacy-framework:${c.id}`,
      severity: severityFor(c.id),
      // A compliance gap is a property of the project, not of one line. The
      // framework file is cited so the finding still has a real, openable
      // location rather than a fabricated one.
      file: '.agentic-security/compliance/nist-privacy-1-1',
      line: 0,
      vuln: `NIST Privacy Framework ${c.id} not satisfied — ${c.summary}`,
      cwe: 'CWE-359',
      description: [
        `Control ${c.id} (${c.category || c.function || 'privacy'}) is mapped to engine signals that are currently failing.`,
        ...(r.observations || []),
      ].join(' '),
      remediation,
      parser: 'COMPLIANCE',
      family: 'privacy-compliance',
      complianceControl: { framework: PRIVACY_FRAMEWORK_ID, id: c.id, codeTestable: c.codeTestable || 'no' },
      controlRefs: r.controlRefs || [],
      // PRD Section 8 REQUIRED DISCLAIMER. `derivedProvenance` carries an
      // origin commit, author and confidence onto a COMPLIANCE claim, and
      // `compliance --privacy --format json` prints this object straight to
      // stdout -- a second human-facing surface for the same data the auditor
      // walkthrough disclaims inline. Found by a review of the walkthrough
      // fix, which had asserted renderWalkthrough was the only consumer. The
      // disclaimer travels ON the record rather than beside it, because a
      // JSON consumer can slice a single finding out of the array and the
      // caveat has to survive that.
      derivedProvenance: r.derivedProvenance
        ? { ...r.derivedProvenance, disclaimer: PROVENANCE_COMPLIANCE_DISCLAIMER }
        : null,
    });
  }

  return {
    frameworkId: PRIVACY_FRAMEWORK_ID,
    frameworkName: fw.name,
    controls,
    summary,
    findings,
    // Carried in the result so a consumer cannot present the numbers without
    // it. `satisfied` is a share of the ASSESSED controls, never of all 104.
    assessable,
    interpretation:
      (!assessable ? 'The scan examined no files, so NO control was assessed. ' : '') +
      `${summary.satisfied} of ${summary.satisfied + summary.gap} assessed controls satisfied. ` +
      `${summary['engine-gap']} controls NIST rates code-testable were NOT assessed by this engine, and ` +
      `${summary.manual} are governance controls outside any scanner's reach. ` +
      'Neither group is evidence of compliance.',
    ...(opts.includeFindings === false ? { findings: [] } : {}),
  };
}

/**
 * Render the assessment as Markdown, worst bucket first.
 *
 * Order is deliberate: gaps, then the controls nobody assessed, then governance,
 * then satisfied. A report that opens with what passed invites the reader to
 * stop there, which is precisely the wrong reading of a document where most
 * controls carry no engine evidence at all.
 */
function renderPrivacyMarkdown(result) {
  if (!result) return '';
  const L = [];
  L.push(`# ${result.frameworkName} — assessment`);
  L.push('');
  L.push(result.interpretation);
  L.push('');
  L.push('| Bucket | Controls | Meaning |');
  L.push('| --- | --- | --- |');
  L.push(`| Gap | ${result.summary.gap} | Mapped to an engine signal, and that signal is failing |`);
  L.push(`| Not assessed | ${result.summary['engine-gap']} | Code-testable, but this engine has no signal — **not** a pass |`);
  L.push(`| Manual | ${result.summary.manual} | Governance/policy control, outside any scanner's reach |`);
  L.push(`| Satisfied | ${result.summary.satisfied} | Mapped, and the signal is clean |`);
  L.push('');
  L.push('> A control in *Not assessed* or *Manual* is not evidence of compliance.');
  // FR-507: sourced from evidence-grade-wording.js so this artifact stays in
  // sync with every other compliance-adjacent disclaimer in the codebase.
  L.push(`> ${EVIDENCE_GRADE_DISCLAIMER_SHORT}`);
  L.push('');
  for (const bucket of BUCKETS) {
    const rows = result.controls.filter(c => c.bucket === bucket);
    if (!rows.length) continue;
    L.push(`## ${bucket} (${rows.length})`);
    L.push('');
    for (const c of rows) {
      L.push(`### ${c.id} — ${c.summary}`);
      L.push(`- NIST code-testable: **${c.codeTestable}**`);
      if (c.disclosure) L.push(`- ${c.disclosure}`);
      for (const o of c.observations || []) L.push(`- ${o}`);
      const rem = bucket === 'gap' ? remediationFor(c.id) : null;
      if (rem) L.push(`- **Remediation:** ${rem}`);
      L.push('');
    }
  }
  return L.join('\n');
}

/**
 * Persist the assessment. Through the seam, so a read-only scan writes nothing
 * while still RETURNING the assessment — the switch changes what is written,
 * never what is reported.
 */
export function persistPrivacyFramework(scanRoot, result) {
  if (!result) return null;
  safeWriteState(statePath(scanRoot, 'privacy-framework.json'), JSON.stringify(result, null, 2));
  safeWriteState(statePath(scanRoot, 'privacy-framework.md'), renderPrivacyMarkdown(result));
  return result;
}
