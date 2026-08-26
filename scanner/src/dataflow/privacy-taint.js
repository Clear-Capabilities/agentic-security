// Privacy / PII data-flow tracking — Recommendation #9 of the
// world-class roadmap.
//
// Runs the existing taint engine with a different lattice (PII / PHI /
// PCI / FIN classes, instead of security taint) to track where each
// regulated-data class flows through a codebase. Outputs:
//
//   1. Per-field PII classification — `user.email: PII (CWE-359 Information
//      Disclosure if reflected)`
//   2. Data flow diagrams — exit points (sinks) per PII class — where
//      regulated data leaves the application (response body, log file,
//      third-party API call, S3 upload, etc.)
//   3. Auto-generated DPIA stub for GDPR Art. 35 / CCPA §1798.130 /
//      HIPAA §164.530 — a compliance artifact the customer's privacy
//      counsel can use
//   4. Findings: each "PII leaves system via untrusted sink" emits a
//      privacy finding with family `pii-exposure`
//
// The PII detection is deterministic and field-name based. We DO NOT
// attempt content classification (Luhn-checking actual values would
// only catch leaks that have already happened); we classify by NAME
// + TYPE in declarations.
//
// The data-class taxonomy itself (PII/PHI/PCI/FIN/CREDENTIALS/GEOLOCATION/
// DEVICE_ID, plus any organization-defined classes) is versioned and
// customizable without editing this file — see ./privacy-taxonomy.js
// (assurance-hardening PRD FR-402). This module keeps only the sink
// taxonomy (where regulated data exits), which is not in FR-402's scope.
//
// Whether a class-reaches-sink flow actually PRODUCES a finding is
// policy-gated (assurance-hardening PRD FR-404) — see
// ./privacy-sink-policy.js. With no policy configured every match is
// prohibited, unchanged from before FR-404.

import {
  BUILTIN_TAXONOMY_VERSION, DEFAULT_TAXONOMY, compileTaxonomy,
  loadPrivacyTaxonomy, classifyFieldAgainst, severityForClasses,
} from './privacy-taxonomy.js';
import { loadPrivacySinkPolicy, isSinkPermitted, permittingRules } from './privacy-sink-policy.js';
import { GOVERNANCE_FIELDS, governanceRecordFor } from './privacy-governance.js';

const _BUILTIN_COMPILED = compileTaxonomy(DEFAULT_TAXONOMY);

const SINK_PATTERNS = {
  log: /\b(?:log|logger|console|System\.out|System\.err|stdout|stderr|fmt\.Print|print)\b/i,
  response: /\b(?:res|response|ctx\.response|HttpContext\.Response)\s*\.\s*(?:write|send|json|render|body)\b/i,
  outboundHttp: /\bfetch\b(?:$|[(\s.])|\b(?:axios|got|httpClient|HttpClient|WebClient|requests|node_fetch)\s*(?:\.\s*(?:get|post|put|delete|send|invoke|patch|head)|\()/i,
  thirdPartySdk: /\b(?:stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|intercom)\s*\.\s*track|identify|capture\b/i,
  fileWrite: /\b(?:fs\.writeFile|File\.WriteAllText|File\.AppendAllText|open\([^)]*,\s*['"]w)\b/i,
  s3Upload: /\b(?:s3|S3Client|aws\.S3)\s*\.\s*putObject\b/i,
  emailSend: /\b(?:nodemailer|sendMail|SendGrid|sendgrid|smtp)\b/i,
};

/**
 * Classify a field/variable name into the built-in taxonomy's buckets
 * (PII / PHI / PCI / FIN / CREDENTIALS / GEOLOCATION / DEVICE_ID).
 * Returns an array of bucket labels (possibly empty, possibly multiple).
 * `compiled` is an optional pre-compiled taxonomy (see
 * privacy-taxonomy.js's compileTaxonomy / loadPrivacyTaxonomy) — omit it
 * to classify against the built-in defaults only.
 */
export function classifyField(name, compiled) {
  return classifyFieldAgainst(name, compiled || _BUILTIN_COMPILED);
}

/**
 * Classify an outbound-data sink expression. Returns the matching sink
 * label (log / response / outboundHttp / etc.) or null.
 */
export function classifySink(expr) {
  if (!expr) return null;
  for (const [label, p] of Object.entries(SINK_PATTERNS)) if (p.test(expr)) return label;
  return null;
}

/**
 * Run a privacy-taint pass over the per-file IR. For each field declared
 * as PII/PHI/PCI/FIN, track flow into a classifySink-matched sink. Emit
 * a privacy-leak finding when a regulated class reaches a non-secure
 * sink (log, response, outbound HTTP, etc.).
 */
export function annotatePrivacyTaint(perFileIR, opts = {}) {
  // FR-402 (assurance-hardening PRD): the taxonomy used for classification
  // is resolved once per call, not hardcoded — `opts.compiled` lets a
  // caller (tests, or a future dry-run) hand in an already-compiled
  // taxonomy directly; `opts.scanRoot` loads and compiles the effective
  // (built-in + operator-config) taxonomy from disk. Neither is required:
  // omitting both classifies against the built-in defaults, unchanged from
  // before FR-402.
  const { version, compiled } = opts.compiled
    ? { version: opts.taxonomyVersion || BUILTIN_TAXONOMY_VERSION, compiled: opts.compiled }
    : (opts.scanRoot ? loadPrivacyTaxonomy(opts.scanRoot) : { version: BUILTIN_TAXONOMY_VERSION, compiled: _BUILTIN_COMPILED });
  // FR-404 (assurance-hardening PRD): whether a class-reaches-sink flow is
  // PROHIBITED is policy-gated the same way — `opts.sinkPolicy` for a
  // caller that already has one, `opts.scanRoot` to load
  // .agentic-security/privacy-policy.json, or the empty policy (everything
  // prohibited, the pre-FR-404 default) when neither is given.
  const sinkPolicy = opts.sinkPolicy || (opts.scanRoot ? loadPrivacySinkPolicy(opts.scanRoot) : { allow: [] });
  // FR-408: the current deployment environment, ONLY from an explicit
  // caller-supplied opts.environment or AGENTIC_SECURITY_ENVIRONMENT — never
  // NODE_ENV (see privacy-sink-policy.js's header for why). Unset means an
  // environment-scoped allow rule never matches (fail closed), same as
  // before this option existed.
  const policyCtx = { environment: opts.environment || process.env.AGENTIC_SECURITY_ENVIRONMENT || null };
  if (!perFileIR) return { findings: [], piiFields: [], taxonomyVersion: version, policyExemptions: [] };
  const findings = [];
  const piiFields = [];
  // Suppression must be visible, not silent — same principle as the
  // ignore-pragma suppression ledger (root CLAUDE.md): a policy-permitted
  // flow is recorded here, never just dropped.
  const policyExemptions = [];
  for (const [filePath, ir] of (perFileIR instanceof Map ? perFileIR : Object.entries(perFileIR))) {
    if (!ir || !ir._content) continue;
    const lines = ir._content.split('\n');
    // Step 1: collect PII-classified decls.
    const taintedVars = new Map(); // name → array of bucket labels
    // FR-406: declaration line per source variable, so a finding/exemption
    // emitted below can link back to where the regulated data ENTERED
    // (evidence locations must cover both ends of a flow, not just the
    // sink) without re-deriving it from piiFields by proximity guessing.
    const declLineByName = new Map();
    for (const d of ir.decls || []) {
      const classes = classifyFieldAgainst(d.name, compiled);
      if (classes.length) {
        taintedVars.set(d.name, classes);
        declLineByName.set(d.name, d.line);
        piiFields.push({ file: filePath, line: d.line, name: d.name, classes, declaredType: d.type || null });
      }
    }
    // Step 2: walk calls and assignments looking for a PII variable
    // reaching a sink.
    for (const call of ir.calls || []) {
      const argText = (call.args || []).map(a => a.text || '').join(',');
      // FR-408: the raw sink expression text, e.g. "stripe.track" — the
      // destination-matching axis needs the actual call identity, not just
      // its broader sink CATEGORY (sinkLabel), which "stripe.track" and
      // "axios.post" would otherwise share.
      const destText = call.fullPath || call.callee || '';
      const sinkLabel = classifySink(destText);
      if (!sinkLabel) continue;
      const ctx = { ...policyCtx, destination: destText };
      for (const [name, classes] of taintedVars) {
        if (!new RegExp(`\\b${name.replace(/[.+^${}()|\\]/g, '\\$&')}\\b`).test(argText)) continue;
        const sourceLine = declLineByName.get(name) ?? null;
        if (isSinkPermitted(classes, sinkLabel, sinkPolicy, ctx)) {
          policyExemptions.push({
            file: filePath, line: call.line, name, classes, sinkKind: sinkLabel,
            sourceLine,
            rules: permittingRules(classes, sinkLabel, sinkPolicy, ctx).map(r => ({ sink: r.sink, class: r.class || null, reason: r.reason || null, environment: r.environment || null, destination: r.destination || null })),
          });
          continue;
        }
        findings.push({
          family: 'pii-exposure',
          subfamily: classes.join('+'),
          file: filePath, line: call.line,
          severity: severityForClasses(classes, compiled),
          cwe: 'CWE-359', // Exposure of Private Personal Information
          vuln: `Privacy — ${classes.join('+')} data flows to ${sinkLabel} sink`,
          snippet: (lines[call.line - 1] || '').trim().slice(0, 200),
          remediation: `${classes.join(' + ')} data must not flow to ${sinkLabel} unencrypted. Mask, redact, or hash the value before logging / responding / sending to third parties.`,
          piiClass: classes,
          sinkKind: sinkLabel,
          // FR-406: evidence linkage back to the source declaration, not
          // just the sink call site.
          sourceName: name,
          sourceLine,
        });
      }
    }
  }
  return { findings, piiFields, taxonomyVersion: version, policyExemptions };
}

/**
 * Emit a DPIA (Data Protection Impact Assessment) Markdown artifact
 * summarizing the privacy posture for compliance reporting. Output goes
 * to .agentic-security/dpia.md.
 */
export function emitDpiaArtifact(piiFields, findings, opts = {}) {
  const grouped = new Map();
  for (const field of piiFields) {
    for (const cls of field.classes) {
      let g = grouped.get(cls);
      if (!g) { g = []; grouped.set(cls, g); }
      g.push(field);
    }
  }
  const lines = [];
  lines.push(`# Data Protection Impact Assessment (DPIA)`);
  lines.push('');
  lines.push(`Generated by agentic-security scanner on ${new Date().toISOString().slice(0, 10)}.`);
  lines.push('');
  lines.push(`This is an automated DPIA scaffold derived from static analysis.`);
  lines.push(`It must be reviewed and completed by a privacy officer before use.`);
  lines.push('');
  lines.push(`## Data classes identified`);
  lines.push('');
  // FR-407: governance fields (purpose, lawful basis, subject, retention,
  // residency, recipient, transfer, minimization, consent, access,
  // deletion) — none inferable from code, so every one is either
  // operator-supplied (opts.governanceConfig) or explicitly manual_required,
  // never blank and never guessed.
  const governanceConfig = opts.governanceConfig || null;
  for (const [cls, fields] of grouped) {
    lines.push(`### ${cls} (${fields.length} fields)`);
    lines.push('');
    for (const f of fields.slice(0, 20)) {
      lines.push(`- \`${f.name}\` in \`${f.file}:${f.line}\` (type: ${f.declaredType || 'unknown'})`);
    }
    if (fields.length > 20) lines.push(`- … and ${fields.length - 20} more`);
    lines.push('');
    lines.push(`**Governance fields for ${cls}** (see the RoPA artifact for the full register):`);
    lines.push('');
    const record = governanceRecordFor(cls, governanceConfig);
    for (const field of GOVERNANCE_FIELDS) {
      const r = record[field];
      lines.push(`- ${field}: \`${r.value}\`${r.source === 'operator_provided' ? ' (operator-provided)' : ''}`);
    }
    lines.push('');
  }
  lines.push(`## Privacy-related findings`);
  lines.push('');
  lines.push(`| Severity | File:Line | Class → Sink | Description |`);
  lines.push(`|---|---|---|---|`);
  for (const f of findings.slice(0, 50)) {
    lines.push(`| ${f.severity} | ${f.file}:${f.line} | ${f.piiClass.join('+')} → ${f.sinkKind} | ${f.vuln} |`);
  }
  if (findings.length > 50) lines.push(`| … | … | … | … and ${findings.length - 50} more |`);
  lines.push('');
  // FR-404: a policy-permitted flow must stay visible here, not vanish —
  // same principle as the ignore-pragma suppression ledger (root
  // CLAUDE.md). Only rendered when the policy actually exempted something.
  const exemptions = Array.isArray(opts.policyExemptions) ? opts.policyExemptions : [];
  if (exemptions.length) {
    lines.push(`## Policy-permitted flows (not flagged above)`);
    lines.push('');
    lines.push(`These flows matched a regulated-data class reaching a sink, but were permitted by .agentic-security/privacy-policy.json and are excluded from the findings table above.`);
    lines.push('');
    lines.push(`| File:Line | Class → Sink | Reason |`);
    lines.push(`|---|---|---|`);
    for (const e of exemptions.slice(0, 50)) {
      const reason = (e.rules || []).map(r => r.reason).filter(Boolean).join('; ') || '(no reason given)';
      lines.push(`| ${e.file}:${e.line} | ${(e.classes || []).join('+')} → ${e.sinkKind} | ${reason} |`);
    }
    if (exemptions.length > 50) lines.push(`| … | … | … and ${exemptions.length - 50} more |`);
    lines.push('');
  }
  lines.push(`## Regulatory framework mapping`);
  lines.push('');
  lines.push(`- **GDPR Art. 35** — DPIA required when processing is likely to result in high risk to data subjects.`);
  lines.push(`- **CCPA §1798.130** — Notice + access rights for collected personal information.`);
  if (grouped.has('PHI')) lines.push(`- **HIPAA §164.308** — Administrative safeguards for ePHI access.`);
  if (grouped.has('PCI')) lines.push(`- **PCI DSS Req. 3** — Protect stored cardholder data.`);
  lines.push('');
  lines.push(`## Reviewer checklist`);
  lines.push('');
  lines.push(`- [ ] Confirm each PII field's collection has a documented lawful basis`);
  lines.push(`- [ ] Confirm retention period for each class is documented`);
  lines.push(`- [ ] Confirm DSAR (data subject access request) workflow exists`);
  lines.push(`- [ ] Confirm encryption at rest + in transit for each class`);
  lines.push(`- [ ] Confirm logging of PII access for audit (where applicable)`);
  return lines.join('\n');
}

export const _internals = { DEFAULT_TAXONOMY, SINK_PATTERNS };
