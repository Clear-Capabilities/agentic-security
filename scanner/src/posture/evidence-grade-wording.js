// Canonical evidence-grade wording (assurance-hardening PRD FR-507).
//
// Every compliance-adjacent artifact this engine emits needs to disclaim
// the same thing, and four of them had already drifted into hand-rolled,
// SLIGHTLY WRONG phrasings before this module existed: compliance-policy.js
// and auditor-walkthrough.js both said "A licensed assessor... is
// responsible for the final attestation" — which conflates two DIFFERENT
// things the PRD (and the standards this tooling maps to) treat as
// distinct:
//
//   - An ATTESTATION is the ORGANIZATION'S OWN management formally
//     asserting that stated controls are in place and operating (SOC 2's
//     "management assertion" is the canonical example). This tool has no
//     visibility into organizational process, personnel, or intent, so it
//     cannot produce one.
//   - A CERTIFICATION is a formal opinion or certificate issued by an
//     ACCREDITED, INDEPENDENT third party (an ISO 27001 certification
//     body, a SOC 2 auditor, a PCI DSS QSA) after their own examination.
//     A "licensed assessor" produces a certification/independent
//     assessment, not an attestation — the exact word swap the old
//     wording got backwards.
//
// This tool produces neither. It produces the third, distinct tier:
//
//   - AUTOMATED TECHNICAL ASSESSMENT — deterministic, code-derived
//     evidence for a bounded, disclosed set of controls. Real evidence,
//     scoped honestly, but not a judgment about the organization.
//
// Naming all three, every time, is what FR-507 asks for ("UI and docs
// distinguish automated technical assessment, management attestation, and
// independent certification") — not just a generic "this isn't
// certification" caveat, which is necessary but not sufficient: a reader
// who has never heard the word "attestation" used correctly has no way to
// know a real management attestation is a DIFFERENT, valid artifact they
// might separately need.
//
// Every artifact quoting from here keeps the exact substring "does not
// certify compliance" — several existing tests (world-class-batch2.test.js's
// CMP-5 cases) already pin that phrase, and there's no reason to break a
// correct, if incomplete, assertion while fixing the incompleteness.

export const ASSURANCE_TIERS = Object.freeze({
  automatedTechnicalAssessment:
    'Automated technical assessment — what THIS TOOL produces: deterministic, ' +
    'code-derived evidence for a bounded, disclosed set of controls.',
  managementAttestation:
    'Management attestation — the ORGANIZATION\'S OWN leadership formally ' +
    'asserting that stated controls are in place and operating. This tool ' +
    'cannot produce one; only the organization\'s management can.',
  independentCertification:
    'Independent certification — a formal opinion or certificate issued by an ' +
    'ACCREDITED, INDEPENDENT third party (e.g. an ISO 27001 certification body, ' +
    'a SOC 2 auditor, a PCI DSS QSA) after their own examination. This tool ' +
    'cannot produce one; only an accredited independent party can.',
});

/** One-paragraph disclaimer for machine-consumed / GRC-ingested artifacts. */
export const EVIDENCE_GRADE_DISCLAIMER =
  'This artifact organizes automated technical assessment evidence produced by this scanner. ' +
  'It does not certify compliance, and it is not a management attestation: only the ' +
  'organization\'s own leadership can formally assert that stated controls are in place ' +
  'and operating. It is also not an independent certification: only an accredited, ' +
  'independent third party (an auditor, assessor, or certification body) examining the ' +
  'organization directly can issue one.';

/** Shorter inline variant for a markdown blockquote or narrow UI surface. */
export const EVIDENCE_GRADE_DISCLAIMER_SHORT =
  'This is automated technical assessment evidence — it does not certify compliance. ' +
  'It is neither a management attestation (the organization\'s own sign-off) nor an ' +
  'independent certification (an accredited third party\'s opinion); a licensed assessor ' +
  'or the organization\'s management, not this tool, is responsible for either.';
