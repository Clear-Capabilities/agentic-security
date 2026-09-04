# Compliance

**Goal:** produce automated technical-control evidence for a framework, and
find the gaps you need to close — without the tool ever claiming assurance
it didn't earn.

**Prerequisites:** a scan has run. Compliance assessment reads the last scan
rather than re-scanning. Commands are shown as Claude Code
(`/agentic-security:compliance …`); a real CLI subcommand
(`agentic-security compliance …`) backs the privacy and gap flows.

---

## Pick a framework

```text
/agentic-security:compliance --list
```

Bundled frameworks include:

| Framework | Id |
|---|---|
| NIST AI 600-1 — Generative AI Profile | `nist-ai-600-1` |
| NIST Cybersecurity Framework 2.0 | `nist-csf-2` |
| NIST Privacy Framework 1.1 | `nist-privacy-1-1` |
| OWASP ASVS 5.0 | `owasp-asvs-5` |
| OWASP Top 10 for LLM Applications 2025 | `owasp-llm-top-10` |
| EU AI Act | `eu-ai-act` |
| GDPR · HIPAA Security Rule · CCPA | `gdpr` · `hipaa-security-rule` · `ccpa` |

You can also bring your own controls at
`.agentic-security/compliance/<id>/controls.json`.

---

## Three things you can produce

### A report (attestation)

```text
/agentic-security:compliance --report <framework>
```

Generates technical-control evidence that maps your scan results to the
framework's controls — a report, not an audit-ready certification.

### A walkthrough (narrative + evidence)

```text
/agentic-security:compliance --walkthrough <framework>
```

Adds a step-by-step auditor narrative with per-control evidence mapping — the
document you hand to someone who needs to see *how* each control was assessed.

### A gap worklist

```text
/agentic-security:compliance --gap <framework>
```

Filters to the controls that aren't clearing, each with its observations. It's
a worklist of what isn't passing — not a magic per-control fix button.

---

## The honesty model — why this won't inflate your score

The most important thing to understand: **a compliance opinion should never
manufacture assurance.** Every control lands in exactly one of four buckets,
and the bucket is always shown:

| Bucket | Meaning |
|---|---|
| **gap** | Mapped to an engine signal, and that signal is failing — the only bucket that emits a finding |
| **not assessed / engine-gap** | Code-testable, but this engine has no signal for it — disclosed by name, never counted as passed |
| **manual** | Governance/policy, outside any scanner's reach |
| **satisfied** | Mapped, checked, and passing |

The satisfied rate is reported over the controls **actually assessed**, never
over the full control count. For NIST Privacy Framework 1.1, for example, only
23 of 104 controls are fully code-testable — a report that quietly marked the
other 81 "passed" would be manufacturing assurance an auditor would rely on.
This tool tells you exactly how much of the framework it did *not* check.

---

## Three separate compliance-state vocabularies — not one unified model

The four-bucket model above (`gap` / `not assessed` / `manual` / `satisfied`)
describes only the `/agentic-security:compliance --report|--walkthrough|--gap`
flows on this page. Three other, unrelated parts of this codebase also
report a "compliance state," each with its own real vocabulary. They are
**not** the same vocabulary wearing different names, and they don't unify
into one — treat each as its own contract:

1. **Data Flow Explorer obligation overlay** (`lineage/obligation-mapping.js`,
   FR-504) — evaluates one regulatory requirement against real graph facts
   (`agentic-security attest --obligations <framework-id>`). Six states:
   `evidence_supported`, `gap_detected`, `unknown`, `manual_required`,
   `not_applicable`, `accepted_exception`. `accepted_exception` is the one
   state with a structural requirement: it is only valid with a non-empty
   `reviewer` **and** a non-empty `expiresAt` — a record claiming this state
   with either field missing fails validation.

2. **Custom compliance-policy gate** (`.agentic-security/rules.yml`-driven,
   `posture/compliance-policy.js`) — a separate, operator-authored policy
   mapping controls to scan checks, evaluated fresh on every scan. Seven
   states: `compliant`, `non-compliant`, `not-applicable`, `gap`, `stale`,
   `error`, `no-policy`. Note `gap` here means something different from the
   report vocabulary's `gap` above — it fires specifically when a
   `not-applicable` exception has *expired*, not when a check is failing.

3. **OSCAL** ([`docs/OSCAL.md`](../OSCAL.md)) — NIST's own assessment-results
   format is binary by design: `satisfied` or `not-satisfied`. There is no
   `unknown` and no `not-applicable` in the OSCAL output itself; this
   scanner's own richer verdicts (including `engine-gap`, a control this
   engine has no check for) are collapsed down to that binary pair before
   export, exactly as `docs/OSCAL.md` describes.

Known gap, not fixed here: `compliance --list` surfaces 9 bundled
frameworks, but [`docs/compliance/`](../compliance/) currently only has
coverage maps for 4 of them.

### Worked example: an `accepted_exception` obligation record

An `accepted_exception` is how an operator formally waives a gap the graph
otherwise flags — for example, a control that requires encryption in transit
for a payment API, where the team has accepted the residual risk for a
legacy internal route pending a migration. This is an illustrative example,
not a captured run — the repository name, ids, digests, reviewer, and dates
below are all placeholders for a fictional `payments-service` scan, not
something a real command produced:

```json
{
  "id": "obligation:example0000000000000000000000000000000000000000000000000000000000000000",
  "graphId": "dfg:payments-service:a1b2c3d:cfg9e8f7",
  "graphDigest": "sha256:example0000000000000000000000000000000000000000000000000000000000",
  "framework": "hipaa-security-rule",
  "frameworkVersion": "7e94038dd9a64d3d",
  "requirementId": "§164.312(e)",
  "requirementSource": "https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164",
  "applicabilityInputs": {
    "entityRole": null, "jurisdiction": null, "dataSubject": null,
    "businessProcess": null, "merchantLevel": null, "systemScope": null,
    "aiSystemRole": null
  },
  "state": "accepted_exception",
  "predicate": "graph:transit-protection:PHI:external:transit:protected",
  "factType": "code_inferred",
  "contributingGraphIds": ["flow:example1234"],
  "evidence": [],
  "conflicts": [],
  "missingManualArtifacts": [],
  "reviewer": "jane.doe@example.com",
  "reviewedAt": "2026-06-01T00:00:00.000Z",
  "expiresAt": "2026-12-01T00:00:00.000Z"
}
```

This is the real `ObligationMapping` record shape (`validateObligationMapping`
in `lineage/obligation-mapping.js`), for the real `graph:` predicate this
bundled HIPAA framework already ships (§164.312(e), "PHI in transit is
protected" — see `compliance-frameworks/hipaa-security-rule.json`).
`repository`/`commit` aren't separate top-level fields, they're embedded in
`graphId` (`dfg:<repository>:<commit>:<configHash>`). `reviewer` and
`expiresAt` are the two fields the validator structurally *requires* to be
non-empty specifically because the state is `accepted_exception`; every
other field is required on every record regardless of state (`evidence` is
typically empty by design — a record's own evidence lives in the resolved
evidence index an `agentic-security attest --obligations` pack builds around
it, not on the record itself). `framework`, `requirementId`, and `predicate`
above are real values from this bundled framework; `id`, `graphId`,
`graphDigest`, `contributingGraphIds`, `reviewer`, `reviewedAt`, and
`expiresAt` are all illustrative — substitute your own repository, commit,
and reviewer when you accept a real exception.

---

## Gaps become fixable findings

For the privacy framework, each gap is emitted as an ordinary finding
(`family: privacy-compliance`, `CWE-359`) with an actionable remediation — so
`/agentic-security:fix` handles it like any other finding. This is opt-in, so a
compliance opinion doesn't silently become your build failure:

```bash
AGENTIC_SECURITY_PRIVACY_FRAMEWORK=1 npx @clear-capabilities/agentic-security-scanner scan .
```

The assessment always writes `.agentic-security/privacy-framework.{json,md}`
regardless of the flag; the flag only controls whether gaps join
`scan.findings`.

---

## Exit codes (for CI)

The CLI `compliance` subcommand exits **0** when a report is produced, **2**
when there's no scan to assess, and **1** only when you ask it to fail with
`--fail-on gap`:

```bash
npx @clear-capabilities/agentic-security-scanner compliance --fail-on gap
```

---

## Related

- [SBOM & AI-BOM](sbom-and-ai-bom.md) — evidence several frameworks ask for
- [Coverage maps](../compliance/) — what each framework's controls map to
- [Fixing vulnerabilities](fixing-vulnerabilities.md)
