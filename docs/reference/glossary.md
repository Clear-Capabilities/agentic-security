# Glossary

Short definitions for the vocabulary used across the docs, findings, and
scan output. Every term here is confirmed against real source — nothing
speculative. Each entry cross-links the doc that covers it in depth rather
than re-explaining it.

---

### finding

One detected issue: `{id, severity, file, line, vuln, cwe, description,
remediation, parser, family, …}` at minimum, plus the evidence fields below.
See [Finding evidence](../walkthroughs/finding-evidence.md) for the full
shape and [Output schema](output-schema.md) for where it sits in scan
output.

### analyzer

One of the 121 detector functions (`scanAuthZ`/`scanCredentials`-shaped
modules, wired into
`engine.js`'s per-file cascade) that produces findings. Each analyzer's
per-file outcome is tracked by the coverage ledger — see **coverage**
below.

### stableId

A hash of the rule id, normalized sink signature, and path shape
(`posture/stable-id.js`) that survives a refactor moving or reformatting
the file — unlike the plain `id`, which bakes in the line number. Used by
fix verification to re-identify a finding across a re-scan. See
[Finding evidence](../walkthroughs/finding-evidence.md#what-it-means-field-by-field).

### chain

The real path-evidence field on a finding: an array of `{file, line, label,
provenance}` hops from source to sink. There is no top-level
`source`/`sink`/`path` field on a finding — those are Data Flow Explorer
graph concepts, a different subsystem. See
[Finding evidence](../walkthroughs/finding-evidence.md).

### proof

`{verdict, reasons}` from the flow-proof gate (`dataflow/proof-gate.js`),
which asks whether the finding can be *discharged* as clean or infeasible.
`"feasible"` means it could not be discharged — the flow reaches the sink
and nothing on the path proves otherwise. A different question from
**falsification** below. See
[Finding evidence](../walkthroughs/finding-evidence.md).

### falsification

`{verdict, reasons}` from a separate pass (`posture/falsification.js`) that
actively tries to *disprove* a finding by looking for a context-matched
control on the path. `"blocked"` means it found one and demoted the
finding's confidence/tiers — but falsification is recall-preserving: a
blocked verdict never removes the finding and never touches `severity`. See
[Finding evidence](../walkthroughs/finding-evidence.md).

### confidence / confidenceTier

A calibrated probability (`confidence`, 0–1) and its bucket (`confidenceTier`:
low/medium/high). A low tier isn't necessarily the detector being unsure
from the start — it can be falsification demoting an already-computed
score after finding a control on the path. See
[Finding evidence](../walkthroughs/finding-evidence.md).

### exploitability / exploitabilityTier

A separate score from confidence: not "how sure are we this is real" but
"how bad is it if it is," driven by `exploitabilityFactors[]` (e.g.
`sev:high`, `relevance:direct`). See
[Finding evidence](../walkthroughs/finding-evidence.md).

### verification.producer

Real vocabulary, but scoped narrowly to the `verification` object on a
finding — **not** a general "Producer Registry" component (no such thing
exists in this codebase). Stamped via
`posture/verification-separation.js`'s `recordProducer` — for the taint-style
findings covered in [Finding evidence](../walkthroughs/finding-evidence.md),
this is called from `posture/falsification.js` (**not**
`posture/verifier.js`, a different, unrelated module); `posture/logic-claims.js`
calls the same `recordProducer` for business-logic findings. Either way it's
a structural guarantee that the party who found a finding cannot be the
same party who clears it. `verification.verdicts[]` and `.consensus` follow
the same narrow scope. See
[Finding evidence](../walkthroughs/finding-evidence.md#what-it-means-field-by-field).

### scanHealth

A scan-level object separating "no findings" from "analysis complete" —
`{schemaVersion, status, files, analyzers, deepAnalysis, lineageAnalysis,
annotatorErrorCount, freshness, conditions}`. See
[Scan health](../walkthroughs/scan-health.md) and
[Scan health troubleshooting](../troubleshooting/scan-health.md).

### coverage

The coverage ledger (`pipeline/coverage-ledger.js`) computes, per file ×
per analyzer, which of that analyzer's applicable files actually ran to
completion — the mechanical basis `scanHealth.analyzers` summarizes. See
[Coverage ledger](../architecture/finding-lifecycle.md#coverage-ledger--pipelinecoverage-ledgerjs).

### complete/partial/failed

Not one unified enum — two related but distinct real vocabularies, and
writing them as a single triple overstates either one:

- **`scanHealth.status`** is strictly binary: `'complete'` or `'partial'`.
  There is no `'failed'` value here — a scan with real problems reports
  `'partial'` with `conditions[]` explaining why, never `'failed'`.
- **The coverage ledger's per-file × per-analyzer terminal status** is one
  of `'completed'`, `'failed'`, `'timed_out'`, or `'skipped_by_policy'` —
  `'failed'` is real here, on an individual analyzer/file pair, not on the
  scan as a whole. (The PRD that defines this ledger also names `'partial'`
  and `'unavailable'` as allowed statuses, but this codebase deliberately
  does not emit either — see `pipeline/coverage-ledger.js`'s own header.)

See [Scan health](../walkthroughs/scan-health.md) and
[Scan health troubleshooting](../troubleshooting/scan-health.md).

### riskDollars scenario states

Three real `scenarioStatus` values on `riskDollars`, reflecting how many of
the five organization-specific inputs (`impactUSD`, `organizationScale`,
`industry`, `recordCount`, `controlStrength`) are configured:
`'scenario_default'` (none configured — generic industry base-rates),
`'scenario_partially_configured'` (some missing, named explicitly), and
`'scenario_organization_specific'` (all configured — a real
organization-specific loss estimate, not a generic scenario). See
[Finding evidence](../walkthroughs/finding-evidence.md#what-it-means-field-by-field).

### The three verify vocabularies

Fix verification (`posture/fix-verify.js` and friends) uses three separate,
differently-cased vocabularies — never one unified enum:

1. **`fix-verify-loop.js`'s kebab-case verdict**: `'verified-clean'` |
   `'verification-failed'` | `'untested-but-passes'`.
2. **`fix-verify.js`'s richer object**: `{ok, verifiedFull, degradedLegs[],
   rescan, lint, tests, honesty, poc, summary}` — `ok` ("nothing that ran,
   failed") is a different claim from `verifiedFull` ("and nothing was
   skipped").
3. **The uppercase completeness tier** — see **FULL/MITIGATION/WORKAROUND**
   below.

See [Verified remediation](../walkthroughs/verified-remediation.md) for the
full detail, including real captured examples of each.

### FULL/MITIGATION/WORKAROUND

The completeness tier from `fix-honesty-gate.js`'s `computeFixTier` —
uppercase, three values. Invariant: `FULL` must carry no residual-risk
text; anything short of `FULL` must document one. A separate axis from the
kebab-case verify-loop verdict above — a fix can verify clean and still be
tiered `MITIGATION` or `WORKAROUND` if it isn't structurally complete. See
[Verified remediation](../walkthroughs/verified-remediation.md).

### egress allow/deny/local-only

The three real `mode:` values in `.agentic-security/egress-policy.yml`
(read by `egress/policy.js`'s `evaluateEgress()`), deciding whether an
outbound LLM call is allowed *before* a prompt is built: `'allow'`
(default), `'deny'` (blocks everything), `'local-only'` (blocks everything
that isn't a loopback address). The decision object's `decision` field is
only ever `'allow'` or `'deny'` — there is no `'redact'` decision value;
redaction is a separate module that runs on an already-allowed payload. See
[Model egress](../walkthroughs/model-egress.md).

### The three compliance vocabularies

Three separate systems, named distinctly — never unified into one enum:

1. **Data Flow Explorer obligation overlay** (`lineage/obligation-mapping.js`),
   snake_case: `evidence_supported`, `gap_detected`, `unknown`,
   `manual_required`, `not_applicable`, `accepted_exception` (the last
   requires a non-empty `reviewer` and `expiresAt`).
2. **Custom compliance-policy gate** (`posture/compliance-policy.js`,
   `.agentic-security/compliance/<id>/controls.json`), kebab-case:
   `compliant`, `non-compliant`, `not-applicable`, `gap`, `stale`, `error`,
   `no-policy`.
3. **OSCAL** (`assessment-results` output only) — binary `satisfied` /
   `not-satisfied`; the NIST Privacy Framework module's own 4 buckets
   (`satisfied`/`gap`/`engine-gap`/`manual`) collapse to this binary
   specifically for OSCAL output. See [OSCAL](../OSCAL.md).

See [Compliance](../guides/compliance.md) for how each is used.

---

## Go deeper

- [Output schema](output-schema.md) — where these fields sit in scan
  output.
- [Finding evidence](../walkthroughs/finding-evidence.md) — the full,
  field-by-field walkthrough most of these terms come from.
- [Scan health](../walkthroughs/scan-health.md) and
  [Scan health troubleshooting](../troubleshooting/scan-health.md).
- [Verified remediation](../walkthroughs/verified-remediation.md).
- [Model egress](../walkthroughs/model-egress.md).
