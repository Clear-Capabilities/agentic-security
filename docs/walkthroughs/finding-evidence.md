# Walkthrough: reading a finding's evidence

**Goal:** read one finding field by field so you can tell what a scanner is
actually claiming — not just "SQL Injection, high severity," but *what proof
backs that claim, who checked it, and how sure they are* — rather than
treating a finding as a single opaque verdict.

---

## Run It

```bash
agentic-security scan . --format json
```

Every field below comes from one entry in the resulting `findings[]` array.

---

## What You'll See

Real captured finding — a SQL injection detected in `report.py`:

```json
{
  "id": "ir-taint:report.py:16:py-cursor-execute",
  "stableId": "d5bd1991a0e5abb8",
  "severity": "high", "vuln": "SQL Injection (cursor.execute)", "cwe": "CWE-89",
  "file": "report.py", "line": 16,
  "chain": [{ "file": "report.py", "line": 13, "label": "request.args/form/values/headers/cookies/json/data.get() (Flask/Django)", "provenance": "url-param" }],
  "confidence": 0.255, "confidenceTier": "low",
  "corroboration": { "count": 2, "by": ["IR-TAINT", "PYTHON"] },
  "proof": { "verdict": "feasible", "reasons": ["reaches-sink, no clean/infeasible proof discharged"] },
  "falsification": { "verdict": "blocked", "reasons": ["context-matched control on path — matched: parameterized query call"] },
  "verification": {
    "producer": "detector:IR-TAINT",
    "verdicts": [{ "verifierId": "verifier:falsification", "lens": "control-flow", "verdict": "refuted", "reason": "context-matched control on path — matched: parameterized query call" }],
    "consensus": { "verdict": "refuted", "upheld": 0, "refuted": 1, "undecided": 0, "lenses": ["control-flow"] }
  },
  "exploitability": 0.75, "exploitabilityTier": "high", "exploitabilityFactors": ["sev:high", "relevance:direct"],
  "riskDollars": {
    "ev": 2066, "prob": 0.18, "impact": 50000, "discount": 0.9, "confidenceWeight": 0.26,
    "scenarioStatus": "scenario_default",
    "range": { "low": 620, "base": 2066, "high": 5422 },
    "scenarios": { "conservative": 620, "base": 2066, "severe": 5422 },
    "assumptions": ["probability of exploit: 0.18 (source: built-in industry base-rate table)", "impact estimate: $50k (tier: default, built-in default)", "reachability discount: 0.9 (tier: route-reachable)", "confidence weight: 0.26 (measured from this scan)"]
  },
  "findingProvenance": { "status": "not_available", "limitations": ["provenance disabled via --no-provenance"] },
  "introducedBy": "T", "introducedIn": "bb6582167a71", "introducedAt": "2026-08-16T04:01:56.000Z",
  "whyFired": { "detector": "dataflow/ir-taint", "ruleId": "CWE-89", "parser": "IR-TAINT" },
  "poc": { "lang": "node", "kind": "http-payload", "runHint": "node poc.mjs", "code": "..." },
  "narration": "An unauthenticated attacker sends a crafted request..."
}
```

---

## What It Means, field by field

- **`stableId`** — a hash of the rule id, the normalized sink signature, and
  the path shape (`posture/stable-id.js`). It survives a refactor that moves
  or reformats the file; the plain `id` above (`ir-taint:report.py:16:…`)
  does not — it bakes in the line number and rotates the moment the code
  around it changes. Fix-verification (see [Verified
  remediation](verified-remediation.md)) checks the re-scan for this
  finding's `stableId`, not its `id`, for exactly that reason.

- **`chain[]` is the real path-evidence field.** Each hop is
  `{file, line, label, provenance}` — here, one hop, the `request.args`
  read at line 13 that feeds the query built at line 16. There is no
  top-level `source`/`sink`/`path` on a finding; those are Data Flow
  Explorer *graph* concepts (a different subsystem — see [Data Flow
  Explorer](../guides/data-flow-explorer.md)), not fields you'll find on a
  finding object itself.

- **`confidence` / `confidenceTier`** — a calibrated probability (`0.255`)
  and its bucket (`low`). Read this finding's `confidence` next to its
  `falsification` field below before trusting it at face value: a `low`
  confidence here isn't the detector being unsure from the start — it's the
  falsification pass demoting an already-computed score after finding a
  control on the path (see `falsification.js`'s `DEMOTE_FACTOR`).

- **`corroboration`** — `{count, by}`: how many independent analyses agree.
  `2` here, from `IR-TAINT` (the taint engine) and `PYTHON` (the parser-level
  corroboration signal) — two different code paths reaching the same
  conclusion independently, which is stronger evidence than either alone.

- **`proof`** — `{verdict, reasons}` from the flow-proof gate
  (`dataflow/proof-gate.js`). `"feasible"` means the gate could not
  *discharge* the finding as clean or infeasible — the flow reaches the sink
  and nothing on the path proves it can't. This is a different pass, and a
  different question, from `falsification` below.

- **`falsification`** — `{verdict, reasons}` from a *separate* pass
  (`posture/falsification.js`) that actively tries to **disprove** the
  finding: it looks for a context-matched control for this CWE family on the
  path. `"blocked"` here means it found one — a parameterized-query call —
  and demoted the finding's confidence/tiers accordingly.
  **Falsification is recall-preserving: a `"blocked"` verdict never removes
  the finding and never touches `severity`.** It's why this finding still
  reports `severity: "high"` even though it was demoted — a blocked finding
  is a *triage signal*, not a false-positive verdict, and the underlying
  code shown here is genuinely worth a human glance even if the demotion
  suggests it's probably fine.

- **`verification.producer` / `.verdicts[]` / `.consensus`** — the
  structural guarantee that the party who found a finding cannot be the
  same party who clears it (`posture/verification-separation.js`).
  `producer: "detector:IR-TAINT"` is real vocabulary, but it's **scoped to
  this object only** — there is no general "Producer Registry" component in
  this codebase; `producer` is just the id stamped on `verification` at
  detection time. `verdicts[]` is one entry per independent verifier/lens
  pair — here, `verifier:falsification` voting `"refuted"` on the
  `control-flow` lens, which is the same falsification result above,
  recorded through the separation-enforcing API instead of directly.
  `consensus` (`consensusOf()`) is the majority across all recorded
  verdicts — `refuted` here because it's currently the only vote.

- **`exploitability` / `exploitabilityTier` / `exploitabilityFactors[]`** —
  a separate score from `confidence`: not "how sure are we this is real,"
  but "how bad is it if it is." `0.75` / `"high"`, driven by the factors
  listed (`sev:high`, `relevance:direct` — this route is reachable from an
  entry point).

- **`riskDollars`** — a modeled expected-loss estimate (`ev: 2066`), not a
  measured one. `scenarioStatus: "scenario_default"` is the tell: this scan
  had none of the five organization-specific inputs configured
  (`impactUSD`, `organizationScale`, `industry`, `recordCount`,
  `controlStrength`), so every number here comes from generic industry
  base-rates (`assumptions[]` names each one and its source). Configuring
  those inputs moves `scenarioStatus` toward
  `"scenario_organization_specific"` and turns this from an industry
  scenario into an estimate that actually reflects your organization — see
  [Risk in dollars](../guides/risk-dollars.md) *(not yet published — forward
  reference)* for the full scenario-disclosure mechanics and the worked
  before/after example.

- **Two separate provenance surfaces — don't confuse them.**
  `introducedBy` / `introducedIn` / `introducedAt` (`"T"`, `bb6582167a71`,
  a timestamp) is the simple, git-blame-derived trio: who, which commit,
  when. It's cheap and close to always present. `findingProvenance` is a
  richer object — origin-commit confidence, lifecycle events, evidence
  attribution — but it is **only populated when provenance is enabled**,
  and here it isn't: `status: "not_available"`, `limitations:
  ["provenance disabled via --no-provenance"]`. `scan` defaults provenance
  OFF; `ci` defaults it ON. See [Finding
  provenance](../guides/finding-provenance.md) for the full status
  vocabulary and the `scan`-vs-`ci` default split.

- **`whyFired`** — `{detector, ruleId, parser}`, the customer-facing "what
  actually caused this to fire" — here, the `dataflow/ir-taint` detector,
  rule `CWE-89`, via the `IR-TAINT` parser. Runs late in the annotation
  pipeline, after the scoring and verification passes — but not last:
  `annotateGitProvenance` and `annotateRelevance` both run after it in the
  same `runFullScan` body.

- **`poc`** — `{lang, kind, runHint, code}`: a generated, runnable
  proof-of-concept for CWE families that have a template. `code` here is
  elided (`"..."`); a real one is a full script matching `runHint` (`node
  poc.mjs`). A finding whose CWE has no template gets `poc: null` instead —
  not every finding carries one.

---

## Try It Yourself

```bash
agentic-security scan . --format json | jq '.findings[] | select(.cwe == "CWE-89")'
```

Pick one finding and read it top to bottom in the order above — `stableId`
for identity, `chain` for the path, `confidence`/`corroboration` for how
sure the engine is, `proof`/`falsification`/`verification` for whether
anyone tried to disprove it and what happened when they did,
`exploitability`/`riskDollars` for how much it matters, the two provenance
fields for when it entered the codebase, and `whyFired`/`poc` for how to
reproduce it.

---

## Go Deeper

- [Finding provenance](../guides/finding-provenance.md) — the full
  `findingProvenance` status vocabulary and the `scan`-vs-`ci` provenance
  default split only summarized above.
- [Verified remediation](verified-remediation.md) — what happens to a
  finding's `stableId` after you fix it: the re-scan, lint, and test legs
  that decide whether a patch actually closed the hole.
- [Scan health](scan-health.md) — the scan-level counterpart to this
  finding-level evidence: whether the analysis that produced these fields
  actually finished.
