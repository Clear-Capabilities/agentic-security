# Documentation Overhaul — Design Spec

**Status:** approved by user 2026-09-03. Architectural-scope brainstorming
completed via two research passes (ground-truth verification, then raw
material gathering) before this spec was written — see conversation history
for the full audit trail if needed.

## Goal

Rewrite `README.md` and build out a docs tree that accurately documents the
implemented Assurance Hardening PRD (72/73 FRs closed, `CHANGELOG.md`
`0.144.0`), using **Show → Explain → Try → Go Deeper** progressive
disclosure: README = why it matters + fastest path to value; walkthroughs =
practical worked examples; feature docs = detailed explanation; reference
docs = schemas/flags/formats. A new developer should understand the value in
under 2 minutes and run their first scan in under 5.

## Non-goals

- Do NOT build a terminal-screenshot (PNG) rendering pipeline for CLI output.
  Real captured terminal text in fenced code blocks is the standard for
  CLI-only content; PNG screenshots are reserved for the Data Flow Explorer's
  real browser UI only (user-approved decision).
- Do NOT produce more than one short GIF (browser UI only, optional).
- Do NOT invent new coverage-map files for the 5 bundled compliance
  frameworks that lack one under `docs/compliance/` (`nist-csf-2`, `gdpr`,
  `hipaa-security-rule`, `ccpa`, `owasp-llm-top-10` has one but check) — that
  gap was discovered during research but is orthogonal to this PRD; flag it
  to the user afterward, don't build it now.
- Do NOT modify `.githooks/`, the pre-push gate, or wire the new doc-testing
  script into any gate — build it as a standalone `npm run` script only.
- Do NOT edit source code to fix the stale "provenance is on by default"
  comment at `scanner/bin/agentic-security.js:538` — that's a source-code
  accuracy issue, not a docs deliverable. Flag it to the user in the final
  report.

## Critical ground truth — read this before writing ANY doc content

These corrections override anything the original user spec said. Every task
brief below must carry the relevant subset verbatim; do not re-derive from
memory.

### `--help` is dangerous — never write it in a doc

**No per-subcommand `--help` exists.** `agentic-security <cmd> --help` is
silently ignored as an unset flag and the command **runs for real** (a
`scan --help` performs a real scan). Only bare `agentic-security help` (or
`--help`/`-h`/no-args at the very top level) prints usage. **Never write
`agentic-security scan --help` or similar in any doc** — always `agentic-security help`.

### `--assurance` is a `ci` flag, not a `scan` flag

Parsed only inside `cmdCi` (`bin/agentic-security.js:1339-1350`), values
`advisory|standard|strict`, default `standard`
(`src/pipeline/assurance-mode.js:47-48`). **`advisory` and `standard` are
mechanically identical** — neither prints an assurance-gate line; only
`strict` does, and only conditionally:

```
$ agentic-security ci examples/demo-app --assurance strict
[ci] full scan (no baseline ref detected)
[ci] 45 findings — 3 critical · 6 high · 7 medium · 17 low
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20699 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```

On success, `bin/agentic-security.js:1350` prints
`[ci] assurance gate PASSED (mode=strict)`. Never write
`agentic-security scan . --assurance strict` in any doc — it is
`agentic-security ci . --assurance strict`.

### `scan` defaults provenance OFF; `ci` defaults provenance ON (existing docs are wrong about this)

This directly contradicts the currently-published `docs/reference/cli.md`
and `CLAUDE.md`, both of which say provenance is "on by default in a git
repo." Real behavior:

- `parseProvenanceFlags` (`bin/agentic-security.js:506`) initializes
  `disabled: true`; only `cmdScan` calls it, and `cmdScan` sets
  `AGENTIC_SECURITY_NO_PROVENANCE=1` unless a provenance-shaped flag was
  passed. The adjacent comment (lines 495-505) explains why: a measured
  4.5s→45s (7.6×) TTFF regression on a 207-file tree — matches this
  session's own TTFF re-baseline work for v0.146.0.
- `cmdCi` calls `runScan()` directly, never through `parseProvenanceFlags`,
  so it never sets the disabling env var — the engine's true default
  (`engine.js:10435`, `disabled: false` absent the env var) governs `ci`.
- Confirmed live: plain `scan` (no flags) on a real project produced
  `findingProvenance.status: "not_available"` with
  `limitations: ["provenance disabled via --no-provenance"]`, despite never
  passing that flag.

**Every doc claiming "provenance is on by default" must be corrected**:
plain `scan` = off by default (pass `--provenance` to enable); `ci` = on by
default. Task 2 below (cli.md/configuration.md) must fix this — it's a
correction to already-shipped, already-updated-this-session docs, not new
content.

### Ship verdict already has 3 states — docs currently show only 2

`toShipVerdict()` (`src/report/index.js:1480-1540`, tagged `FR-206`) already
implements exactly the "0 findings ≠ safe" concept the user's spec asks for,
with **three** states:

```js
const scanIncomplete = scan.scanHealth?.status && scan.scanHealth.status !== 'complete';
const clean = actionable.length === 0 && !scanIncomplete;
// clean                          → '✅  Safe to deploy'
// scanIncomplete, 0 actionable   → '⚠️  Scan incomplete — cannot confirm safe to deploy'
// otherwise                      → '❌  Not safe to deploy'
```

`docs/guides/scanning.md:62-63` and `docs/guides/quickstart.md:70-71` both
document only 2 of the 3 states. This is a pure doc fix (no code change
needed) and should be one of the strongest, most concrete illustrations of
"findings vs. assurance" in the whole doc set — use it as the canonical
example in README's Findings-vs-Assurance section and in
`docs/walkthroughs/scan-health.md`.

### Real `scanHealth` shape (use verbatim field names)

```json
"scanHealth": {
  "schemaVersion": 1,
  "status": "partial",
  "files": { "expected": 6, "scanned": 6, "skipped": 0, "timedOut": 0 },
  "analyzers": { "expected": 120, "completed": 120, "failed": 0, "timedOut": 0, "skippedByPolicy": 0 },
  "deepAnalysis": { "requested": true, "enabled": true, "inCi": false, "ciOverrideAllowed": false, "reason": null, "failure": null },
  "lineageAnalysis": { "requested": false, "enabled": false, "reason": "not requested", "failure": null },
  "annotatorErrorCount": 0,
  "freshness": {
    "kev": { "source": "cache-fresh", "ageDays": 0, "stale": false, "entries": 1694 },
    "epss": { "source": "cache/live", "ageDays": 20699, "stale": true, "cvesChecked": 8 },
    "calibration": { "ageDays": 107, "stale": false },
    "customRules": { "checked": 0, "stale": false, "staleFiles": [] }
  },
  "conditions": ["EPSS exploit-probability data is stale (20699 day(s) old)"]
}
```

Note: no dedicated `--explain-health` flag exists (comment in
`finding-schema.js` explicitly says "not yet wired to a CLI flag"). The real
surface is: `scanHealth` inside `scan --format json`'s output, and `ci`'s
printed `⚠ scan-health=partial — <condition>` stderr line. Document THAT,
never a `--explain-health` flag.

### Real finding evidence fields (verbatim example, an SQLi finding from `report.py`)

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

Key corrections to use: the path-evidence field is **`chain[]`** (array of
`{file,line,label,provenance}` hops), never `source`/`sink`/`path` as
top-level finding fields — those are Data Flow Explorer graph concepts, a
different subsystem. `"producer"` **is** real vocabulary, but scoped
narrowly: `verification.producer` (e.g. `"detector:IR-TAINT"`) — do not
imply a "Producer Registry" architectural component; it doesn't exist.
There are **two** provenance surfaces: the simple, always-present
`introducedBy`/`introducedIn`/`introducedAt` (git-blame-derived) and the
richer `findingProvenance` object (only populated when provenance is
enabled — see the `scan` vs `ci` default difference above).

### Real verify-loop / fix-honesty vocabulary (the user's 9 snake_case verdicts do not exist)

Confirmed absent via direct source read, not just grep. Real vocabulary,
three separate objects:

- `fix-verify-loop.js` (`verifyFixWithTests`) → `'verified-clean' | 'verification-failed' | 'untested-but-passes'` (kebab-case). Summary line: `` `${verdict} (scan: pass · lint: skip · tests: pass)` ``.
- `fix-verify.js` (`verifyFix`) → `{ ok, verifiedFull, degradedLegs[], rescan:{ok,reason}, lint:{ok,runner,skipped}, tests:{ok,skipped,reason,passed,timedOut,exitCode}, honesty:{ok,tier,violations[]}, poc:{status,tier,reason}, summary }`. Real `rescan.reason` values: `'verified'`, `'introduced-new-findings'`, `'original-finding-still-present'`, `'rescan-failed'`, `'no-files-provided'`. Real `poc.status`: `'not-requested'`, `'still-exploitable'`, `'no-longer-proven'`, `'inconclusive'`. Real multi-line summary text:
  ```
  re-scan: PASS
  linter:  eslint PASS
  tests:   PASS
  honesty: PASS (FULL)
  poc:     PASS (ran against the patch and no longer demonstrates the vulnerability)
  ```
  A degraded-but-passing run appends: `NOTE:    PASSED, but NOT fully verified — lint: eslint not installed`.
- `fix-honesty-gate.js` (`computeFixTier`) → `'FULL' | 'MITIGATION' | 'WORKAROUND'` (uppercase). Invariant: FULL tier must carry no residual-risk text; any non-FULL tier MUST document one. Real violation templates include `` `vague-assurance phrase: "${phrase}"` `` and `` `tier 'FULL' is refuted by mechanical evidence: the proof-of-concept still demonstrates the vulnerability against the patch` ``.

Document these three real, differently-cased vocabularies distinctly. Do not
invent a unified `verified_full`/`rejected_*` enum.

### Real model egress module (matches user's intent almost exactly — feature it prominently)

`egress/policy.js` — `evaluateEgress(ctx)` → `{allowed, decision: 'allow'|'deny', reason, provider, policySource, purpose}`. No `'redact'` decision value — redaction is a separate module. Real modes (`.agentic-security/egress-policy.yml`'s `mode:`): `'allow'` (default) | `'deny'` | `'local-only'`. Called **before prompt construction**, `llm-validator/index.js:464-475`:

```js
const egressDecision = evaluateEgress({ scanRoot, purpose: 'llm-validator', endpoint: cfg.endpoint, role: 'validate', model: cfg.model });
if (!egressDecision.allowed) {
  finding._validatorError = 'egress-policy-denied';
  return { verdict: 'unvalidated', error: 'egress-policy-denied', egressDecision };
}
```

`egress/redact.js` — `redactPayload({text, filePath, scanRoot})` → `{text, redactions, categories: {proprietaryPath, secrets, pii, customerData}}`. Four ordered passes: proprietary-path (whole-span replace, short-circuits rest), secrets, PII/PHI/PCI/FIN (`dataflow/privacy-taxonomy.js`, default ON, `redactPii:false` to opt out), customer-data (operator regex list, no built-in default). Real example config:

```yaml
mode: local-only            # allow (default) | deny | local-only
allowedProviders: [anthropic]
deniedPaths: ["secrets/**"]
maxContextTokens: 8000
redactPii: true
proprietaryPaths: ["internal/**"]
customerDataPatterns: ["ACCT-\\d{8}"]
regulatedProfile:
  requireApprovedProviders: true
approvedProviders:
  anthropic: { dpaStatus: signed, baaStatus: signed, retentionPolicy: "zero-retention" }
```

### Real risk-dollars scenario disclosure (already implements the user's exact ask)

`.agentic-security/risk-config.yml`, 5 required inputs
(`REQUIRED_FOR_ORGANIZATION_SPECIFIC_LOSS`):
`impactUSD, organizationScale, industry, recordCount, controlStrength`.
Three real `scenarioStatus` values:

- `'scenario_default'` — *"Uses generic industry-wide scenario defaults. No organization-specific inputs are configured (see .agentic-security/risk-config.yml) — this is NOT a likely-organizational-loss estimate."*
- `'scenario_partially_configured'` — names exactly which of the 5 are still missing.
- `'scenario_organization_specific'` — *"this estimate reflects a likely organizational loss for your organization, not a generic industry scenario."*

Fields: `riskDollars.range:{low,base,high}`, `.scenarios:{conservative,base,severe}`, `.assumptions[]` (human-readable audit trail).

### Real state/retention (FR-702/705/706/707)

TTL table (`retention-policy.js`, `RETENTION_DEFAULTS`):

| Class | default | max |
|---|---|---|
| cache | 7d | 30d |
| scan | 90d | 365d |
| evidence | 365d | 1095d |
| ticket | 180d | 730d |
| backup | 30d | 180d |

Override via `.agentic-security/retention-policy.yml` — can only lower TTL,
never raise past `maxDays` (`Math.min` clamp). Enforcement is **purge, not
archive**, and applies only to `generated` artifacts carrying a
`retentionClass` — `operator-config` artifacts (e.g. `remediation/`) are
never touched.

Encryption (`encryption-provider.js`, FR-705): `'local-key'` provider,
AES-256-GCM, per-install key at `$XDG_CONFIG_HOME/agentic-security/`
(separate from the HMAC signing key). Opt-in via
`.agentic-security/encryption-policy.yml`. Fail-closed: when `required:true`
and no working provider, the write is refused before any bytes touch disk —
never falls back to plaintext. Scope: excludes `last-scan.json`/
`findings.json`; covers `runtime-observations/`, `compliance-evidence.*`.

`export --out <dir>` (real, `cmdExport`, `bin/agentic-security.js:2082`) —
copies every present artifact (both classifications, unlike `reset`), writes
`export-manifest.json` with per-item `{name, classification, retentionClass, status, sha256}`.

`legal-hold add --artifact <name> --owner <id> --reason <text> [--expires <date>]` /
`legal-hold remove --artifact <name>` / `legal-hold list [--all]` (real,
`cmdLegalHold`, `bin/agentic-security.js:2141`). A hold exempts an artifact
from both TTL purge and `reset`.

### Real compliance state vocabularies — THREE separate systems, do not unify

1. **Data Flow Explorer obligation overlay** (`lineage/obligation-mapping.js`, FR-504 — a different PRD, not assurance-hardening): `evidence_supported, gap_detected, unknown, manual_required, not_applicable, accepted_exception` (snake_case). `accepted_exception` structurally requires non-empty `reviewer` and `expiresAt`.
2. **Custom compliance-policy gate** (`posture/compliance-policy.js`, `.agentic-security/compliance/<id>/controls.json`): `compliant, non-compliant, not-applicable, gap, stale, error, no-policy` (kebab-case).
3. **OSCAL** (`docs/OSCAL.md`, `assessment-results` only): binary `satisfied`/`not-satisfied` — the underlying NIST-Privacy-Framework module's own 4 buckets (`satisfied/gap/engine-gap/manual`) collapse to this binary for OSCAL output specifically.

Real `compliance --list` (9 bundled frameworks — more than the 4 with a
`docs/compliance/` coverage map today; note this gap to the user, don't fix
it in this pass):
`ccpa, eu-ai-act, gdpr, hipaa-security-rule, nist-ai-600-1, nist-csf-2, nist-privacy-1-1, owasp-asvs-5, owasp-llm-top-10`.

### Confirmed overclaims to fix (§32 of the user's original ask)

- `README.md:13` tagline: **"Safe, secure, and compliant"** — direct hit, must be replaced (e.g. with language matching the real 3-state ship verdict).
- **"auditor-ready attestation"** appears in `README.md:274`, `docs/README.md:27`, `docs/guides/compliance.md:3` and `:45`, `docs/guides/quickstart.md:183` — reframe per the six-state (well, three-vocabulary) reality above; prefer "automated technical-control evidence."
- `docs/guides/scanning.md:62-63` and `docs/guides/quickstart.md:70-71` — 2-state ship verdict, missing the real 3rd state (see above).

### Data Flow Explorer screenshot target

Use the flagship `payments-platform` fixture
(`scanner/src/lineage/fixtures/build-flagship-fixture.mjs`, already used for
this session's Mermaid diagrams in `docs/guides/data-flow-explorer.md`) —
NOT `examples/demo-app`, which has no lineage-shaped content. It has
masked/raw log branches, unknown-at-rest DB, cleartext-HTTP payment API,
AI/model-provider manual-review path, unresolved dynamic destination — every
protection-verdict color in one graph.

### Doc-testing precedent to reuse

`scripts/check-doc-drift.mjs` already has `exportExistsIn()` (verifies a
named export exists in a source file — reuse this pattern for verifying CLI
flags/commands referenced in docs actually exist in
`bin/agentic-security.js`) and `checkAllLinks()` (already-working link
checker — import directly, don't reimplement). No existing JSON-schema or
Mermaid-syntax checking — these are net-new.

## File manifest

### Modify (existing files)

1. **`README.md`** — full rewrite: hero (5 capabilities: Find/Prove/Fix/Govern/Explain), outcome table replacing feature dump, corrected 5-minute quick start (`ci --assurance strict`, never `scan --assurance`), Findings-vs-Assurance section using the real 3-state ship verdict as the running example, persona nav, "what this is not" (extend existing section), fix the `README.md:13` tagline and `:274` "auditor-ready" overclaim, cross-links to every new doc below.
2. **`docs/README.md`** — add persona-based nav (Developer/AppSec/Privacy/Compliance/Platform), links to new walkthroughs/governance/troubleshooting docs, fix the `:27` "auditor-ready" overclaim.
3. **`docs/guides/compliance.md`** — reframe as "automated technical-control evidence," fix `:3`/`:45` overclaims, document the three real state vocabularies (do not invent a unified one), add one fully-worked example control (framework/control/repository/commit/evidence/analyzers/scanHealth/rationale/reviewer/timestamp/expiration — use a real `accepted_exception` from the obligation overlay as the example since it has the richest real field set).
4. **`docs/guides/quickstart.md`** — fix the 2-state→3-state ship-verdict gap (`:70-71`), fix `:183` overclaim, verify every command still runs as documented.
5. **`docs/guides/ci-setup.md`** — add the `--assurance` modes section (real CLI surface above) and the "security-gate-failure vs. assurance-failure" distinction (a `ci` exit from `--fail-on critical` vs. a `ci` exit from `assurance gate FAILED` are different failure classes with different remediation).
6. **`docs/guides/scanning.md`** — fix the 2-state→3-state ship-verdict gap (`:62-63`).
7. **`docs/guides/finding-provenance.md`** — add a cross-link to the new `finding-evidence.md` walkthrough; correct if it also claims scan-default-on provenance (check while editing).
8. **`docs/reference/cli.md`** — fix `--assurance` to show it under `ci`, not as a general scan flag; fix the provenance-default claim (scan=off, ci=on); add `export` and `legal-hold` commands (currently undocumented); group flags per the user's original intent (Scan/Assurance/Analysis Depth/Privacy/Compliance/Remediation/Model Governance/State/Output/CI-CD).
9. **`docs/reference/configuration.md`** — cross-link to the new `docs/governance/state-and-retention.md` for TTL/encryption/export/legal-hold detail rather than duplicating it here (keep this file's existing scope: env vars + artifact listing).
10. **`docs/ARCHITECTURE.md`** — extend the main diagram with scan-health/coverage-ledger/egress-policy boxes (this file already has this session's Data Flow Explorer + OSCAL additions — follow the same box-drawing precision approach, measure widths with the same Python-script technique used earlier this session).

### Create (new files)

11. **`docs/walkthroughs/assurance-modes.md`** — real captured `ci --assurance advisory` / `strict` output (from this spec's ground-truth section), explain advisory≈standard (only strict gates), tie to the real `assurance-mode.js` contract.
12. **`docs/walkthroughs/scan-health.md`** — real `scanHealth` JSON, the EPSS-staleness real partial-scan example, fault isolation (one analyzer failing ≠ whole scan aborts — cite the real fault-isolation fix from `docs/implementation/assurance-hardening-final-report.md` where two detectors were found bypassing the isolating wrapper and got fixed), the real 3-state ship verdict as the closing example.
13. **`docs/walkthroughs/finding-evidence.md`** — walk the real `report.py` SQLi finding above field-by-field: stableId, chain, confidence/confidenceTier, corroboration, proof, falsification, verification (producer/verdicts/consensus), exploitability, riskDollars, findingProvenance vs. introducedBy/introducedIn, whyFired, poc.
14. **`docs/walkthroughs/privacy-data-flow.md`** — narrative companion to the already-existing `docs/guides/data-flow-explorer.md` (do not duplicate its content — cross-link), using the flagship fixture; may reuse the Mermaid diagrams already committed to `data-flow-explorer.md` this session rather than drawing new ones, or draw a smaller focused one for one specific field's journey.
15. **`docs/walkthroughs/verified-remediation.md`** — real verify-loop vocabulary (three separate real objects above), a real successful-verification summary block, and (if constructible within reasonable effort) a real rejected case; otherwise document the real rejection-message source templates verbatim rather than fabricating example output.
16. **`docs/walkthroughs/model-egress.md`** — real `evaluateEgress`/`redactPayload` behavior, the real example policy config, the real pre-network-call call site in `llm-validator/index.js`.
17. **`docs/architecture/finding-lifecycle.md`** — Mermaid diagram built from real module names (engine.js per-file cascade → `coverage-ledger.js` → `scan-health.js` → `finding-schema.js`/`normalizeFindings()`), not the user's original PRD-draft term "Producer Registry" (doesn't exist).
18. **`docs/governance/state-and-retention.md`** — real TTL table, encryption scope/behavior, `export` command, `legal-hold` command, cross-linked from `configuration.md`.
19. **`docs/guides/risk-dollars.md`** — real `risk-config.yml` shape, the 3 real scenario states and their exact trigger conditions, a worked before/after (unconfigured → configured) example.
20. **`docs/examples/README.md`** — gallery; real captured text/JSON snippets per example (SQLi, authz, secret exposure, vulnerable dependency, IaC misconfig, PII→logs, PII→external API, cross-file taint, incomplete scan [reuse the EPSS-staleness partial example], verified fix, rejected fix, compliance evidence, model egress denial); each answers What happened / What was found / What evidence proves it / What should the developer do.
21. **`docs/reference/output-schema.md`** — real top-level JSON concepts (no top-level `schemaVersion` — it's nested inside `scanHealth`; correct this if the user's spec assumed otherwise), small real excerpts not full dumps, link to full real examples.
22. **`docs/troubleshooting/scan-health.md`** — "why did my scan fail," using real causes only: analyzer timeout, stale EPSS/KEV/calibration feed (real, just demonstrated), parser unavailable, unsupported language, deep analysis unavailable, egress denied (real), required tests unavailable. For each: What happened / Why it matters / How to investigate / How to fix.
23. **`docs/concepts.md`** — two short sections in one file: Evidence Before Severity (Observation→Evidence→Reachability→Proof/Falsification→Confidence→Severity/Risk, using the real field names from finding-evidence.md), and Deterministic vs. Model-Assisted (which capabilities need no model, which optionally use one, which require an approved provider via egress policy, which work fully disconnected).
24. **`docs/reference/glossary.md`** — only terms confirmed real in this spec's ground-truth section: finding, analyzer, stableId, chain, proof, falsification, confidence/confidenceTier, exploitability/exploitabilityTier, scanHealth, coverage, complete/partial/failed, riskDollars scenario states, verified-clean/untested-but-passes/verification-failed, FULL/MITIGATION/WORKAROUND, egress allow/deny/local-only, the three compliance vocabularies (named distinctly). Do not define "producer" as a registry concept — define it narrowly as `verification.producer`.
25. **`docs/assets/*.png`** (2-3 images) + optionally one short GIF — real Data Flow Explorer browser screenshots via `mcp__claude-in-chrome__*` browser automation. Resolved pipeline (verified feasible): `explore` reads `.agentic-security/lineage-graph.json` and requires a valid `.sig` sibling, signed with the same per-install HMAC key as `last-scan.json` (`signLastScan` in `scanner/src/posture/integrity.js`, reused verbatim for the lineage graph at `bin/agentic-security.js:1142`). Run `node scanner/src/lineage/fixtures/build-flagship-fixture.mjs` (writes `flagship-graph.json` next to itself), write a small script that imports `signLastScan`, copies that JSON to `<scratch-dir>/.agentic-security/lineage-graph.json`, writes `signLastScan(body)` to the `.sig` sibling, then run the real `agentic-security explore <scratch-dir>` and screenshot it — this is the real production sign path, not a bypass.
26. **`scripts/verify-doc-examples.mjs`** — reuses `check-doc-drift.mjs`'s `exportExistsIn`/`checkAllLinks`; adds: (a) extract CLI invocations from fenced code blocks in README + new docs, verify the command/flag combination is real by checking against `bin/agentic-security.js`'s actual command dispatch table (never accept `<cmd> --help` as valid for any subcommand but the bare top-level), (b) validate embedded JSON snippets are syntactically valid JSON, (c) a lightweight Mermaid fence sanity check (balanced brackets/arrows, known diagram-type keyword) given the sandboxed `mermaid-cli` render was confirmed non-functional in this environment earlier this session. Wire as a new `npm run` script only — do not add to the pre-push gate.

## Global constraints

- Every command shown in any doc must be one that was actually run (or is
  provably equivalent to one that was run) during this project's research —
  no invented output.
- Never write `<command> --help` for any subcommand other than the bare
  `agentic-security help`.
- Use the real, differently-cased vocabularies exactly as documented above —
  never invent a unifying term across subsystems that don't share one.
- Every "X is on by default" / "X is off by default" claim must match the
  verified scan-vs-ci provenance distinction above.
- Overclaim language (`compliant`, `certification`, `auditor-ready`, `safe
  to deploy` without qualification, `verified`/`fully verified` without a
  named tier, `zero vulnerabilities`, unqualified `financial loss`) must be
  replaced per the confirmed-overclaims list, and the whole doc set swept
  once more for the same patterns before this project is considered done.
- New docs cross-link existing ones instead of duplicating (especially
  `docs/guides/data-flow-explorer.md`, already comprehensive from this
  session's earlier work).
