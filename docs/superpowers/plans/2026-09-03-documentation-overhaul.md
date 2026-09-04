# Documentation Overhaul Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Adaptation note:** this is a documentation project, not a code project.
> "Tests" are verification commands (real CLI invocations, the doc-link
> gate, the new doc-testing script) rather than unit tests, and "No
> Placeholders" means every task specifies the exact real facts, JSON, and
> command output that MUST appear (all sourced from the spec) plus a
> concrete structural outline — not vague instructions like "add
> appropriate content." Connective prose is the implementer's to write, but
> every factual claim must trace to the spec.

**Goal:** Rewrite `README.md` and build a docs tree that accurately
documents the implemented Assurance Hardening PRD, using real captured CLI
output and real source citations throughout — no fabricated commands,
fields, or verdicts.

**Architecture:** Existing docs get targeted corrections (wrong CLI surface,
missing ship-verdict state, overclaiming language). New docs follow
Show → Explain → Try → Go Deeper. README and the docs landing page are
written last, once everything they link to exists, so no doc-link check
ever sees a dangling reference mid-project.

**Tech Stack:** Markdown, Mermaid (native artifact rendering only — no
render pipeline available in this sandbox), Node.js scripts for
verification, `mcp__claude-in-chrome__*` for one real browser-screenshot
task.

**Spec:** `docs/superpowers/specs/2026-09-03-documentation-overhaul-design.md`
— every task below pulls its real facts from that file's "Critical ground
truth" section. Read both; the spec is the authority, this plan is its
argument.

## Global Constraints

- Never write `<command> --help` for any subcommand other than bare
  `agentic-security help` (spec: "`--help` is dangerous").
- `--assurance advisory|standard|strict` is a **`ci`** flag only, default
  `standard`; `advisory`/`standard` are mechanically identical (no gate
  line); only `strict` prints anything.
- `scan` defaults provenance OFF; `ci` defaults provenance ON — the
  opposite of what's currently published. Every doc claiming otherwise
  must be corrected.
- The real ship verdict has **three** states:
  `✅ Safe to deploy` / `⚠️ Scan incomplete — cannot confirm safe to deploy` /
  `❌ Not safe to deploy` (`toShipVerdict()`, `src/report/index.js:1480-1540`).
  Any doc showing only 2 states is wrong.
- Use real, differently-cased vocabularies verbatim (see spec): `chain`
  never `source`/`sink`/`path`; `verified-clean`/`untested-but-passes`/
  `verification-failed` and `FULL`/`MITIGATION`/`WORKAROUND`, never the
  nine snake_case verdicts from the original ask; three separate
  compliance-state vocabularies, never a unified one; `verification.producer`
  narrowly, never a "Producer Registry."
- Replace confirmed overclaims (`README.md:13`'s "Safe, secure, and
  compliant" tagline; "auditor-ready attestation" at the 4 cited
  locations) — do not just add new content alongside them.
- Every command shown must have actually been run (this session's research
  passes already ran most of them — reuse that real output from the spec
  rather than re-running) or be a direct, provable equivalent.
- New docs cross-link `docs/guides/data-flow-explorer.md` rather than
  duplicating it.
- Commit after each task. Do not touch `.githooks/`, the pre-push gate, or
  wire the new script into any gate.

---

### Task 1: Fix `docs/guides/quickstart.md` + `docs/guides/scanning.md` (ship-verdict 3rd state)

**Files:**
- Modify: `docs/guides/quickstart.md:70-71` (ship-verdict section) and `:183` (overclaim)
- Modify: `docs/guides/scanning.md:62-63` (ship-verdict section)

**Requirements:** spec section "Ship verdict already has 3 states." Both
files currently show only `❌ Not safe to deploy` / `✅ Safe to deploy`.
Add the third real state `⚠️  Scan incomplete — cannot confirm safe to
deploy`, with a one-sentence explanation that this fires when
`scanHealth.status !== 'complete'` even with zero findings (cite
`toShipVerdict()`, `src/report/index.js:1480-1540`). Fix `quickstart.md:183`'s
"auditor-ready" phrasing per the overclaims list in the spec (reframe as
"technical-control evidence" or similar, matching whatever the surrounding
sentence is actually claiming — read it first).

- [ ] **Step 1:** Read both files in full to get exact current line numbers and surrounding context (they may have shifted since the spec's research pass).
- [ ] **Step 2:** Edit both ship-verdict sections to show all 3 states with the real trigger condition.
- [ ] **Step 3:** Edit `quickstart.md`'s overclaim line.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate` from repo root — must pass.
- [ ] **Step 5:** Commit: `git add docs/guides/quickstart.md docs/guides/scanning.md && git commit -m "docs: add the real 3rd ship-verdict state, fix an overclaim"`

---

### Task 2: Reframe `docs/guides/compliance.md`

**Files:**
- Modify: `docs/guides/compliance.md` (currently 122 lines)

**Requirements:** spec sections "Real compliance state vocabularies" and
"Confirmed overclaims." Fix the `:3` and `:45` "auditor-ready attestation"
lines — reframe the goal as producing **automated technical-control
evidence**, not an audit-ready certification. Add a new section documenting
the three real, separate state vocabularies verbatim (do not invent a
unified one):
1. Data Flow Explorer obligation overlay (`lineage/obligation-mapping.js`, FR-504): `evidence_supported, gap_detected, unknown, manual_required, not_applicable, accepted_exception` — note `accepted_exception` requires non-empty `reviewer` + `expiresAt`.
2. Custom compliance-policy gate (`posture/compliance-policy.js`): `compliant, non-compliant, not-applicable, gap, stale, error, no-policy`.
3. OSCAL (`docs/OSCAL.md`, cross-link it): binary `satisfied`/`not-satisfied` only.

Add one fully-worked example control using a real `accepted_exception` from
the obligation overlay as the example (framework / control / repository /
commit / evidence / analyzers / scanHealth / rationale / reviewer /
timestamp / expiration — these are the real required fields for that
state). Note in passing (do not build) that `compliance --list` shows 9
real bundled frameworks but `docs/compliance/` only has coverage maps for 4
— flag this as a known gap in a one-line aside, not a task to fix here.

- [ ] **Step 1:** Read the full current file.
- [ ] **Step 2:** Fix both overclaim lines.
- [ ] **Step 3:** Add the three-vocabulary section.
- [ ] **Step 4:** Add the worked `accepted_exception` example.
- [ ] **Step 5:** Run `node scripts/check-doc-drift.mjs --gate` — must pass.
- [ ] **Step 6:** Commit: `git add docs/guides/compliance.md && git commit -m "docs: reframe compliance guide as technical-control evidence, document the real 3 state vocabularies"`

---

### Task 3: Extend `docs/guides/ci-setup.md` + `docs/guides/finding-provenance.md`

**Files:**
- Modify: `docs/guides/ci-setup.md` (currently 105 lines, no `--assurance` mention today)
- Modify: `docs/guides/finding-provenance.md` (currently 244 lines)

**Requirements:** spec sections "`--assurance` is a `ci` flag" and "`scan`
defaults provenance OFF; `ci` defaults provenance ON."

`ci-setup.md`: add a new section on `--assurance advisory|standard|strict`
using the real captured output:
```
$ agentic-security ci examples/demo-app --assurance strict
[ci] full scan (no baseline ref detected)
[ci] 45 findings — 3 critical · 6 high · 7 medium · 17 low
[ci] ⚠ scan-health=partial — EPSS exploit-probability data is stale (20699 day(s) old)
[ci] artifacts: .agentic-security/findings.{json,sarif,junit.xml}
[ci] fail-on=critical  scan-exit=3
[ci] assurance gate FAILED (mode=strict): strict mode requires a fully complete scan; scanHealth.status is 'partial'
```
Explain: advisory ≈ standard (no gate line ever printed); only strict gates,
and only on incomplete analysis, independent of `--fail-on`. Add a short
"Security gate failure vs. assurance failure" subsection: a `--fail-on
critical` exit (`scan-exit=3` above) means real vulnerabilities were found;
an `assurance gate FAILED` exit means the analysis itself didn't complete —
different failure classes, different fixes (triage findings vs.
investigate why an analyzer failed/timed out — link to the new
`docs/troubleshooting/scan-health.md`, created in Task 13, once it exists —
if this task runs before Task 13, add the link text now and it will resolve
once Task 13 lands, since the doc-link gate runs at the very end in Task 18
too).

`finding-provenance.md`: check whether it claims provenance is on by
default for plain `scan` (the CLAUDE.md-level claim the spec found is
stale) — if so, correct it: `scan` defaults OFF, `--provenance` enables it;
`ci` defaults ON. Add a cross-link to `docs/walkthroughs/finding-evidence.md`
(created in Task 7) near the top.

- [ ] **Step 1:** Read both files in full.
- [ ] **Step 2:** Add the `--assurance` section + gate-failure distinction to `ci-setup.md`.
- [ ] **Step 3:** Correct any stale provenance-default claim in `finding-provenance.md`; add the cross-link.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate` — note it may show 1-2 unresolved links to not-yet-created files from other in-progress tasks; only fail the task if a link to an already-existing file is broken.
- [ ] **Step 5:** Commit: `git add docs/guides/ci-setup.md docs/guides/finding-provenance.md && git commit -m "docs: document real --assurance behavior and the scan-vs-ci provenance default split"`

---

### Task 4: Fix `docs/reference/cli.md` + `docs/reference/configuration.md`

**Files:**
- Modify: `docs/reference/cli.md`
- Modify: `docs/reference/configuration.md`

**Requirements:** spec sections "`--assurance` is a `ci` flag," "`scan`
defaults provenance OFF," "Real state/retention."

`cli.md`: move `--assurance` out of any general/scan-flag listing into the
`ci` command's own row/section; correct the provenance-default claim (scan
off / ci on); add two missing real commands: `export --out <dir>` (copies
every present artifact regardless of classification, writes
`export-manifest.json` with per-item `{name, classification, retentionClass,
status, sha256}`) and `legal-hold add --artifact <name> --owner <id>
--reason <text> [--expires <date>]` / `legal-hold remove --artifact <name>`
/ `legal-hold list [--all]`.

`configuration.md`: add a one-paragraph cross-link to
`docs/governance/state-and-retention.md` (Task 10) for TTL/encryption/
export/legal-hold detail — do not duplicate that detail here, this file's
scope stays env vars + artifact listing.

- [ ] **Step 1:** Read both files in full.
- [ ] **Step 2:** Fix `cli.md`'s `--assurance` placement and provenance-default claim; add `export`/`legal-hold` rows.
- [ ] **Step 3:** Add the cross-link in `configuration.md`.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 5:** Commit: `git add docs/reference/cli.md docs/reference/configuration.md && git commit -m "docs: fix cli reference's assurance/provenance claims, document export and legal-hold"`

---

### Task 5: Extend `docs/ARCHITECTURE.md` diagram

**Files:**
- Modify: `docs/ARCHITECTURE.md` (main diagram, already extended twice this session — Data Flow Explorer section + OSCAL row)

**Requirements:** spec section "File manifest #10." Add scan-health /
coverage-ledger / egress-policy boxes to the main pipeline diagram. Follow
the exact box-drawing precision approach already used twice this session
for this same file: measure existing line widths with a small Python
script before inserting new content lines, to guarantee alignment (see
this session's prior OSCAL-row insertion for the technique — read the
current diagram first to find the right insertion point, likely near the
existing "reporters" or engine-pipeline boxes).

- [ ] **Step 1:** Read `docs/ARCHITECTURE.md` in full, identify where the analyzer-cascade → coverage-ledger → scan-health → egress-policy sequence fits relative to existing boxes.
- [ ] **Step 2:** Write a small Python one-liner (via Bash) to measure the exact character width of the box(es) being extended.
- [ ] **Step 3:** Construct and insert the new box(es)/row(s) with programmatically-verified padding.
- [ ] **Step 4:** Read the edited region back to visually confirm alignment.
- [ ] **Step 5:** Add 1-2 short paragraphs (matching the style of the existing "Methodology layer"/"OSCAL" paragraphs) explaining scan-health/coverage-ledger/egress in one sentence each, with links to the relevant new walkthroughs (Task 6's scan-health.md, Task 8's model-egress.md) — link text is fine even before those files exist; Task 18 verifies all links resolve at the end.
- [ ] **Step 6:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 7:** Commit: `git add docs/ARCHITECTURE.md && git commit -m "docs: add scan-health, coverage-ledger, and egress-policy to the architecture diagram"`

---

### Task 6: New walkthroughs — `assurance-modes.md` + `scan-health.md`

**Files:**
- Create: `docs/walkthroughs/assurance-modes.md`
- Create: `docs/walkthroughs/scan-health.md`

**Requirements:** spec sections "`--assurance` is a `ci` flag," "Ship verdict
already has 3 states," "Real `scanHealth` shape."

`assurance-modes.md` — structure: Goal / Run It / What You'll See / What It
Means / Try It Yourself / Go Deeper (the standard walkthrough template —
use this same structure for every walkthrough in Tasks 6-8). Use the real captured `ci --assurance strict`
output from Task 3 verbatim. Explain the `advisory`/`standard`/`strict`
three-value contract, that advisory≈standard, and that `strict` alone gates
on `scanHealth.status !== 'complete'` independent of `--fail-on`.

`scan-health.md` — use the real `scanHealth` JSON block from the spec
verbatim (the EPSS-staleness example — a genuine, non-contrived partial
scan with zero failed analyzers, driven purely by a stale feed). Include a
"fault isolation" subsection: one analyzer failing doesn't abort the whole
scan — cite the real fix from `docs/implementation/assurance-hardening-final-report.md`
where `scanWeb3Advanced` and `scanK8sAdmission` were found bypassing the
isolating wrapper and got fixed (read that file's relevant section for the
exact wording before citing it). Close with the real 3-state ship verdict
as the concrete "why this matters" payoff. There is no `--explain-health`
flag — never write one; the real surface is `scanHealth` in
`scan --format json` output and `ci`'s printed stderr line.

- [ ] **Step 1:** Read `docs/implementation/assurance-hardening-final-report.md`'s fault-isolation section for the exact real wording to cite.
- [ ] **Step 2:** Write `docs/walkthroughs/assurance-modes.md` using the standard template.
- [ ] **Step 3:** Write `docs/walkthroughs/scan-health.md` using the standard template.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 5:** Commit: `git add docs/walkthroughs/assurance-modes.md docs/walkthroughs/scan-health.md && git commit -m "docs: add assurance-modes and scan-health walkthroughs"`

---

### Task 7: New walkthroughs — `finding-evidence.md` + `verified-remediation.md`

**Files:**
- Create: `docs/walkthroughs/finding-evidence.md`
- Create: `docs/walkthroughs/verified-remediation.md`

**Requirements:** spec sections "Real finding evidence fields," "Real
verify-loop / fix-honesty vocabulary."

`finding-evidence.md` — walk the real `report.py` SQLi finding from the
spec field-by-field, in this order: stableId → chain → confidence/
confidenceTier → corroboration → proof → falsification → verification
(producer/verdicts/consensus) → exploitability/exploitabilityTier →
riskDollars (cross-link Task 10's `risk-dollars.md` for the scenario-
disclosure detail, keep this file's treatment brief) → the two provenance
surfaces (`introducedBy`/`introducedIn`/`introducedAt` vs. the richer
`findingProvenance`, noting the latter needs `ci` or `--provenance` per
Task 3/4's correction) → whyFired → poc. Use the exact JSON from the spec.
Explicitly call out: `chain[]` is the real path-evidence field, never
`source`/`sink`/`path`; `verification.producer` is real but scoped to
verification/consensus, not a general "Producer Registry."

`verified-remediation.md` — document the three real, differently-cased
verify vocabularies from the spec verbatim: `fix-verify-loop.js`'s
`'verified-clean'|'verification-failed'|'untested-but-passes'`;
`fix-verify.js`'s richer object (`ok`, `verifiedFull`, `degradedLegs[]`,
`rescan.reason` values, `poc.status` values, the real multi-line `summary`
text block); `fix-honesty-gate.js`'s `'FULL'|'MITIGATION'|'WORKAROUND'` tier
with the invariant (FULL carries no residual, non-FULL must document one).
Use the real summary block from the spec verbatim as the "What You'll See"
example. If a real rejected-fix example isn't constructible within this
task's time budget, document the real rejection-message source templates
verbatim (quoted in the spec) instead of fabricating example output — say
explicitly in the doc that this shows the real message format, not a
captured run, if that's the path taken.

- [ ] **Step 1:** Write `docs/walkthroughs/finding-evidence.md` using the standard template.
- [ ] **Step 2:** Write `docs/walkthroughs/verified-remediation.md` using the standard template.
- [ ] **Step 3:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 4:** Commit: `git add docs/walkthroughs/finding-evidence.md docs/walkthroughs/verified-remediation.md && git commit -m "docs: add finding-evidence and verified-remediation walkthroughs"`

---

### Task 8: New walkthroughs — `privacy-data-flow.md` + `model-egress.md`

**Files:**
- Create: `docs/walkthroughs/privacy-data-flow.md`
- Create: `docs/walkthroughs/model-egress.md`

**Requirements:** spec sections "Data Flow Explorer screenshot target,"
"Real model egress module."

`privacy-data-flow.md` — a **narrative companion**, not a duplicate, of the
already-comprehensive `docs/guides/data-flow-explorer.md` (cross-link it
prominently near the top and don't restate its content). Focus this file
narrowly on "watch one field's journey": reuse the small
`card_number`-masked-vs-raw Mermaid diagram already committed to
`data-flow-explorer.md` this session (read it first — do not redraw), and
add narrative connective prose walking through source→transform→sink and
where the real screenshot from Task 11 will illustrate the fuller graph
(reference `docs/assets/` images by their planned filenames — Task 11 will
produce them; if Task 11 hasn't run yet when this task executes, note the
image reference and it will resolve once Task 11 lands, verified at Task 18).

`model-egress.md` — use the real `evaluateEgress`/`redactPayload` behavior
and the real example policy config from the spec verbatim. Show the real
pre-network-call call site from `llm-validator/index.js:464-475` (quoted in
the spec) as the concrete "policy runs before the network request" proof.
Cover the real decision vocabulary (`allow`/`deny`, modes `allow`/`deny`/
`local-only` — there is no `'redact'` decision value, redaction is a
separate pass) and the four real redaction passes (proprietary-path,
secrets, PII/PHI/PCI/FIN, customer-data).

- [ ] **Step 1:** Read `docs/guides/data-flow-explorer.md` in full to avoid duplicating it.
- [ ] **Step 2:** Write `docs/walkthroughs/privacy-data-flow.md`.
- [ ] **Step 3:** Write `docs/walkthroughs/model-egress.md`.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 5:** Commit: `git add docs/walkthroughs/privacy-data-flow.md docs/walkthroughs/model-egress.md && git commit -m "docs: add privacy-data-flow and model-egress walkthroughs"`

---

### Task 9: `docs/architecture/finding-lifecycle.md` + `docs/concepts.md`

**Files:**
- Create: `docs/architecture/finding-lifecycle.md`
- Create: `docs/concepts.md`

**Requirements:** spec sections "File manifest #17, #23."

`finding-lifecycle.md` — a Mermaid flowchart built from REAL module names,
not the original ask's invented "Producer Registry": per-file cascade
(`engine.js`) → `coverage-ledger.js` → `scan-health.js` →
`finding-schema.js`/`normalizeFindings()` → the evidence fields from Task 7
(chain/proof/falsification/confidence) → exploitability/riskDollars. One
paragraph of prose per stage, matching this repo's existing Mermaid-diagram
style (see the two diagrams already committed to
`docs/guides/data-flow-explorer.md` this session for tone/format).

`docs/concepts.md` — two sections in one file:
1. **Evidence Before Severity**: Observation → Evidence → Reachability →
   Proof/Falsification → Confidence → Severity/Risk, using the exact real
   field names from Task 7's finding-evidence.md (cross-link it).
2. **Deterministic vs. Model-Assisted**: which capabilities need no model
   (SAST/SCA/secrets/IaC — the core deterministic engine), which optionally
   use one (the Layer-3 LLM validator, gated on `AGENTIC_SECURITY_LLM_ENDPOINT`
   being configured, default-on once configured per root CLAUDE.md), which
   require an approved provider via the egress policy (cross-link
   `docs/walkthroughs/model-egress.md`), and which work fully disconnected
   (`--no-network`/`AGENTIC_SECURITY_OFFLINE`, per `docs/reference/configuration.md`).

- [ ] **Step 1:** Read the two existing Mermaid diagrams in `docs/guides/data-flow-explorer.md` for style reference.
- [ ] **Step 2:** Write `docs/architecture/finding-lifecycle.md`.
- [ ] **Step 3:** Write `docs/concepts.md`.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 5:** Commit: `git add docs/architecture/finding-lifecycle.md docs/concepts.md && git commit -m "docs: add finding-lifecycle diagram and a concepts page (evidence-before-severity, deterministic-vs-model-assisted)"`

---

### Task 10: `docs/governance/state-and-retention.md` + `docs/guides/risk-dollars.md`

**Files:**
- Create: `docs/governance/state-and-retention.md`
- Create: `docs/guides/risk-dollars.md`

**Requirements:** spec sections "Real state/retention," "Real risk-dollars
scenario disclosure."

`state-and-retention.md` — a table (Artifact | Purpose | Sensitive? |
Retention | Deleted by Reset) populated from the real
`scanner/src/posture/artifact-registry.js` classifications (already used
correctly this session for `configuration.md`'s tables — reread that
existing work rather than re-deriving), plus the real TTL table from the
spec (cache 7d/30d, scan 90d/365d, evidence 365d/1095d, ticket 180d/730d,
backup 30d/180d), the real encryption behavior (`local-key` AES-256-GCM,
fail-closed, scope exclusions), the real `export --out <dir>` command, and
the real `legal-hold` CLI surface. Cross-linked FROM `configuration.md`
(Task 4 already added that link — this task is the link's target).

`risk-dollars.md` — the real `.agentic-security/risk-config.yml` shape, the
5 required inputs, the three real `scenarioStatus` values and their exact
messages (quoted verbatim in the spec), and a worked before/after
(unconfigured `scenario_default` → configured `scenario_organization_specific`)
example using the real finding from Task 7 as the "before" state.

- [ ] **Step 1:** Read `scanner/src/posture/artifact-registry.js` and the current `docs/reference/configuration.md` tables.
- [ ] **Step 2:** Write `docs/governance/state-and-retention.md`.
- [ ] **Step 3:** Write `docs/guides/risk-dollars.md`.
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 5:** Commit: `git add docs/governance/state-and-retention.md docs/guides/risk-dollars.md && git commit -m "docs: add state-and-retention governance doc and risk-dollars guide"`

---

### Task 11: Real Data Flow Explorer screenshots

**Files:**
- Create: `docs/assets/dataflow-architecture-view.png`, `docs/assets/dataflow-trace-view.png` (2 images minimum; a 3rd or a short GIF optional if time allows)

**Requirements:** spec section "Data Flow Explorer screenshot target"
(resolved pipeline). Steps:
1. Run `node scanner/src/lineage/fixtures/build-flagship-fixture.mjs` — writes `flagship-graph.json` next to itself.
2. Write a small one-off Node script (in the scratchpad dir, not committed) that imports `signLastScan` from `scanner/src/posture/integrity.js`, reads `flagship-graph.json`, and writes it plus its `.sig` (via `signLastScan`) to `<scratch-dir>/.agentic-security/lineage-graph.json[.sig]`.
3. Run the real `node scanner/bin/agentic-security.js explore <scratch-dir> --port <n> --keep-open` in the background.
4. Load `mcp__claude-in-chrome__*` tools (ToolSearch first), navigate to the served URL (including its `#token=` fragment from the command's own stdout), and capture the architecture view and the trace/evidence view (click one flow to show its evidence) as real screenshots.
5. Save cropped, size-optimized PNGs to `docs/assets/`.
6. Stop the `explore` server.

If browser automation or the signed-fixture pipeline proves infeasible
within reasonable effort, report that explicitly rather than fabricating
screenshots — this is the one task in the whole plan allowed to come back
"blocked, here's why" instead of "done."

- [ ] **Step 1:** Build the flagship fixture graph.
- [ ] **Step 2:** Write and run the sign-and-place script (scratchpad only).
- [ ] **Step 3:** Start `explore` in the background against the scratch dir.
- [ ] **Step 4:** Load Chrome tools via ToolSearch, navigate, capture screenshots.
- [ ] **Step 5:** Save optimized PNGs to `docs/assets/`; stop the server.
- [ ] **Step 6:** Commit: `git add docs/assets/*.png && git commit -m "docs: add real Data Flow Explorer browser screenshots"`

---

### Task 12: `docs/examples/README.md` gallery

**Files:**
- Create: `docs/examples/README.md`

**Requirements:** spec section "File manifest #20." One entry per example
(SQLi, authz vulnerability, secret exposure, vulnerable dependency, IaC
misconfiguration, PII→logs, PII→external API, cross-file taint path,
incomplete scan, verified fix, rejected fix, compliance evidence, model
egress denial). Reuse real material already produced by earlier tasks
wherever it overlaps (the `report.py` SQLi finding from Task 7, the
EPSS-staleness partial-scan example from Task 6, the verified-remediation
summary from Task 7, the egress-denial call site from Task 8) rather than
re-deriving new examples — cross-link to the fuller walkthrough for each
rather than duplicating its full content; this page's job is a short,
scannable index, each entry answering: What happened? / What did the tool
find? / What evidence proves it? / What should the developer do?

- [ ] **Step 1:** Re-read the outputs of Tasks 6-8 for reusable real examples.
- [ ] **Step 2:** Write `docs/examples/README.md` with all 13 entries, cross-linking rather than duplicating.
- [ ] **Step 3:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 4:** Commit: `git add docs/examples/README.md && git commit -m "docs: add the examples gallery"`

---

### Task 13: `docs/reference/output-schema.md` + `docs/reference/glossary.md` + `docs/troubleshooting/scan-health.md`

**Files:**
- Create: `docs/reference/output-schema.md`
- Create: `docs/reference/glossary.md`
- Create: `docs/troubleshooting/scan-health.md`

**Requirements:** spec sections "File manifest #21, #22, #24."

`output-schema.md` — top-level concepts (`findings`, `scanHealth`,
`coverage`, `privacyInventory` if real — verify before claiming,
`policyDecision` if real — verify before claiming) with SMALL real excerpts
(reuse the `scanHealth` JSON and the `report.py` finding from earlier
tasks), not full dumps. Correct the schemaVersion nesting: there is no
top-level `schemaVersion` — it's nested inside `scanHealth.schemaVersion`.

`glossary.md` — only terms confirmed real in the spec's ground-truth
section (listed explicitly there — copy that list): finding, analyzer,
stableId, chain, proof, falsification, confidence/confidenceTier,
exploitability/exploitabilityTier, scanHealth, coverage,
complete/partial/failed, the riskDollars scenario states, the three verify
vocabularies, FULL/MITIGATION/WORKAROUND, egress allow/deny/local-only, the
three compliance vocabularies named distinctly. Define `verification.producer`
narrowly — never as a registry concept. 1-3 sentences per term.

`troubleshooting/scan-health.md` — "why did my scan fail," real causes
only: analyzer timeout, stale EPSS/KEV/calibration feed (real, demonstrated
in Task 6), parser unavailable, unsupported language, deep analysis
unavailable, egress denied (real, Task 8), required tests unavailable. Each
entry: What happened / Why it matters / How to investigate / How to fix —
cross-link `scan-health.md` (Task 6) and `model-egress.md` (Task 8).

- [ ] **Step 1:** Verify which of `privacyInventory`/`policyDecision` are real top-level output concepts before writing `output-schema.md` (grep the report-building source).
- [ ] **Step 2:** Write `docs/reference/output-schema.md`.
- [ ] **Step 3:** Write `docs/reference/glossary.md`.
- [ ] **Step 4:** Write `docs/troubleshooting/scan-health.md`.
- [ ] **Step 5:** Run `node scripts/check-doc-drift.mjs --gate`.
- [ ] **Step 6:** Commit: `git add docs/reference/output-schema.md docs/reference/glossary.md docs/troubleshooting/scan-health.md && git commit -m "docs: add output-schema and glossary reference docs, and a scan-health troubleshooting guide"`

---

### Task 14: `scripts/verify-doc-examples.mjs`

**Files:**
- Create: `scripts/verify-doc-examples.mjs`
- Modify: `scanner/package.json` (or repo-root `package.json` if scripts are invoked from there — check which convention `check-doc-drift.mjs` uses and match it) to add an `npm run` entry, e.g. `docs:verify-examples`

**Requirements:** spec section "Doc-testing precedent to reuse." Reuse
`scripts/check-doc-drift.mjs`'s `exportExistsIn()` pattern (verify a named
export exists in a source file) and import `checkAllLinks()` directly
rather than reimplementing link-checking. Add three new checks: (a) extract
CLI invocations from fenced ` ```bash ` blocks across `README.md` and every
new/modified doc in this plan, and verify each command/flag combination is
real by checking against `bin/agentic-security.js`'s command dispatch —
critically, flag any `<subcommand> --help` usage as an error (per the
Global Constraints rule) since that's the one landmine this whole project
must never reintroduce; (b) validate every fenced ` ```json ` block parses
as valid JSON; (c) a lightweight Mermaid fence sanity check (balanced
brackets/arrows/quotes, a recognized diagram-type keyword on the first
line) — a real render via `mermaid-cli` was confirmed non-functional in
this sandbox earlier this session, so this is intentionally a syntax
sanity check, not a real render. Do NOT wire this into `.githooks/` or the
pre-push gate — standalone `npm run` script only.

- [ ] **Step 1:** Read `scripts/check-doc-drift.mjs` in full for its conventions and exports to reuse.
- [ ] **Step 2:** Write `scripts/verify-doc-examples.mjs` with the CLI-invocation check.
- [ ] **Step 3:** Add the JSON-validation check.
- [ ] **Step 4:** Add the Mermaid sanity check.
- [ ] **Step 5:** Add the `npm run` script entry.
- [ ] **Step 6:** Run it against the current state of the repo's docs; fix any real hits it finds (these are genuine bugs the checker just proved exist).
- [ ] **Step 7:** Commit: `git add scripts/verify-doc-examples.mjs package.json scanner/package.json && git commit -m "docs: add a doc-example verification script (CLI flags, JSON, Mermaid syntax)"` (adjust the package.json path to whichever is correct)

---

### Task 15: README.md full rewrite

**Files:**
- Modify: `README.md` (currently 328 lines)

**Requirements:** spec section "File manifest #1" plus the Global
Constraints at the top of this plan. By the time this task runs, every doc
it will link to already exists (Tasks 1-14 are complete) — this is
deliberately sequenced last among the content tasks so no link is ever
dangling.

Structure (per the original request's own §29, still valid): hero (5
capabilities — Find/Prove/Fix/Govern/Explain, reframed with the REAL
vocabulary from this plan, e.g. "Prove It" cites `scanHealth`/the 3-state
ship verdict, not a fabricated `--explain-health`) → outcome table
(replacing any feature-dump list, matching the original ask's §30 table
shape: Capability | What Agentic Security Answers) → 5-minute quick start
(`ci . --assurance strict` — NEVER `scan . --assurance strict` — with the
real captured output from Task 3) → Findings-vs-Assurance section using
the real 3-state ship verdict as the running example (cross-link Task 6's
`scan-health.md`) → persona nav (Developer/AppSec/Privacy/Compliance/
Platform Engineering, each with 2-3 links into the docs built in Tasks
1-14) → "what this is not" (extend the EXISTING section at the end of the
current README, don't replace it) → fix the `:13` tagline ("Safe, secure,
and compliant" → something matching the real 3-state verdict, e.g. "Find
what's exploitable. Prove what ran. Verify what's fixed.") → fix the
`:274` "auditor-ready" line → cross-links to every new doc.

- [ ] **Step 1:** Read the full current `README.md`.
- [ ] **Step 2:** Draft the new structure section by section, pulling real facts only from this plan's earlier tasks' outputs and the spec — no new invented content.
- [ ] **Step 3:** Fix the `:13` tagline and `:274` overclaim as part of the rewrite (not separately — they're being replaced by the new hero/sections anyway).
- [ ] **Step 4:** Run `node scripts/check-doc-drift.mjs --gate` — must show ZERO broken links now that everything exists.
- [ ] **Step 5:** Run `node scripts/verify-doc-examples.mjs` (Task 14's script) against `README.md` specifically — must pass.
- [ ] **Step 6:** Commit: `git add README.md && git commit -m "docs: rewrite README around the 5-capability story with verified real commands throughout"`

---

### Task 16: `docs/README.md` landing page nav

**Files:**
- Modify: `docs/README.md`

**Requirements:** spec section "File manifest #2." Add persona-based nav
(Developer/AppSec/Privacy/Compliance/Platform Engineering — 2-3 links each
into the docs built in Tasks 1-14) as a new section near the top, without
discarding the existing task-based "Doing a task" nav (both can coexist —
persona nav for people who don't know which task-page they want yet).
Fix the `:27` "auditor-ready" overclaim. Add links to every new doc from
Tasks 6-13 into the existing task-based sections where they fit.

- [ ] **Step 1:** Read the full current `docs/README.md`.
- [ ] **Step 2:** Add the persona nav section.
- [ ] **Step 3:** Fix the overclaim line.
- [ ] **Step 4:** Add links to the new docs in the existing sections.
- [ ] **Step 5:** Run `node scripts/check-doc-drift.mjs --gate` — must show zero broken links.
- [ ] **Step 6:** Commit: `git add docs/README.md && git commit -m "docs: add persona-based nav to the docs landing page"`

---

### Task 17: Final overclaim sweep

**Files:** any file touched by `git grep` hits below (modify in place, no new files expected)

**Requirements:** spec's "Confirmed overclaims" list plus the original
ask's §32 full pattern list. Run, from repo root:
```bash
git grep -niP '\b(compliant|certification|auditor-ready|safe to deploy|fully verified|zero vulnerabilities)\b' -- '*.md' ':!docs/superpowers/**' ':!docs/implementation/**'
```
**Use `-P` (PCRE), not `-E` (POSIX ERE) — `git grep -E` does not support
`\b`, so an `-E` version of this command silently matches nothing and
reports a false "zero hits" clean sweep.** (Verified: this exact bug shipped
in this plan's own first run of Task 17 and was only caught by the final
whole-branch review — `git grep -niE '\bauditor-ready\b'` returns 0 hits
while `git grep -niP '\bauditor-ready\b'` returns 15 on the same tree. Before
trusting a zero-hit result from any `\b`-anchored `git grep`, prove the
pattern can match by first running it against a string you know is present.)
(exclude the plan/spec docs themselves and the historical implementation
reports, which legitimately narrate what was built/decided and shouldn't
be rewritten). For each real hit NOT already fixed by Tasks 1-16, apply the
same reframing discipline used throughout this plan (e.g. "Safe to deploy"
bare claims should be checked against whether they're the real, qualified
3-state ship-verdict string — those are fine verbatim — vs. an unqualified
marketing claim, which isn't). Also re-run a scan for `financial loss` /
`likely loss` outside the risk-dollars scenario-disclosure context (spec's
§15 concern) and confirm every such phrase is properly scenario-qualified.

- [ ] **Step 1:** Run the grep sweep above and list every hit with file:line.
- [ ] **Step 2:** For each hit, determine real problem vs. false positive (e.g. a quoted real CLI string like `'  ✅  Safe to deploy'` is fine; a bare marketing claim is not).
- [ ] **Step 3:** Fix every real problem found.
- [ ] **Step 4:** Re-run the grep sweep to confirm no new real hits remain.
- [ ] **Step 5:** Commit (only if changes were made): `git add -u && git commit -m "docs: final overclaim sweep — remove remaining unqualified compliance/safety language"`

---

### Task 18: Final verification pass

**Files:** none (verification only; fix anything broken)

**Requirements:** run the complete verification suite across the whole
docs tree touched by this plan.

- [ ] **Step 1:** `node scripts/check-doc-drift.mjs --gate` — must pass with zero broken links across the ENTIRE repo, not just files this plan touched.
- [ ] **Step 2:** `node scripts/verify-doc-examples.mjs` (Task 14) — must pass across `README.md` and every new/modified doc.
- [ ] **Step 3:** Spot-check 3 real commands from the finished `README.md`'s quick start by actually running them fresh (not trusting the earlier captured output — things may have drifted across the many commits in this plan).
- [ ] **Step 4:** Fix anything either check or the spot-check finds.
- [ ] **Step 5:** Commit any fixes: `git add -u && git commit -m "docs: fix issues found by the final verification pass"` (skip if nothing needed fixing).

---

## Self-Review Notes (for the coordinator, not a task)

- Spec coverage: every numbered file-manifest item in the spec maps to a
  task above — 1↔15, 2↔16, 3↔2, 4↔1, 5↔3, 6↔1, 7↔3, 8↔4, 9↔4, 10↔5, 11↔6,
  12↔6, 13↔7, 14↔8, 15↔7, 16↔8, 17↔9, 18↔10, 19↔10, 20↔12, 21↔13, 22↔13,
  23↔9, 24↔13, 25↔11, 26↔14 (spec item ↔ plan task). All 26 covered.
- No placeholders: every task cites the exact real facts/JSON/output to
  use, sourced from the spec, rather than "add appropriate content."
- Sequencing: README (Task 15) and the docs landing page (Task 16) are
  deliberately last among content tasks so no doc-link check ever sees a
  dangling reference mid-project; the final sweep (Task 17) and
  verification (Task 18) close the loop.
