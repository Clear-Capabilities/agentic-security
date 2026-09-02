# M4 deliverable — Third-Party and Cross-Border Intelligence (FR-506): scoping

## What the parent doc assumed vs. what real investigation found

The M4 top-level scoping doc's own row for this deliverable calls it *"the
one deliverable most likely blocked on more than code"* and recommends its
own dedicated investigation before any implementation plan, "likely the
last of the 4 decision-intelligence FRs to attempt." That caution is
correct and confirmed by this investigation — but the PRD's own FR-506
text (read in full this session, `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md`
line 539) explicitly narrows what's actually required, in a way the parent
doc's one-line summary didn't surface:

> *"Endpoint/provider resolution from code is separate from legal-entity,
> processor-role, contract, and jurisdiction evidence. A recognizable SDK
> or hostname may identify a technical provider but cannot establish legal
> recipient, processing location, DPA, transfer mechanism, or retention.
> **Offline curated mappings and user-supplied contracts/configuration are
> supported; any live enrichment is opt-in**, source-attributed, and
> governed by the existing egress policy."*

This is the PRD's OWN sanctioned path around the "no jurisdiction database"
problem: it never asks for a live third-party lookup service (which this
codebase's own "no runtime cloud calls" convention would reject anyway) —
it asks for (a) a small, offline, curated technical-provider mapping and
(b) an operator-declared facts file for everything code cannot determine,
with every unfilled field honestly `unknown`, never guessed.

### 1. A real, reusable technical-provider signal already exists — for SDK-shaped sinks only

`scanner/src/dataflow/catalog.js`'s AI-model-provider sink entries (added
for Milestone 1's own AC-07 closure) already carry a real `framework`
field naming the technical provider directly: `framework: 'anthropic'`,
`framework: 'openai'` (confirmed by direct grep — `js-anthropic-messages-create`,
`js-openai-chat-completions-create`, etc.). This is exactly the "recognizable
SDK... may identify a technical provider" case the PRD names as real and
legitimate — but it only covers the handful of catalog entries that are
SDK-method-shaped, not a raw hostname/URL literal reaching an
`external-api`/`webhook`/`analytics`/… category sink via `fetch`/`axios`/etc.

### 2. No hostname→provider mapping, no jurisdiction data, no subprocessor registry exists anywhere — confirmed, not assumed

Grepped the whole `src/` tree for any existing hostname-to-provider table,
any jurisdiction/country-of-processing data keyed by vendor, any DPA/SCC/
subprocessor registry: none exists. The one hit that looked promising —
`posture/blast-radius.js`'s own `jurisdictions` set — is a DIFFERENT
concept entirely (which REGULATORY FRAMEWORKS apply to the scanned
application, e.g. `GDPR`/`CCPA`/`HIPAA`, inferred from data-class/industry
signals) — not a recipient's own processing/storage COUNTRY, which is what
FR-506 needs. `resolve-destination.js` (Milestone 2, Sub-project A)
already resolves a sink's own `literalValue` (a raw hostname/URL string,
when statically resolvable) — that's the one piece of real raw material
this sub-project has to start from for the non-SDK case, and it carries
zero provider/jurisdiction information itself, by design (Milestone 2's
own scoping doc names "AI-provider/model resolution" as an explicitly
deferred increment of that same module, never built).

### 3. `decision-story.js` already has a `recipientJurisdiction` factor, permanently stubbed — a real, disclosed integration point, not required scope

Sub-project 7 (Executive Risk Story Mode) built its 9-factor ranking engine
with `recipientJurisdiction` as one of the two factors honestly marked
`available: false` on every flow (the other, `changeRecency`, was closed
by sub-project 8b). Its own header comment says outright: *"recipientJurisdiction
needs a RecipientProfile extension (capability #6, not yet built)."* This
sub-project is capability #6. Wiring `recipientJurisdiction` to become real
once a `RecipientProfile` exists is a natural, low-risk, DISCLOSED
opportunity — not required by FR-506's own text, and not committed to in
this scoping doc's own task breakdown below (a judgment call for the plan,
not decided here) — but flagged so a future reader doesn't miss it.

### 4. The §10.10 fact-typing vocabulary is cross-cutting, not `ObligationMapping`-specific — `RecipientProfile` must reuse it, not invent a parallel one

`obligation-mapping.js`'s own header states its `OBLIGATION_FACT_TYPES`
(`code_inferred`, `config_correlated`, `runtime_observed`, `declared`,
`manual`, `hypothetical`) implements *"PRD §10.10's cross-cutting
fact-typing rule, applied to every extension contract, not just this
one."* `RecipientProfile`'s own per-field evidence source must use this
SAME six-value vocabulary (importing it, not redefining it) — the technical-
provider match from catalog/hostname resolution is `code_inferred`; an
operator-declared fact from a config file is `declared`; anything genuinely
unknown stays `unknown`/absent, never silently defaulted to one of the
other five.

## Scope for this sub-project

**In scope — the code-derivable + operator-declarable half of FR-506,
matching the PRD's own explicit "offline curated + user-supplied" sanction:**

- `recipient-profile.js`: the `RecipientProfile` §10.10 extension contract
  (pure schema/validation, mirroring `obligation-mapping.js`'s exact
  shape — zero imports except the shared `OBLIGATION_FACT_TYPES` vocabulary
  from that file, a real ID scheme in `ids.js` mirroring `obligationId`'s
  own object-argument pattern). Fields per PRD line 541-548's own bullet
  list, each with its own fact-type-tagged evidence: `technicalEndpoint`,
  `provider`/`serviceType`, `legalEntity`, `processorRole`, `subprocessorChain`,
  `processingCountries`, `dataResidencyCommitment`/`observedRegion`,
  `dpaStatus`/`transferMechanism`/`transferImpactReviewStatus`,
  `retentionCommitment`, plus the record-level `evidenceSource`/`owner`/
  `reviewDate`/`confidence`/`conflicts`/`expiration` PRD line 548 names
  explicitly. Every field defaults to `unknown`/absent, never fabricated —
  matching `APPLICABILITY_INPUT_KEYS`'s own "explicitly configured or
  marked unknown — never guessed" precedent from `obligation-mapping.js`.
- A small, curated, offline hostname/SDK→technical-provider lookup table
  (a NEW, narrow catalog — NOT an extension of `dataflow/catalog.js`,
  which is a vulnerability taxonomy, not a provider directory; mirrors
  `transform-catalog.js`'s own precedent of "a genuinely new, small, hand-
  curated table, disclosed as thin and precision-over-recall, not padded
  to look complete"). Seeded from real, already-recognized entries this
  codebase's own catalog already implies exist (the AI-provider `framework`
  field) plus a small, honestly-disclosed set of other common SaaS/cloud
  hostnames (payment, email, cloud storage, analytics — exact list decided
  at plan time, following `transform-catalog.js`'s own "precision over
  recall" discipline: better a short, correct list than a padded, guessed
  one). Resolves EITHER a catalog `framework` match OR a `resolveDestination`
  `literalValue` hostname to `{provider, serviceType, factType: 'code_inferred'}`
  — never anything beyond technical-provider identification, per the PRD's
  own explicit line "cannot establish legal recipient, processing location,
  DPA, transfer mechanism, or retention."
- An operator-declared recipient-facts config file (a NEW
  `.agentic-security/recipient-profiles.json`, matching
  `privacy-policy.json`/`privacy-governance.json`/`drift-policy.json`'s own
  established precedent exactly — same fail-closed loading discipline,
  same "never throws, malformed degrades honestly" contract), letting an
  operator declare the REAL legal-entity/jurisdiction/DPA/subprocessor/
  retention facts for a given provider/hostname key. This is the PRD's own
  "user-supplied contracts/configuration are supported" clause, and is the
  ONLY source these fields can ever come from in this sub-project — never
  guessed, never inferred from a hostname alone.
- A resolution/build step wiring both sources into real `RecipientProfile`
  records per external/unresolved sink node in a real graph (mirrors
  `coverage.js`'s own `opts.resolveX` hook-composition pattern from
  Milestone 2 — additive, never replacing an existing hook).
- CLI export (`dataflow export --format recipients` or a dedicated
  subcommand — decided at plan time, following whichever precedent reads
  more consistent with `dpia`/`ropa`/`briefing`'s own established shape):
  a Markdown/JSON report of every recipient profile the graph produces,
  explicit about which fields are `code_inferred` vs `declared` vs
  `unknown` — never presenting a technical-provider match as if it were a
  legal/jurisdiction fact.

**Out of scope, disclosed, not attempted — matching every prior M4
sub-project's own CLI-only precedent:**

- The "visual experience" PRD line 550 describes (recipient cards,
  jurisdiction/transfer map, subprocessor chain diagram, concentration
  view) — genuinely new frontend/Milestone-3-server work, no CLI/Markdown
  equivalent attempted, matching `dataflow diff`/`dataflow watch`/the
  Executive Risk Story's own established "backend + CLI first, UI is a
  later milestone's job" boundary.
- Any LIVE/network-based enrichment (WHOIS, IP geolocation, a commercial
  vendor-intelligence API) — the PRD's own text makes this explicitly
  opt-in and separate from this sub-project's core; this codebase's own
  "no runtime cloud calls" convention (root `CLAUDE.md`) would gate any
  such addition behind its own opt-in flag and disk cache regardless, and
  nothing in FR-506's own acceptance requires it.
- Wiring `decision-story.js`'s `recipientJurisdiction` factor to become
  real — a real, disclosed, natural follow-up (§3 above), not committed to
  in this sub-project's own task breakdown; a future increment's call.
- Any change to `resolve-destination.js`'s own resolution logic — this
  sub-project CONSUMES its `literalValue` output, never modifies how
  destinations are resolved.
- A subprocessor-CHAIN discovery mechanism (recursively resolving a
  recipient's own downstream subprocessors) — no code-derivable signal for
  this exists; the `subprocessorChain` field stays operator-declared-only,
  same as every other legal/contractual field.

## Sizing

**Large**, matching the parent doc's own estimate — genuinely more new
code than any prior M4 sub-project except #6 (Regulatory Obligation
Overlay, which took a 3-way 6a/6b/6c split) and #7 (Executive Risk Story).
Unlike #6/#7, this sub-project's hardest problem is NOT a predicate/ranking
engine over existing data — it's building the first NEW curated data table
and the first NEW operator-config file this specific area of the codebase
needs, plus the extension contract and CLI wiring on top. Recommend a
similar split to sub-project 8b's own 3-task shape:

1. `RecipientProfile` extension contract (small, mechanical, mirrors
   `obligation-mapping.js` almost line-for-line — comparable to
   sub-project 8a's or this sub-project 9's own Task 1 in size).
2. The provider catalog + operator-config loader + resolution logic (the
   real new work — comparable to sub-project 8b's own Task 2, but with a
   genuinely new curated data table to build and disclose honestly rather
   than an algorithm to design).
3. CLI wiring + docs + tests (comparable to every prior M4 sub-project's
   own final CLI task).

See the companion `-plan.md` for the exact task breakdown, once written.
