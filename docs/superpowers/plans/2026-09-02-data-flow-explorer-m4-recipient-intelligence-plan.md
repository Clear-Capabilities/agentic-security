# M4 — Third-Party and Cross-Border Intelligence (FR-506) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the code-derivable + operator-declarable half of FR-506 —
a `RecipientProfile` extension contract, a small offline curated
technical-provider lookup, an operator-declared recipient-facts config
file, graph-wiring to produce real records, and a CLI export — matching
the PRD's own explicit "offline curated mappings and user-supplied
contracts/configuration are supported; any live enrichment is opt-in"
sanction.

**Architecture:** Three new modules plus graph-builder wiring plus a CLI
subcommand. `recipient-profile.js` (Task 1) is a pure §10.10 contract,
mirroring `obligation-mapping.js`'s exact shape. `recipient-registry.js`
(Task 2) resolves a sink site to a `RecipientProfile` from two sources
only — a small curated hostname/SDK→provider table (`code_inferred`) and
an operator-declared JSON config (`declared`) — never fabricating
anything else. Task 3 wires both into `graph-builder.js`/`coverage.js`
(mirroring Milestone 2 Sub-project A/B's own `opts.resolveX` hook
pattern) and exposes a `dataflow export --format recipients` CLI report.

**Tech Stack:** Node ≥ 24, ESM, no new dependency (matches every prior M4
sub-project).

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m4-recipient-intelligence-scoping.md`
— read in full before starting any task. It documents the real
investigation this plan is built on: a real, reusable technical-provider
signal already exists (`framework` field on AI-provider catalog sink
entries) but is SDK-shaped only; no hostname→provider/jurisdiction/
subprocessor data exists anywhere in this codebase (confirmed by grep,
not assumed); `decision-story.js` already has a `recipientJurisdiction`
factor permanently stubbed `available: false`, naming this exact
capability as its own prerequisite (wiring it real is a disclosed,
NOT-required follow-up, not part of this plan's own tasks); and the
`OBLIGATION_FACT_TYPES` vocabulary (`code_inferred`/`config_correlated`/
`runtime_observed`/`declared`/`manual`/`hypothetical`) is PRD §10.10's own
cross-cutting fact-typing rule, reused here (imported from
`obligation-mapping.js`), never redefined.

## Global Constraints

- Every `RecipientProfile` field that isn't `technicalEndpoint`/
  `provider`/`serviceType` (the only fields a code-derived signal can ever
  populate) stays `null`/absent unless an operator explicitly declared it
  in the config file. NEVER infer legal entity, jurisdiction, DPA status,
  subprocessor chain, or retention commitment from a hostname or provider
  name alone — the PRD's own FR-506 text forbids exactly this ("A
  recognizable SDK or hostname may identify a technical provider but
  cannot establish legal recipient, processing location, DPA, transfer
  mechanism, or retention").
- No live/network enrichment of any kind (no WHOIS, no IP geolocation, no
  vendor-intelligence API call) — matches this repo's "no runtime cloud
  calls" convention (root `CLAUDE.md`) and the PRD's own "any live
  enrichment is opt-in" text, which this plan does not attempt to satisfy
  (a real, disclosed, future increment's job).
- Per-field evidence typing, not one record-level `factType` —
  `RecipientProfile` differs from `ObligationMapping` here (a real,
  disclosed design difference, not an oversight): some fields are
  `code_inferred`, others only ever `declared`, on the SAME record. See
  Task 1's own field-by-field evidence design.
- No UI/frontend work (recipient cards, jurisdiction map, subprocessor
  diagram, concentration view) — CLI/JSON/Markdown only, matching every
  prior M4 sub-project's own established boundary.
- Touching `scanner/bin/agentic-security.js` (Task 3) requires `npm run
  build` before the final commit, with the bundle + sha256 sidecar
  confirmed regenerated.
- Reuse `OBLIGATION_FACT_TYPES` from `./obligation-mapping.js` — do not
  redefine an equivalent enum. This is the first time one §10.10 contract
  module imports from another; disclose this explicitly in Task 1's own
  header comment (mirroring how every prior sub-project discloses a novel
  architectural decision in its own module header, not just the plan).

---

### Task 1: `RecipientProfile` extension contract

**Files:**
- Create: `scanner/src/lineage/recipient-profile.js`
- Test: `scanner/test/lineage/recipient-profile.test.js`

**Interfaces:**
- Consumes: `OBLIGATION_FACT_TYPES` from `./obligation-mapping.js`
  (already shipped, real export — confirm by reading that file directly
  before importing).
- Produces: `RECIPIENT_PROCESSOR_ROLES`, `RECIPIENT_DPA_STATUSES`,
  `RECIPIENT_CONFIDENCE_LEVELS` (small, real enums — exact values below),
  `validateRecipientProfile(record) -> {valid, errors}` (never throws,
  mirrors `validateObligationMapping`'s exact `{path, message}` error
  shape). `ids.js` gains `recipientProfileId({graphId, graphDigest,
  recipientKey}, discriminatorParts = [])` → `recipient:<hash>` (mirror
  `obligationId`'s object-argument shape exactly — `recipientKey` is the
  stable string Task 2 uses to key a recipient, e.g. a normalized
  hostname or provider id; discriminated by graphId+graphDigest+
  recipientKey so two profiles for the same recipient across two
  different graphs never collide, and two DIFFERENT recipients in the
  same graph never collide either).

**Design** (read `obligation-mapping.js` in full first — this task
mirrors its STRUCTURE closely, but NOT its single record-level
`factType` — read the Global Constraints section above for why):

- `RECIPIENT_PROCESSOR_ROLES = Object.freeze(['processor', 'controller', 'joint_controller', 'unknown'])`
- `RECIPIENT_DPA_STATUSES = Object.freeze(['in_place', 'not_in_place', 'unknown'])`
- `RECIPIENT_CONFIDENCE_LEVELS = Object.freeze(['high', 'medium', 'low'])`
- A valid record's real fields (every one PRD line 541-548 names, no
  fewer):
  ```js
  {
    id: 'recipient:...',              // recipientProfileId()
    graphId: string,
    graphDigest: string,
    recipientKey: string,             // non-empty, the Task-2 stable key
    technicalEndpoint: string | null, // e.g. a hostname/URL
    provider: string | null,          // e.g. 'anthropic', 'stripe'
    serviceType: string | null,       // e.g. 'ai-model-provider'
    legalEntity: string | null,
    processorRole: one of RECIPIENT_PROCESSOR_ROLES | null,
    servicePurpose: string | null,
    subprocessorChain: string[],      // default []
    processingCountries: string[],    // default [], ISO-3166 alpha-2 strings, uppercase
    dataResidencyCommitment: string | null,
    observedRegion: string | null,    // honestly unused by Task 2 — no code-derivable signal exists this round; stays operator-declarable only, same as the others
    dpaStatus: one of RECIPIENT_DPA_STATUSES | null,
    transferMechanism: string | null,
    transferImpactReviewStatus: string | null,
    retentionCommitment: string | null,
    contributingGraphIds: string[],   // default [] — real node/edge/flow ids this profile is derived from, mirrors ObligationMapping's own field exactly
    fieldEvidence: {                  // REQUIRED object; every non-null/non-default field ABOVE must have a matching key here
      [fieldName]: { factType: one of OBLIGATION_FACT_TYPES, source: string | null },
    },
    confidence: one of RECIPIENT_CONFIDENCE_LEVELS | null,
    owner: string | null,
    reviewDate: string | null,
    conflicts: string[],              // default []
    expiration: string | null,
  }
  ```
- `validateRecipientProfile(record)` structural rules, mirroring
  `validateObligationMapping`'s own style exactly:
  - `id` required, must start with `recipient:`.
  - `graphId`/`graphDigest`/`recipientKey` required non-empty strings.
  - Every array field defaults to `[]` when omitted (mirror
    `validateObligationMapping`'s `?? []` pattern on `contributingGraphIds`/
    `evidence`/`conflicts`/`missingManualArtifacts` — do the same here)
    and must be a string array when present.
  - `processorRole`/`dpaStatus`/`confidence`, when non-null, must be a
    member of their own enum.
  - `processingCountries` entries, when present, must each be a
    2-uppercase-letter string (`/^[A-Z]{2}$/`) — never validate them
    against a real ISO-3166 list (this module has zero imports beyond
    `OBLIGATION_FACT_TYPES`, matching the "small, cheap, pure" precedent
    every sibling contract module sets; a malformed 2-letter code is the
    OPERATOR's own data-entry error to catch, not this module's job to
    police against a real country list it doesn't have).
  - **The load-bearing structural rule**: for every field in the record
    whose value is non-null (scalars) or non-empty (arrays) among
    `technicalEndpoint`/`provider`/`serviceType`/`legalEntity`/
    `processorRole`/`servicePurpose`/`subprocessorChain`/
    `processingCountries`/`dataResidencyCommitment`/`observedRegion`/
    `dpaStatus`/`transferMechanism`/`transferImpactReviewStatus`/
    `retentionCommitment`, `fieldEvidence` MUST have a matching key with a
    real `factType` from `OBLIGATION_FACT_TYPES`. A field with real data
    but no evidence entry is exactly the "fabricated fact with no
    provenance" failure mode this whole plan's Global Constraints exist
    to prevent — enforce it structurally, not just by convention. (A
    null/empty field needs NO `fieldEvidence` entry — there's nothing to
    attribute.)
  - `fieldEvidence`'s own keys that DON'T correspond to a real field name
    above are also an error (a typo'd key silently produces an
    unenforced, orphaned evidence entry — catch it).

**Tests to write:**
- A well-formed record (every field populated, matching `fieldEvidence`
  for every non-null field) validates clean.
- A record missing `fieldEvidence` for a populated field fails with a
  clear path naming the field.
- A record with an orphaned `fieldEvidence` key (no matching field, or a
  typo'd name) fails.
- Each enum field rejects an unrecognized value.
- `processingCountries` rejects a malformed entry (`'usa'`, `'U'`,
  `123`).
- Array fields default to `[]` when omitted, don't error.
- `recipientProfileId`: same `(graphId, graphDigest, recipientKey)` twice
  → same id; different `recipientKey` → different id; different
  `graphDigest` (same graphId) → different id (mirrors `obligationId`'s
  own pinned discriminator-completeness tests — copy that test's shape).

- [ ] Write the failing tests.
- [ ] Run to verify failure.
- [ ] Implement `recipient-profile.js` + `ids.js`'s `recipientProfileId`.
- [ ] Run to verify pass.
- [ ] Wire into `test:lineage`, run the full scope, commit.

---

### Task 2: The provider catalog + operator-config loader + resolution logic

**Files:**
- Create: `scanner/src/lineage/recipient-registry.js`
- Test: `scanner/test/lineage/recipient-registry.test.js`

**Interfaces:**
- Consumes: `RecipientProfile`'s real shape (Task 1); `dataflow/catalog.js`'s
  real `CATALOG` (read-only, for the `framework` field already on
  AI-provider sink entries — confirm the exact entries/values by reading
  `catalog.js` directly, don't guess); `resolveDestination`'s real
  `destination` object shape (`resolutionStatus`/`literalValue`) from
  Milestone 2 Sub-project A (already shipped, read `resolve-destination.js`
  directly for the exact field names).
- Produces:
  - `TECHNICAL_PROVIDER_CATALOG` — a small, curated array of
    `{provider, serviceType, hostnamePatterns: [regex-source strings],
    frameworkNames: [string]}` entries (design the exact list below).
  - `resolveTechnicalProvider({framework, literalValue}) ->
    {provider, serviceType} | null` — never throws; matches EITHER a
    catalog entry's own `frameworkNames` (exact match against the sink
    site's own `framework`, when present) OR a `hostnamePatterns` regex
    test against `literalValue` (when present). Returns `null` on no
    match — never a guess.
  - `loadRecipientConfig(configFilePath) -> {recipients: {...}}` — mirrors
    `drift-policy.js`'s `loadDriftPolicies` EXACTLY (never throws; missing
    file → `{recipients: {}}`; malformed JSON logs a warning, degrades to
    `{recipients: {}}`; each entry validated loosely, a malformed one is
    skipped with a warning naming the count, never crashes the whole
    load). Config shape: `{"recipients": {"<recipientKey>":
    {"legalEntity": "...", "processorRole": "...", "subprocessorChain":
    [...], "processingCountries": [...], "dataResidencyCommitment": "...",
    "dpaStatus": "...", "transferMechanism": "...",
    "transferImpactReviewStatus": "...", "retentionCommitment": "...",
    "confidence": "...", "owner": "...", "reviewDate": "...",
    "conflicts": [...], "expiration": "..."}}}` — every key here maps
    1:1 onto a `RecipientProfile` field this module can ONLY ever fill
    from operator config (per the Global Constraints), so no separate
    translation table is needed; validate loosely against Task 1's own
    enums (skip/warn on a bad value inside one recipient entry, don't
    drop the whole file).
  - `buildRecipientProfile(site, graphAfter_or_graph, opts) ->
    RecipientProfile | null` — the real resolution function. `site` is
    the same shape `graph-builder.js`'s `enumerateSinkSites` already
    produces (read that function's real output shape directly before
    writing this — it's already shipped and used by Milestone 2's own
    `resolveDestination`/`resolveTransitProtection` hooks, so the exact
    fields you need — `framework`, `destination`, the node/decision this
    site resolves to — are already established precedent; don't invent a
    new site shape).
    - `recipientKey` resolution: prefer `resolveTechnicalProvider`'s own
      `provider` string when it matched; else the destination's own
      `literalValue` (lowercased, a bare hostname extracted from it if
      it's a full URL — reuse a tiny local helper, don't pull in a URL
      parsing dependency); else `null` (return `null` from
      `buildRecipientProfile` — no key, no profile; never fabricate a key
      from nothing).
    - If `resolveTechnicalProvider` matched: `provider`/`serviceType`
      populated, `fieldEvidence.provider`/`fieldEvidence.serviceType` =
      `{factType: 'code_inferred', source: 'recipient-registry:catalog'}`.
      `technicalEndpoint` = the raw `literalValue` when the destination
      was `'literal'`, else `null` — with `fieldEvidence.technicalEndpoint`
      = `{factType: 'code_inferred', source: '...'}` only when non-null.
    - If an operator config entry exists for this `recipientKey`: every
      field it supplies gets copied onto the profile with
      `fieldEvidence.<field> = {factType: 'declared', source:
      'recipient-profiles.json'}`.
    - If NEITHER source produced anything (no catalog/hostname match, no
      operator entry) — return `null`. A site with genuinely zero
      recipient information is not worth minting an all-null record for.
  - `RECIPIENT_CONFIG_FILENAME = 'recipient-profiles.json'` (exported
    constant, mirrors how other config-filename constants in this
    package are named and exported, for Task 3's own `statePath` call).

**The curated provider catalog** — precision over recall, matching
`transform-catalog.js`'s own established discipline (a short, correct
list beats a padded, guessed one). Seed it from TWO real sources only:
1. Every catalog entry with a real `framework` value on an AI-provider
   sink (read `dataflow/catalog.js` directly, confirm the exact set —
   likely `anthropic`/`openai`, possibly more; do not assume, verify).
2. A small, disclosed set of other common SaaS/cloud hostnames this
   codebase's own catalog/privacy-catalog ALREADY implies matter (e.g.
   `stripe.com` if a Stripe-shaped sink entry exists anywhere — check
   `privacy-catalog.js`/`catalog.js` for real receiver/hostname strings
   before inventing any; `s3.amazonaws.com`/`storage.googleapis.com` for
   object storage if `SINK_CATEGORIES`'s `object-storage` has a real
   catalog entry naming one). If you cannot find a real, already-matched
   hostname signal for a category beyond the AI-provider ones, DO NOT
   invent one — a thinner, honestly-disclosed catalog (mirroring
   `transform-catalog.js`'s own "two thinnest kinds, disclosed rather
   than padded" precedent) is correct; name what's missing in your own
   module header comment rather than guessing a hostname this codebase
   has no real signal for.

**Tests to write:**
- `resolveTechnicalProvider`: a real `framework: 'anthropic'` match; a
  real hostname-pattern match against a `literalValue`; no match returns
  `null`, never throws.
- `loadRecipientConfig`: missing file → `{recipients: {}}`; malformed
  JSON → degrades honestly, warns; a malformed individual recipient entry
  (bad enum value) is skipped, others still load; a well-formed file
  round-trips exactly.
- `buildRecipientProfile`: a real end-to-end case combining a catalog
  match (provider/serviceType, `code_inferred`) with an operator config
  match for the SAME recipientKey (legalEntity/jurisdiction/etc.,
  `declared`) on one profile — confirm the two evidence types coexist
  correctly on one record and the record validates via
  `validateRecipientProfile`. A catalog-only case (declared fields all
  null/absent, no `fieldEvidence` entries for them). An
  operator-config-only case (a recipientKey with no catalog match at all
  — e.g. a hostname nothing in the curated list recognizes, but the
  operator declared it anyway; `provider`/`serviceType` stay null,
  `technicalEndpoint` still populates from `literalValue` if resolvable).
  A genuinely-nothing case returns `null`.
- Fail-closed on `processingCountries`/other enum values sourced from a
  malformed operator config entry — never silently accept a bad value
  onto the record (either skip that one field with a warning, or skip the
  whole entry — pick one, document which, in the module's own header
  comment).

- [ ] Write the failing tests.
- [ ] Run to verify failure.
- [ ] Implement `recipient-registry.js` per the design above.
- [ ] Run to verify pass.
- [ ] Wire into `test:lineage`, run the full scope, commit.

---

### Task 3: Graph wiring + CLI export

**Files:**
- Modify: `scanner/src/lineage/graph-builder.js`
- Modify: `scanner/src/lineage/coverage.js`
- Modify: `scanner/src/lineage/index.js`
- Modify: `scanner/bin/agentic-security.js`
- Modify: `commands/dataflow.md`
- Test: `scanner/test/lineage/recipient-wiring.test.js`, `scanner/test/cli/dataflow-recipients.test.js`

**Interfaces:**
- Consumes: `buildRecipientProfile`/`loadRecipientConfig`/
  `RECIPIENT_CONFIG_FILENAME` (Task 2); `validateRecipientProfile` (Task
  1).
- Produces: `graph.recipientProfiles` (an ARRAY on the built graph object
  — NOT inside `dataflow-graph.schema.json`/`validate.js`'s
  `validateGraph`, mirroring how `ObligationMapping`/`DecisionStory`/
  `GraphSnapshot` records are ALL explicitly "associated with, but not
  required inside, the immutable base graph" per §10.10 — read
  `obligation-mapping.js`'s own header comment again if you need the
  exact citation). A new `dataflow export --format recipients` CLI mode.

**Design** (read `graph-builder.js`'s own `opts.resolveDestination`/
`opts.resolveTransitProtection` hook-composition pattern from Milestone 2
Sub-project A/B FIRST — this task adds a THIRD hook of the identical
shape, not a new pattern):

- `graph-builder.js`: after the existing sink-site enumeration/decision
  loop (the same point `resolveDestination`/`resolveTransitProtection`
  already hook into — confirm the exact real line by reading the file,
  the design docs referenced above name it precisely), add
  `opts.buildRecipientProfile(site, graph) -> RecipientProfile | null`,
  called once per sink site whose destination resolved to something
  (skip sites with no destination at all — nothing to key a recipient
  on). Collect non-null results into `graph.recipientProfiles` (dedup by
  `id` — the SAME recipient reached by two different sink sites in one
  scan must not mint two records; merge `contributingGraphIds` across
  duplicate resolutions instead of dropping the second). Byte-identical
  to today's output when the hook is omitted (mirrors every prior
  Milestone 2 hook's own proven "no-op when omitted" contract — write a
  test proving this explicitly, matching `M2A1/hook-1`'s own precedent
  cited in this package's CLAUDE.md).
- `coverage.js`: `buildGraphWithCoverage` wires a default
  `opts.buildRecipientProfile` closing over `opts.recipientConfig` (a
  pre-loaded `{recipients: {...}}` object, NEVER a raw file path —
  mirrors `opts.privacySinkPolicy`'s own precedent from Milestone 2
  Sub-project G exactly: the FILE READ happens once, upstream, in
  `index.js`, never inside `coverage.js`/`graph-builder.js` themselves),
  composing with a caller-supplied override the same way every other
  hook in this file already does.
- `index.js` (`buildLineageGraph`): loads the operator's recipient config
  EXACTLY ONCE per call, gated on a real `fs.existsSync` check against
  `statePath(opts.scanRoot, RECIPIENT_CONFIG_FILENAME)` — mirror Sub-project
  G1's own `privacySinkPolicy` loading discipline in this exact file
  precisely (same single-computation rule, same "genuinely undefined
  unless a file is actually on disk" contract), not a new pattern.
- `bin/agentic-security.js`: add `'recipients'` to whatever the real,
  current `DATAFLOW_EXPORT_FORMATS` set is called (read `cmdDataflowExport`
  directly to confirm the exact name/shape — it's already an established
  set with `json`/`csv`/`html`/`dpia`/`ropa`/`briefing` in it as of this
  plan's own writing; a new member is a mechanical addition, not a design
  decision). The new format's own render function (new, small — Markdown
  table, one row per `graph.recipientProfiles[]` entry, columns for
  provider/serviceType/legalEntity/processorRole/jurisdiction(s)/
  dpaStatus/confidence, with a footer disclosing which fields are
  `code_inferred` vs `declared` vs absent for that row — escape every
  interpolated operator-supplied string via the SAME local
  `_mdInline`/`_mdCell`/`_mdCode` pattern `export-briefing.js`/
  `export-privacy.js` both already establish; do not invent new escaping
  logic). `--no-redact`/`--view`/`--filter` behavior: follow whichever of
  the existing formats' own precedent is the closest fit (this format has
  no view concept, matching `dpia`/`ropa`/`briefing`; decide `--filter`'s
  exact scoping behavior — narrow `graph.recipientProfiles` by whether
  any of a profile's `contributingGraphIds` survive the filter — and
  `--no-redact`'s exact meaning — likely a no-op the same way `dpia`/
  `ropa` treat it, since a `technicalEndpoint`/hostname is arguably
  sensitive but this decision doesn't have strong existing precedent to
  copy verbatim; make the call, disclose it in your own report).
- `commands/dataflow.md`: a new `recipients` row in the `## Formats`
  table (matching every other row's own tone/detail level) — no new
  top-level section needed, unlike `diff`/`watch`, since this is a new
  `--format` value of the EXISTING `export` subcommand, not a new
  subcommand.

**Tests to write:**
- `graph-builder.js`: the hook composes correctly, byte-identical output
  when omitted, real end-to-end profile construction on a real parsed
  fixture reaching an AI-provider sink (reuse sub-project 8b's own
  "patient_record → anthropic.messages.create" fixture shape — a proven,
  reusable real-code case for exactly this scenario). Dedup across two
  sites resolving to the same recipient.
- `coverage.js`/`index.js`: the config-file-loaded-once discipline
  (mirror Sub-project G1's own `Proxy`-based or explicit call-count test
  technique for `scanTransitEvidence`'s "exactly once" proof, whichever
  this package's own precedent used for `privacySinkPolicy`'s load — read
  `policy-verdict.test.js` for the exact technique it already proved).
- CLI: a real end-to-end `dataflow export --format recipients` run
  against a real fixture + a real `recipient-profiles.json` on disk,
  producing a real Markdown report naming the real provider and the real
  operator-declared fields, with the code-inferred vs. declared
  disclosure visibly correct. A run with NO recipient config file present
  still produces a report (catalog-only profiles, or an honest "no
  recipients resolved" message if the fixture reaches nothing
  recipient-worthy).

- [ ] Write the failing tests.
- [ ] Run to verify failure.
- [ ] Wire the graph builder + coverage + index + CLI + docs.
- [ ] Run to verify pass.
- [ ] `npm run build`, confirm bundle sha256 regenerates (and any new
      dist chunk files are `git add`ed), commit.

## Self-review notes (per the writing-plans skill)

- **Spec coverage:** every PRD line 541-548 field is represented in Task
  1's own record shape; the "offline curated + user-supplied, no live
  enrichment" sanction is honored by Task 2's own two-source-only design;
  the "endpoint/provider resolution is separate from legal/jurisdiction
  evidence" rule is enforced structurally by Task 1's own per-field
  `fieldEvidence` requirement, not left to convention.
- **Placeholder scan:** Task 1 has a complete, literal field/enum list
  and a precisely-specified validation rule set (the load-bearing
  fieldEvidence-completeness check is given in full, not sketched). Tasks
  2/3 are design specs at the same level of detail sub-project 8b's own
  Task 2/3 briefs used for comparably novel work — exact function
  signatures, exact reuse targets, exact judgment-call boundaries named —
  not vague prose.
- **Type consistency:** `RecipientProfile`'s real field names (Task 1)
  are exactly what Task 2's `buildRecipientProfile` populates and exactly
  what Task 3's CLI renderer reads — confirmed consistent across all
  three tasks' own Interfaces sections above. `recipientProfileId`'s
  `(graphId, graphDigest, recipientKey)` discriminator is what both Task
  2 (building the key) and Task 3 (deduping by id) rely on.
- **Out-of-scope reminder:** no live enrichment; no UI/frontend; no
  `decision-story.js` wiring (a disclosed, real follow-up, not this
  plan's own task); no subprocessor-chain discovery mechanism (operator-
  declared only, forever, per the PRD's own text — no code signal exists
  for this and none is invented here).
