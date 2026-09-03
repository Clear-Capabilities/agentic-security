# M5, Runtime-Corroborated Digital Twin (deliverable #7): scoping

Per the M5 top-level scoping doc's own row for deliverable #7 ("Large —
split into 2"; 7a CONFIG DECLARED at Medium, 7b RUNTIME OBSERVED at
Large; dependencies "none directly"). That row is a scoping-level guess.
This document verifies it against the real code and corrects it in
**seven** places, two of which invert the row's own conclusions:

1. **This deliverable IS gated by a named acceptance criterion — AC-29,
   named in the Milestone 5 exit gate itself.** The row does not mention
   AC-29 anywhere. It is not an ungated deliverable like #5.
2. **AC-29 gates 7b and gates 7a not at all** — so the row's own
   recommended "7a then 7b" ordering is backwards.
3. **7a is not new scope. It is M2 Sub-project F2/F3**, already scoped in
   a committed document that sized it as *two* Large sub-projects each
   needing its own scoping pass — directly contradicting the row's
   "Medium, connection not new parsing."
4. One of 7a's two "already-shipped, already-tested parsers" does not
   export what the row assumes, and its own module header is wrong about
   its return shape.
5. The row names the wrong shared vocabulary. The real one is bigger,
   graph-level, and already shipped — **two of FR-505's four layers
   already exist.**
6. **Both storage candidates the row names are wrong**, including the one
   it endorses, and for a reason the row never raises: FR-505 requires
   *retention and reset*, which an append-only hash-chained ledger
   actively fights. A third, already-shipped precedent is the right one.
7. `posture/runtime-correlation.js` is real and its technique is
   reusable, as claimed — but it is fully wired into every scan today
   (the row implies it is a standalone pattern), and its state file is an
   **unregistered artifact that silently escapes the registry
   completeness guard**, a trap 7b must not inherit.

---

## 1. What the PRD actually requires (verbatim)

### FR-505 (PRD lines 519-537), verbatim

> #### FR-505: Runtime-Corroborated Digital Twin
>
> Add independently selectable layers for:
>
> - `CODE POSSIBLE` — statically inferred flow;
> - `CONFIG DECLARED` — IaC, service-map, policy, or manual topology;
> - `RUNTIME OBSERVED` — metadata observation correlated to a canonical
>   node/edge/flow;
> - `HYPOTHETICAL` — scenario-only projection.
>
> Runtime observations may include environment, service/workload
> identity, endpoint or destination identity, protocol/TLS metadata,
> schema/attribute names already approved for telemetry, event
> count/frequency band, and first/last observed time. They must not
> include payload values, request/response bodies, prompts, model
> outputs, database records, log messages, secrets, or sampled personal
> data.
>
> Requirements:
>
> - Adapters are explicit and optional, beginning with approved
>   OpenTelemetry traces/service graphs, gateway/mesh metadata, cloud flow
>   metadata, and application-provided schema-safe events.
> - Correlation records the matching method and confidence; ambiguous
>   observations remain candidates and do not silently merge data
>   elements.
> - The UI uses distinct edge treatment for possible, declared, observed,
>   and simulated flows and can filter by environment and observation
>   window.
> - Runtime observation may increase corroboration confidence but cannot
>   prove field-level identity unless safe schema/trace evidence maps that
>   field.
> - Absence of observation is `not_observed_in_window`, never
>   `does_not_occur`.
> - Observation stores follow artifact encryption, retention, reset,
>   access-control, and no-egress rules.

### AC-29 (PRD lines 1749-1753), verbatim

> ### AC-29: Runtime observation remains metadata-only and non-exclusionary
>
> **Given** one statically possible external flow has correlated runtime
> metadata and another has no observation in the selected window,
> **when** Runtime Digital Twin layers are displayed,
> **then** the first is `RUNTIME OBSERVED`, the second is
> `not_observed_in_window`, both static paths remain visible, match
> confidence/method and environment/window are shown, and no captured
> payload, prompt, response, record, log message, or sensitive value
> exists in the observation artifact.

### The Milestone 5 exit gate (PRD line 1854), verbatim

> Exit gate: AC-26, AC-29, and AC-31 plus all declared
> language/performance/accuracy/privacy thresholds pass with published
> limitations.

### The `RuntimeObservation` §10.10 contract row (PRD line 971)

> | `RuntimeObservation` | Observation ID, adapter/source,
> environment/window, matched canonical IDs, metadata-only attributes,
> count/frequency band, first/last observed, match method/confidence,
> retention |

### Four supporting constraints, each load-bearing

- **PRD line 983** (§10.10 cross-cutting rules): "Runtime records use
  approved metadata schemas and **reject** fields capable of carrying
  payload values." A *reject*, not a redact — the validator must be
  closed-world.
- **PRD line 979** (§10.10): "Each fact is typed as `code_inferred`,
  `config_correlated`, `runtime_observed`, `declared`, `manual`, or
  `hypothetical` and retains its evidence/provenance."
- **PRD line 1849** (Milestone 5 deliverable list): "Runtime-Corroborated
  Digital Twin **without collecting payloads or personal data**."
- **PRD line 2098** (§32 definition of done, item 21): "Runtime-
  Corroborated Digital Twin displays possible, declared, observed, and
  hypothetical layers separately, retains no payload or sensitive values,
  and **never treats non-observation as non-occurrence**."

Plus **DFG-039** (PRD line 1898), the backlog entry: *P2*, depends on
DFG-024 ("Privacy-preserving runtime-observation schema and adapter
foundation", also P2), DFG-028, DFG-030. And **PRD line 2061**, the
open-decision table: *"Runtime evidence | Optional P2 overlay, never
required for local static visualization."*

---

## 2. Seven corrections to the M5 top-level doc's own row

### Correction 1 (the load-bearing one): AC-29 gates this deliverable, and the row never mentions it

The M5 row's dependency column reads *"none directly; recommend landing
near item 3 (What-If) to share the `OBLIGATION_FACT_TYPES` vocabulary."*
It never names an acceptance criterion, and its whole framing is about
vocabulary convenience.

**AC-29 is FR-505's own acceptance criterion — its title is literally
"Runtime observation remains metadata-only and non-exclusionary" — and it
is named in the Milestone 5 exit gate alongside AC-26 and AC-31.** That
places this deliverable in exactly deliverable #6's category, not
deliverable #5's:

- #5 (Governance Editing) shipped a materially narrower CLI-only cut, and
  its own scoping doc justified that by proving **no** AC anywhere in the
  PRD gates it.
- #6 (Remediation Command Center) could not use that argument, because
  AC-31 is in the exit gate. Its scoping doc made this Correction 1, and
  the final whole-branch review then found **three Blocking bugs, each
  falsifying one of AC-31's own three clauses** — the first time in this
  session that the miss was on a deliverable's own literal gating
  criterion.
- **#7 is the #6 case, not the #5 case.** Surface area may still narrow
  (no UI, one adapter, CLI-only) — but every clause of AC-29's own `then`
  must be genuinely satisfied by whatever ships, and the same review
  rigor #6 needed applies here.

### Correction 2: AC-29 gates 7b specifically, and 7a not at all — so the row's recommended ordering is backwards

Read AC-29's `given` clause literally: *"one statically possible external
flow **has correlated runtime metadata** and another **has no observation
in the selected window**."* Both arms of the given are runtime
observations. The `then` clause's five requirements are:

| # | AC-29 `then` clause | Which split satisfies it |
|---|---|---|
| 1 | the first is `RUNTIME OBSERVED` | 7b only |
| 2 | the second is `not_observed_in_window` | 7b only |
| 3 | both static paths remain visible | 7b only (a non-exclusion property of the correlation pass) |
| 4 | match confidence/method and environment/window are shown | 7b only |
| 5 | no captured payload… exists in the observation artifact | 7b only |

**CONFIG DECLARED appears in zero of them.** 7a satisfies no acceptance
criterion at all — it is FR-505 body text plus FR-304's already-scoped
work (Correction 3). The M5 doc's own recommended-ordering list
(line 168) says *"split 7a (CONFIG DECLARED) then 7b (RUNTIME
OBSERVED)"*. That ordering puts the ungated half first and the
exit-gate-named half second. **Ruling: reverse it.** 7b is the
deliverable; 7a is the option.

### Correction 3: 7a is not new scope — it is M2 Sub-project F2/F3, already scoped and deliberately deferred as *two Large sub-projects*

The row sizes 7a as **Medium**, "bridges two already-shipped,
already-tested parsers… into graph-attached facts; the work is
connection, not new parsing."

`docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-f-scoping.md`
is a committed document in this same repository that already scoped this
exact work, from a direct read, and reached the opposite conclusion:

> **F2 (Large, deferred, its own future scoping pass)** — bridge
> `cross-lang-openapi/grpc/graphql.js`'s already-parsed contract data into
> real `schema`-provenance graph edges. Real, new graph-building work…
> Sizing and staffing this honestly requires its own scoping pass, not
> estimated further here.
>
> **F3 (Large, deferred, its own future scoping pass)** — an
> operator-declared-service-graph ingestion mechanism, closing FR-304's
> "manually declared" and (partially) "cross-repository or federated"
> clauses. **No existing precedent inside `lineage/`.**

F3's "operator-declared-service-graph ingestion" *is* 7a's `services.yml`
half, named identically. F's own scoping states the reason it is Large,
and I re-confirmed it directly:

> **Every edge `buildDataFlowGraph` mints today is code-derived, 100%,
> with no exception** — seeding is exclusively `planSeeds(callGraph, ...)`
> walking real parsed CFG expressions, sink enumeration is exclusively
> `enumerateSinkSites(callGraph)` walking real CFG call nodes. The
> `opts.resolveSiteDecision`/`opts.resolveDestination`/
> `opts.resolveTransitProtection`/`opts.privacySinkPolicy` hooks all
> operate on a `site` already discovered from real code — **none can
> inject a node/edge with no backing call site.**

Confirmed against the current tree: every hook in `graph-builder.js`
(`opts.resolveSiteDecision` at `:547`, `opts.resolveDestination` at
`:566`, `opts.resolveTransitProtection` at `:699`,
`opts.resolveGovernanceRefs` at `:893`, `opts.buildRecipientProfile` at
`:970`) takes an *already-discovered* `site` and refines it. There is no
"mint an entity from nothing" path anywhere in the package. That
mechanism is what 7a needs and does not have, and inventing it is the
Large part F's scoping already identified.

**Two scoping documents in the same repo cannot both be right about the
same work.** F's is grounded in a direct read of `graph-builder.js`; the
M5 row's is a summary written from the parser side only. F's is correct.

### Correction 4: one of 7a's two "already-shipped, already-tested parsers" does not export what the row assumes

**`services.yml` — the row is RIGHT.**
`scanner/src/dataflow/cross-service-taint.js:52`'s `loadServiceGraph(scanRoot)`
is exported, reads `.agentic-security/services.yml`/`.yaml` via
`statePath`, and returns a normalized
`{services: {name: {name, repo, exposes[], consumes[]}}, edges: [{from, to, via, path, topic}]}`
(`_normalizeGraph`, `:67-86`). Never throws — a parse failure returns
`{_error}`, a missing file returns `null`. This is a genuinely reusable
declared-topology parser and the row's characterization holds.

**IaC exposure facts — the row is WRONG, in three separate ways.**

- `scanner/src/posture/iac-reachability.js:104`'s `scanIacReachability(fileContents, existingFindings)`
  **returns a SAST `Finding[]`, not exposure facts.** Its `return out` at
  `:168` returns only findings. The exposed-resource list is a
  module-private local (`const exposed = []`, `:107`) that is never
  returned and never exported.
- The module's **own header comment is wrong about this**: `:26` claims
  `Output: { exposedResources: [...], findings: [...] }`. No such object
  is ever constructed. Anyone scoping from the header would size this as
  "read an already-exported fact list"; the real work is exporting a new
  function or re-parsing.
- Even granting the refactor, the facts do not fit FR-505's layer.
  CONFIG DECLARED is a layer of *declared flows/edges*. An IaC exposure
  fact ("this `aws_s3_bucket` has a public-read ACL") is a **property of
  a resource**, not a flow between two. Mapping it onto the graph needs a
  node-identity correlation that does not exist: `findCodeReferences`
  (`:80-102`) correlates by uppercasing the Terraform resource name into
  an env-var pattern and by raw string-literal match, then attaches to
  findings within ±5 lines (`:137-139`). That is a text heuristic with no
  graph-ID awareness at all. It is also **Terraform-only and AWS-only**
  (`parseTerraform`, `:31`, gates on `/\.tf$/i`; `classifyExposure`,
  `:47`, matches only `aws_*` resource kinds) — and the module's own
  header discloses that CloudFormation and Kubernetes support were
  documented but never implemented.

**Ruling on Correction 4:** the row's "two already-shipped, already-tested
parsers" is one-and-a-half. The `services.yml` half is real; the IaC half
needs a source change, and even then produces the wrong shape of fact for
the layer it is supposed to populate.

### Correction 5: the row names the wrong shared vocabulary — the real one is bigger, graph-level, and two of FR-505's four layers already exist

The row's ordering note recommends landing near #3 to share
"`OBLIGATION_FACT_TYPES` (`runtime_observed` is FR-505's own fact type,
already real/cross-cutting)".

`runtime_observed` **is** in `OBLIGATION_FACT_TYPES`
(`scanner/src/lineage/obligation-mapping.js:31-34`) — that half of the
row's claim is verified. But grepping the whole tree for it returns
exactly two hits, both declarations or comments:
`obligation-mapping.js:32` and a prose mention in
`recipient-profile.js:49`. **Zero producers, zero consumers.** And
structurally it is the wrong vocabulary to reach for:
`OBLIGATION_FACT_TYPES` types a fact on an `ObligationMapping`
record — a per-compliance-requirement extension artifact built on demand,
never stored on the graph. FR-505's layers are a property of graph edges.

The vocabulary FR-505 actually needs is already in `schema.js`, already
validated, already in the JSON Schema, and the row does not mention any
of it:

| Reserved value | Where | FR-505 layer it serves |
|---|---|---|
| `EDGE_PROVENANCE_VALUES = ['code', 'schema', 'manual', 'runtime']` | `schema.js:75` | **all four** — this IS the layer field |
| `DESTINATION_RESOLUTION_VALUES` reserves `'declared_service'`, `'runtime_corroborated'` | `schema.js:61-64` | CONFIG DECLARED / RUNTIME OBSERVED |
| `EVIDENCE_TYPES` reserves `'iac'`, `'service_declaration'`, `'runtime'` | `schema.js:105` | CONFIG DECLARED / RUNTIME OBSERVED |
| `EVIDENCE_GRADES` reserves `'runtime'` | `protection.js:14` | RUNTIME OBSERVED |
| `IMPACT_SCOPE_VALUES` reserves `'observed'` | `impact-assessment.js:24` | RUNTIME OBSERVED (downstream) |

`schema.js:71-74`'s own comment says it out loud: *"Only `'code'` has a
real producer today (graph-builder.js sets it unconditionally);
`'schema'`/`'manual'`/`'runtime'` are reserved for Sub-project F2/F3, not
yet implemented."*

**And two of FR-505's four layers already exist as shipped code:**

- **CODE POSSIBLE** — `graph-builder.js:687` sets `provenance: 'code'`
  unconditionally on every edge. Shipped (M2 F1), validated
  (`validate.js:172`), schema-parity-tested.
- **HYPOTHETICAL** — the What-If Simulator (M5 #3a, COMPLETE) is exactly
  this layer: `scenario.js`/`scenario-engine.js`/`scenario-diff.js`
  produce a clone-and-override graph whose every overridden field carries
  `evidenceGrade: 'assumed'`, with a shipped test
  (`scenario-no-obligation-wiring.test.js`) pinning that a scenario graph
  can never feed an obligation evaluation as if it were real.

So FR-505 is not four unbuilt layers. It is **two shipped, one already
scoped elsewhere (7a = F2/F3), and one genuinely new (7b).** That is a
materially different — and smaller — picture than the row paints, and it
is what makes the 7b-only ruling in §4 defensible rather than a dodge.

### Correction 6: both storage candidates the row names are wrong, including the one it endorses

The row rules: *"`GraphSnapshot`'s commit-keyed, one-record-per-commit
shape is a confirmed FALSE precedent here…; `posture/provenance/lifecycle.js`'s
many-records-per-key shape is the closer structural fit."*

The first half is right for the reason given. The second half is wrong,
and so is the obvious third candidate (`remediation-ledger.js`, which the
row predates), for a reason **the row never raises at all**: FR-505's
last requirement bullet is *"Observation stores follow artifact
encryption, retention, reset, access-control, and no-egress rules."*

- **`lifecycle.js` — rejected.** It is one JSON document at
  `.agentic-security/provenance/lifecycle.json` shaped
  `{stableId: [event, ...]}`, **rewritten whole on every update**
  (`lifecycle.js:195`, a plain `fs.writeFileSync` of the entire store) under
  a lockfile. "Many records per key" describes its logical shape, but its
  physical shape is a whole-file rewrite — and it is registered in
  `artifact-registry.js:168` with a **deliberate NO `retentionClass`**
  ("this is permanent history, not a cache; auto-expiring it would
  silently lose lifecycle events a report may already have cited").
  That is the exact opposite of what FR-505 requires of an observation
  store.
- **`remediation-ledger.js` — rejected**, despite being this session's
  freshest and most battle-tested precedent. Its own header (`:38-49`)
  explains why it locks: writing an event is a *read-fold-validate-write*
  critical section, because `validateTransition` must run against the
  item's current folded state. A `RuntimeObservation` has **no state
  machine to validate against** — it is imported bulk external evidence,
  not a human decision. Worse, its hash chain (`:57-71`, "each event
  carries `prev`, the SHA-256 hex digest of the PREVIOUS line's exact
  serialized JSON text") makes deletion structurally impossible: you
  cannot expire an old observation without breaking every subsequent
  line's `prev`. Its registry entry (`artifact-registry.js:220`) is
  correspondingly `classification: 'operator-config'` with **no
  retentionClass**, for the same stated reason. An append-only
  hash-chained ledger and a retention-and-reset requirement are directly
  opposed.

**The right precedent is the one the row dismissed for the wrong
attribute.** `graph-snapshot.js`'s `lineage-snapshots/` is a
**directory of independently-readable, immutable whole files**
(`persistGraphSnapshot`, `:118`; `loadSnapshots`, `:130`;
`loadSnapshot(scanRoot, commitKey)`, `:150`). The row correctly rejects
its *commit-keying* — "one record per commit" cannot express many
observations per graph entity. But its *physical* shape is exactly right:
one file per unit, no lock, no chain, per-file deletion that retention
can actually enforce, and a registry entry that already carries
`retentionClass: 'scan'` (`artifact-registry.js:104`) — proof that this
shape and a real retention class coexist. Re-key it from commit to
**import**, and many-observations-per-entity falls out as many files ×
many records inside each. See §4.4.

### Correction 7: `posture/runtime-correlation.js`'s technique is reusable as claimed — with one addition and one trap

The row: *"its offline-JSONL-file pattern and qid-then-file+line matching
TECHNIQUE are directly reusable, but its schema (code-execution-shaped)
and storage model (none — ad hoc JSONL) are not."* Verified, with real
signatures:

- `loadTrace(scanRoot, opts)` (`:42`) reads
  `.agentic-security/runtime-trace.jsonl` (or `runtime.jsonl`/
  `ebpf-trace.jsonl`, or `$AGENTIC_SECURITY_RUNTIME_TRACE_PATH`),
  streams it line-by-line, drops records older than a
  **30-day default observation window** (`:59-70`), and returns
  `{path, qidsObserved:Set, routesObserved:Set, filesObserved:Set, fileLinesObserved:Map, syscallsObserved:Set, recordCount}`.
- `findingObservedInRuntime(finding, trace)` (`:104`) returns
  `true|false|'unknown'` — qid match first, then file+any-chain-line with
  a ±2-line tolerance, then route match.
- `annotateRuntimeCorrelation(scanRoot, findings, opts)` (`:148`)
  annotates and demotes.

**Three things the row gets right and one it understates.** Right: the
schema is code-execution-shaped (`kind: 'function-call'|'route-hit'|'syscall'|'file-touch'`,
keyed on `qid`/`fileRel`/`line`) and is unusable for a
destination/network-shaped observation; there is no storage model. Right:
the offline-file pattern is the proven one. Right: the window concept
already exists.

**Understated: this module is not a standalone pattern — it is fully
wired into every scan today** (`engine.js:235` imports it, `engine.js:9665`
calls it inside `_runAnnotator`). So a second module named
`runtime-correlation.js` under `lineage/` would be the third
`annotate*Provenance`-style naming collision this codebase has had. Name
7b's correlation module distinctly (§4.2).

**And one genuine trap, directly relevant to §5.**
`.agentic-security/runtime-trace.jsonl` is **not registered in
`artifact-registry.js` at all** (grep for `runtime` in that file returns
zero artifact rows). It escapes the completeness guard because
`runtime-correlation.js:44` calls `statePath(scanRoot, n)` with a
**variable**, and `artifact-registry-completeness.test.js`'s own
`PATTERNS` regexes require a **string literal** as the second argument.
An unregistered state artifact means `reset` does not know about it and
retention cannot reach it. FR-505 requires both. 7b must not inherit this
(§5).

---

## 3. What already exists that this deliverable builds on

Every line below was confirmed by direct read this session, not inherited
from a summary.

### Contract precedent — four shipped §10.10 extension contracts to mirror

`scenario.js`, `impact-assessment.js`, `recipient-profile.js`,
`obligation-mapping.js`, `graph-snapshot.js` all share one shape:
a pure, zero-import (or near-zero) module exporting frozen enums plus a
`validateX(record) -> {valid, errors}` structural validator that **never
throws** and **never touches a graph**. `impact-assessment.js` (76 lines)
is the smallest and the closest analogue in age and intent.

**One deliberate departure 7b must make from all four:** each of these
validators is *open-world* — it checks that required fields are present
and well-typed, and silently ignores unknown keys. PRD line 983 forbids
that here: "Runtime records use approved metadata schemas and **reject**
fields capable of carrying payload values." `validateRuntimeObservation`
must be **closed-world** (reject-unknown-key), and that inversion is the
single most load-bearing design decision in the whole sub-project (§4.1).

### `graph-builder.js`'s additive-hook pattern — five live precedents

`opts.resolveSiteDecision` (`:547`), `opts.resolveDestination` (`:566`),
`opts.resolveTransitProtection` (`:699`), `opts.resolveGovernanceRefs`
(`:893`), `opts.buildRecipientProfile` (`:970`). Each is optional, each
composes rather than replaces, each is byte-identical-when-omitted with a
shipped test proving it. This is the established wiring shape and 7b
should use it unchanged.

### `coverage.js` / `index.js`'s single-computation loading discipline

`buildGraphWithCoverage` wires a default hook closing over a
**pre-loaded** object (`opts.privacySinkPolicy`, `opts.recipientConfig`,
`opts.transitEvidenceByFile`) — never a raw file path, never a second
read. `index.js` performs the one read per `buildLineageGraph` call, and
`transit-protection.js`'s own single-scan discipline is proven live by a
`Proxy`-based call-count test. 7b's observation-store load follows this
exactly.

### `edge.provenance` — shipped, validated, and with **zero consumers**

Producer: `graph-builder.js:687` (`provenance: 'code'`, unconditional).
Validator: `validate.js:172`. Schema: in `dataflow-graph.schema.json`'s
edge `$def`, required, parity-tested. **Consumers: none.** A tree-wide
grep finds no read of `edge.provenance` anywhere in
`scanner/src/lineage/`, `frontend/src/`, or `scanner/src/server/` — the
only non-declaration hit is a comment in `export-json.js:26` listing it
among non-redacted fields.

This is a **risk finding, not a convenience one**, and it is why §4.5
rules the way it does. Every downstream consumer built since M2 F1 —
`impact-engine.js`, `decision-story.js`, `obligation-predicates.js`,
`export-csv.js`, `export-privacy.js`, `bench/protection-verdict/runner.mjs` —
was written against a graph where `edge.provenance === 'code'` is
invariantly true. None partitions on it. The moment a non-`'code'` edge
can appear, every one of them can silently treat a *declared* or
*observed* edge as a scanned one — feeding a declared topology into an
obligation-evidence pack, or an impact assessment, exactly the
"hypothetical must never become evidence" failure mode
`scenario-no-obligation-wiring.test.js` and
`impact-no-obligation-wiring.test.js` were both written to prevent.

### The frontend has **zero** layer machinery

`frontend/src/lib/` is `api-client`, `contrast`, `dom`, `escape-html`,
`flow-path`, `focus-controls`, `protection-visual`, `query-language`,
`row-filters`, `state`. `query-language.js`'s `FIELD_ACCESSORS` (`:168-198`)
exposes exactly eleven filterable fields — `class`, `field`, `sink`,
`source`, `transit.verdict`, `at_rest.verdict`, `handling.verdict`,
`policy`, `coverage`, `ai`, `destination.external` — and its own header
comment states each "accessor here reads a field CONFIRMED populated by
real scan code." No `provenance`, no `layer`, no `environment`, no
`window`. `state.js`'s `filters` is an opaque caller-defined object with
no layer concept. No view reads `edge.provenance`.

### AC-31 and the runtime-verification question — #6's ruling re-verified, and it holds

Item 9 of this investigation's brief asks whether AC-29 or FR-505 imply
runtime observation should be a valid verification input for a
`RemediationItem`, reopening a question #6's scoping already settled.
Re-read verbatim, three times over:

- **AC-31's own text has exactly one `or`**: "until compatible rescan
  evidence **or** an explicitly permitted manual attestation satisfies the
  requirement." Runtime is not in it. #6's Correction 2 is correct.
- **FR-505 never mentions remediation, verification, or work items** —
  its verbatim text is quoted in full in §1 above; the words do not
  appear.
- **The shipped implementation is a closed enum.**
  `remediation.js:65`'s `REMEDIATION_EVENT_TYPES` is
  `['opened', 'state_changed', 'scan_verification', 'manual_attestation', 'accepted_risk', 'reopened']`
  — exactly two paths to `verified`, and `validateTransition:269` rejects
  `state_changed → verified` first and unconditionally.

FR-507's *body* bullet does say "a subsequent compatible **scan/runtime
observation**", so a future `runtime_verification` event type is
legitimate FR-507 scope — but it is not AC-31 scope, and adding it means
widening a closed enum, adding a transition rule, and doing so against a
**hash-chained ledger whose existing history must stay valid**.

**Ruling: explicitly and permanently out of scope for this deliverable
(§7).** 7b must not touch `remediation.js`, `remediation-ledger.js`, or
any remediation CLI verb. A shipped source-text import guard, mirroring
`scenario-no-obligation-wiring.test.js`'s exact pattern, should pin this.

**The one thing 7b legitimately *does* unblock**, and must not
accidentally half-close: AC-31's own `given` says "affects possible **and
runtime-observed** sensitive flows" and its `then` requires
"possible/observed **partitions**." The shipped `ImpactAssessment` is
honestly `scope: 'possible'`-only with `IMPACT_SCOPE_VALUES` already
reserving `'observed'` (`impact-assessment.js:20-24`) precisely for this
deliverable. That is a real follow-on — and it is a **follow-on, in its
own increment, with its own review**, not something to fold into 7b's
first cut. #4 and #6 are already honest about the gap; a half-built
partition is worse than a disclosed one.

---

## 4. Design ruling

### 4.0 The headline ruling: build 7b. Do not build 7a in this deliverable.

**7a (CONFIG DECLARED) is descoped from deliverable #7 and returned to
M2 Sub-project F2/F3**, where it was already scoped, already sized as two
Large sub-projects, and already deferred pending its own scoping pass.
Four independent reasons, any one of which would be sufficient:

1. **It satisfies no acceptance criterion** (Correction 2). AC-29's given
   is entirely about runtime observations; the M5 exit gate names AC-29
   and not FR-505's body.
2. **It is already-scoped work under a different name** (Correction 3),
   and the existing scoping — grounded in a direct read of
   `graph-builder.js` — sizes it at 2 × Large against the M5 row's
   Medium.
3. **Half its claimed input does not exist in the form claimed**
   (Correction 4). The IaC parser exports findings, not facts; its header
   is wrong about that; and an exposure fact is a resource property, not
   a declared flow.
4. **It is the single highest-risk change available to `graph-builder.js`**
   (§3, `edge.provenance` has zero consumers). Minting non-code-derived
   edges before any downstream consumer partitions on provenance is how a
   *declared* topology quietly becomes evidence in an obligation pack or
   an impact assessment.

This is a scope *reduction* ruling, not a deferral of difficulty: the
work is real and the PRD calls for it, but it belongs to FR-304's already
open sub-project, sequenced after (not before) a provenance-partitioning
pass through every downstream consumer. Whoever picks up F2/F3 should
read this document's Correction 4 and §3 first.

### 4.1 `lineage/runtime-observation.js` — the pure contract, with a **closed-world** validator

Mirrors `impact-assessment.js`'s shape exactly: zero imports, frozen
enums, `validateRuntimeObservation(record) -> {valid, errors}`, never
throws, no graph access. Fields per PRD line 971:
`{id, version, adapter, source, environment, windowStart, windowEnd, matchedNodeIds, matchedEdgeIds, matchedFlowIds, attributes, eventCountBand, firstObservedAt, lastObservedAt, matchMethod, matchConfidence, retention, importedAt}`.
`id` prefixed `observation:` (mirroring `impact:`/`obligation:`).

**The one deliberate inversion from every sibling contract**, and the
thing to get right or the AC is not met: `attributes` is validated
against a **frozen allowlist of approved metadata keys**
(`RUNTIME_ATTRIBUTE_KEYS` — service/workload identity, endpoint or
destination identity, protocol/TLS metadata, telemetry-approved
schema/attribute *names*), and **any key outside it is a validation
error, not a silently-ignored extra**. PRD line 983 says *reject*; AC-29
clause 5 says *no captured payload… exists in the observation artifact*.
A scrub-known-bad denylist cannot satisfy either — it fails open on every
attribute name nobody thought of. Values are additionally length-capped
and type-restricted to string/number/boolean; no nested objects, no
arrays of objects, since those are how a payload arrives disguised as an
attribute.

`eventCountBand` is a **band**, not a count (`'1'|'2-10'|'11-100'|'101-1k'|'1k+'`
or similar) — PRD line 971 says "count/frequency band", and an exact
count is itself a weak information channel.

Two frozen enums to define: `RUNTIME_MATCH_METHODS` (how a canonical id
was matched) and `RUNTIME_MATCH_CONFIDENCE` (per FR-505: "Correlation
records the matching method and confidence"). FR-505's *"ambiguous
observations remain candidates and do not silently merge data elements"*
means the contract needs an explicit candidate state — an observation
matching more than one canonical id keeps **all** of them in
`matchedNodeIds` with a confidence that says so, and never picks one.

### 4.2 `lineage/observation-correlation.js` — graph-ID-aware correlation

**Named `observation-correlation.js`, not `runtime-correlation.js`** —
`posture/runtime-correlation.js` already exists, is live-wired into every
scan (`engine.js:9665`), and this codebase has already been bitten three
times by same-named-different-thing annotators (see the root
`CLAUDE.md`'s `annotateGitProvenance` naming rule).

One pure function:
`correlateObservations(graph, observations, {environment, windowStart, windowEnd})`
→ `{observedEdgeIds, observedFlowIds, notObservedFlowIds, byFlow: Map<flowId, {observationIds, method, confidence}>}`.

Three properties, each mapping to an AC-29 `then` clause:

- **Clause 3 — non-exclusion is structural, not a policy.** This function
  returns *annotations keyed by id*; it never filters, removes, or
  reorders any graph entity. A flow with no observation is reported in
  `notObservedFlowIds`, and the graph it was computed from is
  untouched. AC-29's "both static paths remain visible" is then true by
  construction, not by discipline — the same argument
  `path-store.js`'s cycle-safety and `falsification.js`'s
  recall-preservation both rest on.
- **Clause 2 — `not_observed_in_window` is a first-class value, never a
  falsy absence.** PRD line 2098: "never treats non-observation as
  non-occurrence." The vocabulary must be three-valued
  (`observed` / `not_observed_in_window` / `not_evaluated`), matching
  this package's own `null`-is-not-`false` precedent from
  `posture/relevance.js` and `posture/runtime-correlation.js`'s own
  `'unknown'` tier. `not_evaluated` (no observation store present at all)
  and `not_observed_in_window` (a store was consulted and the window
  genuinely contained nothing) are **different answers** and must be
  distinguishable in JSON — the same distinction `policy-verdict`'s
  `not_evaluated` already draws for a missing `privacy-policy.json`.
- **Clause 4 — method and confidence travel with the match**, per
  observation, never aggregated away.

The reusable *technique* from `posture/runtime-correlation.js` is the
match ladder (most-specific identifier first, then a weaker
locality match, then honest `unknown`) and the window filter. The
identifiers differ entirely: destination host/endpoint/service identity
against `node.destination.literalValue` / `node.storeDetail` /
`node.queueDetail` / `node.subtype`, never qid/file/line.

### 4.3 Adapters: ship the *interface* plus a native adapter first; OTLP second

FR-505: *"Adapters are explicit and optional, **beginning with** approved
OpenTelemetry traces/service graphs, gateway/mesh metadata, cloud flow
metadata, and application-provided schema-safe events."*

**Confirmed: zero OpenTelemetry support exists anywhere.** A tree-wide
case-insensitive grep for `opentelemetry|otlp|resourceSpans|traceparent`
across `scanner/src`, `scanner/bin`, `frontend/src`, `scripts`, and
`commands` returns hits in exactly two files — `scripts/eu-ai-act/evidence-rules.json`
and `scripts/nist-compliance/evidence-rules.json` — where
`"opentelemetry"` appears only as a **dependency name string** in a
compliance evidence rule's `libraries`/`imports` list. No parser, no
schema, no fixture. The row's "zero existing support" is correct.

**Ruling: the first cut ships the adapter interface plus a native
`RuntimeObservation` JSONL adapter — the operator's own telemetry
export, already shaped to the allowlist — and OTLP is increment 2.**
Reasoning:

- AC-29's `given` requires only "correlated runtime metadata." It does
  not name a format. **The gating criterion is closable without OTLP**,
  and making the exit gate depend on an unbuilt third-party format parser
  is exactly the kind of avoidable coupling this session's scoping passes
  keep catching.
- An OTLP `resourceSpans` document carries an unbounded attribute
  surface — `http.url` with a query string, `db.statement`,
  `messaging.message.payload`, arbitrary `gen_ai.*` prompt/completion
  attributes. Mapping it safely is not "parse JSON"; it is **writing and
  defending the attribute allowlist against a real, adversarial,
  evolving semantic-convention surface**, and getting it wrong is
  precisely AC-29 clause 5's failure. That deserves its own increment and
  its own review, not to be bundled into the increment that also invents
  the contract, the correlation, and the store.
- The native adapter proves the interface with a fixture the repo
  controls, so increment 2's OTLP adapter is a *second* implementation of
  an already-proven interface rather than the only one.

Both adapters follow `posture/runtime-correlation.js`'s proven contract:
**external evidence arrives as a file, never as live ingestion.** No
network call, no collector, no daemon — consistent with the root
`CLAUDE.md`'s "no runtime cloud calls" convention and FR-505's own
no-egress rule.

### 4.4 Storage: a directory of import-keyed whole files. No lock, no hash chain.

`.agentic-security/runtime-observations/<importId>.json` — one file per
adapter import, each containing that import's `{adapter, source,
environment, windowStart, windowEnd, importedAt, observations: [...]}`.
Readers: `loadObservationImports(scanRoot)` / `loadObservationImport(scanRoot, importId)`,
mirroring `graph-snapshot.js:130`/`:150` exactly.

Why this and not the three candidates already considered (Correction 6
has the full reasoning; the summary):

| Candidate | Verdict |
|---|---|
| `GraphSnapshot` commit-keying | Rejected — one record per commit cannot express many observations per entity. **The row is right.** |
| `lifecycle.js` many-records-per-key | Rejected — whole-file rewrite on every update, and registered with a *deliberate* no-retention policy. **The row is wrong.** |
| `remediation-ledger.js` locked hash chain | Rejected — solves a read-fold-validate-write problem that does not exist here, and its chain makes retention structurally impossible. |
| **`lineage-snapshots/`'s directory-of-immutable-files, re-keyed to import** | **Chosen** — no lock (imports are independent files), no chain (no state machine to protect), per-file deletion that retention can enforce, and an existing registry entry proving the shape and a real `retentionClass` coexist. |

Many-observations-per-graph-entity is then a **query property**, not a
storage property: `correlateObservations` reads every import and builds
its `byFlow` map in memory, exactly as `loadSnapshots` + `computeGraphDiff`
already do for snapshots.

### 4.5 Wiring: additive `opts` hook, and `edge.provenance` stays `'code'` in the first cut

`buildDataFlowGraph` gains `opts.correlateObservations(graph) -> correlationResult | undefined`,
applied after nodes/edges/flows are populated — the same placement and
the same byte-identical-when-omitted contract as
`opts.buildRecipientProfile` (`graph-builder.js:970`, which was moved to
exactly this point during its own fix round so the graph it reads is real).
Result lands on `graph.runtimeCorroboration` — a §10.10 extension array
attached to the graph object, the precedent `graph.recipientProfiles[]`
set. Not in `dataflow-graph.schema.json`, not routed through
`validateGraph()`.

**Ruling: the first cut does NOT set `edge.provenance = 'runtime'`.**
This is deliberate and it is the §3 risk finding applied. `edge.provenance`
has zero consumers today, and every downstream module was written against
an invariant that every edge is code-derived. FR-505's layers are
*additive corroboration*, not a reclassification: an observed edge is
still a code-derived edge that was *also* observed. Recording
corroboration as a separate, additive annotation keyed by edge id
preserves that, satisfies all five AC-29 clauses, and cannot silently
change what any existing consumer sees. Flipping `edge.provenance` should
happen only alongside a deliberate provenance-partitioning pass through
`impact-engine.js`, `decision-story.js`, `obligation-predicates.js`, and
the export family — which is F2/F3's job (§4.0), not this one's.

### 4.6 CLI surface

Mirroring `dataflow impact assess` / `dataflow scenario apply`'s
established shape and their exit-code contract (`0` success, `1`
graph-load failure via `loadSignedGraph`'s own four messages, `2` a CLI
argument problem):

- `agentic-security dataflow observations import [path] --adapter <name> --input <file> [--environment <name>] [--window-start <iso>] [--window-end <iso>] [--yes]`
  — validates every record through the closed-world validator **before**
  writing, refuses the whole import on any rejected field (never a
  partial import that silently drops the offending record), writes one
  import file.
- `agentic-security dataflow observations list [path]` — imports,
  windows, counts. No attribute values.
- `agentic-security dataflow twin [path] --output <file> [--format json|markdown] [--environment <name>] [--window <iso>/<iso>]`
  — **this is the AC-29 proof surface**: per flow, its layer
  (`code_possible` always; `runtime_observed` or `not_observed_in_window`
  or `not_evaluated`), plus match method, confidence, environment and
  window for every observed one. Every static flow appears in the output
  regardless of layer (clause 3).

### 4.7 On AC-29's word "displayed" — the honest reading, stated up front

AC-29's `when` is *"when Runtime Digital Twin layers are displayed."* The
frontend has no layer machinery at all (§3), and PRD Appendix D.6 lists a
required reference screen, `runtime-digital-twin.dark.1680x945.png`, with
layer toggles, an environment/window selector, distinct edge treatments,
and an observation inspector.

**Ruling: a CLI/JSON cut genuinely satisfies AC-29's substance, and the
UI gap must be disclosed rather than argued away.** Four of AC-29's five
`then` clauses are properties of the *record and the artifact*, not of a
rendering — `RUNTIME OBSERVED` as a label, `not_observed_in_window` as a
value, both static paths still present in the graph, method/confidence/
environment/window carried on the record, and no payload in the
observation artifact. The one genuinely visual requirement — "distinct
edge treatment for possible, declared, observed, and simulated flows" —
is in **FR-505's body, not AC-29**.

The precedent is unbroken and worth stating plainly: **every
decision-intelligence deliverable shipped this session — Executive Risk
Story (FR-501), Time Machine (FR-503), Obligation Overlay (FR-504),
Recipients (FR-506), What-If (FR-502), Impact and Remediation (FR-507) —
shipped CLI-only and left its D.6 reference screen unbuilt.** D.6 is a
design-handoff artifact list, not an acceptance criterion. Following that
precedent here is consistent, not a special exemption.

What this deliverable must therefore do, and what #6's experience says
will otherwise be missed: **write down, in the shipped module headers and
in `scanner/src/lineage/CLAUDE.md`, that AC-29's clauses are satisfied at
the data/artifact layer and that no UI displays them yet** — so a future
UI increment inherits five properties it must not break, rather than
rediscovering them.

---

## 5. Artifact registry classification — decided now, not later

Deliverable #6's final review found a real gap from not deciding this up
front; #6's *scoping* got it right by ruling early. Same here. Three
entries, each with its reasoning:

| Artifact | Classification | retentionClass | confidential | Why |
|---|---|---|---|---|
| `runtime-observations` (dir) | `generated` | `evidence` | `true` | FR-505's own text requires **reset** and **retention** and **encryption**. `'operator-config'` would make `reset` preserve it, contradicting FR-505 directly. This stretches `'generated'`'s stated definition ("the next scan regenerates it" — a rescan does *not* re-derive an import), and that stretch should be disclosed in the entry's own `note`, the way `remediation`'s and `provenance`'s notes already disclose their own judgment calls. FR-505's explicit reset requirement is what breaks the tie. |
| the adapter **input** file the operator drops in | `operator-config` | none | — | Genuinely hand-supplied, not scanner-written; the same call `recipient-profiles.json` (`artifact-registry.js:225`) and `network-policy.json` already make. |
| `runtime-trace.jsonl` (**pre-existing, currently unregistered**) | `operator-config` | none | — | Correction 7. A real gap in already-shipped code, found by this investigation, not created by it. Fixing it is a two-line registry addition and is worth doing in this sub-project since nobody else is looking at that file. |

**And one mechanical requirement that follows from Correction 7:** 7b's
store must be reached via `statePath(scanRoot, 'runtime-observations')`
with a **string literal**. `artifact-registry-completeness.test.js`'s
`PATTERNS` regexes only match a literal second argument, so a module
constant (`statePath(scanRoot, OBSERVATIONS_DIR)`) silently escapes the
guard — which is exactly how `runtime-trace.jsonl` went unregistered and
unnoticed. Note that `graph-snapshot.js:36` has the same
variable-argument shape and is registered only because someone
remembered; the guard did not enforce it. Widening the guard's regex to
also resolve a module-level `const NAME = 'literal'` is a real, small,
separately-valuable follow-up this document names but does not scope.

---

## 6. Size

**7a: descoped (§4.0).** Returned to M2 Sub-project F2/F3, which already
sized it as 2 × Large pending its own scoping pass. It is neither
Medium nor this deliverable's work.

**7b: the M5 row's "Large" is right for FR-505's full body; the
AC-29-closing cut is Medium.** Every piece has a live precedent:

| Increment | Size | Precedent it mirrors |
|---|---|---|
| `runtime-observation.js` — contract + closed-world validator | Small | `impact-assessment.js` (76 lines) — but the closed-world inversion is genuinely new and is the highest-risk small thing here |
| `observation-correlation.js` — graph-ID-aware correlation + the three-valued layer vocabulary | **Medium** | `posture/runtime-correlation.js`'s match ladder + window filter; genuinely new identifiers |
| Native JSONL adapter + `runtime-observations/` store + registry | Small | `graph-snapshot.js`'s directory-of-files, `loadRecipientConfig`'s never-throws loader |
| `opts.correlateObservations` hook + `index.js` single-load wiring | Small | five live hook precedents in `graph-builder.js` |
| CLI: `observations import`/`list`, `twin` | Small | `dataflow impact assess`, `dataflow scenario apply` |
| **Everything above = the AC-29-closing cut** | **Medium** | |
| OTLP adapter + its attribute allowlist (increment 2) | **Medium–Large** | nothing — zero existing support, adversarial attribute surface |
| UI layers, toggles, environment/window selector, D.6 golden | **Large** | nothing — zero layer machinery in `frontend/` |
| Gateway/mesh + cloud-flow adapters | Large | nothing |

So the row's "Large" is a fair description of FR-505 in full, and a
misleading one for what the exit gate actually requires. **The Medium cut
closes AC-29; the Large remainder is disclosed FR-505 body work.**

---

## 7. Out of scope (disclosed, not built)

- **7a / CONFIG DECLARED entirely** (§4.0) — descoped to M2 F2/F3, with
  Corrections 3 and 4 as the handoff notes.
- **Setting `edge.provenance = 'runtime'`** (§4.5) — deferred until a
  deliberate provenance-partitioning pass exists through every downstream
  consumer. Corroboration is recorded additively instead.
- **Any change to `remediation.js` / `remediation-ledger.js` / the
  `remediation` CLI verbs** (§3). AC-31's own `or` is
  rescan-vs-manual-attestation; `REMEDIATION_EVENT_TYPES` is a closed
  six-value enum with exactly two paths to `verified`. A
  `runtime_verification` event type is legitimate FR-507 *body* scope for
  some future increment and is not this deliverable's. A shipped
  source-text import guard should pin the separation, mirroring
  `scenario-no-obligation-wiring.test.js`.
- **`ImpactAssessment.scope = 'observed'` / possible-observed
  partitioning** (§3). Real, unblocked-by-7b, and deliberately a separate
  increment with its own review — `IMPACT_SCOPE_VALUES` already reserves
  the value and #4 is already honest about the gap. A half-built
  partition is worse than a disclosed one.
- **The OpenTelemetry adapter** (§4.3) — increment 2, with its own
  attribute allowlist and its own review.
- **Gateway/mesh metadata, cloud flow metadata adapters** — FR-505 names
  them; nothing exists; not attempted.
- **Any UI: layer toggles, distinct edge treatment, environment/window
  selector, observation inspector, and the D.6
  `runtime-digital-twin.dark.1680x945.png` golden** (§4.7). Consistent
  with every decision-intelligence deliverable shipped this session.
- **Live ingestion of any kind** — no collector, no daemon, no network
  call. FR-505's no-egress rule and the root `CLAUDE.md`'s "no runtime
  cloud calls" convention both forbid it; the file-based contract is the
  proven pattern.
- **Field-level identity from runtime evidence.** FR-505 is explicit:
  "Runtime observation may increase corroboration confidence but cannot
  prove field-level identity unless safe schema/trace evidence maps that
  field." No such schema/trace mapping exists; observations correlate to
  node/edge/flow ids only, never to a `dataElement`'s field identity.
- **Encryption-at-rest implementation** — the registry entry declares
  `confidential: true` and `posture/encryption-provider.js` enforces that
  class; no new mechanism is introduced here.
- **Any language beyond JS/TS** — unchanged package-wide boundary.

---

## 8. Recommended next step

Write 7b's implementation plan against §4, in the increment order of §6,
with the closed-world validator (§4.1) as Task 1 — it is the smallest
module and the one AC-29 clause 5 rests on entirely, so it should be
written, reviewed, and mutation-tested before anything depends on it.

Do **not** write a 7a plan. If FR-304's declared/schema-derived edges are
wanted, the next document is M2 Sub-project F2's or F3's own scoping
pass, and it should open by reading Correction 3, Correction 4, and §3's
`edge.provenance`-has-zero-consumers finding.
