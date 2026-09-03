# Runtime-Corroborated Digital Twin (M5 deliverable #7, 7b only) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the **RUNTIME OBSERVED** half of FR-505 — a metadata-only,
closed-world `RuntimeObservation` contract, a graph-ID-aware correlation pass,
an import-keyed observation store, one native JSONL adapter, an additive
`graph-builder.js` hook, and a CLI/JSON proof surface — such that every clause
of **AC-29**'s own `then` is genuinely satisfied at the data/artifact layer,
without collecting a single payload value.

**7a (CONFIG DECLARED) is NOT built here.** The scoping doc's §4.0 descopes it
back to M2 Sub-project F2/F3, where it was already scoped as 2 × Large. No task
in this plan mints a non-code-derived node or edge; no task sets
`edge.provenance` to anything other than the `'code'` `graph-builder.js`
already writes.

Like deliverable #6 (Remediation Command Center) and unlike #5 (Governance
Editing), this deliverable **is** named in the Milestone 5 exit gate (PRD line
1854: "AC-26, AC-29, and AC-31 …"). Surface area narrows (CLI-only, one
adapter, no UI); AC-29's five `then` clauses do not narrow with it.

**Architecture:** A four-layer split, each layer with a single responsibility
and a proven precedent in this package:

- `scanner/src/lineage/runtime-observation.js` — **pure, zero imports.** The
  §10.10 contract vocabulary plus `validateRuntimeObservation`, the ONE
  **closed-world** validator in the whole codebase: unknown top-level keys and
  unknown attribute keys are validation ERRORS, never silently-ignored extras.
  This module is what AC-29 clause 5 rests on entirely.
- `scanner/src/lineage/observation-adapters.js` — **pure, zero imports.** The
  adapter registry plus `parseNativeJsonlObservations(text, context)` — text
  in, drafts out, no `fs`. Mirrors `transit-protection.js`'s own
  `scanTransitEvidence(fileContents)` "text, never paths" precedent.
- `scanner/src/lineage/observation-correlation.js` — **pure**, imports only
  `./runtime-observation.js`. `matchObservationToGraph` (the import-time match
  ladder) and `correlateObservations` (the read-time environment/window filter
  and the three-valued per-flow layer). Never mutates a graph, never filters a
  graph entity — AC-29 clause 3 is true by construction.
- `scanner/src/lineage/observation-store.js` — **impure.** A directory of
  independently-readable, immutable, import-keyed whole files under
  `.agentic-security/runtime-observations/`, mirroring `graph-snapshot.js`'s
  `lineage-snapshots/` physical shape exactly. No lock, no hash chain,
  per-file deletion that retention can actually enforce.

Wiring is the established additive-hook shape: `buildDataFlowGraph` gains
`opts.correlateObservations(graph)`, `buildGraphWithCoverage` composes a
default over a **pre-loaded** `opts.runtimeObservations` array, and `index.js`
performs the one read per `buildLineageGraph` call.

Reuses, unmodified: `statePath`/`isSafeStateDir`/`stateWritesEnabled`
(`posture/state-dir.js`), `maybeEncryptForWrite`/`maybeDecryptForRead`
(`posture/encryption-provider.js`), `auditCall` (`mcp/audit.js`),
`loadSignedGraph` (`server/graph-loader.js`), `isRegisteredArtifact`
(`posture/artifact-registry.js`).

**Tech Stack:** Node ESM, `node:test`, no new npm dependency.

**Spec:** `docs/superpowers/plans/2026-09-02-data-flow-explorer-m5-digital-twin-scoping.md`
— the authoritative design ruling for this deliverable. Read it in full before
starting Task 1, including its §4.0 headline ruling and its §7 out-of-scope
list.

---

## AC-29 clause map — every clause to a concrete task and test

AC-29 verbatim (PRD lines 1749-1753):

> **Given** one statically possible external flow has correlated runtime
> metadata and another has no observation in the selected window,
> **when** Runtime Digital Twin layers are displayed,
> **then** the first is `RUNTIME OBSERVED`, the second is
> `not_observed_in_window`, both static paths remain visible, match
> confidence/method and environment/window are shown, and no captured payload,
> prompt, response, record, log message, or sensitive value exists in the
> observation artifact.

| # | `then` clause | Implemented by | Pinned by |
|---|---|---|---|
| 1 | the first is `RUNTIME OBSERVED` | `correlateObservations` sets `byFlow[flowId].layer = 'runtime_observed'`; `dataflow twin` renders the literal label `RUNTIME OBSERVED` | `OC/6a`, `CLI/twin-2` |
| 2 | the second is `not_observed_in_window` | the three-valued `OBSERVATION_LAYERS` vocabulary, with `not_evaluated` a genuinely DIFFERENT third answer (a store was never consulted) | `OC/5a`, `OC/5b`, `OC/5c`, `CLI/twin-3` |
| 3 | both static paths remain visible | `correlateObservations` returns annotations keyed by id and never mutates, filters, removes or reorders any graph entity; `byFlow` covers EVERY flow in the graph exactly once | `OC/1a` (deep-frozen graph), `OC/1b` (total coverage), `WIRE/3` (graph byte-identical when the hook is omitted), `CLI/twin-1` |
| 4 | match confidence/method and environment/window are shown | every `byFlow` entry carries `matchMethod`, `matchConfidence`, `environment`, `windowStart`, `windowEnd`, `firstObservedAt`, `lastObservedAt`, `eventCountBand`; `twin`'s markdown prints all of them per observed flow | `OC/7a`, `CLI/twin-2` |
| 5 | no captured payload, prompt, response, record, log message, or sensitive value exists in the observation artifact | `validateRuntimeObservation`'s closed-world check (unknown TOP-LEVEL key ⇒ error; unknown ATTRIBUTE key ⇒ error; non-scalar attribute value ⇒ error); the adapter's closed wire-key set; `observations import` refuses the WHOLE import on any rejected record | `RO/4a`-`RO/4h`, `RO/5a`-`RO/5f`, `AD/4a`-`AD/4c`, `OS/8`, `CLI/import-4` |

The `when` clause ("when Runtime Digital Twin layers are **displayed**") is
addressed at the data/artifact layer only, per the scoping doc's §4.7 ruling
and the unbroken precedent of every decision-intelligence deliverable shipped
this session. That is a **disclosure obligation**, not a silence: Task 6 writes
it into `scanner/src/lineage/CLAUDE.md` and `commands/dataflow.md` so a future
UI increment inherits five properties it must not break.

---

## Corrections to the scoping doc and to this plan's own brief, verified against live code

Every item below was found by reading the real source in this worktree, not
inferred. Each is binding on the tasks that follow — where a task step
disagrees with the scoping doc's prose, **this section is the resolution**, and
the task step already reflects it.

1. **`confidential: true` is a DECLARATION, not an enforced control — the
   writer must call `maybeEncryptForWrite` itself.** The scoping doc's §7 says
   "the registry entry declares `confidential: true` and
   `posture/encryption-provider.js` enforces that class; no new mechanism is
   introduced here." Half right. The mechanism exists, but it is **per-caller
   opt-in**: a tree-wide grep for `maybeEncryptForWrite`/`maybeDecryptForRead`
   returns exactly three real call sites, all in
   `posture/compliance-policy.js:497`/`:546` and `bin/agentic-security.js:2763`
   — the only two `confidential: true` artifacts in the registry today
   (`compliance-evidence.json`/`.md`, `artifact-registry.js:129-130`). Nothing
   walks the registry and encrypts on its behalf. Also note the real exported
   names are `maybeEncryptForWrite(scanRoot, artifactName, content) ->
   {ok, content, encrypted} | {ok:false, reason}` and
   `maybeDecryptForRead(rawContent) -> string` — **not** `encryptIfConfidential`,
   which does not exist (only a prose mention in that module's own header
   comment). **Resolution:** Task 4's `persistObservationImport` calls
   `maybeEncryptForWrite(scanRoot, 'runtime-observations', json)` and refuses
   the write when it returns `{ok:false}`; the loaders call
   `maybeDecryptForRead` on every raw file read. Two calls, and the flag stops
   being a false claim.

2. **`byFlow` must be a plain object, never a `Map`.** The scoping doc's §4.2
   specifies `byFlow: Map<flowId, {...}>`. The correlation result lands on
   `graph.runtimeCorroboration` (§4.5), and the graph is **persisted to
   `.agentic-security/lineage-graph.json` and HMAC-signed**
   (`bin/agentic-security.js`, the `lineage-graph.json` + `.sig` write). A
   `Map` serializes to `{}`, silently destroying the entire result. Every
   collection on the correlation result is a plain object or a sorted array.

3. **The scoping doc's §4.2 return shape is incomplete for AC-29 clause 2.**
   `{observedEdgeIds, observedFlowIds, notObservedFlowIds, byFlow}` cannot
   express the `not_evaluated` third state at the result level — a graph whose
   store was never consulted and a graph whose store was consulted and empty
   both produce `notObservedFlowIds = []` under that shape only if
   `notObservedFlowIds` is left empty in the first case, which is
   indistinguishable from "every flow was observed." **Resolution:** the result
   carries an explicit `evaluated: boolean` plus `notEvaluatedFlowIds`, and
   `byFlow` covers every flow with an explicit `layer`. `OC/5a`-`OC/5c` pin all
   three states as literal JSON, both directions.

4. **A node match cannot honestly corroborate one flow when several flows
   share that sink — and the scoping doc does not say what to do.** FR-505's
   "ambiguous observations remain candidates and do not silently merge data
   elements" is handled in the scoping doc only for the "one observation
   matched >1 canonical id" case. The commoner case is the inverse: one
   observation matches exactly one sink node, and five different flows end at
   that node. Claiming all five `runtime_observed` at the observation's own
   confidence over-claims. **Resolution:** a flow's `matchConfidence` is
   demoted to `'ambiguous'` whenever more than one flow shares the matched sink
   node for that observation, and `siblingFlowCount` records why. The layer
   still reads `runtime_observed` (the destination genuinely was contacted);
   only the confidence is honest about which path did it. `OC/8a`/`OC/8b`.

5. **`loadSnapshot(scanRoot, commitKey)` has an unvalidated `path.join`
   (`graph-snapshot.js:150-152`), and this plan does not inherit it.** That
   function joins a caller-supplied key straight onto the history directory
   with no shape check, so `loadSnapshot(root, '../../../etc/passwd')` reads
   outside the state directory. Not exploited today (the only callers pass a
   git commit or a `--against` flag), and **out of scope to fix here**. But
   `loadObservationImport(scanRoot, importId)` validates its key against
   `/^obsimport:[0-9a-f]{12}$/` and returns `null` otherwise, before any
   `path.join`. `OS/5c` pins it.

6. **The store's directory name must reach `statePath` as a STRING LITERAL, at
   every call site.** The scoping doc's §5 says this. Confirmed against
   `test/artifact-registry-completeness.test.js:48-51`: `PATTERNS` requires a
   quoted literal as `statePath`'s second argument, and `graph-snapshot.js:36`
   — `statePath(scanRoot, HISTORY_DIR)` — genuinely escapes the guard today,
   registered only because someone remembered. There are **two** call sites in
   this plan (`observation-store.js` and `index.js`) and both use the literal
   `'runtime-observations'`. A module constant is still exported for readers,
   but never passed to `statePath`.

7. **`runtime-correlation.js` reads THREE filenames, not one — register all
   three.** The scoping doc's Correction 7 and §5 name only
   `runtime-trace.jsonl`. `runtime-correlation.js`'s real
   `DEFAULT_TRACE_NAMES` is `['runtime-trace.jsonl', 'runtime.jsonl',
   'ebpf-trace.jsonl']`. Registering one of three leaves the other two exactly
   as unregistered as before. Task 4 registers all three.

8. **`commands/dataflow.md`'s `description` frontmatter has 3 characters of
   headroom.** Measured: 117 characters against
   `scripts/lint-command-descriptions.mjs`'s `DESCRIPTION_CAP = 120`. The
   `argument-hint` is 95 against a 200 cap. **Do not extend the description.**
   Put the new subcommands in `argument-hint` and the body only. This lint runs
   in `test:lifecycle`, NOT in `npm test` — deliverable #6's own final review
   found this exact trap.

9. **`retention` is an object with a closed key set, and `expiresAt: null` is
   legal.** PRD line 971 names "retention" as a `RuntimeObservation` field but
   does not specify its shape. Making it a free-form value would punch a hole
   straight through the closed-world validator. **Resolution:** `retention` is
   `{expiresAt: <ISO-8601 string> | null}` and nothing else — an unknown key
   inside it is an error, exactly like `attributes`. `null` means "no expiry
   declared by the operator," which is a real, disclosed choice; the artifact
   registry's own `retentionClass: 'evidence'` still sweeps the store.

10. **`graph.runtimeCorroboration` is ASSIGNED ONLY when the hook returns
    truthy.** The scoping doc's §4.5 says the result "lands on
    `graph.runtimeCorroboration` — the precedent `graph.recipientProfiles[]`
    set." But `graph.recipientProfiles` is assigned **unconditionally** to
    `[]` (`graph-builder.js:1011`), which would make every pre-existing graph
    grow a new key. Byte-identical-when-omitted (the contract `M2A1/hook-1`
    proved for `resolveDestination`) requires the key be genuinely ABSENT when
    no hook is supplied. `WIRE/3` pins both directions.

11. **`dataflow observations`/`dataflow twin` are `dataflow` subcommands, not a
    new top-level dispatcher.** Root `CLAUDE.md` already says "13 dispatchers"
    in this worktree (`governance` and `remediation` both landed). This
    deliverable adds NO dispatcher, so **do not edit the dispatcher count** —
    deliverable #6 had to edit it, this one must not.

12. **The scoping doc's §5 second registry row — "the adapter **input** file
    the operator drops in" → `operator-config` — has nothing to register.**
    `artifact-registry.js` matches on an exact top-level name under
    `.agentic-security/`, and `observations import --input <file>` takes an
    arbitrary path anywhere on disk. There is no fixed filename, and the CLI
    never calls `statePath` with an input-file literal, so the completeness
    guard has nothing to demand and `reset` has nothing to sweep. The
    `recipient-profiles.json`/`network-policy.json` precedent the scoping doc
    cites does not transfer: both of those ARE fixed names under the state
    directory. **Resolution:** the registry gains four rows and none of them is
    the adapter input — one for the store (`generated`) and three for the
    pre-existing runtime-trace filenames (`operator-config`, Correction 7). If
    an operator chooses to keep their
    export inside `.agentic-security/`, it is an unregistered file they
    manage, exactly as it is today for any hand-dropped input.

13. **`test/lineage/coverage.test.js`'s reuse-boundary test (`C1/10`) WILL
    fail on Task 5 until it is updated.** It reads `coverage.js`'s own import
    list, and Task 5 adds `'./observation-correlation.js'`. This is a necessary
    consequence, not a workaround — the identical thing happened when
    Sub-project B added `transit-protection.js` to that same list. Task 5's
    Step 4 includes the update; do not discover it at Step 7 and treat it as a
    regression.

---

## Global Constraints

- **7b only.** No task in this plan mints a node or edge that is not backed by
  a real code call site; no task writes `edge.provenance` at all. Corroboration
  is recorded **additively**, keyed by canonical id, on
  `graph.runtimeCorroboration` — never by reclassifying an existing edge
  (scoping doc §4.5). Every downstream consumer (`impact-engine.js`,
  `decision-story.js`, `obligation-predicates.js`, `export-csv.js`,
  `export-privacy.js`, `bench/protection-verdict/runner.mjs`) was written
  against a graph where `edge.provenance === 'code'` is invariantly true, and
  stays true after this deliverable.
- **Metadata-only, enforced by a CLOSED-WORLD validator.** PRD line 983:
  "Runtime records use approved metadata schemas and **reject** fields capable
  of carrying payload values." A denylist fails open on every attribute name
  nobody thought of, so there is none. Unknown top-level key ⇒ error. Unknown
  attribute key ⇒ error. Attribute value that is not `string`/`number`/
  `boolean` (or, for the one array-valued key, an array of strings) ⇒ error.
  Every string value length-capped.
- **Absence of observation is never non-occurrence.** PRD line 2098. The layer
  vocabulary is three-valued (`runtime_observed` / `not_observed_in_window` /
  `not_evaluated`) and the two negative values are genuinely distinguishable in
  JSON. `not_evaluated` means no store was consulted; `not_observed_in_window`
  means a store WAS consulted and the window genuinely contained nothing. This
  is the same distinction `flow.policyVerdict`'s own `not_evaluated` already
  draws for a missing `privacy-policy.json` (`index.js:129-150`).
- **Non-exclusion is structural, not a policy.** `correlateObservations`
  returns annotations keyed by id. It never filters, removes, reorders, or
  mutates any graph entity. AC-29 clause 3 is then true by construction, the
  same argument `path-store.js`'s cycle-safety rests on.
- **Ambiguity is kept, never resolved.** An observation matching more than one
  canonical node keeps ALL of them in `matchedNodeIds` with
  `matchConfidence: 'ambiguous'`, and never picks one (FR-505). A flow whose
  matched sink node is shared with sibling flows is likewise demoted to
  `'ambiguous'` (Correction 4).
- **External evidence arrives as a FILE, never live ingestion.** No collector,
  no daemon, no network call, no OTLP endpoint. FR-505's own no-egress rule and
  the root `CLAUDE.md`'s "no runtime cloud calls" convention both forbid it,
  and `posture/runtime-correlation.js`'s offline-file contract is the proven
  in-repo pattern.
- **Pure/impure split is load-bearing.** `runtime-observation.js` and
  `observation-adapters.js` import NOTHING; `observation-correlation.js`
  imports exactly `['./runtime-observation.js']`. Only `observation-store.js`
  touches `fs`. Boundary tests read each module's own source and assert its
  import specifier list, the pattern `path-query.js`/`flow-grade.js` already
  established.
- **`statePath` with a string literal, always.** Both call sites use
  `statePath(scanRoot, 'runtime-observations')` verbatim (Correction 6), so
  `test/artifact-registry-completeness.test.js` genuinely enforces registration.
- **Dry-run by default for the one mutating verb.** `observations import`
  computes and prints exactly what it WOULD write and writes nothing unless
  `--yes`. `observations list` and `twin` never write. Mirrors
  `governance propose-edit`'s own contract.
- **Refuse the whole import, never a partial one.** If ANY record in an adapter
  input fails validation, the entire import is rejected (exit 1) with every
  failing record named. A partial import that silently drops the offending
  record is precisely the failure AC-29 clause 5 forbids — the operator would
  believe the artifact holds what the file held.
- **Exit-code contract, identical to `dataflow impact assess`'s plus an
  explicit 4:** `0` success (preview **or** real write); `1` a validation
  failure (a rejected record, a malformed adapter input, a graph-load failure
  via `loadSignedGraph`'s own four messages); `2` a usage/argument error or an
  `isSafeStateDir` refusal; `4` an unexpected I/O error during the write itself
  — nothing was written and no audit event was recorded.
- **`isSafeStateDir` before any write.** Guard
  `statePath(scanRoot, 'runtime-observations')` before any `mkdirSync`/write.
  Confirmed this passes for a nested state directory:
  `state-dir.js:113-116` recurses up to the `.agentic-security` root, which is
  exactly why `llm-cache/`/`fix-history/` work.
- **`auditCall` AND the store, never either alone.** `auditCall` records
  *"someone ran this command"*; the store records *"these observations were
  imported."* Both are required on every real write, never on a dry run and
  never on a rejected import. `auditCall({sessionRoot, tool, args, outcome,
  reason})` (`mcp/audit.js:83`) — note it silently no-ops when `sessionRoot`
  has no project marker.
- **No change to `dataflow-graph.schema.json` or `validate.js`.**
  `graph.runtimeCorroboration` is a §10.10 extension attached to the graph
  object, never a `DataFlowGraph v1` entity, never routed through
  `validateGraph()`. `test/lineage/json-schema-parity.test.js` must stay green
  untouched.
- **`remediation.js` / `remediation-ledger.js` / the `remediation` CLI verbs
  are untouched** (scoping doc §3, §7). AC-31's own `or` is
  rescan-vs-manual-attestation; runtime is not in it. A shipped source-text
  import guard pins this (Task 2, `OC/9`).
- **`ImpactAssessment.scope` stays `'possible'`.** `IMPACT_SCOPE_VALUES` already
  reserves `'observed'`; nothing in this plan emits it. A half-built
  possible/observed partition is worse than a disclosed gap (scoping doc §7).
- **No new npm dependency.** No changes to `graph-snapshot.js`,
  `impact-engine.js`, `remediation*.js`, `scenario*.js`, `validate.js`,
  `schema.js`, or `posture/runtime-correlation.js` — except the artifact-registry
  additions in Task 4, which change no behavior of any of them.
- **Disclosed, not fixed:** (a) no UI — layer toggles, distinct edge treatment,
  an environment/window selector, an observation inspector, and the D.6
  `runtime-digital-twin.dark.1680x945.png` golden are all unbuilt (scoping doc
  §4.7); (b) no OpenTelemetry adapter (increment 2, scoping doc §4.3); (c) no
  gateway/mesh or cloud-flow adapters; (d) no field-level identity from runtime
  evidence — observations correlate to node/edge/flow ids only, never to a
  `dataElement`'s field identity, per FR-505's own explicit prohibition;
  (e) `graph-snapshot.js`'s own unvalidated `path.join` (Correction 5).

---

### Task 1: `scanner/src/lineage/runtime-observation.js` — the pure contract and the closed-world validator

The single most load-bearing module in the deliverable. AC-29 clause 5 rests on
it entirely, and it is the ONE validator in this codebase that inverts every
sibling §10.10 contract's open-world behavior. It gets the most thorough test
coverage: every field, every cross-field rule, and every rejection reason.

**Files:**
- Create: `scanner/src/lineage/runtime-observation.js`
- Create: `scanner/test/lineage/runtime-observation.test.js`
- Modify: `scanner/src/lineage/ids.js` (append two id functions)
- Modify: `scanner/test/lineage/ids.test.js` (id tests)
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `RUNTIME_OBSERVATION_VERSION` — `'1.0.0'`
- `RUNTIME_OBSERVATION_FIELDS` — frozen array of the 18 allowed top-level keys
- `RUNTIME_OBSERVATION_ADAPTERS` — frozen `['native-jsonl']`
- `RUNTIME_ATTRIBUTE_KEYS` — frozen allowlist of 18 approved metadata keys
- `RUNTIME_ARRAY_ATTRIBUTE_KEYS` — frozen `['schema.attributeNames']`
- `RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH` (`256`), `RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH` (`64`), `RUNTIME_ATTRIBUTE_MAX_KEYS` (`32`)
- `EVENT_COUNT_BANDS` — frozen `['1', '2-10', '11-100', '101-1k', '1k+']`
- `RUNTIME_MATCH_METHODS` — frozen `['destination_literal', 'store_table', 'queue_topic', 'unmatched']`
- `RUNTIME_MATCH_CONFIDENCE` — frozen `['high', 'medium', 'low', 'ambiguous']`
- `OBSERVATION_LAYERS` — frozen `['runtime_observed', 'not_observed_in_window', 'not_evaluated']`
- `validateObservationAttributes(attributes) -> {valid, errors}`
- `validateRuntimeObservation(record) -> {valid, errors}`
- In `ids.js`: `observationId({adapter, environment, windowStart, windowEnd}, discriminatorParts) -> 'observation:<12hex>'` and `observationImportId({adapter, source, environment, windowStart, windowEnd, importedAt}, discriminatorParts) -> 'obsimport:<12hex>'`

**Interfaces (consumed):** none. `runtime-observation.js` has **zero imports**,
mirroring `impact-assessment.js`/`flow-grade.js`'s own precedent. `ids.js` keeps
its single `node:crypto` import.

`errors` is `[{path, message}]` throughout — `impact-assessment.js`'s exact
shape (`{path: '$.id', message: '...'}`), not `governance-edit.js`'s
`[{key, message}]`.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/runtime-observation.test.js`:

```js
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  RUNTIME_OBSERVATION_VERSION, RUNTIME_OBSERVATION_FIELDS, RUNTIME_OBSERVATION_ADAPTERS,
  RUNTIME_ATTRIBUTE_KEYS, RUNTIME_ARRAY_ATTRIBUTE_KEYS,
  RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH, RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH, RUNTIME_ATTRIBUTE_MAX_KEYS,
  EVENT_COUNT_BANDS, RUNTIME_MATCH_METHODS, RUNTIME_MATCH_CONFIDENCE, OBSERVATION_LAYERS,
  validateObservationAttributes, validateRuntimeObservation,
} from '../../src/lineage/runtime-observation.js';
import { observationId, observationImportId } from '../../src/lineage/ids.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));

function _obs(overrides = {}) {
  return {
    id: 'observation:0123456789ab',
    version: '1.0.0',
    adapter: 'native-jsonl',
    source: 'otel-export-2026-09-01.jsonl',
    environment: 'production',
    windowStart: '2026-08-01T00:00:00.000Z',
    windowEnd: '2026-09-01T00:00:00.000Z',
    matchedNodeIds: ['node:aaaaaaaaaaaa'],
    matchedEdgeIds: [],
    matchedFlowIds: [],
    attributes: { 'destination.host': 'api.stripe.com', 'destination.scheme': 'https', 'tls.version': '1.3' },
    eventCountBand: '101-1k',
    firstObservedAt: '2026-08-02T10:00:00.000Z',
    lastObservedAt: '2026-08-30T10:00:00.000Z',
    matchMethod: 'destination_literal',
    matchConfidence: 'high',
    retention: { expiresAt: '2027-09-01T00:00:00.000Z' },
    importedAt: '2026-09-01T12:00:00.000Z',
    ...overrides,
  };
}

const _ok = (r, msg) => { assert.equal(r.valid, true, `${msg}: ${JSON.stringify(r.errors)}`); };
const _named = (r, p) => assert.ok(r.errors.some((e) => e.path === p), `expected an error at ${p}, got ${JSON.stringify(r.errors)}`);

// ── RO/1: the vocabulary ──────────────────────────────────────────────

test('RO/1a: every exported enum is frozen and has exactly the documented values', () => {
  assert.equal(RUNTIME_OBSERVATION_VERSION, '1.0.0');
  assert.deepEqual([...RUNTIME_OBSERVATION_FIELDS], [
    'id', 'version', 'adapter', 'source', 'environment', 'windowStart', 'windowEnd',
    'matchedNodeIds', 'matchedEdgeIds', 'matchedFlowIds', 'attributes', 'eventCountBand',
    'firstObservedAt', 'lastObservedAt', 'matchMethod', 'matchConfidence', 'retention', 'importedAt',
  ]);
  assert.deepEqual([...RUNTIME_OBSERVATION_ADAPTERS], ['native-jsonl']);
  assert.deepEqual([...EVENT_COUNT_BANDS], ['1', '2-10', '11-100', '101-1k', '1k+']);
  assert.deepEqual([...RUNTIME_MATCH_METHODS], ['destination_literal', 'store_table', 'queue_topic', 'unmatched']);
  assert.deepEqual([...RUNTIME_MATCH_CONFIDENCE], ['high', 'medium', 'low', 'ambiguous']);
  assert.deepEqual([...OBSERVATION_LAYERS], ['runtime_observed', 'not_observed_in_window', 'not_evaluated']);
  assert.deepEqual([...RUNTIME_ARRAY_ATTRIBUTE_KEYS], ['schema.attributeNames']);
  for (const e of [RUNTIME_OBSERVATION_FIELDS, RUNTIME_OBSERVATION_ADAPTERS, RUNTIME_ATTRIBUTE_KEYS,
    RUNTIME_ARRAY_ATTRIBUTE_KEYS, EVENT_COUNT_BANDS, RUNTIME_MATCH_METHODS, RUNTIME_MATCH_CONFIDENCE,
    OBSERVATION_LAYERS]) assert.ok(Object.isFrozen(e));
});

test('RO/1b: RUNTIME_ATTRIBUTE_KEYS is exactly FR-505\'s own four named metadata families', () => {
  assert.deepEqual([...RUNTIME_ATTRIBUTE_KEYS], [
    // service/workload identity
    'service.name', 'service.namespace', 'service.version', 'service.instance.id',
    'workload.name', 'workload.kind',
    // endpoint or destination identity
    'destination.host', 'destination.port', 'destination.scheme', 'destination.path', 'destination.service',
    // protocol/TLS metadata
    'network.protocol', 'network.transport', 'tls.version', 'tls.cipher', 'tls.verified',
    // schema/attribute NAMES already approved for telemetry
    'schema.name', 'schema.attributeNames',
  ]);
  // Every array-valued key must itself be an approved key.
  for (const k of RUNTIME_ARRAY_ATTRIBUTE_KEYS) assert.ok(RUNTIME_ATTRIBUTE_KEYS.includes(k));
});

test('RO/1c: the caps are the documented literals', () => {
  assert.equal(RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH, 256);
  assert.equal(RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH, 64);
  assert.equal(RUNTIME_ATTRIBUTE_MAX_KEYS, 32);
});

test('RO/1d: this module is pure — zero imports, and no fs reference anywhere in its source', () => {
  const src = fs.readFileSync(path.resolve(HERE, '../../src/lineage/runtime-observation.js'), 'utf8');
  const specifiers = [...src.matchAll(/^\s*import\s[^;]*?from\s*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
  assert.deepEqual(specifiers, [], 'runtime-observation.js must import nothing — it is pure by contract');
  assert.equal(/\bimport\s*\(/.test(src), false, 'no dynamic import either');
  assert.equal(/node:fs|require\(/.test(src), false, 'no fs access of any kind');
});

// ── RO/2: the happy path ──────────────────────────────────────────────

test('RO/2a: a well-formed observation validates with zero errors', () => {
  const r = validateRuntimeObservation(_obs());
  assert.deepEqual(r.errors, []);
  assert.equal(r.valid, true);
});

test('RO/2b: an unmatched observation validates when every matched array is empty', () => {
  _ok(validateRuntimeObservation(_obs({
    matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [],
    matchMethod: 'unmatched', matchConfidence: 'low',
  })), 'an honestly unmatched observation is a valid record');
});

test('RO/2c: retention.expiresAt may be null — "no expiry declared" is a real operator choice', () => {
  _ok(validateRuntimeObservation(_obs({ retention: { expiresAt: null } })), 'null expiry');
});

// ── RO/3: ordinary field validation ───────────────────────────────────

test('RO/3a: id is required and must carry the observation: prefix', () => {
  for (const bad of ['', null, 42, 'obs:abc', 'observation', 'impact:0123456789ab']) {
    const r = validateRuntimeObservation(_obs({ id: bad }));
    assert.equal(r.valid, false, `id ${JSON.stringify(bad)} must be rejected`);
    _named(r, '$.id');
  }
});

test('RO/3b: adapter must be a live RUNTIME_OBSERVATION_ADAPTERS member', () => {
  const r = validateRuntimeObservation(_obs({ adapter: 'otlp' }));
  assert.equal(r.valid, false, 'an unimplemented adapter must be rejected, not accepted on faith');
  _named(r, '$.adapter');
});

test('RO/3c: every required non-empty string is checked by name', () => {
  for (const field of ['version', 'source', 'environment']) {
    const r = validateRuntimeObservation(_obs({ [field]: '' }));
    assert.equal(r.valid, false, `${field} must be required`);
    _named(r, `$.${field}`);
  }
});

test('RO/3d: eventCountBand must be a band, never a raw count', () => {
  for (const bad of [7, '7', 'many', '', null]) {
    const r = validateRuntimeObservation(_obs({ eventCountBand: bad }));
    assert.equal(r.valid, false, `eventCountBand ${JSON.stringify(bad)} must be rejected — an exact count is itself an information channel`);
    _named(r, '$.eventCountBand');
  }
  for (const good of EVENT_COUNT_BANDS) _ok(validateRuntimeObservation(_obs({ eventCountBand: good })), good);
});

test('RO/3e: matchMethod and matchConfidence must be live enum members', () => {
  _named(validateRuntimeObservation(_obs({ matchMethod: 'guessed' })), '$.matchMethod');
  _named(validateRuntimeObservation(_obs({ matchConfidence: 'certain' })), '$.matchConfidence');
});

test('RO/3f: every matched*Ids field must be an array of correctly-prefixed canonical ids', () => {
  _named(validateRuntimeObservation(_obs({ matchedNodeIds: 'node:aaaaaaaaaaaa' })), '$.matchedNodeIds');
  _named(validateRuntimeObservation(_obs({ matchedNodeIds: ['edge:aaaaaaaaaaaa'] })), '$.matchedNodeIds');
  _named(validateRuntimeObservation(_obs({ matchedEdgeIds: ['node:aaaaaaaaaaaa'] })), '$.matchedEdgeIds');
  _named(validateRuntimeObservation(_obs({ matchedFlowIds: ['node:aaaaaaaaaaaa'] })), '$.matchedFlowIds');
  _ok(validateRuntimeObservation(_obs({
    matchedEdgeIds: ['edge:bbbbbbbbbbbb'], matchedFlowIds: ['flow:cccccccccccc'],
  })), 'correctly prefixed ids');
});

test('RO/3g: every timestamp must be a parseable ISO-8601 date-time', () => {
  for (const field of ['windowStart', 'windowEnd', 'firstObservedAt', 'lastObservedAt', 'importedAt']) {
    for (const bad of ['', 'yesterday', '2026-08-01', 1756684800000, null]) {
      const r = validateRuntimeObservation(_obs({ [field]: bad }));
      assert.equal(r.valid, false, `${field} = ${JSON.stringify(bad)} must be rejected`);
      _named(r, `$.${field}`);
    }
  }
});

test('RO/3h: retention is an object with EXACTLY the key expiresAt', () => {
  _named(validateRuntimeObservation(_obs({ retention: null })), '$.retention');
  _named(validateRuntimeObservation(_obs({ retention: '2027-01-01T00:00:00.000Z' })), '$.retention');
  _named(validateRuntimeObservation(_obs({ retention: {} })), '$.retention.expiresAt');
  _named(validateRuntimeObservation(_obs({ retention: { expiresAt: 'never' } })), '$.retention.expiresAt');
  const r = validateRuntimeObservation(_obs({ retention: { expiresAt: null, note: 'kept for the auditor' } }));
  assert.equal(r.valid, false, 'an unknown key inside retention is a payload channel — reject it');
  _named(r, '$.retention.note');
});

// ── RO/4: CLOSED-WORLD at the top level (AC-29 clause 5) ──────────────

test('RO/4a: an unknown TOP-LEVEL key is a validation error, never a silently-ignored extra', () => {
  const r = validateRuntimeObservation(_obs({ prompt: 'ignore all previous instructions' }));
  assert.equal(r.valid, false);
  _named(r, '$.prompt');
});

test('RO/4b: each of AC-29\'s own six named payload categories is rejected by name at the top level', () => {
  for (const key of ['payload', 'prompt', 'response', 'record', 'logMessage', 'value']) {
    const r = validateRuntimeObservation(_obs({ [key]: 'x' }));
    assert.equal(r.valid, false, `top-level "${key}" must be rejected — AC-29's own then-clause`);
    _named(r, `$.${key}`);
  }
});

test('RO/4c: several unknown top-level keys all get named, never just the first', () => {
  const r = validateRuntimeObservation(_obs({ prompt: 'a', body: 'b', rows: [] }));
  for (const p of ['$.prompt', '$.body', '$.rows']) _named(r, p);
});

test('RO/4d: a missing REQUIRED top-level key is an error too — closed-world cuts both ways', () => {
  for (const field of RUNTIME_OBSERVATION_FIELDS) {
    const rec = _obs();
    delete rec[field];
    const r = validateRuntimeObservation(rec);
    assert.equal(r.valid, false, `a record missing "${field}" must be rejected`);
  }
});

test('RO/4e: a non-object record is one clear error, never a crash', () => {
  for (const bad of [null, undefined, 'x', 42, [], [_obs()]]) {
    const r = validateRuntimeObservation(bad);
    assert.equal(r.valid, false);
    assert.equal(r.errors[0].path, '$');
  }
});

test('RO/4f: validateRuntimeObservation never throws, on anything', () => {
  for (const bad of [null, undefined, 'x', 42, [], {}, { attributes: null }, { attributes: 7 },
    { retention: [] }, Object.create(null), { __proto__: null }]) {
    assert.doesNotThrow(() => validateRuntimeObservation(bad));
  }
});

test('RO/4g: a prototype-polluting key is rejected like any other unknown key', () => {
  const rec = _obs();
  Object.defineProperty(rec, '__proto__', { value: { evil: true }, enumerable: true, configurable: true });
  const r = validateRuntimeObservation(rec);
  assert.equal(r.valid, false);
});

test('RO/4h: the validator NEVER mutates, deletes, or scrubs — it reports', () => {
  const rec = _obs({ prompt: 'secret' });
  const before = JSON.stringify(rec);
  validateRuntimeObservation(rec);
  assert.equal(JSON.stringify(rec), before,
    'PRD line 983 says REJECT, not redact — a scrubbing validator would let a caller persist the scrubbed remainder as if it had been clean');
});

// ── RO/5: CLOSED-WORLD attributes (AC-29 clause 5, the core) ──────────

test('RO/5a: every approved attribute key validates with a scalar value', () => {
  for (const key of RUNTIME_ATTRIBUTE_KEYS) {
    const value = RUNTIME_ARRAY_ATTRIBUTE_KEYS.includes(key) ? ['user_id', 'created_at'] : 'x';
    _ok(validateObservationAttributes({ [key]: value }), `approved key ${key}`);
  }
  _ok(validateObservationAttributes({ 'destination.port': 443 }), 'number');
  _ok(validateObservationAttributes({ 'tls.verified': true }), 'boolean');
  _ok(validateObservationAttributes({}), 'an empty attribute set is valid — an observation may carry only ids and a window');
});

test('RO/5b: an unapproved attribute key is an error naming that key — the allowlist is the control', () => {
  for (const key of ['http.url', 'db.statement', 'messaging.message.payload', 'gen_ai.prompt',
    'gen_ai.completion', 'user.email', 'request.body', 'http.request.header.authorization',
    'destination.hostname' /* near-miss of an approved key */]) {
    const r = validateObservationAttributes({ [key]: 'x' });
    assert.equal(r.valid, false, `attribute "${key}" is not on the allowlist and must be rejected`);
    _named(r, `$.attributes["${key}"]`);
  }
});

test('RO/5c: a non-scalar attribute value is rejected — nesting is how a payload arrives disguised', () => {
  for (const value of [{ a: 1 }, [{ a: 1 }], [1, 2], null, undefined, () => 1]) {
    const r = validateObservationAttributes({ 'service.name': value });
    assert.equal(r.valid, false, `service.name = ${JSON.stringify(value)} must be rejected`);
    _named(r, '$.attributes["service.name"]');
  }
});

test('RO/5d: the ONE array-valued key accepts only an array of short strings, count-capped', () => {
  _ok(validateObservationAttributes({ 'schema.attributeNames': ['a', 'b'] }), 'array of strings');
  assert.equal(validateObservationAttributes({ 'schema.attributeNames': 'a' }).valid, false, 'a bare string is not an array');
  assert.equal(validateObservationAttributes({ 'schema.attributeNames': [1] }).valid, false, 'a non-string element');
  assert.equal(validateObservationAttributes({ 'schema.attributeNames': [{ a: 1 }] }).valid, false, 'an object element');
  assert.equal(validateObservationAttributes({
    'schema.attributeNames': Array.from({ length: RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH + 1 }, (_, i) => `f${i}`),
  }).valid, false, 'over the array cap');
  assert.equal(validateObservationAttributes({
    'schema.attributeNames': ['x'.repeat(RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH + 1)],
  }).valid, false, 'an over-long element');
});

test('RO/5e: an over-long string value and an over-wide attribute set are both rejected', () => {
  assert.equal(validateObservationAttributes({
    'destination.path': 'x'.repeat(RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH + 1),
  }).valid, false, 'a 4KB "path" is a payload with a metadata-shaped name');
  _ok(validateObservationAttributes({
    'destination.path': 'x'.repeat(RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH),
  }), 'exactly at the cap is allowed');
  const wide = {};
  for (let i = 0; i <= RUNTIME_ATTRIBUTE_MAX_KEYS; i++) wide[`service.name${i}`] = 'x';
  assert.equal(validateObservationAttributes(wide).valid, false, 'over the key cap');
});

test('RO/5f: attribute errors surface through validateRuntimeObservation, not only the helper', () => {
  const r = validateRuntimeObservation(_obs({ attributes: { 'db.statement': 'SELECT * FROM users' } }));
  assert.equal(r.valid, false);
  _named(r, '$.attributes["db.statement"]');
});

test('RO/5g: attributes must be a plain object', () => {
  for (const bad of [null, 'x', 42, [], undefined]) {
    _named(validateRuntimeObservation(_obs({ attributes: bad })), '$.attributes');
  }
});

// ── RO/6: cross-field rules ───────────────────────────────────────────

test('RO/6a: windowStart must not be after windowEnd', () => {
  _named(validateRuntimeObservation(_obs({
    windowStart: '2026-09-01T00:00:00.000Z', windowEnd: '2026-08-01T00:00:00.000Z',
  })), '$.windowEnd');
});

test('RO/6b: firstObservedAt must not be after lastObservedAt', () => {
  _named(validateRuntimeObservation(_obs({
    firstObservedAt: '2026-08-30T00:00:00.000Z', lastObservedAt: '2026-08-02T00:00:00.000Z',
  })), '$.lastObservedAt');
});

test('RO/6c: both observation timestamps must fall inside the declared window', () => {
  _named(validateRuntimeObservation(_obs({ firstObservedAt: '2026-07-01T00:00:00.000Z' })), '$.firstObservedAt');
  _named(validateRuntimeObservation(_obs({ lastObservedAt: '2026-09-02T00:00:00.000Z' })), '$.lastObservedAt');
});

test('RO/6d: matchMethod "unmatched" REQUIRES every matched array to be empty', () => {
  const r = validateRuntimeObservation(_obs({ matchMethod: 'unmatched', matchConfidence: 'low' }));
  assert.equal(r.valid, false, 'an "unmatched" record naming a matched node contradicts itself');
  _named(r, '$.matchMethod');
});

test('RO/6e: a real matchMethod REQUIRES at least one matched node id', () => {
  const r = validateRuntimeObservation(_obs({ matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [] }));
  assert.equal(r.valid, false, 'a destination_literal match with nothing matched is not a match');
  _named(r, '$.matchedNodeIds');
});

test('RO/6f (FR-505): more than one matched node REQUIRES matchConfidence "ambiguous" — never a silent pick', () => {
  const two = ['node:aaaaaaaaaaaa', 'node:bbbbbbbbbbbb'];
  for (const c of ['high', 'medium', 'low']) {
    const r = validateRuntimeObservation(_obs({ matchedNodeIds: two, matchConfidence: c }));
    assert.equal(r.valid, false, `two candidate nodes at confidence "${c}" must be rejected — "ambiguous observations remain candidates and do not silently merge data elements"`);
    _named(r, '$.matchConfidence');
  }
  _ok(validateRuntimeObservation(_obs({ matchedNodeIds: two, matchConfidence: 'ambiguous' })), 'two candidates, honestly ambiguous');
});

// ── RO/7: ids ─────────────────────────────────────────────────────────

test('RO/7a: observationId is prefixed, fixed-width, deterministic, and discriminated', () => {
  const base = { adapter: 'native-jsonl', environment: 'production', windowStart: 'a', windowEnd: 'b' };
  const a = observationId(base, ['destination.host=api.stripe.com']);
  assert.match(a, /^observation:[0-9a-f]{12}$/);
  assert.equal(a, observationId(base, ['destination.host=api.stripe.com']), 'idempotent');
  assert.notEqual(a, observationId(base, ['destination.host=api.other.com']), 'discriminator matters');
  assert.notEqual(a, observationId({ ...base, environment: 'staging' }, ['destination.host=api.stripe.com']),
    'the same destination observed in two environments is two observations');
});

test('RO/7b: observationImportId is prefixed, fixed-width, deterministic, and discriminated', () => {
  const base = {
    adapter: 'native-jsonl', source: 'f.jsonl', environment: 'production',
    windowStart: 'a', windowEnd: 'b', importedAt: '2026-09-01T12:00:00.000Z',
  };
  const a = observationImportId(base);
  assert.match(a, /^obsimport:[0-9a-f]{12}$/);
  assert.equal(a, observationImportId(base), 'idempotent');
  assert.notEqual(a, observationImportId({ ...base, importedAt: '2026-09-01T12:00:01.000Z' }),
    'importedAt is a per-run nonce, mirroring snapshotId\'s own capturedAt');
});
```

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/runtime-observation.test.js`
Expected: FAIL — `Cannot find module '../../src/lineage/runtime-observation.js'`.
Read the real output; do not assume. A `SyntaxError` here means the test file
itself does not parse — fix that first, or this step fails for the wrong reason
and you learn nothing about the module.

- [ ] **Step 3: Write `scanner/src/lineage/runtime-observation.js`**

Zero imports. The header comment must record, at minimum:

- What this module is (M5 deliverable #7, 7b only; FR-505 §10.10 + AC-29), and
  that it is pure by contract.
- **Why it is CLOSED-WORLD when every sibling §10.10 contract
  (`impact-assessment.js`, `recipient-profile.js`, `scenario.js`,
  `obligation-mapping.js`, `graph-snapshot.js`) is open-world**, with both
  citations: PRD line 983 ("Runtime records use approved metadata schemas and
  **reject** fields capable of carrying payload values") and AC-29 clause 5
  ("no captured payload, prompt, response, record, log message, or sensitive
  value exists in the observation artifact"). Say plainly that a
  scrub-known-bad denylist cannot satisfy either, because it fails open on
  every attribute name nobody thought of — so a future "simplification" to
  ignore-unknown-keys is a silent AC-29 falsification, not a cleanup.
- That the validator **reports and never mutates** — a scrubbing validator
  would let a caller persist the scrubbed remainder as if it had been clean
  (`RO/4h`).
- That `eventCountBand` is a band because PRD line 971 says "count/frequency
  band" and an exact count is itself a weak information channel.
- That `'ambiguous'` exists because FR-505 requires ambiguous observations stay
  candidates and never silently merge data elements, and that the validator
  enforces it as a cross-field rule (`RO/6f`), not as documentation.
- That `OBSERVATION_LAYERS` is three-valued because PRD line 2098 forbids
  treating non-observation as non-occurrence, and that `not_evaluated` and
  `not_observed_in_window` are genuinely different answers — the same
  distinction `flow.policyVerdict`'s own `not_evaluated` draws for a missing
  `privacy-policy.json`.
- That this deliverable ships **7b only**; 7a/CONFIG DECLARED is M2
  Sub-project F2/F3 (scoping doc §4.0) and nothing here mints a non-code-derived
  edge.
- That AC-29's clauses are satisfied at the **data/artifact layer** and no UI
  displays them yet — so a future UI increment inherits five properties it must
  not break (scoping doc §4.7).

Implementation notes, in the order they matter:

- Local helpers, no imports: `_isPlainObject(v)`,
  `_isNonEmptyString(v, maxLen)`, `_isIsoDateTime(v)` (a string matching
  `/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/` whose
  `Date.parse` is finite), `_isPrefixedIdArray(v, prefix)`.
- `validateObservationAttributes(attributes)`: `_isPlainObject` guard first
  (one error at `$.attributes`, then stop). Then `Object.keys(attributes)`
  length against `RUNTIME_ATTRIBUTE_MAX_KEYS`. Then, per key, in this order:
  (1) `RUNTIME_ATTRIBUTE_KEYS.includes(key)` — an unapproved key is an error at
  `$.attributes["<key>"]` and the value is NOT further inspected; (2) if
  `RUNTIME_ARRAY_ATTRIBUTE_KEYS.includes(key)`, require an array whose length
  is `<= RUNTIME_ATTRIBUTE_MAX_ARRAY_LENGTH` and whose every element is a
  string of length `<= RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH`; (3) otherwise
  require `typeof v === 'string' | 'number' | 'boolean'`, and for a string,
  length `<= RUNTIME_ATTRIBUTE_MAX_VALUE_LENGTH`. Numbers must be finite. Use
  `Object.prototype.hasOwnProperty` semantics via
  `Object.keys`/`Object.entries` so an inherited key cannot slip through.
- `validateRuntimeObservation(record)`: `_isPlainObject` guard first (one
  error at `$`, return). Then the **closed-world sweep, before anything else**:
  for every `key of Object.keys(record)`, if
  `!RUNTIME_OBSERVATION_FIELDS.includes(key)` push
  `{path: '$.' + key, message: 'unknown field — RuntimeObservation records are closed-world (PRD line 983): only approved metadata fields are accepted, and an unrecognized field is rejected, never ignored'}`.
  Then the **missing-required sweep**: for every
  `field of RUNTIME_OBSERVATION_FIELDS`, if `!(field in record)` push an error.
  Then per-field type/enum checks. Then the cross-field rules, each guarded so
  it only fires when both operands are already well-formed (never cascade a
  window-ordering error off a malformed date). Return
  `{valid: errors.length === 0, errors}`.
- Cross-field rules, exactly:
  - `windowStart <= windowEnd` → error at `$.windowEnd`.
  - `firstObservedAt <= lastObservedAt` → error at `$.lastObservedAt`.
  - `firstObservedAt >= windowStart` → error at `$.firstObservedAt`;
    `lastObservedAt <= windowEnd` → error at `$.lastObservedAt`.
  - `matchMethod === 'unmatched'` ⟹ all three matched arrays empty → error at
    `$.matchMethod`.
  - `matchMethod !== 'unmatched'` ⟹ `matchedNodeIds.length >= 1` → error at
    `$.matchedNodeIds`.
  - `matchedNodeIds.length > 1` ⟹ `matchConfidence === 'ambiguous'` → error at
    `$.matchConfidence`. **Deliberately scoped to `matchedNodeIds` only** —
    edges and flows derive from a matched node, so several of them is normal
    and not an ambiguity; a rule over the union would fire on every ordinary
    match. Say this in the code comment.
- `retention`: `_isPlainObject` guard at `$.retention`; then a closed-key sweep
  over `Object.keys(retention)` against the literal `['expiresAt']`; then
  `expiresAt === null || _isIsoDateTime(expiresAt)`.
- `source` is capped at 512 characters; `environment` at 64.

Every exported function returns rather than throws, including on `null`,
`undefined`, and wrong-typed input.

- [ ] **Step 4: Append the two id functions to `scanner/src/lineage/ids.js`**

Append at the end of the file, mirroring `impactAssessmentId`'s own
object-argument shape and its `_hash(_canon([...]))` body exactly:

```js
/**
 * A RuntimeObservation record's id (M5 deliverable #7, FR-505 §10.10) —
 * NOT a DataFlowGraph v1 entity, mirrors impactAssessmentId's/scenarioId's
 * own precedent exactly. Discriminated by (adapter, environment,
 * windowStart, windowEnd) plus caller-supplied discriminatorParts, which
 * the adapter fills with the observation's own attribute fingerprint —
 * two observations of the SAME destination in the SAME environment and
 * window are the same observation and must collapse to one id, which is
 * what makes an accidental double-import idempotent at the record level.
 */
export function observationId(
  { adapter, environment, windowStart, windowEnd },
  discriminatorParts = [],
) {
  return `observation:${_hash(_canon([adapter, environment, windowStart, windowEnd, ...discriminatorParts]))}`;
}

/**
 * One adapter IMPORT's id (M5 deliverable #7, FR-505 §10.10) — the store's
 * own file key, mirroring graph-snapshot.js's commit key one dimension
 * over (import, not commit; see that sub-project's scoping doc §4.4 for
 * why commit-keying cannot express many observations per graph entity).
 * `importedAt` is a per-run nonce, exactly the role snapshotId's own
 * capturedAt plays: re-importing the same file must produce a NEW import
 * file, never silently overwrite the earlier one, because the store is a
 * directory of IMMUTABLE whole files.
 */
export function observationImportId(
  { adapter, source, environment, windowStart, windowEnd, importedAt },
  discriminatorParts = [],
) {
  return `obsimport:${_hash(_canon([adapter, source, environment, windowStart, windowEnd, importedAt, ...discriminatorParts]))}`;
}
```

Then append to `scanner/test/lineage/ids.test.js` a check that both new
functions are covered by whatever totality/prefix sweep that file already runs
— read the file first and follow its existing convention rather than inventing
a second one.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/runtime-observation.test.js test/lineage/ids.test.js`
Expected: PASS, 0 failures. Read the real output.

- [ ] **Step 6: Mutation-prove the two load-bearing guards**

A guard nobody has seen fail is not a guard. Temporarily, one at a time:

1. Delete the closed-world top-level sweep. Run
   `node --test test/lineage/runtime-observation.test.js`. Expected: `RO/4a`,
   `RO/4b`, `RO/4c` FAIL. Restore.
2. Change `validateObservationAttributes`'s unapproved-key branch to `continue`
   instead of pushing an error. Run again. Expected: `RO/5b`, `RO/5f` FAIL.
   Restore.

Confirm a clean run after restoring both. Record the transcript in the task
report; do not ship a mutated file.

- [ ] **Step 7: Wire the test file into `test:lineage`**

Read `scanner/package.json`'s current `test:lineage` script string first (it
currently ends with `test/lineage/remediation.test.js`), then append
` test/lineage/runtime-observation.test.js` to its end.

- [ ] **Step 8: Run the full lineage suite**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures. Capture and read `echo $?` in the same turn.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/runtime-observation.js scanner/test/lineage/runtime-observation.test.js scanner/src/lineage/ids.js scanner/test/lineage/ids.test.js scanner/package.json
git commit -m "feat(lineage): add runtime-observation.js — the RuntimeObservation contract and its closed-world validator (AC-29 clause 5)"
```

---

### Task 2: `scanner/src/lineage/observation-correlation.js` — the match ladder and the three-valued layer

Where AC-29 clauses 1-4 are actually satisfied. Two exported functions with
genuinely different jobs: `matchObservationToGraph` runs once per record at
IMPORT time and produces the record's own `matched*Ids`/`matchMethod`/
`matchConfidence` fields; `correlateObservations` runs at READ time and
produces the per-flow layer for a given environment and window.

**Files:**
- Create: `scanner/src/lineage/observation-correlation.js`
- Create: `scanner/test/lineage/observation-correlation.test.js`
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `matchObservationToGraph(graph, draft) -> {matchedNodeIds, matchedEdgeIds, matchedFlowIds, matchMethod, matchConfidence}`
  — `draft` is any object with an `attributes` field. Never throws; a malformed
  graph or draft yields the honest all-empty `'unmatched'`/`'low'` answer.
- `correlateObservations(graph, observations, opts) -> CorrelationResult`
  — `observations` is `RuntimeObservation[]`, or `null`/`undefined` meaning
  **no store was consulted**. `opts` is
  `{environment, windowStart, windowEnd}`, each nullable.
- `CorrelationResult` (a plain, JSON-serializable object — Correction 2):

```js
{
  version: '1.0.0',
  evaluated: true,                    // false ⟺ observations was null/undefined
  environment: 'production' | null,   // the FILTER that was applied, echoed back
  windowStart: '<iso>' | null,
  windowEnd: '<iso>' | null,
  observedNodeIds: [],                // sorted, deduplicated
  observedEdgeIds: [],
  observedFlowIds: [],
  notObservedFlowIds: [],             // [] when evaluated === false
  notEvaluatedFlowIds: [],            // every flow id when evaluated === false, else []
  byFlow: {                           // TOTAL over graph.flows — every flow, exactly once
    '<flowId>': {
      layer: 'runtime_observed' | 'not_observed_in_window' | 'not_evaluated',
      observationIds: [],             // sorted; [] unless layer === 'runtime_observed'
      matchMethod: '<method>' | null,
      matchConfidence: '<confidence>' | null,
      environment: '<name>' | null,
      windowStart: '<iso>' | null,
      windowEnd: '<iso>' | null,
      firstObservedAt: '<iso>' | null,
      lastObservedAt: '<iso>' | null,
      eventCountBand: '<band>' | null,
      siblingFlowCount: 0,            // other flows sharing this matched sink node
    },
  },
  consideredObservationIds: [],
  outOfWindowObservationIds: [],
  otherEnvironmentObservationIds: [],
  unmatchedObservationIds: [],
  invalidObservationIds: [],          // failed validateRuntimeObservation; never used
  limitations: [],                    // honest, human-readable strings
}
```

**Interfaces (consumed):** `OBSERVATION_LAYERS`, `RUNTIME_MATCH_METHODS`,
`RUNTIME_MATCH_CONFIDENCE`, `validateRuntimeObservation` from
`./runtime-observation.js` (Task 1). Nothing else. **The import specifier list
must be exactly `['./runtime-observation.js']`** — the same one-step-stricter
boundary test `path-query.js` already ships.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/observation-correlation.test.js`. Build graphs
with a small local `_graph()` helper (hand-built, NOT `buildDataFlowGraph` —
this module is pure and must be testable without the whole pipeline; a real
end-to-end proof lands in Task 5). The helper must produce entities whose
shapes match the real ones read from `graph-builder.js` this session:

```js
function _node(id, over = {}) {
  return {
    id, kind: 'external', subtype: 'external-api', label: 'x', aliases: [], location: null,
    system: { application: 'repo', environment: null },
    destination: null, storeDetail: null, queueDetail: null,
    externality: { value: 'external', evidenceRefs: [] },
    lifecycleStages: [], governanceRefs: {}, dataElementIds: [], evidenceRefs: [],
    confidence: { score: 0.9, tier: 'high' }, coverageStatus: 'modeled', coverageReason: null,
    ...over,
  };
}
function _edge(id, from, to) { return { id, from, to, relationship: 'data_flow', provenance: 'code' }; }
function _flow(id, source, sink, edgeIds) { return { id, source, sink, edgeIds, dataElementIds: [] }; }
function _graph(over = {}) {
  return { schemaVersion: '1.0.0', graphId: 'dfg:repo:uncommitted:default',
    nodes: [], edges: [], dataElements: [], flows: [], transformations: [], evidence: [], ...over };
}
```

Cover, at minimum, every one of these — each assertion stated exactly:

**`OC/1` — non-exclusion (AC-29 clause 3), the structural property:**
- `OC/1a` Deep-freeze a real graph (recursive `Object.freeze` over
  `nodes`/`edges`/`flows`/`dataElements` and each entity), call
  `correlateObservations` with a matching observation, assert it does not
  throw and that `graph.flows.length`/`graph.nodes.length`/`graph.edges.length`
  are unchanged. A function that mutates would throw in strict mode; a function
  that filters would change a length. **This is the test that makes clause 3
  true by construction rather than by discipline.**
- `OC/1b` `Object.keys(result.byFlow).sort()` deep-equals
  `graph.flows.map(f => f.id).sort()` — every flow appears exactly once,
  regardless of layer. Run with 3 flows where only 1 is observed.
- `OC/1c` `observedFlowIds` ∪ `notObservedFlowIds` ∪ `notEvaluatedFlowIds`
  exactly partitions the flow-id set (union equals, pairwise intersections
  empty), in all three evaluated states.

**`OC/2` — the match ladder (`matchObservationToGraph`):**
- `OC/2a` Rung 1, `destination_literal`/`high`: a node with
  `destination: {resolutionStatus: 'literal', raw: 'https://api.stripe.com/v1/charges', literalValue: 'https://api.stripe.com/v1/charges', blockingExpression: null}`
  and an observation with `{'destination.host': 'api.stripe.com'}` matches that
  node id.
- `OC/2b` Host comparison is case-insensitive (`API.STRIPE.COM` matches) and
  ignores a port on either side only when the observation supplies no
  `destination.port`; when it does supply one, the port must match the literal's
  own explicit port, and a mismatch is NOT a match.
- `OC/2c` A node whose `destination.resolutionStatus !== 'literal'` (e.g.
  `'dynamic'`, or `null` destination) never matches at rung 1 — there is no
  literal to compare against, and matching on a `blockingExpression` would be
  matching on source text.
- `OC/2d` Rung 2, `store_table`/`medium`: a node with
  `storeDetail: {table: 'User', operation: 'create', columns: ['email']}` and an
  observation with `{'destination.service': 'user'}` matches case-insensitively.
  `schema.name` matches the same rung.
- `OC/2e` Rung 3, `queue_topic`/`medium`: a node with
  `queueDetail: {provider: null, topic: 'https://sqs.us-east-1.amazonaws.com/1/orders', operation: 'publish'}`
  and an observation with that exact topic in `destination.service` matches.
  A partial/substring topic (`'orders'`) does **not** match — assert this
  explicitly, with a comment saying substring matching is how false positives
  get in.
- `OC/2f` Rungs are ordered: when a graph contains BOTH a rung-1 and a rung-2
  match for one observation, only the rung-1 node is returned and the method is
  `'destination_literal'`. The ladder stops at the first rung that produces any
  match.
- `OC/2g` Ambiguity: two nodes both matching at rung 1 → BOTH ids in
  `matchedNodeIds` (sorted), `matchConfidence: 'ambiguous'`, and neither
  dropped. Assert `matchedNodeIds.length === 2`.
- `OC/2h` No match → `{matchedNodeIds: [], matchedEdgeIds: [], matchedFlowIds: [], matchMethod: 'unmatched', matchConfidence: 'low'}`.
- `OC/2i` Derived ids: `matchedEdgeIds` is every edge whose `to` is a matched
  node id; `matchedFlowIds` is every flow whose `sink` is a matched node id.
  Both sorted and deduplicated. Prove with a graph where one matched node has
  2 in-edges and 2 flows, and an unmatched node has its own edge and flow that
  must NOT appear.
- `OC/2j` The result of `matchObservationToGraph` composed into a full record
  passes `validateRuntimeObservation` — including the `RO/6d`/`RO/6e`/`RO/6f`
  cross-field rules — for the matched, unmatched, and ambiguous cases alike.
  **This is the test that keeps Task 1 and Task 2 from drifting apart.**
- `OC/2k` Never throws: `matchObservationToGraph(null, null)`,
  `(_graph(), {})`, `(_graph(), {attributes: null})`,
  `({nodes: null}, {attributes: {}})` all return the `'unmatched'` shape.

**`OC/3` — the environment filter:**
- `OC/3a` `opts.environment === null` considers every observation regardless of
  its own `environment`.
- `OC/3b` `opts.environment = 'production'` puts a `'staging'` observation in
  `otherEnvironmentObservationIds` and never in `consideredObservationIds`;
  the matching flow's layer is `not_observed_in_window`, NOT
  `runtime_observed`.
- `OC/3c` The comparison is exact and case-sensitive (`'Production'` does not
  match `'production'`) — assert it, and comment that an operator's environment
  names are theirs and fuzzy-matching them would silently merge two
  environments.

**`OC/4` — the window filter:**
- `OC/4a` Both `opts.windowStart` and `opts.windowEnd` null → every observation
  is in-window.
- `OC/4b` An observation whose `[windowStart, windowEnd]` does not intersect
  the requested window goes to `outOfWindowObservationIds`; the flow reads
  `not_observed_in_window`.
- `OC/4c` A partially-overlapping observation IS considered (interval overlap,
  not containment) — assert with an observation window straddling
  `opts.windowStart`.
- `OC/4d` Only `opts.windowStart` given (open-ended end), and only
  `opts.windowEnd` given, each behave as a half-open filter.

**`OC/5` — the three-valued layer (AC-29 clause 2, PRD line 2098):**
- `OC/5a` `correlateObservations(graph, null, {})` → `evaluated: false`, every
  `byFlow` entry `layer: 'not_evaluated'`, `notObservedFlowIds: []`,
  `notEvaluatedFlowIds` equal to every flow id. Pin the whole result as
  **literal JSON**.
- `OC/5b` `correlateObservations(graph, [], {})` → `evaluated: true`, every
  entry `layer: 'not_observed_in_window'`, `notEvaluatedFlowIds: []`. Pin as
  literal JSON.
- `OC/5c` `assert.notDeepEqual` the two results above, and assert that the two
  serialize differently under `JSON.stringify`. **A store that was never
  consulted and a store that was consulted and empty are different answers, and
  a JSON consumer must be able to tell them apart** — PRD line 2098's own
  requirement, and the exact property a future refactor is most likely to
  collapse.
- `OC/5d` `undefined` behaves identically to `null` (both mean "no store").

**`OC/6` — AC-29's own two-flow scenario, end to end:**
- `OC/6a` One graph, two statically possible external flows to two different
  external nodes. One observation matching the first node's literal
  destination. Assert, in one test: flow A's `layer === 'runtime_observed'`,
  flow B's `layer === 'not_observed_in_window'`, BOTH flows present in
  `byFlow`, both node ids still in `graph.nodes`, and flow A's entry carries a
  non-null `matchMethod`, `matchConfidence`, `environment`, `windowStart`,
  `windowEnd`. This single test is AC-29's `given`/`then` transcribed.

**`OC/7` — clause 4, method and confidence travel with the match:**
- `OC/7a` Every `runtime_observed` entry has non-null `matchMethod`,
  `matchConfidence`, `environment`, `windowStart`, `windowEnd`,
  `firstObservedAt`, `lastObservedAt`, `eventCountBand`; every non-observed
  entry has all of them `null`. Assert both directions.
- `OC/7b` Two observations matching the same flow: `observationIds` holds both
  (sorted), `firstObservedAt` is the EARLIEST and `lastObservedAt` the LATEST
  across them, `eventCountBand` is the HIGHEST band present (index in
  `EVENT_COUNT_BANDS`), and `matchConfidence` is the WORST (last in
  `RUNTIME_MATCH_CONFIDENCE` order, i.e. `'ambiguous'` beats `'high'`) —
  a risk-precedence reduction mirroring `protection.js`'s `aggregateVerdicts`
  convention. `matchMethod` is the method of the STRONGEST-confidence
  observation, with ties broken by `RUNTIME_MATCH_METHODS` order, so the field
  is deterministic.

**`OC/8` — Correction 4, sibling-flow honesty:**
- `OC/8a` One observation matching one sink node that THREE flows end at: all
  three read `runtime_observed`, all three carry `siblingFlowCount: 2`, and all
  three have `matchConfidence: 'ambiguous'` even though the observation's own
  confidence is `'high'`. Assert the observation record itself is unchanged
  (still `'high'`) — the demotion is a property of the per-flow answer, not a
  rewrite of the evidence.
- `OC/8b` The same observation against a node with exactly ONE flow: the flow
  keeps `'high'` and `siblingFlowCount: 0`.

**`OC/9` — boundaries:**
- `OC/9a` The module's static import specifier list is exactly
  `['./runtime-observation.js']`, and there is no dynamic `import(` and no
  `node:fs` anywhere in its source.
- `OC/9b` A source-text guard, mirroring
  `test/lineage/scenario-no-obligation-wiring.test.js`'s exact pattern: neither
  `scanner/src/lineage/remediation.js` nor
  `scanner/src/posture/remediation-ledger.js` may import
  `runtime-observation.js`/`observation-correlation.js`/`observation-store.js`/
  `observation-adapters.js`, and none of those four may import either
  remediation module. AC-31's own `or` is rescan-vs-manual-attestation;
  runtime is not in it (scoping doc §3, §7). Read both files' source and assert
  on the specifier lists.
- `OC/9c` An observation that fails `validateRuntimeObservation` lands in
  `invalidObservationIds` (by its own `id` when it has a string one, else by
  the literal `'(no id)'`) and is never counted as considered, observed, or
  out-of-window. A whole list of invalid observations still returns
  `evaluated: true` with every flow `not_observed_in_window` — never a throw,
  and never a silent promotion.
- `OC/9d` `correlateObservations` never throws on
  `(null, null, null)`, `({}, [], {})`, `({flows: null}, [_obs()], {})`,
  `(_graph(), 'x', {})`.

**`OC/10` — limitations honesty:**
- `OC/10a` When `evaluated === false`, `limitations` contains a string naming
  "no runtime observation store was consulted". When
  `evaluated === true` and every flow is `not_observed_in_window`,
  `limitations` contains a string saying non-observation is not
  non-occurrence. When any flow was demoted by `siblingFlowCount`,
  `limitations` names the node-granularity boundary. Assert each is present in
  its case and absent in the others.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/observation-correlation.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `scanner/src/lineage/observation-correlation.js`**

Header comment must record:

- **Why it is named `observation-correlation.js` and not
  `runtime-correlation.js`**: `scanner/src/posture/runtime-correlation.js`
  already exists and is live-wired into every scan (`engine.js` imports it and
  calls `annotateRuntimeCorrelation` inside `_runAnnotator`), and this codebase
  has already been bitten by same-named-different-thing annotators — see the
  root `CLAUDE.md`'s `annotateGitProvenance` naming rule.
- **What is reused from `posture/runtime-correlation.js` and what is not**: the
  *technique* (a most-specific-identifier-first match ladder, then an honest
  no-match; a window filter) is reused; the *schema* is not. That module is
  code-execution-shaped (`qid`/`fileRel`/`line`, `kind: 'function-call' |
  'route-hit' | 'syscall' | 'file-touch'`); this one is destination-shaped
  (`node.destination.literalValue` / `node.storeDetail.table` /
  `node.queueDetail.topic`). Nothing is imported from it.
- **Clause 3 is structural**: this module returns annotations keyed by id and
  never filters, removes, reorders, or mutates a graph entity, so "both static
  paths remain visible" is true by construction. Say that a future refactor
  that starts returning a filtered flow list falsifies AC-29 directly.
- **Clause 2 is three-valued**, with the `not_evaluated` vs
  `not_observed_in_window` distinction spelled out and cited to PRD line 2098.
- **Correction 4's node-granularity boundary**, in full: an observation
  corroborates that a DESTINATION was contacted, never which of several flows
  did it, so a flow sharing its matched sink node with siblings is demoted to
  `'ambiguous'`. This is FR-505's "cannot prove field-level identity" applied
  at the granularity the evidence actually has.
- That `byFlow` is a plain object because the result is persisted inside a
  signed `lineage-graph.json` and a `Map` serializes to `{}` (Correction 2).

Implementation notes:

- `_hostOf(literal)`: parse with `new URL(literal)` inside a `try` and return
  `{host, port, pathname}` lowercased; on failure return `null`. Never regex a
  URL by hand.
- `matchObservationToGraph(graph, draft)`: guard `graph?.nodes` is an array and
  `draft?.attributes` is a plain object, else return the `'unmatched'` shape.
  Build the three rung predicates, evaluate rung 1 over every node, then rung 2,
  then rung 3, stopping at the first rung with a non-empty result. Sort the
  matched node ids. Confidence is the rung's own (`'high'`/`'medium'`/
  `'medium'`) unless `matchedNodeIds.length > 1`, in which case `'ambiguous'`.
  Derive `matchedEdgeIds`/`matchedFlowIds` from `graph.edges`/`graph.flows`
  (`to`/`sink` membership), sorted and deduplicated.
- `correlateObservations(graph, observations, opts)`: build the total `byFlow`
  skeleton FIRST, from `graph.flows`, with every entry at the correct default
  layer (`'not_evaluated'` when `observations == null`, else
  `'not_observed_in_window'`). Return immediately in the `not_evaluated` case,
  after filling `notEvaluatedFlowIds`. Otherwise: validate each observation,
  apply the environment filter, apply the window overlap filter, and for each
  considered observation fold its `matchedFlowIds` onto the skeleton. Compute
  `siblingFlowCount` per matched sink node from the graph's own flow list, once,
  before the fold. Sort every array before returning. `evaluated` is `true`
  whenever `observations` is an array, including an empty one.
- **Never re-run the match ladder here.** `correlateObservations` reads the
  record's already-recorded `matchedFlowIds`; the ladder ran at import time.
  Note in the header that this is deliberate: it keeps the record honest about
  what it was correlated against, and it means a graph rebuilt after a code
  change does not silently re-attribute old evidence to new entities. The
  consequence — a stale import whose `matchedFlowIds` no longer exist in the
  graph — is handled by filtering each `matchedFlowIds` entry against the
  graph's own flow-id set and recording the dropped ids in `limitations`.
  Assert this in `OC/9c`'s neighbourhood with a dedicated case.

Every exported function returns rather than throws.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/observation-correlation.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 5: Mutation-prove the two load-bearing guards**

1. Make `correlateObservations` return `{...result, notObservedFlowIds: []}`
   when `evaluated === false` is collapsed into the same branch as
   `evaluated === true` (i.e. delete the `not_evaluated` branch and always
   report `not_observed_in_window`). Expected: `OC/5a`, `OC/5c` FAIL. Restore.
2. Delete the `siblingFlowCount` demotion. Expected: `OC/8a` FAILS. Restore.

Confirm a clean run after restoring both.

- [ ] **Step 6: Wire the test file into `test:lineage` and run the suite**

Append ` test/lineage/observation-correlation.test.js` to `test:lineage`.
Run: `cd scanner && npm run test:lineage` — PASS, 0 failures, `echo $?` read in
the same turn.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/observation-correlation.js scanner/test/lineage/observation-correlation.test.js scanner/package.json
git commit -m "feat(lineage): add observation-correlation.js — the graph-ID match ladder and the three-valued observation layer (AC-29 clauses 1-4)"
```

---

### Task 3: `scanner/src/lineage/observation-adapters.js` — the adapter interface and the native JSONL adapter

Pure, text-in/drafts-out. Ships the *interface* plus ONE implementation so the
OTLP adapter (increment 2, scoping doc §4.3) is a second implementation of an
already-proven interface rather than the only one.

**Files:**
- Create: `scanner/src/lineage/observation-adapters.js`
- Create: `scanner/test/lineage/observation-adapters.test.js`
- Create: `scanner/test/fixtures/runtime-observations/native-clean.jsonl`
- Create: `scanner/test/fixtures/runtime-observations/native-payload.jsonl`
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `NATIVE_JSONL_RECORD_KEYS` — frozen `['environment', 'attributes', 'eventCountBand', 'firstObservedAt', 'lastObservedAt']`
- `parseNativeJsonlObservations(text, context) -> {drafts, errors}` where
  `context` is `{version, adapter, source, environment, windowStart, windowEnd, importedAt, retention}`
  — note `version` is supplied BY THE CALLER, not read from
  `runtime-observation.js`, precisely because this module is zero-import; the
  CLI passes `RUNTIME_OBSERVATION_VERSION` — and each draft is
  `{version, adapter, source, environment, windowStart, windowEnd, attributes, eventCountBand, firstObservedAt, lastObservedAt, retention, importedAt}`
  — every `RuntimeObservation` field EXCEPT `id`, `matchedNodeIds`,
  `matchedEdgeIds`, `matchedFlowIds`, `matchMethod`, `matchConfidence`, which
  are minted/derived downstream and can never be supplied by the wire.
- `adapterFor(name) -> {name, parse} | null` — the registry lookup. `parse` has
  the `(text, context) -> {drafts, errors}` signature above.

**Interfaces (consumed):** none. **Zero imports** — the adapter shapes, the
contract module validates. Boundary-tested (`AD/6`).

- [ ] **Step 1: Write the two fixtures**

`scanner/test/fixtures/runtime-observations/native-clean.jsonl` — four records,
one per line, no trailing content beyond a final newline:

```
{"attributes":{"destination.host":"api.stripe.com","destination.scheme":"https","tls.version":"1.3"},"eventCountBand":"101-1k","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-30T10:00:00.000Z"}
{"attributes":{"destination.service":"User","schema.attributeNames":["email","created_at"]},"eventCountBand":"11-100","firstObservedAt":"2026-08-03T10:00:00.000Z","lastObservedAt":"2026-08-29T10:00:00.000Z"}
{"environment":"staging","attributes":{"destination.host":"api.stripe.com"},"eventCountBand":"1","firstObservedAt":"2026-08-04T10:00:00.000Z","lastObservedAt":"2026-08-04T10:00:00.000Z"}
{"attributes":{"destination.service":"https://sqs.us-east-1.amazonaws.com/1/orders","network.protocol":"https"},"eventCountBand":"2-10","firstObservedAt":"2026-08-05T10:00:00.000Z","lastObservedAt":"2026-08-06T10:00:00.000Z"}
```

`scanner/test/fixtures/runtime-observations/native-payload.jsonl` — four
records, EACH carrying exactly one different smuggling attempt, so a test can
assert all four are caught:

```
{"attributes":{"destination.host":"api.stripe.com","http.url":"https://api.stripe.com/v1/charges?card=4111111111111111"},"eventCountBand":"1","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-02T10:00:00.000Z"}
{"attributes":{"destination.host":"db.internal","db.statement":"SELECT ssn FROM patients"},"eventCountBand":"1","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-02T10:00:00.000Z"}
{"attributes":{"destination.host":"api.anthropic.com"},"eventCountBand":"1","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-02T10:00:00.000Z","prompt":"the patient's SSN is 123-45-6789"}
{"attributes":{"destination.host":"api.stripe.com"},"eventCountBand":"1","firstObservedAt":"2026-08-02T10:00:00.000Z","lastObservedAt":"2026-08-02T10:00:00.000Z","matchedNodeIds":["node:aaaaaaaaaaaa"],"matchConfidence":"high"}
```

The fourth line is the one nobody would think to test: an operator (or a
compromised exporter) pre-declaring its own match, which would let the wire
dictate what the graph believes was observed. It must be rejected by the
adapter, before validation ever runs.

- [ ] **Step 2: Write the failing test file**

Create `scanner/test/lineage/observation-adapters.test.js`. Cover:

- `AD/1a` `adapterFor('native-jsonl')` returns an object whose `name` is
  `'native-jsonl'` and whose `parse` is a function; `adapterFor('otlp')` and
  `adapterFor(null)` both return `null` — an unimplemented adapter is not
  silently accepted (scoping doc §4.3 defers OTLP to increment 2).
- `AD/2a` The clean fixture parses to exactly 4 drafts and 0 errors.
- `AD/2b` Each draft carries every context field verbatim (`adapter`, `source`,
  `windowStart`, `windowEnd`, `retention`, `importedAt`, `version`).
- `AD/2c` A per-line `environment` overrides the context's default (line 3
  yields `'staging'`); a line without one inherits the context's.
- `AD/2d` **No draft carries any of `id`, `matchedNodeIds`, `matchedEdgeIds`,
  `matchedFlowIds`, `matchMethod`, `matchConfidence`** — assert with
  `for (const k of [...]) assert.equal(k in draft, false)`. These are minted
  downstream; a draft that carried them would let the wire dictate the graph's
  own beliefs.
- `AD/3a` A malformed JSON line yields one `{line, message}` error naming the
  1-based line number, and the other lines still parse. Blank lines and a
  trailing newline are skipped silently, never reported as errors.
- `AD/4a` **The two-layer rejection split, stated once and asserted here.** The
  adapter enforces the WIRE shape (unknown top-level wire key, a pre-declared
  match, a non-scalar attribute value); `validateRuntimeObservation` (Task 1) is
  the single authority on WHICH attribute keys are approved, so the adapter
  never duplicates that allowlist. Against the payload fixture the adapter
  therefore yields **2 errors** (line 3's top-level `prompt`, line 4's
  `matchedNodeIds`) and **2 drafts** (lines 1 and 2, whose attribute keys
  `http.url`/`db.statement` are structurally fine and are rejected one layer up
  — pinned by `CLI/import-4`). Assert exactly `errors.length === 2` and
  `drafts.length === 2`, and add a comment naming `CLI/import-4` as where the
  other two are caught, so a reader does not mistake this for a hole.
- `AD/4b` **Any adapter error means the whole file yields nothing usable.** The
  adapter returns its drafts regardless, but the IMPORT command refuses the
  file whole on `errors.length > 0` — assert here only that both errors carry a
  correct 1-based `line` (3 and 4) and that their messages name `prompt` and
  `matchedNodeIds` respectively, via `assert.match`. The
  refuse-the-whole-import behavior itself is `CLI/import-4`'s to prove.
- `AD/4c` A line with an unknown top-level wire key not in
  `NATIVE_JSONL_RECORD_KEYS` (e.g. `{"attributes":{},"note":"x"}`) is an error
  naming `note`.
- `AD/5a` `parseNativeJsonlObservations('', ctx)` → `{drafts: [], errors: []}`
  — an empty file is an empty import, not a failure.
- `AD/5b` Never throws: `('', null)`, `(null, ctx)`, `(42, ctx)`,
  `('{}', ctx)`, `('null\n', ctx)`, `('[]\n', ctx)`, `('"x"\n', ctx)` all
  return a `{drafts, errors}` shape.
- `AD/5c` A line that is valid JSON but not an object (`[1,2]`, `"x"`, `7`,
  `null`) is one error, not a crash.
- `AD/6a` The module's static import specifier list is exactly `[]`, there is
  no dynamic `import(`, and no `node:fs` anywhere in its source. One step
  stricter than Task 2's, mirroring `flow-grade.js`'s own boundary test.
- `AD/7a` Round-trip against Task 1: for every draft from the clean fixture,
  compose `{...draft, id: observationId(...), ...matchObservationToGraph(graph, draft)}`
  and assert `validateRuntimeObservation` returns `{valid: true, errors: []}`.
  **This is the cross-task signature check** — it fails loudly if the adapter's
  draft shape and the contract's field list drift apart.

- [ ] **Step 3: Run to verify failure**

Run: `cd scanner && node --test test/lineage/observation-adapters.test.js`
Expected: FAIL — module not found.

- [ ] **Step 4: Write `scanner/src/lineage/observation-adapters.js`**

Header comment must record:

- FR-505's own adapter list ("beginning with approved OpenTelemetry
  traces/service graphs, gateway/mesh metadata, cloud flow metadata, and
  application-provided schema-safe events") and the scoping doc §4.3 ruling:
  ship the interface plus a native adapter first, OTLP second. State the
  reason: an OTLP `resourceSpans` document carries an unbounded attribute
  surface (`http.url` with a query string, `db.statement`,
  `messaging.message.payload`, arbitrary `gen_ai.*` prompt/completion
  attributes), and mapping it safely is writing and defending an allowlist
  against an adversarial, evolving semantic-convention surface — its own
  increment with its own review, not bundled into the increment that also
  invents the contract, the correlation, and the store.
- That external evidence arrives as a **file**, never live ingestion — FR-505's
  no-egress rule and the root `CLAUDE.md`'s "no runtime cloud calls"
  convention, and `posture/runtime-correlation.js`'s own proven offline-file
  contract.
- That the wire key set is CLOSED for the same reason the record is
  (`AD/4c`), and that `id`/`matched*`/`matchMethod`/`matchConfidence` are
  refused from the wire specifically so an exporter can never pre-declare what
  the graph believes was observed (`AD/4b`, error 4).
- The exact native-JSONL wire format, as a worked example, so an operator can
  produce one without reading the code.

Implementation notes:

- `parseNativeJsonlObservations(text, context)`: guard `typeof text === 'string'`
  and `context` is a plain object, else `{drafts: [], errors: [{line: 0,
  message: '...'}]}`. Split on `/\r?\n/`, skip lines whose `.trim()` is empty.
  Per line: `JSON.parse` in a `try` (a failure is one error, continue to the
  next line so the operator sees every problem at once, not just the first);
  reject a non-plain-object; sweep `Object.keys` against
  `NATIVE_JSONL_RECORD_KEYS`; require `attributes` to be a plain object,
  `eventCountBand`/`firstObservedAt`/`lastObservedAt` to be non-empty strings.
  **This module does NOT validate attribute KEYS** — it collects them and lets
  `validateRuntimeObservation` reject, so there is exactly one authority on the
  allowlist. What it DOES enforce is the wire shape: `attributes` must be a
  plain object whose every value is a scalar or an array of strings, no
  top-level key outside `NATIVE_JSONL_RECORD_KEYS`, and never an `id`/
  `matched*`/`matchMethod`/`matchConfidence` supplied by the file. That is the
  two-layer split `AD/4a` states and asserts: against the payload fixture this
  module yields 2 errors (lines 3 and 4) and 2 drafts (lines 1 and 2), and the
  IMPORT command (`CLI/import-4`) is what refuses the file whole. JSONL admits
  no comment line, so record the split in the TEST file's own header comment,
  never in the fixture.
- `errors` entries are `{line, message}` with `line` 1-based.
- `adapterFor(name)`: a frozen module-level object keyed by adapter name;
  return `null` for anything unknown, never a default.

- [ ] **Step 5: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/observation-adapters.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 6: Wire the test file into `test:lineage` and run the suite**

Append ` test/lineage/observation-adapters.test.js` to `test:lineage`.
Run: `cd scanner && npm run test:lineage` — PASS, `echo $?` read in the same turn.

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/observation-adapters.js scanner/test/lineage/observation-adapters.test.js scanner/test/fixtures/runtime-observations/ scanner/package.json
git commit -m "feat(lineage): add observation-adapters.js — the adapter interface and the native JSONL adapter"
```

---

### Task 4: `scanner/src/lineage/observation-store.js` — the import-keyed store, plus four artifact-registry fixes

The impure layer. A directory of independently-readable, immutable whole files
— `graph-snapshot.js`'s physical shape, re-keyed commit → import. **No lock**
(imports are independent files, there is no read-fold-validate-write critical
section), **no hash chain** (there is no state machine to protect, and a chain
makes the retention FR-505 requires structurally impossible).

**Files:**
- Create: `scanner/src/lineage/observation-store.js`
- Create: `scanner/test/lineage/observation-store.test.js`
- Modify: `scanner/src/posture/artifact-registry.js`
- Modify: `scanner/test/artifact-registry.test.js`
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `OBSERVATION_STORE_DIR` — the literal `'runtime-observations'`, exported for
  readers, **never passed to `statePath`** (Correction 6)
- `OBSERVATION_IMPORT_VERSION` — `'1.0.0'`
- `observationsDir(scanRoot) -> string`
- `importFileName(importId) -> string | null`
- `validateObservationImport(record) -> {valid, errors}`
- `persistObservationImport(scanRoot, importRecord) -> {ok, path, reason}`
- `loadObservationImports(scanRoot) -> importRecord[]` (newest first by mtime; never throws)
- `loadObservationImport(scanRoot, importId) -> importRecord | null` (never throws)
- `loadObservations(scanRoot) -> RuntimeObservation[]` (flattened across imports, deduplicated by `id`, sorted by `id`)
- `deleteObservationImport(scanRoot, importId) -> boolean`

Import record shape:
```js
{ id, version, adapter, source, environment, windowStart, windowEnd, importedAt, retention, observations: [...] }
```

**Interfaces (consumed):** `statePath`, `isSafeStateDir`, `stateWritesEnabled`
from `../posture/state-dir.js`; `maybeEncryptForWrite`, `maybeDecryptForRead`
from `../posture/encryption-provider.js`; `validateRuntimeObservation` from
`./runtime-observation.js`; `node:fs`, `node:path`.

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/observation-store.test.js`. Use a real temp
project directory — `fs.mkdtempSync(path.join(os.tmpdir(), 'agsec-obs-store-'))`
plus a `package.json` marker so `isSafeStateDir` passes — the same
temp-project helper shape `test/cli/governance-propose-edit.test.js` uses.
Clean up in a `finally`.

Cover:

- `OS/1a` `observationsDir` resolves to
  `<root>/.agentic-security/runtime-observations`, via `statePath`, never a
  hand-joined string.
- `OS/1b` **The registry-guard shape**: read `observation-store.js`'s own
  source and assert it contains the literal
  `statePath(scanRoot, 'runtime-observations')`, and that `OBSERVATION_STORE_DIR`
  is never the second argument of a `statePath(` call. This is the exact
  bypass that let `runtime-trace.jsonl` go unregistered
  (`artifact-registry-completeness.test.js`'s `PATTERNS` need a quoted literal),
  and `graph-snapshot.js:36` still has it.
- `OS/2a` `loadObservationImports` on a missing directory returns `[]`, never
  throws. `loadObservations` likewise. `loadObservationImport` returns `null`.
- `OS/3a` Round trip: persist one import with two observations, then
  `loadObservationImports` returns exactly one record, deep-equal to what was
  written; `loadObservations` returns both observations, sorted by `id`.
- `OS/3b` Two imports are two files, both readable, and `loadObservations`
  returns the union deduplicated by `id` — persist two imports that share one
  observation id and assert the flattened list has it once.
- `OS/3c` `loadObservationImports` is newest-first by mtime. Persist two,
  touching the second's mtime forward, and assert the order.
- `OS/4a` **Immutability + retention**: `deleteObservationImport` removes
  exactly one file, leaves every sibling intact, and returns `true`; a second
  call returns `false`. **This is the property an append-only hash chain could
  not provide** — say so in the test's assertion message, citing FR-505's own
  "Observation stores follow artifact encryption, retention, reset,
  access-control, and no-egress rules."
- `OS/5a` `importFileName('obsimport:0123456789ab')` is `'0123456789ab.json'`
  — the `obsimport:` prefix is stripped, because a colon is not a portable
  filename character.
- `OS/5b` `importFileName` returns `null` for `null`, `''`, `'obsimport:'`,
  `'snapshot:0123456789ab'`, `'obsimport:XYZ'`, `'obsimport:0123456789abc'`.
- `OS/5c` **Path-traversal refusal** (Correction 5):
  `loadObservationImport(root, '../../../etc/passwd')` and
  `loadObservationImport(root, 'obsimport:../../x')` both return `null` and
  read no file — assert with a spy or by confirming a planted file outside the
  store is not returned. `deleteObservationImport` refuses the same inputs and
  returns `false` without unlinking anything.
- `OS/6a` `persistObservationImport` refuses when
  `isSafeStateDir(observationsDir(root))` is false (a temp dir with no project
  marker): `{ok: false, reason}` naming the refusal, and **no
  `.agentic-security/` directory is created** — assert
  `fs.existsSync(path.join(root, '.agentic-security')) === false`.
- `OS/6b` `persistObservationImport` refuses when `stateWritesEnabled()` is
  false — use `setStateWritesEnabled(false)` inside a `try/finally` that
  restores it.
- `OS/7a` `persistObservationImport` REFUSES an import whose record fails
  `validateObservationImport` — including one whose `observations[]` contains a
  record failing `validateRuntimeObservation` — and writes nothing. Assert
  `loadObservationImports(root).length === 0` afterwards. **The store is the
  last line of defense: no path exists by which an unvalidated observation
  reaches disk.**
- `OS/7b` `validateObservationImport` is closed-world at the import level too:
  an unknown top-level key on the import record is an error. Assert with
  `{...import, rawTrace: '...'}`.
- `OS/8` **The AC-29 clause 5 artifact-level proof, end to end**: persist an
  import built from the clean fixture, then read the file back off disk as raw
  bytes and assert the text contains none of the substrings
  `'payload'`, `'prompt'`, `'response'`, `'SELECT'`, `'4111111111111111'`,
  `'123-45-6789'`, `'http.url'`, `'db.statement'`. Then attempt to persist an
  import built from the payload fixture's drafts and assert it is REFUSED and
  the store is unchanged. Assert the raw-bytes check in both directions so it
  is not vacuous.
- `OS/9a` Encryption wiring (Correction 1): with no
  `.agentic-security/encryption-policy.yml`, `persistObservationImport` writes
  plaintext JSON and `loadObservationImports` round-trips it. With
  `{provider: 'local-key'}` configured, the file on disk is an encrypted
  envelope (`isEncryptedEnvelope(JSON.parse(raw)) === true`) and
  `loadObservationImports` still round-trips the plaintext record. Assert both.
  **Without this test, `confidential: true` in the registry is a claim nothing
  backs.**
- `OS/9b` With `{provider: null, required: true}` configured,
  `persistObservationImport` returns `{ok: false, reason}` and writes nothing —
  `maybeEncryptForWrite`'s own fail-closed branch, surfaced rather than
  swallowed.
- `OS/10a` A corrupt file in the store directory (invalid JSON, or a
  non-`.json` file) is skipped by `loadObservationImports` — the other imports
  still load, and nothing throws. Mirrors `loadSnapshots`'s own tolerance.
- `OS/10b` An import file whose content fails `validateObservationImport` on
  read is skipped and never returned. A file nobody validated on write (planted
  by hand) must not become trusted by being on disk.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/observation-store.test.js`
Expected: FAIL — module not found.

- [ ] **Step 3: Write `scanner/src/lineage/observation-store.js`**

Header comment must record:

- The storage ruling and the three rejected candidates, with the real reason
  for each (scoping doc §4.4 / Correction 6): `GraphSnapshot`'s commit-keying
  cannot express many observations per graph entity;
  `posture/provenance/lifecycle.js` rewrites its whole document on every update
  and is registered with a **deliberate** no-`retentionClass` policy;
  `posture/remediation-ledger.js`'s locked hash chain solves a
  read-fold-validate-write problem that does not exist here, and its chain
  makes deletion structurally impossible — an append-only hash chain and a
  retention-and-reset requirement are directly opposed. Then state the choice:
  `lineage-snapshots/`'s directory-of-immutable-files, re-keyed commit →
  import.
- That there is **no lock** and why (imports are independent whole files; the
  only concurrency hazard a lock would address is two writers targeting one
  file, and `observationImportId` includes `importedAt`, so two imports never
  collide).
- That `statePath` is called with a **string literal** at every site, and why
  (`artifact-registry-completeness.test.js`'s `PATTERNS` needs a literal;
  `graph-snapshot.js:36` escapes the guard and is registered only because
  someone remembered).
- That `maybeEncryptForWrite`/`maybeDecryptForRead` are called explicitly,
  because `confidential: true` in the registry is a declaration that does
  nothing on its own — the only two confidential artifacts in the tree today
  (`compliance-evidence.json`/`.md`) each call it from their own writer
  (`posture/compliance-policy.js:497`/`:546`). Cite Correction 1.
- That `loadObservationImport` validates its key shape before any `path.join`,
  and that `graph-snapshot.js`'s `loadSnapshot` does not — a disclosed
  pre-existing gap this module deliberately does not inherit and deliberately
  does not fix elsewhere.

Implementation notes:

- `function observationsDir(scanRoot) { return statePath(scanRoot, 'runtime-observations'); }`
  — the literal, verbatim, in this one place. `OBSERVATION_STORE_DIR` is
  exported as a separate `const` for readers and asserted never to be
  `statePath`'s second argument.
- `importFileName(importId)`: return `null` unless
  `/^obsimport:[0-9a-f]{12}$/.test(importId)`; else
  `` `${importId.slice('obsimport:'.length)}.json` ``.
- `validateObservationImport(record)`: same `{valid, errors}`/`[{path, message}]`
  shape and same closed-world discipline as `validateRuntimeObservation` —
  closed top-level key set
  `['id','version','adapter','source','environment','windowStart','windowEnd','importedAt','retention','observations']`,
  `id` prefixed `obsimport:`, `observations` an array, and **every** element
  routed through `validateRuntimeObservation` with its errors re-pathed to
  `$.observations[i].<path>`. Never throws.
- `persistObservationImport(scanRoot, importRecord)`: (1) validate — invalid ⇒
  `{ok:false, reason}` with the errors summarized, nothing written; (2)
  `stateWritesEnabled()` ⇒ `{ok:false, reason:'state writes are disabled'}`;
  (3) `isSafeStateDir(observationsDir(scanRoot))` ⇒ `{ok:false, reason}`;
  (4) `importFileName(importRecord.id)` ⇒ `{ok:false, reason}` when null;
  (5) `maybeEncryptForWrite(scanRoot, 'runtime-observations', JSON.stringify(importRecord, null, 2))`
  ⇒ propagate `{ok:false, reason}` verbatim; (6) `fs.mkdirSync(dir, {recursive:true})`
  then `fs.writeFileSync(full, gated.content)`, both inside one `try` whose
  `catch` returns `{ok:false, reason}` (never a swallowed
  `try {} catch {}` — `persistGraphSnapshot:122-123` swallows, and an import the
  operator asked for must report its own failure); (7) `{ok:true, path: full}`.
- `loadObservationImports(scanRoot)`: mirror `loadSnapshots:130-147` exactly —
  `existsSync` guard, `readdirSync` filtered to `.json`, mtime sort descending,
  then per file `maybeDecryptForRead(fs.readFileSync(full,'utf8'))` →
  `JSON.parse` → `validateObservationImport`, pushing only valid records, every
  step inside its own `try {} catch {}`. Never throws.
- `loadObservationImport(scanRoot, importId)`: `importFileName` guard first,
  then the same read/decrypt/parse/validate path. Never throws.
- `loadObservations(scanRoot)`: flatten `loadObservationImports`'s
  `observations` arrays into a `Map` keyed by `id` (first write wins — the
  newest import's copy, since the list is newest-first), then return
  `[...map.values()].sort((a,b) => a.id < b.id ? -1 : 1)`.
- `deleteObservationImport(scanRoot, importId)`: `importFileName` guard, then
  `fs.unlinkSync` inside a `try`, returning `true`/`false`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/observation-store.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 5: Register the four artifacts**

In `scanner/src/posture/artifact-registry.js`, add ONE entry to the
**generated** section (near the `lineage-snapshots` entry at `:104`, whose
shape this one deliberately echoes):

```js
  // M5 deliverable #7 (FR-505 §7.12, AC-29): the Runtime-Corroborated Digital
  // Twin's observation store — one immutable whole file per adapter import,
  // written by src/lineage/observation-store.js's persistObservationImport(),
  // mirroring lineage-snapshots/'s own directory-of-files shape re-keyed
  // commit -> import.
  { name: 'runtime-observations', kind: 'dir', classification: 'generated', retentionClass: 'evidence', confidential: true, source: 'src/lineage/observation-store.js (persistObservationImport)', note: 'FR-505 requires an observation store follow artifact encryption, RETENTION, RESET, access-control and no-egress rules. That is why this is `generated` (a plain `reset` MUST be able to delete it) rather than `operator-config`, and why it carries a real retentionClass — deliberately NOT the `remediation`/`legal-holds.json` no-retention call one section down, and deliberately NOT `provenance`\'s permanent-history call. This DOES stretch `generated`\'s usual definition — a rescan does not re-derive an import, the operator re-imports it — and that stretch is disclosed here rather than hidden: FR-505\'s explicit reset requirement breaks the tie. `confidential: true` is enforced by observation-store.js calling maybeEncryptForWrite/maybeDecryptForRead itself (posture/encryption-provider.js), the same per-writer opt-in compliance-evidence.json makes — the flag alone enforces nothing.' },
```

And add THREE entries to the **operator-config** section (Correction 7 — the
scoping doc named only the first; `posture/runtime-correlation.js`'s real
`DEFAULT_TRACE_NAMES` is all three):

```js
  // Pre-existing gap, found by M5 deliverable #7's own scoping investigation
  // and fixed here rather than left: posture/runtime-correlation.js reads
  // these three filenames via `statePath(scanRoot, n)` with a VARIABLE, so
  // test/artifact-registry-completeness.test.js's own PATTERNS regexes (which
  // require a string literal) never saw them and never demanded registration.
  // An unregistered state artifact means `reset` does not know about it and
  // retention cannot reach it. Operator-config, not generated: these are
  // hand-supplied eBPF/APM trace exports the scanner only ever reads.
  { name: 'runtime-trace.jsonl', kind: 'file', classification: 'operator-config', note: 'eBPF/APM runtime trace consumed by posture/runtime-correlation.js#loadTrace — operator-supplied, never scanner-written; $AGENTIC_SECURITY_RUNTIME_TRACE_PATH overrides the location entirely' },
  { name: 'runtime.jsonl', kind: 'file', classification: 'operator-config', note: 'alternate filename for runtime-trace.jsonl — see posture/runtime-correlation.js\'s DEFAULT_TRACE_NAMES' },
  { name: 'ebpf-trace.jsonl', kind: 'file', classification: 'operator-config', note: 'alternate filename for runtime-trace.jsonl — see posture/runtime-correlation.js\'s DEFAULT_TRACE_NAMES' },
```

Then add to `scanner/test/artifact-registry.test.js`, following that file's
existing conventions (read it first):

- `OS/reg-1` `runtime-observations` is registered, `classification: 'generated'`,
  `retentionClass: 'evidence'`, `confidentialOf('runtime-observations') === true`.
- `OS/reg-2` A real `reset` genuinely deletes a populated
  `.agentic-security/runtime-observations/` directory. Follow the existing
  lineage-artifact reset regression test in that file (added when
  `lineage-graph.json` had the same gap) — **prove it live, do not assert the
  registry row and stop.**
- `OS/reg-3` All three runtime-trace filenames are registered as
  `operator-config` and a real `reset` does NOT delete them.

- [ ] **Step 6: Run the affected suites**

Run: `cd scanner && node --test test/artifact-registry.test.js test/artifact-registry-completeness.test.js test/lineage/observation-store.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 7: Prove the completeness guard would have caught a mistake**

Temporarily remove the `runtime-observations` registry entry and run
`node --test test/artifact-registry-completeness.test.js`. Expected: FAIL,
naming `runtime-observations`. Restore, re-run, confirm PASS. Record the
transcript. This is the direct proof that Correction 6's string-literal
discipline is doing real work.

- [ ] **Step 8: Wire the test file into `test:lineage` and run the suites**

Append ` test/lineage/observation-store.test.js` to `test:lineage`.
Run: `cd scanner && npm run test:lineage && npm run test:posture && npm run test:lifecycle`
Expected: PASS, 0 failures, all three. Capture `echo $?`.

- [ ] **Step 9: Commit**

```bash
git add scanner/src/lineage/observation-store.js scanner/test/lineage/observation-store.test.js scanner/src/posture/artifact-registry.js scanner/test/artifact-registry.test.js scanner/package.json
git commit -m "feat(lineage): add observation-store.js — the import-keyed observation store; register it and the three pre-existing runtime-trace artifacts"
```

---

### Task 5: `opts.correlateObservations` — the additive graph hook and its single-load wiring

The fifth hook of an established shape. Byte-identical when omitted, proven the
same way `M2A1/hook-1` proved it for `resolveDestination`.

**Files:**
- Modify: `scanner/src/lineage/graph-builder.js`
- Modify: `scanner/src/lineage/coverage.js`
- Modify: `scanner/src/lineage/index.js`
- Create: `scanner/test/lineage/runtime-corroboration-wiring.test.js`
- Modify: `scanner/package.json` (`test:lineage`)

**Interfaces (produced):**
- `buildDataFlowGraph`'s new `opts.correlateObservations(graph) -> correlationResult | undefined`
- `graph.runtimeCorroboration` — assigned **only** when the hook returns truthy
- `buildGraphWithCoverage`'s new `opts.runtimeObservations` (a pre-loaded
  `RuntimeObservation[]`, or `undefined` meaning "no store consulted"),
  `opts.observationWindowStart`, `opts.observationWindowEnd`
- `buildLineageGraph`'s new `opts.observationWindowStart`/`opts.observationWindowEnd`

**Interfaces (consumed):** `correlateObservations` from
`./observation-correlation.js` (Task 2); `loadObservations` from
`./observation-store.js` (Task 4); `statePath` from
`../posture/state-dir.js` (already imported by `index.js`).

- [ ] **Step 1: Write the failing test file**

Create `scanner/test/lineage/runtime-corroboration-wiring.test.js`. Build real
graphs with `buildGraphWithCoverage` over parsed JS/TS (`parseJsFile` +
`buildCallGraph`), following `test/lineage/coverage.test.js`'s own fixture
shape. Cover:

- `WIRE/1` The hook fires exactly once per build, and receives a graph whose
  `nodes`/`edges`/`flows`/`dataElements` are already populated — assert the
  arrays are non-empty inside the hook. This is the `buildRecipientProfile`
  fix-round-1 B2 placement lesson applied: a hook that runs earlier gets an
  empty envelope.
- `WIRE/2` The hook's return value lands verbatim on
  `graph.runtimeCorroboration` (`assert.deepEqual` against a sentinel object).
- `WIRE/3` **Byte-identical when omitted** (Correction 10): build the same
  callGraph twice, once with no `correlateObservations` and no
  `runtimeObservations`, once with the hook returning `undefined`. Assert
  `JSON.stringify(a) === JSON.stringify(b)` and that
  `'runtimeCorroboration' in graph === false` in both. **The key must be
  genuinely ABSENT, not `null`.**
- `WIRE/4` `buildGraphWithCoverage` with `opts.runtimeObservations = undefined`
  installs no default hook — `'runtimeCorroboration' in graph === false`.
  With `opts.runtimeObservations = []`, a result IS produced with
  `evaluated: true` and every flow `not_observed_in_window`. **This is the
  `privacySinkPolicy` `undefined`-vs-`[]` precedent applied to observations**
  (`index.js:129-150`), and it is what keeps AC-29 clause 2's
  `not_evaluated`/`not_observed_in_window` distinction alive at the wiring
  layer, not just inside Task 2.
- `WIRE/5` A caller-supplied `opts.correlateObservations` always wins over the
  default built from `opts.runtimeObservations` — the composition contract
  every sibling hook in `coverage.js` already honors.
- `WIRE/6` `opts.environment`/`opts.observationWindowStart`/
  `opts.observationWindowEnd` reach `correlateObservations`'s `opts` verbatim —
  assert on `graph.runtimeCorroboration.environment`/`.windowStart`/`.windowEnd`.
  Note `opts.environment` is ALREADY consumed by the policy-verdict path
  (`graph-builder.js`, Sub-project G) and is deliberately shared, not
  duplicated.
- `WIRE/7` `validateGraph(graph)` returns zero errors with
  `runtimeCorroboration` present — the extension is attached to the graph
  object and never routed through the validator, exactly like
  `graph.recipientProfiles`. Also run
  `node --test test/lineage/json-schema-parity.test.js` in Step 4 and confirm
  it needed no change.
- `WIRE/8` `index.js`'s single-load discipline, proven live, not architected:
  wrap `loadObservations` in a counting `Proxy` (or monkey-patch the module's
  export via a test-local import shim, following
  `test/lineage/transit-protection.test.js`'s `B2/8` Proxy pattern) and assert
  it is called **exactly once** per `buildLineageGraph` call. `coverage.js` and
  `graph-builder.js` must never read the store themselves.
- `WIRE/9` `buildLineageGraph` with no `.agentic-security/runtime-observations/`
  directory on disk produces a graph with `'runtimeCorroboration' in graph ===
  false` — `not_evaluated` expressed by absence at the top level, matching the
  `privacySinkPolicy` gate. With an EMPTY store directory present, a result IS
  produced with `evaluated: true`. Assert both against a real temp project.
- `WIRE/10` End-to-end, the AC-29 scenario over REAL parsed code: a fixture
  with two external sinks (`fetch('https://api.stripe.com/v1/charges', ...)`
  and `fetch('https://api.other.example/v1/notify', ...)`), one persisted
  import observing only the first host. Assert one flow reads
  `runtime_observed` and the other `not_observed_in_window`, both nodes are
  still in `graph.nodes`, and every flow appears in `byFlow`. **This is
  `OC/6a` promoted from a hand-built graph to real scanned code.**

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/lineage/runtime-corroboration-wiring.test.js`
Expected: FAIL.

- [ ] **Step 3: Edit `scanner/src/lineage/graph-builder.js`**

Add the hook immediately AFTER the
`graph.recipientProfiles = [...recipientProfilesById.values()].sort(byId);`
line and BEFORE `graph.coverage = {...}`:

```js
  // M5 deliverable #7 (FR-505 §7.12, AC-29): a FIFTH additive hook of the
  // identical shape — `opts.correlateObservations(graph) -> correlationResult
  // | undefined`. Runs here, after nodes/edges/flows/dataElements AND
  // recipientProfiles are populated, for the same reason
  // `opts.buildRecipientProfile` was moved here in its own fix round: the hook
  // reads the real, finished graph, never a still-empty envelope.
  //
  // Assigned ONLY when the hook returns truthy — `graph.runtimeCorroboration`
  // is genuinely ABSENT otherwise, never `null` and never `{}`. That is what
  // makes the output byte-identical to a build with no hook at all (the
  // contract `M2A1/hook-1` proved for `resolveDestination`), and it is also
  // AC-29 clause 2's `not_evaluated` state expressed at the top level: a graph
  // with no `runtimeCorroboration` key was never evaluated against any
  // observation store, which is a DIFFERENT answer from a graph that was
  // evaluated and found nothing in the window (PRD line 2098 — non-observation
  // is never non-occurrence).
  //
  // Deliberately does NOT touch `edge.provenance`, which stays `'code'` on
  // every edge. Corroboration is ADDITIVE: an observed edge is still a
  // code-derived edge that was ALSO observed. Flipping `edge.provenance` needs
  // a deliberate provenance-partitioning pass through impact-engine.js,
  // decision-story.js, obligation-predicates.js and the export family first —
  // that is M2 Sub-project F2/F3's job, not this one's. See the M5 #7 scoping
  // doc §4.5 and §3's "edge.provenance has zero consumers" finding.
  if (typeof opts.correlateObservations === 'function') {
    const corroboration = opts.correlateObservations(graph);
    if (corroboration) graph.runtimeCorroboration = corroboration;
  }
```

Also extend this file's header comment block (which already documents the four
existing hooks at `:30`, `:43`, `:67` and the `buildRecipientProfile` note) with
a fifth paragraph naming `opts.correlateObservations` and its
byte-identical-when-omitted contract.

- [ ] **Step 4: Edit `scanner/src/lineage/coverage.js`**

Add the import and the composed default. Inside `buildGraphWithCoverage`'s
`buildDataFlowGraph(callGraph, {...})` call, alongside the sibling hooks:

```js
    // M5 deliverable #7 (FR-505/AC-29): identical composition pattern — a
    // caller-supplied hook always wins. The default is installed ONLY when
    // `opts.runtimeObservations` is genuinely defined; when it is `undefined`
    // (no store on disk, per index.js's own existsSync gate) NO hook is
    // installed at all, so `graph.runtimeCorroboration` stays absent and reads
    // as `not_evaluated`. This is exactly the `undefined`-vs-`[]` distinction
    // `opts.privacySinkPolicy` already draws for a missing privacy-policy.json,
    // and collapsing the two would make "we never looked" indistinguishable
    // from "we looked and saw nothing" — PRD line 2098's own prohibition.
    correlateObservations: opts.correlateObservations
      ?? (opts.runtimeObservations !== undefined
        ? ((graph) => correlateObservations(graph, opts.runtimeObservations, {
          environment: opts.environment ?? null,
          windowStart: opts.observationWindowStart ?? null,
          windowEnd: opts.observationWindowEnd ?? null,
        }))
        : undefined),
```

Add `import { correlateObservations } from './observation-correlation.js';` at
the top, and JSDoc for the three new `opts` fields on
`buildGraphWithCoverage` mirroring `opts.recipientConfig`'s own wording
("a PRE-LOADED array, never a path — the read happens once, upstream, in
`index.js`").

**Note:** `test/lineage/coverage.test.js`'s reuse-boundary test (`C1/10`) reads
`coverage.js`'s own import list. It will need `'./observation-correlation.js'`
added to its expected set — a necessary consequence, exactly as
`transit-protection.js` was when Sub-project B landed. Update it in this step.

- [ ] **Step 5: Edit `scanner/src/lineage/index.js`**

Add the import and the single load, alongside the existing single-load block
for `privacySinkPolicy`/`recipientConfig`:

```js
    // M5 deliverable #7 (FR-505/AC-29): the operator's runtime-observation
    // store, loaded exactly ONCE here — the same single-computation discipline
    // scanTransitEvidence and loadPrivacySinkPolicy already follow. Existence
    // is checked EXPLICITLY, exactly like privacySinkPolicy and for the
    // identical reason: `loadObservations` returns the same empty array whether
    // the store directory is missing or present-and-empty, and those are two
    // DIFFERENT answers under AC-29 clause 2. A MISSING store must leave
    // `graph.runtimeCorroboration` absent (`not_evaluated` — nothing was
    // consulted); a PRESENT-but-empty store must produce a real correlation
    // result whose every flow reads `not_observed_in_window` (a store WAS
    // consulted and the window genuinely contained nothing). PRD line 2098:
    // absence of observation is never non-occurrence.
    const _observationsDir = opts.scanRoot ? statePath(opts.scanRoot, 'runtime-observations') : null;
    const runtimeObservations = _observationsDir && fs.existsSync(_observationsDir)
      ? loadObservations(opts.scanRoot)
      : undefined;
```

Note the string literal `'runtime-observations'` — the second registry-guard
call site (Correction 6). Thread `runtimeObservations`,
`observationWindowStart: opts.observationWindowStart`, and
`observationWindowEnd: opts.observationWindowEnd` into the
`buildGraphWithCoverage(callGraph, {...})` call, and document all three in this
function's JSDoc block.

- [ ] **Step 6: Run the test to verify it passes**

Run: `cd scanner && node --test test/lineage/runtime-corroboration-wiring.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 7: Prove the byte-identical contract has not regressed anything**

Run: `cd scanner && npm run test:lineage`
Expected: PASS, 0 failures — in particular `graph-builder.test.js`,
`coverage.test.js`, `flagship-fixture.test.js`, `json-schema-parity.test.js`,
`export-json.test.js`, `export-csv.test.js`, `redact-graph.test.js`,
`protection-summary.test.js` and `ac01-multi-sink.test.js` must all be
untouched. **If any of them moved, the hook is not additive** — stop and find
out why rather than updating the assertion.

Then: `cd scanner && npm run bench:protection-verdict:check && echo "EXIT:$?"`
Expected: exit 0. This bench builds real graphs through
`buildGraphWithCoverage`; a non-additive change surfaces here.

- [ ] **Step 8: Wire the test file into `test:lineage` and commit**

Append ` test/lineage/runtime-corroboration-wiring.test.js` to `test:lineage`.

```bash
git add scanner/src/lineage/graph-builder.js scanner/src/lineage/coverage.js scanner/src/lineage/index.js scanner/test/lineage/runtime-corroboration-wiring.test.js scanner/test/lineage/coverage.test.js scanner/package.json
git commit -m "feat(lineage): wire opts.correlateObservations — additive runtime corroboration on the built graph, byte-identical when omitted"
```

---

### Task 6: CLI (`dataflow observations import|list`, `dataflow twin`) and the disclosure docs

The AC-29 proof surface, plus the disclosure obligation the scoping doc's §4.7
ruling creates.

**Files:**
- Modify: `scanner/bin/agentic-security.js`
- Create: `scanner/test/cli/dataflow-observations.test.js`
- Modify: `commands/dataflow.md`
- Modify: `commands/secure.md`
- Modify: `scanner/src/lineage/CLAUDE.md`
- Modify: `scanner/package.json` (`test:mcp` — see Step 8)
- Modify: `scanner/dist/agentic-security.mjs` + sidecar (via `npm run build`)

**Interfaces (produced):**
- `agentic-security dataflow observations import [path] --adapter native-jsonl --input <file> [--source <name>] [--environment <name>] [--window-start <iso>] [--window-end <iso>] [--retain-until <iso>] [--yes]`
- `agentic-security dataflow observations list [path] [--json]`
- `agentic-security dataflow twin [path] --output <file> [--format json|markdown] [--environment <name>] [--window-start <iso>] [--window-end <iso>]`

**Interfaces (consumed):** `loadSignedGraph` (`../src/server/graph-loader.js`),
`adapterFor` (Task 3), `observationId`/`observationImportId` (Task 1),
`validateRuntimeObservation` (Task 1), `matchObservationToGraph`/
`correlateObservations` (Task 2), `persistObservationImport`/
`loadObservationImports`/`loadObservations` (Task 4), `auditCall`
(`../src/mcp/audit.js`), `isSafeStateDir` (`../src/posture/state-dir.js`).

- [ ] **Step 1: Write the failing CLI test file**

Create `scanner/test/cli/dataflow-observations.test.js`, following
`test/cli/governance-propose-edit.test.js`'s own subprocess shape (spawn the
real `bin/agentic-security.js` with `node`, in a real temp project with a
`package.json` marker and a real signed `lineage-graph.json` produced by a
`AGENTIC_SECURITY_LINEAGE_DEEP=1` scan of a small fixture). Cover:

- `CLI/import-1` Dry run (no `--yes`): exit 0, stdout names the adapter, the
  record count, the environment and the window, the store on disk is
  **unchanged** (`loadObservationImports(root).length === 0`), and
  `mcp-audit.log` gained **no** entry.
- `CLI/import-2` `--yes`: exit 0, exactly one import file appears under
  `.agentic-security/runtime-observations/`, and `mcp-audit.log` gained exactly
  one entry with `tool: 'dataflow_observations_import'` and `outcome: 'ok'`.
- `CLI/import-3` The persisted observations carry real `matchedNodeIds` derived
  from the signed graph — assert at least one is non-empty and every persisted
  record passes `validateRuntimeObservation`.
- `CLI/import-4` **The payload fixture is refused whole**: exit 1, stderr names
  every offending record with its 1-based index and its offending key
  (`http.url`, `db.statement`, `prompt`, `matchedNodeIds`), the store is
  unchanged, and `mcp-audit.log` gained no entry. Assert
  `loadObservationImports(root).length === 0` explicitly — **a partial import
  that silently drops the offending record is the exact AC-29 clause 5 failure
  this test exists to prevent.**
- `CLI/import-5` A missing `--adapter`, an unknown `--adapter otlp`, a missing
  `--input`, and a nonexistent `--input` path each exit 2 with an actionable
  message and write nothing.
- `CLI/import-6` `--window-start` after `--window-end` exits 2.
- `CLI/import-7` No `lineage-graph.json` on disk exits 1 with
  `loadSignedGraph`'s own "missing" message — correlation needs a graph to
  correlate against, and importing observations that match nothing would be
  silently useless.
- `CLI/import-8` Re-running the same import with `--yes` writes a SECOND import
  file (immutable store, `importedAt` in the id) and `loadObservations`
  deduplicates the observations by id to the original count.
- `CLI/list-1` `observations list` with an empty store prints an honest "no
  imports" line, exit 0. With two imports, prints one row per import naming
  adapter, source, environment, window, observation count, and importedAt.
- `CLI/list-2` **`observations list` never prints an attribute VALUE.** Import
  a record whose `destination.host` is a distinctive sentinel
  (`sentinel-host.example`), run `list`, and assert the sentinel does not
  appear in stdout. Then assert it DOES appear in the raw store file, so the
  test is not vacuous.
- `CLI/twin-1` **AC-29 clause 3**: every flow in the graph appears in the
  output regardless of layer. Assert
  `Object.keys(out.byFlow).length === graph.flows.length`.
- `CLI/twin-2` **AC-29 clauses 1 and 4**: the observed flow's entry reads
  `layer: 'runtime_observed'`, and the markdown output contains the literal
  string `RUNTIME OBSERVED` plus that flow's match method, match confidence,
  environment and window.
- `CLI/twin-3` **AC-29 clause 2**: the unobserved flow's entry reads
  `not_observed_in_window`, and the markdown contains an explicit sentence
  stating that this means the flow was not observed in the selected window and
  **not** that it does not occur. Assert on the sentence.
- `CLI/twin-4` With no store on disk at all, every flow reads `not_evaluated`
  and the markdown says no observation store was consulted — a different
  output from `CLI/twin-3`'s. `assert.notEqual` the two markdown bodies.
- `CLI/twin-5` `--environment staging` narrows: a production-only observation
  no longer marks its flow observed, and the result's own `environment` field
  echoes `'staging'`.
- `CLI/twin-6` Exit codes: missing `--output` → 2; unknown `--format` → 2;
  no `lineage-graph.json` → 1; success → 0.
- `CLI/twin-7` `dataflow twin` writes NOTHING into `.agentic-security/` — it is
  a read-only report. Snapshot the state directory before and after.
- `CLI/isSafe-1` `observations import --yes` pointed at a directory with no
  project marker exits 2 and creates no `.agentic-security/` directory.

- [ ] **Step 2: Run to verify failure**

Run: `cd scanner && node --test test/cli/dataflow-observations.test.js`
Expected: FAIL — unknown subcommand.

- [ ] **Step 3: Add `cmdDataflowObservationsImport` to `scanner/bin/agentic-security.js`**

Place it immediately after `cmdDataflowImpactAssess` (around line 4372),
mirroring that function's own structure and its exit-code contract.

Order of operations, and it is load-bearing:

1. Resolve `targetAbs` from `args._[3] || '.'` (`args._ = ['dataflow',
   'observations', 'import', <path>?]`).
2. Argument validation → exit 2: `--adapter` present and
   `adapterFor(adapter) !== null`; `--input` present and the file exists;
   `--window-start`/`--window-end` both parse as ISO date-times and
   `start <= end`; `--retain-until`, when given, parses.
3. `loadSignedGraph(targetAbs)` → exit 1 with `loaded.message` on failure.
4. Read the input file; run `adapterFor(adapter).parse(text, context)` where
   `context = {adapter, source: args.flags.source ?? path.basename(inputPath),
   environment: args.flags.environment ?? 'unspecified', windowStart, windowEnd,
   importedAt: new Date().toISOString(), retention: {expiresAt: retainUntil ?? null},
   version: RUNTIME_OBSERVATION_VERSION}`.
5. **Any adapter error ⇒ exit 1**, printing every `{line, message}`. Nothing is
   written.
6. Per draft, in order: `matchObservationToGraph(loaded.graph, draft)` → merge;
   mint `observationId({adapter, environment: draft.environment, windowStart,
   windowEnd}, [<canonical attribute fingerprint>])` where the fingerprint is
   `Object.entries(draft.attributes).sort().map(([k,v]) => k + '=' + JSON.stringify(v)).join('&')`;
   then `validateRuntimeObservation(record)`.
7. **Any invalid record ⇒ exit 1**, printing the record's 1-based index and
   every `{path, message}`. Nothing is written, no audit event. Say in the
   message that the import is refused as a whole, deliberately, so a partial
   import can never silently drop the offending record.
8. Build the import record and print the preview (adapter, source, environment,
   window, record count, matched/unmatched counts, retention). **Never print an
   attribute value.**
9. Without `--yes`: exit 0 here. Nothing written, no audit event.
10. With `--yes`: `isSafeStateDir(statePath(targetAbs, 'runtime-observations'))`
    → exit 2 on refusal (string literal, third registry-guard call site);
    `persistObservationImport` inside a `try/catch` whose `catch` returns 4 with
    a clean message; a `{ok:false}` return is exit 1 (validation) or 4 (I/O),
    distinguished by `reason`; on success `auditCall({sessionRoot: targetAbs,
    tool: 'dataflow_observations_import', args: {adapter, source, environment,
    windowStart, windowEnd, observations: n, matched: m, importId}, outcome: 'ok'})`
    then exit 0.

- [ ] **Step 4: Add `cmdDataflowObservationsList`**

Loads `loadObservationImports(targetAbs)` and prints one row per import:
`importId`, `adapter`, `source`, `environment`, `windowStart..windowEnd`,
`observations.length`, `importedAt`, `retention.expiresAt ?? 'no expiry declared'`.
`--json` emits the same rows as JSON. **Never prints an attribute key or
value** — say so in a comment citing `CLI/list-2`. Exit 0 always (an empty
store is not an error). Never writes.

- [ ] **Step 5: Add `cmdDataflowTwin`**

1. `--output` required → exit 2; `--format` in `json|markdown` (default `json`)
   → exit 2 otherwise.
2. `loadSignedGraph(targetAbs)` → exit 1 on failure.
3. `const dir = statePath(targetAbs, 'runtime-observations');` (string literal,
   fourth registry-guard call site) — `fs.existsSync(dir) ? loadObservations(targetAbs) : null`.
   **The `null` is the `not_evaluated` signal and must not be coerced to `[]`.**
4. `correlateObservations(loaded.graph, observations, {environment, windowStart, windowEnd})`.
5. JSON format: `JSON.stringify(result, null, 2)`.
6. Markdown format — this is the human-readable AC-29 proof, so it must render,
   in this order:
   - a header with `graphId`, `graphDigest` (via `computeGraphDigest`), the
     environment filter and the window;
   - a **Layers** section with one row per flow: flow id, source node label,
     sink node label, and the layer rendered as the literal display strings
     `RUNTIME OBSERVED`, `not_observed_in_window`, `not_evaluated`;
   - for each `RUNTIME OBSERVED` row, its match method, match confidence,
     environment, window, first/last observed, event count band, and
     `siblingFlowCount` when non-zero;
   - a **Limitations** section printing `result.limitations` verbatim, plus
     three fixed sentences: (a) `not_observed_in_window` means the flow was not
     observed in the selected window and **never** that it does not occur
     (PRD line 2098); (b) runtime observation increases corroboration
     confidence and **cannot** prove field-level identity — observations
     correlate to node/edge/flow ids only (FR-505); (c) every statically
     possible path in the graph is listed above regardless of layer, and
     nothing was filtered out.
   Escape every interpolated value through local `_dfTwinMdInline`/
   `_dfTwinMdCell` helpers, byte-identical in body to `_dfCoverageMdInline`/
   `_dfCoverageMdCell` (`bin/agentic-security.js:3757`), per this codebase's
   per-module-owns-its-own-escaping-helpers convention.
7. Write `--output` inside a `try/catch` → exit 2 on write failure, matching
   `cmdDataflowImpactAssess`'s own branch. Never writes into
   `.agentic-security/`.

- [ ] **Step 6: Extend the `dataflow` dispatcher**

In `case 'dataflow':` (around line 5645), after the `impact` branch:

```js
        else if (sub === 'observations') {
          const obsSub = args._[2];
          if (obsSub === 'import') { process.exit(await cmdDataflowObservationsImport(args)); }
          else if (obsSub === 'list') { process.exit(await cmdDataflowObservationsList(args)); }
          else {
            process.stderr.write(`agentic-security dataflow observations: unrecognized sub-command "${obsSub}" — must be "import" or "list".\n`);
            process.exit(2);
          }
          break;
        }
        else if (sub === 'twin') { process.exit(await cmdDataflowTwin(args)); }
```

and update the trailing unknown-subcommand message to name `observations` and
`twin` alongside the existing five.

- [ ] **Step 7: Run the CLI test**

Run: `cd scanner && node --test test/cli/dataflow-observations.test.js`
Expected: PASS, 0 failures.

- [ ] **Step 8: Wire the test into `test:mcp`**

Read `scanner/package.json`'s current `test:mcp` script string first, then
append ` test/cli/dataflow-observations.test.js`. `test:mcp` — not
`test:lineage` — because this file asserts against a real on-disk
`.agentic-security/mcp-audit.log`, which matches that script's own stated scope
("MCP server tools + audit log") more precisely, the same call
`test/cli/governance-propose-edit.test.js` already makes.

- [ ] **Step 9: Update `commands/dataflow.md`**

**Do NOT touch the `description:` frontmatter line — it is 117 characters
against a 120 cap (Correction 8).** Extend `argument-hint` only (currently 95
against a 200 cap):

```
argument-hint: "export|diff|watch|scenario apply|impact assess|observations import|observations list|twin [path] [options] --output <file> --format <fmt>"
```

Then add two new body sections, matching the file's existing section shape:

- `## Runtime observations (FR-505)` — the three commands, an options table for
  each, the native-JSONL wire format as a worked example, the exit-code
  contract (0/1/2/4), and the dry-run-by-default rule.
- `## Runtime Digital Twin layers (AC-29)` — what the three layers mean, with
  `not_observed_in_window` explicitly contrasted against "does not occur", and
  `not_evaluated` explicitly contrasted against `not_observed_in_window`.

Both sections must state, above their options tables, the four disclosed
limitations: (1) **CLI/JSON only — no UI**: layer toggles, distinct edge
treatment, an environment/window selector and an observation inspector are all
unbuilt, and AC-29's clauses are satisfied at the data/artifact layer;
(2) **one adapter** — `native-jsonl`; OpenTelemetry, gateway/mesh and cloud
flow adapters are unbuilt; (3) **node-granular corroboration** — an observation
proves a destination was contacted, never which of several flows did it, which
is why a flow sharing its sink with siblings reads `ambiguous`;
(4) **`edge.provenance` stays `'code'`** — corroboration is additive and never
reclassifies an edge.

Then verify:
`node scripts/lint-command-descriptions.mjs && echo "EXIT:$?"` — exit 0.

- [ ] **Step 10: Update `commands/secure.md`**

Add three rows beside the existing `/dataflow` rows (lines 96-97):

```
| Import runtime observation metadata (FR-505) | `/dataflow observations import --adapter native-jsonl --input <file> --environment <name> [--yes]` |
| List imported runtime observation windows | `/dataflow observations list` |
| Show Runtime Digital Twin layers per flow (AC-29) | `/dataflow twin --output <file> --format markdown` |
```

Doing this proactively is deliberate — deliverable #5 had to fix the same doc
drift reactively.

**Do NOT edit the dispatcher count in the root `CLAUDE.md`** (Correction 11) —
this deliverable adds no dispatcher.

- [ ] **Step 11: Update `scanner/src/lineage/CLAUDE.md`**

Add a new section, `## Milestone 5, Runtime-Corroborated Digital Twin (FR-505,
deliverable #7, 7b only) — COMPLETE`, with a module table covering
`runtime-observation.js`, `observation-adapters.js`,
`observation-correlation.js`, `observation-store.js`, and the
`graph-builder.js`/`coverage.js`/`index.js` extensions.

It must record, in prose a future reader cannot miss:

- **The five AC-29 properties a future UI increment inherits and must not
  break**, one line each, mapping to the clause table at the top of this plan.
  This is the scoping doc §4.7 disclosure obligation, and #6's experience says
  it is what otherwise gets missed.
- **Why the validator is closed-world** when every sibling §10.10 contract is
  open-world, with the PRD line 983 and AC-29 clause 5 citations.
- **Why 7a is not here**: CONFIG DECLARED is M2 Sub-project F2/F3, already
  scoped as 2 × Large, and whoever picks it up should read the #7 scoping doc's
  Corrections 3 and 4 and its `edge.provenance`-has-zero-consumers finding
  first.
- **The full out-of-scope list** from the scoping doc §7, verbatim in substance:
  no OTLP adapter; no gateway/mesh or cloud-flow adapters; no UI or D.6 golden;
  no live ingestion; no field-level identity from runtime evidence; no
  `edge.provenance = 'runtime'`; no `ImpactAssessment.scope = 'observed'`
  partition; no change to `remediation.js`/`remediation-ledger.js`/the
  `remediation` CLI verbs.
- **The two pre-existing gaps this deliverable touched and the one it did
  not**: `runtime-trace.jsonl`/`runtime.jsonl`/`ebpf-trace.jsonl` are now
  registered (fixed); `confidential: true` requires the writer to call
  `maybeEncryptForWrite` itself and this store does (fixed);
  `graph-snapshot.js`'s `loadSnapshot` still joins an unvalidated key
  (disclosed, not fixed).

- [ ] **Step 12: Rebuild and run every affected suite**

Run: `cd scanner && npm run build` — exit 0, then `git status` on the WHOLE
`dist/` directory to confirm the bundle and its sidecar both moved.

Run: `cd scanner && npm run test:mcp && npm run test:lineage && npm run test:posture && npm run test:lifecycle`
Expected: PASS, 0 failures, all four. `test:lifecycle` is where the
command-description lint and the doc-drift checker live, so a `commands/` or
CLAUDE.md mistake surfaces there and nowhere else.

- [ ] **Step 13: Run the full CI gate**

Run: `cd scanner && npm test`
Expected: PASS, 0 failures. Capture and read the real exit code immediately
after (`echo $?`) — do not infer success from output length. Run this in the
**foreground**, or via a real background-and-wait pattern (never
fire-and-forget): two prior M5 sub-projects had real coordination problems from
an implementer backgrounding this exact command and never checking back. If a
Chrome-resource-contention-shaped failure appears (a
`cmd-dataflow-export.test.js` / `export-image.test.js` test failing with a
`null`/killed status, unrelated to anything this task touched), re-run just
that file in isolation to confirm it passes alone before concluding it is
pre-existing environmental flakiness — verify it reproduces the same way, do
not just assume.

Then run the two graph-shaped benches, capturing each exit code:
`cd scanner && npm run bench:protection-verdict:check; echo "EXIT:$?"` and
`npm run bench:cve-replay:check; echo "EXIT:$?"` — both must be 0.

- [ ] **Step 14: Commit**

```bash
git add scanner/bin/agentic-security.js scanner/dist/ scanner/test/cli/dataflow-observations.test.js scanner/package.json commands/dataflow.md commands/secure.md scanner/src/lineage/CLAUDE.md
git commit -m "feat(cli): wire dataflow observations import/list and dataflow twin — the AC-29 Runtime Digital Twin proof surface"
```

---

## Final Review Checklist (for the coordinator, not a task)

**AC-29's five `then` clauses, each verified against shipped code, not plan text:**

- [ ] *Clause 1 — `RUNTIME OBSERVED`.* Read the shipped `correlateObservations`
  and confirm a matched flow genuinely reaches `layer: 'runtime_observed'`, then
  read `cmdDataflowTwin`'s markdown branch and confirm the literal display
  string `RUNTIME OBSERVED` appears. Run the real CLI against the real fixture
  and read the real output file.
- [ ] *Clause 2 — `not_observed_in_window`, and the third state.* Confirm
  `OC/5a`/`OC/5b`/`OC/5c` genuinely fail against a mutated implementation that
  collapses `not_evaluated` into `not_observed_in_window` (comment out the
  branch, run, restore). A guard nobody has seen fail is not a guard. Then
  confirm the SAME distinction survives the wiring layer (`WIRE/4`, `WIRE/9`)
  and the CLI layer (`CLI/twin-3` vs `CLI/twin-4`) — it is easy to get right in
  the pure module and lose in the two layers above it.
- [ ] *Clause 3 — both static paths remain visible.* Grep the shipped
  `observation-correlation.js` for `filter`, `splice`, `pop`, `shift`, `delete`,
  and any assignment to `graph.` — there must be none. Confirm `OC/1a`'s
  deep-freeze test genuinely covers `graph.flows`, `graph.nodes`,
  `graph.edges`, AND each entity object, not just the top-level arrays.
  Confirm `OC/1b`'s totality assertion is over the real flow-id set.
- [ ] *Clause 4 — method/confidence/environment/window shown.* Confirm every
  `runtime_observed` `byFlow` entry has all eight fields non-null and every
  non-observed entry has them all null (`OC/7a`, both directions), and that the
  markdown genuinely prints them (`CLI/twin-2` asserts on the rendered text,
  not on the record).
- [ ] *Clause 5 — no payload in the artifact.* This is the one to be hardest
  on. (a) Confirm the closed-world top-level sweep runs BEFORE any per-field
  check and is genuinely unconditional. (b) Confirm
  `validateObservationAttributes` rejects an unapproved key without inspecting
  its value, so an allowlist miss can never be reached around. (c) Confirm
  `OS/8`'s raw-bytes assertion is non-vacuous in BOTH directions. (d) Confirm
  `CLI/import-4` asserts the store is genuinely unchanged, not merely that the
  exit code was 1. (e) Hand-write a NEW payload record the plan never
  anticipated (e.g. `{"attributes":{"destination.host":"x","tls.sni":"secret"}}`
  and `{"attributes":{"destination.host":"x"},"observedBody":"..."}`), run it
  through the real `observations import`, and confirm both are refused by name.

**Metadata-only, in depth:**

- [ ] `RUNTIME_ATTRIBUTE_KEYS` contains no key whose value could be a URL with
  a query string, a statement, a body, a message, or a model input/output.
  Re-read the 18 keys one at a time against FR-505's own sentence. In
  particular confirm `destination.path` is capped and confirm nothing named
  `url`, `query`, `statement`, `body`, `message`, `prompt`, `completion`,
  `header`, or `cookie` is on the list.
- [ ] Every string cap is enforced on the value's `.length`, not on a truncated
  copy — a validator that truncates is a validator that persists a truncated
  payload.
- [ ] `observations list` genuinely prints no attribute key or value
  (`CLI/list-2`, both directions).

**Additivity and non-regression:**

- [ ] `graph.runtimeCorroboration` is genuinely ABSENT (`'runtimeCorroboration'
  in graph === false`) when no hook is supplied — not `null`, not `{}`
  (`WIRE/3`).
- [ ] `edge.provenance` is `'code'` on every edge of a real corroborated graph.
  Grep the whole diff for `provenance` and confirm no task writes it.
- [ ] `dataflow-graph.schema.json` and `validate.js` are untouched, and
  `json-schema-parity.test.js` passed without modification.
- [ ] `graph-builder.test.js`, `coverage.test.js`, `flagship-fixture.test.js`,
  `export-json.test.js`, `export-csv.test.js`, `redact-graph.test.js`,
  `protection-summary.test.js`, `ac01-multi-sink.test.js` all passed with **no
  assertion moved**. If any moved, the hook is not additive.
- [ ] `bench:protection-verdict:check` and `bench:cve-replay:check` both exit 0.

**Write-path ordering:**

- [ ] `isSafeStateDir` is checked before any `mkdirSync`/write, in BOTH
  `observation-store.js` and `cmdDataflowObservationsImport`.
- [ ] `auditCall` fires ONLY on a real write — never on a dry run, never on a
  rejected import, never on a graph-load failure. Confirm by reading the shipped
  code path, then by asserting `mcp-audit.log` after `CLI/import-1` and
  `CLI/import-4`.
- [ ] `validateRuntimeObservation` is genuinely called on the write path
  (`persistObservationImport`), not only at the CLI. Grep the tree for the
  symbol; the CLI's own call is a deliberate PREVIEW that produces the exit-1
  message, and the store's is the one that gates the write. Confirm the store
  refuses even when the CLI is bypassed (`OS/7a`).
- [ ] An unexpected I/O error during the write returns 4 with a clean message
  and leaves the store unchanged.

**Storage and registry:**

- [ ] `statePath(scanRoot, 'runtime-observations')` appears as a STRING LITERAL
  at every call site — `observation-store.js`, `index.js`, and both CLI
  commands. Grep for `statePath(` in the diff and read each one.
- [ ] Removing the `runtime-observations` registry entry genuinely fails
  `artifact-registry-completeness.test.js` (transcript recorded in Step 7 of
  Task 4).
- [ ] `reset` genuinely deletes a populated store directory and genuinely does
  NOT delete the three `runtime-trace` files — proven live, not asserted off
  the registry row.
- [ ] `confidentialOf('runtime-observations') === true` AND
  `observation-store.js` genuinely calls `maybeEncryptForWrite`/
  `maybeDecryptForRead` (`OS/9a`, `OS/9b`). Without the calls the flag is a
  false claim.
- [ ] `loadObservationImport`/`deleteObservationImport` refuse a traversal key
  before any `path.join` (`OS/5c`).

**Boundaries:**

- [ ] `runtime-observation.js` and `observation-adapters.js` each have exactly
  `[]` import specifiers; `observation-correlation.js` has exactly
  `['./runtime-observation.js']`. Confirm each boundary test is actually in
  `test:lineage`'s file list, not merely written.
- [ ] `OC/9b`'s remediation-separation guard genuinely reads both remediation
  modules' source and all four observation modules' source.
- [ ] `posture/runtime-correlation.js` is untouched, and nothing in the diff
  imports it.
- [ ] No module in this deliverable is named `runtime-correlation.js`.

**Cross-task signature consistency:**

- [ ] Every function Task 6 calls exists with the exact name and arity Tasks
  1-4 shipped: `adapterFor(name)`,
  `parseNativeJsonlObservations(text, context)`,
  `observationId({adapter, environment, windowStart, windowEnd}, parts)`,
  `observationImportId({adapter, source, environment, windowStart, windowEnd, importedAt}, parts)`,
  `validateRuntimeObservation(record)`,
  `matchObservationToGraph(graph, draft)`,
  `correlateObservations(graph, observations, opts)`,
  `persistObservationImport(scanRoot, importRecord)`,
  `loadObservationImports(scanRoot)`, `loadObservations(scanRoot)`.
  None of them is async — confirm no CLI call site `await`s one by mistake.
- [ ] `AD/7a`'s round trip genuinely composes an adapter draft plus a match
  result plus a minted id into a record that `validateRuntimeObservation`
  accepts. This is the one test that catches a field-list drift between Task 1
  and Task 3.
- [ ] `OC/2j` genuinely runs the Task-2 match result through the Task-1
  cross-field rules for all three of the matched, unmatched, and ambiguous
  cases.
- [ ] `RUNTIME_OBSERVATION_FIELDS`'s 18 entries and the import record's 10
  entries are each exactly what the store, the adapter, and the CLI construct —
  no field is written that the closed-world sweep would reject, and no required
  field is left unwritten.

**Docs:**

- [ ] `commands/dataflow.md`'s `description` frontmatter is UNCHANGED and still
  ≤ 120 characters; `argument-hint` is ≤ 200. `node
  scripts/lint-command-descriptions.mjs` exits 0.
- [ ] `commands/dataflow.md` states all four disclosed limitations ABOVE its
  options tables.
- [ ] `scanner/src/lineage/CLAUDE.md` names the five AC-29 properties a future
  UI must not break, and carries the full §7 out-of-scope list.
- [ ] The root `CLAUDE.md` dispatcher count is UNCHANGED (still 13).
- [ ] `npm run test:lifecycle` passes — the doc-drift checker flags a
  backtick-quoted path that does not exist, and this deliverable adds several.

**Final:**

- [ ] Re-run `npm run build` after ALL edits land and check `git status` on the
  whole `dist/` directory.
- [ ] `npm test` green with a captured exit code, read in the same turn.
