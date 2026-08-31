# Source/Sink Registries — Reclassification Design Record

Scope: Sub-project D of Milestone 1 (see
`docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-d-scoping.md`).
Binding on every later Sub-project D increment, the same way
`DESIGN_INTRAPROCEDURAL.md` binds Sub-projects A/B and `DESIGN_PATH_PROVENANCE.md`
binds Sub-project C.

This increment (D1) is design + proof-of-concept only. `src/` is unmodified by
it apart from this file. The mechanical registries (`source-registry.js` = D2,
`sink-registry.js` = D3) and transformation-kind recognition (D4) are follow-up
increments; §9 is their checklist.

**Every number, list and claim in this document was produced by running real
code against the live catalogs in the increment that wrote it**, via
`test/lineage/registry-mapping-poc.test.js`. Nothing here is quoted from the
scoping doc, and §7.3 records four places where the scoping doc was measurably
wrong.

---

## 1. What this sub-project actually is

Sub-projects A/B/C built new analysis capability. Sub-project D builds almost
none. Its job is to **reclassify** detection the scanner already performs —
`scanner/src/dataflow/catalog.js`'s 756 entries, proven across the whole
benchmark corpus — into `schema.js`'s `DataFlowGraph v1` vocabulary.

The registries are therefore **pure data consumers**. They read a catalog
entry's `provenance` / `category` / `vuln` / `label` / `framework` fields and
emit a `{kind, category, coverageStatus, externality, reason}` decision. They
**never** re-derive what a call site matches — `matchSource` /
`matchSinkOrSanitizer` / `matchPrivacySink` already own that, and duplicating
it would fork a matcher the corpus proves against one that nothing proves.

Reading `CATALOG` from `src/lineage/` is data consumption, not a taint-engine
import, and is consistent with this PRD's isolation principle (§18.1) — the
same basis on which Sub-project A reuses `access-paths.js`. Confirmed by
reading `catalog.js`: `CATALOG` is a frozen-by-convention module-level array of
plain objects with no engine state and no mutation path.

---

## 2. Ground truth (measured, not sampled)

| Fact | Value |
|---|---|
| `CATALOG.length` | **756** |
| — `kind: 'source'` | **180** |
| — `kind: 'sink'` | **194** |
| — `kind: 'sanitizer'` | **382** |
| `EXPANDED_SANITIZERS.length` | **324**, and **100% `kind: 'sanitizer'`** |
| `PRIVACY_SINK_CATALOG.length` | **18** |
| `PRIVACY_SINK_CATEGORIES.length` | **9** |
| Distinct source `provenance` values | **12** |
| Source entries with **no** `provenance` at all | **82** (46% of sources) |
| Distinct sink `vuln.cwe` values | **20** |
| Sink entries carrying a `category` field | **0** |

Export shapes, confirmed by reading rather than assumed:

- `catalog.js` exports `CATALOG` (plus matcher functions and
  `_languageFamilyExtensions`).
- `catalog-expanded.js` exports `EXPANDED_SANITIZERS` and
  `_expandedSanitizerStats` — **not** a `CATALOG`-shaped array, and it
  contributes **no** source or sink entries. It is irrelevant to D2/D3 and
  relevant to D4 only as a counter-example (§8.3).
- `privacy-catalog.js` exports `PRIVACY_SINK_CATALOG`,
  `PRIVACY_SINK_CATEGORIES`, and four matcher/classifier functions.

### 2.1 The classification signals are asymmetric

This is the fact that shapes everything below.

- **Sources** carry a purpose-built classification field, `provenance` — but
  only 98 of 180 do.
- **Sinks** carry **none**. There is no `category` on any of the 194. The only
  classification signal is `vuln.cwe`, which is a **vulnerability class**, not
  a destination.

---

## 3. The central structural finding

`schema.js`'s `SINK_CATEGORIES` is an **egress taxonomy**: it answers *where
does the data go* (a log, a database, an object store, an email, a model
provider). `catalog.js`'s sink entries are a **vulnerability taxonomy**: they
answer *what goes wrong* (injection, traversal, deserialization, overflow).

These are orthogonal, and they only coincide where a vulnerability happens to
be named after its destination. They do for SQL (→ `database`), path traversal
(→ `file`), SSRF (→ `external-api`), response splitting and open redirect (→
`http-response`). They do **not** for command injection, code injection, SSTI,
deserialization, XXE, XPath injection, buffer overflow, ReDoS or untrusted
library load — in every one of those the "destination" is **in-process
computation**: an interpreter, a parser, a template engine, a regex engine, a
dynamic loader, or raw memory. FR-201's list models none of them, correctly,
because none of them is egress.

**Measured: 82 of 194 sink entries (42%) fall in that bucket.** They are not
mapping failures. They are a category of thing FR-201 does not model, and §6.4
keeps every one of them in the graph rather than dropping it.

`privacy-catalog.js` is the mirror image and the reason it exists: it *is*
destination-shaped (log / response / outboundHttp / fileWrite / s3Upload /
emailSend / storage / queues / thirdPartySdk), and consequently **8 of its 9
categories map to `SINK_CATEGORIES` cleanly** (§5). An 18-entry inert catalog
therefore has better *destination* coverage than the 194-entry proven one — a
real, disclosable asymmetry (§7.2).

---

## 4. Source mapping table (complete)

Primary key: the entry's declared `provenance`.

| `provenance` | count | → `SOURCE_CATEGORIES` | `coverageStatus` | basis |
|---|---:|---|---|---|
| `http-body` | 31 | `http-body` | `modeled` | exact vocabulary match |
| `url-param` | 14 | `http-query` | `modeled` | pure rename |
| `header` | 10 | `http-header` | `modeled` | pure rename |
| `cookie` | 7 | `http-cookie` | `modeled` | pure rename |
| `path-param` | 5 | `http-route` | `modeled` | pure rename |
| `env` | 4 | `env-value` | `modeled` | pure rename |
| `cli` | 3 | `cli-argument` | `modeled` | pure rename |
| `network` | 8 | `external-api-response` | `modeled` | all 8 read an outbound response body (`fetch`/`axios`/`requests`/`urlopen`/`recv`) |
| `file-read` | 4 | `storage-read` | `modeled` | FR-101 groups "files and object storage reads"; `storage-read` is its only encoding |
| `url-fragment` | 2 | `http-query` | **`partial`** | lossy — a fragment is URL-borne but never transmitted to the server; no `http-fragment` value exists |
| `stdin` | 2 | `user-input` | **`partial`** | lossy — broadens to the generic value; no stdin/console value exists |
| `agent-tool` | 8 | *splits* | *see below* | **the one value that does not resolve on the provenance key alone** |

### 4.1 `agent-tool` splits directionally

Its 8 entries are not one thing. Five are tool-invocation **arguments** (the
model chose them); three are **results/resources** flowing back. They belong in
different `SOURCE_CATEGORIES`, so the rule needs one documented per-entry
refinement:

| entry id | → category | status |
|---|---|---|
| `py-mcp-tool`, `py-mcp-server-tool`, `js-mcp-call-args`, `js-mcp-request-params`, `js-mcp-extra-args` | `ai-model-output` | `partial` — the arguments *were* produced by the model, but `ai-model-output` normally denotes a completion |
| `js-mcp-tool-result`, `py-mcp-tool-result` | `ai-tool-result` | `modeled` |
| `js-mcp-resource-contents` | `ai-retrieved-document` | `modeled` |

### 4.2 The 82 entries with no `provenance`

They get a per-entry-id override table (enumerated in full in the PoC file's
`NO_PROVENANCE_OVERRIDES`), and every one of them is **`candidate`** — see
§6.3 for why. The gap is not random: **`go`, `java`, `rb` and `php` declare
`provenance` on literally zero of their source entries**, so entire language
families would otherwise be uncategorized.

Resulting source coverage: **89 `modeled`, 9 `partial`, 82 `candidate`, 0
`unsupported`.**

---

## 5. Sink mapping tables (complete)

### 5.1 `catalog.js` — primary key `vuln.cwe`

| CWE | count | → `SINK_CATEGORIES` | status | basis |
|---|---:|---|---|---|
| CWE-89 | 38 | `database` | `modeled` | a SQL query call is unambiguously a database destination |
| CWE-943 | 1 | `database` | `modeled` | NoSQL `$where` |
| CWE-22 | 16 | `file` | `modeled` | traversal sinks are filesystem reads/writes |
| CWE-73 | 1 | `file` | `modeled` | arbitrary file write |
| CWE-918 | 15 | `external-api` | `modeled` | SSRF sinks are outbound HTTP client calls |
| CWE-601 | 7 | `http-response` | `modeled` | a redirect is a response header |
| CWE-113 | 9 | `http-response` | `modeled` | the sink *is* the response-header writer |
| CWE-79 | 16 | *splits* | *see 5.2* | |
| CWE-90 | 9 | `database` | **`candidate`** | an LDAP directory is a queryable store, structurally like a DB — but FR-201 never names directory services |
| CWE-78 | 29 | — | **`unsupported`** | shell/process execution |
| CWE-95 | 5 | — | **`unsupported`** | code evaluation — destination is an interpreter |
| CWE-94 | 10 | — | **`unsupported`** | code injection / template compilation |
| CWE-1336 | 2 | — | **`unsupported`** | SSTI — destination is a template engine |
| CWE-502 | 10 | — | **`unsupported`** | destination is a deserializer |
| CWE-611 | 10 | — | **`unsupported`** | XXE — destination is an XML parser |
| CWE-643 | 10 | — | **`unsupported`** | XPath — destination is an in-memory query engine |
| CWE-120 | 3 | — | **`unsupported`** | destination is raw memory |
| CWE-787 | 1 | — | **`unsupported`** | destination is raw memory |
| CWE-1333 | 1 | — | **`unsupported`** | destination is the regex engine |
| CWE-114 | 1 | — | **`unsupported`** | destination is the dynamic loader |

CWE-94 and CWE-1336 are both `unsupported` **deliberately and uniformly**,
even though a rendered template's output usually does reach a response: the
catalog entry names the *compile* call, not the response write, so a
`http-response` mapping would be an inference about a different program point.
Treating SSTI as egress while treating `eval` as non-egress would be special
pleading; the rule is "the entry's own callee decides", applied consistently.

### 5.2 CWE-79's refinement — the sink side's one exception

CWE-79 covers two genuinely different destinations, split on `framework`:

| `framework` | entries | → category | status |
|---|---:|---|---|
| `dom`, `react` | 6 | `client-storage` | **`partial`** |
| everything else (`express`, `koa`, `servlet`, `flask`, `rails`, `ktor`, `aspnet`, `fmt`, `core`) | 10 | `http-response` | `modeled` |

The `partial` is a **naming gap in `schema.js`, disclosed not patched** (§7.4):
FR-201's bullet reads "browser DOM **or** client storage", and `schema.js`
encodes that whole bullet as the single value `client-storage`. So
`client-storage` is the *correct* target per the PRD's own text while
under-naming the DOM half. `innerHTML` is not client storage in any ordinary
reading of the phrase, and a reader of the graph will be misled unless the
status says `partial`.

Resulting sink coverage: **97 `modeled`, 6 `partial`, 9 `candidate`, 82
`unsupported`.**

### 5.3 `privacy-catalog.js` ↔ `SINK_CATEGORIES`, entry by entry

| privacy `category` | entries | → `SINK_CATEGORIES` | status | basis |
|---|---:|---|---|---|
| `log` | 4 | `log` | `modeled` | `console.log/error`, `logger.info/warn` |
| `response` | 2 | `http-response` | `modeled` | `res.send` / `res.json` |
| `outboundHttp` | 2 | `external-api` | `modeled` | `fetch` / `axios.post` |
| `fileWrite` | 2 | `file` | `modeled` | `fs.writeFile` / `writeFileSync` |
| `s3Upload` | 1 | `object-storage` | `modeled` | `s3.putObject` |
| `emailSend` | 1 | `email` | `modeled` | nodemailer `sendMail` |
| `storage` | 2 | `database` | `modeled` | **does not split** — see below |
| `queues` | 2 | `queue` | `modeled` | `sqs.sendMessage` / `sns\|kafka publish`; FR-201's `queue` covers "queues, topics, streams, and event buses" |
| `thirdPartySdk` | 2 | `analytics` | **`partial`** | **does split** — see below |

**`storage` does NOT split**, contrary to the scoping doc's expectation that it
would need splitting across `database`/`object-storage`/`cache`. Both entries
carrying it are mongodb `insertOne`/`insertMany` with a `collection|db|mongo`
receiver. The *name* is broader than its entries; the entries are not. D1/4b
pins this so a future redis or S3 entry filed under `storage` fails loudly
instead of being silently mapped to `database`.

**`thirdPartySdk` DOES split, and cannot be resolved by a registry at all.**
Its two entries share one `receiverTypeIn` alternation:
`stripe|sentry|datadog|segment|amplitude|mixpanel|posthog|braze|intercom|analytics`.
That single regex spans four different `SINK_CATEGORIES` — `analytics`
(segment/amplitude/mixpanel/posthog), `monitoring` (sentry/datadog),
`external-api` (stripe) and `collaboration` (intercom/braze). Which one is
correct is only decidable **at match time**, from the receiver that actually
matched — information a registry reclassifying *entries* never sees. It
therefore resolves to `analytics` (the plurality) with status `partial`, and
§9's D3 checklist carries the match-time refinement forward.

---

## 6. The `coverageStatus` decision procedure

Given a catalog entry, apply in order. The procedure is **total**: every one of
the 756 entries gets a decision, and D1/1e proves it.

### 6.1 `modeled`

The entry carries an **explicitly declared classification field** — a source's
`provenance`, a privacy sink's `category` — or, for a `catalog.js` sink, a
`vuln.cwe` whose vulnerability class *is* its destination; **and** that value
resolves to exactly one `SOURCE_CATEGORIES`/`SINK_CATEGORIES` value with no
semantic loss.

### 6.2 `partial`

Same evidentiary basis as `modeled` — the classification is author-declared —
but the resolution is **lossy in a stated way**. Two loss shapes occur, and
both must be named in the entry's `reason`:

- **Broadening**: the target value is strictly more general than the source
  fact (`stdin` → `user-input`).
- **Narrowing / adjacency**: the target value is the closest available but is
  not the same thing (`url-fragment` → `http-query`; DOM XSS →
  `client-storage`; `thirdPartySdk` → `analytics`).

`partial` is *not* "we are unsure". It is "we are sure, and the vocabulary
cannot say it exactly." That distinction is the whole reason it is separate
from `candidate`.

### 6.3 `candidate`

The entry carries **no declared classification field**, and the category is
inferred from secondary metadata the author wrote for a different purpose —
the entry's `id`, `label`, or `framework`. The mapping is plausible and
reviewed, but nobody asserted it.

This tier has a second, operational meaning that matters more than the first:
**a `candidate` mapping does not generalize.** It comes from a per-entry
override table, so a *newly added* catalog entry of the same shape gets no
mapping at all and must fail the registry's own completeness check rather than
silently inheriting one. `modeled`/`partial` mappings are keyed on a declared
value and do generalize.

All 82 unprovenanced sources are `candidate`. Not because
`py-flask-request-cookies → http-cookie` is doubtful — it plainly is not — but
because the evidence for it is a human reading a label, and the graph should
say so.

### 6.4 `unsupported`

**No `SOURCE_CATEGORIES`/`SINK_CATEGORIES` value models the entry's real
semantics.** Category is `null`.

Critically, `unsupported` is **not** exclusion. AC-11 requires a detected
source or sink with no resolved path to be "visible with a coverage reason",
and FR-201 requires all supported sinks to "remain discoverable". So an
`unsupported` entry still becomes a node: it keeps a `NODE_KINDS` value
(§7.1's `process`), keeps its label and location, and carries a non-empty
`reason` string. D1/1e asserts the non-empty reason on every entry precisely
so this cannot regress into a silent drop — the §18.4 failure mode this whole
PRD treats as load-bearing.

### 6.5 `manual` — the open question, resolved

**`manual` means the classification was asserted by a human, not derived by
the analyzer. No registry can ever emit it, and D2/D3 must not.**

Three independent lines of evidence, all checked in this increment:

1. **Codebase precedent, consistent across four modules.**
   `posture/privacy-framework.js` defines `BUCKETS = ['gap', 'engine-gap',
   'manual', 'satisfied']` and selects between the middle two on
   `codeTestable === 'no' ? 'manual' : 'engine-gap'` — *manual* is
   "not code-testable at all", explicitly distinguished from *engine-gap*,
   "code-testable but unimplemented". `posture/auditor-walkthrough.js`
   documents `'manual'` as "requires manual attestation".
   `lineage/protection.js`'s `EVIDENCE_GRADES` and `schema.js`'s
   `EVIDENCE_TYPES` both carry `'manual'` in the same human-asserted sense.
   That `engine-gap` / `manual` pair is the exact analogue of the
   `unsupported` / `manual` pair here.

2. **The PRD's own text.** FR-101's acceptance clause reads: "**All Sources**
   shows both connected and disconnected sources, with `modeled`, `partial`,
   `candidate`, or `unsupported` status." Four values. `manual` is deliberately
   absent from the *inventory* clause while present in the §10.3 *node
   contract* — i.e. a node may be `manual`; a discovered-source inventory row
   may not.

3. **Construction.** A catalog entry is analyzer-derived by definition. There
   is no path by which reading one produces a human assertion.

`manual` is therefore reserved for a later increment in which an operator
**declares** a node — pairing with the `declared` value that already exists in
both `SOURCE_CATEGORIES` and `SINK_CATEGORIES`, and with
`evidenceType: 'manual'`. That is also exactly why `declared` shows up in §7.2
as unreachable: it is the operator-declaration path, and nothing implements it
yet.

D1/2a asserts no entry in any of the three catalogs yields `manual`. D1/2b
asserts the schema's five values minus the four a registry may emit is exactly
`['manual']` — so if a sixth status is ever added, this file's premise fails
loudly rather than quietly.

---

## 7. Node kind, externality, and the disclosed gaps

### 7.1 Node-kind assignment rule

**Sources: always `NODE_KINDS.source`.** Checked, not assumed (D1/3b). The
alternative considered was `boundary`; it is wrong, because `boundary` models a
**trust-zone crossing**, which is a property of an edge between two systems,
and no catalog entry carries system, zone, or deployment information at all
(D1/8d).

**Sinks: derived from the resolved category, never from the entry.** The
category → kind table is in the PoC's `CATEGORY_NODE_KIND`; its shape is
`log`/`stdout` → `log`; every store-ish category (`database`, `file`,
`object-storage`, `cache`, `client-storage`, `backup`, `export`) → `store`;
`queue` → `queue`; every remote-party category (`external-api`, `webhook`,
`email`, `sms`, `push-notification`, `collaboration`, `analytics`,
`monitoring`, all `ai-*` except `ai-local-model`) → `external`;
`http-response` and `declared` → `sink`.

**A `null` category (i.e. `unsupported`) → `process`.** This is not a fallback;
it is the *explanation*. Every unsupported sink is an in-process computation
destination, which is precisely why FR-201's egress taxonomy has no value for
it. D1/3c pins the biconditional: `kind === 'process'` **iff**
`coverageStatus === 'unsupported'`. Measured sink kinds across all 194:
exactly `{external, process, sink, store}`.

### 7.2 Categories no catalog can reach today

Measured, and pinned as exact lists so they cannot go stale silently.

**`SOURCE_CATEGORIES`: 14 of 21 reachable.** Unreachable:
`graphql-argument`, `grpc-field`, `queue-message`, `database-read`,
`webhook-payload`, `ai-memory`, `declared`.

All seven are expected. GraphQL and gRPC have no source entries in `catalog.js`
at all; queue-message and database-read are ingress shapes the scanner does not
pattern-match; `declared` is the operator-declaration path (§6.5).

**`SINK_CATEGORIES`: only 10 of 29 reachable** — even counting
`privacy-catalog.js`. Unreachable: `stdout`, `cache`, `monitoring`, `sms`,
`push-notification`, `collaboration`, `webhook`, `backup`, `export`,
`declared`, and **all nine `ai-*` values** (`ai-model-provider`,
`ai-local-model`, `ai-agent`, `ai-tool`, `ai-vector-store`, `ai-memory`,
`ai-training`, `ai-evaluation`, `ai-telemetry`).

**The headline gap: FR-205 (AI destinations) has zero sink-catalog coverage.**
The source side *does* have AI coverage — the eight MCP entries reach three
`ai-*` source categories — so the asymmetry is real and specific: this scanner
can see data arriving *from* an agent context and cannot see data being sent
*to* a model provider, vector store, or agent. AC-07 ("PHI enters an
Anthropic/OpenAI/Bedrock model request") is **not satisfiable** by
reclassification alone. It needs new detection, which is out of Sub-project D's
scope entirely and must be raised where Milestone-2 AI-BOM destination work is
planned. `stdout` is likewise unreachable despite FR-201 naming it, because
`console.log` is catalogued as `log`, not split.

### 7.3 Four places the scoping doc was measurably wrong

Recorded because later increments will otherwise re-inherit them:

1. **Catalog size.** The scoping doc (and `scanner/src/dataflow/CLAUDE.md`)
   say **655 entries (149 source / 124 sink / 382 sanitizer)**. The live
   figures are **756 (180 / 194 / 382)**. `dataflow/CLAUDE.md` itself warns
   this number "has already drifted once"; it has now drifted twice.
   Pinned by D1/8a.
2. **The privacy vocabulary.** The scoping doc names eight categories —
   `log`/`response`/`storage`/`queues`/`email`/`file`/`outbound`/`third-party`.
   The real vocabulary is **nine**, and four of those eight names do not exist:
   the real identifiers are `emailSend`, `fileWrite`, `outboundHttp`,
   `thirdPartySdk`, plus `s3Upload`, which the eight-value list omits entirely.
   Pinned by D1/4d.
3. **`storage` splitting.** Anticipated to need splitting; measured not to
   (§5.3).
4. **The sink classification field.** The scoping doc calls it `vuln`. That is
   correct as far as it goes, but the operative sub-field is `vuln.cwe`, and
   the more important fact — that **no sink entry carries a `category` field at
   all** — is not recorded there. Pinned by D1/8b.

### 7.4 Two genuine schema/catalog gaps — named, deliberately not patched

Per this plan's Global Constraints, both are reported rather than fixed.

**(a) `catalog.js` is missing `provenance` on 82 source entries.** This is a
*catalog* defect, not a lineage-side one, and it is the direct cause of 46% of
sources being `candidate` rather than `modeled`. It looks trivially fixable and
is not: `provenance` is **not inert**. `dataflow/engine.js` propagates it onto
findings as `sourceProvenance` and `chain[].provenance`, and
`src/report/index.js` emits it. Adding it to 82 entries would change reported
finding content for go/java/rb/php/py flows across the corpus. That is a real,
benchmarked change and must be its own increment with `bench:cve-replay:check`
and `bench:layer-recall:check` run against it — **not** a side effect of a
lineage design task. Until then, D2 carries the override table and honestly
reports `candidate`.

**(b) `schema.js`'s `client-storage` under-names FR-201's "browser DOM or
client storage".** Six DOM XSS sinks (`document.write`, `innerHTML`,
`outerHTML`, `insertAdjacentHTML`, both `dangerouslySetInnerHTML` forms) have
the rendered DOM as their destination. `client-storage` is the PRD-faithful
target and a misleading label for them. A future additive `browser-dom` value
would promote all six from `partial` to `modeled`, but adding a
`SINK_CATEGORIES` value is a **schema-version-bumping change** (`schema.js`'s
own header says so) requiring `dataflow-graph.schema.json` and
`validate.js` to move in lockstep. Out of scope for a design increment; raised
here for whoever owns the next schema bump.

Neither `catalog.js`, `catalog-expanded.js`, `privacy-catalog.js` nor
`schema.js` was modified by this increment.

### 7.5 Externality: derivable, but only weakly

`schema.js`'s node contract requires `externality` ∈
`{internal, external, unknown}` "plus evidence" (PRD §10.3).

**No catalog entry carries any destination information** — no host, URL,
provider, system, or externality field. D1/8d asserts this across all 756
entries. Externality therefore **cannot** be entry-derived and must be
**category-derived**, per the `CATEGORY_EXTERNALITY` table: `log`, `stdout`,
`http-response`, `file`, `client-storage`, `ai-local-model` and every
`unsupported`/`process` sink → `internal`; every remote-party category →
`external`; every store-or-queue category (`database`, `object-storage`,
`cache`, `queue`, `backup`, `export`, `declared`) → **`unknown`**, because a
database may equally be a local container or a managed cloud service and the
entry gives no way to tell.

The consequence D2/D3 must respect: the accompanying evidence grade is at best
`declared` (it comes from a registry table), **never** `code`. Real externality
resolution is FR-202's job and lands in Milestone 2. Emitting `external` with a
`code` grade off this table would be an unsupported claim.

---

## 8. Confirmations for D4 (transformation-kind recognition)

D4 is not designed here. Three facts it depends on were checked so it starts
from a settled base.

**8.1 `TRANSFORM_KINDS` is correct and complete.** It matches PRD §10.6's
prose exactly, in order, 13 values, no duplicates:
`mask, redact, tokenize, hash, encrypt, decrypt, encode, decode, aggregate,
truncate, normalize, custom, unknown`. `REVERSIBILITY_VALUES` likewise matches
"reversible, irreversible, unknown". **No change is needed** — D4 can treat the
vocabulary as fixed. Pinned by D1/7a, which also asserts `mask`/`hash`/
`tokenize`/`encrypt` remain four distinct values, per §10.6's explicit "must
never be treated as synonyms".

**8.2 The 706 sanitizer entries are the WRONG input for D4.** `catalog.js`'s
382 sanitizers and `catalog-expanded.js`'s 324 are keyed on `effect`
(`strip`/`taintNever`/`taintIf-not-pinned`) and `appliesTo` (a *threat class*,
e.g. XSS vs SQLi). They answer "does this neutralize this vulnerability
family", not "what kind of transformation is this and is it reversible".
Reclassifying them into `TRANSFORM_KINDS` would be a category error — an HTML
escaper is `encode`, but 380-odd others carry no signal that maps at all.

**8.3 The one genuinely transform-shaped list is private.**
`privacy-catalog.js`'s `PRIVACY_TRANSFORM_CALLEES` is a hand-curated set
already grouped along `TRANSFORM_KINDS` lines — hashes (`createHash`, `sha256`,
`md5`), KDFs (`bcrypt`, `scrypt`, `argon2`), ciphers (`createCipheriv`,
`encrypt`, `seal`), and masking (`mask`, `redact`, `anonymize`,
`pseudonymize`, `tokenize`). It is **not exported**; it is reachable only
through the `isPrivacyTransformCallee(calleeExpr)` boolean predicate, which
tells a caller *that* a callee is a transform but never *which kind*. D4 must
resolve that access problem — the conservative option is a lineage-side table
of its own, mirroring §6.3's per-entry precedent; exporting the set from
`privacy-catalog.js` is an additive alternative. D1 records the constraint and
does not decide it.

---

## 9. Checklist for the follow-up increments

### D2 — `src/lineage/source-registry.js`

1. Export `reclassifySource(entry)` returning
   `{kind, category, coverageStatus, externality, reason}`, exactly the shape
   proven in the PoC. `kind` is always `'source'` (§7.1).
2. Port `PROVENANCE_MAP` (12 rows, §4), `AGENT_TOOL_REFINEMENT` (8 rows, §4.1)
   and `NO_PROVENANCE_OVERRIDES` (82 rows, §4.2) verbatim from
   `test/lineage/registry-mapping-poc.test.js`.
3. Import `CATALOG` from `../dataflow/catalog.js`. Import nothing else from
   `dataflow/` — no matcher, no engine (§1).
4. Keep the completeness guards as **shipped** tests, not PoC-only: the
   provenance key set and the override key set must each be asserted equal to
   the live catalog's, both directions. They are the only thing standing
   between a new catalog entry and a silently uncategorized node. All three
   were mutation-proven to fail in D1.
5. Never emit `manual` (§6.5).

### D3 — `src/lineage/sink-registry.js`

1. Export `reclassifySink(entry)` and `reclassifyPrivacySink(entry)` — two
   functions, because the two catalogs key on different fields (§2.1) and
   `privacy-catalog.js` is deliberately not merged into `CATALOG`.
2. Port `CWE_MAP` (20 rows, §5.1), the CWE-79 `framework` refinement (§5.2),
   `PRIVACY_CATEGORY_MAP` (9 rows, §5.3), `CATEGORY_NODE_KIND` and
   `CATEGORY_EXTERNALITY` (§7.1, §7.5).
3. **Preserve the `unsupported` → `process` node, with its reason string.**
   Dropping those 82 entries would be the single easiest way to violate AC-11
   and FR-201, and it would look like an optimization. D1/3c's biconditional
   and D1/1e's non-empty-reason assertion must both ship.
4. Carry forward the `thirdPartySdk` match-time refinement as a **known open
   item, not a silent `analytics`** (§5.3): a registry cannot resolve it, but a
   later match-time consumer that knows which receiver matched can, and should
   promote `partial` → `modeled` when it does.
5. Ship the measured-count pins (§4.2, §5.1, §5.2) as tests. `bench/layer-recall`
   has already demonstrated in this repo that a floor-only gate lets a stale
   published number survive for weeks; these are equality pins for that reason.

### Sequencing

D2 and D3 are independent and can run in parallel — they share only this
document and `schema.js`, and touch disjoint files. D4 depends on §8 but not on
D2/D3.

### Carried forward from Sub-project C: §16.7 Finding 2

`DESIGN_PATH_PROVENANCE.md` §16.7 left one finding explicitly **unfixed and
binding on whoever scopes Sub-project D**, with an instruction that D's own
documents must carry it forward rather than let it be rediscovered. Recording
it here discharges that obligation; it is **not** resolved by D1, and it is not
D2's or D3's to resolve either.

The finding: a §13.6 context-cap-degraded binding edge's target node is
unreachable from `path-query.js`'s `sinkCandidates()`. That node has zero
out-edges and is none of the `return`/`escape`/`loss` kinds `sinkCandidates()`
enumerates, so a normal **sink-rooted** reconstruction never surfaces it at
all. `flow-grade.js` grades it correctly if a caller reaches it directly;
nothing in a sink-rooted query asks. This is §18.4's "truncation must never
look like no-flow" constraint re-opening at the *query* boundary rather than
the recording boundary.

Why it is not D2/D3's problem: `sinkCandidates()` is documented as a
**registry stand-in** — "there is no sink registry yet — Sub-project D" — so
the obvious reading is that D3 replaces it and inherits the bug. That reading
is wrong. D3 produces a *classification for a catalog entry*; it does not
enumerate graph nodes, and it never sees a `PathStore`. The consumer that
eventually replaces `sinkCandidates()` with real registry-backed sink
enumeration is **Sub-project E's graph builder**, and that is where the fix
belongs — either by adding the candidate "truncation-terminal" node shape §16.7
sketches, or by having the enumerator union `diagnostics()`'s degraded targets
into its candidate set. Whoever scopes Sub-project E must pick one up front,
because a registry-backed enumerator that simply mirrors `sinkCandidates()`'
current kind list reproduces the gap exactly.

### Not in scope for any of D2/D3/D4

Modifying `catalog.js` / `catalog-expanded.js` / `privacy-catalog.js` /
`schema.js` (§7.4); FR-202 destination resolution; any `DataFlowGraph v1`
envelope output or graph builder (Sub-project E); wiring any registry into
`runScan`; new *detection* of any kind — in particular the AI-destination gap
(§7.2), which reclassification cannot close.
