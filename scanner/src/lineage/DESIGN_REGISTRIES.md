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
scoping doc, and §7.3 records five places where the upstream documents (the
scoping doc and the D1 task brief) were measurably wrong.

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
| `network` | 8 | `external-api-response` | `modeled` ×6, **`partial` ×2** | the 6 JS/Python entries read an outbound response body (`fetch`/`axios`/`requests`/`urlopen`); the 2 `cpp` entries are refined — see §4.2 |
| `file-read` | 4 | `storage-read` | `modeled` ×1, **`partial` ×3** | FR-101 groups "files and object storage reads"; `storage-read` is its only encoding. The 3 `cpp` entries are refined — see §4.2 |
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

### 4.2 C's I/O primitives are descriptor-generic — the third refinement key

The `network` and `file-read` rows above cannot claim `modeled` for their C
entries, under §6.1's own bar ("resolves 1:1 with no semantic loss"). C's I/O
primitives are **descriptor-generic**: the same call reads a file, a socket, a
pipe or stdin, and the catalog entry has no way to say which.

| entry | provenance | why not `modeled` |
|---|---|---|
| `cpp-recv`, `cpp-recvfrom` | `network` | directionally ambiguous — on a *client* socket this is an API response; on a *listening* socket it is an inbound client request, which `external-api-response` actively mis-describes |
| `cpp-read` | `file-read` | a raw fd is equally a file, socket or pipe |
| `cpp-fread`, `cpp-fgets` | `file-read` | a `FILE*` is commonly `stdin`, not a file |

The refinement key is therefore **`language === 'cpp'`** within these two
provenance buckets: category unchanged, status demoted to `partial`, caveat
stated. This is the third and last documented refinement, alongside §4.1's
per-entry-id one and §5.2's `framework` one — and it is the same *shape* as
both: a declared classification value that is correct for most of its entries
and lossy for an identifiable subset. (§4.3's 82-row override table is a
different mechanism entirely — a fallback for entries with *no* declared value,
not a refinement of one.) Note the `stdin` provenance (§4, also `cpp`-only) was
already `partial` for the adjacent reason, so the C entries are now uniformly
honest across all three buckets.

### 4.3 The 82 entries with no `provenance`

They get a per-entry-id override table (enumerated in full in the PoC file's
`NO_PROVENANCE_OVERRIDES`), and every one of them is **`candidate`** — see
§6.3 for why. The gap is not random: **`go`, `java`, `rb` and `php` declare
`provenance` on literally zero of their source entries**, so entire language
families would otherwise be uncategorized.

Resulting source coverage: **84 `modeled`, 14 `partial`, 82 `candidate`, 0
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

**The four `NODE_KINDS` values a reclassified sink never gets, and why** —
recorded so a later reader sees a decision rather than an oversight.
`api` was considered for `external-api`/`webhook` and rejected: it denotes a
*service endpoint entity*, whereas a catalog sink is the **call site** that
sends data to one, and `external` is the value that says "the data leaves to
a party outside this program". (When Sub-project E builds real destination
nodes from FR-202 resolution, *those* may well be `api`; the registry's
call-site node is not.) `transform` belongs to `TRANSFORM_KINDS`-shaped
transformation entities (§8), not to sinks. `boundary` is rejected for the
same reason it is on the source side — it needs trust-zone data no entry
carries. `unresolved` is rejected **here** but is genuinely needed one layer
out, for a *dynamic destination* rather than an unmappable category — see
§9's D3 checklist item 5 and the degraded-dead-end rule in §9's
carried-forward section.

**A `null` category (i.e. `unsupported`) → `process`.** This is not a fallback;
it is the *explanation*. Every unsupported sink is an in-process computation
destination, which is precisely why FR-201's egress taxonomy has no value for
it. D1/3c pins the biconditional: `kind === 'process'` **iff**
`coverageStatus === 'unsupported'`. Measured sink kinds across all 194:
exactly `{external, process, sink, store}`.

> **The biconditional is contingent, and whoever breaks it should know they
> are meant to.** It holds today only because the one *other* category that
> maps to `process` — `ai-local-model` — is **vacuously unreachable** (§7.2:
> no catalog entry produces any `ai-*` sink). The moment AI-destination
> detection lands — which §7.2 names as the single largest piece of future
> work here — an `ai-local-model` sink will have `kind: 'process'` with a
> non-null category and a non-`unsupported` status, and `D1/3c`'s reverse
> implication (`kind === 'process'` ⟹ `unsupported`) becomes false.
> **That is a correct consequence of new coverage, not a regression.**
> Whoever adds AI-sink detection owns relaxing the assertion to its forward
> direction only (`unsupported` ⟹ `process`), which is the half that
> actually encodes §3's claim. The assertion is written as a biconditional
> deliberately, because until then the stronger form is true and catches
> more; it is flagged here so it is not mistaken for something the AI work
> broke.

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
scope entirely.

**Whose problem this is: Sub-project H, inside Milestone 1 — not Milestone 2.**
AC-07 sits in **Milestone 1's own exit gate** (PRD §26, quoted verbatim in the
parent M1 scoping doc: *"AC-01, AC-02, AC-07, AC-11, and schema completeness
pass on the supported-language corpus"*), and that doc's §5 table assigns
running it to **Sub-project H** (*"Runs AC-01, AC-02, AC-07, AC-11, and schema
completeness against the real JS/TS corpus"*). So this is not a
deferred-to-a-later-milestone concern that D may hand off and forget: it is a
gap in the milestone D itself belongs to, and H will hit it as a hard exit-gate
failure unless AI-destination detection lands somewhere in D through G first.
**Whoever scopes Sub-project H must budget for that**, and should treat "AC-07
passes" as blocked on new detection work that no current increment owns.

`stdout` is likewise unreachable despite FR-201 naming it, because
`console.log` is catalogued as `log`, not split.

### 7.3 Five places the upstream documents were measurably wrong

Recorded because later increments will otherwise re-inherit them. "Upstream"
rather than "the scoping doc" deliberately — items 3 and 5 originate in the D1
task brief, not the scoping doc, and attributing everything to one source would
send a corrector to the wrong file.

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
3. **`storage` splitting.** The **task brief** (not the scoping doc, which only
   says the two vocabularies don't match) predicted `storage` would need
   splitting across `database`/`object-storage`/`cache`. Measured: it does not
   (§5.3). Pinned by D1/4b.
4. **The sink classification field.** The scoping doc calls it `vuln`. That is
   correct as far as it goes, but the operative sub-field is `vuln.cwe`, and
   the more important fact — that **no sink entry carries a `category` field at
   all** — is not recorded there. Pinned by D1/8b.
5. **`SINK_CATEGORIES` has 29 values, not 28.** Both the scoping doc (D3's row:
   *"more categories: 28 vs 21"*) and the task brief say 28. The live export
   has **29** (`SOURCE_CATEGORIES`' 21 is correct). This document uses 29
   throughout — §7.2's "10 of 29 reachable" and "19 unreachable" sum correctly
   — but the correction was not flagged alongside the others in D1's first
   draft, so it is recorded here. It matters for D3's sizing, and any
   coverage-fraction computed off 28 is wrong. Pinned by D1/6c.

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

### 9.0 The decision shape, and how `category` reaches a node

Both registries return the same object:
`{kind, category, coverageStatus, externality, reason}`.

**`category` is the REGISTRY's own field name. On a `DataFlowGraph v1` node it
becomes `subtype`.** The PRD's §10.3 node contract has no `category` field at
all — the vocabulary lands in `subtype` ("Framework/provider-specific type such
as `express-route`, `postgres-table`, `stdout`"), and `schema.js`'s own comment
on `SOURCE_CATEGORIES`/`SINK_CATEGORIES` says so explicitly: *"the fixed
vocabulary a node's `subtype`/an inventory row's `category` field draws from."*
So D2/D3 emit `category`, and Sub-project E's graph builder writes it to
`node.subtype`. Neither side should invent a third name, and a registry must
not emit a field literally called `subtype` — the two are the same vocabulary
at different layers, and conflating them would let a registry decision be
validated as a node without ever passing through the builder.

A `null` `category` therefore becomes a `null`/absent `subtype`, which is
exactly what an `unsupported` node needs (§6.4) — its `kind` and `reason` carry
the meaning instead.

### D2 — `src/lineage/source-registry.js`

1. Export `reclassifySource(entry)` returning the §9.0 shape. `kind` is always
   `'source'` (§7.1).
2. Port `PROVENANCE_MAP` (12 rows, §4), `AGENT_TOOL_REFINEMENT` (8 rows, §4.1),
   the `language === 'cpp'` descriptor-generic refinement (§4.2) and
   `NO_PROVENANCE_OVERRIDES` (82 rows, §4.3) from
   `test/lineage/registry-mapping-poc.test.js` — see §9.1 for why that file is
   the source of truth for the 82-row table and what happens to it afterwards.
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
5. **Close FR-203 — a dynamic destination still produces a node.** The parent
   scoping doc assigns FR-203 to D3 explicitly, and nothing else in this
   checklist covers it, because it is a *different axis* from everything above:
   §5's tables answer "which category is this sink", FR-203 answers "we know
   the call, but not where it points". A recognized sink whose destination
   cannot be resolved (`fetch(url)` with a computed `url`, an SDK client built
   from config) must emit a node with **`kind: 'unresolved'`** — the
   `NODE_KINDS` value that exists for exactly this and is used nowhere else in
   this design — its resolved `category` retained (the *category* is known even
   when the *destination* is not), `externality: 'unknown'`, and a `reason`
   naming the expression that prevented resolution, since FR-203 requires the
   evidence panel to show it. **`coverageStatus`** carries over unchanged from
   whatever the category mapping already assigned the underlying catalog entry
   (§4/§5) — destination resolution is a different axis from classification
   confidence (this item's own opening sentence), so a `modeled` sink whose
   destination happens to be dynamic stays `modeled`; it does NOT demote to
   `partial` the way §16.7 half 2's degraded-dead-end node does (that node
   carries `partial` for an unrelated reason — the analysis itself is
   incomplete, not the classification, per §9.2's own routing above — do not
   conflate the two `unresolved`-kind cases). **Never** drop the node, and never let it
   degrade into the `process`/`unsupported` bucket, which means something
   entirely different (§3: no category exists at all). Note D3 can only mark
   the *shape*; actually resolving destinations is FR-202 and lands in
   Milestone 2 (§7.5).
6. Ship the measured-count pins (§4.3, §5.1, §5.2) as tests. `bench/layer-recall`
   has already demonstrated in this repo that a floor-only gate lets a stale
   published number survive for weeks; these are equality pins for that reason.

### 9.1 Who owns the 82-row override table, and who deletes the PoC

Two questions every prior sub-project answered explicitly and this one must
too (the precedent is `DESIGN_PATH_PROVENANCE.md` §13.7 item 15, where a single
absorbing task carried an explicit deletion instruction).

**The override table's permanent home is `source-registry.js`.** It is code,
not prose, and it belongs in the module that executes it. This ADR
deliberately does **not** reproduce all 82 rows: a hand-copied 82-row table in
markdown would drift from the executable one with nothing able to detect the
drift, which is strictly worse than a single authoritative copy plus a pointer.
What this document owns instead is the *derivation rule* (§4.3 + §6.3) and the
*completeness guarantee* (D2 item 4) — both of which survive any move of the
table itself. Until D2 lands, the PoC is the table's interim home; after D2
lands, `source-registry.js` is, and the PoC's copy is redundant.

**Deletion: whichever of D2/D3 lands SECOND deletes
`test/lineage/registry-mapping-poc.test.js`**, in its own commit, after
confirming the other increment's absorption is complete. D2 and D3 run in
parallel (§9.2) and each absorbs a *disjoint* half of the PoC — D2 the source
tables and guards, D3 the sink and privacy ones — so neither may delete it
unilaterally while the other is still in flight. The second-lander must verify
both halves are present as shipped tests before removing it, and must also
remove the file from `package.json`'s `test:lineage` script and from this
package's `CLAUDE.md` table in the same commit. If D4 somehow lands before
either, it changes nothing: D4 absorbs no part of this file (§8 is
confirmations only, `D1/7a`/`D1/7b` stay until the second registry lands).

### 9.2 Sequencing and D5's exit criterion

D2 and D3 are independent and can run in parallel — they share only this
document and `schema.js`, and touch disjoint files. D4 depends on §8 but not on
D2/D3.

**D5's exit criterion, as the parent scoping doc states it, cannot pass — and
must be corrected before D5 is briefed.** That doc's D5 row reads: *"every
FR-101/FR-201 source/sink category has at least one real-code proof."* §7.2
measures why that is unachievable: **19 of 29 sink categories and 7 of 21
source categories have zero catalog entries mapping to them**, by construction
rather than by any implementation gap. No quality of D2/D3/D4 execution can
change that, because the detection those categories would need does not exist
anywhere in the scanner (§7.2's headline: all nine `ai-*` sink categories are
among them). Briefed as written, D5 would either fail permanently or be quietly
softened — and quietly softening a coverage criterion is precisely the failure
mode this whole PRD treats as load-bearing.

This is a defect in D5's *paraphrase*, not in FR-201. FR-201's own text says
**"all *supported* sinks must remain discoverable"**, and the `unsupported`-
with-reason design satisfies that honestly: every one of the 756 entries
produces a node carrying a non-empty reason (`D1/1e`), and every unreachable
category is named in a test that fails if the set changes (`D1/6a`, `D1/6b`).

**The corrected criterion D2–D5 should be built and judged against:**

> Every **reachable** category has at least one real-code proof, **and** every
> **unreachable** category has a recorded, tested reason — never silent
> absence.

Both halves are testable today and already have their shape fixed by `D1/6a`
and `D1/6b`, which pin the unreachable sets as exact lists. D5's job is to
extend that from "the registry maps it" to "real parsed code exercises it",
for the reachable half only, while inheriting the unreachable half's existing
assertions unchanged. A category moving from unreachable to reachable is then
a *deliberate* event that fails a test and forces both lists to be updated —
which is the behavior wanted, and the opposite of a floor-only gate.

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

§16.7 offers two fixes, and they are **not alternatives — they are two halves,
one of which is D's**. Both are settled here.

**Half 2 (the taxonomy) IS D's, and is decided now.** §16.7's second option —
"Sub-project D's registry deciding a degraded dead end is a reportable
endpoint" — is a vocabulary question in §6/§7.1's remit and needs no
`PathStore` at all, so leaving it open would force Sub-project E to invent the
node's vocabulary while implementing the enumerator. **A truncation-terminal —
a `path` node with zero out-edges whose in-edges carry a
`context-cap-degraded` annotation — is a reportable endpoint, and it carries
`kind: 'unresolved'`, `coverageStatus: 'partial'`, `externality: 'unknown'`,
with a `reason` naming the context-cap degradation.** The reasoning, in the
terms §6 and §7.1 already set: `unresolved` is right for the same reason it is
right for FR-203 (§9's D3 item 5) — the flow is known to exist and its endpoint
is not knowable, which is exactly what that kind means, and it must **not** be
`process`/`unsupported`, which asserts the different and false claim that no
category models it; `partial` is right because the analyzer genuinely observed
this flow and lost only its continuation, which is §6.2's "sure, and lossy in a
stated way", not §6.3's "inferred" or §6.4's "unmodellable"; `externality:
'unknown'` follows §7.5 directly, since the callee's body was never analyzed
and nothing is known about where the data goes next. This is the one place in
this design where a node's `coverageStatus` comes from the *analysis* rather
than from a catalog entry — consistent, because a truncation-terminal has no
catalog entry behind it at all, which is exactly why §4/§5's tables could not
settle it.

**Half 1 (the enumerator) is Sub-project E's, not D2's or D3's.**
`sinkCandidates()` is documented as a
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
