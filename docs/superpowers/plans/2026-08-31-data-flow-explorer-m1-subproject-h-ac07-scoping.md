# Sub-project H, AC-07 closure — scoping report (AI-sink catalog bridge)

**Status:** research/scoping only, no production code or fixture files changed. Written to ground a real implementation plan for closing AC-07 (PRD §25, lines 1627-1631) — one of Milestone 1's 4 exit-gate criteria (§26, line 1796). Grounds itself in Sub-project F's own scoping report §5, which found AC-07 unsatisfiable today (`dataflow/catalog.js` has zero AI-provider sink entries) but recommended porting `posture/aibom.js`'s already-validated detection patterns as "bounded, scoped engineering work — a real increment, not a research problem." This report proves that recommendation concretely, against real parsed code.

---

## 1. `aibom.js`'s `PROVIDER_PATTERNS` — full list, extracted call shapes

Read in full (`scanner/src/posture/aibom.js:30-49`), 11 entries:

| provider | call shape (receiver.method chain) | argument carrying the model/payload |
|---|---|---|
| openai | `(openai\|client\|oai).(chat.)?completions.create({model, ...})` | object literal, `model` key |
| openai | `(openai\|client\|oai).responses.create({model, ...})` | object literal, `model` key |
| anthropic | `(anthropic\|client\|claude).(messages\|completions).create({model, ...})` | object literal, `model` key |
| openai (vercel-ai) | `generateText/streamText/generateObject({model: openai("...")})` | nested SDK call inside an object literal |
| anthropic (vercel-ai) | same, `model: anthropic("...")` | same |
| google | `(genAI\|GoogleGenerativeAI)(...).getGenerativeModel({model})` | chained constructor + method |
| mistral | `mistral.chat.complete({model})` | object literal |
| cohere | `(cohere\|co).(chat\|generate)({model})` | object literal |
| groq | `groq.chat.completions.create({model})` | object literal |
| bedrock | `InvokeModelCommand({modelId})` | object literal, bare call (constructor-shaped, no fixed receiver) |
| replicate | `replicate.(run\|predictions.create)('owner/model', ...)` | positional string, not an object |

**Scope decision for THIS increment (recommended): openai (chat.completions + responses), anthropic (messages), bedrock.** These are AC-07's own worked example verbatim ("Anthropic/OpenAI/Bedrock model request," PRD line 1629). Google/Mistral/Cohere/Groq/Replicate/vercel-ai are structurally the same kind of work (a `match` descriptor per shape) and should be a follow-up increment, not scope creep into this one — flagged as an explicit open question in §8.

---

## 2. `dataflow/catalog.js`'s matcher semantics — read from the real implementation, not guessed

Read `_receiverSegments`/`_receiverAllowed` (`catalog.js:1406-1465`) and the index-build loop (`catalog.js:1544-1567`) directly.

- **Indexing is by bare callee NAME.** `match.type: 'call'` entries are keyed in `CALLEE_INDEX` by `match.callee` (e.g. `'create'`), not by the full chain. Every `X.create(...)` call site in the whole codebase is a CANDIDATE for every entry keyed `callee: 'create'` — precision comes ENTIRELY from `match.receiver`/`match.receiverBase`, which are checked afterward.
- **`_receiverSegments(calleeExpr)` walks the WHOLE member chain outward from the callee**, collecting every intermediate property name plus the base identifier. For `anthropic.messages.create(...)`, the callee is `create`; segments (measured, via a real parse — see §3) are `['messages', 'anthropic']`. For `openai.chat.completions.create(...)`, segments are `['completions', 'chat', 'openai']`.
- **`match.receiver`** requires ONE segment to match the regex. **`match.receiverBase`** (optional, additive) requires an INDEPENDENT second segment to ALSO match — both are checked against the same segment set, order-independent. This is exactly what distinguishes `openai.chat.completions.create` (has both `completions` and `chat` segments) from `anthropic.completions.create` (has `completions` but never `chat`) — using `receiver: '^completions$'` alone would match both; adding `receiverBase: '^chat$'` scopes it to only the chat-completions shape.
- **`match.receiverTypeIn`** (CHA-resolved class type) is NOT needed here — these are exact, distinctive method-chain names, not a generic vocabulary like `db`/`pool`/`conn` that needs type-narrowing. Confirmed unnecessary for this closure, not merely omitted.
- **A bare, unqualified constructor-shaped call** (`InvokeModelCommand({...})`, no receiver at all) needs NO `match.receiver` — bare-name matching alone is safe here because `InvokeModelCommand` is a distinctive, unambiguous identifier (the same precedent `js-fetch: {type:'call', callee:'fetch'}` already uses for a bare global).

**Critical, measured finding — the realistic Bedrock call shape defeats lineage's own sink enumeration, even though the dataflow taint engine sees it fine.** Real AWS SDK v3 usage is `client.send(new InvokeModelCommand({modelId, body}))` — parsed (confirmed live, `parser-js.js`), the TOP-LEVEL CFG node is a `call` whose callee is `client.send`; `new InvokeModelCommand({...})` lowers to a NESTED `{kind:'call', callee:{kind:'ident',name:'InvokeModelCommand'}, isNew:true}` inside `client.send`'s own `args[0]`. `dataflow/engine.js`'s `_nestedSinkFindings` (documented in `dataflow/CLAUDE.md`) DOES walk into nested call arguments for ordinary SAST/taint purposes — so a `js-bedrock-invoke-model-command` catalog entry would fire correctly for taint/SAST findings on this realistic shape. **But `lineage/graph-builder.js`'s `enumerateSinkSites` only enumerates BARE STATEMENT `call`-kind CFG nodes** (§4.1 of `DESIGN_GRAPH_BUILDER.md`, re-confirmed by reading `enumerateSinkSites` directly) — a call nested inside another call's argument list is only ever recorded in `nonStatementSitesNotEnumerable`, never becomes an `escape` provenance node, and can never anchor a lineage flow. **A realistic `client.send(new InvokeModelCommand({...}))` fixture would therefore be structurally unscoreable by `bench/data-lineage/`'s own runner (F1), even after this catalog fix lands** — not a catalog gap, a pre-existing, disclosed lineage-engine limitation (the same one that already produces `js-exec-unsupported-sink`-style capability-tier fixtures in Sub-project F). The AC-07 corpus fixture must therefore call `InvokeModelCommand({...})` as a BARE STATEMENT (no `client.send(...)` wrapper, no `new`) to be lineage-scoreable — see §7's fixture sketch. Also true, independently confirmed: `const resp = anthropic.messages.create({...})` (an ASSIGN-form call, the realistic way these SDKs are actually used — you need the response) is likewise NOT enumerable by `enumerateSinkSites` (which only reads `node.kind === 'call'` statement nodes, never an `assign` node's call-shaped `source`). **Every AC-07 corpus fixture must call the AI SDK as a bare, un-assigned statement** for the lineage engine to see it as a connected flow. This is a real, disclosed authoring constraint for whoever writes the fixture (§7), not a catalog defect.

---

## 3. Proposed `dataflow/catalog.js` entries — structurally verified against real parsed code

Verified live: parsed the 3 real call shapes below via `parseJsFile`, extracted the real receiver-segment sets (`_receiverSegments`'s own algorithm, reproduced verbatim), and confirmed each proposed entry matches its intended shape and REJECTS the other two — 9/9 checks passed, zero false positives, zero false negatives.

```js
// dataflow/catalog.js — new sink entries (append near the other AI/ML-adjacent
// entries, or a new "AI model provider sinks" section)

{ kind: 'sink', id: 'js-openai-chat-completions-create', language: 'js', framework: 'openai',
  match: { type: 'call', callee: 'create', receiver: '^completions$', receiverBase: '^chat$' }, argIndex: 0,
  vuln: { name: 'Regulated Data to AI Model Provider (OpenAI chat.completions.create)', severity: 'medium', cwe: 'CWE-201',
          remediation: 'Confirm the request payload carries no PCI/PHI/PII before sending to a third-party model provider, or route through an approved DPA / redaction layer.' } },

{ kind: 'sink', id: 'js-openai-responses-create', language: 'js', framework: 'openai',
  match: { type: 'call', callee: 'create', receiver: '^responses$' }, argIndex: 0,
  vuln: { name: 'Regulated Data to AI Model Provider (OpenAI responses.create)', severity: 'medium', cwe: 'CWE-201',
          remediation: 'Confirm the request payload carries no PCI/PHI/PII before sending to a third-party model provider, or route through an approved DPA / redaction layer.' } },

{ kind: 'sink', id: 'js-anthropic-messages-create', language: 'js', framework: 'anthropic',
  match: { type: 'call', callee: 'create', receiver: '^messages$' }, argIndex: 0,
  vuln: { name: 'Regulated Data to AI Model Provider (Anthropic messages.create)', severity: 'medium', cwe: 'CWE-201',
          remediation: 'Confirm the request payload carries no PCI/PHI/PII before sending to a third-party model provider, or route through an approved DPA / redaction layer.' } },

{ kind: 'sink', id: 'js-bedrock-invoke-model-command', language: 'js', framework: 'bedrock',
  match: { type: 'call', callee: 'InvokeModelCommand' }, argIndex: 0,
  vuln: { name: 'Regulated Data to AI Model Provider (AWS Bedrock InvokeModelCommand)', severity: 'medium', cwe: 'CWE-201',
          remediation: 'Confirm the request payload carries no PCI/PHI/PII before sending to a third-party model provider, or route through an approved DPA / redaction layer.' } },
```

Measured match matrix (real parse + real `_receiverSegments`/`_receiverAllowed` logic, all 4 entries × 3 real call shapes — `InvokeModelCommand` omitted from the matrix since it has no receiver constraint to test):

| real call site | `js-openai-chat-completions-create` | `js-openai-responses-create` | `js-anthropic-messages-create` |
|---|---|---|---|
| `openai.chat.completions.create(...)` | **true** | false | false |
| `openai.responses.create(...)` | false | **true** | false |
| `anthropic.messages.create(...)` | false | false | **true** |

`argIndex: 0` (whole first-argument object) matches the established precedent every other object-literal-argument sink in this catalog already uses (e.g. `s3.putObject(params)` in `privacy-catalog.js`) — the taint/field-identity engines already walk into object-literal properties structurally, so a PHI field nested at `messages[0].content` reaches the sink through the SAME mechanism proven for every other object-argument sink; not a new capability.

**Not proposed in this pass, flagged as an open question (§8):** the legacy `anthropic.completions.create(...)` shape (superseded by `messages.create`, still in `aibom.js`'s regex) — a `receiver: '^completions$', receiverExclude: '^chat$'` entry would close it cleanly (excludes the openai chat-completions shape via the same `receiverExclude` mechanism `py-compile` already uses), but is lower priority than AC-07's own named 3 providers.

---

## 4. CWE/family convention — CWE-201, NOT CWE-359

**CWE-359 is explicitly forbidden for this purpose.** `sink-registry.js`'s `PRIVACY_CATEGORY_MAP` already owns CWE-359 for the whole `privacy-catalog.js` family (console.log, res.send, fetch, fs.writeFile, s3.putObject, sendMail, mongo insert, queue publish — "Privacy Leak" as a generic label), and the hotfix that just landed (`docs/superpowers/plans/2026-08-31-lineage-coverage-privacy-catalog-fr203-hotfix.md`) added `sink-registry.test.js`'s `completeness/1c`, which asserts — and would FAIL the build if violated — that `CWE_MAP` NEVER maps `'CWE-359'`, specifically because doing so would silently reclassify every privacy-catalog entry as whatever category `'CWE-359'` mapped to. Re-verified live: `CWE-201` has zero occurrences anywhere in `catalog.js` or `sink-registry.js` today — free to use.

**Recommendation: `CWE-201` (Insertion of Sensitive Information Into Sent Data)** — a real, standard CWE whose own definition ("transmission of data to another actor... where the data has not been properly scrubbed of sensitive information") is a closer semantic fit for "sent regulated data to a third-party AI model provider" than CWE-359 ("Exposure of Private Personal Information to an Unauthorized Actor," the broader privacy-leak umbrella already spoken for). Distinct CWE, distinct category, no collision, no ambiguity for a future reader of `CATALOG`.

---

## 5. `sink-registry.js` change — one new `CWE_MAP` row, additive only

```js
// sink-registry.js's CWE_MAP, new row:
'CWE-201': Object.freeze({ category: 'ai-model-provider', status: 'modeled',
  why: 'a call to a named AI model provider SDK (OpenAI/Anthropic/Bedrock) is unambiguously an AI-model-provider destination' }),
```

`schema.js`'s `SINK_CATEGORIES` (`src/lineage/schema.js:73-74`) confirmed to include exactly 9 `ai-*` values: `ai-model-provider`, `ai-local-model`, `ai-agent`, `ai-tool`, `ai-vector-store`, `ai-memory`, `ai-training`, `ai-evaluation`, `ai-telemetry`. `ai-model-provider` is the correct single target for all 4 proposed entries (a direct API call to a hosted model provider — not `ai-agent`/`ai-tool`, which are for agent-framework/tool-call shapes, out of scope here). `CATEGORY_NODE_KIND['ai-model-provider']` and `CATEGORY_EXTERNALITY['ai-model-provider']` are both ALREADY `'external'` in `sink-registry.js` (D1/D3's own tables, unchanged, no edit needed) — this closure needs exactly ONE new line in `CWE_MAP`, nothing else in the registry.

**Completeness-guard consequence, must be updated in the same change:** `sink-registry.test.js`'s pinned "19 unreachable `SINK_CATEGORIES`" list (§7.2 of `DESIGN_REGISTRIES.md`, currently including all nine `ai-*` values as unreachable) drops to 18 once `ai-model-provider` becomes reachable — the pinned-list test must be updated in the same commit or it will fail loudly (a good thing — it's the completeness guard doing its job, not a bug to route around).

---

## 6. Scope boundary: sink-category reclassification is enough; provider/model detail is NOT this increment's job

Read `graph-builder.js`'s node-minting (`mintNode`, `sinkNodeFor`) directly: a node's identity is `(kind, subtypeKey, coverageStatus, externality, destination)` where `subtypeKey` is the registry `category` and `destination` is **always `''` in Milestone 1** (§6.1 of `DESIGN_GRAPH_BUILDER.md`, unchanged by this closure). This means **every AI provider collapses onto the SAME `ai-model-provider` node** — the graph cannot and will not distinguish "went to OpenAI" from "went to Anthropic" from "went to Bedrock" at the node level; that is FR-202's job (external destination resolution, explicitly Milestone 2, per the PRD's own Milestone 2 deliverables: "external resolver... AI-BOM linkage"). **This increment's correct, bounded scope is proving the FLOW** — a PHI/PCI/PII-tagged data element reaches an `ai-model-provider`-category node — **not** attaching provider/model evidence to the graph. AC-07's own wording ("provider, model when known") is explicitly a Milestone-2-or-later enrichment on top of this increment's flow proof, not something this increment must deliver. No scope creep recommended.

---

## 7. Corpus fixture sketch (no fixture file written — proof-on-paper only)

`bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/source.js` (sketch, matching the existing corpus format exactly):

```js
function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
```

Note the two authoring constraints from §2, both load-bearing: (a) the call is a BARE STATEMENT, never assigned to a variable — an assign-form call is invisible to `enumerateSinkSites`; (b) the source field name is `patient_record` (verified in Sub-project F's own F2 batch to classify `['PHI']` — `patient_summary` does NOT match the PHI regex, a real, previously-measured correction). `expected.json` would read `sourceCategory: 'ai-model-output'` (already reachable, D2), `sinkCategory: 'ai-model-provider'` (newly reachable by this closure), `dataClass: ['PHI']`, `expectedTransformKind: null`, `tier: 'regression'`. This is Sub-project F's own job to actually author and verify against real runner output (per F1/F2's established "never guess, always verify" discipline) — sketched here only to confirm the catalog entries proposed in §3 make this fixture SHAPE achievable on paper.

---

## 8. Open questions for the implementation plan

1. **Scope of providers in THIS increment.** Recommended: OpenAI (chat.completions + responses) + Anthropic (messages) + Bedrock (InvokeModelCommand) — AC-07's own named 3. Google/Mistral/Cohere/Groq/Replicate/vercel-ai wrapper forms are the same mechanical work, deliberately deferred to a follow-up (not blocking Milestone 1's exit gate, which only names AC-07's own scenario).
2. **The legacy `anthropic.completions.create` shape** (§3's closing note) — include now (cheap, one more entry with `receiverExclude`) or defer with the other non-core providers? Low-cost either way; a real implementation plan should just decide and move on.
3. **Severity/CWE choice is a judgment call, not a measured fact** — `CWE-201` at `severity: 'medium'` mirrors this catalog's own privacy-adjacent sink severities (`privacy-catalog.js`'s CWE-359 entries range `medium`/`high` by destination sensitivity); a plan author should sanity-check this against the codebase's actual severity-assignment conventions for third-party-data-exposure sinks before finalizing, not just copy this report's guess.
4. **Should the same 4 shapes also get privacy-catalog (`PRIVACY_SINK_CATALOG`) siblings**, the way `s3.putObject` has both a general-CATALOG entry AND a privacy-catalog entry? Given AC-07 is specifically a lineage/lineage-registry concern (reachable via `sink-registry.js`'s CWE-keyed `reclassifySink`, which only reads general `CATALOG`), a privacy-catalog sibling is NOT needed to close AC-07 itself — but may be worth adding later for this codebase's OWN privacy-taint engine (`dataflow/index.js`'s `AGENTIC_SECURITY_PRIVACY_DEEP` pass) to also recognize AI-provider leaks as a "Privacy Leak" finding, independent of lineage. Out of THIS closure's scope; flagged for whoever next touches `privacy-catalog.js`.
5. **The nested/assign-form fixture-authoring constraint (§2) should be documented somewhere durable** — likely a short addition to `bench/data-lineage/README.md` (matching how F2 already documents its own discovered constraints) or `DESIGN_GRAPH_BUILDER.md` §4.1's existing "enumeration unit is a CFG call STATEMENT node" note — so a future AC-07 (or any AI-sink) fixture author doesn't rediscover this the hard way.
