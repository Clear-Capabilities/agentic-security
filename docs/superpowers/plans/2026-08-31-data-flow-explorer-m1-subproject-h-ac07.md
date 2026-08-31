# Data Flow Explorer — Sub-project H, AC-07 closure (AI-sink catalog bridge) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close AC-07 (PRD §25, "AI and regulated data intersection" — one of Milestone 1's 4 exit-gate criteria) by porting `posture/aibom.js`'s already-validated AI-provider call-shape detection into real `dataflow/catalog.js` sink entries for OpenAI, Anthropic, and Bedrock — AC-07's own named providers — making `ai-model-provider` a reachable `SINK_CATEGORIES` value for the first time, and proving the resulting flow end-to-end with a real corpus fixture.

**Architecture:** Two additive catalog entries' worth of work (4 new `dataflow/catalog.js` sink entries + 1 new `sink-registry.js` `CWE_MAP` row) plus the completeness-guard updates this codebase's own discipline requires whenever a previously-unreachable category becomes reachable, plus one real corpus fixture proving the flow through `buildGraphWithCoverage`. No `src/lineage/` production logic changes beyond the one `CWE_MAP` row — the reclassification, node-minting, and flow-reconstruction machinery are all already correct and just need something real to reclassify.

**Tech Stack:** Node ≥ 24, ESM.

**Spec:** `docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-h-ac07-scoping.md` — read it in full; every entry and decision below is sourced from its §1-§7, each independently verified against real parsed code and the real matcher implementation (a 9/9 match-matrix proof, not a guess).

## Global Constraints

- **`CWE-201` is the chosen CWE, `CWE-359` is FORBIDDEN.** `sink-registry.js`'s own `completeness/1c` test (added in the 2026-08-31 privacy-catalog FR-203 hotfix) asserts `CWE_MAP` never maps `'CWE-359'` — that CWE belongs exclusively to `PRIVACY_SINK_CATALOG`'s "Privacy Leak" family. Mapping it here would silently reclassify every privacy-catalog entry. `CWE-201` (Insertion of Sensitive Information Into Sent Data) is confirmed unused anywhere in `catalog.js`/`sink-registry.js` today.
- **Scope is OpenAI (chat.completions.create + responses.create), Anthropic (messages.create), and Bedrock (InvokeModelCommand) only** — AC-07's own named 3 providers (PRD line 1629). Google/Mistral/Cohere/Groq/Replicate/vercel-ai wrapper forms and the legacy `anthropic.completions.create` shape are explicitly deferred to a follow-up increment — do not add them in this plan.
- **This closure proves the FLOW, not provider/model attribution.** A node's identity in Milestone 1's graph is `(kind, subtypeKey, coverageStatus, externality, destination)` with `destination` always `''` — every provider collapses onto the same `ai-model-provider` node. This is correct and by design (FR-202/external destination resolution is Milestone 2's job); do not attempt to add provider/model evidence to the graph in this plan.
- **The realistic call shapes are NOT lineage-scoreable — this is a real, disclosed constraint, not a bug to fix.** `client.send(new InvokeModelCommand({...}))` (nested call) and `const resp = anthropic.messages.create({...})` (assign-form call) are both invisible to `graph-builder.js`'s `enumerateSinkSites`, which only enumerates bare-STATEMENT `call`-kind CFG nodes (§4.1 of `DESIGN_GRAPH_BUILDER.md`). The corpus fixture in Task 2 MUST call the AI SDK as an unassigned bare statement. Do not attempt to extend `enumerateSinkSites` to handle nested/assign-form calls in this plan — that is a separate, larger change with its own blast radius across every other sink category, well outside AC-07's own scope.
- `npm run test:dataflow` (the catalog lives under `dataflow/`) and `npm run test:lineage` (the registry/corpus live under `lineage/`/`bench/data-lineage/`) must both stay green, plus the full `npm test` gate.

---

### Task 1: the 4 catalog entries + the `CWE_MAP` row + completeness-guard updates

**Files:**
- Modify: `scanner/src/dataflow/catalog.js`
- Modify: `scanner/src/lineage/sink-registry.js`
- Modify: `scanner/test/lineage/sink-registry.test.js`
- Modify: `scanner/test/lineage/registry-real-code.test.js`

**Interfaces:** None new — `reclassifySink`'s signature is unchanged; this task only adds data the existing machinery already knows how to process.

- [ ] **Step 1: Add the 4 new sink entries to `dataflow/catalog.js`**

Add near the other sink entries (a new "AI model provider sinks" comment section is fine, or append near the existing SSRF/network sinks — match this file's own section-heading convention):

```js
// AI model provider sinks (AC-07 closure — Sub-project H). Regulated data
// (PCI/PHI/PII) reaching a hosted third-party AI model provider is a real
// data-exposure concern the same way any other third-party API call is —
// CWE-201 (Insertion of Sensitive Information Into Sent Data), NOT CWE-359
// (reserved exclusively for privacy-catalog.js's own "Privacy Leak" family
// — sink-registry.js's completeness/1c test enforces this).
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

Before trusting the `receiver`/`receiverBase` fields blindly, re-verify the scoping report's own match-matrix claim yourself: write a throwaway script parsing `openai.chat.completions.create(...)`, `openai.responses.create(...)`, and `anthropic.messages.create(...)` via `parseJsFile`, and confirm `matchSinkOrSanitizer`/`matchSinkOrSanitizer`-equivalent matching logic resolves each to exactly the intended entry and no other (the scoping report's own §3 measured this as 9/9 — reproduce at least a few of those 9 checks yourself before moving on).

- [ ] **Step 2: Add the `CWE_MAP` row to `sink-registry.js`**

Find `CWE_MAP`'s object literal and add:

```js
  'CWE-201': Object.freeze({ category: 'ai-model-provider', status: 'modeled',
    why: 'a call to a named AI model provider SDK (OpenAI/Anthropic/Bedrock) is unambiguously an AI-model-provider destination' }),
```

- [ ] **Step 3: Update `sink-registry.test.js`'s pinned unreachable-category list**

Find the test `'unreachable sink categories match the pinned list from DESIGN_REGISTRIES.md §7.2 — including EVERY ai-* sink'`. This test's own name and one of its assertions (`for (const c of aiSinks) assert.ok(!reachable.has(c), ...)`) are now factually wrong — `ai-model-provider` IS reachable. Update:

```js
test('unreachable sink categories match the pinned list from DESIGN_REGISTRIES.md §7.2 — all ai-* EXCEPT ai-model-provider, closed by the AC-07 catalog bridge', () => {
  const reachable = new Set([
    ...SINKS.map((e) => reclassifySink(e).category),
    ...PRIVACY_SINK_CATALOG.map((e) => reclassifyPrivacySink(e).category),
  ].filter(Boolean));
  const unreachable = SINK_CATEGORIES.filter((c) => !reachable.has(c)).sort();
  assert.deepEqual(unreachable, [
    'ai-agent', 'ai-evaluation', 'ai-local-model', 'ai-memory',
    'ai-telemetry', 'ai-tool', 'ai-training',
    'ai-vector-store', 'backup', 'cache', 'collaboration', 'declared',
    'export', 'monitoring', 'push-notification', 'sms', 'stdout', 'webhook',
  ], 'sink-side coverage gap changed — re-read DESIGN_REGISTRIES.md §7.2');
  assert.equal(reachable.size, 11);
  const aiSinks = SINK_CATEGORIES.filter((c) => c.startsWith('ai-'));
  assert.equal(aiSinks.length, 9);
  for (const c of aiSinks) {
    if (c === 'ai-model-provider') { assert.ok(reachable.has(c), 'ai-model-provider must now be reachable — AC-07 closure'); continue; }
    assert.ok(!reachable.has(c), `${c} unexpectedly reachable`);
  }
});
```

Run this test in isolation before moving on: `node --test test/lineage/sink-registry.test.js` — confirm it fails BEFORE Step 1/2's catalog changes (proving the old assertion was real) is not necessary here since you're editing sequentially, but DO confirm it passes AFTER Steps 1-2 are in place, and that the exact `reachable.size`/unreachable-list numbers match what you actually measure, not what this plan guessed — if your real count differs, trust your measurement and correct this step's own numbers, noting why in your task report.

- [ ] **Step 4: Add a `sink-registry.test.js` reachability test for the 4 new entries**, mirroring the file's own existing per-entry test convention (representative real end-to-end reclassifications):

```js
test('AC-07 closure: all 4 new AI-model-provider entries reclassify to ai-model-provider/modeled/external', () => {
  for (const id of ['js-openai-chat-completions-create', 'js-openai-responses-create', 'js-anthropic-messages-create', 'js-bedrock-invoke-model-command']) {
    const entry = SINKS.find((e) => e.id === id);
    assert.ok(entry, `${id} must exist in CATALOG`);
    const decision = reclassifySink(entry);
    assert.equal(decision.category, 'ai-model-provider');
    assert.equal(decision.coverageStatus, 'modeled');
    assert.equal(decision.externality, 'external');
    assert.equal(decision.kind, 'external');
  }
});
```

- [ ] **Step 5: Add a real-code proof to `registry-real-code.test.js`**, matching D5's own established `SINK_PROOFS` convention (every reachable sink category gets one real-parsed-code proof):

Find `SINK_PROOFS` and add one entry:

```js
  { category: 'ai-model-provider', entryId: 'js-anthropic-messages-create', catalogSide: 'catalog', extraction: 'call-sink', src: 'anthropic.messages.create(params);' },
```

Find the test asserting `SINK_PROOFS.length === 10` / `cats.size === 10` and update both to `11`.

- [ ] **Step 6: Run the scoped test suites**

Run: `cd scanner && npm run test:dataflow`
Expected: prior count + 0 new tests here (Task 1 adds no new `dataflow/` tests, only new catalog data) — but confirm no EXISTING `dataflow/` test regresses (a new sink entry could theoretically collide with an existing one on the same `callee` index bucket — `create`/`InvokeModelCommand` — verify no existing catalog test asserting "exactly N candidates for callee X" breaks).

Run: `cd scanner && npm run test:lineage`
Expected: prior count + 2 (Step 4's new test, plus whatever `SINK_PROOFS`'s loop-generated test count change is — confirm the real delta, don't guess it).

- [ ] **Step 7: Commit**

```bash
git add scanner/src/dataflow/catalog.js scanner/src/lineage/sink-registry.js scanner/test/lineage/sink-registry.test.js scanner/test/lineage/registry-real-code.test.js
git commit -m "feat(lineage): close AC-07 — bridge OpenAI/Anthropic/Bedrock AI-sink detection into the taint catalog (Sub-project H)"
```

---

### Task 2: the AC-07 corpus fixture + the durable enumeration-constraint doc note

**Files:**
- Create: `bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/{source.js,expected.json}`
- Modify: `bench/data-lineage/README.md` (the durable doc note about the bare-statement enumeration constraint)
- Modify: `scanner/test/bench-data-lineage-runner.test.js`'s `F1/11` regression pin (fixture-count floor, same update pattern F2's own Task 4 already established)

**Interfaces:** None new — this task only adds corpus content, scored by the already-shipped `runner.mjs`.

- [ ] **Step 1: Author the fixture**

`bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/source.js`:

```js
function summarizePatient(anthropic, params) {
  const patientRecord = params.arguments.patient_record;
  anthropic.messages.create({
    model: 'claude-3',
    messages: [{ role: 'user', content: patientRecord }],
  });
}
```

`bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PHI"],
  "sourceCategory": "ai-model-output",
  "sinkCategory": "ai-model-provider",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "tier": "regression",
  "notes": "AC-07's own worked example (PRD line 1629): patient_record (PHI) flows into an anthropic.messages.create() call — the AI-sink catalog bridge (Sub-project H) that closes this fixture's own sinkCategory reachability. The call is a BARE STATEMENT (never assigned to a variable, never nested inside client.send(...)) — both are load-bearing: enumerateSinkSites only enumerates bare-statement call CFG nodes (DESIGN_GRAPH_BUILDER.md §4.1), so an assign-form or nested-call shape (the more 'realistic' way these SDKs are actually used) would be invisible to this corpus's own scoring, per the AC-07 catalog-bridge scoping report §2. patient_record (not patient_summary — verified in Sub-project F's own F2 batch) is the field name that classifies PHI."
}
```

- [ ] **Step 2: Run the runner and verify against real output**

Run: `node bench/data-lineage/runner.mjs` from the repo root. This fixture must report `ok` — if it doesn't, this is the single most important verification in this whole plan (it's the actual proof AC-07 is closed). Read the printed error if it fails and determine the real cause before adjusting anything; do not weaken `expected.json` to force a pass without understanding why the real output differs.

Run: `node bench/data-lineage/runner.mjs --check; echo "exit: $?"` and confirm the new fixture is counted, `regression-tier failure(s)` stays 0, exit 0.

- [ ] **Step 3: Add the durable enumeration-constraint doc note**

Per the scoping report's own §8 open question 5, add a short paragraph to `bench/data-lineage/README.md` (near where F2's own discovered constraints are already documented) stating: any AI-SDK (or, in general, any sink whose realistic call shape is nested inside another call's arguments, or is an assign-form call capturing a response) must be authored as a bare, un-assigned statement to be lineage-scoreable — `enumerateSinkSites` only enumerates bare-statement `call`-kind CFG nodes (cite `DESIGN_GRAPH_BUILDER.md` §4.1) — so a fixture author cannot write the SDK call the way it's actually used in production code (`client.send(new InvokeModelCommand(...))`, `const resp = anthropic.messages.create(...)`) and expect it to score.

- [ ] **Step 4: Update `F1/11`'s fixture-count floor**, mirroring F2's own Task 4 pattern exactly (recompute the real new total from what's actually on disk, don't guess it).

- [ ] **Step 5: Run the full test suite**

Run: `cd scanner && npm run test:lineage`
Expected: prior count (post-Task-1) + 0 new `test()` calls (the fixture itself isn't a new `test()`, it's picked up by `F1/11`'s existing loop) — confirm this is actually true by reading `F1/11`'s loop structure, matching F2's own established verification discipline.

Run: `node bench/data-lineage/runner.mjs --check; echo "exit: $?"`
Expected: exit 0, new total fixture count, 0 regression-tier failures.

Run: `cd scanner && npm test`
Expected: full gate green, exit 0.

- [ ] **Step 6: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/data-lineage/fixtures/js-ai-model-output-to-ai-model-provider-phi/ bench/data-lineage/README.md scanner/test/bench-data-lineage-runner.test.js
git commit -m "feat(lineage): author the AC-07 corpus fixture proving the AI-sink catalog bridge end to end (Sub-project H)"
```

---

## Self-review notes

- **Spec coverage:** every recommendation in the scoping report's §1-§7 is implemented: the 4 catalog entries (§3), the CWE-201/CWE_MAP row (§4/§5), the completeness-guard updates the new reachability requires (§5's own "must be updated in the same change" note), the scope boundary respected (§6 — no provider/model attribution attempted), and the fixture (§7's sketch, now actually authored and verified). The open questions in §8 (other providers, the legacy anthropic.completions.create shape, privacy-catalog siblings) are explicitly deferred, matching the report's own recommendation, not silently dropped.
- **Placeholder scan:** every step has literal, complete code; no TBD.
- **Type consistency:** `reclassifySink`'s return shape (`{kind, category, coverageStatus, externality, reason}`) is asserted identically in Task 1 Step 4's new test and matches every other entry in `sink-registry.test.js`.
