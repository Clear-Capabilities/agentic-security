# Data Flow Explorer — M1 Sub-project D, Increment 5: exit-gate closure

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close out Sub-project D by proving, against REAL PARSED CODE (not just catalog data in isolation), that D2/D3/D4's registries work end-to-end — per the corrected exit criterion in `DESIGN_REGISTRIES.md` §9.2: *"Every **reachable** category has at least one real-code proof, and every **unreachable** category has a recorded, tested reason — never silent absence."* This is the LAST increment of Sub-project D (D1-D4 are all merged and complete); after this lands, Sub-project D as a whole is done.

**Why this increment exists, and what it does NOT do:** D2's `source-registry.test.js` and D3's `sink-registry.test.js` already prove, exhaustively, that every catalog entry reclassifies correctly — but every one of those tests operates on `CATALOG`'s own static entries directly, never on a call site extracted from actually-parsed source code. Nobody has yet proven that a REAL, textually-written piece of code, run through this repo's own Layer-1 IR parser, produces a call-site shape that the catalog's own `match` field can genuinely recognize. That is the specific, narrow gap this increment closes — it is verification and cleanup, not new detection capability (`transform-catalog.js`, D4, was the one new-capability increment in this sub-project). This increment does NOT wire the registries into `runScan`, does NOT build a graph, does NOT touch `path-store.js`/`path-query.js`/`driver.js`, and does NOT resolve `DESIGN_PATH_PROVENANCE.md` §16.7 Finding 2's "Half 1" (the truncation-terminal enumerator) — that is explicitly Sub-project E's job (§16.7's "Half 2", the taxonomy decision, is already settled in `DESIGN_REGISTRIES.md`'s own §9's closing section, "Carried forward from Sub-project C: §16.7 Finding 2" — read it, but there is nothing left for D5 to implement there).

**Architecture:** One new test file, `scanner/test/lineage/registry-real-code.test.js`. For each REACHABLE source/sink/privacy-sink category, and for AC-02's masked/raw distinction, the test: (1) writes a small, realistic JS/TS code snippet; (2) parses it with `scanner/src/ir/parser-js.js`'s `parseJsFile` (the same Layer-1 IR every prior Sub-project A-D module reuses, per this PRD's own isolation principle — NEVER `dataflow/engine.js`, NEVER a matcher); (3) extracts the resulting call site's flat callee name from the parsed function's own `calls[]` array (`fn.calls[].callee`, already a flat string like `'req.body'`-shaped names ARE NOT what this returns — re-read the actual shape by running real code, don't assume from this plan's own paraphrase); (4) for source/sink categories: finds the chosen representative catalog entry, independently confirms (via a small, self-contained structural comparison this task writes itself — NOT `dataflow/engine.js`'s real matcher, which this package may never import) that the entry's own `match` field is consistent with what the parser actually extracted from the snippet, then feeds the CATALOG ENTRY (not the parsed descriptor) into `reclassifySource`/`reclassifySink`/`reclassifyPrivacySink` and asserts the resulting `category` is the expected reachable one; (5) for the transform-catalog/AC-02 half: builds a `recognizeTransformation`-shaped descriptor directly from the parsed callee name and calls it directly (no catalog-entry indirection needed, since `transform-catalog.js` already consumes a descriptor, not an entry).

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:**
- `scanner/src/lineage/DESIGN_REGISTRIES.md` §9.2 ("Sequencing and D5's exit criterion" — quoted above; this is the binding definition of what "done" means for this increment) and §7.2 (the reachable/unreachable category measurements this increment's category lists must match).
- `scanner/src/lineage/source-registry.js`, `scanner/src/lineage/sink-registry.js`, `scanner/src/lineage/transform-catalog.js` — the three modules being proven, already merged and complete. Read each in full, including their own test files, to know each module's exact exported functions and each catalog entry's exact shape (especially `match`) before writing snippets meant to exercise specific entries.
- `scanner/src/ir/parser-js.js` — read `parseJsFile`'s full output shape (the header comment at the top of the file documents the IR shape in detail: `calls: [{site, callee, args, line}]` per function). Confirm the exact shape of `callee` (a flat string, built from `calleeExpr.kind === 'ident' ? calleeExpr.name : ...` for a member expression — read the actual code around line 606-613, don't take this plan's paraphrase as gospel) by running it against a real snippet yourself before writing any test that depends on it.
- `scanner/src/dataflow/catalog.js` and `scanner/src/dataflow/privacy-catalog.js` — the entries being matched, for their exact `match: {type, callee}` / `{type, object, prop}` shapes.

## Global Constraints

- The new test file must NEVER import `scanner/src/dataflow/engine.js`, `scanner/src/dataflow/summaries.js`, or any matcher internals — the same isolation principle every prior module in this PRD respects. It MAY import `scanner/src/ir/parser-js.js` (Layer-1 IR, already an established reuse boundary across Sub-projects A-D) and the three registry modules plus their source catalogs.
- Do NOT modify `source-registry.js`, `sink-registry.js`, `transform-catalog.js`, `catalog.js`, `privacy-catalog.js`, or `schema.js` — this increment is proof, not implementation. If a real-code proof reveals an actual bug in one of those modules, STOP and report it rather than silently patching around it in the test (the finding is real project information, not a nuisance to route around).
- Every REACHABLE category must get at least one real-code proof: **14 source categories** (`http-body`, `http-query`, `http-route`, `http-header`, `http-cookie`, `http-upload`, `cli-argument`, `env-value`, `storage-read`, `user-input`, `external-api-response`, `ai-model-output`, `ai-tool-result`, `ai-retrieved-document`) and **10 sink categories** (`log`, `http-response`, `client-storage`, `database`, `file`, `object-storage`, `queue`, `analytics`, `email`, `external-api`) — **re-derive and confirm these two lists yourself** by running `source-registry.test.js`'s and `sink-registry.test.js`'s own unreachable-category tests before writing anything; if either list has drifted since this plan was written (a later change added real detection for a previously-unreachable category), use the CURRENT live list, not this plan's copy, and note the drift in your report.
- The existing unreachable-category tests (`D1/6a`/`D1/6b`-descended, in `source-registry.test.js`/`sink-registry.test.js`) must be left completely unchanged and must still pass — this increment inherits that half of the exit criterion, it does not re-prove it.
- AC-02's masked-vs-raw distinction must be proven via REAL PARSED CODE specifically (not the descriptor-literal form D4's own tests already used) — parse `maskCard(cardNumber)`-shaped source, confirm `kind: 'mask'`; parse a raw-log-shaped call, confirm `null`.
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` before and after any change.
- Follow this repo's root `CLAUDE.md` verification discipline: every claim in this increment's report about which categories are reachable, and which snippet proves which category, must be demonstrated by a real test run in this task, not asserted from this plan's own prose.

## Coordination

Sequential; no other Sub-project D increment is in flight (D1-D4 are all merged). This is the LAST increment of Sub-project D — after it lands and merges, Sub-project D as a whole is complete.

---

### Task 1: Prove D2/D3/D4's registries against real parsed code; close Sub-project D's exit gate

**Files:**
- Create: `scanner/test/lineage/registry-real-code.test.js`
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`)
- Modify: `scanner/src/lineage/CLAUDE.md` (a short new entry recording D5's completion, closing out the Sub-project D section; update the "What is NOT here yet" section's Sub-project D language to say the whole sub-project is now complete)
- Read only: `scanner/src/lineage/DESIGN_REGISTRIES.md` §9.2/§7.2 and the "Carried forward from Sub-project C: §16.7 Finding 2" closing section, `scanner/src/lineage/source-registry.js` + its test file, `scanner/src/lineage/sink-registry.js` + its test file, `scanner/src/lineage/transform-catalog.js` + its test file, `scanner/src/ir/parser-js.js` (in full, for the IR output shape), `scanner/src/dataflow/catalog.js`, `scanner/src/dataflow/privacy-catalog.js`.

**Interfaces:**
- Consumes: `parseJsFile` from `../../src/ir/parser-js.js`; `reclassifySource` from `../../src/lineage/source-registry.js`; `reclassifySink`/`reclassifyPrivacySink` from `../../src/lineage/sink-registry.js`; `recognizeTransformation` from `../../src/lineage/transform-catalog.js`; `CATALOG` from `../../src/dataflow/catalog.js`; the privacy catalog's own export from `../../src/dataflow/privacy-catalog.js`.
- Produces: nothing consumed by a later task (this is the final increment).

- [ ] **Step 1: Read the spec sections, then run `parseJsFile` against a throwaway snippet to confirm the real IR output shape**

Before writing any real test, write a small scratch script (not committed — delete it once you've confirmed the shape, or just run it via `node -e` / a temporary file you clean up) that calls `parseJsFile` on a snippet like:
```js
function handler(req) {
  const body = req.body;
  db.query(sql);
}
```
and prints the resulting `fn.calls` array. Confirm exactly what `callee` looks like for a bare call (`db.query(sql)` — is it `'db.query'`, or something else?) and how a bare member READ (`req.body`, not a call) is or isn't represented (it may not appear in `calls` at all, since it's not a call — check `fn.body`/whatever the IR's node-walk exposes for non-call member reads, since several of your 14 source categories are member-read sources like `req.body`, not calls). This step exists because this plan's own Architecture section deliberately does NOT claim to know the exact shape — confirm it empirically before Step 2, and note in your report exactly what you found (this is likely to differ for a member-read source vs. a call-based sink, and your extraction approach for each will differ accordingly).

- [ ] **Step 2: Re-derive the current reachable category lists**

Run `source-registry.test.js`'s and `sink-registry.test.js`'s own unreachable-category tests (or read their current assertions directly) to confirm the 14-source/10-sink reachable lists in this plan's Global Constraints are still current. Use the current live lists for every subsequent step; note any drift from this plan's copy in your report.

- [ ] **Step 3: For each of the 14 reachable source categories, write one real-code proof**

For each category, pick ONE representative catalog entry from `CATALOG` (`kind: 'source'`) whose `reclassifySource(entry).category` equals that category — search the live catalog yourself, don't guess an entry id. Write a small, realistic JS/TS snippet containing that entry's `match` pattern (e.g. for a `match: {type: 'member', object: 'req', prop: 'body'}` entry, write `const x = req.body;`). Parse it with `parseJsFile`. Using whatever the IR actually exposes for member reads / calls (per Step 1's findings), independently confirm the parsed structure is consistent with the entry's own `match` field (a small, self-written, purpose-built comparison — not a general matcher, just enough structural comparison to prove "yes, this entry's match pattern really does correspond to what real code produces here"). Then call `reclassifySource(entry)` directly and assert `category` equals the expected reachable category. One test per category (or one parameterized test iterating all 14 — your choice, as long as each category's proof is independently identifiable in a failure message).

- [ ] **Step 4: For each of the 10 reachable sink categories, write one real-code proof**

Same approach as Step 3, but against `CATALOG`'s `kind: 'sink'` entries (via `reclassifySink`) and, where a sink category is ONLY reachable via `privacy-catalog.js` (check which of the 10 are catalog-reachable vs. privacy-only reachable — `analytics` is a strong candidate for privacy-only, confirm from `sink-registry.test.js`'s own tests), via `reclassifyPrivacySink` and `PRIVACY_SINK_CATALOG` instead. Same match-consistency check, same per-category assertion.

- [ ] **Step 5: Prove AC-02's masked-vs-raw distinction against real parsed code**

Parse a snippet like `const masked = maskCard(cardNumber);` and a snippet like `logger.info(cardNumber);` (or whatever raw-log shape `transform-catalog.js`'s own tests already establish returns `null` — reuse that exact shape for consistency). Extract each call's callee name from the real parsed IR (per Step 1's findings), build the `{type: 'call', callee}` (or `{type: 'member-call', object, method}`) descriptor `recognizeTransformation` expects, and assert: the masked snippet → `kind: 'mask'`; the raw-log snippet → `null`. This proves the SAME distinction D4's own `D4/1a`-`D4/1d` already proved with hand-built descriptors, but this time starting from real parsed source — the missing link this whole increment exists to close.

- [ ] **Step 6: A closing summary assertion**

One final test that counts how many DISTINCT reachable categories (source + sink, summed) got a real-code proof in this file, and asserts the count equals 24 (14 + 10) — so a future refactor that silently drops one of Steps 3/4's per-category tests fails loudly here too, not just via a missing individual test.

- [ ] **Step 7: `scanner/src/lineage/CLAUDE.md` update**

Add a short paragraph (not a full new module-table row — this increment ships no new production module, only a test file) closing out the Sub-project D section: name that D5 is complete, that Sub-project D (D1-D5) is now fully done, state the exact real-code-proof count achieved (24, or the current figure if Step 2 found drift), and note that the unreachable-category tests continue to hold unchanged. Update the "What is NOT here yet" section's Sub-project D language accordingly — Sub-project D moves from "D1-D4 complete, D5 pending" framing to "Sub-project D (D1-D5) is now fully complete."

- [ ] **Step 8: Run the scoped suite and doc-drift check**

```bash
cd scanner
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 9: Commit**

```bash
git add scanner/test/lineage/registry-real-code.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git commit -m "test(lineage): close Sub-project D exit gate — prove registries against real parsed code (D5)"
```
