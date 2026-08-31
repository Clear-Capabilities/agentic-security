# Data Flow Explorer — M1 Sub-project D, Increment 4: `transform-catalog.js`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `scanner/src/lineage/transform-catalog.js`, a curated callee-pattern catalog that recognizes calls performing a data transformation — masking, redaction, tokenization, hashing, encryption, decryption, encoding, decoding, aggregation, truncation, normalization — and classifies them per `DataFlowGraph v1`'s §10.6 transformation contract. This is the ONE genuinely new detection capability in Sub-project D (D2/D3 reclassified an existing catalog; this increment has no existing catalog to lean on — a targeted grep across `src/dataflow/`, `src/sast/`, `src/posture/` confirmed no callee-pattern recognizer for "this call performs masking/hashing/tokenization/encryption" exists anywhere in this codebase today).

**Architecture:** `transform-catalog.js` is a new, self-contained pure-data-plus-lookup module, structurally parallel to `scanner/src/dataflow/catalog.js` (same `match: {type, callee/object/prop}` descriptor shape, for a future consumer's familiarity) but NOT a reclassification layer over an existing catalog — it defines its OWN catalog of known transformation-performing callees from scratch, curated by kind. It exports one lookup function, `recognizeTransformation(calleeDescriptor)`, returning `null` for no match or a decision object shaped per §10.6 (kind, reversibility, algorithm-when-knowable, evidence, confidence) — explicitly NOT the "control credit granted or denied" field, which PRD §10.6 lists but Decision 2 (the parent Milestone 1 scoping doc's binding scope boundary) reserves for Milestone 2's protection-verdict analyzers.

**Tech Stack:** Node.js ESM, `node:test` + `node:assert`. No new dependencies.

**Spec:**
- `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §10.6 (transformation contract, quoted in full below) and AC-02 (masked vs. raw log worked example, quoted in full below) — the repo root, an untracked working document per this repo's convention; read it directly.
- `docs/superpowers/plans/2026-08-30-data-flow-explorer-m1-subproject-d-scoping.md` row D4 and its "Decision 2" quote (the binding scope boundary: transformation-*kind* recognition is in scope; awarding protection-verdict *credit* from it is explicitly NOT, until Milestone 2).
- `scanner/src/lineage/schema.js` — `TRANSFORM_KINDS` (13 values: `mask`, `redact`, `tokenize`, `hash`, `encrypt`, `decrypt`, `encode`, `decode`, `aggregate`, `truncate`, `normalize`, `custom`, `unknown`) and `REVERSIBILITY_VALUES` (`reversible`, `irreversible`, `unknown`) — the target vocabulary this module classifies into.
- `scanner/src/dataflow/catalog.js` — read as the structural precedent for the `match` descriptor shape (`{type: 'call', callee: 'name'}` / `{type: 'member', object, prop}`) and for this repo's convention of one entry per line with `id`/`language` fields. Do NOT import anything from this file — it is precedent for shape only, not a data source (there is no existing transformation-callee data in it to port).

### §10.6 Transformation contract (PRD, quoted in full)

> Each transformation must identify:
> - input and output access paths;
> - function/callee and code location;
> - kind: mask, redact, tokenize, hash, encrypt, decrypt, encode, decode, aggregate, truncate, normalize, custom, or unknown;
> - reversibility: reversible, irreversible, unknown;
> - algorithm and strength when statically knowable;
> - key-management evidence when applicable;
> - whether the transform applies on all feasible paths or only some paths;
> - evidence and confidence;
> - control credit granted or denied and the reason.
>
> Masking, hashing, tokenization, and encryption must never be treated as synonyms.

Of this list, `transform-catalog.js` produces: **kind**, **reversibility**, **algorithm** (when the callee name itself names one, e.g. `bcrypt`/`argon2`/`aes-256-gcm` — otherwise `null`, never guessed), **evidence and confidence** (this module's own catalog match is the evidence; confidence is `high` for an exact well-known callee, `medium` for a generic same-family name with no specific library signal). It does NOT produce: input/output access paths, function code location, "applies on all/some paths", or **control credit** — those need a call site (this module only classifies a *callee pattern*, it never sees a call site) and/or Milestone 2's protection-verdict analyzers (Decision 2's own explicit boundary). A future Sub-project E graph builder is what will call this module once per actual call site and combine its answer with call-site location/path data to build a real `Transformation` entity.

### AC-02 (PRD, quoted in full)

> **Given** one path applies a proven `maskCard()` transform to all branches and another logs the raw card number,
> **then** the masked flow is visibly distinct and may receive handling-control credit, while the raw log creates an issue. Both flows remain visible.

This module's own job, scoped to AC-02: prove that a call recognizable as a masking transform (e.g. `maskCard(cardNumber)`) is genuinely classified `kind: 'mask'` and is DISTINCT from a call with no transformation classification at all (e.g. a raw `logger.info(cardNumber)` call, which `recognizeTransformation` must return `null` for — it is not this module's job to decide that logging is bad, only that it recognizes no transformation there). "May receive handling-control credit" is explicitly Milestone 2's job, not this module's.

## Global Constraints

- `transform-catalog.js` must import NOTHING from `scanner/src/dataflow/` — this is genuinely new data, not a reclassification of an existing catalog, so there is no `CATALOG`/`privacy-catalog.js` import to make (unlike D2/D3). It may import `TRANSFORM_KINDS`/`REVERSIBILITY_VALUES` from `./schema.js`.
- Must NEVER import `dataflow/engine.js`, `dataflow/summaries.js`, or any matcher internals — this PRD's §18.1 isolation principle, same basis every prior Sub-project A-D module uses.
- The returned decision object's `kind` must always be a value from `TRANSFORM_KINDS`; `reversibility` must always be a value from `REVERSIBILITY_VALUES`. Never invent a value outside either enum.
- Must NOT emit a "control credit" field of any kind, granted or denied — Decision 2's binding scope boundary. If you find yourself computing whether a transform is "good enough," stop — that's Milestone 2's job, not this module's.
- Masking, hashing, tokenization, and encryption must never be treated as synonyms (§10.6's own explicit sentence) — each must be its own distinct, independently-testable `kind` in the catalog, with at least one real, well-known callee pattern proving each is reachable (not just present in the enum).
- The catalog must be **curated, not exhaustive** — this is new detection capability being built from scratch; favor precision (a handful of well-known, unambiguous library/naming patterns per kind) over recall (guessing at every possible synonym). A `custom`/`unknown` fallback exists in the enum for exactly the cases this catalog doesn't recognize; do not force an ambiguous pattern into a specific kind to inflate coverage.
- Every entry in the catalog must be provably matchable by a real, executable test — no entry that exists only in prose.
- Follow this repo's root `CLAUDE.md` verification discipline: prove AC-02's own worked example (`maskCard()` vs. a raw log call) as a real, executable test, not just documented intent.
- Every existing test suite this task touches or reads from must keep passing — run `npm run test:lineage` before and after any change.

## Coordination

Sequential, not parallel — no other Sub-project D increment is in flight. This can be dispatched from current `main` directly (D2 and D3 are both merged).

---

### Task 1: Design and implement `transform-catalog.js`, prove AC-02's worked example

**Files:**
- Create: `scanner/src/lineage/transform-catalog.js`
- Create: `scanner/test/lineage/transform-catalog.test.js`
- Modify: `scanner/package.json` (wire the new test file into `test:lineage`)
- Modify: `scanner/src/lineage/CLAUDE.md` (new module-table row under a new "Sub-project D, increment 4" heading, plus update the "What is NOT here yet" section to remove transformation-kind recognition from the still-pending list)
- Read only: `AGENTIC_SECURITY_DATA_FLOW_EXPLORER_PRD.md` §10.6 and AC-02 (repo root — quoted in full above, but read the surrounding context too, especially §9 for how "kind" and "AI processing context" are NOT the same axis, in case a transformation touches AI-related data — this module does not need to handle that specially, but should not accidentally conflict with it), `scanner/src/lineage/schema.js` (`TRANSFORM_KINDS`/`REVERSIBILITY_VALUES`), `scanner/src/dataflow/catalog.js` (structural precedent for the `match` shape only — see Spec above).

**Interfaces:**
- Consumes: nothing from other modules in this codebase (a self-contained new catalog).
- Produces: `recognizeTransformation(calleeDescriptor)`, exported from `scanner/src/lineage/transform-catalog.js`. `calleeDescriptor` is `{type: 'call', callee: string}` for a bare call (`maskCard(x)` → `{type: 'call', callee: 'maskCard'}`) or `{type: 'member-call', object: string, method: string}` for a method call (`crypto.createHash('sha256')` → `{type: 'member-call', object: 'crypto', method: 'createHash'}`). Returns `null` for no match, or `{kind, reversibility, algorithm, confidence, evidence}` where `kind` ∈ `TRANSFORM_KINDS`, `reversibility` ∈ `REVERSIBILITY_VALUES`, `algorithm` is a string or `null`, `confidence` is `'high'` or `'medium'`, `evidence` is a short human-readable string naming the matched pattern (e.g. `"callee name 'maskCard' matches the app-level masking naming convention"`).

- [ ] **Step 1: Read the spec sections above, then `schema.js` and `catalog.js`'s match-shape precedent**

Confirm `TRANSFORM_KINDS` and `REVERSIBILITY_VALUES`'s exact live values by reading `schema.js` directly, not from this plan's own paraphrase (this plan was written by reading it, but re-derive it yourself — the array order matters for nothing here, but the exact string values do).

- [ ] **Step 2: Design and build the curated catalog**

Build a catalog covering every non-`custom`/`unknown` `TRANSFORM_KINDS` value with at least one real, well-known, unambiguous pattern. A reasonable starting point per kind (research and adjust for accuracy — do not copy this list uncritically, verify each callee name is a real, commonly-used API before including it):

- **mask**: an app-level naming convention (`mask*` callee names — e.g. `maskCard`, `maskSSN`, `maskEmail`) is the only reliable signal, since masking has no single canonical library the way hashing does. Confidence `medium` for a naming-convention match (there is no `mask` builtin to be `high`-confident about). `reversibility: 'irreversible'` (masking discards information).
- **redact**: same naming-convention approach (`redact*`), `reversibility: 'irreversible'`, confidence `medium`.
- **tokenize**: naming-convention (`tokenize*`) plus, if you find one, a real tokenization-vault SDK method name (many are proprietary/vendor-specific — do not invent one; a naming-convention-only catalog for this kind is acceptable and should be disclosed as such). `reversibility: 'reversible'` (a token is designed to be detokenized by the vault, unlike masking).
- **hash**: real, well-known APIs — `crypto.createHash` (Node builtin, `algorithm: null` unless the argument itself is inspectable, which this module does NOT do — it classifies the CALLEE pattern only, per this module's own stated non-goal of reading call-site arguments), `bcrypt.hash`/`bcrypt.hashSync` (`algorithm: 'bcrypt'`), `argon2.hash` (`algorithm: 'argon2'`). `reversibility: 'irreversible'`, confidence `high` (these are unambiguous, single-purpose library APIs).
- **encrypt**: `crypto.createCipheriv` (Node builtin), a well-known library method if you can verify one (e.g. `crypto.publicEncrypt`). `reversibility: 'reversible'` (encryption is designed to be decrypted), confidence `high`.
- **decrypt**: `crypto.createDecipheriv`, `crypto.privateDecrypt` — the direct counterparts of the encrypt entries above, same confidence/reversibility reasoning (`'reversible'`).
- **encode**: `Buffer.from(...).toString('base64')`-style calls are hard to catalog by callee name alone (the pattern is in the argument, not the callee) — favor callee-name signals that ARE reliable: `encodeURIComponent`/`encodeURI` (Node/browser builtins — note `encodeURIComponent` already exists in `dataflow/catalog.js` as a SANITIZER, a different classification for a different purpose; this module's classification of the same callee as a transformation `kind: 'encode'` is not a conflict — they are two different axes serving two different consumers, and this module must never import or check against `dataflow/catalog.js`'s classification). `reversibility: 'reversible'`, confidence `high`.
- **decode**: `decodeURIComponent`/`decodeURI`, the direct counterparts. `reversibility: 'reversible'`, confidence `high`.
- **aggregate**: this is genuinely hard to recognize by callee name alone (aggregation is usually a data-shape operation like `.reduce()`, `.groupBy()`, not a security-relevant callee) — a naming-convention approach (`aggregate*`/`summarize*`) is the honest answer here; disclose in the module header if you find this kind's real-world catalog is thin. `reversibility: 'irreversible'` (aggregation discards per-record detail).
- **truncate**: a well-known utility (`lodash`'s `_.truncate`, or an app-level `truncate*` naming convention). `reversibility: 'irreversible'`, confidence `medium` (lodash's truncate is general-purpose string truncation, not always applied for privacy reasons — say so in the evidence string).
- **normalize**: `String.prototype.normalize` (a real JS builtin, Unicode normalization — NOT privacy-related, but a real, well-known transformation the enum explicitly wants recognized) — `reversibility: 'unknown'` (Unicode normalization can be lossy or lossless depending on form; do not overclaim). Confidence `high` for the builtin itself.

For each entry, `evidence` must name the actual matched pattern (callee/object.method name), and never claim more certainty than the pattern actually supports — a naming-convention match is genuinely `medium`, not `high`, even if it "feels" obviously right for one hand-picked example. If your own research turns up that a given kind genuinely has no reliable, real-world pattern (not even a naming convention you can defend), it is acceptable to leave that kind with ZERO catalog entries — DO NOT force a low-confidence guess into the catalog just to claim coverage; instead, disclose the gap explicitly in the module header (mirroring this whole PRD's established convention of naming what is NOT covered, not just what is) and in a dedicated test asserting `recognizeTransformation` correctly returns `null` for that kind's obvious candidates today.

- [ ] **Step 3: Implement `recognizeTransformation(calleeDescriptor)`**

A straightforward lookup over the catalog built in Step 2 — no need for `dataflow/catalog.js`'s full match-type generality (this module only needs `call`/`member-call`, per the Interfaces section above); keep the matching logic simple and directly readable. Returns `null` when nothing in the catalog matches. Must not throw on a malformed/unexpected `calleeDescriptor` shape — return `null` instead (a future caller may pass an incomplete descriptor for a callee it could not fully resolve; treat that as "no match," not a crash).

- [ ] **Step 4: Write `transform-catalog.test.js`**

At minimum:
- **AC-02's own worked example**: `recognizeTransformation({type: 'call', callee: 'maskCard'})` returns `kind: 'mask'`; a raw-log-style callee descriptor (e.g. `{type: 'member-call', object: 'logger', method: 'info'}`) returns `null` — proving the masked-vs-raw distinction this module is responsible for.
- **At least one real, passing match per catalog kind you actually populated** — a totality-style test that every kind you claim to cover has at least one real callee descriptor that matches it, proving the catalog isn't just prose.
- **`masking, hashing, tokenization, and encryption must never be treated as synonyms`** (§10.6's own explicit sentence): a dedicated test asserting a real hash-family callee (e.g. `bcrypt.hash`), a real encrypt-family callee (e.g. `crypto.createCipheriv`), and a real mask-family callee (e.g. `maskCard`) each return DIFFERENT `kind` values — proving the catalog doesn't conflate them.
- **`kind`/`reversibility` are always valid enum values**: a sweep over every catalog entry (however you access them internally — export them, or iterate via a battery of known-good descriptors) asserting every non-null result's `kind` ∈ `TRANSFORM_KINDS` and `reversibility` ∈ `REVERSIBILITY_VALUES`.
- **No "control credit" field ever appears**: a sweep asserting no returned decision object has a key resembling `credit`/`controlCredit`/`creditGranted` (Decision 2's boundary, proven, not just claimed).
- **A genuine non-match returns `null`, not a guess**: at least one plausible-but-uncataloged callee descriptor (e.g. a generic `transform()` or `process()` callee) returns `null`.
- **Malformed input does not throw**: `recognizeTransformation(undefined)`, `recognizeTransformation({})`, and `recognizeTransformation({type: 'unknown-type'})` all return `null`, never throw.

- [ ] **Step 5: `scanner/src/lineage/CLAUDE.md` — new module-table row**

Add a `transform-catalog.js` row under a new "**Milestone 1, Sub-project D, increment 4 (`transform-catalog.js` — transformation-kind recognition; closes the Sub-project D `TRANSFORM_KINDS` requirement) — COMPLETE:**" heading (matching the exact heading style of the D2/D3 headings immediately above it in the file), describing: the module's role, why it is genuinely new capability (no existing catalog to reclassify from, unlike D2/D3), the catalog's actual measured shape (how many entries per kind you actually shipped — count them, don't estimate), which kinds (if any) you deliberately left with zero entries and why, the Decision 2 scope boundary (no control-credit field), and the AC-02 proof. Also update the "What is NOT here yet" section's transformation-kind-recognition sentence to reflect it is now complete.

- [ ] **Step 6: Run the scoped suite and doc-drift check**

```bash
cd scanner
npm run test:lineage
node ../scripts/check-doc-drift.mjs
```

- [ ] **Step 7: Commit**

```bash
git add scanner/src/lineage/transform-catalog.js scanner/test/lineage/transform-catalog.test.js scanner/package.json scanner/src/lineage/CLAUDE.md
git commit -m "feat(lineage): implement transform-catalog.js, transformation-kind recognition (Sub-project D, increment D4)"
```
