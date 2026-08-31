# Milestone 2, Sub-project E, increment 1: ORM-write sink recognition (isolated catalog)

Per `docs/superpowers/plans/2026-08-31-data-flow-explorer-m2-subproject-e-scoping.md`'s
revised increment breakdown and its Finding 3 (the precision-mechanism
gap). This document makes the deliberate design decision Finding 3
required before any code gets written, then specifies increment 1
precisely.

## The design decision (read before implementing)

**Do NOT add ORM-write entries to `dataflow/catalog.js`'s general
`CATALOG`.** Confirmed by reading `dataflow/privacy-catalog.js`'s own
header comment (lines 12-27): `CATALOG` is a shared, always-active
singleton consumed by `runTaintEngine`/`matchSinkOrSanitizer` for EVERY
scan, with no per-family filtering. A new `database`-adjacent entry added
there would immediately become a live SAST finding for every existing
tainted source reaching it — a real, unintended expansion of the general
SAST pipeline's own output as a side effect of a Data Flow Explorer
feature, not something Sub-project E is chartered to decide. This is
EXACTLY the reasoning `privacy-catalog.js` itself documents for why it is
a separate file, never merged into `CATALOG`, never wired into
`runTaintEngine`.

**Instead: a new, isolated file, `scanner/src/dataflow/orm-write-catalog.js`,
mirroring `privacy-catalog.js`'s own structure exactly** — same
`{kind, id, language, framework, category, match, argIndex, vuln}` entry
shape, its own standalone matcher function, imported ONLY by
`src/lineage/`'s own registry (never by `dataflow/engine.js`, never by
`runTaintEngine`). **Correction to an earlier draft of this plan, verified
before dispatch:** `privacy-catalog.js` itself is NOT in
`test/no-dead-modules.test.js`'s `ALLOWLIST` — grepped directly, no match
— because it already has real consumers (`sink-registry.js`'s
`reclassifyPrivacySink` imports `PRIVACY_SINK_CATALOG`, `coverage.js`
imports that function). Since this increment wires `orm-write-catalog.js`
into `sink-registry.js`/`coverage.js` in the SAME commit it is added, it
will likewise have real consumers from the start and needs NO allowlist
entry — do not add one; if `npm run test:lifecycle` flags it anyway,
that is a signal the wiring is incomplete, not that an allowlist entry is
owed.

**The precision gate is TWO signals, not one, and only one of them lives
in the catalog entry itself.** Confirmed by reading `matchPrivacySink`
(`privacy-catalog.js:241`): its signature is `(calleeExpr, file,
receiverType)` — it never receives the call's ARGUMENTS, only the callee
expression. This means an "argument must be an object literal" check
cannot be expressed inside the catalog's own `match` object or its
matcher function; it must be applied by the CALLER, which has
`site.args` — i.e., lineage-side, in `coverage.js`, exactly the same
architectural pattern `resolveDestination`/`resolveSiteDecision` already
established for post-match refinement. The two signals:

1. **Callee shape** (in the new catalog + its matcher, mirroring
   `matchPrivacySink`'s own callee-name extraction): method name is one of
   `create`/`save`/`update`/`upsert` (per `cross-lang-orm.js`'s own
   `findOrmWrites` regex, lines ~28-41 of that file — reuse ITS vocabulary
   as reference, never its regex mechanism), receiver is a BARE, CAPITALIZED
   identifier (`^[A-Z]\w*$` on the receiver name extracted from a `member`-
   kind `calleeExpr` whose `object` is `kind: 'ident'`) — the SAME shape
   `mass-assignment.js` (line 27) and `cross-lang-orm.js` (`findOrmWrites`)
   already use in production as real SAST detectors; this is not a new or
   untested heuristic, it is the established one, reused for a lower-stakes
   (candidate-tier, disclosed) purpose than either of those two modules'
   own full-confidence findings.
2. **Argument shape** (lineage-side, new code in `coverage.js`): the
   matched call's FIRST argument (`site.args[0]`) must be an object-literal
   expression (`kind: 'object'`, matching the same expression-tree shape
   `resolve-destination.js`'s own `isLiteral`/`renderExpr` helpers already
   consume — read `parser-js.js`'s object-literal IR shape directly before
   writing this check, don't assume it matches `resolve-destination.js`'s
   `isLiteral` helper, which tests for `kind: 'literal'`, a DIFFERENT node
   kind than an object expression). A call whose first argument is NOT an
   object literal (a bare variable, a spread, a positional string) does
   NOT become a sink site at all — this is a hard exclusion at the
   `resolveSiteDecision`-equivalent hook point, not a downgrade.

**`coverageStatus` is `'candidate'`, unconditionally, never `'modeled'`,
never `'partial'`.** Even with both signals present, this is real,
disclosed uncertainty — an arbitrary capitalized-identifier receiver could
still be a non-ORM builder pattern that happens to take an object-literal
argument. `sink-registry.js`'s existing `reclassifySink`/
`reclassifyPrivacySink` precedent (D3) already has real `candidate`-tier
entries computed this way; this is not a new tier-assignment pattern.

## What this increment does NOT do

- Extract table/column/operation facts onto a `node.storeDetail`-style
  schema field — that's E2, needs its own new schema surface, not decided
  here.
- Wire the new catalog into `dataflow/engine.js`/`runTaintEngine` at all,
  ever — a deliberate, permanent isolation (unlike `privacy-catalog.js`,
  which is ALSO isolated from `runTaintEngine` today but at least shares
  its entry shape with something that COULD wire in later; this catalog's
  isolation is closer to structural — the object-literal-argument gate
  cannot be expressed in `matchSinkOrSanitizer`'s existing signature at
  all without changing that shared function, which this increment
  explicitly refuses to touch).
- Cover Python/Java/Go/Ruby/PHP ORM shapes (Django `.objects.create()`,
  GORM, ActiveRecord, Eloquent) — JS/TS only, continuing this whole
  package's established §22.1 scope decision. Name them as a real,
  disclosed gap in the new file's own header comment, the same way D2's
  `source-registry.js` disclosed its own language gaps.
- Attempt Prisma's distinctive `data: { ... }` wrapper shape (e.g.
  `prisma.user.create({ data: { email: x } })`) — the object-literal-arg
  check as specified above would see the OUTER `{ data: {...} }` literal
  and pass (it IS an object literal), which is fine for the callee-match
  gate, but note this explicitly rather than silently treating Prisma's
  wrapper as identical in shape to Mongoose's flat form — the implementer
  must confirm both shapes reach `resolveSiteDecision`'s hook correctly
  and disclose if they don't, not assume symmetry.

## Implementation

**New file: `scanner/src/dataflow/orm-write-catalog.js`**

Mirror `privacy-catalog.js`'s file header discipline (explain the
isolation decision in the file's own comment, don't just implement it
silently) and its `{kind, id, language, framework, category, match,
argIndex, vuln}` entry shape. Export:

- `ORM_WRITE_CATALOG` — an array of entries. Suggested starting set (verify
  against `cross-lang-orm.js`'s own regex vocabulary before finalizing
  method names — this list is a starting point, not a mandate):
  `create`, `save`, `update`, `upsert`. `category: 'database'` on every
  entry (reuse the existing `SINK_CATEGORIES` value — this is genuinely a
  database write, just a lower-confidence detection of one; minting a new
  category is real, undecided scope the E-scoping doc's own increment
  breakdown left open, not decided here — use the existing category and
  flag the open question in this file's own header if the implementer
  believes a new category is warranted).
- A matcher function, e.g. `matchOrmWrite(calleeExpr, file)` — no
  `receiverType` third parameter needed (unlike `matchPrivacySink`, this
  catalog's receiver constraint is a SHAPE regex on the receiver's own
  IDENTIFIER NAME, not a `receiverTypeIn` exact-list lookup; unrelated to
  the IR's inferred `receiverType`). Write a local, small
  `_ormCalleeNames(calleeExpr)` helper (mirror `_privacyCalleeNames`'s
  ~10-line shape — do not import the private one from `privacy-catalog.js`,
  this package's established precedent, per `handling-analyzer.js`'s own
  disclosed `calleeDescriptorOf` duplicate, is a small local copy over an
  awkward cross-module dependency on another module's private helper).
  Language-allowed check mirrors `_privacyLanguageAllowed`'s own shape
  (JS/TS extensions only, per the scope boundary above).

**`sink-registry.js` addition:** a new `reclassifyOrmWrite(entry)`
function, mirroring `reclassifyPrivacySink`'s own shape (D3) — returns
`{kind: 'sink', category: 'database', coverageStatus: 'candidate',
externality: <look up CATEGORY_EXTERNALITY['database'], already exists>,
reason: '<explain: heuristic ORM-write recognition, unconfirmed receiver
identity>'}`. `coverageStatus` is a LITERAL `'candidate'` always — never
computed from `entry` the way `reclassifySink` computes it from `CWE_MAP`,
since there is no CWE here at all (this catalog has no `vuln.cwe` the way
`CATALOG`'s general entries do — confirm what `vuln` field this new
catalog even needs; `privacy-catalog.js`'s own entries DO carry a `vuln`
block with a `cwe`, but that CWE is never read by `reclassifyPrivacySink`,
which keys on `entry.category` instead — mirror that same "vuln block
present for documentation/potential-future-use, but category drives
reclassification" pattern here too, don't invent a fake CWE to satisfy an
imagined requirement).

**`coverage.js` addition:** the object-literal-argument gate. Find where
`buildGraphWithCoverage`/`buildDataFlowGraph`'s site enumeration currently
calls `matchSinkOrSanitizer`/`matchPrivacySink` (`enumerateSinkSites` in
`graph-builder.js` is the likely site — read it directly, this plan does
not cite an exact line number on purpose since D2's own plan cited stale
numbers that the implementer had to re-verify) and add a call to
`matchOrmWrite` alongside the existing two matchers, with the
object-literal-argument check applied as a HARD filter immediately after
a match (before the site is added to the sink-site list at all, not as a
`resolveSiteDecision`-style post-hoc reclassification) — a site whose
first argument is not `kind: 'object'` is simply never emitted as an ORM-
write sink candidate.

## Test plan

New `scanner/test/catalog-orm-write.test.js` (mirroring
`test/catalog-ai-model-provider-precision.test.js`'s own structure and
naming, since this is the same class of test — precision proof for a new
catalog family):

1. Real ORM shapes match: `User.create({ email: x })`,
   `Order.save({...})`-style, `Payment.update({...})` — each producing a
   real sink site with `coverageStatus: 'candidate'`.
2. The object-literal gate rejects non-literal arguments:
   `User.create(req.body)` (a bare identifier, not an object literal) must
   NOT produce a sink site at all — this is the load-bearing precision
   proof, and the exact shape `mass-assignment.js`'s OWN detector treats as
   its positive case, so a reader must not confuse "this increment
   recognizes fewer shapes than mass-assignment.js" with a regression —
   name this distinction explicitly in the test's own comment.
3. Non-ORM `.create()` calls with an object-literal argument on a
   lowercase or non-capitalized receiver do NOT match (`widget.create({...})`)
   — the receiver-shape gate proven independently of the argument-shape
   gate.
4. `dataflow/engine.js`/`runTaintEngine` is genuinely unaffected — a real
   scan (or a targeted unit test importing `runTaintEngine` directly) over
   a fixture containing `User.create({ email: req.body.email })` produces
   NO new finding attributable to `orm-write-catalog.js` — proving the
   isolation claim live, not just asserting it in a comment (mirrors
   `privacy-catalog.js`'s own "these entries do not affect any scan's
   output" claim, but THAT claim has never actually been proven by a test
   anywhere in this codebase as far as this plan's own research found —
   check whether one exists before assuming you need to write the first
   one; if none exists, write it here rather than leaving it undischarged
   for a third file to eventually prove).
5. Full `npm run test:lineage` and `npm test` stay green, real captured
   exit codes.

## Explicitly deferred

Table/column/operation extraction (E2). Python/Java/Go/Ruby/PHP ORM
shapes. Prisma's `data: {...}` wrapper form's own precise handling
(flagged above as needing explicit confirmation, not silent assumption).
A new `orm-write`-style `SINK_CATEGORIES` value, if `database` turns out
to be the wrong reuse — the E-scoping doc's own open question, not
resolved here. Queue/topic mapping (E3).
