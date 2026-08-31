# Data Flow Explorer — Sub-project F, increment F2 (category-coverage fixture batch) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Author the first real batch of `bench/data-lineage/` corpus fixtures — one connected flow per each of the 14 reachable `SOURCE_CATEGORIES` and, by pairing choice, coverage of all 10 reachable `SINK_CATEGORIES` too, plus a small number of structurally-distinct fixtures (aliased, interprocedural, two negative/clean cases) — scored by F1's already-shipped `runner.mjs`.

**Architecture:** Pure content authoring against an already-shipped, already-reviewed scoring contract (F1). No changes to `src/lineage/` production code, no changes to `runner.mjs`. Every fixture pairs a KNOWN-GOOD source snippet and a KNOWN-GOOD sink snippet — both taken verbatim from `scanner/test/lineage/registry-real-code.test.js`'s own `SOURCE_PROOFS`/`SINK_PROOFS` tables (D5's own real-code proof set, already confirmed to structurally match the live catalog matchers) — combined into one realistic function per fixture, with a sensitive field NAME chosen from `scanner/src/dataflow/privacy-taxonomy.js`'s own recognized patterns so the data element actually classifies into a real `dataClass`.

**Tech Stack:** Node ≥ 24, ESM (fixture files are plain `.js`, not test code).

**Spec:** `docs/superpowers/plans/2026-08-31-data-flow-explorer-m1-subproject-f-scoping.md` (§2's per-bullet checklist, §6's recommended increment breakdown — this IS the "hand-author the structurally-distinct fixtures first" increment it names), and `bench/data-lineage/runner.mjs`/`README.md` (the F1-shipped scoring contract this batch is scored against — read both before starting, they are short).

## Global Constraints

- Every new fixture directory follows the existing shape exactly: `bench/data-lineage/fixtures/<id>/{source.js, expected.json}`. Naming convention (per the README): `<lang>-<source-category>-to-<sink-category>-<distinguishing-trait>`.
- **Every fixture's `expected.json` must be verified against REAL runner output before being considered done — never guessed.** Data-element classification (`dataClass`) is driven by the FIELD NAME the source expression resolves to (`classifyDataElementName`, `scanner/src/lineage/classification.js`, reading `scanner/src/dataflow/privacy-taxonomy.js`'s regex patterns) — this plan gives a chosen field name per fixture believed to classify correctly, but the implementer MUST run `node bench/data-lineage/runner.mjs` after authoring each fixture and adjust `expected.json` (or, if genuinely necessary, the field name) to match what the engine ACTUALLY produces, exactly like F1's own "verify against real code, don't force a fixture to pass by guessing" discipline. A field name that turns out not to classify as expected is a normal, expected finding, not a sign of a bug — record what you found.
- Every new fixture must default to `"tier": "regression"` unless it exercises one of the two Milestone-2-blocked dimensions (transport-protection states, policy-permitted/prohibited flows) named in the F scoping report §2 — none of this batch's fixtures do, so every fixture in THIS increment is `regression`-tier.
- `expectedConnected` defaults to `true` (omit the field) for every fixture in this batch except the two negative/clean fixtures in Task 4, which set it `false` explicitly.
- Do not modify `runner.mjs`, `scoreFixture`, or any file under `scanner/src/lineage/`. If a fixture genuinely cannot be scored by the existing contract (e.g. a cross-file flow — `runner.mjs` only loads a single `source.<ext>` per fixture today), do NOT extend the runner in this plan — skip that shape and note it as deferred to a later increment (F3+), per the scoping report's own explicit exclusion of cross-file/runner-extension work from "hand-author the structurally-distinct fixtures first."
- After each task, run `node bench/data-lineage/runner.mjs --check` from the repo root and confirm exit 0 with every fixture (old and new) reported `ok`.

---

### Task 1: the 14 reachable-source-category fixtures

**Files:** Create 14 new directories under `bench/data-lineage/fixtures/`.

**Interfaces:** None — pure fixture content, scored by the existing `runner.mjs`/`scoreFixture` unchanged.

The table below pairs each of the 14 reachable `SOURCE_CATEGORIES` (left, with its KNOWN-GOOD matcher shape from `SOURCE_PROOFS` in `scanner/test/lineage/registry-real-code.test.js`) against one of the 10 reachable `SINK_CATEGORIES` (right, with its KNOWN-GOOD matcher shape from `SINK_PROOFS` in the same file), chosen so all 10 sink categories are exercised at least once across the 14 rows. A sensitive field name is chosen per row from `scanner/src/dataflow/privacy-taxonomy.js`'s own regex patterns (quoted inline) so the resulting data element should classify into the named `dataClass`.

| # | source category | known-good source shape | chosen field | dataClass | sink category | known-good sink shape |
|---|---|---|---|---|---|---|
| 1 | `http-body` | `req.body` | `card_number` (`\bcard[_-]?(?:number\|num\|no)\b`) | PCI | `database` | `db.query(sql)` |
| 2 | `http-query` | `req.query` | `email` (`\bemail...\b`) | PII | `log` | `console.log(x)` |
| 3 | `http-route` | `req.params` | `ssn` (`\bssn\b`) | PII | `external-api` | `fetch(url)` |
| 4 | `http-header` | `req.headers` | `api_key` (`\bapi[_-]?key\b`) | CREDENTIALS | `analytics` | `analytics.track(props)` |
| 5 | `http-cookie` | `req.cookies` | `session_token` (`\bsession[_-]?token\b`) | CREDENTIALS | `http-response` | `res.redirect(url)` |
| 6 | `http-upload` | `request.FILES` (mirrors `py-django-request-FILES`, JS syntax mirroring the Python match shape per D5's own precedent) | `medical_record` (`\b(?:medical\|patient\|health)[_-]?record\b`) | PHI | `object-storage` | `s3.putObject(params)` |
| 7 | `cli-argument` | `sys.argv` (mirrors `py-sys-argv`) | n/a — index access, no field name | (verify real output — may be untagged) | `file` | `fs.readFile(path)` |
| 8 | `env-value` | `process.env` | `DATABASE_PASSWORD` (`\bpassword\b`, verify case-insensitivity in the real regex before relying on it) | CREDENTIALS | `queue` | `queue.sendMessage(params)` |
| 9 | `storage-read` | `open(path)` (mirrors `py-open-read`) | n/a — a file handle, no field name | (verify real output) | `email` | `sendMail(msg)` |
| 10 | `user-input` | `input()` (mirrors `py-input`) | n/a — a bare call, no field name | (verify real output) | `log` | `console.log(x)` |
| 11 | `external-api-response` | `response.data` | `card_number` | PCI | `client-storage` | `el.innerHTML = payload` |
| 12 | `ai-model-output` | `params.arguments` | `patient_summary` (no exact pattern match — verify; AC-07's own worked example uses this exact field name, so keep it even if unclassified, for continuity with the PRD's own scenario) | PHI (verify) | `log` | `console.log(x)` |
| 13 | `ai-tool-result` | `result.content` | `diagnosis` (`\bdiagnosis\b`) | PHI | `database` | `db.query(sql)` |
| 14 | `ai-retrieved-document` | `resource.contents` | `medical_record` | PHI | `external-api` | `fetch(url)` |

- [ ] **Step 1: Author the worked example in full — row 1 (`js-http-body-to-database-pci`)**

`bench/data-lineage/fixtures/js-http-body-to-database-pci/source.js`:

```js
function handleCheckout(req, db) {
  const cardNumber = req.body.card_number;
  const sql = `SELECT * FROM cards WHERE number = '${cardNumber}'`;
  db.query(sql);
}
```

`bench/data-lineage/fixtures/js-http-body-to-database-pci/expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "database",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "tier": "regression",
  "notes": "req.body.card_number flows into a SQL query string via template-literal concatenation, reaching db.query(sql) unmasked. F2 category-coverage batch, row 1: http-body -> database."
}
```

Run: `node bench/data-lineage/runner.mjs` from the repo root. Confirm this fixture reports `ok`. If it does not, read the printed error, determine the real cause (a wrong category name, a data element that didn't classify as PCI, a flow that didn't connect because of how the template literal lowers in the IR — check `scanner/src/lineage/DESIGN_INTRAPROCEDURAL.md`'s notes on `tpl` production if a template-literal concat doesn't carry identity the way you expect), and correct `expected.json` or `source.js` to match reality, documenting the correction in this task's own commit message or a code comment in `source.js` if the real behavior is genuinely surprising.

- [ ] **Step 2: Author rows 2-14, following Step 1's exact pattern**

For each remaining row in the table: write a small, realistic function combining the source snippet's real member-read/call shape with the sink snippet's real call shape, assigning the sensitive field to a local variable and passing it (or a trivial derivation, like row 1's template literal) into the sink call. Use the row's chosen field name. Write `expected.json` with the row's `sourceCategory`/`sinkCategory`/best-guess `dataClass`, then run the runner and correct based on real output — per this plan's Global Constraints, this is mandatory for every fixture, not just the worked example.

For the four rows marked "n/a — no field name" (cli-argument, storage-read, user-input) and the two marked "verify" (ai-model-output's classification, env-value's case-sensitivity): these are the rows most likely to need a real correction. Do not skip them or leave them unauthored — an empty or wrong `dataClass` array (`[]`) is an ACCEPTABLE, honest outcome if that's genuinely what the real engine produces for an unclassified field; document that finding in the fixture's own `notes` field rather than inventing a `dataClass` the real output doesn't support.

- [ ] **Step 3: Run the full runner and confirm all 14 (plus the 4 pre-existing) fixtures pass**

Run: `node bench/data-lineage/runner.mjs --check; echo "exit: $?"` from the repo root.
Expected: `18/18 passed (0 regression-tier failure(s), 0 capability-tier failure(s))`, `exit: 0`.

- [ ] **Step 4: Commit**

```bash
cd /Users/ross/code/agentic-security
git add bench/data-lineage/fixtures/
git commit -m "feat(lineage): author 14 category-coverage corpus fixtures — all reachable source categories (Sub-project F, increment F2 Task 1)"
```

---

### Task 2: aliasing and interprocedural fixtures

**Files:** Create 2 new fixture directories.

- [ ] **Step 1: `js-http-body-to-log-aliased/`**

`source.js`:

```js
function handleCheckout(req, logger) {
  const body = req.body;
  const cardNumber = body.card_number;
  logger.info('checkout', cardNumber);
}
```

`expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "tier": "regression",
  "notes": "req.body is aliased to a local (`body`) before .card_number is read off it — proves field identity survives an alias hop, not just a direct member chain (DESIGN_INTRAPROCEDURAL.md's structure-preserving `ident` case)."
}
```

- [ ] **Step 2: `js-http-body-to-log-interprocedural/`**

`source.js`:

```js
function extractCard(req) {
  return req.body.card_number;
}

function handleCheckout(req, logger) {
  const cardNumber = extractCard(req);
  logger.info('checkout', cardNumber);
}
```

`expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PCI"],
  "sourceCategory": "http-body",
  "sinkCategory": "log",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "tier": "regression",
  "notes": "card_number is extracted in a HELPER function and returned to the caller, which then logs it — proves the flow survives a real interprocedural summary hop (Sub-project B), not just intraprocedural analysis."
}
```

- [ ] **Step 3: Run and verify both against real output**, correcting `expected.json` if the real classification/flow shape differs, per this plan's Global Constraints. Run `node bench/data-lineage/runner.mjs --check` and confirm `20/20 passed`, exit 0.

- [ ] **Step 4: Commit**

```bash
git add bench/data-lineage/fixtures/js-http-body-to-log-aliased/ bench/data-lineage/fixtures/js-http-body-to-log-interprocedural/
git commit -m "feat(lineage): author aliased + interprocedural corpus fixtures (Sub-project F, increment F2 Task 2)"
```

---

### Task 3: two negative/clean fixtures

**Files:** Create 2 new fixture directories.

- [ ] **Step 1: `js-http-query-to-log-unclassified-clean/`** — a genuinely clean negative: a source category matches structurally, but the field itself carries no sensitive-data-class name, so NO flow should be scored as carrying a `dataClass` this fixture cares about.

`source.js`:

```js
function handleList(req, logger) {
  const page = req.query.page;
  logger.info('listing page', page);
}
```

`expected.json`:

```json
{
  "language": "js",
  "dataClass": ["PII"],
  "sourceCategory": "http-query",
  "sinkCategory": "log",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "expectedConnected": false,
  "tier": "regression",
  "notes": "req.query.page is a pagination index, not PII — classifyDataElementName should not tag it PII, so no flow should carry a PII-tagged dataElement from source to sink even though the category match and the call itself are real. A genuinely clean negative case, distinct from js-api-to-log-disconnected's 'right data, wrong sink' shape — this is 'right category shape, wrong data entirely.'"
}
```

Run against real output. **This fixture's exact behavior needs real verification, not assumption**: confirm whether `graph.dataElements` even mints an entry for `page` at all (it may, with an empty or generic `dataClasses`, or `classifyDataElementName` may return no classes and the seed might still register structurally). Whatever the REAL behavior is, set `expected.json`'s fields to match it exactly and record what you found in `notes` — this fixture's entire purpose is pinning that a non-sensitive field does NOT get miscategorized as carrying a `dataClass` it doesn't have, so the assertion must reflect genuine engine behavior, not a hoped-for one.

- [ ] **Step 2: `js-exec-unsupported-sink/`** — AC-11's OTHER coarse-half case (D3's `unsupported`/`process`-kind sink): a real, discovered sink with no matching category, proving it stays visible rather than silently dropped.

`source.js`:

```js
function runDiagnostics(cmd) {
  exec(cmd);
}
```

`expected.json`:

```json
{
  "language": "js",
  "dataClass": [],
  "sourceCategory": "http-body",
  "sinkCategory": "database",
  "expectedProtection": null,
  "expectedTransformKind": null,
  "expectedConnected": false,
  "tier": "capability",
  "notes": "exec(cmd) matches js-exec (CWE-78), a null-category/unsupported sink (kind:'process') per D3 -- there is no PCI/http-body source in this fixture at all, so sourceCategory/sinkCategory here are placeholders the current scoreFixture contract cannot actually target (it has no way to assert 'an unsupported-kind node with subtype:null exists'). Marked capability-tier and left deliberately unscored by the connected/disconnected assertion — see this fixture's own follow-up note for whoever extends scoreFixture to support asserting kind:'process'/subtype:null nodes directly, which F1's contract does not yet cover. Authored now so the shape exists in the corpus even though the runner cannot fully evaluate it yet."
}
```

**This second fixture is a known, disclosed limit of F1's own contract** (which asserts by `subtype` category match, not by `kind === 'process'`/`subtype === null`) — do not attempt to extend `scoreFixture` to handle it in this task; author it as `capability`-tier (never gates `--check`) and confirm the runner does not crash on it (a `sourceCategory`/`sinkCategory` that matches nothing should still degrade to a clean, readable FAIL under `capability` tier, not an uncaught exception — verify this live).

- [ ] **Step 3: Run and confirm.** `js-http-query-to-log-unclassified-clean` must be `regression`-tier and pass. `js-exec-unsupported-sink` is `capability`-tier and is EXPECTED to report FAIL (not `ok`) — confirm `--check` still exits 0 despite that printed FAIL (mirrors F1's own already-proven tier semantics). Run `node bench/data-lineage/runner.mjs --check; echo "exit: $?"` and confirm `21/22 passed (0 regression-tier failure(s), 1 capability-tier failure(s))`, `exit: 0` (the exact pass count depends on Task 1/2's own final fixture count — recompute the expected total from however many fixtures actually exist at this point rather than trusting this plan's arithmetic blindly).

- [ ] **Step 4: Commit**

```bash
git add bench/data-lineage/fixtures/js-http-query-to-log-unclassified-clean/ bench/data-lineage/fixtures/js-exec-unsupported-sink/
git commit -m "feat(lineage): author 2 negative/clean corpus fixtures — unclassified field + unsupported-sink shape (Sub-project F, increment F2 Task 3)"
```

---

### Task 4: update the README's corpus-state section and run the full gate

**Files:** Modify: `bench/data-lineage/README.md`, `scanner/test/bench-data-lineage-runner.test.js`'s `F1/11` test (the "real seed corpus" regression pin — it currently asserts `ids.length >= 4`; update the assertion and its own name/comment to reflect the new, larger real count, and confirm it still runs every fixture through `scoreFixture` and asserts `pass: true` for every one — this is the load-bearing regression guard that would have caught any of this batch's fixtures silently regressing).

- [ ] **Step 1: Update the README's "Corpus state" section** with the real final fixture count (old count + this increment's additions), noting the new category-coverage rows, the aliased/interprocedural pair, and the two negative/clean fixtures (including the disclosed limitation the `js-exec-unsupported-sink` fixture names).

- [ ] **Step 2: Update `F1/11` in `scanner/test/bench-data-lineage-runner.test.js`** — change the `>= 4` assertion to the real new count, and rename the test description to reflect "all seed + F2 fixtures" rather than just "the 4 seed fixtures."

- [ ] **Step 3: Run the full test suite**

Run: `cd scanner && npm run test:lineage`
Expected: same count as after F1 (the fixture count changed but the TEST count — `F1/11` iterates fixtures at runtime, it doesn't add new `test()` calls per fixture — stays the same; confirm this is actually true by reading `F1/11`'s own loop structure before assuming).

Run: `cd /Users/ross/code/agentic-security && node bench/data-lineage/runner.mjs --check; echo "exit: $?"`
Expected: exit 0.

Run: `cd scanner && npm test`
Expected: full gate green, exit 0.

- [ ] **Step 4: Commit**

```bash
git add bench/data-lineage/README.md scanner/test/bench-data-lineage-runner.test.js
git commit -m "docs(lineage): update corpus-state docs + F1/11's regression pin count for the F2 fixture batch"
```

---

## Self-review notes

- **Spec coverage:** all 14 reachable source categories get a fixture (Task 1); all 10 reachable sink categories are exercised across those 14 rows (verify this explicitly once Task 1 is done — count distinct `sinkCategory` values across the 14 `expected.json` files and confirm all 10 appear at least once, since the table's own hand-assignment could have an error); aliasing and interprocedural shapes get dedicated fixtures (Task 2); both of AC-11's coarse-half cases (disconnected-with-real-data already existed from F1, unsupported/process-kind sink is new in Task 3) are represented.
- **Placeholder scan:** every fixture has real, complete `source.js`/`expected.json` content or an explicit, disclosed reason a field is left to real-output verification (never a bare TBD). The one deliberately incomplete case (`js-exec-unsupported-sink`'s inability to be fully scored) is disclosed as a named limitation of F1's own contract, not silently glossed over.
- **Type consistency:** every new `expected.json` uses exactly the field names F1's `runner.mjs`/`scoreFixture` already reads (`language`, `dataClass`, `sourceCategory`, `sinkCategory`, `expectedProtection`, `expectedTransformKind`, `tier`, `expectedConnected`, `notes`) — no new field is introduced, matching this increment's own "pure content authoring, no runner changes" scope.
