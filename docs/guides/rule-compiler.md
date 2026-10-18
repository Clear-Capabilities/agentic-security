# Self-learning finding-to-rule compiler

**Status: new.** Turns ONE model- or human-discovered vulnerability into a reusable, deterministic detection rule ,
evidence promotes rules, never a model. Nothing here calls a model; a model (or a human) may propose a candidate
pattern, and this machinery decides, from executable evidence, whether it is good enough to go live.

## Three similarly-named, different things, read this first

This codebase already has two other features with "synthesize" or "rule" in their name. The slash-command mode `/labs --synthesize-rule` is the first row below; the CLI subcommand `labs synthesize-rule <finding-id>` is this guide's feature. None of the three
overlaps in what they do:

| Command | Input | Output | What it needs |
|---|---|---|---|
| `labs --synthesize-rule` | sample vulnerable files for one CWE | a **detector spec proposal** for a human to manually copy into a new SAST module | an LLM endpoint |
| `labs claude-audit` / `posture/rule-synthesis.js` | repeated **false-positive** triage verdicts | a **suppression** rule proposal | triage history |
| `rules synthesize` / `labs synthesize-rule <finding-id>` (this guide; the second is the same command under the name the program calls it) | one confirmed **true-positive** finding | a **live, promoted detection rule**, validated against its own corpus | an eligible finding + the vulnerable and patched code (a candidate pattern is optional) |

## The lifecycle

```
DRAFT → CANDIDATE → VALIDATED → PROMOTED → DEPRECATED / ROLLED_BACK
```

Recorded in an append-only, hash-chained ledger (`rule-lifecycle.js`'s idiom, same pattern as the invariants
approval ledger). A rule cannot promote itself: there is no edge from `CANDIDATE` straight to `PROMOTED`, and
nothing in the evaluate/promote split writes the ledger from inside the scoring function.

## Eligibility

A finding may enter synthesis only with: a stable id, a vulnerable span (`file:line`), a CWE or family, code-flow
evidence (an `IR-TAINT`/`MULTI-SINK` parser origin, or a snippet), and deterministic corroboration or exploit proof
, reusing the existing `proofTier` vocabulary and, when available, the [exploit proof fabric](exploit-proof-fabric.md)'s
evidence-state ladder, rather than a third one.

## Worked example, a real, verified miss

The deterministic engine does not recognize `db.rawQuery(...)` as a SQL sink (verified by a real scan in this
session: zero findings on `db.rawQuery("SELECT * FROM users WHERE id = " + userId)`). This is the actual, grounded
case the test suite's killer scenario (`test/cli/rule-compiler-cli.test.js`) walks end to end.

```bash
agentic-security rules synthesize hunt-rawquery-0001 --spec spec.json
```

`spec.json` is exactly what a model (or a human) proposes, this command never invents a pattern:

```json
{
  "id": "orm-raw-query-concat", "title": "ORM rawQuery built from string concatenation",
  "severity": "critical", "cwe": "CWE-89", "family": "sql-injection", "languages": ["javascript"],
  "match": { "pattern": "rawQuery\\s*\\(\\s*[\"'][^\"']*[\"']\\s*\\+" },
  "remediation": "Bind parameters; never concatenate untrusted input into rawQuery()."
}
```

```bash
agentic-security rules evaluate orm-raw-query-concat --corpus corpus.json
```

`corpus.json` supplies the original code and, optionally, a patched version, nearby clean calls and
sanitizer/guard-carrying variants:

```json
{
  "originalCode": "db.rawQuery(\"SELECT * FROM users WHERE id = \" + userId);",
  "patchedCode": "db.rawQuery(\"SELECT * FROM users WHERE id = ?\", [userId]);",
  "nearbyCleanCode": ["db.rawQuery(\"SELECT * FROM users\");"],
  "protectedVariantsCode": ["db.rawQuery(\"SELECT * FROM users WHERE id = ?\", [userId]);"]
}
```

`evaluate` automatically generates structural siblings of both the positive and negative sides, variable rename,
wrap-in-function, insert-indirection, deterministic and semantics-preserving, so "does this rule generalize"
is answered without needing a second hand-written fixture for every shape. The promotion gate (default: precision
≥95%, recall ≥80%, zero protected-negative failures) must pass before the state can advance to `VALIDATED`, and
only a `VALIDATED` rule can be promoted:

```bash
agentic-security rules promote orm-raw-query-concat
```

This compiles the rule IR into a document the EXISTING custom-rule engine (`posture/custom-rules.js`) already
knows how to run, no second matching engine, and writes it to `.agentic-security/rules/orm-raw-query-concat.yml`.
From the next scan onward, this rule fires deterministically, with no model call, including on an **unseen
sibling** the corpus never contained (different file, renamed identifiers, extra indirection around the same
shape), the "no model call occurs for B" scenario PRD 3 asks for, and the exact thing
`test/cli/rule-compiler-cli.test.js` asserts against a real spawned CLI and a real `scan`.

```bash
agentic-security rules status orm-raw-query-concat
agentic-security rules rollback orm-raw-query-concat   # un-publishes; ROLLED_BACK, never deleted from the ledger
```

## The synthesis loop

Nothing supplies the pattern: `--auto` (or a spec with no `match`) makes the compiler propose it from the two pieces of evidence it
has. The lines that exist only in the vulnerable version say what the flaw looks like; the calls and placeholders that exist only
in the patched version say what safe looks like, and become the `notMatch` that keeps the rule quiet on safe files. A model's own
proposal (`match` in the spec) is tried first when there is one. Every attempt is scored on the real corpus, with its mutations, by
the same matcher the promoted rule will run on; a failure is revised from why it failed (a negative that fired adds the safe
version's vocabulary to `notMatch`); attempts are bounded (`--max-attempts`, default 6); and the loop emits a CANDIDATE, never a
promoted rule. Where no attempt meets the gate it says so and keeps the best one as a candidate only.

```
$ agentic-security scan . --format json   # before: the engine does not flag this shape
findings: 0
```

```
$ agentic-security labs synthesize-rule hunt-rawquery-0001 --spec spec.json --auto
  attempt 1: line-shape                         precision 100.0%  recall 100.0%  protected-failures 0  PASS
  candidate meets the promotion gate on this corpus (not yet recorded as VALIDATED).
Rule orm-raw-query-concat: DRAFT -> CANDIDATE (digest d8408acb5652)
```

```
$ agentic-security rules evaluate orm-raw-query-concat
Rule orm-raw-query-concat: VALIDATED
  precision 100.0%  recall 100.0%  protected-failures 0
  regression fixtures written: 18 file(s) under .agentic-security/rule-compiler/orm-raw-query-concat/fixtures/
```

```
$ agentic-security rules promote orm-raw-query-concat
Rule orm-raw-query-concat: VALIDATED -> PROMOTED. Published to ./.agentic-security/rules/orm-raw-query-concat.yml.
```

A promoted rule is an unsigned rule pack. On a machine with trusted rule-pack keys configured, a scan refuses it until it is signed
(`REFUSED rule pack ... unsigned`); for local use `AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1` loads it and tags its findings
`_unsigned`:

```
$ AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1 agentic-security scan . --format json   # after: an unseen sibling in orders.js is caught, with no model call
orders.js:4 CWE-89 custom:rule-compiler/orm-raw-query-concat:orders.js:4
server.js:3 CWE-89 custom:rule-compiler/orm-raw-query-concat:server.js:3
```

`orders.js` is the unseen sibling: different file, renamed identifiers, an extra function around it. It was never in the corpus,
and no model was called to catch it.

### The seven mutators

Positives and negatives are both mutated, so a rule has to survive the other author's version of the same code: variable rename,
wrap-in-function, indirection, equivalent API (`exec` / `execSync`, `db.query` / `db.execute`), statement reordering (adjacent
statements that share no identifier), alternate sanitizer (`escapeHtml` / `validator.escape`, `shlex.quote` / `pipes.quote`) and
framework variant (`req.query` / `ctx.query`, `request.args` / `request.form`, `$_GET` / `$_REQUEST`). The safe side is mutated too:
a rule keyed to one sanitizer's name fires on its alternate-sanitizer sibling, which counts as a protected-negative failure and
stops promotion. The tables are small and conservative on purpose, and `mutatorCoverage` records which mutators did not apply to a
given snippet, so the evidence says what it did not exercise.

## Provenance and cost

Evaluation writes `provenance.json` next to the rule: originating finding and commit, evidence state, generating model, prompt or
configuration version, the hash of the positive and of the negative corpus, the benchmark results and thresholds, the leakage
check, mutator coverage, the rule hash and version, and (once promoted) the promotion event.

`rules cost <rule-id>` reports the business metric: what the first, model-assisted discovery cost (recorded from the spec or
`--discovery-cost-usd` / `--discovery-tokens`) against every later deterministic detection, which makes no model call.

```
$ agentic-security rules cost orm-raw-query-concat
Rule orm-raw-query-concat (promoted)
  first discovery: $0.42, 51234 tokens, hunt-agent-1
  later detections by this rule in the last scan: 0, each at $0 of model spend
```

The detection count comes from the last scan only, so it is a floor, not a history.

## Anti-cheating

The synthesis material is checked before anything is written, and a hit fails closed (exit 4, nothing stored): benchmark names
(OWASP Benchmark, Juliet, corpus baselines, ground truth, adjudicated labels, plus any `--benchmark-names` you add), advisory and
weakness identifiers, a comment that describes the vulnerability (`FLAW`, `BAD`, `vulnerable`, `exploit`), a weakness-bearing file
name (`CWE89_...`) and an answer-key file name (`expected.json`, `labels.csv`) given in the spec's `fileNames`. `gatePromotion`
refuses with no leakage check at all as hard as it refuses a failing score; there is no path where omitting the check reads as
"passed". This is a pattern check. It is independent of the evaluation custodian, whose guard is deliberately unreachable from
outside `posture/evaluation/`.

## What this does not do

- **A proposal is a regular expression over text.** The loop generalizes the vulnerable line and, failing that, the sink call with
  interpolation, a source-and-sink pair within a window, or the bare sink. It does not build an AST or data-flow rule, and a rule is
  only as good as its corpus.
- **The mutators are syntactic and table-driven.** They show that a rule survives a different author's version of the code, not that
  it survives every one. `bench/mutation/` (the engine-wide verdict-flip gate) is a different, much larger thing and is untouched.
- **Benchmark leakage is a pattern check on the synthesis material**, not a connection to any real benchmark population.
- **No MCP tool** exposes synthesis.
- **Regression fixtures are written in the operator's own `.agentic-security/`**, in the existing `vulnerable`/`clean` convention
  `agentic-security rule test` already reads, not into this repository's own `bench/`.

## Reference

- Module: `scanner/src/posture/rule-compiler/` (`ir.js`, `eligibility.js`, `mutation.js`, `corpus.js`,
  `proposal.js`, `promotion.js`, `lifecycle.js`, `store.js`, `cli.js`)
- Tests: `scanner/test/rule-compiler/{core,synthesis}.test.js`, `scanner/test/cli/rule-compiler-cli.test.js` (the killer
  scenario, with and without a supplied pattern), all in `npm run test:posture`
- Implementation status: [`docs/implementation-status/rule-compiler.md`](../implementation-status/rule-compiler.md)
