# Self-learning finding-to-rule compiler

**Maturity:** Labs. See the [capability registry](../capabilities.yaml) and the [maturity model](../how-it-works/maturity-model.md).

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
Once the scanner trusts it (see "Promotion is not trust"), this rule fires deterministically in every scan, with no model call, including on an **unseen
sibling** the corpus never contained (different file, renamed identifiers, extra indirection around the same
shape), the "no model call occurs for B" scenario PRD 3 asks for, and the exact thing
`test/cli/rule-compiler-cli.test.js` asserts against a real spawned CLI and a real `scan`.

```bash
agentic-security rules status orm-raw-query-concat
agentic-security rules rollback orm-raw-query-concat   # un-publishes; ROLLED_BACK, never deleted from the ledger
```

## Structured rules: source, sink, sanitizer

The rule IR is more than a pattern. These fields are regular expressions the scanner's rule matcher **enforces**; there is no
free-text hint that looks like a constraint and is ignored (a field that is not a valid regular expression is rejected):

| Field | What the matcher does with it |
|---|---|
| `sink` | the location of the finding; a sink alone is the pattern |
| `source`, `propagator` | must occur within `window` lines of the sink (a windowed co-occurrence, anchored on the sink) |
| `sanitizer`, `dominatingGuard` | a hit is dropped when either matches within `guardWindow` lines **before** (or on) it |
| `frameworkConstraint` | a file-level precondition: the file must contain it, wherever it is |
| `exclusions` | a hit is dropped when its own line matches one |
| `languages` | the rule only runs on files of those languages |

A sanitizer is **local**: it silences the hit it guards, not every hit in the file. The two files below show the difference. `mixed.js`
has a sanitized function and, further down, an unsanitized one; a file-wide `notMatch` would have hidden both.

```bash
agentic-security rules synthesize hunt-rawquery-0002 --spec spec.json
Rule orm-raw-query-structured: DRAFT -> CANDIDATE (digest 221aa8b79daf)
agentic-security rules evaluate orm-raw-query-structured --corpus corpus.json
Rule orm-raw-query-structured: VALIDATED
  precision 100.0%  recall 100.0%  protected-failures 0
  regression fixtures written: 15 file(s) under .agentic-security/rule-compiler/orm-raw-query-structured/fixtures/
agentic-security rules promote orm-raw-query-structured --sign-key "$RULE_SIGNING_KEY"
Rule orm-raw-query-structured: VALIDATED -> PROMOTED. Published to /private/var/folders/df/jvqnhbfd36v2lw3z4kwbdc580000gn/T/tmp.W6DJQJj3Wj/.agentic-security/rules/orm-raw-query-structured.yml.
  signed: /private/var/folders/df/jvqnhbfd36v2lw3z4kwbdc580000gn/T/tmp.W6DJQJj3Wj/.agentic-security/rules/orm-raw-query-structured.yml.sig
  The scanner will load it (signed, accepted in pass-through mode (no trusted keys are configured)).

agentic-security rules status orm-raw-query-structured
Rule orm-raw-query-structured: PROMOTED
  live: yes (signed, accepted in pass-through mode (no trusted keys are configured))
  2026-10-18T23:07:35.815Z  (new) -> DRAFT  (drafted from hunt-rawquery-0002)
  2026-10-18T23:07:35.817Z  DRAFT -> CANDIDATE  (eligibility passed)
  2026-10-18T23:07:38.709Z  CANDIDATE -> VALIDATED  (promotion gate passed)
  2026-10-18T23:07:40.507Z  VALIDATED -> PROMOTED  (promoted)
```

The published rule, as the scanner loads it:

```yaml
# Compiled by the rule compiler from finding hunt-rawquery-0002 (taint-proven).
- id: rule-compiler/orm-raw-query-structured
  title: "rawQuery fed by a request value without escaping"
  severity: critical
  cwe: CWE-89
  languages: [javascript]
  match:
    allOf:
      - "rawQuery\\s*\\("
      - "(?:req(?:uest)?|ctx)\\.(?:request\\.)?(?:query|params|body)\\b"
    window: 4
    guardedBy: "(?:escapeSql\\s*\\()"
    guardWindow: 4
    excludeLine:
      - "//\\s*audited"
  message: "rawQuery fed by a request value without escaping (CWE-89, compiled from hunt-rawquery-0002)"
```

A real scan then reports the unguarded handler and the unguarded function in the mixed file, and not the sanitizer-guarded one:

```
mixed.js:10 critical
server.js:3 critical
```

Two properties worth knowing. First, the evaluation does its job: with a narrower source (`req` only) the same rule scored 75%
recall and was refused, because the mutation engine's framework variant (`ctx.query`) slipped past it. Second, scoring now goes through
the scanner's own rule loader, so a rule the loader would refuse (a nested-quantifier pattern, say) is rejected at compile time
instead of scoring well and never firing. An AST pattern is deliberately not a field: the engine has no AST matcher for a rule to
compile to.

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

## Promotion is not trust

Publishing a rule file is not the same as the scanner running it. Rule packs are signature-checked so that a rule dropped into a
repository cannot run in someone's CI: **an unsigned pack is refused** unless `AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1`. So `rules promote`
signs the published rule when you give it a key (`--sign-key <base64>` or `AGENTIC_SECURITY_PRIVATE_KEY`; make one with
`agentic-security-rule keygen`), and then says whether the scanner will load it. With no key it publishes, records `PROMOTED`, and tells you
plainly that the rule is **not live yet**, instead of implying a capability that a scan would then not show:

```
agentic-security rules promote orm-raw-query-structured
Rule orm-raw-query-structured: VALIDATED -> PROMOTED. Published to /private/var/folders/df/jvqnhbfd36v2lw3z4kwbdc580000gn/T/tmp.OQ9DCuPOeM/.agentic-security/rules/orm-raw-query-structured.yml.
  NOT LIVE YET: the scanner will refuse this rule (unsigned). To make it live: sign it (agentic-security-rule sign .agentic-security/rules/orm-raw-query-structured.yml with your key, or re-run promote with --sign-key <base64>), or opt in for this environment with AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1.

agentic-security rules status orm-raw-query-structured
Rule orm-raw-query-structured: PROMOTED
  live: NO, the scanner refuses it (unsigned). sign it (agentic-security-rule sign .agentic-security/rules/orm-raw-query-structured.yml with your key, or re-run promote with --sign-key <base64>), or opt in for this environment with AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1.
```

`rules status` (and `rules status --json`) show `live` for every promoted rule. Know what the signature buys you: with no trusted keys
configured the scanner is in *pass-through* mode, which accepts any signed pack (and refuses it entirely in CI unless
`AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1`). To have the signature actually checked against your key, add the public key to
`.agentic-security/trusted-keys.json` and set `AGENTIC_SECURITY_ALLOW_PROJECT_KEYS=1` (the setup is in `bin/agentic-security-rule.js`).
Signing was broken on current Node (`Invalid JWK OKP key`) until this release; `test/rule-pack-signing.test.js` now round-trips it.

## Regression integration: the shared false-positive corpus

A promoted rule joins a corpus every later rule and every later run is held to. The **shared false-positive corpus** is the safe code of
every promoted rule (its patched, nearby-clean and protected variants) plus any file you drop in
`.agentic-security/rule-compiler/fp-corpus/` (real code a rule must never flag). It is part of the promotion gate: a rule that fires on any
of it cannot be `VALIDATED`, and `rules promote` re-checks it against the corpus as it is *now*, since other rules may have been promoted
since the evaluation. Rule B below is too broad (it flags any escape call) and is stopped by rule A's safe code:

```
agentic-security rules evaluate rule-b-overbroad --corpus corpus-b.json
rules synthesize h3 --spec b.json 0 Rule rule-b-overbroad: DRAFT -> CANDIDATE (digest dd9aebc90e3f)
 
rules evaluate rule-b-overbroad --corpus corpus-b.json 1 Rule rule-b-overbroad: gate FAILED
  precision 100.0%  recall 66.7%  protected-failures 0
  - recall 66.7% below 80%
  - fires on 8 of 11 item(s) in the shared false-positive corpus: rule:rule-a-rawquery:patched, rule:rule-a-rawquery:patched-sibling:variable-rename, rule:rule-a-rawquery:patched-sibling:wrap-in-function, ...
```

`rules regress [rule-id]` re-scores every promoted rule against its own corpus and then the shared false-positive corpus, and exits 1 if any
rule no longer clears its gate (the matcher, the loader or another rule changed underneath it, or a false positive you recorded now matches).
After the operator added a real false positive that rule A fires on:

```
agentic-security rules regress
rule-a-rawquery: REGRESSED  precision 100.0%  recall 100.0%  false-positive corpus hits 1
  - fires on 1 item(s) of the shared false-positive corpus: operator-fp:audit-log.js
```

`rules evaluate --corpus` now keeps the corpus it evaluated, so `regress` and the shared corpus use exactly the code the rule was judged on.
Per-rule unit tests remain the fixtures written at evaluation (the existing `rule test` convention); the cross-rule check is the part a
per-rule test cannot see. This does not wire a promoted rule into this repository's own `bench/` corpora: those live in the project's
source tree, not in an operator's `.agentic-security/`.

## Anti-cheating

The synthesis material is checked before anything is written, and a hit fails closed (exit 4, nothing stored): benchmark names
(OWASP Benchmark, Juliet, corpus baselines, ground truth, adjudicated labels, plus any `--benchmark-names` you add), advisory and
weakness identifiers, a comment that describes the vulnerability (`FLAW`, `BAD`, `vulnerable`, `exploit`), a weakness-bearing file
name (`CWE89_...`) and an answer-key file name (`expected.json`, `labels.csv`) given in the spec's `fileNames`. `gatePromotion`
refuses with no leakage check at all as hard as it refuses a failing score; there is no path where omitting the check reads as
"passed". This is a pattern check. It is independent of the evaluation custodian, whose guard is deliberately unreachable from
outside `posture/evaluation/`.

## What this does not do

- **A rule is regular expressions over text, with structure.** The loop proposes a generalized line, a sink with interpolation, a
  source-and-sink pair, or a structural source/sink/sanitizer candidate. There is no AST pattern (the engine has no AST matcher to
  compile to) and no data-flow rule: "source within N lines of the sink" is proximity, not a proven flow. A rule is only as good as
  its corpus.
- **The mutators are syntactic and table-driven.** They show that a rule survives a different author's version of the code, not that
  it survives every one. `bench/mutation/` (the engine-wide verdict-flip gate) is a different, much larger thing and is untouched.
- **Benchmark leakage is a pattern check on the synthesis material**, not a connection to any real benchmark population.
- **No MCP tool** exposes synthesis.
- **Regression is per installation.** Fixtures and the false-positive corpus live in the operator's own `.agentic-security/`, in the
  existing `vulnerable`/`clean` convention `agentic-security rule test` reads. A promoted rule is not added to this repository's `bench/`
  corpora automatically (they are the project's gated regression net, and a rule that lives in operator state is not part of the engine
  those benches scan with).

## Output schema

Each rule keeps its state under `.agentic-security/rule-compiler/<rule-id>/`: `ir.json` (`agentic-security/rule-ir` version 1), `corpus.json`
(the code it was judged on), `evaluation.json` (the gate result and every positive and negative with whether it fired), `provenance.json`,
`synthesis.json` (every attempt), and the hash-chained `ledger.json` beside them. `provenance.json`, real, nested values abbreviated:

```json
{
  "schema": "agentic-security/rule-provenance",
  "version": 1,
  "ruleId": "rule-a-rawquery",
  "ruleVersion": 1,
  "ruleHash": "dfe10d11b5bca4584d1c852b15feb6dc65c149ae6c5cda0edc74a3448...",
  "originatingFinding": "h3",
  "originatingCommit": null,
  "evidenceState": "taint-proven",
  "generatingModel": null,
  "promptConfigVersion": null,
  "positiveCorpusHash": "84e31aab849581319f82fef89191f44b4d7f96e03fefa55138296e140...",
  "negativeCorpusHash": "232238d2a54680f9ec1f478362bbc3a827543f1aaf0cbe128cfc18579...",
  "benchmarkResults": {
    "precision": 1,
    "recall": 1,
    "tp": 4,
    "fp": 0,
    "fn": 0,
    "tn": 11,
    "protectedFailures": 0,
    "thresholds": "{...}",
    "gate": "passed",
    "reasons": "[...]"
  },
  "leakageCheck": {
    "ok": true,
    "offendingTerms": "[...]"
  },
  "mutatorCoverage": {
    "applied": "[...]",
    "notApplicable": "[...]"
  },
  "discoveryCost": null,
  "promotionEvent": {
    "at": "2026-10-18T23:09:15.587Z",
    "actor": "operator",
    "reason": "promoted",
    "ruleHash": "dfe10d11b5bca4584d1c852b15feb6dc65c149ae6c5cda0edc74a3448..."
  },
  "evaluatedAt": "2026-10-18T23:09:14.855Z"
}
```

`rules status --json` lists every rule with its state and, for promoted rules, whether the scanner will load it; `rules regress --json`
reports each promoted rule:

```json
[
  {
    "id": "rule-a-rawquery",
    "state": "PROMOTED",
    "live": false
  },
  {
    "id": "rule-b-overbroad",
    "state": "CANDIDATE"
  }
]
```

```json
{
  "results": [
    {
      "id": "rule-a-rawquery",
      "status": "regressed",
      "reasons": [
        "fires on 1 item(s) of the shared false-positive corpus: operator-fp:audit-log.js"
      ],
      "precision": 1,
      "recall": 1,
      "protectedFailures": 0,
      "fpCorpusHits": 1
    }
  ]
}
```

## Troubleshooting

| What you see | Why, and what to do |
|---|---|
| `gate FAILED ... recall 75.0% below 80%` | The mutation siblings exposed a rule that is too narrow. Open `evaluation.json` and look at which positive has `"fired": false` (for example a `framework-variant` using `ctx.query` against a source that only matches `req`). Widen the source or sink, not the threshold. |
| `the scanner's rule loader would reject this rule` | The rule has a pattern the scanner refuses to load (nested quantifiers are a ReDoS risk). It would have scored well and never fired. Rewrite the pattern. |
| `NOT LIVE YET: the scanner will refuse this rule (unsigned)` | By design: an unsigned rule pack is refused. Re-run `rules promote <id> --sign-key <base64>` (key from `agentic-security-rule keygen`), sign the file with `agentic-security-rule sign`, or opt in for one environment with `AGENTIC_SECURITY_ALLOW_UNSIGNED_PACKS=1`. In CI, pass-through of signed packs is refused unless `AGENTIC_SECURITY_ALLOW_PASSTHROUGH_IN_CI=1`. |
| `fires on N of M item(s) in the shared false-positive corpus` | The rule matches safe code from another promoted rule or a file in `fp-corpus/`. Narrow the rule. If the file is not a real false positive, remove it from `.agentic-security/rule-compiler/fp-corpus/`. |
| `rules regress`: `REGRESSED` or `unverifiable` | `REGRESSED` names the reason (the rule no longer clears its gate, or now matches a false positive). `unverifiable: no evaluated corpus was kept` means the rule was evaluated before corpora were kept; run `rules evaluate <id> --corpus <file>` again. |
| `Refusing: the material for this rule shows benchmark or answer-key signals` | The anti-cheating check found a benchmark name, advisory id, vulnerability comment or answer-key file name in the synthesis material. Nothing was written. Remove the signal; do not work around it. |
| `Not eligible for rule synthesis` | The finding needs a stable id, a vulnerable span, a CWE or family, code-flow evidence, and an exploit proof or deterministic corroboration. The message lists what is missing. |
| `Rule ... is not VALIDATED ... refusing to promote` | Promotion needs a passing `rules evaluate` first. A rule that failed the gate cannot be promoted. |

## Reference

- Module: `scanner/src/posture/rule-compiler/` (`ir.js`, `eligibility.js`, `mutation.js`, `corpus.js`,
  `proposal.js`, `promotion.js`, `lifecycle.js`, `store.js`, `cli.js`)
- Tests: `scanner/test/rule-compiler/{core,synthesis}.test.js`, `scanner/test/cli/rule-compiler-cli.test.js` (the killer
  scenario, with and without a supplied pattern), all in `npm run test:posture`
- Implementation status: [`docs/implementation-status/rule-compiler.md`](../implementation-status/rule-compiler.md)
