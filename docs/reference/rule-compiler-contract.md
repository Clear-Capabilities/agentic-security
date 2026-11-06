# Finding-to-rule compiler: rule and record contract

<!-- seo: title="Rule compiler contract: the rule format, lifecycle states and the records a rule leaves" description="The frozen rule IR, the lifecycle states, the evaluation, provenance and ledger records, and the exit codes of the rules commands, with the limits of a regular-expression rule." -->

**Maturity:** Preview

This page freezes the rule format and the records a rule leaves behind. A compatibility test (`scanner/test/contracts/rule-compiler.contract.test.js`) drives `rules synthesize`, `evaluate`, `promote`, `status` and `regress` over a fixture finding and holds each record to the tables below in both directions, so a field cannot be added or removed without changing this page. The workflow and examples are in the [rule compiler guide](../guides/rule-compiler.md).

## The rule

`agentic-security/rule-ir`, version 1. A rule is regular expressions over text, with structure. It compiles into the existing custom-rule matcher, not a parallel one.

**Rule fields**

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/rule-ir` |
| `version` | `1` |
| `id` | Lower-case kebab-case, 3 to 80 characters |
| `title` | Required text |
| `severity` | `critical`, `high`, `medium` or `low` |
| `cwe` | `CWE-` and digits |
| `family` | Required text |
| `languages` | A non-empty list from `javascript`, `typescript`, `python`, `go`, `ruby`, `java`, `rust`, `csharp`, `php`, `any` |
| `match` | `pattern`, or a non-empty `allOf`; optional `notMatch` and `window` (1 to 200) |
| `remediation` | Text, or `null` |
| `state` | A lifecycle state (below). Not part of the rule's digest |
| `provenance` | Where the rule came from (below) |

A rule may carry structural fields, each a regular expression the matcher enforces: `sink`, `source`, `propagator`, `sanitizer`, `dominatingGuard`, `frameworkConstraint`, plus `window`, `guardWindow` and `exclusions`. Free text in any of them is rejected, so a field can never look like a constraint while being ignored. The corpus inputs given at synthesis (`originalCode`, `patchedCode`, `nearbyCleanCode`, `protectedVariantsCode`, and since 0.195.23 the independent examples `independentVulnerableCode` and `independentCleanCode`: code from outside the finding that is never mutated) are stored beside the rule.

**Rule provenance**

| Field | Meaning |
|---|---|
| `originatingFindingId` | The finding the rule was made from |
| `originatingCommit` | A commit, or `null` |
| `evidenceState` | `execution-proven`, `taint-proven` or `deterministic-corroboration` |
| `model` | The model that proposed it, or `null` |
| `promptConfigVersion` | The prompt configuration, or `null` |

**Lifecycle states:** `DRAFT`, `CANDIDATE`, `VALIDATED`, `PROMOTED`, `DEPRECATED`, `ROLLED_BACK`. A change of state is an entry in an append-only, hash-chained ledger.

## Records

**Evaluation** (`evaluation.json`; `rules evaluate --json`)

| Field | Meaning |
|---|---|
| `pass` | Whether the promotion gate passed, including the shared false-positive corpus |
| `reasons` | Why it did not, if it did not |
| `evaluation` | The score and thresholds (below) |
| `independent` | The independent examples: `positives`, `negatives`, `detected`, `falseAlarms`. The gate needs at least one of each, every vulnerable one detected and no safe one fired on |
| `fpCorpus` | `items`: how many known-safe files it was held to; `hits`: those it fired on |

**Evaluation score**

| Field | Meaning |
|---|---|
| `pass` | Whether this corpus met the thresholds |
| `reasons` | Why not |
| `score` | The counts (below) |
| `thresholds` | The thresholds used. The defaults are precision 0.95, recall 0.80, zero protected-variant failures, and one independent vulnerable and one independent safe example |

**Score**

| Field | Meaning |
|---|---|
| `precision` | Of what fired, the share that should have |
| `recall` | Of what should fire, the share that did |
| `tp` | True positives |
| `fp` | False positives |
| `tn` | True negatives |
| `fn` | False negatives |
| `protectedFailures` | Protected variants the rule fired on |
| `independent` | Counts for the independent examples alone: `positives`, `negatives`, `detected`, `falseAlarms` |
| `positives` | Every positive item and whether it fired |
| `negatives` | Every negative item and whether it fired |

**Provenance record** (`provenance.json`, `agentic-security/rule-provenance` version 1)

| Field | Meaning |
|---|---|
| `schema` | `agentic-security/rule-provenance` |
| `version` | `1` |
| `ruleId` | The rule |
| `ruleVersion` | `1` |
| `ruleHash` | Digest of the rule, without its state |
| `originatingFinding` | The finding |
| `originatingCommit` | A commit, or `null` |
| `evidenceState` | As in the rule |
| `generatingModel` | The model, or `null` |
| `promptConfigVersion` | The prompt configuration, or `null` |
| `positiveCorpusHash` | Digest of the positive corpus |
| `negativeCorpusHash` | Digest of the negative corpus |
| `benchmarkResults` | The score, the thresholds, `gate` and `reasons` |
| `leakageCheck` | `ok` and any `offendingTerms` |
| `mutatorCoverage` | `applied` and `notApplicable` mutators |
| `discoveryCost` | What finding the original issue cost, or `null` |
| `promotionEvent` | `at`, `actor`, `reviewer`, `scope`, `reason`, `ruleHash` and (since 0.195.27) `evidence`, or `null` before promotion |
| `evaluatedAt` | When it was evaluated |

**Promotion evidence** (`promotionEvent.evidence`, also the ledger entry's `evidence`; since 0.195.27)

| Field | Meaning |
|---|---|
| `reviewer` | The named reviewer |
| `scope` | The reviewed scope, required |
| `independent` | The independent example counts at evaluation |
| `ruleHash` | The rule digest reviewed |
| `evaluationDigest` | Digest of the evaluation record as it stood |
| `provenanceDigest` | Digest of the provenance record as it stood |
| `positiveCorpusHash` | Digest of the positive corpus reviewed; `rules regress` re-derives it |
| `negativeCorpusHash` | Digest of the negative corpus reviewed; `rules regress` re-derives it |
| `sharedFalsePositiveItems` | How many shared false-positive items the rule was held to |

**Ledger entry**

| Field | Meaning |
|---|---|
| `ruleId` | The rule |
| `from` | The state before, or `null` for a new rule |
| `to` | The state after |
| `reason` | Why |
| `evidence` | What justified it, or `null` |
| `actor` | Who or what moved it |
| `at` | When |
| `prevHash` | The previous entry's hash |
| `entryHash` | This entry's hash |

**Status entry** (`rules status --json`)

| Field | Meaning |
|---|---|
| `id` | The rule |
| `state` | A lifecycle state |
| `live` | For a promoted rule, whether the scanner will load it. A rule published unsigned is not live until it is signed or the environment opts in |

**Regression result** (`rules regress --json`, under `results`)

| Field | Meaning |
|---|---|
| `id` | The rule |
| `status` | `ok` or `regressed` |
| `reasons` | Why it regressed |
| `precision` | Re-scored against its own corpus |
| `recall` | Re-scored |
| `protectedFailures` | Protected variants it now fires on |
| `fpCorpusHits` | Known-safe items it now fires on |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Done (an evaluation that passed, a promotion, a status) |
| `1` | A gate failed: the evaluation did not pass, a promotion was refused on the false-positive corpus, or a promoted rule regressed |
| `4` | A usage problem, a rule or finding that does not exist, a rule that is not eligible, an invalid rule, a leakage refusal, or a ledger that failed its integrity check |

## Guarantees

- **Promotion is not trust.** A promoted rule is published unsigned unless you sign it, and the scanner refuses an unsigned rule pack; `live` says which.
- **A gate failure is not softened.** A rule that fires on the shared false-positive corpus does not pass, and one promoted earlier is re-held to the corpus as it is now.
- **The ledger cannot be edited quietly.** Each entry carries the previous entry's hash, and since 0.195.23 the file is signed with the per-install key that signs the scan state; a broken chain, a bad signature or an unsigned ledger with entries refuses every `rules` command, and the ledger is never replaced by an empty one. An unsigned ledger written before 0.195.23 is accepted once with `AGENTIC_SECURITY_RULES_UNSIGNED=1` and signed on its next save.
- **Promotion is a reviewed decision.** `rules promote` needs `--reviewed-by <person>` (a model or agent name is not a reviewer) and, since 0.195.27, `--scope <text>`; it records the reviewer, the scope and the evidence digests (the promotion evidence table) in the ledger entry and the provenance; a rule changed after its evaluation, an originating commit that is not in the repository's history, a rule file the compiler did not write under the same id, and a promoted rule with the identical match are each refused with the reason.
- **Independent evidence is required, and checked for independence.** Promotion needs at least one vulnerable and one safe example that are not the source finding or a mutation of it; the rule must detect every independent vulnerable example and fire on no independent safe one. Since 0.195.27 an example that is the original snippet, its patch or one of the compiler's own mutations (whitespace aside) is refused as not independent.
- **The ledger travels with the repository.** `promote --sign-key` (or `AGENTIC_SECURITY_PRIVATE_KEY`) also signs the ledger with the operator's Ed25519 key, beside the per-install signature; on a machine without that install key (a CI runner, another clone) every `rules` command accepts the ledger when its chain verifies and the author signature verifies against `AGENTIC_SECURITY_RULES_PUBLIC_KEY` (set outside the repository) or the rule-pack trust store, and refuses it otherwise. The signature covers the whole file, so a dropped last entry fails like any other edit. `rules regress --json` reports `ledgerVerifiedBy`.
- **A promoted rule is held to a shared negative corpus wherever it runs.** The scanner ships a corpus of safe, idiomatic code (`negative-corpus.js`) that is the same on every machine; it sits in front of the shared false-positive corpus with the other promoted rules' safe code, the project's `fp-corpus/` files and any directories named in `AGENTIC_SECURITY_RULES_FP_CORPUS`. Evaluation, promotion and regression all refuse a rule that fires on any of it.
- **A review is of one corpus.** The corpus digests recorded at promotion are re-derived by `rules regress`; a corpus changed after the review is reported with the reason and the rule is treated as regressed until it is evaluated and promoted again.
- **`rule test` fails.** Since 0.195.27 a missed vulnerable fixture or a hit on a clean fixture exits 1; it used to exit 0 whatever the fixtures said.
- **A pattern that could run away is refused.** Every rule pattern passes the same superlinear-regex detector the scanner applies to code (nested quantifiers, ambiguous alternation under a quantifier), not only a textual heuristic.
- **Benchmark answer keys are refused.** Synthesis material that shows benchmark or answer-key signals writes nothing.

## What the compiler does not do

<!-- limits-verified: 2026-11-05 -->

- **A rule is text matching with structure.** There is no syntax-tree pattern and no data-flow rule; "source within N lines of the sink" is proximity, not a proven flow.
- **The mutators are syntactic.** They show a rule survives a different author's version of the code, not every one.
- **Nothing here measures learning independently.** The independent examples a reviewer supplies grade one rule; no longitudinal measurement of the detector population exists, so Learn stays below GA until a measurement that is not the compiler's own exists.
- **Rules live in the operator's state, and travel only if committed.** A promoted rule is not added to this repository's benches. `rules regress` re-scores every promoted rule against its own corpus, its independent examples and the shared false-positive corpus; every CI template and the generated GitHub workflow run it before the scan gate, and it finds nothing to regress unless `.agentic-security/rule-compiler/` and `.agentic-security/rules/` are committed and the ledger was author-signed at promotion.
- **The reviewer is a recorded name, not an authenticated identity.** `--reviewed-by` is held to a denylist of model and agent names and recorded with the evidence digests; nothing checks the person exists. The independence check compares text after collapsing whitespace, so a renamed copy of the original passes it and is caught, if at all, by the score.
- **Cost is bounded, not measured per rule.** A pattern is refused by the superlinear-regex guard before it runs, and at run time each rule gets 200 ms per file and the loader 30 s per scan; no per-rule cost figure is recorded.
- **The shipped negative corpus is small.** Twenty-seven safe snippets across nine languages; it catches the overbroad rules written against the most common sinks, not every false positive. Add the project's own and a fleet's shared directories for the rest.
- **No MCP tool exposes synthesis.**
