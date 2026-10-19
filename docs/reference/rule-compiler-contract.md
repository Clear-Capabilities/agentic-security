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

A rule may carry structural fields, each a regular expression the matcher enforces: `sink`, `source`, `propagator`, `sanitizer`, `dominatingGuard`, `frameworkConstraint`, plus `window`, `guardWindow` and `exclusions`. Free text in any of them is rejected, so a field can never look like a constraint while being ignored. The corpus inputs given at synthesis (`originalCode`, `patchedCode`, `nearbyCleanCode`, `protectedVariantsCode`) are stored beside the rule.

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
| `fpCorpus` | `items`: how many known-safe files it was held to; `hits`: those it fired on |

**Evaluation score**

| Field | Meaning |
|---|---|
| `pass` | Whether this corpus met the thresholds |
| `reasons` | Why not |
| `score` | The counts (below) |
| `thresholds` | The thresholds used. The defaults are precision 0.95, recall 0.80 and zero protected-variant failures |

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
| `promotionEvent` | `at`, `actor`, `reason` and `ruleHash`, or `null` before promotion |
| `evaluatedAt` | When it was evaluated |

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
- **The ledger cannot be edited quietly.** Each entry carries the previous entry's hash; a broken chain refuses every command that would change state.
- **Benchmark answer keys are refused.** Synthesis material that shows benchmark or answer-key signals writes nothing.

## What the compiler does not do

<!-- limits-verified: 2026-10-19 -->

- **A rule is text matching with structure.** There is no syntax-tree pattern and no data-flow rule; "source within N lines of the sink" is proximity, not a proven flow.
- **The mutators are syntactic.** They show a rule survives a different author's version of the code, not every one.
- **Nothing here measures learning independently.** The compiler grades rules against a corpus built from the same finding, so Learn stays below GA until a measurement that is not the compiler's own exists.
- **Rules live in the operator's state.** A promoted rule is not added to this repository's benches.
- **No MCP tool exposes synthesis.**
